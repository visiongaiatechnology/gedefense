//! V6.3.0 AP-9 (S12) â€” high-priority security evidence drain (`SEC_CRIT_*`).
//!
//! Core-side owner of the two-class telemetry contract implemented by
//! `rust/gedefense-ebpf/src/sec_crit.rs`:
//!
//! - [`SEC_CRIT_EVENTS`] is the independent high-priority ring (256 KiB =
//!   4096 queued 64-byte records). Credential denies, attach-time eBPF
//!   helper-risk verdicts, LKM loads and critical persistence records are
//!   duplicated into it by their eBPF producers; bulk telemetry (exec argv,
//!   kernel probe, flow, DNS) can never displace it because it uses different
//!   rings.
//! - [`SEC_CRIT_STATE`] is the ABI-1 armed word: epoch low 32 bits | armed bit
//!   32 | magic `0x53` (bits 40..47) | ABI 1 (bits 48..55). This module writes
//!   the word at load (arm once) and on `SEC_CRIT_SET`.
//! - [`SEC_CRIT_COUNTERS`] carries the five documented per-CPU lanes:
//!   emitted / ring drops / refused-unarmed / read failures / suppressed.
//! - `TELEMETRY_FLOOD_BUCKETS` (LRU, 4096 entries) and
//!   `TELEMETRY_FLOOD_SUPPRESSED` are taken as mandatory maps so a stale
//!   object (missing map) fails the whole core load loudly, exactly like every
//!   other security family. The bucket *contents* are kernel-owned and are not
//!   iterated by the core (see [`STATUS`] below); the status reports the honest
//!   capacity bound instead of a live count it cannot cheaply obtain.
//!
//! # Wire contract (control plane)
//!
//! `take_events` answers `empty` when nothing is pending, otherwise
//! `<dropped>|<record>[,<record>â€¦]` where `<dropped>` is the saturating
//! ring-drop delta since the previous drain and every `<record>` is the exact
//! 12-field text form (native decimal, `comm`/`extra` lowercase hex):
//!
//! `<ts>:<source>:<kind>:<action>:<detail_code>:<pid>:<tgid>:<uid>:<dev>:<ino>:<comm_hex>:<extra_hex>`
//!
//! `status` answers the exactly-seven documented `key=value` fields:
//!
//! `enabled=<0|1>:events=<u64>:drops=<u64>:refused_unarmed=<u64>:read_failures=<u64>:suppressed=<u64>:bucket_capacity=<u64>`
//!
//! `bucket_capacity` is `SEC_CRIT_BUCKET_ENTRIES` (the map's max entries, i.e.
//! the documented capability bound). It is deliberately **not** named
//! `buckets=` because the core does not enumerate live bucket keys on every
//! 2 s poll (up to 4096 `BPF_MAP_GET_NEXT_KEY` syscalls); reporting the map max
//! under a live-count label would be a lie, so the label states what the value
//! is. `suppressed` is `max(lane suppressed, TELEMETRY_FLOOD_SUPPRESSED)` â€” the
//! producer increments both in the same helper invocation, so the maximum can
//! only over-report (never hide) a partial counter write.
//!
//! A record the shared rejecting decoder refuses is counted (`rejected`,
//! reported on stderr) and never forwarded.

use aya::{
    maps::{Array as AyaArray, HashMap as AyaHashMap, MapData, PerCpuArray, RingBuf},
    Ebpf,
};
use gedefense_common::{
    decode_sec_crit_event, SecCritEvent, SEC_CRIT_BUCKET_ENTRIES, SEC_CRIT_BUCKET_KEY_BYTES,
    SEC_CRIT_BUCKET_VALUE_BYTES, SEC_CRIT_COUNTER_EMITTED, SEC_CRIT_COUNTER_LANES,
    SEC_CRIT_COUNTER_READ_FAILURES, SEC_CRIT_COUNTER_REFUSED_UNARMED, SEC_CRIT_COUNTER_RING_DROPS,
    SEC_CRIT_COUNTER_SUPPRESSED, SEC_CRIT_EVENT_RING_BYTES, SEC_CRIT_MAX_DRAIN_PAYLOAD_BYTES,
    SEC_CRIT_MAX_EVENTS_PER_DRAIN, SEC_CRIT_STATE_ABI, SEC_CRIT_STATE_ABI_SHIFT,
    SEC_CRIT_STATE_ARMED_SHIFT, SEC_CRIT_STATE_BYTE_MASK, SEC_CRIT_STATE_MAGIC,
    SEC_CRIT_STATE_MAGIC_SHIFT,
};
use std::{error::Error, fs, io::Read as _};

type BoxError = Box<dyn Error + Send + Sync + 'static>;

/// Index of the single state word in `SEC_CRIT_STATE`.
const SEC_CRIT_STATE_INDEX: u32 = 0;
/// Index of the single aggregate suppression lane in
/// `TELEMETRY_FLOOD_SUPPRESSED`.
const TELEMETRY_FLOOD_SUPPRESSED_INDEX: u32 = 0;
/// Defensive headroom for the `<dropped>|` prefix when enforcing the bounded
/// drain payload.
const DRAIN_PREFIX_HEADROOM: usize = 24;

/// Core-side owner of the high-priority security evidence ring and the
/// flood-suppression health facts.
pub(crate) struct SecCritCore {
    events: RingBuf<MapData>,
    state: AyaArray<MapData, u64>,
    counters: PerCpuArray<MapData, u64>,
    suppressed: PerCpuArray<MapData, u64>,
    /// The flood-bucket map is mandatory (a stale object must fail loudly) but
    /// its contents are kernel-owned; the core never enumerates it. The field
    /// keeps the map handle alive for the lifetime of the core like every
    /// other mandatory map.
    _buckets: AyaHashMap<MapData, [u8; SEC_CRIT_BUCKET_KEY_BYTES], [u8; SEC_CRIT_BUCKET_VALUE_BYTES]>,
    /// Random per-boot epoch rendered into the state word's low 32 bits.
    epoch: u64,
    enabled: bool,
    /// Records the shared decoder refused (a producer bug, never forwarded).
    rejected: u64,
    /// Last observed cumulative ring-drop count; `take_events` reports deltas.
    last_ring_drops: u64,
}

/// Packs the documented [`SEC_CRIT_STATE`] ABI-1 word.
///
/// A zero/absent word means "not armed"; the eBPF helpers accept only this
/// exact magic/ABI/armed image, so a foreign or stale word can only disable the
/// observer (fail-safe) and never fake it.
pub(crate) fn encode_state_word(epoch: u64, armed: bool) -> u64 {
    let epoch_bits = epoch & 0xffff_ffff;
    epoch_bits
        | (u64::from(armed) << SEC_CRIT_STATE_ARMED_SHIFT)
        | ((SEC_CRIT_STATE_MAGIC as u64) << SEC_CRIT_STATE_MAGIC_SHIFT)
        | ((SEC_CRIT_STATE_ABI as u64) << SEC_CRIT_STATE_ABI_SHIFT)
}

/// True only for a word written by [`encode_state_word`] with `armed = true`.
/// Kept available for callers/tests that verify the ABI image.
#[allow(dead_code)]
pub(crate) fn state_word_armed(word: u64) -> bool {
    let magic = ((word >> SEC_CRIT_STATE_MAGIC_SHIFT) & SEC_CRIT_STATE_BYTE_MASK) as u8;
    let abi = ((word >> SEC_CRIT_STATE_ABI_SHIFT) & SEC_CRIT_STATE_BYTE_MASK) as u8;
    let armed = (word >> SEC_CRIT_STATE_ARMED_SHIFT) & 1;
    magic == SEC_CRIT_STATE_MAGIC && abi == SEC_CRIT_STATE_ABI && armed == 1
}

/// The documented capability bound of the flood-bucket map (honest upper
/// bound, not a live count; see the module docs).
pub(crate) fn bucket_capacity() -> u64 {
    u64::from(SEC_CRIT_BUCKET_ENTRIES)
}

/// Random epoch. `/dev/urandom` preferred; a clock-mixed fallback keeps the
/// epoch non-zero and boot-unique even without a readable RNG node (the epoch
/// is a freshness marker, not key material).
fn random_epoch() -> u64 {
    let mut bytes = [0u8; 8];
    if let Ok(mut file) = fs::File::open("/dev/urandom") {
        if file.read_exact(&mut bytes).is_ok() {
            let value = u64::from_ne_bytes(bytes);
            if value != 0 {
                return value;
            }
        }
    }
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos() as u64)
        .unwrap_or(0);
    (nanos ^ 0x9e37_79b9_7f4a_7c15) | 1
}

impl SecCritCore {
    /// Takes the five mandatory `SEC_CRIT_*`/flood maps and arms the state word.
    ///
    /// A stale object (missing map) fails the whole core load loudly: the
    /// two-class ring is a security guarantee, not an optional sensor. Arming
    /// happens last, after every map handle exists, so no producer can emit
    /// into a half-initialised observer.
    pub(crate) fn load(ebpf: &mut Ebpf) -> Result<Self, BoxError> {
        let events = RingBuf::try_from(
            ebpf.take_map(&crate::chameleon::map_name("SEC_CRIT_EVENTS"))
                .ok_or("SEC_CRIT_EVENTS missing")?,
        )?;
        let state = AyaArray::try_from(
            ebpf.take_map(&crate::chameleon::map_name("SEC_CRIT_STATE"))
                .ok_or("SEC_CRIT_STATE missing")?,
        )?;
        let counters = PerCpuArray::try_from(
            ebpf.take_map(&crate::chameleon::map_name("SEC_CRIT_COUNTERS"))
                .ok_or("SEC_CRIT_COUNTERS missing")?,
        )?;
        let buckets = AyaHashMap::try_from(
            ebpf.take_map(&crate::chameleon::map_name("TELEMETRY_FLOOD_BUCKETS"))
                .ok_or("TELEMETRY_FLOOD_BUCKETS missing")?,
        )?;
        let suppressed = PerCpuArray::try_from(
            ebpf.take_map(&crate::chameleon::map_name("TELEMETRY_FLOOD_SUPPRESSED"))
                .ok_or("TELEMETRY_FLOOD_SUPPRESSED missing")?,
        )?;
        let mut core = Self {
            events,
            state,
            counters,
            suppressed,
            _buckets: buckets,
            epoch: random_epoch(),
            enabled: false,
            rejected: 0,
            last_ring_drops: 0,
        };
        core.set_armed(true)?;
        eprintln!(
            "GeDefense S12 high-priority security ring: enabled=true ring_bytes={} bucket_capacity={}",
            SEC_CRIT_EVENT_RING_BYTES,
            bucket_capacity()
        );
        Ok(core)
    }

    /// Writes the state word. Disarming keeps the epoch (a re-arm is the same
    /// boot) and only clears the armed bit.
    fn set_armed(&mut self, armed: bool) -> Result<(), BoxError> {
        let word = encode_state_word(self.epoch, armed);
        self.state.set(SEC_CRIT_STATE_INDEX, word, 0)?;
        self.enabled = armed;
        Ok(())
    }

    /// `SEC_CRIT_SET <0|1>` -> `armed` / `disarmed`.
    pub(crate) fn set_enabled_token(&mut self, token: &str) -> Result<String, BoxError> {
        match token {
            "0" => {
                self.set_armed(false)?;
                Ok("disarmed".to_owned())
            }
            "1" => {
                self.set_armed(true)?;
                Ok("armed".to_owned())
            }
            _ => Err("SEC_CRIT_SET accepts 0 or 1".into()),
        }
    }

    /// Sums one per-CPU counter lane across CPUs (saturating).
    fn counter_sum(counter: &PerCpuArray<MapData, u64>, lane: u32) -> Result<u64, BoxError> {
        if lane >= SEC_CRIT_COUNTER_LANES {
            return Err("sec-crit counter lane out of range".into());
        }
        let values = counter.get(&lane, 0)?;
        Ok(values
            .iter()
            .copied()
            .fold(0u64, |sum, value| sum.saturating_add(value)))
    }

    /// Reads one per-CPU counter lane, reporting 0 (and a bounded stderr note)
    /// when the map read fails: a health render must never panic or hide the
    /// rest of the status.
    fn counter_sum_or_zero(&self, lane: u32) -> u64 {
        match Self::counter_sum(&self.counters, lane) {
            Ok(value) => value,
            Err(error) => {
                eprintln!("sec-crit counter lane {lane} read failed ({error}); reporting 0");
                0
            }
        }
    }

    /// Sums the aggregate suppression counter map (`TELEMETRY_FLOOD_SUPPRESSED`).
    fn suppressed_map_sum(&self) -> u64 {
        match Self::counter_sum(&self.suppressed, TELEMETRY_FLOOD_SUPPRESSED_INDEX) {
            Ok(value) => value,
            Err(error) => {
                eprintln!("sec-crit flood-suppressed counter read failed ({error}); reporting 0");
                0
            }
        }
    }

    /// Cumulative ring drops (one drain).
    fn ring_drops(&self) -> Result<u64, BoxError> {
        Self::counter_sum(&self.counters, SEC_CRIT_COUNTER_RING_DROPS)
    }
}

impl SecCritCore {
    /// Drains up to [`SEC_CRIT_MAX_EVENTS_PER_DRAIN`] records within
    /// [`SEC_CRIT_MAX_DRAIN_PAYLOAD_BYTES`].
    ///
    /// Answers `empty` when nothing is pending, otherwise
    /// `<dropped>|<record>[,<record>â€¦]`; `<dropped>` is the saturating ring-drop
    /// delta since the previous drain (so a silent overflow is impossible: the
    /// control plane receives the loss and reports it as degradation).
    pub(crate) fn take_events(&mut self) -> Result<String, BoxError> {
        let mut records: Vec<String> = Vec::with_capacity(SEC_CRIT_MAX_EVENTS_PER_DRAIN);
        let mut payload_bytes = 0usize;
        let rejected_before = self.rejected;
        while records.len() < SEC_CRIT_MAX_EVENTS_PER_DRAIN {
            let Some(item) = self.events.next() else {
                break;
            };
            let Some(event) = decode_sec_crit_event(&item) else {
                self.rejected = self.rejected.saturating_add(1);
                continue;
            };
            let record = encode_event_text(&event);
            let separator = usize::from(!records.is_empty());
            if payload_bytes
                .saturating_add(separator)
                .saturating_add(record.len())
                .saturating_add(DRAIN_PREFIX_HEADROOM)
                > SEC_CRIT_MAX_DRAIN_PAYLOAD_BYTES
            {
                // Defensive: with the bounded 12-field record the 16-record
                // batch is mathematically below the budget; this guards a
                // future record-width change without dropping the remainder.
                eprintln!(
                    "sec-crit drain budget exhausted at {} record(s); remainder stays queued",
                    records.len()
                );
                break;
            }
            payload_bytes = payload_bytes
                .saturating_add(separator)
                .saturating_add(record.len());
            records.push(record);
        }
        if self.rejected > rejected_before {
            eprintln!(
                "sec-crit rejected {} malformed record(s) in this drain (total {})",
                self.rejected.saturating_sub(rejected_before),
                self.rejected
            );
        }
        let ring_drops = self.ring_drops()?;
        let dropped = ring_drops.saturating_sub(self.last_ring_drops);
        self.last_ring_drops = ring_drops;
        if records.is_empty() {
            if dropped == 0 && self.rejected == 0 {
                return Ok("empty".to_owned());
            }
            return Ok(format!("{dropped}|"));
        }
        Ok(format!("{dropped}|{}", records.join(",")))
    }
}

impl SecCritCore {
    /// `SEC_CRIT_STATUS` â€” exactly the documented seven `key=value` fields.
    pub(crate) fn status(&self) -> String {
        let events = self.counter_sum_or_zero(SEC_CRIT_COUNTER_EMITTED);
        let drops = self.counter_sum_or_zero(SEC_CRIT_COUNTER_RING_DROPS);
        let refused_unarmed = self.counter_sum_or_zero(SEC_CRIT_COUNTER_REFUSED_UNARMED);
        let read_failures = self.counter_sum_or_zero(SEC_CRIT_COUNTER_READ_FAILURES);
        let suppressed_lane = self.counter_sum_or_zero(SEC_CRIT_COUNTER_SUPPRESSED);
        let suppressed = suppressed_lane.max(self.suppressed_map_sum());
        format!(
            "enabled={}:events={}:drops={}:refused_unarmed={}:read_failures={}:suppressed={}:bucket_capacity={}",
            u8::from(self.enabled),
            events,
            drops,
            refused_unarmed,
            read_failures,
            suppressed,
            bucket_capacity()
        )
    }
}

/// Encodes the documented 12-field text record. `comm` bytes are hex-encoded
/// up to the first NUL (the decoder guarantees a printable, NUL-padded slot);
/// `extra` is always the full 8 bytes as 16 lowercase hex characters.
pub(crate) fn encode_event_text(event: &SecCritEvent) -> String {
    let comm_end = event
        .comm
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(event.comm.len());
    format!(
        "{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}",
        event.ts_ns,
        event.source,
        event.kind,
        event.action,
        event.detail_code,
        event.pid,
        event.tgid,
        event.uid,
        event.dev,
        event.ino,
        hex::encode(&event.comm[..comm_end]),
        hex::encode(event.extra)
    )
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod smoke_tests;
