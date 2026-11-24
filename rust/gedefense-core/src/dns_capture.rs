//! V6.3.0 AP-6 — bounded DNS query capture (`DNS_CAPTURE_*`).
//!
//! Loads and drains the `DNS_CAPTURE_EVENTS` ring produced by
//! `rust/gedefense-ebpf/src/dns_capture.rs`:
//!
//! - `tp/syscalls/sys_enter_sendto` and `tp/syscalls/sys_enter_sendmsg` on UDP
//!   port 53, bounded to a 12-byte DNS header + 64-byte QNAME wire window,
//! - one 64-byte `DnsCaptureEvent` per observed query (see
//!   `gedefense_common::dns_capture` for the wire layout and the rejecting
//!   decoder).
//!
//! The core frames, bounds, validates and converts. The multi-signal tunnelling
//! analysis (`XDR.DNS_TUNNEL`: subdomain entropy, Zipf deviation, FQDN length,
//! TXT/NULL share, distinct subdomains/hour) runs in the control plane, which
//! must never receive a fabricated field: every rejected record is counted and
//! every unavailable tracepoint is reported as `attached=0` for that hook.
//!
//! # Kernel view -> presentation view
//!
//! The kernel records the QNAME **wire** form (see the verifier note in the
//! eBPF module): the full QNAME when it fits 15 wire bytes, otherwise the last
//! 15 wire bytes. This module resolves the clipped tail's label phase, rebuilds a
//! label-aligned presentation view (`first-label[.trailing labels]`) and
//! cross-checks it against `fqdn_len`, `sub_len` and the stored wire. `label_count`
//! arrives as 0 from the shipped kernel producer (the kernel cannot walk labels
//! under the verifier budget); a future non-zero value is cross-checked. A record
//! whose wire view cannot be resolved is rejected and counted, never repaired.
//!
//! # Attach ladder (each step is optional and honest)
//!
//! 1. the three mandatory maps are taken first; a stale object (missing map)
//!    fails the whole core load loudly,
//! 2. `sys_enter_sendto` and `sys_enter_sendmsg` are attached independently;
//!    `attached` is a bitmask (`bit0` = sendto, `bit1` = sendmsg) so a partial
//!    ladder is visible instead of rounded up to "DNS visibility works",
//! 3. the state word is armed last with a random per-boot epoch, so no record
//!    can be produced before the ladder and the layout are final.
//!
//! # Drain contract
//!
//! `DNS_EVENTS` returns `<dropped>|<record>[,<record>…]` or `empty`. At most
//! [`DNS_CAPTURE_MAX_EVENTS_PER_DRAIN`] records and
//! [`DNS_CAPTURE_MAX_DRAIN_PAYLOAD_BYTES`] bytes are returned per call; a
//! record is
//! `<ts_ns>:<pid>:<tgid>:<uid>:<qtype>:<comm_hex>:<qname_hex>:<fqdn_len>`
//! (the last field is the full presentation FQDN length, which is what makes
//! the documented `FQDN length > 50` signal verifiable even when the stored
//! name bytes were clipped). `dropped` is the saturating `DNS_CAPTURE_EVENTS`
//! ring-drop delta since the previous drain.
//!
//! `DNS_STATUS` returns exactly
//! `enabled=<0|1>:attached=<0..3>:events=<n>:drops=<n>:read_failures=<n>`.
//!
//! Observe-only: this module never derives a response, never signals a process
//! and never mutates the kernel policy.

use aya::{
    maps::{Array as AyaArray, MapData, PerCpuArray, RingBuf},
    programs::TracePoint,
    Ebpf,
};
use gedefense_common::{
    decode_dns_capture_event, dns_capture_state_word, DnsCaptureEvent,
    DNS_CAPTURE_COUNTER_EMITTED, DNS_CAPTURE_COUNTER_READ_FAILURES,
    DNS_CAPTURE_COUNTER_RING_DROPS, DNS_CAPTURE_MAX_DRAIN_PAYLOAD_BYTES,
    DNS_CAPTURE_MAX_EVENTS_PER_DRAIN,
};
use std::{error::Error, fs, io::Read as _};

mod qname;

use self::qname::*;

type BoxError = Box<dyn Error + Send + Sync + 'static>;

/// Index of the single state word in `DNS_CAPTURE_STATE`.
const DNS_CAPTURE_STATE_INDEX: u32 = 0;

/// `tp/syscalls/sys_enter_sendto`.
const DNS_CAPTURE_SENDTO_PROGRAM: &str = "gedefense_dns_sendto";
/// `tp/syscalls/sys_enter_sendmsg`.
const DNS_CAPTURE_SENDMSG_PROGRAM: &str = "gedefense_dns_sendmsg";
const DNS_CAPTURE_TRACEPOINT_CATEGORY: &str = "syscalls";
const DNS_CAPTURE_SENDTO_TRACEPOINT: &str = "sys_enter_sendto";
const DNS_CAPTURE_SENDMSG_TRACEPOINT: &str = "sys_enter_sendmsg";

/// `attached` bitmask: `bit0` = sendto tracepoint, `bit1` = sendmsg tracepoint.
const ATTACHED_SENDTO: u8 = 1 << 0;
const ATTACHED_SENDMSG: u8 = 1 << 1;

/// Core-side owner of the DNS capture maps/ring.
pub(crate) struct DnsCaptureCore {
    events: RingBuf<MapData>,
    state: AyaArray<MapData, u64>,
    counters: PerCpuArray<MapData, u64>,
    /// Random per-boot epoch carried in the low 32 bits of the state word.
    epoch: u64,
    enabled: bool,
    attached: u8,
    rejected: u64,
    last_ring_drops: u64,
}

impl DnsCaptureCore {
    /// Takes the mandatory `DNS_CAPTURE_*` maps, attaches both tracepoints
    /// independently and arms the state word.
    ///
    /// A stale object fails loudly (missing map); an unsupported tracepoint
    /// only clears its `attached` bit — never a fake DNS visibility claim.
    pub(crate) fn load(ebpf: &mut Ebpf) -> Result<Self, BoxError> {
        let events = RingBuf::try_from(
            ebpf.take_map(&crate::chameleon::map_name("DNS_CAPTURE_EVENTS"))
                .ok_or("DNS_CAPTURE_EVENTS missing")?,
        )?;
        let state = AyaArray::try_from(
            ebpf.take_map(&crate::chameleon::map_name("DNS_CAPTURE_STATE"))
                .ok_or("DNS_CAPTURE_STATE missing")?,
        )?;
        let counters = PerCpuArray::try_from(
            ebpf.take_map(&crate::chameleon::map_name("DNS_CAPTURE_COUNTERS"))
                .ok_or("DNS_CAPTURE_COUNTERS missing")?,
        )?;
        let mut core = Self {
            events,
            state,
            counters,
            epoch: random_epoch(),
            enabled: false,
            attached: 0,
            rejected: 0,
            last_ring_drops: 0,
        };
        core.attach_sendto(ebpf);
        core.attach_sendmsg(ebpf);
        // Arm last: both programs ignore every syscall until the state word is
        // magic/ABI-valid and armed.
        core.set_armed(true)?;
        eprintln!(
            "GeDefense DNS capture: enabled={} attached={} (sendto={} sendmsg={})",
            u8::from(core.enabled),
            core.attached,
            u8::from(core.attached & ATTACHED_SENDTO != 0),
            u8::from(core.attached & ATTACHED_SENDMSG != 0)
        );
        Ok(core)
    }

    fn attach_sendto(&mut self, ebpf: &mut Ebpf) {
        self.attached |= Self::attach_tracepoint(
            ebpf,
            DNS_CAPTURE_SENDTO_PROGRAM,
            DNS_CAPTURE_SENDTO_TRACEPOINT,
            ATTACHED_SENDTO,
        );
    }

    fn attach_sendmsg(&mut self, ebpf: &mut Ebpf) {
        self.attached |= Self::attach_tracepoint(
            ebpf,
            DNS_CAPTURE_SENDMSG_PROGRAM,
            DNS_CAPTURE_SENDMSG_TRACEPOINT,
            ATTACHED_SENDMSG,
        );
    }

    fn attach_tracepoint(
        ebpf: &mut Ebpf,
        program_name: &str,
        event_name: &str,
        attached_bit: u8,
    ) -> u8 {
        let Some(program) = ebpf.program_mut(&crate::chameleon::program_name(program_name)) else {
            eprintln!("DNS capture program {program_name} missing; tracepoint not attached");
            return 0;
        };
        let result = (|| -> Result<(), BoxError> {
            let tracepoint: &mut TracePoint = program.try_into()?;
            tracepoint.load()?;
            tracepoint.attach(DNS_CAPTURE_TRACEPOINT_CATEGORY, event_name)?;
            Ok(())
        })();
        match result {
            Ok(()) => attached_bit,
            Err(error) => {
                eprintln!(
                    "DNS capture tracepoint {DNS_CAPTURE_TRACEPOINT_CATEGORY}:{event_name} unavailable ({error}); not attached"
                );
                0
            }
        }
    }

    fn set_armed(&mut self, armed: bool) -> Result<String, BoxError> {
        let word = dns_capture_state_word(self.epoch as u32, armed);
        self.state.set(DNS_CAPTURE_STATE_INDEX, word, 0)?;
        self.enabled = armed;
        Ok(if armed { "armed" } else { "disarmed" }.to_owned())
    }

    /// `DNS_SET <0|1>` -> `armed` / `disarmed`.
    pub(crate) fn set_enabled_token(&mut self, token: &str) -> Result<String, BoxError> {
        match token {
            "0" => self.set_armed(false),
            "1" => self.set_armed(true),
            _ => Err("DNS_SET accepts 0 or 1".into()),
        }
    }

    /// Drains up to [`DNS_CAPTURE_MAX_EVENTS_PER_DRAIN`] records as
    /// `<dropped>|<record>[,<record>…]`; `empty` when nothing is pending.
    pub(crate) fn take_events(&mut self) -> Result<String, BoxError> {
        let mut records: Vec<String> = Vec::with_capacity(DNS_CAPTURE_MAX_EVENTS_PER_DRAIN);
        let mut payload_bytes = 0usize;
        let rejected_before = self.rejected;
        while records.len() < DNS_CAPTURE_MAX_EVENTS_PER_DRAIN {
            let Some(item) = self.events.next() else {
                break;
            };
            let Some(event) = decode_dns_capture_event(&item) else {
                // Mandatory rejecting decoder: a record the kernel producer
                // cannot have emitted never reaches the control plane.
                self.rejected = self.rejected.saturating_add(1);
                continue;
            };
            let Some(record) = encode_event_text(&event) else {
                // The wire-level record decoded but its QNAME view is not
                // consistent with the producer contract (e.g. a label phase that
                // cannot be resolved): count it, never repair or emit it.
                self.rejected = self.rejected.saturating_add(1);
                continue;
            };
            let separator = usize::from(!records.is_empty());
            if payload_bytes
                .saturating_add(separator)
                .saturating_add(record.len())
                .saturating_add(24) // drop-prefix headroom
                > DNS_CAPTURE_MAX_DRAIN_PAYLOAD_BYTES
            {
                // Defensive: with a bounded 64-byte record the 16-record batch
                // is mathematically far below the budget; this branch only
                // guards a future record-width change.
                eprintln!(
                    "DNS capture drain budget exhausted at {} record(s); remainder stays queued",
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
                "DNS capture rejected {} malformed record(s) in this drain (total {})",
                self.rejected.saturating_sub(rejected_before),
                self.rejected
            );
        }
        let ring_drops =
            Self::counter_total_or_zero(&self.counters, DNS_CAPTURE_COUNTER_RING_DROPS);
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

    /// `key=value` health, exactly the five documented fields:
    /// `enabled`, `attached`, `events`, `drops`, `read_failures`.
    pub(crate) fn status(&self) -> String {
        format!(
            "enabled={}:attached={}:events={}:drops={}:read_failures={}",
            u8::from(self.enabled),
            self.attached,
            Self::counter_total_or_zero(&self.counters, DNS_CAPTURE_COUNTER_EMITTED),
            Self::counter_total_or_zero(&self.counters, DNS_CAPTURE_COUNTER_RING_DROPS),
            Self::counter_total_or_zero(&self.counters, DNS_CAPTURE_COUNTER_READ_FAILURES),
        )
    }

    /// Sums one per-CPU counter lane across CPUs.
    fn counter_total(counter: &PerCpuArray<MapData, u64>, lane: u32) -> Result<u64, BoxError> {
        let values = counter.get(&lane, 0)?;
        Ok(values
            .iter()
            .copied()
            .fold(0u64, |sum, value| sum.saturating_add(value)))
    }

    fn counter_total_or_zero(counter: &PerCpuArray<MapData, u64>, lane: u32) -> u64 {
        match Self::counter_total(counter, lane) {
            Ok(value) => value,
            Err(error) => {
                eprintln!("DNS capture counter lane {lane} read failed ({error}); reporting 0");
                0
            }
        }
    }
}

/// Random epoch. `/dev/urandom` preferred; a clock-mixed fallback keeps the
/// epoch non-zero and boot-unique even on a host without a readable RNG node
/// (the epoch is a freshness marker, not key material).
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

/// Encodes the bounded control-plane text record:
/// `<ts_ns>:<pid>:<tgid>:<uid>:<qtype>:<comm_hex>:<qname_hex>:<fqdn_len>`.
///
/// The kernel records a bounded QNAME *wire* view; this function turns it into
/// the label-aligned presentation view the analyser groups by:
///
/// - a fully stored name (`wire_len <= 15`) is parsed label by label and must
///   match `sub_len` and `fqdn_len` exactly (a non-zero `label_count` is
///   cross-checked; the shipped producer sends 0),
/// - a clipped name resolves the phase of the 15-byte wire tail (the tail always
///   ends at the root label), keeps only complete trailing labels, and prefixes
///   the stored first-label bytes. The result is a stable grouping view: it
///   always ends with the registrable-domain labels even when middle labels were
///   clipped. The omitted-character budget is validated against the full
///   `fqdn_len`; `label_count == 0` (shipped producer) means the kernel did not
///   count labels, so the core validates the reconstruction without that count.
///
/// `qname_hex` is that view; `fqdn_len` carries the *full* presentation length so
/// the control plane can evaluate the `FQDN > 50` signal without guessing.
/// `None` means the record is structurally inconsistent with the kernel producer
/// (counted as a rejected record; never repaired).
pub(crate) fn encode_event_text(event: &DnsCaptureEvent) -> Option<String> {
    let comm_end = event
        .comm
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(event.comm.len());
    let qname = reconstruct_qname(event)?;
    Some(format!(
        "{}:{}:{}:{}:{}:{}:{}:{}",
        event.ts_ns,
        event.pid,
        event.tgid,
        event.uid,
        event.qtype,
        hex::encode(&event.comm[..comm_end]),
        hex::encode(&qname),
        event.fqdn_len,
    ))
}

#[cfg(test)]
mod tests;
