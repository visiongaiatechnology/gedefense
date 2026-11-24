use super::*;

impl BpfGuardCore {
    /// `BPF_GUARD_SET <0|1>` -> `armed` / `disarmed`.
    pub(crate) fn set_enabled_token(&mut self, token: &str) -> Result<String, BoxError> {
        match token {
            "0" => self.set_armed(false),
            "1" => self.set_armed(true),
            _ => Err("BPF_GUARD_SET accepts 0 or 1".into()),
        }
    }
}

impl BpfGuardCore {
    /// Drains up to [`BPF_GUARD_MAX_EVENTS_PER_DRAIN`] records as
    /// `<dropped>|<record>[,<record>…]`; `empty` when nothing is pending. Each
    /// record is the 15-field text form
    /// `<ts>:<pid>:<tgid>:<uid>:<action>:<command>:<prog_type>:<helper_mask>:<id0>:<id1>:<id2>:<id3>:<exe_dev>:<exe_ino>:<comm_hex>`.
    pub(crate) fn take_events(&mut self) -> Result<String, BoxError> {
        let mut records: Vec<String> = Vec::with_capacity(BPF_GUARD_MAX_EVENTS_PER_DRAIN);
        let mut payload_bytes = 0usize;
        let rejected_before = self.rejected;
        while records.len() < BPF_GUARD_MAX_EVENTS_PER_DRAIN {
            let Some(item) = self.events.next() else {
                break;
            };
            let Some(event) = decode_bpf_guard_event(&item) else {
                self.rejected = self.rejected.saturating_add(1);
                continue;
            };
            let record = encode_event_text(&event);
            let separator = usize::from(!records.is_empty());
            if payload_bytes
                .saturating_add(separator)
                .saturating_add(record.len())
                .saturating_add(24) // drop-prefix headroom
                > BPF_GUARD_MAX_DRAIN_PAYLOAD_BYTES
            {
                // Defensive: with a bounded 64-byte record the 16-record batch
                // is mathematically far below the budget; this branch only
                // guards a future record-width change.
                eprintln!(
                    "bpf guard drain budget exhausted at {} record(s); remainder stays queued",
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
                "bpf guard rejected {} malformed record(s) in this drain (total {})",
                self.rejected.saturating_sub(rejected_before),
                self.rejected
            );
        }
        let ring_drops = Self::per_cpu_sum(&self.ring_drops)?;
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

impl BpfGuardCore {
    /// `key=value` health string, exactly the documented ten fields:
    /// `enabled`, `attached`, `lsm`, `tp`, `kprobe`, `events`, `drops`,
    /// `read_failures`, `loads`, `helper_risk`.
    pub(crate) fn status(&self) -> String {
        let emitted = Self::per_cpu_sum_or_zero(&self.emitted);
        let drops = Self::per_cpu_sum_or_zero(&self.ring_drops);
        let read_failures = Self::per_cpu_sum_or_zero(&self.read_failures);
        let loads = Self::per_cpu_sum_or_zero(&self.program_loads);
        let helper_risk = Self::per_cpu_sum_or_zero(&self.helper_risk);
        let attached = self.lsm_attached || self.tp_attached || self.kprobe_attached;
        format!(
            "enabled={}:attached={}:lsm={}:tp={}:kprobe={}:events={}:drops={}:read_failures={}:loads={}:helper_risk={}",
            u8::from(self.enabled),
            u8::from(attached),
            u8::from(self.lsm_attached),
            u8::from(self.tp_attached),
            u8::from(self.kprobe_attached),
            emitted,
            drops,
            read_failures,
            loads,
            helper_risk
        )
    }
}

impl BpfGuardCore {
    pub(super) fn per_cpu_sum(counter: &PerCpuArray<MapData, u64>) -> Result<u64, BoxError> {
        let values = counter.get(&0, 0)?;
        Ok(values
            .iter()
            .copied()
            .fold(0u64, |sum, value| sum.saturating_add(value)))
    }
}

impl BpfGuardCore {
    pub(super) fn per_cpu_sum_or_zero(counter: &PerCpuArray<MapData, u64>) -> u64 {
        match Self::per_cpu_sum(counter) {
            Ok(value) => value,
            Err(error) => {
                eprintln!("bpf guard counter read failed ({error}); reporting 0");
                0
            }
        }
    }
}

/// Encodes the bounded 15-field text record for the control-plane protocol.
pub(crate) fn encode_event_text(event: &BpfGuardEvent) -> String {
    let comm_end = event
        .comm
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(event.comm.len());
    format!(
        "{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}",
        event.ts_ns,
        event.pid,
        event.tgid,
        event.uid,
        event.action,
        event.command,
        event.prog_type,
        event.helper_mask,
        event.helper_ids[0],
        event.helper_ids[1],
        event.helper_ids[2],
        event.helper_ids[3],
        event.exe_dev,
        event.exe_ino,
        hex::encode(&event.comm[..comm_end]),
    )
}
