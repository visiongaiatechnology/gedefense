use super::*;

impl KernelHooksCore {
    /// `key=value` health string, exactly the documented ten fields:
    /// `enabled`, `attached`, `io_uring`, `module_trace`, `kprobes`,
    /// `lsm_extra`, `events`, `drops`, `loads`, `ring_creates`.
    pub(crate) fn status(&self) -> String {
        format_status(
            self.enabled,
            self.io_uring_attached
                || self.module_trace_attached
                || self.kprobes_attached > 0
                || self.lsm_attached > 0,
            self.io_uring_attached,
            self.module_trace_attached,
            self.kprobes_attached,
            self.lsm_attached,
            Self::per_cpu_sum_or_zero(&self.emitted),
            Self::per_cpu_sum_or_zero(&self.ring_drops),
            Self::per_cpu_sum_or_zero(&self.module_loads),
            Self::per_cpu_sum_or_zero(&self.ring_creates),
        )
    }
}

impl KernelHooksCore {
    pub(super) fn per_cpu_sum(counter: &PerCpuArray<MapData, u64>) -> Result<u64, BoxError> {
        let values = counter.get(&0, 0)?;
        Ok(values
            .iter()
            .copied()
            .fold(0u64, |sum, value| sum.saturating_add(value)))
    }
}

impl KernelHooksCore {
    pub(super) fn per_cpu_sum_or_zero(counter: &PerCpuArray<MapData, u64>) -> u64 {
        match Self::per_cpu_sum(counter) {
            Ok(value) => value,
            Err(error) => {
                eprintln!("kernel hooks counter read failed ({error}); reporting 0");
                0
            }
        }
    }
}

/// Renders the exactly-ten-field status string (pure, unit-testable).
#[allow(clippy::too_many_arguments)]
pub(super) fn format_status(
    enabled: bool,
    attached: bool,
    io_uring: bool,
    module_trace: bool,
    kprobes: u8,
    lsm_extra: u8,
    events: u64,
    drops: u64,
    loads: u64,
    ring_creates: u64,
) -> String {
    format!(
        "enabled={}:attached={}:io_uring={}:module_trace={}:kprobes={}:lsm_extra={}:events={}:drops={}:loads={}:ring_creates={}",
        u8::from(enabled),
        u8::from(attached),
        u8::from(io_uring),
        u8::from(module_trace),
        kprobes,
        lsm_extra,
        events,
        drops,
        loads,
        ring_creates
    )
}

/// Encodes the bounded 9-field text record for the control-plane protocol:
/// `<ts>:<pid>:<tgid>:<uid>:<kind>:<action>:<detail_code>:<comm_hex>:<detail_hex>`.
pub(super) fn encode_event_text(event: &KernelHookEvent) -> String {
    let comm_end = event
        .comm
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(event.comm.len());
    let detail_end = usize::from(event.detail_len).min(KERNEL_HOOK_DETAIL_BYTES);
    format!(
        "{}:{}:{}:{}:{}:{}:{}:{}:{}",
        event.ts_ns,
        event.pid,
        event.tgid,
        event.uid,
        event.kind,
        event.action,
        event.detail_code,
        hex::encode(&event.comm[..comm_end]),
        hex::encode(&event.detail[..detail_end]),
    )
}

/// Random epoch. `/dev/urandom` preferred; a clock-mixed fallback keeps the
/// epoch non-zero and boot-unique even without a readable RNG node (the epoch is
/// a freshness marker, not key material).
pub(super) fn random_epoch() -> u64 {
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
