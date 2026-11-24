use super::*;

/// Packs the `BPF_GUARD_STATE` word (epoch low 32 bits | armed | magic | ABI).
pub(crate) fn encode_state_word(epoch: u64, armed: bool) -> u64 {
    bpf_guard_state_word(epoch as u32, armed)
}

/// Random epoch. `/dev/urandom` preferred; a clock-mixed fallback keeps the
/// epoch non-zero and boot-unique even on a host without a readable RNG node
/// (the epoch is a freshness marker, not key material).
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
