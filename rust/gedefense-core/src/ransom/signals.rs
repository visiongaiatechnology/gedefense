//! M2.2 wire vocabulary and ABI encoders: signal/reason tokens, the 8-field
//! event record and the `RANSOM_STATE` word.

use gedefense_common::{
    RansomEvent, RANSOM_SIGNAL_RENAME_STORM, RANSOM_STATE_ABI, RANSOM_STATE_ABI_SHIFT,
    RANSOM_STATE_ARMED_SHIFT, RANSOM_STATE_MAGIC, RANSOM_STATE_MAGIC_SHIFT,
};

/// Packs the `RANSOM_STATE` word (32-bit epoch | armed | magic | abi).
pub(crate) fn encode_state_word(epoch: u64, armed: bool) -> u64 {
    (epoch & u64::from(u32::MAX))
        | (u64::from(armed) << RANSOM_STATE_ARMED_SHIFT)
        | (u64::from(RANSOM_STATE_MAGIC) << RANSOM_STATE_MAGIC_SHIFT)
        | (u64::from(RANSOM_STATE_ABI) << RANSOM_STATE_ABI_SHIFT)
}

pub(crate) fn random_epoch() -> u64 {
    use std::io::Read as _;
    let mut bytes = [0u8; 8];
    match std::fs::File::open("/dev/urandom") {
        Ok(mut file) => {
            let _ = file.read_exact(&mut bytes);
            u64::from_ne_bytes(bytes) & u64::from(u32::MAX)
        }
        Err(_) => 0,
    }
}

/// Control-plane closed wire vocabulary (`control/coreipc_ransom.go`).
pub(crate) fn wire_reason(signal: u8) -> &'static str {
    match signal {
        RANSOM_SIGNAL_RENAME_STORM => "rename_storm",
        _ => "entropy_burst",
    }
}

/// `XDR.RANSOM_*` rule token for the freeze/kill evidence contract.
pub(crate) fn reason_token(signal: u8) -> &'static str {
    match signal {
        RANSOM_SIGNAL_RENAME_STORM => "XDR.RANSOM_RENAME_STORM",
        _ => "XDR.RANSOM_ENTROPY_BURST",
    }
}

/// Encodes the 8-field control-plane text record
/// (`tgid:pgid:uid:signal:reason:ts_ns:count:comm_hex`).
pub(crate) fn encode_event_text(event: &RansomEvent, pgid: i32) -> String {
    let comm_end = event.comm.iter().position(|byte| *byte == 0).unwrap_or(15);
    format!(
        "{}:{}:{}:{}:{}:{}:{}:{}",
        event.tgid,
        pgid,
        event.uid,
        event.signal,
        wire_reason(event.signal),
        event.ts_ns,
        event.count,
        hex::encode(&event.comm[..comm_end]),
    )
}
