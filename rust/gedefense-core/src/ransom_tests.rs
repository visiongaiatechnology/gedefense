//! M2.2 (6.2.0): ransomware-sensor wire/status tests.
//!
//! The kernel side is compiled and ABI-checked, but the kprobes are not loaded
//! in the unit-test environment (no CAP_BPF/perf privileges); these tests pin
//! the userspace contract: 8-field event text, reason tokens, bounded trusted
//! comm list, strict `RANSOM_SET` token handling and the `/proc` PGID resolver.

use crate::process_tree;
use crate::ransom::*;
use gedefense_common::{
    RansomEvent, RANSOM_ACTION_AUDIT, RANSOM_EVENT_WIRE_BYTES, RANSOM_SIGNAL_ENTROPY_BURST,
    RANSOM_SIGNAL_RENAME_STORM,
};

fn sample_event(signal: u8) -> RansomEvent {
    RansomEvent {
        ts_ns: 1_700_000_000_000_000_000,
        cgroup_id: 3149,
        tgid: 4242,
        tid: 4243,
        uid: 0,
        gid: 0,
        count: 18,
        window_ms: 487,
        signal,
        action: RANSOM_ACTION_AUDIT,
        comm: *b"encryptor\0\0\0\0\0\0\0",
        reserved: [0; 6],
    }
}

#[test]
fn event_text_is_the_documented_eight_field_wire() {
    let text = encode_event_text(&sample_event(RANSOM_SIGNAL_ENTROPY_BURST), 4200);
    assert_eq!(
        text,
        "4242:4200:0:1:entropy_burst:1700000000000000000:18:656e63727970746f72"
    );
    assert_eq!(text.split(':').count(), 8);
    let text = encode_event_text(&sample_event(RANSOM_SIGNAL_RENAME_STORM), 7);
    assert_eq!(text.split(':').count(), 8);
    assert!(text.contains(":rename_storm:"));
    assert_eq!(wire_reason(RANSOM_SIGNAL_ENTROPY_BURST), "entropy_burst");
    assert_eq!(wire_reason(RANSOM_SIGNAL_RENAME_STORM), "rename_storm");
    // A comm that fills all 16 bytes cannot happen (kernel NUL-pads); the
    // encoder still keeps the record 8-field-shaped and bounded.
    let mut event = sample_event(RANSOM_SIGNAL_ENTROPY_BURST);
    event.comm = *b"exactly-15-char\0";
    let text = encode_event_text(&event, -1);
    assert_eq!(text.split(':').count(), 8);
}

#[test]
fn queue_preserves_fifo_order_and_accounts_for_overflow() {
    let mut queue = RansomQueue::default();
    for idx in 0..(MAX_PENDING_RANSOM_RECORDS + 5) {
        queue.push_record(format!("record-{idx}"));
    }
    assert_eq!(queue.pending_len(), MAX_PENDING_RANSOM_RECORDS);
    let (batch, dropped_local) = queue.pop_batch();
    assert_eq!(batch.len(), MAX_RANSOM_EVENTS_PER_RESPONSE);
    assert_eq!(dropped_local, 5);
    assert_eq!(batch[0], "record-5");
    let (_, second_dropped) = queue.pop_batch();
    assert_eq!(second_dropped, 0);
}

#[test]
fn reason_tokens_are_valid_freeze_rules() {
    for signal in [RANSOM_SIGNAL_ENTROPY_BURST, RANSOM_SIGNAL_RENAME_STORM] {
        let rule = reason_token(signal);
        assert!(crate::process_control::valid_rule_token(rule), "{rule}");
        assert!(rule.len() <= 64);
        assert!(rule.starts_with("XDR.RANSOM_"));
    }
    assert_eq!(
        reason_token(RANSOM_SIGNAL_RENAME_STORM),
        "XDR.RANSOM_RENAME_STORM"
    );
    assert_eq!(
        reason_token(RANSOM_SIGNAL_ENTROPY_BURST),
        "XDR.RANSOM_ENTROPY_BURST"
    );
}

#[test]
fn trusted_comm_list_respects_the_task_name_abi() {
    let mut seen = std::collections::HashSet::new();
    for name in TRUSTED_COMMS {
        assert!(!name.is_empty(), "empty trusted comm");
        assert!(name.len() < 16, "trusted comm too long: {name}");
        assert!(
            name.bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.')),
            "trusted comm alphabet: {name}"
        );
        assert!(seen.insert(*name), "duplicate trusted comm: {name}");
    }
    // The package-manager/compiler/build FP guard must be present.
    for required in ["apt", "apt-get", "dpkg", "tar", "cargo", "rustc", "ld", "make"] {
        assert!(TRUSTED_COMMS.contains(&required), "missing exemption {required}");
    }
    for name in POOL_SERVICE_COMMS {
        assert!(!name.is_empty(), "empty pool service comm");
        assert!(name.len() < 16, "pool service comm too long: {name}");
        assert!(seen.insert(*name), "duplicate pool service comm: {name}");
    }
    assert!(
        TRUSTED_COMMS.len() + POOL_SERVICE_COMMS.len()
            <= gedefense_common::RANSOM_TRUSTED_COMM_ENTRIES as usize,
        "comm exemption tiers exceed kernel map capacity"
    );
}

#[test]
fn wire_event_carries_every_signal_and_is_bounded() {
    for signal in [RANSOM_SIGNAL_ENTROPY_BURST, RANSOM_SIGNAL_RENAME_STORM] {
        let event = sample_event(signal);
        let mut raw = [0u8; RANSOM_EVENT_WIRE_BYTES];
        raw[0..8].copy_from_slice(&event.ts_ns.to_ne_bytes());
        raw[8..16].copy_from_slice(&event.cgroup_id.to_ne_bytes());
        raw[16..20].copy_from_slice(&event.tgid.to_ne_bytes());
        raw[20..24].copy_from_slice(&event.tid.to_ne_bytes());
        raw[24..28].copy_from_slice(&event.uid.to_ne_bytes());
        raw[28..32].copy_from_slice(&event.gid.to_ne_bytes());
        raw[32..36].copy_from_slice(&event.count.to_ne_bytes());
        raw[36..40].copy_from_slice(&event.window_ms.to_ne_bytes());
        raw[40] = event.signal;
        raw[41] = event.action;
        raw[42..58].copy_from_slice(&event.comm);
        raw[58..64].copy_from_slice(&event.reserved);
        assert_eq!(gedefense_common::decode_ransom_event(&raw), Some(event));
    }
}

#[test]
fn proc_pgid_resolver_reads_the_real_stat_field() {
    // The resolver reads /proc/<pid>/stat for the current process; the result
    // must match the kernel process group of this test runner.
    let pgid = process_tree::process_group_of(std::process::id() as i32).expect("own pgid");
    // SAFETY: getpgrp has no arguments and cannot fail.
    assert_eq!(pgid, unsafe { libc::getpgrp() });
    assert!(process_tree::process_group_of(-1).is_err());
}

#[test]
fn max_batch_bounds_are_pinned() {
    assert_eq!(crate::ransom::MAX_RANSOM_EVENTS_PER_RESPONSE, 8);
    assert_eq!(crate::ransom::MAX_RANSOM_PAYLOAD_BYTES, 2048);
}

#[test]
fn state_word_masks_epoch_bits_above_u32() {
    use gedefense_common::{
        RANSOM_STATE_ABI, RANSOM_STATE_ABI_SHIFT, RANSOM_STATE_ARMED_SHIFT,
        RANSOM_STATE_BYTE_MASK, RANSOM_STATE_MAGIC, RANSOM_STATE_MAGIC_SHIFT,
    };
    let word = encode_state_word(u64::MAX, true);
    assert_eq!(
        ((word >> RANSOM_STATE_MAGIC_SHIFT) & RANSOM_STATE_BYTE_MASK) as u8,
        RANSOM_STATE_MAGIC
    );
    assert_eq!(
        ((word >> RANSOM_STATE_ABI_SHIFT) & RANSOM_STATE_BYTE_MASK) as u8,
        RANSOM_STATE_ABI
    );
    assert_eq!((word >> RANSOM_STATE_ARMED_SHIFT) & 1, 1);
    assert_eq!(encode_state_word(u64::MAX, false) >> RANSOM_STATE_ARMED_SHIFT & 1, 0);
}
