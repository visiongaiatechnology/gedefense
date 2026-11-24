use super::*;
use gedefense_common::{decode_sec_crit_event, encode_sec_crit_event, SEC_CRIT_EVENT_WIRE_BYTES};

fn sample() -> SecCritEvent {
    SecCritEvent {
        ts_ns: 1_700_000_000_000_000_000,
        source: 1,
        kind: 1,
        action: 2,
        reserved: 0,
        detail_code: 0o100644,
        pid: 4242,
        tgid: 4242,
        uid: 0,
        dev: 8,
        ino: 123_456,
        comm: gedefense_common::sec_crit_comm(b"fake_sshd"),
        extra: [0u8; 8],
    }
}

#[test]
fn state_word_is_the_documented_abi1_image() {
    let word = encode_state_word(0xdead_beef_cafe_f00d, true);
    assert_eq!(word & 0xffff_ffff, 0xcafe_f00d, "epoch low 32 bits");
    assert_eq!((word >> 32) & 1, 1, "armed bit");
    assert_eq!((word >> 40) & 0xff, u64::from(SEC_CRIT_STATE_MAGIC));
    assert_eq!((word >> 48) & 0xff, u64::from(SEC_CRIT_STATE_ABI));
    assert!(state_word_armed(word));
    assert!(!state_word_armed(encode_state_word(7, false)));
    // A zero or foreign word is disarmed (fail-safe), never "armed".
    assert!(!state_word_armed(0));
    assert!(!state_word_armed(u64::MAX));
    assert!(!state_word_armed(0x0053_0001_0000_0000));
}

#[test]
fn event_text_record_has_the_documented_twelve_fields() {
    let event = sample();
    let decoded = decode_sec_crit_event(&encode_sec_crit_event(&event)).expect("valid record");
    let text = encode_event_text(&decoded);
    let fields: Vec<&str> = text.split(':').collect();
    assert_eq!(fields.len(), 12, "record: {text}");
    assert_eq!(fields[0], decoded.ts_ns.to_string());
    assert_eq!(fields[1], decoded.source.to_string());
    assert_eq!(fields[2], decoded.kind.to_string());
    assert_eq!(fields[3], decoded.action.to_string());
    assert_eq!(fields[4], decoded.detail_code.to_string());
    assert_eq!(fields[5], decoded.pid.to_string());
    assert_eq!(fields[6], decoded.tgid.to_string());
    assert_eq!(fields[7], decoded.uid.to_string());
    assert_eq!(fields[8], decoded.dev.to_string());
    assert_eq!(fields[9], decoded.ino.to_string());
    assert_eq!(fields[10], hex::encode(b"fake_sshd"));
    assert_eq!(fields[11], "0000000000000000");
    // The bounded drain contract stays satisfiable for a full batch.
    let worst = encode_event_text(&SecCritEvent {
        ts_ns: u64::MAX,
        detail_code: u32::MAX,
        pid: u32::MAX,
        tgid: u32::MAX,
        uid: u32::MAX,
        dev: u32::MAX,
        ino: u64::MAX,
        comm: *b"abcdefghijklmno\0",
        extra: [0xff; 8],
        ..decoded
    });
    assert!(
        SEC_CRIT_MAX_EVENTS_PER_DRAIN * (worst.len() + 1) + DRAIN_PREFIX_HEADROOM
            <= SEC_CRIT_MAX_DRAIN_PAYLOAD_BYTES
    );
    assert_eq!(bucket_capacity(), u64::from(SEC_CRIT_BUCKET_ENTRIES));
    assert_eq!(SEC_CRIT_EVENT_WIRE_BYTES, 64);
}
