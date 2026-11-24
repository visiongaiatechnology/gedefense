use super::*;
use core::mem::{align_of, offset_of, size_of};

fn sample_tap() -> CrossViewEvent {
    CrossViewEvent {
        ts_ns: 987_654_321_000,
        ino: 0,
        pid: 4242,
        uid: 1000,
        dev: 0,
        detail_code: CROSS_VIEW_DETAIL_TAP_FILTER,
        domain: CROSS_VIEW_DOMAIN_NETLINK_FILTER,
        kind: CROSS_VIEW_KIND_RAW_TAP_FILTER,
        severity: CROSS_VIEW_SEVERITY_MEDIUM,
        action: CROSS_VIEW_ACTION_AUDIT,
        comm: *b"dhclient\0\0\0\0\0\0\0\0",
        reserved: [0u8; 12],
    }
}

fn sample_gap() -> CrossViewEvent {
    CrossViewEvent {
        ts_ns: 987_654_321_001,
        ino: 7,
        pid: 0,
        uid: 0,
        dev: 0,
        detail_code: CROSS_VIEW_DETAIL_ID_GAP,
        domain: CROSS_VIEW_DOMAIN_EBPF_ID_GAP,
        kind: CROSS_VIEW_KIND_HIDDEN_PROG,
        severity: CROSS_VIEW_SEVERITY_CRITICAL,
        action: CROSS_VIEW_ACTION_AUDIT,
        comm: *b"hidden-prog\0\0\0\0\0",
        reserved: [0u8; 12],
    }
}

fn encode(event: &CrossViewEvent) -> [u8; CROSS_VIEW_EVENT_WIRE_BYTES] {
    let mut raw = [0u8; CROSS_VIEW_EVENT_WIRE_BYTES];
    raw[0..8].copy_from_slice(&event.ts_ns.to_ne_bytes());
    raw[8..16].copy_from_slice(&event.ino.to_ne_bytes());
    raw[16..20].copy_from_slice(&event.pid.to_ne_bytes());
    raw[20..24].copy_from_slice(&event.uid.to_ne_bytes());
    raw[24..28].copy_from_slice(&event.dev.to_ne_bytes());
    raw[28..32].copy_from_slice(&event.detail_code.to_ne_bytes());
    raw[32] = event.domain;
    raw[33] = event.kind;
    raw[34] = event.severity;
    raw[35] = event.action;
    raw[36..52].copy_from_slice(&event.comm);
    raw[52..64].copy_from_slice(&event.reserved);
    raw
}

#[test]
fn wire_layout_matches_the_64_byte_contract() {
    assert_eq!(size_of::<CrossViewEvent>(), CROSS_VIEW_EVENT_WIRE_BYTES);
    assert_eq!(align_of::<CrossViewEvent>(), 8);
    assert_eq!(offset_of!(CrossViewEvent, ts_ns), 0);
    assert_eq!(offset_of!(CrossViewEvent, ino), 8);
    assert_eq!(offset_of!(CrossViewEvent, pid), 16);
    assert_eq!(offset_of!(CrossViewEvent, uid), 20);
    assert_eq!(offset_of!(CrossViewEvent, dev), 24);
    assert_eq!(offset_of!(CrossViewEvent, detail_code), 28);
    assert_eq!(offset_of!(CrossViewEvent, domain), 32);
    assert_eq!(offset_of!(CrossViewEvent, kind), 33);
    assert_eq!(offset_of!(CrossViewEvent, severity), 34);
    assert_eq!(offset_of!(CrossViewEvent, action), 35);
    assert_eq!(offset_of!(CrossViewEvent, comm), 36);
    assert_eq!(offset_of!(CrossViewEvent, reserved), 52);
    // No implicit padding: the named fields cover all 64 bytes.
    assert_eq!(
        offset_of!(CrossViewEvent, reserved) + 12,
        CROSS_VIEW_EVENT_WIRE_BYTES
    );
}

#[test]
fn decoders_roundtrip_both_producer_shapes() {
    for event in [sample_tap(), sample_gap()] {
        assert_eq!(decode_cross_view_event(&encode(&event)), Some(event));
    }
}

#[test]
fn decoder_rejects_records_the_producers_cannot_have_emitted() {
    let tap = encode(&sample_tap());
    for length in [0usize, 1, 32, 52, 63] {
        assert!(decode_cross_view_event(&tap[..length]).is_none(), "{length}");
    }
    let mut extra = [0u8; CROSS_VIEW_EVENT_WIRE_BYTES + 1];
    extra[..CROSS_VIEW_EVENT_WIRE_BYTES].copy_from_slice(&tap);
    assert!(decode_cross_view_event(&extra).is_none());

    let mut bad = sample_tap();
    bad.ts_ns = 0;
    assert!(decode_cross_view_event(&encode(&bad)).is_none());
    bad = sample_tap();
    bad.domain = 0;
    assert!(decode_cross_view_event(&encode(&bad)).is_none());
    bad = sample_tap();
    bad.domain = CROSS_VIEW_DOMAIN_COUNT + 1;
    assert!(decode_cross_view_event(&encode(&bad)).is_none());
    bad = sample_tap();
    bad.kind = 0;
    assert!(decode_cross_view_event(&encode(&bad)).is_none());
    bad = sample_tap();
    bad.kind = CROSS_VIEW_KIND_RAW_TAP_FILTER + 1;
    assert!(decode_cross_view_event(&encode(&bad)).is_none());
    // Closed domain/kind product: a hidden prog cannot arrive on the pin view.
    bad = sample_tap();
    bad.domain = CROSS_VIEW_DOMAIN_PIN_VIEW;
    bad.kind = CROSS_VIEW_KIND_HIDDEN_PROG;
    assert!(decode_cross_view_event(&encode(&bad)).is_none());
    bad = sample_tap();
    bad.severity = 0;
    assert!(decode_cross_view_event(&encode(&bad)).is_none());
    bad = sample_tap();
    bad.severity = CROSS_VIEW_SEVERITY_CRITICAL + 1;
    assert!(decode_cross_view_event(&encode(&bad)).is_none());
    bad = sample_tap();
    bad.action = 0;
    assert!(decode_cross_view_event(&encode(&bad)).is_none());
    bad = sample_tap();
    bad.action = CROSS_VIEW_ACTION_OBSERVE + 1;
    assert!(decode_cross_view_event(&encode(&bad)).is_none());
    bad = sample_tap();
    bad.reserved[11] = 1;
    assert!(decode_cross_view_event(&encode(&bad)).is_none());
    // comm: control byte, missing NUL, all-zero.
    bad = sample_tap();
    bad.comm = *b"bad\x1bcomm\0\0\0\0\0\0\0\0";
    assert!(decode_cross_view_event(&encode(&bad)).is_none());
    bad = sample_tap();
    bad.comm = *b"no-nul-padding!!";
    assert!(decode_cross_view_event(&encode(&bad)).is_none());
    bad = sample_tap();
    bad.comm = [0u8; 16];
    assert!(decode_cross_view_event(&encode(&bad)).is_none());
    // comm: high-bit byte (non-ASCII task name) and DEL.
    for byte in [0x7fu8, 0x80, 0xff] {
        bad = sample_tap();
        bad.comm[0] = byte;
        assert!(decode_cross_view_event(&encode(&bad)).is_none(), "{byte}");
    }
}

#[test]
fn domain_kind_product_is_closed_and_total() {
    for domain in 1..=CROSS_VIEW_DOMAIN_COUNT {
        let mut kinds = 0;
        for kind in 1..=CROSS_VIEW_KIND_RAW_TAP_FILTER {
            if cross_view_kind_domain_valid(domain, kind) {
                kinds += 1;
            }
        }
        assert!(kinds >= 1, "domain {domain} has no kind");
    }
    assert!(!cross_view_kind_domain_valid(0, 1));
    assert!(!cross_view_kind_domain_valid(1, 0));
    assert!(!cross_view_kind_domain_valid(9, 1));
    assert!(cross_view_kind_domain_valid(
        CROSS_VIEW_DOMAIN_MAP_NAME_VIEW,
        CROSS_VIEW_KIND_HIDDEN_MAP
    ));
    assert!(cross_view_kind_domain_valid(
        CROSS_VIEW_DOMAIN_EBPF_ID_GAP,
        CROSS_VIEW_KIND_LINK_TAMPER
    ));
    assert!(cross_view_kind_domain_valid(
        CROSS_VIEW_DOMAIN_NETLINK_FILTER,
        CROSS_VIEW_KIND_RAW_TAP_FILTER
    ));
}

#[test]
fn state_word_is_armed_only_for_magic_abi_and_armed_bit() {
    let flags = (1 << CROSS_VIEW_STATE_LSM_CREATE_BIT)
        | (1 << CROSS_VIEW_STATE_LSM_SETSOCKOPT_BIT);
    let word = cross_view_state_word(0xdead_beef, true, flags);
    assert!(cross_view_state_armed(word));
    assert_eq!((word & u64::from(u32::MAX)) as u32, 0xdead_beef);
    assert!(cross_view_state_flag(word, CROSS_VIEW_STATE_LSM_CREATE_BIT));
    assert!(cross_view_state_flag(
        word,
        CROSS_VIEW_STATE_LSM_SETSOCKOPT_BIT
    ));
    assert!(!cross_view_state_flag(word, CROSS_VIEW_STATE_KPROBE_BIT));
    assert!(!cross_view_state_armed(cross_view_state_word(1, false, flags)));
    assert!(!cross_view_state_armed(0));
    assert!(!cross_view_state_armed(u64::MAX));
    let mut foreign = word;
    foreign &= !(0xff << CROSS_VIEW_STATE_ABI_SHIFT);
    foreign |= 2 << CROSS_VIEW_STATE_ABI_SHIFT;
    assert!(!cross_view_state_armed(foreign));
    let mut foreign = word;
    foreign &= !(0xff << CROSS_VIEW_STATE_MAGIC_SHIFT);
    foreign |= 0x42 << CROSS_VIEW_STATE_MAGIC_SHIFT;
    assert!(!cross_view_state_armed(foreign));
    assert_eq!(CROSS_VIEW_STATE_MAGIC, 0x58);
    assert_eq!(CROSS_VIEW_STATE_ABI, 1);
}

#[test]
fn wire_bounds_match_the_documented_contract() {
    assert_eq!(CROSS_VIEW_EVENT_RING_BYTES as usize / CROSS_VIEW_EVENT_WIRE_BYTES, 1024);
    assert!(CROSS_VIEW_MAX_DRAIN_PAYLOAD_BYTES >= 4096 / 2);
    assert!(CROSS_VIEW_MAX_REPORT_BYTES <= 4096);
    assert!(CROSS_VIEW_MAX_STATUS_BYTES <= 1024);
    assert!(CROSS_VIEW_SCAN_INTERVAL_MS > CROSS_VIEW_EVENT_SCAN_MIN_GAP_MS);
    // Worst-case 16-record drain must stay inside the payload budget. The
    // longest fixed record: 10 decimal fields + comm hex; 220 bytes is the
    // documented ceiling used by the Go parser as well.
    assert!(220 * CROSS_VIEW_MAX_EVENTS_PER_DRAIN <= CROSS_VIEW_MAX_DRAIN_PAYLOAD_BYTES);
}
