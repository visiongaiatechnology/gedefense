#![cfg(test)]
//! Wave 5a: StyX flow / allow / veto / wire tests moved verbatim from
//! `main_tests.rs` (structure-only split).

use super::*;

fn styx_cidr(family: u8, text: &str) -> styx_flow::StyxCidr {
    styx_flow::parse_cidr(family, text).expect("valid fixture cidr")
}

fn styx_allow(args: &[&str]) -> styx_flow::StyxAllowRequest {
    styx_flow::parse_allow_request(args).expect("valid fixture allow request")
}

#[test]
fn styx_cidr_parsing_accepts_canonical_forms_only() {
    assert_eq!(
        styx_cidr(4, "203.0.113.0/24").address,
        IpAddr::V4(Ipv4Addr::new(203, 0, 113, 0))
    );
    assert_eq!(styx_cidr(4, "203.0.113.7").prefix, 32);
    assert_eq!(styx_cidr(4, "0.0.0.0/0").prefix, 0);
    assert_eq!(styx_cidr(6, "2001:db8::/32").prefix, 32);
    assert_eq!(styx_cidr(6, "::1/128").address, IpAddr::V6(Ipv6Addr::LOCALHOST));
    for (family, token) in [
        (4u8, "203.0.113.9/24"), // host bits set
        (4, "1.2.3.4/0"),
        (4, "0.0.0.0/33"),
        (4, "2001:db8::/32"),
        (6, "203.0.113.0/24"),
        (6, "2001:db8::1/129"),
        (6, "::ffff:1.2.3.4/128"),
        (4, " 10.0.0.0/8"),
        (4, "10.0.0.0/8\n"),
        (4, "10.0.0.0/8\0"),
        (4, ""),
        (4, "10.0.0.0/"),
        (4, "10.0.0.0/8/8"),
        (5, "10.0.0.0/8"),
    ] {
        assert!(
            styx_flow::parse_cidr(family, token).is_err(),
            "{family} {token:?} was accepted"
        );
    }
    let oversized = format!("10.0.0.0/8{}", "0".repeat(140));
    assert!(styx_flow::parse_cidr(4, &oversized).is_err());
}

#[test]
fn styx_veto_cidr_enforces_the_seed_prefix_ranges() {
    for token in [
        "0.0.0.0/8",
        "169.254.0.0/16",
        "100.100.100.200/32",
        "224.0.0.0/4",
    ] {
        assert!(styx_flow::parse_prefix_cidr(4, token).is_ok(), "{token}");
    }
    for token in ["0.0.0.0/0", "10.0.0.0/1", "10.0.0.0/3"] {
        assert!(styx_flow::parse_prefix_cidr(4, token).is_err(), "{token}");
    }
    for token in ["fd00:ec2::254/128", "fe80::/10", "ff00::/8"] {
        assert!(styx_flow::parse_prefix_cidr(6, token).is_ok(), "{token}");
    }
    for token in ["::/0", "2001:db8::/7"] {
        assert!(styx_flow::parse_prefix_cidr(6, token).is_err(), "{token}");
    }
}

#[test]
fn styx_numeric_and_flag_arguments_are_strict() {
    assert_eq!(styx_flow::parse_u16("443").unwrap(), 443);
    assert_eq!(styx_flow::parse_cgroup_id("42").unwrap(), 42);
    for token in ["", " 1", "1 ", "+1", "-1", "0x10", "1_0", "\u{661}"] {
        assert!(styx_flow::parse_u16(token).is_err(), "{token:?}");
    }
    for token in ["0", "1", "2"] {
        assert_eq!(
            styx_flow::parse_mode(token).unwrap(),
            token.parse::<u8>().unwrap()
        );
    }
    for token in ["3", "7", "255", "-1"] {
        assert!(styx_flow::parse_mode(token).is_err(), "{token}");
    }
    assert_eq!(styx_flow::parse_mode_flags("120").unwrap(), 120);
    for token in ["7", "128", "255"] {
        assert!(styx_flow::parse_mode_flags(token).is_err(), "{token}");
    }
    assert_eq!(styx_flow::parse_global_flags("0").unwrap(), 0);
    assert_eq!(
        styx_flow::parse_global_flags("1").unwrap(),
        gedefense_common::STYX_FLAG_LOG_FLOWS
    );
    for token in ["2", "64", "255"] {
        assert!(styx_flow::parse_global_flags(token).is_err(), "{token}");
    }
    assert_eq!(styx_flow::parse_port_range("0", "65535").unwrap(), (0, 65535));
    assert_eq!(styx_flow::parse_port_range("443", "443").unwrap(), (443, 443));
    assert!(styx_flow::parse_port_range("443", "80").is_err());
    for token in ["0", "1", "2", "3"] {
        assert_eq!(
            styx_flow::parse_proto_mask(token).unwrap(),
            token.parse::<u8>().unwrap()
        );
    }
    assert!(styx_flow::parse_proto_mask("4").is_err());
}

#[test]
fn styx_allow_request_validates_scope_family_and_shape() {
    let request = styx_allow(&["4", "cell", "42", "203.0.113.0/24", "0", "65535", "3"]);
    assert_eq!(request.cgroup_id, 42);
    assert_eq!(request.scope, styx_flow::StyxScope::Cell);
    let request = styx_allow(&["6", "global", "0", "2001:db8::/32", "53", "53", "1"]);
    assert_eq!(request.scope, styx_flow::StyxScope::Global);
    assert_eq!(request.cidr.family, 6);
    for args in [
        &["4", "cell", "0", "203.0.113.0/24", "0", "65535", "3"][..],
        &["4", "global", "42", "203.0.113.0/24", "0", "65535", "3"],
        &["5", "cell", "42", "203.0.113.0/24", "0", "65535", "3"],
        &["4", "zone", "42", "203.0.113.0/24", "0", "65535", "3"],
        &["4", "cell", "42", "203.0.113.0/24", "65535", "0", "3"],
        &["4", "cell", "42", "203.0.113.0/24", "0", "65535", "4"],
        &["4", "cell", "42", "203.0.113.9/24", "0", "65535", "3"],
        &["4", "cell", "42"],
    ] {
        assert!(
            styx_flow::parse_allow_request(args).is_err(),
            "{args:?} was accepted"
        );
    }
    assert_eq!(
        styx_flow::parse_allow_request(&["4", "cell"]).unwrap_err(),
        styx_flow::UNKNOWN_COMMAND
    );
}

#[test]
fn styx_command_shapes_reject_unknown_arity_and_bad_values() {
    use styx_flow::UNKNOWN_COMMAND;
    assert_eq!(styx_flow::parse_global_request(&[]).unwrap_err(), UNKNOWN_COMMAND);
    assert_eq!(
        styx_flow::parse_global_request(&["1"]).unwrap_err(),
        UNKNOWN_COMMAND
    );
    assert_eq!(
        styx_flow::parse_global_request(&["1", "0", "0"]).unwrap_err(),
        UNKNOWN_COMMAND
    );
    assert_eq!(styx_flow::parse_global_request(&["1", "0"]).unwrap().mode, 1);
    assert!(styx_flow::parse_global_request(&["3", "0"]).is_err());
    assert_eq!(
        styx_flow::parse_mode_set_request(&["9", "2", "64"]).unwrap(),
        (9, 2, 64)
    );
    assert_eq!(
        styx_flow::parse_mode_set_request(&["0", "2", "0"]).unwrap_err(),
        "styx cgroup id must be non-zero"
    );
    assert_eq!(styx_flow::parse_mode_del_request(&["9"]).unwrap(), 9);
    assert_eq!(
        styx_flow::parse_mode_del_request(&["9", "9"]).unwrap_err(),
        UNKNOWN_COMMAND
    );
    assert_eq!(
        styx_flow::parse_prefix_request(&["4", "169.254.0.0/16"])
            .unwrap()
            .prefix,
        16
    );
    assert_eq!(
        styx_flow::parse_prefix_request(&["4"]).unwrap_err(),
        UNKNOWN_COMMAND
    );
}

#[test]
fn styx_cell_v4_allow_keys_follow_section_four() {
    use styx_flow::StyxAllowKey;
    let cgroup = 0x0102_0304_0506_0708u64;
    match styx_allow(&["4", "cell", "72623859790382856", "0.0.0.0/0", "0", "65535", "3"])
        .allow_key()
        .unwrap()
    {
        StyxAllowKey::CellV4(key, prefix) => {
            assert_eq!(prefix, 64);
            assert_eq!(&key[..8], &cgroup.to_le_bytes());
            assert_eq!(&key[8..], &[0u8; 8]);
        }
        other => panic!("{other:?}"),
    }
    match styx_allow(&["4", "cell", "7", "10.0.0.0/8", "0", "65535", "3"])
        .allow_key()
        .unwrap()
    {
        StyxAllowKey::CellV4(key, prefix) => {
            assert_eq!(prefix, 72);
            assert_eq!(&key[8..12], &[10, 0, 0, 0]);
        }
        other => panic!("{other:?}"),
    }
    match styx_allow(&["4", "cell", "7", "203.0.113.9/32", "443", "443", "3"])
        .allow_key()
        .unwrap()
    {
        StyxAllowKey::CellV4(key, prefix) => {
            assert_eq!(prefix, 112);
            assert_eq!(&key[12..14], &443u16.to_be_bytes());
            assert_eq!(key[14], 0);
        }
        other => panic!("{other:?}"),
    }
    match styx_allow(&["4", "cell", "7", "203.0.113.9/32", "443", "443", "1"])
        .allow_key()
        .unwrap()
    {
        StyxAllowKey::CellV4(key, prefix) => {
            assert_eq!(prefix, 120);
            assert_eq!(key[14], gedefense_common::STYX_PROTO_TCP);
        }
        other => panic!("{other:?}"),
    }
    assert!(styx_allow(&["4", "cell", "7", "10.0.0.0/8", "443", "443", "3"])
        .allow_key()
        .is_err());
    assert!(styx_allow(&["4", "cell", "7", "203.0.113.9/32", "0", "65535", "1"])
        .allow_key()
        .is_err());
    assert!(styx_allow(&["4", "cell", "7", "203.0.113.9/32", "1", "2", "3"])
        .allow_key()
        .is_err());
}

#[test]
fn styx_cell_v6_and_global_keys_follow_section_four() {
    use styx_flow::StyxAllowKey;
    match styx_allow(&["6", "cell", "7", "2001:db8::/64", "53", "53", "1"])
        .allow_key()
        .unwrap()
    {
        StyxAllowKey::CellV6(key, prefix) => {
            assert_eq!(prefix, 128);
            assert_eq!(&key[..8], &7u64.to_le_bytes());
            assert_eq!(&key[8..12], &[0x20, 0x01, 0x0d, 0xb8]);
        }
        other => panic!("{other:?}"),
    }
    match styx_allow(&["4", "global", "0", "203.0.113.0/24", "0", "65535", "3"])
        .allow_key()
        .unwrap()
    {
        StyxAllowKey::GlobalV4(key, prefix) => {
            assert_eq!(prefix, 24);
            assert_eq!(&key[..4], &[203, 0, 113, 0]);
        }
        other => panic!("{other:?}"),
    }
    match styx_allow(&["4", "global", "0", "203.0.113.9/32", "53", "53", "2"])
        .allow_key()
        .unwrap()
    {
        StyxAllowKey::GlobalV4(key, prefix) => {
            assert_eq!(prefix, 56);
            assert_eq!(&key[4..6], &53u16.to_be_bytes());
            assert_eq!(key[6], gedefense_common::STYX_PROTO_UDP);
        }
        other => panic!("{other:?}"),
    }
    // §4 prefixes 48 (global-v4 +port) and 144/152 (global-v6) as well as
    // the full 192-bit cell-v6 lookup key must be exactly reproducible.
    match styx_allow(&["4", "global", "0", "203.0.113.9/32", "53", "53", "3"])
        .allow_key()
        .unwrap()
    {
        StyxAllowKey::GlobalV4(_, prefix) => assert_eq!(prefix, 48),
        other => panic!("{other:?}"),
    }
    match styx_allow(&["6", "cell", "7", "2001:db8::1/128", "0", "65535", "3"])
        .allow_key()
        .unwrap()
    {
        StyxAllowKey::CellV6(_, prefix) => assert_eq!(prefix, 192),
        other => panic!("{other:?}"),
    }
    match styx_allow(&["6", "global", "0", "2001:db8::1/128", "853", "853", "3"])
        .allow_key()
        .unwrap()
    {
        StyxAllowKey::GlobalV6(_, prefix) => assert_eq!(prefix, 144),
        other => panic!("{other:?}"),
    }
    match styx_allow(&["6", "global", "0", "2001:db8::/128", "853", "853", "1"])
        .allow_key()
        .unwrap()
    {
        StyxAllowKey::GlobalV6(key, prefix) => {
            assert_eq!(prefix, 152);
            assert_eq!(&key[16..18], &853u16.to_be_bytes());
            assert_eq!(key[18], gedefense_common::STYX_PROTO_TCP);
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn styx_policy_prefix_keys_are_bare_networks() {
    use styx_flow::StyxPrefixKey;
    assert_eq!(
        styx_flow::parse_prefix_cidr(4, "169.254.0.0/16")
            .unwrap()
            .prefix_key()
            .unwrap(),
        StyxPrefixKey::V4([169, 254, 0, 0], 16)
    );
    match styx_flow::parse_prefix_cidr(6, "fe80::/10")
        .unwrap()
        .prefix_key()
        .unwrap()
    {
        StyxPrefixKey::V6(key, prefix) => {
            assert_eq!(prefix, 10);
            assert_eq!(&key[..2], &[0xfe, 0x80]);
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn styx_global_word_packs_epoch_flags_and_mode() {
    let word =
        styx_flow::encode_styx_global(0xdead_beef, 2, gedefense_common::STYX_FLAG_LOG_FLOWS);
    assert_eq!(word & 0xffff_ffff, 0xdead_beef);
    assert_eq!(
        (word >> 32) as u8,
        gedefense_common::STYX_FLAG_LOG_FLOWS
    );
    assert_eq!((word >> 40) as u8, 2);
    assert_eq!(styx_flow::encode_styx_global(1, 0, 0), 1);
}

fn styx_fixture_event() -> gedefense_common::FlowEvent {
    gedefense_common::FlowEvent {
        cgroup_id: 0x0102_0304_0506_0708,
        ts_ns: 9,
        tx_bytes: 10,
        rx_bytes: 0,
        pid: 42,
        uid: 1000,
        dst: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 203, 0, 113, 9],
        src: [0u8; 16],
        dst_port: 443,
        src_port: 51_234,
        packets: 3,
        proto: gedefense_common::STYX_PROTO_TCP,
        family: NETWORK_FAMILY_V4,
        direction: gedefense_common::STYX_DIR_EGRESS,
        tcp_flags: 0x18,
        verdict: gedefense_common::STYX_VERDICT_ALLOW,
        reserved: [0; 3],
        comm: *b"curl\0\0\0\0\0\0\0\0\0\0\0\0",
    }
}

#[test]
fn styx_flow_text_wire_matches_the_contract() {
    let text =
        styx_flow::encode_styx_flow_event_text(&styx_fixture_event()).expect("encodable event");
    assert_eq!(
        text,
        "0102030405060708:9:10:0:42:1000:cb007109:443:51234:3:4:6:1:24:0:6375726c"
    );
    assert_eq!(text.split(':').count(), 16);
    // A comm with bytes the Go decoder refuses degrades to an empty field ...
    let mut event = styx_fixture_event();
    event.comm = *b"Web Content\0\0\0\0\0";
    let text = styx_flow::encode_styx_flow_event_text(&event).expect("encodable event");
    assert!(text.ends_with(':'), "comm field not degraded: {text}");
    // ... while non-representable records are skipped instead of poisoning
    // an entire batch.
    let mut event = styx_fixture_event();
    event.pid = i32::MAX as u32 + 1;
    assert!(styx_flow::encode_styx_flow_event_text(&event).is_none());
    let mut event = styx_fixture_event();
    event.family = NETWORK_FAMILY_V6;
    event.dst = [0u8; 16];
    assert!(styx_flow::encode_styx_flow_event_text(&event).is_none());
    let mut event = styx_fixture_event();
    event.comm = [b'x'; 16];
    assert!(styx_flow::encode_styx_flow_event_text(&event).is_none());
}

#[test]
fn styx_flow_batch_is_bounded_and_reports_drops() {
    // 6.2.0 flow-telemetry contract: the eBPF ring grew to 16 MiB, the core
    // drains 64 records per poll and the response ceiling covers the whole
    // base64url-encoded batch. Pinning the numbers here makes an accidental
    // rollback to the 8-record/2048-byte StyX limits fail loudly.
    assert_eq!(styx_flow::MAX_STYX_FLOW_EVENTS_PER_RESPONSE, 64);
    assert_eq!(styx_flow::MAX_STYX_FLOW_PAYLOAD_BYTES, 16 * 1024);
    assert_eq!(MAX_RESPONSE_BYTES, 24 * 1024);
    // base64url(16 KiB) plus the "VGT3R <nonce> <status> <payload> <mac>"
    // line must fit the control-plane reader after the Go-side update.
    assert!(styx_flow::MAX_STYX_FLOW_PAYLOAD_BYTES.div_ceil(3) * 4 + 128 < MAX_RESPONSE_BYTES);
    assert_eq!(styx_flow_batch_response(&[], 0), "empty");
    assert_eq!(styx_flow_batch_response(&[], 7), "7|");
    assert_eq!(
        styx_flow_batch_response(&["a".to_owned(), "b".to_owned()], 3),
        "3|a,b"
    );
    let mut event = styx_fixture_event();
    event.cgroup_id = u64::MAX;
    event.ts_ns = u64::MAX;
    event.tx_bytes = u64::MAX;
    event.rx_bytes = u64::MAX;
    event.pid = i32::MAX as u32;
    event.uid = u32::MAX;
    event.packets = u32::MAX;
    event.family = NETWORK_FAMILY_V6;
    event.dst = [0xff; 16];
    event.proto = 0;
    event.tcp_flags = 0;
    event.dst_port = 0;
    event.src_port = 0;
    event.comm = *b"fifteen-char-na\0";
    let record = styx_flow::encode_styx_flow_event_text(&event).expect("maximal record");
    let records = vec![record; styx_flow::MAX_STYX_FLOW_EVENTS_PER_RESPONSE];
    let batch = styx_flow_batch_response(&records, u64::MAX);
    assert_eq!(
        batch.split(',').count(),
        styx_flow::MAX_STYX_FLOW_EVENTS_PER_RESPONSE
    );
    assert!(
        batch.len() <= styx_flow::MAX_STYX_FLOW_PAYLOAD_BYTES,
        "batch of {batch:?} bytes"
    );
}

#[test]
fn styx_flow_health_has_six_decimal_fields() {
    assert_eq!(
        styx_flow::encode_styx_flow_health(&[1, 2, 3, 4, 5, 6]),
        "1:2:3:4:5:6"
    );
    let maximal = styx_flow::encode_styx_flow_health(&[u64::MAX; 6]);
    assert_eq!(maximal.split(':').count(), 6);
    assert!(maximal.len() <= 160);
}

#[test]
fn styx_epoch_is_sixteen_lowercase_hex_characters() {
    let (value, hex_epoch) = random_styx_epoch().expect("random epoch");
    assert_eq!(hex_epoch.len(), 16);
    assert!(hex_epoch
        .bytes()
        .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()));
    assert_eq!(hex_epoch, format!("{value:016x}"));
}

#[test]
fn styx_map_results_are_explicit_and_deletes_idempotent() {
    assert_eq!(styx_map_result(Ok(()), true).unwrap(), "added");
    assert_eq!(styx_map_result(Ok(()), false).unwrap(), "deleted");
    assert_eq!(
        styx_map_result(Err(MapError::KeyNotFound), false).unwrap(),
        "deleted"
    );
    assert!(styx_map_result(Err(MapError::KeyNotFound), true).is_err());
    assert!(styx_map_result(Err(MapError::InvalidMapType { map_type: 0 }), false).is_err());
}

// ---- Point 1: synthetic BTF fixtures for the mini parser (§4.1/§6). ----
//
// The parser module is capped at 500 lines, so its fixtures live here. The
// `6.18`/`7.0` layouts below use the §4.1 golden values (BTF-verified on
// those kernels); broken variants must be `Err`, never a heuristic.
