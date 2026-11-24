use super::*;
use core::mem::{align_of, offset_of, size_of};

/// Builds a fully stored short QNAME in wire form, e.g. `www.example.com`.
fn wire_name(labels: &[&[u8]]) -> ([u8; DNS_CAPTURE_QNAME_TAIL_BYTES], usize, u8) {
    let mut tail = [0u8; DNS_CAPTURE_QNAME_TAIL_BYTES];
    let mut at = 0usize;
    for label in labels {
        tail[at] = label.len() as u8;
        at += 1;
        tail[at..at + label.len()].copy_from_slice(label);
        at += label.len();
    }
    tail[at] = 0;
    at += 1;
    // Presentation length: sum(label chars) + (labels - 1) dots.
    let chars: usize = labels.iter().map(|label| label.len()).sum();
    let presentation = chars + labels.len() - 1;
    (tail, at, presentation as u8)
}

fn base_event() -> DnsCaptureEvent {
    // "a.example.com" needs 15 QNAME wire bytes and fits the tail slot
    // exactly, so this is the un-truncated producer shape.
    let (tail, _wire_len, presentation) = wire_name(&[b"a", b"example", b"com"]);
    DnsCaptureEvent {
        ts_ns: 1_700_000_000_000_000_000,
        pid: 4242,
        tgid: 4241,
        uid: 1000,
        query_id: 0xbeef,
        qtype: DNS_QTYPE_A,
        flags: 0,
        label_count: 0,
        fqdn_len: presentation,
        sub_len: 1,
        subdomain: *b"a\0\0\0\0\0\0\0\0\0\0\0",
        qname_tail: tail,
        comm: *b"curl\0\0\0\0",
    }
}

fn encode(event: &DnsCaptureEvent) -> [u8; DNS_CAPTURE_EVENT_WIRE_BYTES] {
    encode_dns_capture_event(event)
}

#[test]
fn wire_layout_matches_the_64_byte_contract() {
    assert_eq!(size_of::<DnsCaptureEvent>(), DNS_CAPTURE_EVENT_WIRE_BYTES);
    assert_eq!(align_of::<DnsCaptureEvent>(), 8);
    assert_eq!(offset_of!(DnsCaptureEvent, ts_ns), 0);
    assert_eq!(offset_of!(DnsCaptureEvent, pid), 8);
    assert_eq!(offset_of!(DnsCaptureEvent, tgid), 12);
    assert_eq!(offset_of!(DnsCaptureEvent, uid), 16);
    assert_eq!(offset_of!(DnsCaptureEvent, query_id), 20);
    assert_eq!(offset_of!(DnsCaptureEvent, qtype), 22);
    assert_eq!(offset_of!(DnsCaptureEvent, flags), 24);
    assert_eq!(offset_of!(DnsCaptureEvent, label_count), 25);
    assert_eq!(offset_of!(DnsCaptureEvent, fqdn_len), 26);
    assert_eq!(offset_of!(DnsCaptureEvent, sub_len), 27);
    assert_eq!(offset_of!(DnsCaptureEvent, subdomain), 28);
    assert_eq!(offset_of!(DnsCaptureEvent, qname_tail), 40);
    assert_eq!(offset_of!(DnsCaptureEvent, comm), 56);
    // Every byte is a named field: a stored record cannot leak
    // uninitialised stack bytes into the ring.
    assert_eq!(
        offset_of!(DnsCaptureEvent, comm) + DNS_CAPTURE_COMM_BYTES,
        DNS_CAPTURE_EVENT_WIRE_BYTES
    );
    assert_eq!(
        DNS_CAPTURE_EVENT_RING_BYTES as usize / DNS_CAPTURE_EVENT_WIRE_BYTES,
        1024
    );
}

#[test]
fn decoder_roundtrips_every_producer_shape() {
    let benign = base_event();
    assert_eq!(decode_dns_capture_event(&encode(&benign)), Some(benign));
    assert_eq!(benign.qname_tail_bytes(), b"\x01a\x07example\x03com\x00");
    assert_eq!(benign.subdomain_bytes(), b"a");

    // Long FQDN (clipped tail, clipped first label). The decoder validates
    // structure only; the core parses the wire tail labels.
    let mut tail = [0u8; DNS_CAPTURE_QNAME_TAIL_BYTES];
    for (index, byte) in tail.iter_mut().take(15).enumerate() {
        *byte = (index as u8) + 1;
    }
    let tunnel = DnsCaptureEvent {
        ts_ns: 1,
        pid: 7,
        tgid: 7,
        uid: 0,
        query_id: 1,
        qtype: DNS_QTYPE_TXT,
        flags: DNS_CAPTURE_FLAG_LONG_FQDN
            | DNS_CAPTURE_FLAG_SUBDOMAIN_TRUNCATED
            | DNS_CAPTURE_FLAG_SUFFIX_TRUNCATED
            | DNS_CAPTURE_FLAG_RD
            | DNS_CAPTURE_FLAG_VIA_SENDMSG,
        label_count: 0,
        fqdn_len: 60,
        sub_len: 12,
        subdomain: *b"aGVsbG8gd29y",
        qname_tail: tail,
        comm: *b"dnscat2\0",
    };
    assert_eq!(decode_dns_capture_event(&encode(&tunnel)), Some(tunnel));
    assert_eq!(tunnel.qname_tail_bytes(), &tail[..15]);

    // Single-label / pxy-style name: whole QNAME wire fits the tail.
    let single = DnsCaptureEvent {
        ts_ns: 3,
        pid: 8,
        tgid: 8,
        uid: 1000,
        query_id: 2,
        qtype: DNS_QTYPE_NULL,
        flags: 0,
        label_count: 0,
        fqdn_len: 9,
        sub_len: 9,
        subdomain: *b"localhost\0\0\0",
        qname_tail: *b"\x09localhost\0\0\0\0\0\0",
        comm: *b"nslooku\0",
    };
    assert_eq!(decode_dns_capture_event(&encode(&single)), Some(single));

    // Any non-zero raw QTYPE is preserved (CAA, unknown experimental).
    for qtype in [DNS_QTYPE_CAA, 65_000, u16::MAX] {
        let event = DnsCaptureEvent {
            qtype,
            ..base_event()
        };
        assert_eq!(
            decode_dns_capture_event(&encode(&event)),
            Some(event),
            "qtype {qtype}"
        );
    }
}

#[test]
fn rejects_records_the_kernel_cannot_have_emitted() {
    let base = base_event();
    let raw = encode(&base);
    for length in [0usize, 1, 32, 48, 63] {
        assert!(
            decode_dns_capture_event(&raw[..length]).is_none(),
            "{length}"
        );
    }
    let mut extra = [0u8; DNS_CAPTURE_EVENT_WIRE_BYTES + 1];
    extra[..DNS_CAPTURE_EVENT_WIRE_BYTES].copy_from_slice(&raw);
    assert!(decode_dns_capture_event(&extra).is_none());

    let mutations: &[(fn(&mut DnsCaptureEvent), &str)] = &[
        (|event| event.ts_ns = 0, "ts 0"),
        (|event| event.pid = 0, "pid 0"),
        (|event| event.tgid = 0, "tgid 0"),
        (|event| event.qtype = 0, "qtype 0"),
        (|event| event.flags = 1 << 5, "unknown flag bit"),
        (|event| event.flags = 0xff, "all flag bits"),
        (|event| event.label_count = 9, "label count 9"),
        (|event| event.fqdn_len = 0, "fqdn len 0"),
        (|event| event.fqdn_len = 63, "fqdn len 63"),
        (|event| event.sub_len = 0, "sub len 0"),
        (|event| event.sub_len = 13, "sub len 13"),
        (
            |event| event.subdomain[3] = b'x',
            "non-zero padding after sub_len",
        ),
        (|event| event.subdomain[0] = b'.', "dot inside first label"),
        (
            |event| event.subdomain[0] = b' ',
            "space inside first label",
        ),
        (
            |event| event.comm = [0u8; DNS_CAPTURE_COMM_BYTES],
            "empty comm",
        ),
        (|event| event.comm = *b"12345678", "unpadded comm"),
        (|event| event.comm[0] = 0x01, "control comm byte"),
        (
            |event| event.flags |= DNS_CAPTURE_FLAG_LONG_FQDN,
            "long fqdn flag with short name",
        ),
        (
            |event| event.flags |= DNS_CAPTURE_FLAG_SUBDOMAIN_TRUNCATED,
            "subdomain truncation at sub_len 3",
        ),
        (
            |event| event.flags |= DNS_CAPTURE_FLAG_SUFFIX_TRUNCATED,
            "suffix truncation for a short name",
        ),
        (
            |event| event.fqdn_len = 16,
            "fqdn len mismatch (tail width)",
        ),
        (
            |event| event.label_count = 8,
            "label count too large for length",
        ),
        (|event| event.qname_tail[15] = b'x', "non-zero tail padding"),
    ];
    for (mutate, label) in mutations {
        let mut event = base;
        mutate(&mut event);
        assert!(
            decode_dns_capture_event(&encode(&event)).is_none(),
            "{label}"
        );
    }

    // Long FQDN flag requires fqdn_len > 50 (and, at that length, the tail
    // must be the clipped 15-byte form).
    let mut long = base;
    long.fqdn_len = 51;
    assert!(decode_dns_capture_event(&encode(&long)).is_none());
    long.flags |= DNS_CAPTURE_FLAG_LONG_FQDN | DNS_CAPTURE_FLAG_SUFFIX_TRUNCATED;
    assert!(decode_dns_capture_event(&encode(&long)).is_some());
    long.fqdn_len = 50;
    assert!(decode_dns_capture_event(&encode(&long)).is_none());

    // Multi-label names need a presentation length that can host the dots.
    let mut too_short = base;
    too_short.fqdn_len = 4;
    assert!(decode_dns_capture_event(&encode(&too_short)).is_none());
}

#[test]
fn qtype_classification_covers_the_documented_set() {
    for (qtype, name) in [
        (1u16, "A"),
        (2, "NS"),
        (5, "CNAME"),
        (6, "SOA"),
        (10, "NULL"),
        (12, "PTR"),
        (15, "MX"),
        (16, "TXT"),
        (28, "AAAA"),
        (33, "SRV"),
        (255, "ANY"),
        (257, "CAA"),
    ] {
        assert!(dns_qtype_known(qtype), "{name}");
    }
    for unknown in [0u16, 3, 13, 99, 256, 65_535] {
        assert!(!dns_qtype_known(unknown), "{unknown}");
    }
    assert!(dns_qtype_is_txt_or_null(DNS_QTYPE_TXT));
    assert!(dns_qtype_is_txt_or_null(DNS_QTYPE_NULL));
    assert!(!dns_qtype_is_txt_or_null(DNS_QTYPE_A));
    assert!(!dns_qtype_is_txt_or_null(DNS_QTYPE_AAAA));
}

#[test]
fn state_word_is_armed_only_for_the_current_magic_abi_and_armed_bit() {
    let word = dns_capture_state_word(0xdead_beef, true);
    assert!(dns_capture_state_armed(word));
    assert_eq!((word & u64::from(u32::MAX)) as u32, 0xdead_beef);
    assert_eq!(
        (word >> DNS_CAPTURE_STATE_MAGIC_SHIFT) & DNS_CAPTURE_STATE_BYTE_MASK,
        u64::from(DNS_CAPTURE_STATE_MAGIC)
    );
    assert_eq!(DNS_CAPTURE_STATE_MAGIC, b'D');
    assert_eq!(DNS_CAPTURE_STATE_ABI, 1);
    assert!(!dns_capture_state_armed(dns_capture_state_word(1, false)));
    assert!(!dns_capture_state_armed(0));
    assert!(!dns_capture_state_armed(u64::MAX));
    let mut foreign = word;
    foreign &= !(0xff << DNS_CAPTURE_STATE_ABI_SHIFT);
    foreign |= 2 << DNS_CAPTURE_STATE_ABI_SHIFT;
    assert!(!dns_capture_state_armed(foreign));
    assert_eq!(DNS_CAPTURE_COUNTER_LANES, 4);
    assert_eq!(DNS_CAPTURE_COUNTER_EMITTED, 0);
    assert_eq!(DNS_CAPTURE_COUNTER_RING_DROPS, 1);
    assert_eq!(DNS_CAPTURE_COUNTER_READ_FAILURES, 2);
    assert_eq!(DNS_CAPTURE_COUNTER_PROBES, 3);
}

#[test]
fn tail_length_is_derived_from_the_validated_lengths() {
    assert_eq!(dns_capture_tail_len(0), 0);
    assert_eq!(dns_capture_tail_len(15), 15);
    assert_eq!(dns_capture_tail_len(16), 15);
    assert_eq!(dns_capture_tail_len(64), 15);
    let event = base_event();
    assert_eq!(event.qname_wire_len(), 15);
    assert_eq!(event.comm_bytes(), b"curl");
}
