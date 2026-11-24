use gedefense_common::{
    dns_capture_tail_len, DNS_CAPTURE_FLAG_SUBDOMAIN_TRUNCATED,
};

use super::*;
use gedefense_common::{
    encode_dns_capture_event, DNS_CAPTURE_COMM_BYTES, DNS_CAPTURE_EVENT_WIRE_BYTES,
    DNS_CAPTURE_FLAG_LONG_FQDN, DNS_CAPTURE_FLAG_SUFFIX_TRUNCATED, DNS_CAPTURE_MAX_QNAME_TAIL,
    DNS_CAPTURE_QNAME_TAIL_BYTES, DNS_CAPTURE_STATE_ABI, DNS_CAPTURE_STATE_ABI_SHIFT,
    DNS_CAPTURE_STATE_ARMED_SHIFT, DNS_CAPTURE_STATE_MAGIC, DNS_CAPTURE_STATE_MAGIC_SHIFT,
    DNS_CAPTURE_SUBDOMAIN_BYTES, DNS_QTYPE_TXT,
};

/// Builds the QNAME wire bytes of a name.
fn wire_name(labels: &[&[u8]]) -> Vec<u8> {
    let mut wire = Vec::new();
    for label in labels {
        wire.push(label.len() as u8);
        wire.extend_from_slice(label);
    }
    wire.push(0);
    wire
}

/// Builds the kernel producer shape for one name.
fn event_for(
    labels: &[&[u8]],
    qtype: u16,
    comm: [u8; DNS_CAPTURE_COMM_BYTES],
) -> DnsCaptureEvent {
    let wire = wire_name(labels);
    let wire_len = wire.len();
    let fqdn_len = (wire_len - 2) as u8;
    let tail_len = dns_capture_tail_len(wire_len);
    let tail_start = wire_len - tail_len;
    let mut qname_tail = [0u8; DNS_CAPTURE_QNAME_TAIL_BYTES];
    qname_tail[..tail_len].copy_from_slice(&wire[tail_start..]);
    let first = labels[0];
    let mut subdomain = [0u8; DNS_CAPTURE_SUBDOMAIN_BYTES];
    let stored = first.len().min(DNS_CAPTURE_SUBDOMAIN_BYTES);
    subdomain[..stored].copy_from_slice(&first[..stored]);
    let mut flags = 0u8;
    if fqdn_len > 50 {
        flags |= DNS_CAPTURE_FLAG_LONG_FQDN;
    }
    if first.len() > DNS_CAPTURE_SUBDOMAIN_BYTES {
        flags |= DNS_CAPTURE_FLAG_SUBDOMAIN_TRUNCATED;
    }
    if wire_len > DNS_CAPTURE_MAX_QNAME_TAIL {
        flags |= DNS_CAPTURE_FLAG_SUFFIX_TRUNCATED;
    }
    DnsCaptureEvent {
        ts_ns: 1_700_000_000_000_000_000,
        pid: 4242,
        tgid: 4241,
        uid: 1000,
        query_id: 0xbeef,
        qtype,
        flags,
        label_count: 0,
        fqdn_len,
        sub_len: stored as u8,
        subdomain,
        qname_tail,
        comm,
    }
}

fn encode_state_word(epoch: u64, armed: bool) -> u64 {
    dns_capture_state_word(epoch as u32, armed)
}

#[test]
fn state_word_carries_epoch_armed_magic_and_abi() {
    let word = encode_state_word(0xdead_beef_cafe_f00d, true);
    assert!(gedefense_common::dns_capture_state_armed(word));
    assert_eq!((word & u64::from(u32::MAX)) as u32, 0xcafe_f00d);
    assert_eq!((word >> DNS_CAPTURE_STATE_ARMED_SHIFT) & 1, 1, "armed bit");
    assert_eq!(
        (word >> DNS_CAPTURE_STATE_MAGIC_SHIFT) & 0xff,
        u64::from(DNS_CAPTURE_STATE_MAGIC)
    );
    assert_eq!(
        (word >> DNS_CAPTURE_STATE_ABI_SHIFT) & 0xff,
        u64::from(DNS_CAPTURE_STATE_ABI)
    );
    assert!(!gedefense_common::dns_capture_state_armed(
        encode_state_word(7, false)
    ));
    assert!(!gedefense_common::dns_capture_state_armed(0));
    assert_eq!(DNS_CAPTURE_STATE_ABI, 1);
}

#[test]
fn epoch_rendering_is_sixteen_lowercase_hex_chars() {
    let epoch = random_epoch();
    assert_ne!(epoch, 0);
    let rendered = format!("{epoch:016x}");
    assert_eq!(rendered.len(), 16);
    assert!(rendered
        .chars()
        .all(|character| character.is_ascii_hexdigit() && !character.is_ascii_uppercase()));
}

#[test]
fn event_text_record_has_eight_bounded_fields() {
    let benign = event_for(&[b"a", b"example", b"com"], 28, *b"curl\0\0\0\0");
    let record = encode_event_text(&benign).expect("benign record");
    assert_eq!(record.split(':').count(), 8);
    assert_eq!(
        record,
        "1700000000000000000:4242:4241:1000:28:6375726c:612e6578616d706c652e636f6d:13"
    );

    // A long, clipped tunnel record keeps the first-label prefix and the
    // label-aligned registrable suffix plus the full FQDN length.
    let long_label = "0123456789012345678901234567890123456789";
    let tunnel = event_for(
        &[long_label.as_bytes(), b"example", b"com"],
        DNS_QTYPE_TXT,
        *b"dnscat2\0",
    );
    let record = encode_event_text(&tunnel).expect("tunnel record");
    let fields: Vec<&str> = record.split(':').collect();
    assert_eq!(fields.len(), 8);
    assert_eq!(fields[4], "16");
    assert_eq!(fields[5], "646e7363617432");
    assert_eq!(fields[7], "52");
    assert_eq!(
        fields[6],
        hex::encode("012345678901.example.com"),
        "clipped suffix view"
    );

    // Single-label / pxy-style name: the complete wire form fits the tail.
    let single = event_for(&[b"localhost"], 1, *b"nslooku\0");
    let record = encode_event_text(&single).expect("single-label record");
    assert_eq!(
        record.split(':').nth(6),
        Some(hex::encode("localhost").as_str())
    );

    // Worst-case 16-record batch fits the documented payload budget.
    let max_record = "18446744073709551615:4294967295:4294967295:4294967295:65535:0011223344556677:00112233445566778899aabbccddeeff0011223344556677:62";
    assert_eq!(max_record.split(':').count(), 8);
    let worst_batch = max_record.len() * DNS_CAPTURE_MAX_EVENTS_PER_DRAIN
        + DNS_CAPTURE_MAX_EVENTS_PER_DRAIN
        + 24;
    assert!(worst_batch <= DNS_CAPTURE_MAX_DRAIN_PAYLOAD_BYTES);
    assert!(DNS_CAPTURE_EVENT_WIRE_BYTES >= 64);
}

#[test]
fn wire_inconsistencies_are_rejected_by_the_core_view() {
    let benign = event_for(&[b"a", b"example", b"com"], 1, *b"curl\0\0\0\0");
    assert!(encode_event_text(&benign).is_some());
    // The shared decoder must accept the producer shape.
    let raw = encode_dns_capture_event(&benign);
    assert!(decode_dns_capture_event(&raw).is_some());

    // Subdomain bytes that do not match the first label of the stored wire.
    let mut mismatched = benign;
    mismatched.subdomain[0] = b'z';
    assert!(encode_event_text(&mismatched).is_none());

    // A clipped tail whose phase cannot be resolved (no root at the end).
    let long_label = "0123456789012345678901234567890123456789";
    let mut unresolvable = event_for(
        &[long_label.as_bytes(), b"example", b"com"],
        1,
        *b"curl\0\0\0\0",
    );
    for byte in unresolvable.qname_tail.iter_mut() {
        *byte = b'A';
    }
    assert!(encode_event_text(&unresolvable).is_none());
    unresolvable.qname_tail[15] = 0;
    assert!(encode_event_text(&unresolvable).is_none());

    // A fully stored record whose length disagrees with its wire view.
    let mut too_long = benign;
    too_long.fqdn_len = 3;
    assert!(encode_event_text(&too_long).is_none());
}
