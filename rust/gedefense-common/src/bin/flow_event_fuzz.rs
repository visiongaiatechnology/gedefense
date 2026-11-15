//! Host-side fuzz harness for the Point-3 flow-event wire decoder
//! `gedefense_common::decode_styx_flow_event`.
//!
//! Input protocol: up to `STYX_FLOW_EVENT_WIRE_BYTES + 1` bytes are read from
//! stdin and passed to the exact decoder the privileged core uses, so any panic
//! or acceptance of an impossible record is a real decoder finding. Empty stdin
//! runs a deterministic seed corpus of valid and invalid 104-byte records plus
//! a byte-mutation sweep. Every wire offset is spelled out here instead of
//! relying on the struct layout, so the corpus independently pins the ABI table
//! from `docs/POINT3-EGRESS-BEACON.md` §3.2.

use gedefense_common::{
    decode_styx_flow_event, FlowEvent, NETWORK_FAMILY_V4, NETWORK_FAMILY_V6, STYX_DIR_EGRESS,
    STYX_DIR_INGRESS, STYX_FLOW_EVENT_WIRE_BYTES, STYX_PROTO_TCP, STYX_PROTO_UDP,
    STYX_PROTO_UNKNOWN, STYX_VERDICT_ALLOW, STYX_VERDICT_DEFAULT_DENY,
};
use std::io::{self, Read};

const OFF_CGROUP_ID: usize = 0;
const OFF_TS_NS: usize = 8;
const OFF_TX_BYTES: usize = 16;
const OFF_RX_BYTES: usize = 24;
const OFF_PID: usize = 32;
const OFF_UID: usize = 36;
const OFF_DST: usize = 40;
const OFF_SRC: usize = 56;
const OFF_DST_PORT: usize = 72;
const OFF_SRC_PORT: usize = 74;
const OFF_PACKETS: usize = 76;
const OFF_PROTO: usize = 80;
const OFF_FAMILY: usize = 81;
const OFF_DIRECTION: usize = 82;
const OFF_TCP_FLAGS: usize = 83;
const OFF_VERDICT: usize = 84;
const OFF_COMM: usize = 88;

fn decode(raw: &[u8]) -> Option<FlowEvent> {
    std::hint::black_box(decode_styx_flow_event(raw))
}

fn require_valid(raw: &[u8]) -> FlowEvent {
    decode(raw).expect("valid seed record was rejected")
}

fn require_rejected(raw: &[u8]) {
    assert!(decode(raw).is_none(), "invalid seed record was accepted");
}

/// Every invariant §3.2 promises for an accepted record. A decoder that repairs
/// instead of rejecting would still fail this check.
fn assert_contract(event: &FlowEvent) {
    assert!(matches!(event.family, NETWORK_FAMILY_V4 | NETWORK_FAMILY_V6));
    assert!(event.ts_ns > 0 && event.packets > 0);
    assert!(event.verdict <= STYX_VERDICT_DEFAULT_DENY);
    assert!(matches!(
        event.direction,
        STYX_DIR_EGRESS | STYX_DIR_INGRESS
    ));
    assert!(matches!(
        event.proto,
        STYX_PROTO_UNKNOWN | STYX_PROTO_TCP | STYX_PROTO_UDP
    ));
    if event.proto != STYX_PROTO_TCP {
        assert_eq!(event.tcp_flags, 0);
    }
    if event.proto == STYX_PROTO_UNKNOWN {
        assert_eq!((event.dst_port, event.src_port), (0, 0));
    }
    if event.family == NETWORK_FAMILY_V4 {
        assert!(event.dst[..12].iter().all(|byte| *byte == 0));
        assert!(event.dst[12..].iter().any(|byte| *byte != 0));
    }
}

/// Serialises a valid IPv4/TCP/egress record with the documented ABI offsets.
fn valid_ipv4_record() -> [u8; STYX_FLOW_EVENT_WIRE_BYTES] {
    let mut raw = [0u8; STYX_FLOW_EVENT_WIRE_BYTES];
    raw[OFF_CGROUP_ID..OFF_CGROUP_ID + 8].copy_from_slice(&0x0102_0304_0506_0708u64.to_ne_bytes());
    raw[OFF_TS_NS..OFF_TS_NS + 8].copy_from_slice(&9_876_543_210u64.to_ne_bytes());
    raw[OFF_TX_BYTES..OFF_TX_BYTES + 8].copy_from_slice(&65_536u64.to_ne_bytes());
    raw[OFF_RX_BYTES..OFF_RX_BYTES + 8].copy_from_slice(&0u64.to_ne_bytes());
    raw[OFF_PID..OFF_PID + 4].copy_from_slice(&4242u32.to_ne_bytes());
    raw[OFF_UID..OFF_UID + 4].copy_from_slice(&1000u32.to_ne_bytes());
    raw[OFF_DST + 12..OFF_DST + 16].copy_from_slice(&[203, 0, 113, 9]);
    raw[OFF_SRC + 12..OFF_SRC + 16].copy_from_slice(&[192, 0, 2, 10]);
    raw[OFF_DST_PORT..OFF_DST_PORT + 2].copy_from_slice(&443u16.to_ne_bytes());
    raw[OFF_SRC_PORT..OFF_SRC_PORT + 2].copy_from_slice(&51_234u16.to_ne_bytes());
    raw[OFF_PACKETS..OFF_PACKETS + 4].copy_from_slice(&12u32.to_ne_bytes());
    raw[OFF_PROTO] = STYX_PROTO_TCP;
    raw[OFF_FAMILY] = NETWORK_FAMILY_V4;
    raw[OFF_DIRECTION] = STYX_DIR_EGRESS;
    raw[OFF_TCP_FLAGS] = 0x18;
    raw[OFF_VERDICT] = STYX_VERDICT_ALLOW;
    raw[OFF_COMM..OFF_COMM + 4].copy_from_slice(b"curl");
    raw
}

/// Same as [`valid_ipv4_record`] but with a real IPv6 destination/source.
fn valid_ipv6_record() -> [u8; STYX_FLOW_EVENT_WIRE_BYTES] {
    let mut raw = valid_ipv4_record();
    raw[OFF_FAMILY] = NETWORK_FAMILY_V6;
    raw[OFF_DST..OFF_DST + 16]
        .copy_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x53]);
    raw[OFF_SRC..OFF_SRC + 16]
        .copy_from_slice(&[0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10]);
    raw
}

/// A record whose single documented invariant at `offset` was broken.
fn mutated(
    base: [u8; STYX_FLOW_EVENT_WIRE_BYTES],
    offset: usize,
    value: u8,
) -> [u8; STYX_FLOW_EVENT_WIRE_BYTES] {
    let mut raw = base;
    raw[offset] = value;
    raw
}

fn run_seed_corpus() {
    // --- Valid records: every verdict, both directions, all three protocols,
    // both families and saturated counters must decode and round-trip.
    for verdict in 0..=STYX_VERDICT_DEFAULT_DENY {
        for direction in [STYX_DIR_EGRESS, STYX_DIR_INGRESS] {
            let raw = mutated(valid_ipv4_record(), OFF_VERDICT, verdict);
            assert_eq!(require_valid(&raw).direction, STYX_DIR_EGRESS);
            let raw = mutated(raw, OFF_DIRECTION, direction);
            let event = require_valid(&raw);
            assert_eq!(event.verdict, verdict);
            assert_eq!(event.direction, direction);
        }
    }
    for proto in [STYX_PROTO_TCP, STYX_PROTO_UDP, STYX_PROTO_UNKNOWN] {
        let mut raw = valid_ipv6_record();
        raw[OFF_PROTO] = proto;
        if proto != STYX_PROTO_TCP {
            raw[OFF_TCP_FLAGS] = 0;
        }
        if proto == STYX_PROTO_UNKNOWN {
            raw[OFF_DST_PORT..OFF_DST_PORT + 2].copy_from_slice(&0u16.to_ne_bytes());
            raw[OFF_SRC_PORT..OFF_SRC_PORT + 2].copy_from_slice(&0u16.to_ne_bytes());
        }
        let event = require_valid(&raw);
        assert_eq!(event.proto, proto);
        assert_eq!(event.family, NETWORK_FAMILY_V6);
    }
    let mut saturated = valid_ipv4_record();
    saturated[OFF_CGROUP_ID..OFF_CGROUP_ID + 8].copy_from_slice(&u64::MAX.to_ne_bytes());
    saturated[OFF_TS_NS..OFF_TS_NS + 8].copy_from_slice(&u64::MAX.to_ne_bytes());
    saturated[OFF_TX_BYTES..OFF_TX_BYTES + 8].copy_from_slice(&u64::MAX.to_ne_bytes());
    saturated[OFF_RX_BYTES..OFF_RX_BYTES + 8].copy_from_slice(&u64::MAX.to_ne_bytes());
    saturated[OFF_PACKETS..OFF_PACKETS + 4].copy_from_slice(&u32::MAX.to_ne_bytes());
    require_valid(&saturated);

    // --- Invalid records: one hostile seed per documented reject rule.
    for len in [0usize, 1, 8, 64, 103] {
        require_rejected(&valid_ipv4_record()[..len]);
    }
    let mut longer = [0u8; 208];
    longer[..STYX_FLOW_EVENT_WIRE_BYTES].copy_from_slice(&valid_ipv4_record());
    for len in [105usize, 106, 208] {
        require_rejected(&longer[..len]);
    }
    for family in [0u8, 1, 2, 3, 5, 7, 255] {
        let raw = mutated(valid_ipv4_record(), OFF_FAMILY, family);
        require_rejected(&raw);
    }
    for proto in [1u8, 2, 3, 58, 132, 255] {
        let raw = mutated(valid_ipv4_record(), OFF_PROTO, proto);
        require_rejected(&raw);
    }
    for direction in [0u8, 3, 4, 255] {
        let raw = mutated(valid_ipv4_record(), OFF_DIRECTION, direction);
        require_rejected(&raw);
    }
    for verdict in [STYX_VERDICT_DEFAULT_DENY + 1, 7, 255] {
        let raw = mutated(valid_ipv4_record(), OFF_VERDICT, verdict);
        require_rejected(&raw);
    }
    let mut raw = valid_ipv4_record();
    raw[OFF_PACKETS..OFF_PACKETS + 4].copy_from_slice(&0u32.to_ne_bytes());
    require_rejected(&raw);
    let mut raw = valid_ipv4_record();
    raw[OFF_TS_NS..OFF_TS_NS + 8].copy_from_slice(&0u64.to_ne_bytes());
    require_rejected(&raw);
    for offset in OFF_DST..OFF_DST + 12 {
        require_rejected(&mutated(valid_ipv4_record(), offset, 1));
    }
    let mut unspecified = valid_ipv4_record();
    unspecified[OFF_DST + 12..OFF_DST + 16].copy_from_slice(&[0, 0, 0, 0]);
    require_rejected(&unspecified);
    for proto in [STYX_PROTO_UDP, STYX_PROTO_UNKNOWN] {
        let mut raw = mutated(valid_ipv4_record(), OFF_PROTO, proto);
        raw[OFF_TCP_FLAGS] = 0x02;
        if proto == STYX_PROTO_UNKNOWN {
            raw[OFF_DST_PORT..OFF_DST_PORT + 2].copy_from_slice(&0u16.to_ne_bytes());
            raw[OFF_SRC_PORT..OFF_SRC_PORT + 2].copy_from_slice(&0u16.to_ne_bytes());
        }
        require_rejected(&raw);
    }
    for port_offset in [OFF_DST_PORT, OFF_SRC_PORT] {
        let mut raw = mutated(valid_ipv4_record(), OFF_PROTO, STYX_PROTO_UNKNOWN);
        raw[OFF_TCP_FLAGS] = 0;
        raw[port_offset..port_offset + 2].copy_from_slice(&1u16.to_ne_bytes());
        require_rejected(&raw);
    }
    // A 16-byte comm without any NUL terminator cannot come from the producer.
    let mut comm = valid_ipv4_record();
    comm[OFF_COMM..OFF_COMM + 16].fill(b'x');
    require_rejected(&comm);
    // A non-zero byte behind the first NUL breaks the zero padding.
    let mut comm_padding = valid_ipv4_record();
    comm_padding[OFF_COMM + 5] = 1;
    require_rejected(&comm_padding);

    // --- Deterministic mutation sweep: no byte value at any offset may panic,
    // and any record the decoder still accepts must obey every contract
    // invariant (a decoder that repairs instead of rejecting would fail here).
    let base = valid_ipv4_record();
    for offset in 0..STYX_FLOW_EVENT_WIRE_BYTES {
        for value in [0x00u8, 0x01, 0x7f, 0x80, 0xff] {
            if let Some(event) = decode(&mutated(base, offset, value)) {
                assert_contract(&event);
            }
        }
    }
}

fn main() -> io::Result<()> {
    let mut input = Vec::new();
    io::stdin()
        .take((STYX_FLOW_EVENT_WIRE_BYTES + 1) as u64)
        .read_to_end(&mut input)?;
    if input.is_empty() {
        run_seed_corpus();
        return Ok(());
    }
    if let Some(event) = decode(&input) {
        assert_contract(&event);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn deterministic_seed_corpus_pins_the_flow_event_contract() {
        super::run_seed_corpus();
    }
}
