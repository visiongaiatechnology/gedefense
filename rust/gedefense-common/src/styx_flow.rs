//! Point 3 (Phase 1): shared wire contract for per-cgroup flow telemetry.
//!
//! Rust half of ABI-1 in `docs/POINT3-EGRESS-BEACON.md` (§3.1 constants, §3.2
//! `FlowEvent`). Producer and core run on the same host: native endian,
//! `repr(C)`, exactly [`STYX_FLOW_EVENT_WIRE_BYTES`] bytes, never portable.
//!
//! [`decode_styx_flow_event`] rejects every record the producer cannot have
//! emitted instead of repairing it (doctrine of `decode_ingress_event`); the
//! core skips it and counts `FLOW_REJECTED`. Exactly the §3.2 decoder matrix is
//! rejected: wire length, family, protocol, direction, verdict, `packets`,
//! `ts_ns`, canonical IPv4 destination, unspecified IPv4 destination,
//! `tcp_flags` under non-TCP, ports under the neutral marker and `comm`
//! NUL-padding. Unconstrained fields are carried through unchanged: `reserved`
//! (producer writes 0, decoder contract lists no reject, text wire omits it),
//! the source address (only the destination layout is pinned), `rx_bytes`
//! (Phase 2), and zero `cgroup_id`/`pid`/`uid`.

/// Wire size of one [`FlowEvent`] (`sizeof(FlowEvent) == 104`).
pub const STYX_FLOW_EVENT_WIRE_BYTES: usize = 104;

/// Protocol marker: 0 = neutral/unknown, 6 = TCP, 17 = UDP.
pub const STYX_PROTO_UNKNOWN: u8 = 0;
pub const STYX_PROTO_TCP: u8 = 6;
pub const STYX_PROTO_UDP: u8 = 17;

/// Direction: 1 = egress (Phase 1), 2 = ingress (Phase 2); 0 is rejected.
pub const STYX_DIR_UNKNOWN: u8 = 0;
pub const STYX_DIR_EGRESS: u8 = 1;
pub const STYX_DIR_INGRESS: u8 = 2;

/// Verdict values 0..=5, see §3.1.
pub const STYX_VERDICT_ALLOW: u8 = 0;
pub const STYX_VERDICT_AUDIT_DROP: u8 = 1;
pub const STYX_VERDICT_DROP: u8 = 2;
pub const STYX_VERDICT_METADATA_VETO: u8 = 3;
pub const STYX_VERDICT_DNS_PIN: u8 = 4;
pub const STYX_VERDICT_DEFAULT_DENY: u8 = 5;

/// Mode: bits 0..2 of a mode/flags byte (OFF = default after upgrade).
pub const STYX_MODE_OFF: u8 = 0;
pub const STYX_MODE_MONITOR: u8 = 1;
pub const STYX_MODE_ENFORCE: u8 = 2;
pub const STYX_MODE_MASK: u8 = 0b0000_0111;

/// Flags inside a mode/flags byte.
pub const STYX_FLAG_DNS_RESOLVER: u8 = 1 << 3;
pub const STYX_FLAG_ALLOW_METADATA: u8 = 1 << 4;
pub const STYX_FLAG_ALLOW_HOST_ALLOWLIST: u8 = 1 << 5;
pub const STYX_FLAG_LOG_FLOWS: u8 = 1 << 6;

/// One aggregated flow sample emitted by the egress sensor.
///
/// Byte layout (native endian, no implicit padding, size 104): `cgroup_id` 0,
/// `ts_ns` 8, `tx_bytes` 16, `rx_bytes` 24, `pid` 32, `uid` 36, `dst` 40,
/// `src` 56, `dst_port` 72, `src_port` 74, `packets` 76, `proto` 80, `family`
/// 81, `direction` 82, `tcp_flags` 83, `verdict` 84, `reserved` 85, `comm` 88.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FlowEvent {
    pub cgroup_id: u64,
    pub ts_ns: u64,
    pub tx_bytes: u64,
    pub rx_bytes: u64,
    pub pid: u32,
    pub uid: u32,
    /// Destination; IPv4 lives in the last four bytes, the first twelve are 0.
    pub dst: [u8; 16],
    /// Source; the decoder pins only the destination layout (§3.2).
    pub src: [u8; 16],
    /// Host-order destination port.
    pub dst_port: u16,
    /// Host-order source port.
    pub src_port: u16,
    pub packets: u32,
    /// [`STYX_PROTO_TCP`], [`STYX_PROTO_UDP`] or [`STYX_PROTO_UNKNOWN`].
    pub proto: u8,
    /// 4 or 6.
    pub family: u8,
    /// [`STYX_DIR_EGRESS`] or [`STYX_DIR_INGRESS`].
    pub direction: u8,
    /// OR of the TCP flags; 0 when `proto != TCP`.
    pub tcp_flags: u8,
    /// 0..=[`STYX_VERDICT_DEFAULT_DENY`].
    pub verdict: u8,
    /// Reserved, producer writes zero.
    pub reserved: [u8; 3],
    /// NUL-padded process name (`bpf_get_current_comm`).
    pub comm: [u8; 16],
}

/// Decodes one fixed-size flow-event wire record.
///
/// Returns `None` for every record the producer cannot have emitted (see the
/// module-level reject matrix). The record is never repaired or neutralised.
pub fn decode_styx_flow_event(bytes: &[u8]) -> Option<FlowEvent> {
    if bytes.len() != STYX_FLOW_EVENT_WIRE_BYTES {
        return None;
    }

    let cgroup_id = u64::from_ne_bytes(bytes[0..8].try_into().ok()?);
    let ts_ns = u64::from_ne_bytes(bytes[8..16].try_into().ok()?);
    let tx_bytes = u64::from_ne_bytes(bytes[16..24].try_into().ok()?);
    let rx_bytes = u64::from_ne_bytes(bytes[24..32].try_into().ok()?);
    let pid = u32::from_ne_bytes(bytes[32..36].try_into().ok()?);
    let uid = u32::from_ne_bytes(bytes[36..40].try_into().ok()?);
    let dst: [u8; 16] = bytes[40..56].try_into().ok()?;
    let src: [u8; 16] = bytes[56..72].try_into().ok()?;
    let dst_port = u16::from_ne_bytes(bytes[72..74].try_into().ok()?);
    let src_port = u16::from_ne_bytes(bytes[74..76].try_into().ok()?);
    let packets = u32::from_ne_bytes(bytes[76..80].try_into().ok()?);
    let proto = bytes[80];
    let family = bytes[81];
    let direction = bytes[82];
    let tcp_flags = bytes[83];
    let verdict = bytes[84];
    let reserved: [u8; 3] = bytes[85..88].try_into().ok()?;
    let comm: [u8; 16] = bytes[88..104].try_into().ok()?;

    if !matches!(family, crate::NETWORK_FAMILY_V4 | crate::NETWORK_FAMILY_V6)
        || !matches!(proto, STYX_PROTO_UNKNOWN | STYX_PROTO_TCP | STYX_PROTO_UDP)
        || !matches!(direction, STYX_DIR_EGRESS | STYX_DIR_INGRESS)
        || verdict > STYX_VERDICT_DEFAULT_DENY
        || packets == 0
        || ts_ns == 0
    {
        return None;
    }

    // TCP flags describe TCP packets only; any other protocol carrying them is
    // mislabelled and must not be relabelled into a neutral record.
    if proto != STYX_PROTO_TCP && tcp_flags != 0 {
        return None;
    }

    // The wire keeps IPv4 in the last four bytes of the 16-byte field. A
    // non-zero prefix is not canonical, and the unspecified destination address
    // can never be a real flow target.
    if family == crate::NETWORK_FAMILY_V4 {
        if dst[..12].iter().any(|byte| *byte != 0) || dst[12..].iter().all(|byte| *byte == 0) {
            return None;
        }
    }

    // The neutral marker exists to say "no L4 information"; ports then carry
    // nothing and must be zero (fragments, non-TCP/UDP). TCP/UDP ports are not
    // constrained further by §3.2 (a zero port is representable).
    if proto == STYX_PROTO_UNKNOWN && (dst_port != 0 || src_port != 0) {
        return None;
    }

    // `comm` is NUL-terminated and NUL-padded by the producer
    // (`bpf_get_current_comm` zero-fills the remainder); embedded arbitrary
    // bytes before the terminator are allowed, a missing terminator or garbage
    // behind it is not.
    if !comm_is_nul_padded(&comm) {
        return None;
    }

    Some(FlowEvent {
        cgroup_id,
        ts_ns,
        tx_bytes,
        rx_bytes,
        pid,
        uid,
        dst,
        src,
        dst_port,
        src_port,
        packets,
        proto,
        family,
        direction,
        tcp_flags,
        verdict,
        reserved,
        comm,
    })
}

/// A producer `comm` is NUL-terminated (task names are at most 15 bytes plus
/// NUL) and all bytes behind the terminator are zero padding.
fn comm_is_nul_padded(comm: &[u8; 16]) -> bool {
    let mut padded = false;
    for &byte in comm.iter() {
        if padded {
            if byte != 0 {
                return false;
            }
        } else if byte == 0 {
            padded = true;
        }
    }
    padded
}

#[cfg(test)]
mod tests {
    use super::*;

    const COMM_CURL: [u8; 16] = *b"curl\0\0\0\0\0\0\0\0\0\0\0\0";

    /// Canonical IPv4 address: twelve zero bytes, then the four octets.
    const fn ipv4(octets: [u8; 4]) -> [u8; 16] {
        [
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, octets[0], octets[1], octets[2], octets[3],
        ]
    }

    fn sample_ipv4() -> FlowEvent {
        FlowEvent {
            cgroup_id: 0x0102_0304_0506_0708,
            ts_ns: 9_876_543_210,
            tx_bytes: 65_536,
            rx_bytes: 0,
            pid: 4242,
            uid: 1000,
            dst: ipv4([203, 0, 113, 9]),
            src: ipv4([192, 0, 2, 10]),
            dst_port: 443,
            src_port: 51_234,
            packets: 12,
            proto: STYX_PROTO_TCP,
            family: crate::NETWORK_FAMILY_V4,
            direction: STYX_DIR_EGRESS,
            tcp_flags: 0x18,
            verdict: STYX_VERDICT_ALLOW,
            reserved: [0; 3],
            comm: COMM_CURL,
        }
    }

    fn sample_ipv6() -> FlowEvent {
        let mut event = sample_ipv4();
        event.family = crate::NETWORK_FAMILY_V6;
        event.dst = [
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x53,
        ];
        event.src = [
            0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
        ];
        event
    }

    /// Serialises a [`FlowEvent`] at the hard-coded ABI offsets. Deliberately
    /// independent of `offset_of!` so the round-trip tests cross-check the
    /// struct layout against the table.
    fn encode(event: &FlowEvent) -> [u8; STYX_FLOW_EVENT_WIRE_BYTES] {
        let mut raw = [0u8; STYX_FLOW_EVENT_WIRE_BYTES];
        raw[0..8].copy_from_slice(&event.cgroup_id.to_ne_bytes());
        raw[8..16].copy_from_slice(&event.ts_ns.to_ne_bytes());
        raw[16..24].copy_from_slice(&event.tx_bytes.to_ne_bytes());
        raw[24..32].copy_from_slice(&event.rx_bytes.to_ne_bytes());
        raw[32..36].copy_from_slice(&event.pid.to_ne_bytes());
        raw[36..40].copy_from_slice(&event.uid.to_ne_bytes());
        raw[40..56].copy_from_slice(&event.dst);
        raw[56..72].copy_from_slice(&event.src);
        raw[72..74].copy_from_slice(&event.dst_port.to_ne_bytes());
        raw[74..76].copy_from_slice(&event.src_port.to_ne_bytes());
        raw[76..80].copy_from_slice(&event.packets.to_ne_bytes());
        raw[80] = event.proto;
        raw[81] = event.family;
        raw[82] = event.direction;
        raw[83] = event.tcp_flags;
        raw[84] = event.verdict;
        raw[85..88].copy_from_slice(&event.reserved);
        raw[88..104].copy_from_slice(&event.comm);
        raw
    }

    fn decode(raw: &[u8; STYX_FLOW_EVENT_WIRE_BYTES]) -> Option<FlowEvent> {
        decode_styx_flow_event(raw)
    }

    #[test]
    fn flow_event_wire_layout_matches_the_abi_table() {
        use core::mem::{align_of, offset_of, size_of};
        assert_eq!(size_of::<FlowEvent>(), STYX_FLOW_EVENT_WIRE_BYTES);
        assert_eq!(align_of::<FlowEvent>(), 8);
        assert_eq!(offset_of!(FlowEvent, cgroup_id), 0);
        assert_eq!(offset_of!(FlowEvent, ts_ns), 8);
        assert_eq!(offset_of!(FlowEvent, tx_bytes), 16);
        assert_eq!(offset_of!(FlowEvent, rx_bytes), 24);
        assert_eq!(offset_of!(FlowEvent, pid), 32);
        assert_eq!(offset_of!(FlowEvent, uid), 36);
        assert_eq!(offset_of!(FlowEvent, dst), 40);
        assert_eq!(offset_of!(FlowEvent, src), 56);
        assert_eq!(offset_of!(FlowEvent, dst_port), 72);
        assert_eq!(offset_of!(FlowEvent, src_port), 74);
        assert_eq!(offset_of!(FlowEvent, packets), 76);
        assert_eq!(offset_of!(FlowEvent, proto), 80);
        assert_eq!(offset_of!(FlowEvent, family), 81);
        assert_eq!(offset_of!(FlowEvent, direction), 82);
        assert_eq!(offset_of!(FlowEvent, tcp_flags), 83);
        assert_eq!(offset_of!(FlowEvent, verdict), 84);
        assert_eq!(offset_of!(FlowEvent, reserved), 85);
        assert_eq!(offset_of!(FlowEvent, comm), 88);
        assert_eq!(offset_of!(FlowEvent, comm) + size_of::<[u8; 16]>(), 104);
    }

    #[test]
    fn decodes_valid_ipv4_records_for_every_verdict_and_direction() {
        for verdict in 0..=STYX_VERDICT_DEFAULT_DENY {
            for direction in [STYX_DIR_EGRESS, STYX_DIR_INGRESS] {
                for proto in [STYX_PROTO_UNKNOWN, STYX_PROTO_TCP, STYX_PROTO_UDP] {
                    let mut event = sample_ipv4();
                    event.verdict = verdict;
                    event.direction = direction;
                    event.proto = proto;
                    if proto != STYX_PROTO_TCP {
                        event.tcp_flags = 0;
                    }
                    if proto == STYX_PROTO_UNKNOWN {
                        event.dst_port = 0;
                        event.src_port = 0;
                    }
                    assert_eq!(decode(&encode(&event)), Some(event));
                }
            }
        }
    }

    #[test]
    fn decodes_valid_ipv6_records_for_every_verdict_and_direction() {
        for verdict in 0..=STYX_VERDICT_DEFAULT_DENY {
            for direction in [STYX_DIR_EGRESS, STYX_DIR_INGRESS] {
                let mut event = sample_ipv6();
                event.verdict = verdict;
                event.direction = direction;
                assert_eq!(decode(&encode(&event)), Some(event));
            }
        }
    }

    #[test]
    fn accepts_saturating_counters_and_phase_two_rx_bytes() {
        let mut event = sample_ipv4();
        event.cgroup_id = u64::MAX;
        event.ts_ns = u64::MAX;
        event.tx_bytes = u64::MAX;
        event.rx_bytes = u64::MAX;
        event.pid = u32::MAX;
        event.uid = u32::MAX;
        event.packets = u32::MAX;
        assert_eq!(decode(&encode(&event)), Some(event));
    }

    #[test]
    fn rejects_records_with_the_wrong_wire_length() {
        let raw = encode(&sample_ipv4());
        for len in [0usize, 1, 8, 64, 103] {
            assert!(decode_styx_flow_event(&raw[..len]).is_none(), "len {len}");
        }
        let mut longer = [0u8; 208];
        longer[..STYX_FLOW_EVENT_WIRE_BYTES].copy_from_slice(&raw);
        for len in [105usize, 106, 208] {
            assert!(decode_styx_flow_event(&longer[..len]).is_none(), "len {len}");
        }
    }

    #[test]
    fn rejects_unknown_family_protocol_and_direction() {
        for family in [0u8, 1, 2, 3, 5, 7, 8, 255] {
            let mut event = sample_ipv4();
            event.family = family;
            assert_eq!(decode(&encode(&event)), None, "family {family}");
        }
        for proto in [1u8, 2, 3, 58, 132, 255] {
            let mut event = sample_ipv4();
            event.proto = proto;
            assert_eq!(decode(&encode(&event)), None, "proto {proto}");
        }
        for direction in [STYX_DIR_UNKNOWN, 3, 4, 255] {
            let mut event = sample_ipv4();
            event.direction = direction;
            assert_eq!(decode(&encode(&event)), None, "direction {direction}");
        }
    }

    #[test]
    fn rejects_verdicts_out_of_range() {
        for verdict in (STYX_VERDICT_DEFAULT_DENY + 1)..=u8::MAX {
            let mut event = sample_ipv4();
            event.verdict = verdict;
            assert_eq!(decode(&encode(&event)), None, "verdict {verdict}");
        }
    }

    #[test]
    fn rejects_zero_packets_or_a_missing_kernel_timestamp() {
        let mut event = sample_ipv4();
        event.packets = 0;
        assert_eq!(decode(&encode(&event)), None);

        let mut event = sample_ipv4();
        event.ts_ns = 0;
        assert_eq!(decode(&encode(&event)), None);

        // Any non-zero monotonic timestamp is representable, including small
        // values around early boot.
        let mut event = sample_ipv4();
        event.ts_ns = 1;
        assert_eq!(decode(&encode(&event)), Some(event));
    }

    #[test]
    fn rejects_non_canonical_ipv4_destinations() {
        for byte_index in 40..52 {
            let mut raw = encode(&sample_ipv4());
            raw[byte_index] = 1;
            assert!(decode(&raw).is_none(), "byte {byte_index}");
        }
    }

    #[test]
    fn rejects_the_unspecified_ipv4_destination() {
        let mut event = sample_ipv4();
        event.dst = [0u8; 16];
        assert_eq!(decode(&encode(&event)), None);

        // 0.0.0.1 is canonical and not the unspecified address.
        event.dst = ipv4([0, 0, 0, 1]);
        assert_eq!(decode(&encode(&event)), Some(event));
    }

    #[test]
    fn rejects_tcp_flags_under_non_tcp_protocols() {
        for proto in [STYX_PROTO_UNKNOWN, STYX_PROTO_UDP] {
            for tcp_flags in [0x01u8, 0x02, 0x18, 0xff] {
                let mut event = sample_ipv4();
                event.proto = proto;
                event.tcp_flags = tcp_flags;
                if proto == STYX_PROTO_UNKNOWN {
                    event.dst_port = 0;
                    event.src_port = 0;
                }
                assert_eq!(decode(&encode(&event)), None, "proto {proto}");
            }
        }
        let mut event = sample_ipv4();
        event.tcp_flags = 0xff;
        assert_eq!(decode(&encode(&event)), Some(event));
    }

    #[test]
    fn rejects_ports_under_the_neutral_protocol_marker() {
        let mut neutral = sample_ipv4();
        neutral.proto = STYX_PROTO_UNKNOWN;
        neutral.tcp_flags = 0;
        neutral.dst_port = 0;
        neutral.src_port = 0;
        assert_eq!(decode(&encode(&neutral)), Some(neutral));
        for (dst_port, src_port) in [(1u16, 0u16), (0, 1), (u16::MAX, u16::MAX)] {
            let mut event = neutral;
            event.dst_port = dst_port;
            event.src_port = src_port;
            assert_eq!(decode(&encode(&event)), None);
        }

        // TCP/UDP ports are otherwise unconstrained: a zero port is a
        // representable value, §3.2 only constrains the neutral marker.
        for proto in [STYX_PROTO_TCP, STYX_PROTO_UDP] {
            let mut event = sample_ipv4();
            event.proto = proto;
            event.dst_port = 0;
            event.src_port = 0;
            event.tcp_flags = if proto == STYX_PROTO_TCP { 0x02 } else { 0 };
            assert_eq!(decode(&encode(&event)), Some(event));
        }
    }

    #[test]
    fn validates_comm_nul_padding() {
        // 15 name bytes plus the mandatory terminator (Linux TASK_COMM_LEN 16),
        // shorter/empty names, and opaque non-UTF-8 bytes before the terminator
        // are all valid; a missing terminator or garbage behind it is not.
        let mut event = sample_ipv4();
        event.comm = *b"fifteen-char-na\0";
        assert_eq!(decode(&encode(&event)), Some(event));
        event.comm = COMM_CURL;
        assert_eq!(decode(&encode(&event)), Some(event));
        event.comm = [0u8; 16];
        assert_eq!(decode(&encode(&event)), Some(event));
        event.comm = [
            0xff, 0xfe, b'x', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ];
        assert_eq!(decode(&encode(&event)), Some(event));
        event.comm = [b'x'; 16];
        assert_eq!(decode(&encode(&event)), None);
        let mut comm = [0u8; 16];
        comm[0] = b'x';
        comm[2] = 1;
        event.comm = comm;
        assert_eq!(decode(&encode(&event)), None);
    }
}
