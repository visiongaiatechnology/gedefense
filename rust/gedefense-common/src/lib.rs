#![no_std]

pub const MAX_BLOCKLIST_ENTRIES_V4: u32 = 250_000;
pub const MAX_BLOCKLIST_ENTRIES_V6: u32 = 250_000;
pub const ACTION_DROP: u8 = 1;
pub const L2_PREFIX_BYTES: usize = 22;
pub const EXEC_COMM_BYTES: usize = 16;
pub const NETWORK_ADDRESS_BYTES: usize = 16;
pub const NETWORK_FAMILY_V4: u8 = 4;
pub const NETWORK_FAMILY_V6: u8 = 6;
pub const CELL_LSM_DENY_NON_UNIX_SOCKET: u8 = 1;
pub const CANARY_PATH_BYTES: usize = 64;
pub const INGRESS_EVENT_WIRE_BYTES: usize = 64;
pub const NETWORK_PROTOCOL_TCP: u8 = 6;

mod styx_flow;
pub use styx_flow::*;

mod titan_exec;
pub use titan_exec::*;

mod lockdown;
pub use lockdown::*;

mod worker_guard;
pub use worker_guard::*;

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeceptionAccessEvent {
    pub pid: u32,
    pub uid: u32,
    pub canary_type: u8,
    pub reserved: [u8; 7],
    pub comm: [u8; EXEC_COMM_BYTES],
    pub path_prefix: [u8; CANARY_PATH_BYTES],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExecEvent {
    pub pid: u32,
    pub uid: u32,
    pub gid: u32,
    pub comm: [u8; EXEC_COMM_BYTES],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EgressDropEvent {
    pub pid: u32,
    pub uid: u32,
    pub family: u8,
    pub protocol: u8,
    pub action: u8,
    pub reserved: u8,
    pub destination: [u8; NETWORK_ADDRESS_BYTES],
    pub comm: [u8; EXEC_COMM_BYTES],
}

/// Bounded, header-only ingress sample emitted by the kernel sensor. `packets`
/// and `syn_count` are deltas since the previous sample for the source/CPU.
/// No payload bytes ever cross the kernel/userspace trust boundary.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IngressEvent {
    pub family: u8,
    pub protocol: u8,
    pub tcp_flags: u8,
    /// Exact connection/activity attempts represented by this bounded sample.
    /// The eBPF producer flushes an aggregate before it can exceed `u8::MAX`
    /// packets, so this field is exact and is never silently clamped. A wider
    /// wire field (u16/u32) requires changing the userspace decoders first.
    pub attempt_count: u8,
    pub src_port: u16,
    pub dst_port: u16,
    pub packets: u32,
    pub bytes: u32,
    pub syn_count: u32,
    pub ack_count: u32,
    /// Monotonic kernel second from bpf_ktime_get_ns(). This is intentionally
    /// not wall-clock time; userspace uses it only to preserve exact 1-second
    /// rate-window boundaries across IPC batching.
    pub window_epoch_sec: u64,
    pub source: [u8; NETWORK_ADDRESS_BYTES],
    pub destination: [u8; NETWORK_ADDRESS_BYTES],
}

/// Decodes the fixed kernel/userspace wire representation of an ingress event.
///
/// The eBPF producer and Rust Core run on the same host, so scalar values use
/// native endian just like the in-memory `repr(C)` structure emitted through
/// the BPF ring buffer. The explicit decoder keeps the trust boundary bounded
/// and prevents the userspace reader from scattering unchecked byte offsets.
///
/// Producer contract checked here:
/// * `packets` is the batch length; no counter may exceed it.
/// * `syn_count` (SYN without ACK) and `ack_count` (ACK set) are disjoint
///   packet classes, so their sum cannot exceed `packets`.
/// * A TCP label only describes a homogeneous TCP batch. Such a batch keeps
///   `attempt_count == syn_count` (every TCP packet contributes its SYN
///   attempt flag, every other protocol contributes one attempt) and its
///   counters are never clamped, because the producer flushes before a batch
///   can exceed `u8::MAX` packets.
/// * Aggregates that mix TCP with non-TCP packets, and counters carried over a
///   window/port boundary, use the explicit neutral marker `protocol == 0`
///   with `tcp_flags == 0` instead of borrowing an unrelated packet's label.
///
/// A record that contradicts this contract cannot be repaired without guessing.
/// The decoder therefore rejects it (`None`); the core skips the sample and
/// raises its drain-level alarm once too many samples are rejected. It must
/// never neutralise `protocol`/`tcp_flags` in place: that is exactly how a
/// saturated `attempt_count` used to erase the TCP label of a genuine SYN
/// batch, which hid corruption instead of reporting it.
pub fn decode_ingress_event(bytes: &[u8]) -> Option<IngressEvent> {
    if bytes.len() != INGRESS_EVENT_WIRE_BYTES {
        return None;
    }

    let family = bytes[0];
    let protocol = bytes[1];
    let tcp_flags = bytes[2];
    let attempt_count = bytes[3];
    let src_port = u16::from_ne_bytes([bytes[4], bytes[5]]);
    let dst_port = u16::from_ne_bytes([bytes[6], bytes[7]]);
    let packets = u32::from_ne_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
    let packet_bytes = u32::from_ne_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]);
    let syn_count = u32::from_ne_bytes([bytes[16], bytes[17], bytes[18], bytes[19]]);
    let ack_count = u32::from_ne_bytes([bytes[20], bytes[21], bytes[22], bytes[23]]);
    let window_epoch_sec = u64::from_ne_bytes([
        bytes[24], bytes[25], bytes[26], bytes[27], bytes[28], bytes[29], bytes[30], bytes[31],
    ]);
    let source: [u8; NETWORK_ADDRESS_BYTES] = bytes[32..48].try_into().ok()?;
    let destination: [u8; NETWORK_ADDRESS_BYTES] = bytes[48..64].try_into().ok()?;

    // Structurally impossible records are corruption and are refused: a family the
    // producer cannot emit, no packets at all, counters larger than the packets they
    // describe, disjoint flag classes that cannot fit into the batch, or a missing
    // kernel second.
    if !matches!(family, NETWORK_FAMILY_V4 | NETWORK_FAMILY_V6)
        || packets == 0
        || syn_count > packets
        || ack_count > packets
        || syn_count.saturating_add(ack_count) > packets
        || u32::from(attempt_count) > packets
        || window_epoch_sec == 0
    {
        return None;
    }

    // A TCP label that contradicts its own attempt counter cannot describe a
    // homogeneous TCP batch. This is exactly the shape a clamped counter produced
    // (packets/syn_count above u8::MAX, attempt_count saturating at 255), so the
    // record is rejected instead of being rewritten into a neutral label: the
    // userspace consumer sees a counted sample loss and a drain alarm rather than
    // silently losing the TCP flags of the whole aggregate.
    if protocol == NETWORK_PROTOCOL_TCP && u32::from(attempt_count) != syn_count {
        return None;
    }
    // TCP flags exist only for TCP packets; any other label carrying them is
    // mislabelled or corrupted. Keep the record out instead of guessing which
    // part of it is wrong.
    if protocol != NETWORK_PROTOCOL_TCP && tcp_flags != 0 {
        return None;
    }

    Some(IngressEvent {
        family,
        protocol,
        tcp_flags,
        attempt_count,
        src_port,
        dst_port,
        packets,
        bytes: packet_bytes,
        syn_count,
        ack_count,
        window_epoch_sec,
        source,
        destination,
    })
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CellLsmDenyEvent {
    pub cgroup_id: u64,
    pub pid: u32,
    pub uid: u32,
    pub family: i32,
    pub action: u8,
    pub reserved: [u8; 3],
}
const ETH_P_IP: u16 = 0x0800;
const ETH_P_IPV6: u16 = 0x86dd;
const ETH_P_8021Q: u16 = 0x8100;
const ETH_P_8021AD: u16 = 0x88a8;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NetworkHeader {
    Ipv4(usize),
    Ipv6(usize),
    Other,
}

#[inline(always)]
fn ether_type(prefix: &[u8; L2_PREFIX_BYTES], offset: usize) -> u16 {
    u16::from_be_bytes([prefix[offset], prefix[offset + 1]])
}

/// Parses Ethernet plus at most two 802.1Q/802.1ad tags from a fixed-size
/// prefix. The fixed input size gives the eBPF verifier static bounds while
/// exposing the exact production parser to host-side fuzzing.
#[inline(always)]
pub fn parse_network_header(prefix: &[u8; L2_PREFIX_BYTES]) -> NetworkHeader {
    let mut protocol = ether_type(prefix, 12);
    let mut offset = 14usize;

    if protocol == ETH_P_8021Q || protocol == ETH_P_8021AD {
        protocol = ether_type(prefix, 16);
        offset = 18;
    }
    if protocol == ETH_P_8021Q || protocol == ETH_P_8021AD {
        protocol = ether_type(prefix, 20);
        offset = 22;
    }

    match protocol {
        ETH_P_IP => NetworkHeader::Ipv4(offset),
        ETH_P_IPV6 => NetworkHeader::Ipv6(offset),
        _ => NetworkHeader::Other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_plain_and_double_tagged_network_headers() {
        let mut plain = [0u8; L2_PREFIX_BYTES];
        plain[12..14].copy_from_slice(&ETH_P_IP.to_be_bytes());
        assert_eq!(parse_network_header(&plain), NetworkHeader::Ipv4(14));

        let mut tagged = [0u8; L2_PREFIX_BYTES];
        tagged[12..14].copy_from_slice(&ETH_P_8021Q.to_be_bytes());
        tagged[16..18].copy_from_slice(&ETH_P_8021AD.to_be_bytes());
        tagged[20..22].copy_from_slice(&ETH_P_IPV6.to_be_bytes());
        assert_eq!(parse_network_header(&tagged), NetworkHeader::Ipv6(22));
    }

    #[test]
    fn every_two_byte_protocol_value_is_bounded() {
        let mut prefix = [0u8; L2_PREFIX_BYTES];
        for protocol in 0u16..=u16::MAX {
            prefix[12..14].copy_from_slice(&protocol.to_be_bytes());
            match parse_network_header(&prefix) {
                NetworkHeader::Ipv4(offset) | NetworkHeader::Ipv6(offset) => {
                    assert!((14..=22).contains(&offset));
                }
                NetworkHeader::Other => {}
            }
        }
    }

    /// Encodes an IPv4 ingress wire record with valid ports, epoch, source and
    /// destination. Tests only vary the fields under test.
    fn encode_ingress_wire(
        protocol: u8,
        tcp_flags: u8,
        attempt_count: u8,
        packets: u32,
        packet_bytes: u32,
        syn_count: u32,
        ack_count: u32,
    ) -> [u8; INGRESS_EVENT_WIRE_BYTES] {
        let mut raw = [0u8; INGRESS_EVENT_WIRE_BYTES];
        raw[0] = NETWORK_FAMILY_V4;
        raw[1] = protocol;
        raw[2] = tcp_flags;
        raw[3] = attempt_count;
        raw[4..6].copy_from_slice(&54321u16.to_ne_bytes());
        raw[6..8].copy_from_slice(&443u16.to_ne_bytes());
        raw[8..12].copy_from_slice(&packets.to_ne_bytes());
        raw[12..16].copy_from_slice(&packet_bytes.to_ne_bytes());
        raw[16..20].copy_from_slice(&syn_count.to_ne_bytes());
        raw[20..24].copy_from_slice(&ack_count.to_ne_bytes());
        raw[24..32].copy_from_slice(&12345u64.to_ne_bytes());
        raw[32..36].copy_from_slice(&[203, 0, 113, 9]);
        raw[48..52].copy_from_slice(&[192, 0, 2, 10]);
        raw
    }

    #[test]
    fn ingress_event_wire_decoder_accepts_valid_ipv4_sample() {
        assert_eq!(
            core::mem::size_of::<IngressEvent>(),
            INGRESS_EVENT_WIRE_BYTES
        );
        let raw = encode_ingress_wire(6, 0x02, 2, 3, 180, 2, 1);

        let event = decode_ingress_event(&raw).expect("valid ingress event");
        assert_eq!(event.family, NETWORK_FAMILY_V4);
        assert_eq!(event.protocol, NETWORK_PROTOCOL_TCP);
        assert_eq!(event.tcp_flags, 0x02);
        assert_eq!(event.dst_port, 443);
        assert_eq!(event.packets, 3);
        assert_eq!(event.bytes, 180);
        assert_eq!(event.syn_count, 2);
        assert_eq!(event.ack_count, 1);
        assert_eq!(event.attempt_count, 2);
        assert_eq!(event.window_epoch_sec, 12345);
        assert_eq!(&event.source[..4], &[203, 0, 113, 9]);
    }

    #[test]
    fn ingress_event_wire_decoder_rejects_invalid_metadata() {
        let mut raw = encode_ingress_wire(6, 0x02, 1, 1, 60, 1, 0);
        // AF_UNSPEC-like family: the producer only labels IPv4/IPv6 batches.
        raw[0] = 0;
        assert!(decode_ingress_event(&raw).is_none());

        raw[0] = NETWORK_FAMILY_V6;
        // Counters that contradict the batch length are refused.
        raw[16..20].copy_from_slice(&2u32.to_ne_bytes());
        assert!(decode_ingress_event(&raw).is_none());

        raw[16..20].copy_from_slice(&0u32.to_ne_bytes());
        // A batch length of zero is impossible.
        raw[8..12].copy_from_slice(&0u32.to_ne_bytes());
        assert!(decode_ingress_event(&raw).is_none());
    }

    #[test]
    fn ingress_event_wire_decoder_keeps_the_tcp_label_of_a_large_ack_batch() {
        // More than u8::MAX packets is representable because every counter
        // (attempt_count here is zero) fits the wire fields. The decoder must keep
        // the TCP label instead of neutralising it; a batch size alone is not a
        // contradiction.
        let raw = encode_ingress_wire(6, 0x10, 0, 300, 19_200, 0, 300);
        let event = decode_ingress_event(&raw).expect("a consistent large batch is valid");
        assert_eq!(event.protocol, NETWORK_PROTOCOL_TCP);
        assert_eq!(event.tcp_flags, 0x10);
        assert_eq!(event.packets, 300);
        assert_eq!(event.attempt_count, 0);
        assert_eq!(event.ack_count, 300);
    }

    #[test]
    fn ingress_event_wire_decoder_keeps_the_tcp_label_of_a_full_syn_batch() {
        // The producer flushes at exactly 255 packets, so a full SYN batch keeps
        // attempt_count == syn_count == u8::MAX and its label stays intact.
        let raw = encode_ingress_wire(6, 0x02, u8::MAX, 255, 15_300, 255, 0);
        let event = decode_ingress_event(&raw).expect("a full SYN batch is valid");
        assert_eq!(event.protocol, NETWORK_PROTOCOL_TCP);
        assert_eq!(event.tcp_flags, 0x02);
        assert_eq!(event.attempt_count, u8::MAX);
        assert_eq!(event.syn_count, 255);
    }

    #[test]
    fn ingress_event_wire_decoder_rejects_a_saturated_attempt_counter() {
        // Regression for the silent flag loss: a large SYN batch whose attempt_count
        // was clamped to u8::MAX no longer matches syn_count. The old decoder rewrote
        // this record to protocol 0 / tcp_flags 0 and the TCP flags of the whole
        // aggregate disappeared without any visible error. The record is refused now;
        // the core counts it as a rejected sample and alarms when it keeps happening.
        let raw = encode_ingress_wire(6, 0x02, u8::MAX, 8192, 524_288, 8192, 0);
        assert!(decode_ingress_event(&raw).is_none());
    }

    #[test]
    fn ingress_event_wire_decoder_accepts_the_explicit_neutral_batch_marker() {
        // Mixed TCP/UDP aggregates are emitted with the documented neutral marker
        // (protocol 0, tcp_flags 0) and exact counters, never by zeroing a TCP label.
        let raw = encode_ingress_wire(0, 0, 9, 9, 900, 7, 0);
        let event = decode_ingress_event(&raw).expect("the neutral marker is valid");
        assert_eq!(event.protocol, 0);
        assert_eq!(event.tcp_flags, 0);
        assert_eq!(event.attempt_count, 9);
        assert_eq!(event.syn_count, 7);
        assert_eq!(event.packets, 9);
    }

    #[test]
    fn ingress_event_wire_decoder_rejects_tcp_flags_under_a_non_tcp_label() {
        let raw = encode_ingress_wire(17, 0x02, 1, 1, 64, 0, 0);
        assert!(decode_ingress_event(&raw).is_none());
    }

    #[test]
    fn ingress_event_wire_decoder_rejects_counters_larger_than_the_packets() {
        // Counters that contradict the batch length are corruption, not a label
        // disagreement.
        let raw = encode_ingress_wire(6, 0x02, 0, 2, 120, 3, 0);
        assert!(decode_ingress_event(&raw).is_none());

        let raw = encode_ingress_wire(0, 0, 0, 3, 180, 2, 2);
        assert!(decode_ingress_event(&raw).is_none());
    }
}
