use aya_ebpf::{helpers::bpf_ktime_get_ns, maps::PerCpuArray, programs::XdpContext};
use core::mem;
use gedefense_common::{
    IngressEvent, L2_PREFIX_BYTES, NETWORK_ADDRESS_BYTES, NETWORK_FAMILY_V4, NETWORK_FAMILY_V6,
    NETWORK_PROTOCOL_TCP,
};
use crate::maps::{
    INGRESS_EVENTS, INGRESS_EVENTS_EMITTED, INGRESS_RING_DROPS, INGRESS_TRACK_INSERT_FAILURES,
    INGRESS_TRACK_V4, INGRESS_TRACK_V6,
};
use crate::util::increment_counter;

// One event per 255 packets keeps every wire counter exact: `attempt_count` is a
// u8 in the ring record and in the control-plane text protocol, so a batch larger
// than u8::MAX would have to clamp its attempt counter. That clamping made the
// decoder treat a genuine TCP label as inconsistent and silently erase
// `(protocol, tcp_flags)` for the whole aggregate. Flushing at 255 packets is
// cheap: 8 MiB ring / 64-byte record = 131072 queued events, far above what
// multi-hundred-kpps floods produce at one flush per 255 packets per source.
// New ports and the per-second epoch flush remain immediate.
const INGRESS_BATCH_PACKETS: u32 = 255;
// Compile-time coupling to the wire contract: the batch must never exceed the
// u8 range of `attempt_count`, so no emitted counter needs saturation. Raising
// this bound requires widening the wire field and the userspace decoders first.
const _: () = assert!(INGRESS_BATCH_PACKETS <= u8::MAX as u32);

#[repr(C)]
pub(crate) struct L2Prefix {
    pub(crate) bytes: [u8; L2_PREFIX_BYTES],
}

#[repr(C)]
pub(crate) struct Ipv4Hdr {
    pub(crate) version_ihl: u8,
    pub(crate) tos: u8,
    pub(crate) total_len: [u8; 2],
    pub(crate) id: [u8; 2],
    pub(crate) frag: [u8; 2],
    pub(crate) ttl: u8,
    pub(crate) protocol: u8,
    pub(crate) checksum: [u8; 2],
    pub(crate) src: [u8; 4],
    pub(crate) dst: [u8; 4],
}

#[repr(C)]
pub(crate) struct Ipv6Hdr {
    pub(crate) version_flow: [u8; 4],
    pub(crate) payload_len: [u8; 2],
    pub(crate) next_header: u8,
    pub(crate) hop_limit: u8,
    pub(crate) src: [u8; 16],
    pub(crate) dst: [u8; 16],
}

#[repr(C)]
pub(crate) struct TcpPrefix {
    pub(crate) src_port: [u8; 2],
    pub(crate) dst_port: [u8; 2],
    pub(crate) seq: [u8; 4],
    pub(crate) ack_seq: [u8; 4],
    pub(crate) data_offset_reserved: u8,
    pub(crate) flags: u8,
}

#[repr(C)]
pub(crate) struct UdpPrefix {
    pub(crate) src_port: [u8; 2],
    pub(crate) dst_port: [u8; 2],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct IngressWindow {
    epoch_sec: u64,
    packets: u32,
    bytes: u32,
    syn_count: u32,
    ack_count: u32,
    attempt_count: u32,
    // Number of buffered packets whose network protocol is TCP. Together with
    // `packets` this tells a flush whether the aggregate mixes TCP and non-TCP
    // packets. Such a batch has no single honest transport label, so it is emitted
    // with the explicit neutral marker instead of inheriting the trigger packet's
    // `(protocol, tcp_flags)`; that inheritance is what the decoder had to guess
    // about before, and it is why the label used to be neutralised on mismatch.
    tcp_packets: u32,
    // Exact bounded destination-port sample for this one-second source window.
    // The old modulo-64 bitmap allowed attacker-controlled collisions (e.g.
    // ports 22 and 86), which could hide a low-volume port scan from userspace.
    port0: u16,
    port1: u16,
    port2: u16,
    port3: u16,
    port4: u16,
    port5: u16,
    port6: u16,
    port7: u16,
}

#[inline(always)]
fn remember_port(state: &mut IngressWindow, port: u16) -> bool {
    if port == 0 {
        return false;
    }
    if state.port0 == port
        || state.port1 == port
        || state.port2 == port
        || state.port3 == port
        || state.port4 == port
        || state.port5 == port
        || state.port6 == port
        || state.port7 == port
    {
        return false;
    }
    if state.port0 == 0 {
        state.port0 = port;
        return true;
    }
    if state.port1 == 0 {
        state.port1 = port;
        return true;
    }
    if state.port2 == 0 {
        state.port2 = port;
        return true;
    }
    if state.port3 == 0 {
        state.port3 = port;
        return true;
    }
    if state.port4 == 0 {
        state.port4 = port;
        return true;
    }
    if state.port5 == 0 {
        state.port5 = port;
        return true;
    }
    if state.port6 == 0 {
        state.port6 = port;
        return true;
    }
    if state.port7 == 0 {
        state.port7 = port;
        return true;
    }
    // Eight exact ports are enough to exceed the default five-port scan gate.
    // Once full, batching continues by packet count rather than emitting every
    // packet and turning telemetry itself into a DoS vector.
    false
}

#[inline(always)]
fn clear_ports(state: &mut IngressWindow) {
    state.port0 = 0;
    state.port1 = 0;
    state.port2 = 0;
    state.port3 = 0;
    state.port4 = 0;
    state.port5 = 0;
    state.port6 = 0;
    state.port7 = 0;
}

/// True when the buffered aggregate mixes TCP and non-TCP packets. Such a batch
/// has no single honest transport label, so its flush must use the explicit
/// neutral marker (`protocol = 0`, `tcp_flags = 0`) instead of inheriting the
/// label of the packet that happened to trigger the flush. A homogeneous batch
/// keeps its label, and for TCP the attempt counter then always equals the SYN
/// counter, which is the invariant the userspace decoder verifies.
#[inline(always)]
fn aggregate_mixes_tcp_classes(state: &IngressWindow) -> bool {
    state.tcp_packets != 0 && state.tcp_packets != state.packets
}

#[inline(always)]
pub(crate) fn observe_ingress_v4(
    source: [u8; 4],
    destination: [u8; 4],
    protocol: u8,
    src_port: u16,
    dst_port: u16,
    tcp_flags: u8,
    packet_len: u32,
) {
    let mut src = [0u8; NETWORK_ADDRESS_BYTES];
    let mut dst = [0u8; NETWORK_ADDRESS_BYTES];
    src[0] = source[0];
    src[1] = source[1];
    src[2] = source[2];
    src[3] = source[3];
    dst[0] = destination[0];
    dst[1] = destination[1];
    dst[2] = destination[2];
    dst[3] = destination[3];
    observe_ingress_common_v4(
        source, src, dst, protocol, src_port, dst_port, tcp_flags, packet_len,
    );
}

#[inline(always)]
fn observe_ingress_common_v4(
    key: [u8; 4],
    source: [u8; NETWORK_ADDRESS_BYTES],
    destination: [u8; NETWORK_ADDRESS_BYTES],
    protocol: u8,
    src_port: u16,
    dst_port: u16,
    tcp_flags: u8,
    packet_len: u32,
) {
    let epoch_sec = unsafe { bpf_ktime_get_ns() } / 1_000_000_000;
    let syn =
        if protocol == NETWORK_PROTOCOL_TCP && (tcp_flags & 0x02) != 0 && (tcp_flags & 0x10) == 0 {
            1
        } else {
            0
        };
    let ack = if protocol == NETWORK_PROTOCOL_TCP && (tcp_flags & 0x10) != 0 {
        1
    } else {
        0
    };
    let attempt = if protocol == NETWORK_PROTOCOL_TCP {
        syn
    } else {
        1
    };
    if let Some(ptr) = INGRESS_TRACK_V4.get_ptr_mut(&key) {
        let state = unsafe { &mut *ptr };
        if state.epoch_sec != epoch_sec {
            // The pending counters belong to the previous second and may span
            // multiple ports/protocols. Do not label that carry-over with the
            // metadata of the *current* packet; doing so can turn old ACK/data
            // traffic into a fake SYN/port signal in userspace. Exact SYN/ACK
            // deltas are preserved, while transport/destination context is
            // intentionally neutral for this flush.
            emit_ingress(
                NETWORK_FAMILY_V4,
                0,
                0,
                0,
                0,
                state.packets,
                state.bytes,
                state.syn_count,
                state.ack_count,
                state.attempt_count,
                state.epoch_sec,
                source,
                [0u8; NETWORK_ADDRESS_BYTES],
            );
            state.epoch_sec = epoch_sec;
            state.packets = 0;
            state.bytes = 0;
            state.syn_count = 0;
            state.ack_count = 0;
            state.attempt_count = 0;
            state.tcp_packets = 0;
            clear_ports(state);
        }
        let new_port = remember_port(state, dst_port);
        if new_port && state.packets > 0 {
            // Flush older activity neutrally before attributing the new port.
            // Otherwise a single new-port packet could inherit up to 15 older
            // attempts and create a false dark-port/portscan strike.
            emit_ingress(
                NETWORK_FAMILY_V4,
                0,
                0,
                0,
                0,
                state.packets,
                state.bytes,
                state.syn_count,
                state.ack_count,
                state.attempt_count,
                state.epoch_sec,
                source,
                [0u8; NETWORK_ADDRESS_BYTES],
            );
            state.packets = 0;
            state.bytes = 0;
            state.syn_count = 0;
            state.ack_count = 0;
            state.attempt_count = 0;
            state.tcp_packets = 0;
        }
        state.packets = state.packets.saturating_add(1);
        state.bytes = state.bytes.saturating_add(packet_len);
        state.syn_count = state.syn_count.saturating_add(syn);
        state.ack_count = state.ack_count.saturating_add(ack);
        state.attempt_count = state.attempt_count.saturating_add(attempt);
        if protocol == NETWORK_PROTOCOL_TCP {
            state.tcp_packets = state.tcp_packets.saturating_add(1);
        }
        if new_port || state.packets >= INGRESS_BATCH_PACKETS {
            if aggregate_mixes_tcp_classes(state) {
                // A mixed TCP/non-TCP batch has no honest transport label: neither
                // the protocol nor the TCP flags of the trigger packet describe the
                // aggregate. Emit the explicit neutral marker (the same contract as
                // the carry-over flushes) with exact counters, so userspace never
                // has to guess and never loses a label that was genuinely TCP-only.
                emit_ingress(
                    NETWORK_FAMILY_V4,
                    0,
                    0,
                    0,
                    0,
                    state.packets,
                    state.bytes,
                    state.syn_count,
                    state.ack_count,
                    state.attempt_count,
                    epoch_sec,
                    source,
                    [0u8; NETWORK_ADDRESS_BYTES],
                );
            } else {
                // Homogeneous batch: the trigger packet's label is representative,
                // and for a TCP-only batch attempt_count equals syn_count.
                emit_ingress(
                    NETWORK_FAMILY_V4,
                    protocol,
                    tcp_flags,
                    src_port,
                    dst_port,
                    state.packets,
                    state.bytes,
                    state.syn_count,
                    state.ack_count,
                    state.attempt_count,
                    epoch_sec,
                    source,
                    destination,
                );
            }
            state.packets = 0;
            state.bytes = 0;
            state.syn_count = 0;
            state.ack_count = 0;
            state.attempt_count = 0;
            state.tcp_packets = 0;
        }
        return;
    }
    let state = IngressWindow {
        epoch_sec,
        packets: 0,
        bytes: 0,
        syn_count: 0,
        ack_count: 0,
        attempt_count: 0,
        tcp_packets: 0,
        port0: dst_port,
        port1: 0,
        port2: 0,
        port3: 0,
        port4: 0,
        port5: 0,
        port6: 0,
        port7: 0,
    };
    if INGRESS_TRACK_V4.insert(&key, &state, 0).is_ok() {
        emit_ingress(
            NETWORK_FAMILY_V4,
            protocol,
            tcp_flags,
            src_port,
            dst_port,
            1,
            packet_len,
            syn,
            ack,
            attempt,
            epoch_sec,
            source,
            destination,
        );
    } else {
        increment_ingress_counter(&INGRESS_TRACK_INSERT_FAILURES);
    }
}

#[inline(always)]
pub(crate) fn observe_ingress_v6(
    source: [u8; 16],
    destination: [u8; 16],
    protocol: u8,
    src_port: u16,
    dst_port: u16,
    tcp_flags: u8,
    packet_len: u32,
) {
    let epoch_sec = unsafe { bpf_ktime_get_ns() } / 1_000_000_000;
    let syn =
        if protocol == NETWORK_PROTOCOL_TCP && (tcp_flags & 0x02) != 0 && (tcp_flags & 0x10) == 0 {
            1
        } else {
            0
        };
    let ack = if protocol == NETWORK_PROTOCOL_TCP && (tcp_flags & 0x10) != 0 {
        1
    } else {
        0
    };
    let attempt = if protocol == NETWORK_PROTOCOL_TCP {
        syn
    } else {
        1
    };
    if let Some(ptr) = INGRESS_TRACK_V6.get_ptr_mut(&source) {
        let state = unsafe { &mut *ptr };
        if state.epoch_sec != epoch_sec {
            // See the IPv4 path above: the pending counters pre-date the
            // current packet, so flush them without borrowing current transport
            // metadata. This keeps source/rate accounting exact without false
            // port or TCP-flag attribution.
            emit_ingress(
                NETWORK_FAMILY_V6,
                0,
                0,
                0,
                0,
                state.packets,
                state.bytes,
                state.syn_count,
                state.ack_count,
                state.attempt_count,
                state.epoch_sec,
                source,
                [0u8; NETWORK_ADDRESS_BYTES],
            );
            state.epoch_sec = epoch_sec;
            state.packets = 0;
            state.bytes = 0;
            state.syn_count = 0;
            state.ack_count = 0;
            state.attempt_count = 0;
            state.tcp_packets = 0;
            clear_ports(state);
        }
        let new_port = remember_port(state, dst_port);
        if new_port && state.packets > 0 {
            // Flush older activity neutrally before attributing the new port.
            // Otherwise a single new-port packet could inherit up to 15 older
            // attempts and create a false dark-port/portscan strike.
            emit_ingress(
                NETWORK_FAMILY_V6,
                0,
                0,
                0,
                0,
                state.packets,
                state.bytes,
                state.syn_count,
                state.ack_count,
                state.attempt_count,
                state.epoch_sec,
                source,
                [0u8; NETWORK_ADDRESS_BYTES],
            );
            state.packets = 0;
            state.bytes = 0;
            state.syn_count = 0;
            state.ack_count = 0;
            state.attempt_count = 0;
            state.tcp_packets = 0;
        }
        state.packets = state.packets.saturating_add(1);
        state.bytes = state.bytes.saturating_add(packet_len);
        state.syn_count = state.syn_count.saturating_add(syn);
        state.ack_count = state.ack_count.saturating_add(ack);
        state.attempt_count = state.attempt_count.saturating_add(attempt);
        if protocol == NETWORK_PROTOCOL_TCP {
            state.tcp_packets = state.tcp_packets.saturating_add(1);
        }
        if new_port || state.packets >= INGRESS_BATCH_PACKETS {
            if aggregate_mixes_tcp_classes(state) {
                // Mixed TCP/non-TCP aggregate: emit the explicit neutral marker with
                // exact counters instead of an unrelated trigger label. See the IPv4
                // path above for the full rationale.
                emit_ingress(
                    NETWORK_FAMILY_V6,
                    0,
                    0,
                    0,
                    0,
                    state.packets,
                    state.bytes,
                    state.syn_count,
                    state.ack_count,
                    state.attempt_count,
                    epoch_sec,
                    source,
                    [0u8; NETWORK_ADDRESS_BYTES],
                );
            } else {
                // Homogeneous batch: keep the representative trigger label.
                emit_ingress(
                    NETWORK_FAMILY_V6,
                    protocol,
                    tcp_flags,
                    src_port,
                    dst_port,
                    state.packets,
                    state.bytes,
                    state.syn_count,
                    state.ack_count,
                    state.attempt_count,
                    epoch_sec,
                    source,
                    destination,
                );
            }
            state.packets = 0;
            state.bytes = 0;
            state.syn_count = 0;
            state.ack_count = 0;
            state.attempt_count = 0;
            state.tcp_packets = 0;
        }
        return;
    }
    let state = IngressWindow {
        epoch_sec,
        packets: 0,
        bytes: 0,
        syn_count: 0,
        ack_count: 0,
        attempt_count: 0,
        tcp_packets: 0,
        port0: dst_port,
        port1: 0,
        port2: 0,
        port3: 0,
        port4: 0,
        port5: 0,
        port6: 0,
        port7: 0,
    };
    if INGRESS_TRACK_V6.insert(&source, &state, 0).is_ok() {
        emit_ingress(
            NETWORK_FAMILY_V6,
            protocol,
            tcp_flags,
            src_port,
            dst_port,
            1,
            packet_len,
            syn,
            ack,
            attempt,
            epoch_sec,
            source,
            destination,
        );
    } else {
        increment_ingress_counter(&INGRESS_TRACK_INSERT_FAILURES);
    }
}

#[inline(always)]
fn emit_ingress(
    family: u8,
    protocol: u8,
    tcp_flags: u8,
    src_port: u16,
    dst_port: u16,
    packets: u32,
    bytes: u32,
    syn_count: u32,
    ack_count: u32,
    attempt_count: u32,
    window_epoch_sec: u64,
    source: [u8; NETWORK_ADDRESS_BYTES],
    destination: [u8; NETWORK_ADDRESS_BYTES],
) {
    if packets == 0 {
        return;
    }
    // Every emitted aggregate fits the wire exactly: `INGRESS_BATCH_PACKETS` is
    // compile-time bounded to u8::MAX, the producer flushes before a larger batch
    // can accumulate, and every path that produces an aggregate counts at most one
    // attempt per packet. Do not saturate here: a silently clamped attempt counter
    // made a genuine TCP label look inconsistent and erased protocol/tcp_flags for
    // the whole batch in userspace. If the invariant were ever broken, drop the
    // sample and account it in the existing event-loss health counter instead.
    if packets > INGRESS_BATCH_PACKETS || attempt_count > u8::MAX as u32 {
        increment_ingress_counter(&INGRESS_RING_DROPS);
        return;
    }
    let event = IngressEvent {
        family,
        protocol,
        tcp_flags,
        attempt_count: attempt_count as u8,
        src_port,
        dst_port,
        packets,
        bytes,
        syn_count,
        ack_count,
        window_epoch_sec,
        source,
        destination,
    };
    if INGRESS_EVENTS.output::<IngressEvent>(&event, 0).is_ok() {
        increment_ingress_counter(&INGRESS_EVENTS_EMITTED);
    } else {
        increment_ingress_counter(&INGRESS_RING_DROPS);
    }
}

#[inline(always)]
fn increment_ingress_counter(counter: &PerCpuArray<u64>) {
    increment_counter(counter);
}

#[inline(always)]
pub(crate) fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();
    if start
        .checked_add(offset)
        .and_then(|value| value.checked_add(len))
        .ok_or(())?
        > end
    {
        return Err(());
    }
    Ok((start + offset) as *const T)
}
