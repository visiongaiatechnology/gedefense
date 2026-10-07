#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::{xdp_action, BPF_F_NO_PREALLOC, TC_ACT_OK, TC_ACT_SHOT},
    helpers::{
        bpf_get_current_cgroup_id, bpf_get_current_comm, bpf_get_current_pid_tgid,
        bpf_get_current_uid_gid, bpf_ktime_get_ns,
    },
    macros::{cgroup_skb, classifier, lsm, map, tracepoint, xdp},
    maps::{lpm_trie::Key, HashMap, LpmTrie, LruPerCpuHashMap, PerCpuArray, RingBuf},
    programs::{LsmContext, SkBuffContext, TcContext, TracePointContext, XdpContext},
};
use core::mem;
use gedefense_common::{
    parse_network_header, CellLsmDenyEvent, EgressDropEvent, ExecEvent, IngressEvent, NetworkHeader, ACTION_DROP,
    CELL_LSM_DENY_NON_UNIX_SOCKET, EXEC_COMM_BYTES, L2_PREFIX_BYTES, MAX_BLOCKLIST_ENTRIES_V4,
    MAX_BLOCKLIST_ENTRIES_V6, NETWORK_ADDRESS_BYTES, NETWORK_FAMILY_V4, NETWORK_FAMILY_V6,
};

const MAX_ALLOWLIST_ENTRIES: u32 = 65_536;
const EXEC_EVENT_RING_BYTES: u32 = 1 << 20;
const EGRESS_EVENT_RING_BYTES: u32 = 1 << 20;
const CELL_LSM_EVENT_RING_BYTES: u32 = 1 << 20;
const INGRESS_EVENT_RING_BYTES: u32 = 2 << 20;
const MAX_INGRESS_TRACKED_SOURCES: u32 = 8_192;
const INGRESS_BATCH_PACKETS: u32 = 16;
const INGRESS_HEALTH_KEY: u32 = 0;
const MAX_CELL_LSM_POLICIES: u32 = 4096;
const AF_UNIX: i32 = 1;
const EPERM: i32 = 1;

#[repr(C)]
struct L2Prefix {
    bytes: [u8; L2_PREFIX_BYTES],
}

#[repr(C)]
struct Ipv4Hdr {
    version_ihl: u8,
    tos: u8,
    total_len: [u8; 2],
    id: [u8; 2],
    frag: [u8; 2],
    ttl: u8,
    protocol: u8,
    checksum: [u8; 2],
    src: [u8; 4],
    dst: [u8; 4],
}

#[repr(C)]
struct Ipv6Hdr {
    version_flow: [u8; 4],
    payload_len: [u8; 2],
    next_header: u8,
    hop_limit: u8,
    src: [u8; 16],
    dst: [u8; 16],
}

#[repr(C)]
struct TcpPrefix {
    src_port: [u8; 2],
    dst_port: [u8; 2],
    seq: [u8; 4],
    ack_seq: [u8; 4],
    data_offset_reserved: u8,
    flags: u8,
}

#[repr(C)]
struct UdpPrefix {
    src_port: [u8; 2],
    dst_port: [u8; 2],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct IngressWindow {
    epoch_sec: u64,
    packets: u32,
    bytes: u32,
    syn_count: u32,
    ack_count: u32,
    attempt_count: u32,
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

#[map]
static ALLOWLIST_V4: LpmTrie<[u8; 4], u8> =
    LpmTrie::with_max_entries(MAX_ALLOWLIST_ENTRIES, BPF_F_NO_PREALLOC);
#[map]
static ALLOWLIST_V6: LpmTrie<[u8; 16], u8> =
    LpmTrie::with_max_entries(MAX_ALLOWLIST_ENTRIES, BPF_F_NO_PREALLOC);
#[map]
static BLOCKLIST_V4: LpmTrie<[u8; 4], u8> =
    LpmTrie::with_max_entries(MAX_BLOCKLIST_ENTRIES_V4, BPF_F_NO_PREALLOC);
#[map]
static BLOCKLIST_V6: LpmTrie<[u8; 16], u8> =
    LpmTrie::with_max_entries(MAX_BLOCKLIST_ENTRIES_V6, BPF_F_NO_PREALLOC);
#[map]
static EXEC_EVENTS: RingBuf = RingBuf::with_byte_size(EXEC_EVENT_RING_BYTES, 0);
#[map]
static EGRESS_EVENTS: RingBuf = RingBuf::with_byte_size(EGRESS_EVENT_RING_BYTES, 0);
#[map]
static INGRESS_EVENTS: RingBuf = RingBuf::with_byte_size(INGRESS_EVENT_RING_BYTES, 0);
#[map]
static INGRESS_TRACK_V4: LruPerCpuHashMap<[u8; 4], IngressWindow> =
    LruPerCpuHashMap::with_max_entries(MAX_INGRESS_TRACKED_SOURCES, 0);
#[map]
static INGRESS_TRACK_V6: LruPerCpuHashMap<[u8; 16], IngressWindow> =
    LruPerCpuHashMap::with_max_entries(MAX_INGRESS_TRACKED_SOURCES, 0);
#[map]
static INGRESS_EVENTS_EMITTED: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);
#[map]
static INGRESS_RING_DROPS: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);
#[map]
static INGRESS_TRACK_INSERT_FAILURES: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);

#[map]
static CELL_LSM_POLICIES: HashMap<u64, u8> =
    HashMap::with_max_entries(MAX_CELL_LSM_POLICIES, BPF_F_NO_PREALLOC);
#[map]
static CELL_LSM_EVENTS: RingBuf = RingBuf::with_byte_size(CELL_LSM_EVENT_RING_BYTES, 0);

#[lsm(hook = "socket_create")]
pub fn gedefense_cell_socket_create(ctx: LsmContext) -> i32 {
    match try_cell_socket_create(ctx) {
        Ok(value) | Err(value) => value,
    }
}

#[inline(always)]
fn try_cell_socket_create(ctx: LsmContext) -> Result<i32, i32> {
    let previous: i32 = ctx.arg(4);
    if previous != 0 {
        return Ok(previous);
    }
    let family: i32 = ctx.arg(0);
    if family == AF_UNIX {
        return Ok(0);
    }
    let cgroup_id = unsafe { bpf_get_current_cgroup_id() };
    let Some(policy) = (unsafe { CELL_LSM_POLICIES.get(&cgroup_id) }) else {
        return Ok(0);
    };
    if *policy & CELL_LSM_DENY_NON_UNIX_SOCKET == 0 {
        return Ok(0);
    }
    let pid_tgid = bpf_get_current_pid_tgid();
    let uid_gid = bpf_get_current_uid_gid();
    let event = CellLsmDenyEvent {
        cgroup_id,
        pid: (pid_tgid >> 32) as u32,
        uid: uid_gid as u32,
        family,
        action: ACTION_DROP,
        reserved: [0; 3],
    };
    let _ = CELL_LSM_EVENTS.output::<CellLsmDenyEvent>(&event, 0);
    Ok(-EPERM)
}
#[tracepoint]
pub fn gedefense_exec(_ctx: TracePointContext) -> u32 {
    let pid_tgid = bpf_get_current_pid_tgid();
    let uid_gid = bpf_get_current_uid_gid();
    let comm = match bpf_get_current_comm() {
        Ok(value) => value,
        Err(_) => return 0,
    };
    let event = ExecEvent {
        pid: (pid_tgid >> 32) as u32,
        uid: uid_gid as u32,
        gid: (uid_gid >> 32) as u32,
        comm,
    };
    let _ = EXEC_EVENTS.output::<ExecEvent>(&event, 0);
    0
}

#[xdp]
pub fn gedefense_xdp(ctx: XdpContext) -> u32 {
    match inspect(&ctx) {
        Ok(action) => action,
        Err(()) => xdp_action::XDP_PASS,
    }
}

#[classifier]
pub fn gedefense_tc_ingress(ctx: TcContext) -> i32 {
    match inspect_tc_ingress(&ctx) {
        Ok(true) => TC_ACT_SHOT,
        Ok(false) | Err(()) => TC_ACT_OK,
    }
}

#[inline(always)]
fn inspect_tc_ingress(ctx: &TcContext) -> Result<bool, ()> {
    let prefix: L2Prefix = ctx.load(0).map_err(|_| ())?;
    match parse_network_header(&prefix.bytes) {
        NetworkHeader::Ipv4(offset) => inspect_tc_ipv4(ctx, offset),
        NetworkHeader::Ipv6(offset) => inspect_tc_ipv6(ctx, offset),
        NetworkHeader::Other => Ok(false),
    }
}

#[inline(always)]
fn inspect_tc_ipv4(ctx: &TcContext, offset: usize) -> Result<bool, ()> {
    let header: Ipv4Hdr = ctx.load(offset).map_err(|_| ())?;
    if header.version_ihl >> 4 != NETWORK_FAMILY_V4 || header.version_ihl & 0x0f < 5 {
        return Err(());
    }
    let key = Key::new(32, header.src);
    if ALLOWLIST_V4.get(&key).is_some() {
        return Ok(false);
    }
    let (src_port, dst_port, flags) = if header.version_ihl & 0x0f == 5 {
        tc_transport_metadata(ctx, offset + mem::size_of::<Ipv4Hdr>(), header.protocol)
    } else {
        (0, 0, 0)
    };
    observe_ingress_v4(header.src, header.dst, header.protocol, src_port, dst_port, flags, ctx.len());
    Ok(BLOCKLIST_V4
        .get(&key)
        .is_some_and(|action| *action == ACTION_DROP))
}

#[inline(always)]
fn inspect_tc_ipv6(ctx: &TcContext, offset: usize) -> Result<bool, ()> {
    let header: Ipv6Hdr = ctx.load(offset).map_err(|_| ())?;
    if u32::from_be_bytes(header.version_flow) >> 28 != u32::from(NETWORK_FAMILY_V6) {
        return Err(());
    }
    let key = Key::new(128, header.src);
    if ALLOWLIST_V6.get(&key).is_some() {
        return Ok(false);
    }
    let (src_port, dst_port, flags) = tc_transport_metadata(
        ctx,
        offset + mem::size_of::<Ipv6Hdr>(),
        header.next_header,
    );
    observe_ingress_v6(header.src, header.dst, header.next_header, src_port, dst_port, flags, ctx.len());
    Ok(BLOCKLIST_V6
        .get(&key)
        .is_some_and(|action| *action == ACTION_DROP))
}

#[inline(always)]
fn tc_transport_metadata(ctx: &TcContext, offset: usize, protocol: u8) -> (u16, u16, u8) {
    if protocol == 6 {
        if let Ok(tcp) = ctx.load::<TcpPrefix>(offset) {
            return (
                u16::from_be_bytes(tcp.src_port),
                u16::from_be_bytes(tcp.dst_port),
                tcp.flags,
            );
        }
    } else if protocol == 17 {
        if let Ok(udp) = ctx.load::<UdpPrefix>(offset) {
            return (
                u16::from_be_bytes(udp.src_port),
                u16::from_be_bytes(udp.dst_port),
                0,
            );
        }
    }
    (0, 0, 0)
}

#[cgroup_skb(egress)]
pub fn gedefense_egress(ctx: SkBuffContext) -> i32 {
    match inspect_egress(&ctx) {
        Ok(true) => 0,
        Ok(false) | Err(()) => 1,
    }
}

#[inline(always)]
fn inspect_egress(ctx: &SkBuffContext) -> Result<bool, ()> {
    let version: u8 = ctx.load(0).map_err(|_| ())?;
    match version >> 4 {
        NETWORK_FAMILY_V4 => inspect_egress_v4(ctx),
        NETWORK_FAMILY_V6 => inspect_egress_v6(ctx),
        _ => Err(()),
    }
}

#[inline(always)]
fn inspect_egress_v4(ctx: &SkBuffContext) -> Result<bool, ()> {
    let header: Ipv4Hdr = ctx.load(0).map_err(|_| ())?;
    if header.version_ihl >> 4 != NETWORK_FAMILY_V4 || header.version_ihl & 0x0f < 5 {
        return Err(());
    }
    let key = Key::new(32, header.dst);
    if ALLOWLIST_V4.get(&key).is_some() {
        return Ok(false);
    }
    if let Some(action) = BLOCKLIST_V4.get(&key) {
        if *action == ACTION_DROP {
            emit_egress_drop(
                NETWORK_FAMILY_V4,
                header.protocol,
                [
                    header.dst[0],
                    header.dst[1],
                    header.dst[2],
                    header.dst[3],
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                ],
            );
            return Ok(true);
        }
    }
    Ok(false)
}

#[inline(always)]
fn inspect_egress_v6(ctx: &SkBuffContext) -> Result<bool, ()> {
    let header: Ipv6Hdr = ctx.load(0).map_err(|_| ())?;
    if u32::from_be_bytes(header.version_flow) >> 28 != u32::from(NETWORK_FAMILY_V6) {
        return Err(());
    }
    let key = Key::new(128, header.dst);
    if ALLOWLIST_V6.get(&key).is_some() {
        return Ok(false);
    }
    if let Some(action) = BLOCKLIST_V6.get(&key) {
        if *action == ACTION_DROP {
            emit_egress_drop(NETWORK_FAMILY_V6, header.next_header, header.dst);
            return Ok(true);
        }
    }
    Ok(false)
}

#[inline(always)]
fn emit_egress_drop(family: u8, protocol: u8, destination: [u8; NETWORK_ADDRESS_BYTES]) {
    let pid_tgid = bpf_get_current_pid_tgid();
    let uid_gid = bpf_get_current_uid_gid();
    let comm = bpf_get_current_comm().unwrap_or([0u8; EXEC_COMM_BYTES]);
    let event = EgressDropEvent {
        pid: (pid_tgid >> 32) as u32,
        uid: uid_gid as u32,
        family,
        protocol,
        action: ACTION_DROP,
        reserved: 0,
        destination,
        comm,
    };
    let _ = EGRESS_EVENTS.output::<EgressDropEvent>(&event, 0);
}

#[inline(always)]
fn inspect(ctx: &XdpContext) -> Result<u32, ()> {
    let prefix: *const L2Prefix = ptr_at(ctx, 0)?;
    // SAFETY: ptr_at proves the complete fixed prefix lies inside data..data_end.
    // Copying it into the stack exposes the same bounded parser to host fuzzing.
    let bytes = unsafe { (*prefix).bytes };
    match parse_network_header(&bytes) {
        NetworkHeader::Ipv4(offset) => inspect_v4(ctx, offset),
        NetworkHeader::Ipv6(offset) => inspect_v6(ctx, offset),
        NetworkHeader::Other => Ok(xdp_action::XDP_PASS),
    }
}

#[inline(always)]
fn inspect_v4(ctx: &XdpContext, offset: usize) -> Result<u32, ()> {
    let header: *const Ipv4Hdr = ptr_at(ctx, offset)?;
    let version_ihl = unsafe { (*header).version_ihl };
    if version_ihl >> 4 != 4 {
        return Err(());
    }
    let ihl_words = version_ihl & 0x0f;
    if ihl_words < 5 {
        return Err(());
    }

    let src = unsafe { (*header).src };
    let dst = unsafe { (*header).dst };
    let protocol = unsafe { (*header).protocol };
    let key = Key::new(32, src);
    if ALLOWLIST_V4.get(&key).is_some() {
        return Ok(xdp_action::XDP_PASS);
    }

    // Transport parsing is deliberately restricted to the fixed IPv4 header
    // form (IHL=5). Packets carrying IPv4 options still contribute source/rate
    // telemetry, but ports remain unknown instead of relying on attacker-
    // controlled pointer arithmetic that hardening kernels may reject.
    let (src_port, dst_port, flags) = if ihl_words == 5 {
        xdp_transport_metadata(ctx, offset + mem::size_of::<Ipv4Hdr>(), protocol)
    } else {
        (0, 0, 0)
    };
    let packet_len = ctx.data_end().saturating_sub(ctx.data()) as u32;
    observe_ingress_v4(src, dst, protocol, src_port, dst_port, flags, packet_len);

    if let Some(action) = BLOCKLIST_V4.get(&key) {
        if *action == ACTION_DROP {
            return Ok(xdp_action::XDP_DROP);
        }
    }
    Ok(xdp_action::XDP_PASS)
}

#[inline(always)]
fn inspect_v6(ctx: &XdpContext, offset: usize) -> Result<u32, ()> {
    let header: *const Ipv6Hdr = ptr_at(ctx, offset)?;
    if u32::from_be_bytes(unsafe { (*header).version_flow }) >> 28 != 6 {
        return Err(());
    }
    let src = unsafe { (*header).src };
    let dst = unsafe { (*header).dst };
    let protocol = unsafe { (*header).next_header };
    let key = Key::new(128, src);
    if ALLOWLIST_V6.get(&key).is_some() {
        return Ok(xdp_action::XDP_PASS);
    }

    // Only direct TCP/UDP next-headers are parsed here. Extension-header chains
    // remain visible as IP-level telemetry and are left to userspace/L7 logic.
    let (src_port, dst_port, flags) =
        xdp_transport_metadata(ctx, offset + mem::size_of::<Ipv6Hdr>(), protocol);
    let packet_len = ctx.data_end().saturating_sub(ctx.data()) as u32;
    observe_ingress_v6(src, dst, protocol, src_port, dst_port, flags, packet_len);

    if let Some(action) = BLOCKLIST_V6.get(&key) {
        if *action == ACTION_DROP {
            return Ok(xdp_action::XDP_DROP);
        }
    }
    Ok(xdp_action::XDP_PASS)
}

#[inline(always)]
fn xdp_transport_metadata(ctx: &XdpContext, offset: usize, protocol: u8) -> (u16, u16, u8) {
    if protocol == 6 {
        if let Ok(tcp) = ptr_at::<TcpPrefix>(ctx, offset) {
            let tcp = unsafe { &*tcp };
            return (
                u16::from_be_bytes(tcp.src_port),
                u16::from_be_bytes(tcp.dst_port),
                tcp.flags,
            );
        }
    } else if protocol == 17 {
        if let Ok(udp) = ptr_at::<UdpPrefix>(ctx, offset) {
            let udp = unsafe { &*udp };
            return (
                u16::from_be_bytes(udp.src_port),
                u16::from_be_bytes(udp.dst_port),
                0,
            );
        }
    }
    (0, 0, 0)
}

#[inline(always)]
fn remember_port(state: &mut IngressWindow, port: u16) -> bool {
    if port == 0 {
        return false;
    }
    if state.port0 == port || state.port1 == port || state.port2 == port || state.port3 == port
        || state.port4 == port || state.port5 == port || state.port6 == port || state.port7 == port
    {
        return false;
    }
    if state.port0 == 0 { state.port0 = port; return true; }
    if state.port1 == 0 { state.port1 = port; return true; }
    if state.port2 == 0 { state.port2 = port; return true; }
    if state.port3 == 0 { state.port3 = port; return true; }
    if state.port4 == 0 { state.port4 = port; return true; }
    if state.port5 == 0 { state.port5 = port; return true; }
    if state.port6 == 0 { state.port6 = port; return true; }
    if state.port7 == 0 { state.port7 = port; return true; }
    // Eight exact ports are enough to exceed the default five-port scan gate.
    // Once full, batching continues by packet count rather than emitting every
    // packet and turning telemetry itself into a DoS vector.
    false
}

#[inline(always)]
fn clear_ports(state: &mut IngressWindow) {
    state.port0 = 0; state.port1 = 0; state.port2 = 0; state.port3 = 0;
    state.port4 = 0; state.port5 = 0; state.port6 = 0; state.port7 = 0;
}

#[inline(always)]
fn observe_ingress_v4(
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
    src[0] = source[0]; src[1] = source[1]; src[2] = source[2]; src[3] = source[3];
    dst[0] = destination[0]; dst[1] = destination[1]; dst[2] = destination[2]; dst[3] = destination[3];
    observe_ingress_common_v4(source, src, dst, protocol, src_port, dst_port, tcp_flags, packet_len);
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
    let syn = if protocol == 6 && (tcp_flags & 0x02) != 0 && (tcp_flags & 0x10) == 0 { 1 } else { 0 };
    let ack = if protocol == 6 && (tcp_flags & 0x10) != 0 { 1 } else { 0 };
    let attempt = if protocol == 6 { syn } else { 1 };
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
            clear_ports(state);
        }
        let new_port = remember_port(state, dst_port);
        if new_port && state.packets > 0 {
            // Flush older activity neutrally before attributing the new port.
            // Otherwise a single new-port packet could inherit up to 15 older
            // attempts and create a false dark-port/portscan strike.
            emit_ingress(
                NETWORK_FAMILY_V4, 0, 0, 0, 0, state.packets, state.bytes,
                state.syn_count, state.ack_count, state.attempt_count, state.epoch_sec,
                source, [0u8; NETWORK_ADDRESS_BYTES],
            );
            state.packets = 0;
            state.bytes = 0;
            state.syn_count = 0;
            state.ack_count = 0;
            state.attempt_count = 0;
        }
        state.packets = state.packets.saturating_add(1);
        state.bytes = state.bytes.saturating_add(packet_len);
        state.syn_count = state.syn_count.saturating_add(syn);
        state.ack_count = state.ack_count.saturating_add(ack);
        state.attempt_count = state.attempt_count.saturating_add(attempt);
        if new_port || state.packets >= INGRESS_BATCH_PACKETS {
            emit_ingress(NETWORK_FAMILY_V4, protocol, tcp_flags, src_port, dst_port, state.packets, state.bytes, state.syn_count, state.ack_count, state.attempt_count, epoch_sec, source, destination);
            state.packets = 0;
            state.bytes = 0;
            state.syn_count = 0;
            state.ack_count = 0;
            state.attempt_count = 0;
        }
        return;
    }
    let state = IngressWindow {
        epoch_sec, packets: 0, bytes: 0, syn_count: 0, ack_count: 0, attempt_count: 0,
        port0: dst_port, port1: 0, port2: 0, port3: 0, port4: 0, port5: 0, port6: 0, port7: 0,
    };
    if INGRESS_TRACK_V4.insert(&key, &state, 0).is_ok() {
        emit_ingress(NETWORK_FAMILY_V4, protocol, tcp_flags, src_port, dst_port, 1, packet_len, syn, ack, attempt, epoch_sec, source, destination);
    } else {
        increment_ingress_counter(&INGRESS_TRACK_INSERT_FAILURES);
    }
}

#[inline(always)]
fn observe_ingress_v6(
    source: [u8; 16],
    destination: [u8; 16],
    protocol: u8,
    src_port: u16,
    dst_port: u16,
    tcp_flags: u8,
    packet_len: u32,
) {
    let epoch_sec = unsafe { bpf_ktime_get_ns() } / 1_000_000_000;
    let syn = if protocol == 6 && (tcp_flags & 0x02) != 0 && (tcp_flags & 0x10) == 0 { 1 } else { 0 };
    let ack = if protocol == 6 && (tcp_flags & 0x10) != 0 { 1 } else { 0 };
    let attempt = if protocol == 6 { syn } else { 1 };
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
            clear_ports(state);
        }
        let new_port = remember_port(state, dst_port);
        if new_port && state.packets > 0 {
            // Flush older activity neutrally before attributing the new port.
            // Otherwise a single new-port packet could inherit up to 15 older
            // attempts and create a false dark-port/portscan strike.
            emit_ingress(
                NETWORK_FAMILY_V6, 0, 0, 0, 0, state.packets, state.bytes,
                state.syn_count, state.ack_count, state.attempt_count, state.epoch_sec,
                source, [0u8; NETWORK_ADDRESS_BYTES],
            );
            state.packets = 0;
            state.bytes = 0;
            state.syn_count = 0;
            state.ack_count = 0;
            state.attempt_count = 0;
        }
        state.packets = state.packets.saturating_add(1);
        state.bytes = state.bytes.saturating_add(packet_len);
        state.syn_count = state.syn_count.saturating_add(syn);
        state.ack_count = state.ack_count.saturating_add(ack);
        state.attempt_count = state.attempt_count.saturating_add(attempt);
        if new_port || state.packets >= INGRESS_BATCH_PACKETS {
            emit_ingress(NETWORK_FAMILY_V6, protocol, tcp_flags, src_port, dst_port, state.packets, state.bytes, state.syn_count, state.ack_count, state.attempt_count, epoch_sec, source, destination);
            state.packets = 0;
            state.bytes = 0;
            state.syn_count = 0;
            state.ack_count = 0;
            state.attempt_count = 0;
        }
        return;
    }
    let state = IngressWindow {
        epoch_sec, packets: 0, bytes: 0, syn_count: 0, ack_count: 0, attempt_count: 0,
        port0: dst_port, port1: 0, port2: 0, port3: 0, port4: 0, port5: 0, port6: 0, port7: 0,
    };
    if INGRESS_TRACK_V6.insert(&source, &state, 0).is_ok() {
        emit_ingress(NETWORK_FAMILY_V6, protocol, tcp_flags, src_port, dst_port, 1, packet_len, syn, ack, attempt, epoch_sec, source, destination);
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
    let attempts = if attempt_count > u8::MAX as u32 { u8::MAX } else { attempt_count as u8 };
    let event = IngressEvent {
        family, protocol, tcp_flags, attempt_count: attempts, src_port, dst_port, packets, bytes, syn_count, ack_count, window_epoch_sec, source, destination,
    };
    if INGRESS_EVENTS.output::<IngressEvent>(&event, 0).is_ok() {
        increment_ingress_counter(&INGRESS_EVENTS_EMITTED);
    } else {
        increment_ingress_counter(&INGRESS_RING_DROPS);
    }
}

#[inline(always)]
fn increment_ingress_counter(counter: &PerCpuArray<u64>) {
    if let Some(ptr) = counter.get_ptr_mut(INGRESS_HEALTH_KEY) {
        let value = unsafe { &mut *ptr };
        *value = value.saturating_add(1);
    }
}

#[inline(always)]
fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
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

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    // eBPF programs cannot unwind. This branch is unreachable in verified paths.
    unsafe { core::hint::unreachable_unchecked() }
}
