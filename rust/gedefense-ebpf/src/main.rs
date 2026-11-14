#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::{xdp_action, BPF_F_NO_PREALLOC, TC_ACT_OK, TC_ACT_SHOT},
    helpers::{
        bpf_get_current_ancestor_cgroup_id, bpf_get_current_comm, bpf_get_current_pid_tgid,
        bpf_get_current_uid_gid, bpf_ktime_get_ns,
    },
    macros::{cgroup_skb, classifier, lsm, map, tracepoint, xdp},
    maps::{lpm_trie::Key, HashMap, LpmTrie, LruPerCpuHashMap, PerCpuArray, RingBuf},
    programs::{LsmContext, SkBuffContext, TcContext, TracePointContext, XdpContext},
};
use core::mem;
use gedefense_common::{
    parse_network_header, CellLsmDenyEvent, EgressDropEvent, ExecEvent, IngressEvent,
    NetworkHeader, ACTION_DROP, CELL_LSM_DENY_NON_UNIX_SOCKET, EXEC_COMM_BYTES, L2_PREFIX_BYTES,
    MAX_BLOCKLIST_ENTRIES_V4, MAX_BLOCKLIST_ENTRIES_V6, NETWORK_ADDRESS_BYTES, NETWORK_FAMILY_V4,
    NETWORK_FAMILY_V6, NETWORK_PROTOCOL_TCP,
};

const MAX_ALLOWLIST_ENTRIES: u32 = 65_536;
const EXEC_EVENT_RING_BYTES: u32 = 1 << 20;
const EGRESS_EVENT_RING_BYTES: u32 = 1 << 20;
const CELL_LSM_EVENT_RING_BYTES: u32 = 1 << 20;
const INGRESS_EVENT_RING_BYTES: u32 = 8 << 20;
const MAX_INGRESS_TRACKED_SOURCES: u32 = 8_192;
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
const INGRESS_HEALTH_KEY: u32 = 0;
const MAX_CELL_LSM_POLICIES: u32 = 4096;
// Maximum cgroup-v2 ancestor levels inspected per socket creation. The walk
// starts at the root (level 0) and the kernel returns 0 once the requested level
// is below the current cgroup, so the real cost is hierarchy depth + 2 helper
// calls. cgroup.max.depth defaults to "max"; hierarchies deeper than this bound
// are a documented residual limitation of the bounded eBPF loop.
const MAX_CGROUP_ANCESTOR_LEVELS: i32 = 64;
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
    // The trailing argument is the return value of the previously attached LSM
    // program on this hook. Defer to it, exactly like the kernel LSM chain does,
    // before applying the Gaia Cell policy.
    let previous: i32 = ctx.arg(4);
    if previous != 0 {
        return Ok(previous);
    }
    let family: i32 = ctx.arg(0);
    if family == AF_UNIX {
        return Ok(0);
    }
    // AF_UNSPEC (0) reaches this hook because __sock_create() only range-checks
    // the family and performs the real lookup afterwards; a socket for it can
    // never exist (-EAFNOSUPPORT). Refuse such requests explicitly instead of
    // passing them through the policy check. Families that do not fit the u8
    // field of CellLsmDenyEvent are refused the same way and without telemetry:
    // the core's CELL_LSM event validator rejects family <= 0 or > u8::MAX as
    // malformed wire data, so emitting a deny event there would abort a whole
    // event drain. The matching userspace boundary is fixed in the core crate
    // (rust/gedefense-core/src/main.rs); this is the kernel-side half.
    if family <= 0 || family > i32::from(u8::MAX) {
        return Ok(-EPERM);
    }
    // Walk the complete cgroup-v2 ancestry from the root (level 0) down to the
    // current cgroup instead of matching only the current cgroup id. A policy
    // installed on the Gaia Cell cgroup has to cover every descendant/leaf cgroup
    // a cell process can be moved into; the previous direct-key match let child
    // cgroups escape enforcement entirely. The kernel returns 0 for levels below
    // the current cgroup, which ends the bounded loop. The matched cgroup id is
    // reported in the event because that is the cell boundary the control plane
    // installs policies for and correlates evidence against.
    //
    // Coverage boundary: socket_create is only reached when a socket is created.
    // Sockets inherited across fork/exec or received over SCM_RIGHTS never pass
    // this hook again, so a task inside an enforcing cell can still receive an
    // already-created AF_INET socket from outside the cell. Closing that gap needs
    // connect/sendmsg-time enforcement and remains a documented residual risk of
    // this hook; it cannot be observed or repaired here.
    let mut level: i32 = 0;
    while level < MAX_CGROUP_ANCESTOR_LEVELS {
        let cgroup_id = unsafe { bpf_get_current_ancestor_cgroup_id(level) };
        if cgroup_id == 0 {
            break;
        }
        if let Some(policy) = unsafe { CELL_LSM_POLICIES.get(&cgroup_id) } {
            if *policy & CELL_LSM_DENY_NON_UNIX_SOCKET != 0 {
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
                return Ok(-EPERM);
            }
        }
        level += 1;
    }
    Ok(0)
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
        // Fail closed: the only error paths here are frames advertised as IPv4/IPv6
        // whose headers are truncated or self-contradictory. Such a frame is invalid
        // for the kernel network stack as well, so passing it on would only hand the
        // malformed packet to the stack; non-IP L2 is classified as
        // `NetworkHeader::Other` and stays on the pass path.
        Err(()) => xdp_action::XDP_DROP,
    }
}

#[classifier]
pub fn gedefense_tc_ingress(ctx: TcContext) -> i32 {
    match inspect_tc_ingress(&ctx) {
        Ok(true) => TC_ACT_SHOT,
        Ok(false) => TC_ACT_OK,
        // Same fail-closed rule as XDP: malformed/truncated L3 frames cannot be
        // classified against the policy maps, so they are dropped instead of passed.
        Err(()) => TC_ACT_SHOT,
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
    let (src_port, dst_port, flags) = if header.version_ihl & 0x0f == 5 {
        tc_transport_metadata(ctx, offset + mem::size_of::<Ipv4Hdr>(), header.protocol)
    } else {
        (0, 0, 0)
    };
    // Observe before the policy verdict: an allowlisted source must not become
    // invisible to the ingress counters. The previous early return meant a flood
    // from an allowlisted prefix never reached the sensor health/rate telemetry.
    observe_ingress_v4(
        header.src,
        header.dst,
        header.protocol,
        src_port,
        dst_port,
        flags,
        ctx.len(),
    );
    if ALLOWLIST_V4.get(&key).is_some() {
        return Ok(false);
    }
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
    let (src_port, dst_port, flags) =
        tc_transport_metadata(ctx, offset + mem::size_of::<Ipv6Hdr>(), header.next_header);
    // Count before the allowlist verdict; see the IPv4 path above.
    observe_ingress_v6(
        header.src,
        header.dst,
        header.next_header,
        src_port,
        dst_port,
        flags,
        ctx.len(),
    );
    if ALLOWLIST_V6.get(&key).is_some() {
        return Ok(false);
    }
    Ok(BLOCKLIST_V6
        .get(&key)
        .is_some_and(|action| *action == ACTION_DROP))
}

#[inline(always)]
fn tc_transport_metadata(ctx: &TcContext, offset: usize, protocol: u8) -> (u16, u16, u8) {
    if protocol == NETWORK_PROTOCOL_TCP {
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
    // Observe before the policy verdict: an allowlisted source must not become
    // invisible to the ingress counters. The previous early return meant a flood
    // from an allowlisted prefix never reached the sensor health/rate telemetry.
    observe_ingress_v4(src, dst, protocol, src_port, dst_port, flags, packet_len);
    if ALLOWLIST_V4.get(&key).is_some() {
        return Ok(xdp_action::XDP_PASS);
    }

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

    // Only direct TCP/UDP next-headers are parsed here. Extension-header chains
    // remain visible as IP-level telemetry and are left to userspace/L7 logic.
    let (src_port, dst_port, flags) =
        xdp_transport_metadata(ctx, offset + mem::size_of::<Ipv6Hdr>(), protocol);
    let packet_len = ctx.data_end().saturating_sub(ctx.data()) as u32;
    // Count before the allowlist verdict; see the IPv4 path above.
    observe_ingress_v6(src, dst, protocol, src_port, dst_port, flags, packet_len);
    if ALLOWLIST_V6.get(&key).is_some() {
        return Ok(xdp_action::XDP_PASS);
    }

    if let Some(action) = BLOCKLIST_V6.get(&key) {
        if *action == ACTION_DROP {
            return Ok(xdp_action::XDP_DROP);
        }
    }
    Ok(xdp_action::XDP_PASS)
}

#[inline(always)]
fn xdp_transport_metadata(ctx: &XdpContext, offset: usize, protocol: u8) -> (u16, u16, u8) {
    if protocol == NETWORK_PROTOCOL_TCP {
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
