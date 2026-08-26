#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::{xdp_action, BPF_F_NO_PREALLOC, TC_ACT_OK, TC_ACT_SHOT},
    helpers::{bpf_get_current_cgroup_id, bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid},
    macros::{cgroup_skb, classifier, lsm, map, tracepoint, xdp},
    maps::{lpm_trie::Key, HashMap, LpmTrie, RingBuf},
    programs::{LsmContext, SkBuffContext, TcContext, TracePointContext, XdpContext},
};
use core::mem;
use gedefense_common::{
    parse_network_header, CellLsmDenyEvent, EgressDropEvent, ExecEvent, NetworkHeader, ACTION_DROP,
    CELL_LSM_DENY_NON_UNIX_SOCKET,
    EXEC_COMM_BYTES, L2_PREFIX_BYTES, MAX_BLOCKLIST_ENTRIES_V4, MAX_BLOCKLIST_ENTRIES_V6,
    NETWORK_ADDRESS_BYTES, NETWORK_FAMILY_V4, NETWORK_FAMILY_V6,
};

const MAX_ALLOWLIST_ENTRIES: u32 = 65_536;
const EXEC_EVENT_RING_BYTES: u32 = 1 << 20;
const EGRESS_EVENT_RING_BYTES: u32 = 1 << 20;
const CELL_LSM_EVENT_RING_BYTES: u32 = 1 << 20;
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
static CELL_LSM_POLICIES: HashMap<u64, u8> = HashMap::with_max_entries(MAX_CELL_LSM_POLICIES, BPF_F_NO_PREALLOC);
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
    Ok(BLOCKLIST_V6
        .get(&key)
        .is_some_and(|action| *action == ACTION_DROP))
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
                    header.dst[0], header.dst[1], header.dst[2], header.dst[3], 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0,
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
    // Source-CIDR filtering only needs the fixed IPv4 base header. Do not add
    // attacker-controlled IHL/total_len values to packet pointers: older and
    // hardened kernel verifiers correctly reject such arithmetic unless every
    // scalar bound remains provable across all compiler optimizations.
    //
    // ptr_at::<Ipv4Hdr>() above already proves that all fields read below are
    // inside data..data_end. Options and payload are deliberately left to the
    // normal network stack; malformed packets therefore remain fail-open.
    let ihl_words = version_ihl & 0x0f;
    if ihl_words < 5 {
        return Err(());
    }

    let key = Key::new(32, unsafe { (*header).src });
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
    // Source-CIDR filtering only consumes the fixed IPv6 header. Avoid
    // packet-dependent payload_len pointer arithmetic for the same verifier
    // reason as IPv4. ptr_at::<Ipv6Hdr>() already bounds every field we read.
    let key = Key::new(128, unsafe { (*header).src });
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
