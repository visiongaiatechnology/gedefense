#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::{xdp_action, BPF_F_NO_PREALLOC, TC_ACT_OK, TC_ACT_SHOT},
    helpers::{
        bpf_get_current_ancestor_cgroup_id, bpf_get_current_cgroup_id, bpf_get_current_comm,
        bpf_get_current_pid_tgid, bpf_get_current_uid_gid, bpf_get_socket_uid, bpf_ktime_get_ns,
        bpf_probe_read_kernel, bpf_probe_read_kernel_str_bytes, bpf_skb_ancestor_cgroup_id,
        bpf_skb_cgroup_id,
    },
    macros::{cgroup_skb, classifier, lsm, map, tracepoint, xdp},
    maps::{lpm_trie::Key, Array, HashMap, LpmTrie, LruHashMap, LruPerCpuHashMap, PerCpuArray, RingBuf},
    programs::{LsmContext, SkBuffContext, TcContext, TracePointContext, XdpContext},
    EbpfContext,
};
use core::mem;
use gedefense_common::{
    cell_lsm_socket_create_denied, kernel_s_dev_to_stat_u32, parse_network_header,
    strip_ctime_queried_flag, CellLsmDenyEvent, EgressDropEvent,
    ExecEvent, FlowEvent, IngressEvent, NetworkHeader, TitanExecEvent, ACTION_DROP,
    CELL_LSM_DENY_NON_UNIX_SOCKET, EXEC_COMM_BYTES, L2_PREFIX_BYTES,
    LOCKDOWN_FLAG_ALLOW_LOOPBACK,
    LOCKDOWN_FLAG_DROP_ALL, LOCKDOWN_MODE_ARMED, LOCKDOWN_STATE_ABI, LOCKDOWN_STATE_ABI_SHIFT,
    LOCKDOWN_STATE_BYTE_MASK, LOCKDOWN_STATE_FLAGS_SHIFT, LOCKDOWN_STATE_MAGIC,
    LOCKDOWN_STATE_MAGIC_SHIFT, LOCKDOWN_STATE_MODE_SHIFT, MAX_BLOCKLIST_ENTRIES_V4,
    MAX_BLOCKLIST_ENTRIES_V6, NETWORK_ADDRESS_BYTES, NETWORK_FAMILY_V4, NETWORK_FAMILY_V6,
    NETWORK_PROTOCOL_TCP, STYX_DIR_EGRESS, STYX_FLAG_ALLOW_HOST_ALLOWLIST,
    STYX_FLAG_ALLOW_METADATA, STYX_FLAG_DNS_RESOLVER, STYX_FLAG_LOG_FLOWS,
    STYX_FLOW_EVENT_WIRE_BYTES, STYX_MODE_ENFORCE, STYX_MODE_MASK, STYX_MODE_MONITOR,
    STYX_MODE_OFF, STYX_PROTO_TCP, STYX_PROTO_UNKNOWN, STYX_PROTO_UDP, STYX_VERDICT_ALLOW,
    STYX_VERDICT_AUDIT_DROP, STYX_VERDICT_DEFAULT_DENY, STYX_VERDICT_DNS_PIN, STYX_VERDICT_DROP,
    STYX_VERDICT_METADATA_VETO, KERNEL_PROBE_ACTION_DENY, KERNEL_PROBE_KIND_PROTOCOL,
    TITAN_EXEC_ACTION_AUDIT, TITAN_EXEC_ACTION_DENY,
    TITAN_EXEC_EVENT_WIRE_BYTES, TITAN_EXEC_HOOK_BPRM, TITAN_EXEC_HOOK_MMAP,
    TITAN_EXEC_MODE_OFF, TITAN_EXEC_MODE_OBSERVE, TITAN_EXEC_MODE_STRICT,
    TITAN_EXEC_MODE_UNTRUSTED, TITAN_EXEC_OFFSETS_ABI,
    TITAN_EXEC_OFFSETS_MAGIC, TITAN_EXEC_REASON_ANON_NO_JIT, TITAN_EXEC_REASON_CTIME_MISMATCH,
    TITAN_EXEC_REASON_FS_HARD, TITAN_EXEC_REASON_MEMFD, TITAN_EXEC_REASON_NON_ROOT_OWNER,
    TITAN_EXEC_REASON_NOT_ALLOWLISTED, TITAN_EXEC_REASON_READ_FAILURE,
    TITAN_EXEC_REASON_TMPFS, TITAN_EXEC_REASON_UNLINKED, TITAN_EXEC_REASON_UNTRUSTED_PATH,
    TITAN_EXEC_REASON_WORLD_WRITABLE_PATH, TITAN_EXEC_REASON_WX,
    TITAN_EXEC_SCOPE_FLAG_JIT_ALLOW, TITAN_EXEC_STATE_ABI,
    TITAN_EXEC_STATE_MAGIC,
};

/// 6.1.0 Module B: independent worker crash sensor (own maps/program).
mod worker_guard;

/// 6.2.0 M2.2: ransomware / rename-storm sensor (own maps/kprobes).
mod ransom;

/// 6.2.0 M2.4: file_open LSM credential guard (own map set/program).
mod credential_guard;

/// Kernel XDR behavioral tracepoints & probe emitters.
mod xdr_kernel;

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
const AF_INET: i32 = 2;
const AF_INET6: i32 = 10;
const IPPROTO_RDS: i32 = 21;
const IPPROTO_DCCP: i32 = 33;
const IPPROTO_SCTP: i32 = 132;
const EPERM: i32 = 1;

/// 6.1.0 Module D: the per-cgroup socket-deny bits beyond the pre-existing
/// NON_UNIX bit. The policy word stays a u8; the core rejects unknown bits.
///
/// The decision itself is `gedefense_common::cell_lsm_socket_create_denied`, so
/// it is unit-tested by the host test suite instead of only by the BPF
/// verifier. In particular the RDS bit is keyed on `family == AF_RDS` (Linux
/// creates RDS as `socket(AF_RDS /*21*/, SOCK_SEQPACKET, 0)`), never on the
/// protocol argument; SCTP/DCCP stay protocol-keyed because they are AF_INET
/// sockets carrying that protocol value. FIND-002.
#[inline(always)]
fn socket_policy_denies(flags: u8, family: i32, protocol: i32) -> bool {
    cell_lsm_socket_create_denied(flags, family, protocol)
}

// ---------------------------------------------------------------------------
// Point 1 (Phase 1): Titan exec/library gate.
//
// Contract: docs/POINT1-TITAN-EXEC-GATE.md §4 (map ABI-2) and §4.2 (decision
// semantics). The map names, key/value byte layouts and max_entries below are
// looked up by name from rust/gedefense-core; do not rename or reshape them.
//
// The verifier forbids variable offsets on a BPF context, so the LSM ctx slots
// are fixed compile-time hook ABI values (`LSM_HOOK` definitions) and the
// core-provided §4.1 argument indices are used to *validate* that ABI before
// any decision. Kernel structures are read exclusively through
// `bpf_probe_read_kernel` with runtime offsets from `TITAN_EXEC_OFFSETS`: the
// pointer is treated as a scalar and the helper performs the bounded read.
// ---------------------------------------------------------------------------

/// Maximum number of per-cgroup exec-gate scopes (§4).
const MAX_TITAN_EXEC_SCOPES: u32 = 4_096;
/// Maximum number of inode-policy entries (§4).
const MAX_TITAN_EXEC_POLICIES: u32 = 65_536;
/// `TITAN_EXEC_OFFSETS` entry count (§4.1: 28 used, 28..47 reserved).
const TITAN_EXEC_OFFSETS_ENTRIES: u32 = 48;
/// `TITAN_EXEC_EVENTS` ring size: 1 MiB (§4).
const TITAN_EXEC_EVENT_RING_BYTES: u32 = 1 << 20;
/// `TITAN_EXEC_STATE` has exactly one word at index 0 (§4).
const TITAN_EXEC_STATE_INDEX: u32 = 0;
/// `TITAN_EXEC_STATE` bit layout (§4): epoch 0..31, mode 32..39, flags 40..47,
/// abi 48..55, magic 56..63.
const TITAN_EXEC_STATE_MODE_SHIFT: u64 = 32;
const TITAN_EXEC_STATE_FLAGS_SHIFT: u64 = 40;
const TITAN_EXEC_STATE_ABI_SHIFT: u64 = 48;
const TITAN_EXEC_STATE_MAGIC_SHIFT: u64 = 56;
const TITAN_EXEC_STATE_BYTE_MASK: u64 = 0xff;
/// STATE flag bit2 `ctime_check_enabled` (§4); part of the REQUIRE_CTIME
/// source agreed with the core (STATE bit2 AND policy value flag bit0).
const TITAN_EXEC_STATE_FLAG_CTIME_CHECK: u8 = 1 << 2;
/// `TITAN_EXEC_MODE` value layout agreed with the core (§4 is otherwise
/// ambiguous with `JIT_ALLOW = 1<<0`): mode bits 2..3, scope flag bit0.
const TITAN_EXEC_SCOPE_MODE_SHIFT: u8 = 2;
const TITAN_EXEC_SCOPE_MODE_MASK: u8 = 0x03;
/// `TITAN_EXEC_POLICY` value layout (§4): action u8, flags u8, reserved u16,
/// ctime_ns u64 LE at byte 4 (packed 1+1+2 = 4, then 8 bytes, then pad 4).
const TITAN_EXEC_POLICY_ACTION_ALLOW: u8 = 1;
const TITAN_EXEC_POLICY_FLAG_REQUIRE_CTIME: u8 = 1 << 0;
const TITAN_EXEC_POLICY_ACTION_OFFSET: usize = 0;
const TITAN_EXEC_POLICY_FLAGS_OFFSET: usize = 1;
const TITAN_EXEC_POLICY_CTIME_OFFSET: usize = 4;
/// uapi `PROT_*` bits relevant to the mmap gate.
const PROT_WRITE: u32 = 0x2;
const PROT_EXEC: u32 = 0x4;
/// Defensive upper bound for the core-provided structure sizes (§4.1 indexes
/// 25..27); a value above it can only come from a partial/stale offsets map.
const TITAN_EXEC_MAX_STRUCT_SIZE: u32 = 65_536;
/// UNTRUSTED mode (§4.2 ABI 2): first 15 path bytes are enough to recognise the
/// three drop-root prefixes (`/tmp/`, `/var/tmp/`, `/dev/shm/`); the read is a
/// bounded kernel string helper, never a pointer dereference.
const TITAN_UNTRUSTED_PATH_BYTES: usize = 16;
/// Bounded `dentry -> d_parent` ancestor walk of the UNTRUSTED mode. Four levels
/// cover the documented drop layouts (`/tmp/dir/file`, `/var/www/uploads/x`)
/// without an unbounded loop; deeper nesting is caught by the drop-root prefix
/// check and the non-root-owner rule.
const TITAN_UNTRUSTED_ANCESTOR_LEVELS: u8 = 4;
/// `S_IWOTH`: a world-writable executable or any world-writable directory among
/// the first four ancestors is exactly the shared drop-path pattern (/tmp,
/// /var/tmp, /dev/shm, a 0777 upload directory); the sticky bit is irrelevant
/// for the refusal because both variants are untrusted for execution.
const TITAN_S_IWOTH: u16 = 0o002;
const UNTRUSTED_ROOT_TMP: &[u8] = b"/tmp/";
const UNTRUSTED_ROOT_VAR_TMP: &[u8] = b"/var/tmp/";
const UNTRUSTED_ROOT_DEV_SHM: &[u8] = b"/dev/shm/";

/// `TITAN_EXEC_OFFSETS` index enum (§4.1): the core resolves these from vmlinux
/// BTF and validates them; eBPF re-checks everything it dereferences.
const TITAN_OFF_MAGIC: u32 = 0;
const TITAN_OFF_ABI: u32 = 1;
const TITAN_OFF_BPRM_FILE: u32 = 2;
const TITAN_OFF_FILE_INODE: u32 = 3;
const TITAN_OFF_INODE_INO: u32 = 4;
const TITAN_OFF_INODE_SB: u32 = 5;
const TITAN_OFF_INODE_NLINK: u32 = 6;
const TITAN_OFF_INODE_MODE: u32 = 7;
const TITAN_OFF_INODE_GEN: u32 = 8;
const TITAN_OFF_SB_DEV: u32 = 9;
const TITAN_OFF_SB_MAGIC: u32 = 10;
const TITAN_OFF_INODE_CTIME_SEC: u32 = 11;
const TITAN_OFF_INODE_CTIME_NSEC: u32 = 12;
const TITAN_OFF_BPRM_NARGS: u32 = 13;
const TITAN_OFF_MMAP_NARGS: u32 = 14;
const TITAN_OFF_MMAP_FILE_ARG: u32 = 15;
const TITAN_OFF_MMAP_PROT_ARG: u32 = 16;
const TITAN_OFF_TMPFS_MAGIC: u32 = 18;
const TITAN_OFF_DEVTMPFS_MAGIC: u32 = 19;
const TITAN_OFF_PROC_MAGIC: u32 = 20;
const TITAN_OFF_SYSFS_MAGIC: u32 = 21;
const TITAN_OFF_BPRM_RETVAL_SLOT: u32 = 23;
const TITAN_OFF_MMAP_RETVAL_SLOT: u32 = 24;
const TITAN_OFF_INODE_SIZE: u32 = 25;
const TITAN_OFF_FILE_SIZE: u32 = 26;
const TITAN_OFF_BPRM_SIZE: u32 = 27;
/// Kernels 6.18/7.0 split `i_ctime` into `i_ctime_sec` (8 B) plus
/// `i_ctime_nsec` (4 B); older kernels keep the `timespec64` pair (8 B each).
/// The core reports the nsec half's width in this §4.1 entry (4 or 8).
const TITAN_OFF_INODE_CTIME_NSEC_WIDTH: u32 = 28;
/// §4.1 ABI 2 (6.2.0): UNTRUSTED-mode facts — `linux_binprm.filename`,
/// `inode.i_uid`, `file.f_path.dentry`, `dentry.d_parent`, `dentry.d_inode` and
/// the `struct dentry` size.
const TITAN_OFF_BPRM_FILENAME: u32 = 29;
const TITAN_OFF_INODE_I_UID: u32 = 30;
const TITAN_OFF_FILE_F_PATH_DENTRY: u32 = 31;
const TITAN_OFF_DENTRY_D_PARENT: u32 = 32;
const TITAN_OFF_DENTRY_D_INODE: u32 = 33;
const TITAN_OFF_DENTRY_SIZE: u32 = 34;
const TITAN_CTIME_NSEC_WIDTH_32: u32 = 4;
const TITAN_CTIME_NSEC_WIDTH_64: u32 = 8;
/// LSM ctx slots of the two hooks: compile-time kernel ABI, validated against
/// the core's §4.1 argument indices (BPRM_NARGS/MMAP_NARGS/…_ARG_IDX) first.
const TITAN_LSM_BPRM_FILE_ARG: usize = 0;
const TITAN_LSM_BPRM_PREVIOUS_ARG: usize = 1;
const TITAN_LSM_MMAP_FILE_ARG: usize = 0;
const TITAN_LSM_MMAP_PROT_ARG: usize = 2;
const TITAN_LSM_MMAP_PREVIOUS_ARG: usize = 4;
const TITAN_BPRM_NARGS: u32 = 1;
const TITAN_MMAP_NARGS: u32 = 4;
/// The previous-LSM return value is always the slot right after the hook args.
const _: () = assert!(TITAN_LSM_BPRM_PREVIOUS_ARG == TITAN_BPRM_NARGS as usize);
const _: () = assert!(TITAN_LSM_MMAP_PREVIOUS_ARG == TITAN_MMAP_NARGS as usize);

// ---------------------------------------------------------------------------
// Point 3 (Phase 1): per-cgroup egress enforcement and flow telemetry.
//
// Contract: docs/POINT3-EGRESS-BEACON.md §3.1/§3.2 (FlowEvent wire record),
// §4 (map ABI) and §6 (ordered decision pipeline). The map names, key/value
// byte layouts, max_entries and flags below are ABI-2 and are looked up by
// name from rust/gedefense-core; do not rename or reshape them.
// ---------------------------------------------------------------------------

/// Index of the single global mode word in `STYX_GLOBAL`.
const STYX_GLOBAL_INDEX: u32 = 0;
/// `u64 = epoch(low 32) | flags << 32 | mode << 40` (§4), see §3.1 for the bits.
const STYX_GLOBAL_FLAGS_SHIFT: u64 = 32;
const STYX_GLOBAL_MODE_SHIFT: u64 = 40;
const STYX_GLOBAL_MODE_MASK: u64 = 0x07;
const STYX_GLOBAL_FLAGS_MASK: u64 = 0xff;
const MAX_CELL_EGRESS_MODES: u32 = 4_096;
const MAX_CELL_ALLOW_ENTRIES: u32 = 65_536;
const MAX_GLOBAL_ALLOW_ENTRIES: u32 = 16_384;
const MAX_STYX_BLOCK_ENTRIES: u32 = 4_096;
const MAX_STYX_RESOLVER_ENTRIES: u32 = 256;
const MAX_STYX_RESOLVED_ENTRIES: u32 = 16_384;
const MAX_FLOW_AGG_ENTRIES: u32 = 4_096;
// Flow-telemetry ring (`FLOW_EVENTS`) size: 16 MiB = 131072 queued 104-byte
// `FlowEvent` records per ring buffer. The previous 4 MiB (32768 records) filled
// up under many-short-flow web/PHP/NTP workloads and the kernel dropped samples
// (`FLOW_RING_DROPS`) before the userspace core could drain them; enforcement
// was unaffected, but the StyX beacon telemetry became incomplete. 16 MiB keeps
// every 12-core burst of the observed profile inside the ring.
//
// This is a compile-time map definition: a ring-buffer map's size is fixed when
// the eBPF object is loaded by `gedefense-core` and cannot be changed at
// runtime. It is therefore *not* a hot setting; an operator changes the size by
// rebuilding this object (Cargo feature/env override would need a build script,
// which the locked offline toolchain intentionally does not have) and doing a
// controlled core restart. The userspace drain batch is bounded separately in
// `gedefense-core` (`MAX_STYX_FLOW_EVENTS_PER_RESPONSE`) and is the only part
// that follows the core binary, not this map.
const MAX_STYX_FLOW_EVENT_BYTES: u32 = 16 << 20;
/// Bounded parser limit for IPv6 extension headers before the L4 header (§6.8).
const IPV6_EXT_HEADER_HOPS: u8 = 4;
const IPV6_PROTOCOL_ICMPV6: u8 = 58;
const ICMPV6_NEIGHBOR_SOLICITATION: u8 = 135;
const ICMPV6_NEIGHBOR_ADVERTISEMENT: u8 = 136;
const DNS_TRANSPORT_PORT: u16 = 53;
const DOT_TRANSPORT_PORT: u16 = 853;
const NS_PER_SECOND: u64 = 1_000_000_000;
/// Flow aggregation emission thresholds (§6.5). The aggregation window is reset
/// after every emission, so the emitted `packets`/`tx_bytes` are deltas since
/// the previous event (or since the first packet of the flow).
const FLOW_EMIT_BYTES: u64 = 64 * 1024;
const FLOW_EMIT_PACKETS: u32 = 256;
/// Offset of the aggregation value fields inside the fixed `[u8; 40]` value (§4):
/// [first_ts 8][last_ts 8][tx 8][packets 4][pid 4][tcp_flags 1][verdict 1][pad 6].
const FLOW_AGG_FIRST_TS: usize = 0;
const FLOW_AGG_LAST_TS: usize = 8;
const FLOW_AGG_TX: usize = 16;
const FLOW_AGG_PACKETS: usize = 24;
const FLOW_AGG_PID: usize = 28;
const FLOW_AGG_TCP_FLAGS: usize = 32;
const FLOW_AGG_VERDICT: usize = 33;
/// Wire size guard: the ring record is emitted as the shared `FlowEvent` struct.
const _: () = assert!(mem::size_of::<FlowEvent>() == STYX_FLOW_EVENT_WIRE_BYTES);

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

// Point 3 egress enforcement maps (ABI-2, §4). Keys/values are plain byte
// arrays so the core can populate them without depending on kernel struct
// layouts; all multi-byte integers are little endian (native) except the L4
// port fields of the LPM keys, which are big endian to make the prefix bits
// follow the wire order of the port.
#[map]
static CELL_EGRESS_MODE: HashMap<u64, u8> =
    HashMap::with_max_entries(MAX_CELL_EGRESS_MODES, BPF_F_NO_PREALLOC);
#[map]
static CELL_EGRESS_ALLOW_V4: LpmTrie<[u8; 16], u8> =
    LpmTrie::with_max_entries(MAX_CELL_ALLOW_ENTRIES, BPF_F_NO_PREALLOC);
#[map]
static CELL_EGRESS_ALLOW_V6: LpmTrie<[u8; 24], u8> =
    LpmTrie::with_max_entries(MAX_CELL_ALLOW_ENTRIES, BPF_F_NO_PREALLOC);
#[map]
static STYX_ALLOW_GLOBAL_V4: LpmTrie<[u8; 8], u8> =
    LpmTrie::with_max_entries(MAX_GLOBAL_ALLOW_ENTRIES, BPF_F_NO_PREALLOC);
#[map]
static STYX_ALLOW_GLOBAL_V6: LpmTrie<[u8; 20], u8> =
    LpmTrie::with_max_entries(MAX_GLOBAL_ALLOW_ENTRIES, BPF_F_NO_PREALLOC);
#[map]
static STYX_BLOCK_V4: LpmTrie<[u8; 4], u8> =
    LpmTrie::with_max_entries(MAX_STYX_BLOCK_ENTRIES, BPF_F_NO_PREALLOC);
#[map]
static STYX_BLOCK_V6: LpmTrie<[u8; 16], u8> =
    LpmTrie::with_max_entries(MAX_STYX_BLOCK_ENTRIES, BPF_F_NO_PREALLOC);
#[map]
static STYX_RESOLVER_V4: LpmTrie<[u8; 4], u8> =
    LpmTrie::with_max_entries(MAX_STYX_RESOLVER_ENTRIES, BPF_F_NO_PREALLOC);
#[map]
static STYX_RESOLVER_V6: LpmTrie<[u8; 16], u8> =
    LpmTrie::with_max_entries(MAX_STYX_RESOLVER_ENTRIES, BPF_F_NO_PREALLOC);
#[map]
static STYX_GLOBAL: Array<u64> = Array::with_max_entries(1, 0);
#[map]
static STYX_RESOLVED: LruHashMap<u64, [u8; 16]> =
    LruHashMap::with_max_entries(MAX_STYX_RESOLVED_ENTRIES, 0);
#[map]
static FLOW_AGG_V4: LruPerCpuHashMap<[u8; 16], [u8; 40]> =
    LruPerCpuHashMap::with_max_entries(MAX_FLOW_AGG_ENTRIES, 0);
#[map]
static FLOW_AGG_V6: LruPerCpuHashMap<[u8; 32], [u8; 40]> =
    LruPerCpuHashMap::with_max_entries(MAX_FLOW_AGG_ENTRIES, 0);
#[map]
static FLOW_EVENTS: RingBuf = RingBuf::with_byte_size(MAX_STYX_FLOW_EVENT_BYTES, 0);
#[map]
static FLOW_EVENTS_EMITTED: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);
#[map]
static FLOW_RING_DROPS: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);
#[map]
static FLOW_AGG_INSERT_FAILURES: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);
#[map]
static EGRESS_PARSE_ERRORS: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);
#[map]
static EGRESS_DROPS_TOTAL: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);
#[map]
static EGRESS_POLICY_DROPS: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);

// Point 1 Titan exec-gate maps (ABI-2, §4). The core `take_map`s every one of
// them by name at startup and refuses to run silently if one is missing.
#[map]
static TITAN_EXEC_STATE: Array<u64> = Array::with_max_entries(1, 0);
#[map]
static TITAN_EXEC_OFFSETS: Array<u32> = Array::with_max_entries(TITAN_EXEC_OFFSETS_ENTRIES, 0);
#[map]
static TITAN_EXEC_MODE: HashMap<u64, u8> =
    HashMap::with_max_entries(MAX_TITAN_EXEC_SCOPES, BPF_F_NO_PREALLOC);
#[map]
static TITAN_EXEC_POLICY: HashMap<[u8; 16], [u8; 16]> =
    HashMap::with_max_entries(MAX_TITAN_EXEC_POLICIES, BPF_F_NO_PREALLOC);
#[map]
static TITAN_EXEC_EVENTS: RingBuf = RingBuf::with_byte_size(TITAN_EXEC_EVENT_RING_BYTES, 0);
#[map]
static TITAN_EXEC_EVENTS_EMITTED: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);
#[map]
static TITAN_EXEC_RING_DROPS: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);
#[map]
static TITAN_EXEC_READ_FAILURES: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);
#[map]
static TITAN_EXEC_POLICY_DENIES: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);
#[map]
static TITAN_EXEC_POLICY_AUDITS: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);
#[map]
static TITAN_EXEC_CTIME_REJECTS: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);

// ---------------------------------------------------------------------------
// Point 5 (Phase 1): Emergency Lockdown global network drop.
//
// Contract: docs/POINT5-LOCKDOWN.md §3 (state word ABI) and §4 (program
// paths). The core `take_map`s these maps by name at startup; map names, the
// word bit layout and the 64-byte word are ABI-1 and must not be renamed or
// reshaped. No packet ring buffer is added on purpose (§4: flood safety);
// lifecycle events belong to the core. The state map is not pinned: a core
// crash ends the drop (documented fail-open window, §5) and the core re-arms.
// ---------------------------------------------------------------------------

/// Index of the single lockdown state word in `LOCKDOWN_STATE` (§4).
const LOCKDOWN_STATE_INDEX: u32 = 0;

/// §3 state word: epoch 0..31, mode 32..39, flags 40..47, ABI 48..55, magic
/// 56..63. Default 0 (kernel map zero-init) = not a valid word = OFF.
#[map]
static LOCKDOWN_STATE: Array<u64> = Array::with_max_entries(1, 0);
/// Packets dropped by the lockdown fastpath, per CPU (§4/§5 health).
#[map]
static LOCKDOWN_DROPS: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);
/// Lockdown packets that passed through the `ALLOW_LOOPBACK` exception (§4).
#[map]
static LOCKDOWN_WITNESS_PASSES: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);

// The ring record is exactly the §3.2 wire record shared with the core decoder;
// a layout drift would make the core drain counter climb without an event.
const _: () = assert!(mem::size_of::<TitanExecEvent>() == TITAN_EXEC_EVENT_WIRE_BYTES);
const _: () = assert!(mem::align_of::<TitanExecEvent>() <= 8);

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
    // 6.1.0 Module D: socket(2) protocol (third LSM argument). The kernel keeps
    // it in the hook signature; the pre-6.1.0 hook ignored it. Reading it is
    // required to refuse SCTP/DCCP/RDS on an otherwise allowed AF_INET socket.
    let protocol: i32 = ctx.arg(2);
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
    if (family == AF_INET || family == AF_INET6)
        && (protocol == IPPROTO_SCTP || protocol == IPPROTO_DCCP || protocol == IPPROTO_RDS)
    {
        xdr_kernel::emit_kernel_probe(
            KERNEL_PROBE_KIND_PROTOCOL,
            KERNEL_PROBE_ACTION_DENY,
            0,
            protocol as u32,
            if protocol == IPPROTO_SCTP {
                b"SCTP"
            } else if protocol == IPPROTO_DCCP {
                b"DCCP"
            } else {
                b"RDS"
            },
        );
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
            if *policy & CELL_LSM_DENY_NON_UNIX_SOCKET != 0
                || socket_policy_denies(*policy, family, protocol)
            {
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

// ---------------------------------------------------------------------------
// Point 1 (Phase 1): Titan exec/library gate — §4.2 decision engine.
//
// Failure contract (§4.2): every offsets/read failure is fail-safe (allow 0),
// but never silent: TITAN_EXEC_READ_FAILURES increases and one AUDIT event with
// reason READ_FAILURE is emitted. The only deny value is -EPERM (same LSM
// semantics as the pre-existing socket_create cell gate).
// ---------------------------------------------------------------------------

/// Global gate state decoded from `TITAN_EXEC_STATE` (§4).
#[derive(Clone, Copy)]
struct TitanGlobal {
    mode: u8,
    flags: u8,
}

/// Per-cgroup gate scope resolved from `TITAN_EXEC_MODE` (§4/§4.2).
#[derive(Clone, Copy)]
struct TitanScope {
    mode: u8,
    jit_allow: bool,
    cgroup_id: u64,
    /// True when the mode came from a per-cgroup scope instead of the global word.
    matched: bool,
}

/// File/inode identity of the executable under evaluation. The `inode`/`sb`
/// pointers stay internal to the read chain (the event carries no pointers);
/// `dev`/`ino` are the §4 policy key.
#[derive(Clone, Copy)]
struct TitanFile {
    dev: u32,
    inode_mode: u32,
    ino: u64,
    generation: u32,
    inode: u64,
    sb: u64,
    /// `struct file *` itself: needed for `f_path.dentry` in UNTRUSTED mode.
    file_ptr: u64,
}

/// §4.2 ABI 2 UNTRUSTED-mode facts of one executable. All three are lifted by a
/// configured `TITAN_EXEC_POLICY` allow entry, exactly like the CONTAIN rules.
#[derive(Clone, Copy, Default)]
struct TitanUntrusted {
    /// `bprm->filename` starts with `/tmp/`, `/var/tmp/` or `/dev/shm/`.
    path_denied: bool,
    /// `inode.i_uid != 0` (the file itself is not root-owned).
    non_root_owner: bool,
    /// The file or one of its first four ancestor directories is world-writable.
    world_writable_path: bool,
}

/// CONTAIN rules need the link count and the super-block magic; STRICT does not.
#[derive(Clone, Copy)]
struct TitanContainment {
    nlink: u32,
    fs_magic: u32,
}

/// Decoded `TITAN_EXEC_POLICY` value (§4); only action == ALLOW counts.
#[derive(Clone, Copy)]
struct TitanPolicy {
    allow: bool,
    require_ctime: bool,
    ctime_ns: u64,
}

/// Runtime offset table re-read from `TITAN_EXEC_OFFSETS` (§4.1).
#[derive(Clone, Copy)]
pub(crate) struct TitanOffsets {
    pub(crate) bprm_file: u32,
    pub(crate) file_inode: u32,
    pub(crate) inode_ino: u32,
    pub(crate) inode_sb: u32,
    inode_nlink: u32,
    pub(crate) inode_mode: u32,
    inode_gen: u32,
    pub(crate) sb_dev: u32,
    sb_magic: u32,
    ctime_sec: u32,
    ctime_nsec: u32,
    /// Width of the nsec half in bytes (4 or 8, §4.1 index 28).
    ctime_nsec_width: u32,
    tmpfs_magic: u32,
    devtmpfs_magic: u32,
    proc_magic: u32,
    sysfs_magic: u32,
    /// §4.1 ABI 2 (UNTRUSTED mode) offsets.
    bprm_filename: u32,
    inode_uid: u32,
    file_f_path_dentry: u32,
    dentry_parent: u32,
    dentry_inode: u32,
    dentry_size: u32,
}

/// Reads one `TITAN_EXEC_OFFSETS` entry; an absent array slot is a read failure.
#[inline(always)]
fn titan_offset(index: u32) -> Option<u32> {
    TITAN_EXEC_OFFSETS.get(index).copied()
}

/// Reads and validates the §4.1 offset table. Returns `None` for every
/// partial/stale/inconsistent table, so callers fail open with a READ_FAILURE
/// event instead of reading a kernel structure at a guessed offset.
#[inline(always)]
pub(crate) fn titan_offsets() -> Option<TitanOffsets> {
    if titan_offset(TITAN_OFF_MAGIC)? != TITAN_EXEC_OFFSETS_MAGIC {
        return None;
    }
    if titan_offset(TITAN_OFF_ABI)? != TITAN_EXEC_OFFSETS_ABI {
        return None;
    }
    let bprm_size = titan_offset(TITAN_OFF_BPRM_SIZE)?;
    let file_size = titan_offset(TITAN_OFF_FILE_SIZE)?;
    let inode_size = titan_offset(TITAN_OFF_INODE_SIZE)?;
    // §4.1 index 28: only the two documented nsec widths are valid. A missing or
    // unknown width would make the ctime comparison read a neighbouring field.
    let ctime_nsec_width = titan_offset(TITAN_OFF_INODE_CTIME_NSEC_WIDTH)?;
    if ctime_nsec_width != TITAN_CTIME_NSEC_WIDTH_32
        && ctime_nsec_width != TITAN_CTIME_NSEC_WIDTH_64
    {
        return None;
    }
    let offsets = TitanOffsets {
        bprm_file: titan_offset(TITAN_OFF_BPRM_FILE)?,
        file_inode: titan_offset(TITAN_OFF_FILE_INODE)?,
        inode_ino: titan_offset(TITAN_OFF_INODE_INO)?,
        inode_sb: titan_offset(TITAN_OFF_INODE_SB)?,
        inode_nlink: titan_offset(TITAN_OFF_INODE_NLINK)?,
        inode_mode: titan_offset(TITAN_OFF_INODE_MODE)?,
        inode_gen: titan_offset(TITAN_OFF_INODE_GEN)?,
        sb_dev: titan_offset(TITAN_OFF_SB_DEV)?,
        sb_magic: titan_offset(TITAN_OFF_SB_MAGIC)?,
        ctime_sec: titan_offset(TITAN_OFF_INODE_CTIME_SEC)?,
        ctime_nsec: titan_offset(TITAN_OFF_INODE_CTIME_NSEC)?,
        ctime_nsec_width,
        tmpfs_magic: titan_offset(TITAN_OFF_TMPFS_MAGIC)?,
        devtmpfs_magic: titan_offset(TITAN_OFF_DEVTMPFS_MAGIC)?,
        proc_magic: titan_offset(TITAN_OFF_PROC_MAGIC)?,
        sysfs_magic: titan_offset(TITAN_OFF_SYSFS_MAGIC)?,
        bprm_filename: titan_offset(TITAN_OFF_BPRM_FILENAME)?,
        inode_uid: titan_offset(TITAN_OFF_INODE_I_UID)?,
        file_f_path_dentry: titan_offset(TITAN_OFF_FILE_F_PATH_DENTRY)?,
        dentry_parent: titan_offset(TITAN_OFF_DENTRY_D_PARENT)?,
        dentry_inode: titan_offset(TITAN_OFF_DENTRY_D_INODE)?,
        dentry_size: titan_offset(TITAN_OFF_DENTRY_SIZE)?,
    };
    // Every runtime offset must place the complete field inside the structure
    // size the core resolved from BTF; a zero/garbage size is invalid as well.
    if bprm_size > TITAN_EXEC_MAX_STRUCT_SIZE
        || file_size > TITAN_EXEC_MAX_STRUCT_SIZE
        || inode_size > TITAN_EXEC_MAX_STRUCT_SIZE
        || !titan_field_fits(offsets.bprm_file, 8, bprm_size)
        || !titan_field_fits(offsets.file_inode, 8, file_size)
        || !titan_field_fits(offsets.inode_ino, 8, inode_size)
        || !titan_field_fits(offsets.inode_sb, 8, inode_size)
        || !titan_field_fits(offsets.inode_nlink, 4, inode_size)
        || !titan_field_fits(offsets.inode_mode, 2, inode_size)
        || !titan_field_fits(offsets.inode_gen, 4, inode_size)
        || !titan_field_fits(offsets.ctime_sec, 8, inode_size)
        || !titan_field_fits(
            offsets.ctime_nsec,
            u64::from(offsets.ctime_nsec_width),
            inode_size,
        )
        // §4.1 ABI 2 (UNTRUSTED mode): the six new entries must fit the real
        // structure sizes and the dentry size must be a plausible struct.
        || !titan_field_fits(offsets.bprm_filename, 8, bprm_size)
        || !titan_field_fits(offsets.inode_uid, 4, inode_size)
        || !titan_field_fits(offsets.file_f_path_dentry, 8, file_size)
        || offsets.dentry_size == 0
        || offsets.dentry_size > TITAN_EXEC_MAX_STRUCT_SIZE
        || !titan_field_fits(offsets.dentry_parent, 8, offsets.dentry_size)
        || !titan_field_fits(offsets.dentry_inode, 8, offsets.dentry_size)
        // §4.1 has no super_block size entry; bound the two fields defensively.
        || offsets.sb_dev > TITAN_EXEC_MAX_STRUCT_SIZE
        || offsets.sb_magic > TITAN_EXEC_MAX_STRUCT_SIZE
    {
        return None;
    }
    Some(offsets)
}

#[inline(always)]
fn titan_field_fits(offset: u32, width: u64, size: u32) -> bool {
    u64::from(offset).saturating_add(width) <= u64::from(size)
}

/// The kernel-side LSM ctx ABI is compile-time (the verifier has to know each
/// slot); the core's §4.1 argument indices are the mandate to run. If they do
/// not describe exactly this ABI, the gate fails open instead of enforcing a
/// decision made from the wrong slot.
#[inline(always)]
fn titan_arguments_match(hook: u8) -> bool {
    if hook == TITAN_EXEC_HOOK_BPRM {
        titan_offset(TITAN_OFF_BPRM_NARGS) == Some(TITAN_BPRM_NARGS)
            && titan_offset(TITAN_OFF_BPRM_RETVAL_SLOT)
                == Some(TITAN_LSM_BPRM_PREVIOUS_ARG as u32)
    } else {
        titan_offset(TITAN_OFF_MMAP_NARGS) == Some(TITAN_MMAP_NARGS)
            && titan_offset(TITAN_OFF_MMAP_FILE_ARG) == Some(TITAN_LSM_MMAP_FILE_ARG as u32)
            && titan_offset(TITAN_OFF_MMAP_PROT_ARG) == Some(TITAN_LSM_MMAP_PROT_ARG as u32)
            && titan_offset(TITAN_OFF_MMAP_RETVAL_SLOT)
                == Some(TITAN_LSM_MMAP_PREVIOUS_ARG as u32)
    }
}

/// Decodes `TITAN_EXEC_STATE`; `None` for an absent/uninitialised word and for
/// a magic/ABI mismatch or an out-of-range mode (§4: fail-safe, counter).
#[inline(always)]
fn titan_global() -> Option<TitanGlobal> {
    let word = *TITAN_EXEC_STATE.get(TITAN_EXEC_STATE_INDEX)?;
    let magic = ((word >> TITAN_EXEC_STATE_MAGIC_SHIFT) & TITAN_EXEC_STATE_BYTE_MASK) as u8;
    let abi = ((word >> TITAN_EXEC_STATE_ABI_SHIFT) & TITAN_EXEC_STATE_BYTE_MASK) as u8;
    let mode = ((word >> TITAN_EXEC_STATE_MODE_SHIFT) & TITAN_EXEC_STATE_BYTE_MASK) as u8;
    let flags = ((word >> TITAN_EXEC_STATE_FLAGS_SHIFT) & TITAN_EXEC_STATE_BYTE_MASK) as u8;
    if magic != TITAN_EXEC_STATE_MAGIC || abi != TITAN_EXEC_STATE_ABI
        || mode > TITAN_EXEC_MODE_UNTRUSTED
    {
        return None;
    }
    Some(TitanGlobal { mode, flags })
}

/// Resolves the effective mode/flags: first ancestor scope hit wins (cell-root
/// scope, children inherit §4.2), otherwise the global mode. The walk reuses
/// the bounded Level 0..63 pattern of the pre-existing socket_create hook.
#[inline(always)]
fn titan_scope(global_mode: u8) -> TitanScope {
    let mut level: i32 = 0;
    while level < MAX_CGROUP_ANCESTOR_LEVELS {
        let cgroup_id = unsafe { bpf_get_current_ancestor_cgroup_id(level) };
        if cgroup_id == 0 {
            break;
        }
        if let Some(raw) = unsafe { TITAN_EXEC_MODE.get(&cgroup_id) } {
            return TitanScope {
                mode: (*raw >> TITAN_EXEC_SCOPE_MODE_SHIFT) & TITAN_EXEC_SCOPE_MODE_MASK,
                jit_allow: (*raw & TITAN_EXEC_SCOPE_FLAG_JIT_ALLOW) != 0,
                cgroup_id,
                matched: true,
            };
        }
        level += 1;
    }
    TitanScope {
        mode: global_mode,
        jit_allow: false,
        cgroup_id: unsafe { bpf_get_current_cgroup_id() },
        matched: false,
    }
}

/// Reads a kernel structure field through `bpf_probe_read_kernel`. The kernel
/// pointer is deliberately kept as a scalar (`u64`) and only the helper turns
/// the computed address into a real kernel access — that is the verifier-safe
/// pattern for runtime offsets (§4.1).
#[inline(always)]
pub(crate) fn titan_probe<T>(base: u64, offset: u32) -> Option<T> {
    let address = base.wrapping_add(u64::from(offset)) as *const T;
    unsafe { bpf_probe_read_kernel(address).ok() }
}

/// `linux_binprm -> file -> inode` identity chain for `bprm_check_security`.
#[inline(always)]
fn titan_read_bprm(bprm: u64, offsets: &TitanOffsets) -> Option<TitanFile> {
    let file = titan_probe::<u64>(bprm, offsets.bprm_file)?;
    if file == 0 {
        return None;
    }
    titan_read_file(file, offsets)
}

/// `struct file -> f_inode -> struct inode -> i_sb` identity chain.
#[inline(always)]
fn titan_read_file(file: u64, offsets: &TitanOffsets) -> Option<TitanFile> {
    let inode = titan_probe::<u64>(file, offsets.file_inode)?;
    if inode == 0 {
        return None;
    }
    let sb = titan_probe::<u64>(inode, offsets.inode_sb)?;
    if sb == 0 {
        return None;
    }
    let ino = titan_probe::<u64>(inode, offsets.inode_ino)?;
    let inode_mode = titan_probe::<u16>(inode, offsets.inode_mode)? as u32;
    let generation = titan_probe::<u32>(inode, offsets.inode_gen)?;
    let dev = kernel_s_dev_to_stat_u32(titan_probe::<u32>(sb, offsets.sb_dev)?);
    Some(TitanFile { dev, inode_mode, ino, generation, inode, sb, file_ptr: file })
}

#[inline(always)]
fn titan_read_containment(file: &TitanFile, offsets: &TitanOffsets) -> Option<TitanContainment> {
    Some(TitanContainment {
        nlink: titan_probe::<u32>(file.inode, offsets.inode_nlink)?,
        fs_magic: titan_probe::<u32>(file.sb, offsets.sb_magic)?,
    })
}

/// Policy key = `s_dev u32 LE | i_ino u64 LE | pad[4]` (§4). A zero identity can
/// never match a policy entry because the core rejects zero dev/ino on write.
#[inline(always)]
fn titan_policy(file: &TitanFile, global: &TitanGlobal) -> TitanPolicy {
    let mut policy = TitanPolicy { allow: false, require_ctime: false, ctime_ns: 0 };
    if file.dev == 0 || file.ino == 0 {
        return policy;
    }
    let mut key = [0u8; 16];
    key[0..4].copy_from_slice(&file.dev.to_le_bytes());
    key[4..12].copy_from_slice(&file.ino.to_le_bytes());
    if let Some(value) = unsafe { TITAN_EXEC_POLICY.get(&key) } {
        if value[TITAN_EXEC_POLICY_ACTION_OFFSET] == TITAN_EXEC_POLICY_ACTION_ALLOW {
            policy.allow = true;
            policy.require_ctime = (value[TITAN_EXEC_POLICY_FLAGS_OFFSET]
                & TITAN_EXEC_POLICY_FLAG_REQUIRE_CTIME)
                != 0
                && (global.flags & TITAN_EXEC_STATE_FLAG_CTIME_CHECK) != 0;
            let ctime = &value[TITAN_EXEC_POLICY_CTIME_OFFSET..TITAN_EXEC_POLICY_CTIME_OFFSET + 8];
            policy.ctime_ns = u64::from_le_bytes([
                ctime[0], ctime[1], ctime[2], ctime[3], ctime[4], ctime[5], ctime[6], ctime[7],
            ]);
        }
    }
    policy
}

/// `i_ctime` (sec, nsec) as nanoseconds since the Unix epoch. The nsec half is
/// read with the core-provided width (4 B on the 6.18/7.0 split-inode layout,
/// 8 B for the historical `timespec64` pair) and zero-extended; the sum is
/// saturated so a corrupt timestamp can never wrap into a "match". `None` is a
/// read failure, not a mismatch: callers fail open with READ_FAILURES (§4.2).
#[inline(always)]
fn titan_ctime_mismatch(
    file: &TitanFile,
    offsets: &TitanOffsets,
    expected_ns: u64,
) -> Option<bool> {
    let sec: u64 = titan_probe(file.inode, offsets.ctime_sec)?;
    let nsec: u64 = if offsets.ctime_nsec_width == TITAN_CTIME_NSEC_WIDTH_32 {
        u64::from(strip_ctime_queried_flag(titan_probe::<u32>(file.inode, offsets.ctime_nsec)?))
    } else {
        titan_probe::<u64>(file.inode, offsets.ctime_nsec)?
    };
    // `tv_nsec` is always in [0, 1e9); anything else is a corrupt read.
    if nsec >= NS_PER_SECOND {
        return None;
    }
    // Saturation without `u64::saturating_mul`: Rust's u64 saturating multiply
    // is lowered to the 128-bit `__multi3` builtin on the BPF target (unsupported
    // by bpf-linker). The division guard folds to a compile-time constant, so the
    // multiply below cannot overflow and `saturating_add` keeps the contract.
    let seconds_ns = if sec > u64::MAX / NS_PER_SECOND {
        u64::MAX
    } else {
        sec * NS_PER_SECOND
    };
    let actual_ns = seconds_ns.saturating_add(nsec);
    Some(actual_ns != expected_ns)
}

/// §4.2 ABI 2: lifts the three UNTRUSTED-mode facts with bounded reads only.
/// `None` is a read failure and keeps the §4.2 fail-safe contract (allow + a
/// READ_FAILURE audit event that the control plane counts and alarms on).
#[inline(always)]
fn titan_untrusted(bprm: u64, file: &TitanFile, offsets: &TitanOffsets) -> Option<TitanUntrusted> {
    let mut facts = TitanUntrusted::default();
    let filename: u64 = titan_probe(bprm, offsets.bprm_filename)?;
    if filename == 0 {
        return None;
    }
    let mut path = [0u8; TITAN_UNTRUSTED_PATH_BYTES];
    let path = unsafe { bpf_probe_read_kernel_str_bytes(filename as *const u8, &mut path).ok()? };
    facts.path_denied = path.starts_with(UNTRUSTED_ROOT_TMP)
        || path.starts_with(UNTRUSTED_ROOT_VAR_TMP)
        || path.starts_with(UNTRUSTED_ROOT_DEV_SHM);
    let owner: u32 = titan_probe(file.inode, offsets.inode_uid)?;
    facts.non_root_owner = owner != 0;
    // World-writable file or a bounded ancestor-directory walk. `/` is 0755 and
    // the loop is capped, so the cost is at most four pointer + mode reads.
    if file.inode_mode as u16 & TITAN_S_IWOTH != 0 {
        facts.world_writable_path = true;
    }
    let mut dentry: u64 = titan_probe(file.file_ptr, offsets.file_f_path_dentry)?;
    let mut level = 0u8;
    while level < TITAN_UNTRUSTED_ANCESTOR_LEVELS && !facts.world_writable_path {
        if dentry == 0 {
            break;
        }
        let inode: u64 = titan_probe(dentry, offsets.dentry_inode)?;
        if inode != 0 {
            let mode: u16 = titan_probe(inode, offsets.inode_mode)?;
            if mode & TITAN_S_IWOTH != 0 {
                facts.world_writable_path = true;
            }
        }
        dentry = titan_probe(dentry, offsets.dentry_parent)?;
        level += 1;
    }
    Some(facts)
}

/// §4.2 verdict: `Some(reason)` means the gate acts on this ground (audit in
/// OBSERVE, deny in CONTAIN/STRICT); `None` means allow silently. Modes OFF and
/// scope-OFF never reach this function. UNTRUSTED (mode 4, ABI 2) applies the
/// three drop-root/owner gates on top of the CONTAIN containment rules; the
/// configured inode allowlist lifts them exactly like the CONTAIN rules.
#[inline(always)]
fn titan_decide(
    mode: u8,
    jit_allow: bool,
    hook: u8,
    prot: u32,
    anon: bool,
    containment: TitanContainment,
    untrusted: TitanUntrusted,
    offsets: &TitanOffsets,
    policy_allow: bool,
    ctime_mismatch: bool,
) -> Option<u8> {
    // Anonymous executable mappings carry no file/inode identity. They are only
    // permitted through a per-cgroup JIT_ALLOW scope (§4.2); a W|X rule is not
    // applied here because §3.2 cannot represent an identity-less WX record.
    if anon {
        return if jit_allow {
            None
        } else {
            Some(TITAN_EXEC_REASON_ANON_NO_JIT)
        };
    }
    // §4.2 CONTAIN/STRICT: W|X file mappings are always a ground; an inode
    // policy ALLOW never lifts a W^X violation.
    if hook == TITAN_EXEC_HOOK_MMAP
        && prot & (PROT_WRITE | PROT_EXEC) == (PROT_WRITE | PROT_EXEC)
    {
        return Some(TITAN_EXEC_REASON_WX);
    }
    if ctime_mismatch {
        return Some(TITAN_EXEC_REASON_CTIME_MISMATCH);
    }
    if mode == TITAN_EXEC_MODE_STRICT {
        return if policy_allow {
            None
        } else {
            Some(TITAN_EXEC_REASON_NOT_ALLOWLISTED)
        };
    }
    // §4.2 UNTRUSTED (ABI 2): the CONTAIN rules plus the drop-path gates. A
    // configured TITAN_EXEC_POLICY allow entry lifts all three, so legitimate
    // operator-approved binaries keep working. This runs before the shared
    // containment block below so the event names the most specific ground.
    if mode == TITAN_EXEC_MODE_UNTRUSTED && !policy_allow {
        if untrusted.path_denied {
            return Some(TITAN_EXEC_REASON_UNTRUSTED_PATH);
        }
        if untrusted.non_root_owner {
            return Some(TITAN_EXEC_REASON_NON_ROOT_OWNER);
        }
        if untrusted.world_writable_path {
            return Some(TITAN_EXEC_REASON_WORLD_WRITABLE_PATH);
        }
    }
    // OBSERVE and CONTAIN share the containment rules. An inode-policy ALLOW
    // only lifts the file-system/unlinked-inode rules (§4.2 documented exception).
    if policy_allow {
        return None;
    }
    if containment.nlink == 0 {
        return Some(if containment.fs_magic == offsets.tmpfs_magic {
            TITAN_EXEC_REASON_MEMFD
        } else {
            TITAN_EXEC_REASON_UNLINKED
        });
    }
    if containment.fs_magic == offsets.tmpfs_magic {
        return Some(TITAN_EXEC_REASON_TMPFS);
    }
    if containment.fs_magic == offsets.devtmpfs_magic
        || containment.fs_magic == offsets.proc_magic
        || containment.fs_magic == offsets.sysfs_magic
    {
        return Some(TITAN_EXEC_REASON_FS_HARD);
    }
    None
}

/// Turns the §4.2 reason into the kernel verdict and the audit/deny event.
#[inline(always)]
fn titan_finish(
    hook: u8,
    scope: TitanScope,
    reason: Option<u8>,
    dev: u32,
    inode_mode: u32,
    ino: u64,
    generation: u32,
    prot: u32,
    ctime_mismatch: bool,
) -> i32 {
    let reason = match reason {
        Some(reason) => reason,
        None => return 0,
    };
    let action = if scope.mode == TITAN_EXEC_MODE_OBSERVE {
        TITAN_EXEC_ACTION_AUDIT
    } else {
        TITAN_EXEC_ACTION_DENY
    };
    // §3.2 event flags: bit0 ctime mismatch observed, bit1 scope snapshot.
    let flags = (ctime_mismatch as u8) | ((scope.matched as u8) << 1);
    emit_titan_exec_event(
        hook, action, reason, scope.cgroup_id, dev, inode_mode, ino, generation, prot, flags,
    );
    if action == TITAN_EXEC_ACTION_DENY {
        increment_counter(&TITAN_EXEC_POLICY_DENIES);
        -EPERM
    } else {
        increment_counter(&TITAN_EXEC_POLICY_AUDITS);
        0
    }
}

/// Records an offsets/read failure and fails open (§4.2). The event proof is
/// mandatory: READ_FAILURE + AUDIT is the only §3.2 record where a zero
/// identity is allowed, so it is representable even when no inode was read.
#[inline(always)]
fn titan_read_failure(hook: u8, prot: u32) -> i32 {
    increment_counter(&TITAN_EXEC_READ_FAILURES);
    emit_titan_exec_event(
        hook,
        TITAN_EXEC_ACTION_AUDIT,
        TITAN_EXEC_REASON_READ_FAILURE,
        0,
        0,
        0,
        0,
        0,
        prot,
        0,
    );
    0
}

/// Emits one native-endian 88-byte `TitanExecEvent` (§3.2). The record is
/// written directly into the ring-buffer reservation: a stack copy would add
/// 88 bytes to the 512-byte eBPF stack frame that already holds the read chain.
#[inline(always)]
fn emit_titan_exec_event(
    hook: u8,
    action: u8,
    reason: u8,
    cgroup_id: u64,
    dev: u32,
    inode_mode: u32,
    ino: u64,
    generation: u32,
    prot: u32,
    flags: u8,
) {
    let ts_ns = unsafe { bpf_ktime_get_ns() };
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = pid_tgid as u32;
    // The core decoder rejects pid/ts 0 records; never produce one.
    if pid == 0 || ts_ns == 0 {
        return;
    }
    let tgid = (pid_tgid >> 32) as u32;
    let uid_gid = bpf_get_current_uid_gid();
    let comm = bpf_get_current_comm().unwrap_or([0u8; EXEC_COMM_BYTES]);
    if let Some(mut entry) = TITAN_EXEC_EVENTS.reserve::<TitanExecEvent>(0) {
        let event = entry.as_mut_ptr();
        // SAFETY: the reservation is exactly size_of::<TitanExecEvent>() bytes
        // and 8-aligned; every field is written through the raw pointer before
        // the entry is submitted, and the entry is submitted before scope end.
        unsafe {
            core::ptr::addr_of_mut!((*event).cgroup_id).write(cgroup_id);
            core::ptr::addr_of_mut!((*event).ts_ns).write(ts_ns);
            core::ptr::addr_of_mut!((*event).dev).write(dev);
            core::ptr::addr_of_mut!((*event).inode_mode).write(inode_mode);
            core::ptr::addr_of_mut!((*event).ino).write(ino);
            core::ptr::addr_of_mut!((*event).generation).write(generation);
            core::ptr::addr_of_mut!((*event).pid).write(pid);
            core::ptr::addr_of_mut!((*event).tgid).write(tgid);
            core::ptr::addr_of_mut!((*event).uid).write(uid_gid as u32);
            core::ptr::addr_of_mut!((*event).gid).write((uid_gid >> 32) as u32);
            core::ptr::addr_of_mut!((*event).prot).write(prot);
            // §4.1 has no file.f_flags offset, so the field stays 0 (unknown);
            // the core decoder does not interpret it.
            core::ptr::addr_of_mut!((*event).f_flags).write(0);
            core::ptr::addr_of_mut!((*event).hook).write(hook);
            core::ptr::addr_of_mut!((*event).action).write(action);
            core::ptr::addr_of_mut!((*event).reason).write(reason);
            core::ptr::addr_of_mut!((*event).flags).write(flags);
            core::ptr::addr_of_mut!((*event).comm).write(comm);
            core::ptr::addr_of_mut!((*event).reserved).write([0u8; 8]);
        }
        entry.submit(0);
        increment_counter(&TITAN_EXEC_EVENTS_EMITTED);
    } else {
        // Ring full: visibility loss is reported, the verdict is unaffected.
        increment_counter(&TITAN_EXEC_RING_DROPS);
    }
}

#[lsm(hook = "bprm_check_security")]
pub fn gedefense_titan_exec_bprm(ctx: LsmContext) -> i32 {
    try_titan_exec_bprm(ctx)
}

#[inline(always)]
fn try_titan_exec_bprm(ctx: LsmContext) -> i32 {
    // Defer to a previously attached LSM program exactly like the kernel chain.
    let previous: i32 = ctx.arg(TITAN_LSM_BPRM_PREVIOUS_ARG);
    if previous != 0 {
        return previous;
    }
    let global = match titan_global() {
        Some(global) => global,
        None => return titan_read_failure(TITAN_EXEC_HOOK_BPRM, 0),
    };
    // §4.2: a default-OFF gate returns before any structure read or event.
    if global.mode == TITAN_EXEC_MODE_OFF {
        return 0;
    }
    let offsets = match titan_offsets() {
        Some(offsets) => offsets,
        None => return titan_read_failure(TITAN_EXEC_HOOK_BPRM, 0),
    };
    if !titan_arguments_match(TITAN_EXEC_HOOK_BPRM) {
        return titan_read_failure(TITAN_EXEC_HOOK_BPRM, 0);
    }
    let scope = titan_scope(global.mode);
    if scope.mode == TITAN_EXEC_MODE_OFF {
        return 0;
    }
    let bprm: u64 = ctx.arg(TITAN_LSM_BPRM_FILE_ARG);
    if bprm == 0 {
        return titan_read_failure(TITAN_EXEC_HOOK_BPRM, 0);
    }
    let file = match titan_read_bprm(bprm, &offsets) {
        Some(file) => file,
        None => return titan_read_failure(TITAN_EXEC_HOOK_BPRM, 0),
    };
    // §4.2 STRICT does not use the containment facts; skip those two reads.
    let containment = if scope.mode == TITAN_EXEC_MODE_STRICT {
        TitanContainment { nlink: 1, fs_magic: 0 }
    } else {
        match titan_read_containment(&file, &offsets) {
            Some(containment) => containment,
            None => return titan_read_failure(TITAN_EXEC_HOOK_BPRM, 0),
        }
    };
    let policy = titan_policy(&file, &global);
    // §4.2 ABI 2: UNTRUSTED-mode path/owner/world-writable facts. Unavailable
    // facts are a READ_FAILURE (visible audit + counter), never a silent allow.
    let untrusted = if scope.mode == TITAN_EXEC_MODE_UNTRUSTED {
        match titan_untrusted(bprm, &file, &offsets) {
            Some(untrusted) => untrusted,
            None => return titan_read_failure(TITAN_EXEC_HOOK_BPRM, 0),
        }
    } else {
        TitanUntrusted::default()
    };
    let mut ctime_mismatch = false;
    if policy.require_ctime {
        match titan_ctime_mismatch(&file, &offsets, policy.ctime_ns) {
            Some(mismatch) => {
                ctime_mismatch = mismatch;
                if mismatch {
                    increment_counter(&TITAN_EXEC_CTIME_REJECTS);
                }
            }
            None => return titan_read_failure(TITAN_EXEC_HOOK_BPRM, 0),
        }
    }
    let reason = titan_decide(
        scope.mode,
        scope.jit_allow,
        TITAN_EXEC_HOOK_BPRM,
        0,
        false,
        containment,
        untrusted,
        &offsets,
        policy.allow && !ctime_mismatch,
        ctime_mismatch,
    );
    titan_finish(
        TITAN_EXEC_HOOK_BPRM,
        scope,
        reason,
        file.dev,
        file.inode_mode,
        file.ino,
        file.generation,
        0,
        ctime_mismatch,
    )
}

#[lsm(hook = "mmap_file")]
pub fn gedefense_titan_exec_mmap(ctx: LsmContext) -> i32 {
    try_titan_exec_mmap(ctx)
}

#[inline(always)]
fn try_titan_exec_mmap(ctx: LsmContext) -> i32 {
    // Defer to a previously attached LSM program exactly like the kernel chain.
    let previous: i32 = ctx.arg(TITAN_LSM_MMAP_PREVIOUS_ARG);
    if previous != 0 {
        return previous;
    }
    // §4.2 performance rule: the requested protection is a ctx scalar slot and
    // must be read before any map/kernel read; non-executable mappings (the vast
    // majority of library mappings) leave the hook immediately. The slot is
    // declared `unsigned long` in the hook proto, so it is read as the full
    // 8-byte argument and then truncated to the uapi `PROT_*` bit width — a
    // 4-byte context read of an 8-byte proto argument is not portable across
    // verifier versions.
    let prot_raw: u64 = ctx.arg(TITAN_LSM_MMAP_PROT_ARG);
    let prot = prot_raw as u32;
    if prot & PROT_EXEC == 0 {
        return 0;
    }
    let global = match titan_global() {
        Some(global) => global,
        None => return titan_read_failure(TITAN_EXEC_HOOK_MMAP, prot),
    };
    if global.mode == TITAN_EXEC_MODE_OFF {
        return 0;
    }
    let offsets = match titan_offsets() {
        Some(offsets) => offsets,
        None => return titan_read_failure(TITAN_EXEC_HOOK_MMAP, prot),
    };
    if !titan_arguments_match(TITAN_EXEC_HOOK_MMAP) {
        return titan_read_failure(TITAN_EXEC_HOOK_MMAP, prot);
    }
    let scope = titan_scope(global.mode);
    if scope.mode == TITAN_EXEC_MODE_OFF {
        return 0;
    }
    let file: u64 = ctx.arg(TITAN_LSM_MMAP_FILE_ARG);
    if file == 0 {
        // Anonymous executable mapping: no file/inode identity (§3.2 exception).
        let reason = titan_decide(
            scope.mode,
            scope.jit_allow,
            TITAN_EXEC_HOOK_MMAP,
            prot,
            true,
            TitanContainment { nlink: 1, fs_magic: 0 },
            TitanUntrusted::default(),
            &offsets,
            false,
            false,
        );
        return titan_finish(TITAN_EXEC_HOOK_MMAP, scope, reason, 0, 0, 0, 0, prot, false);
    }
    let file = match titan_read_file(file, &offsets) {
        Some(file) => file,
        None => return titan_read_failure(TITAN_EXEC_HOOK_MMAP, prot),
    };
    let containment = if scope.mode == TITAN_EXEC_MODE_STRICT {
        TitanContainment { nlink: 1, fs_magic: 0 }
    } else {
        match titan_read_containment(&file, &offsets) {
            Some(containment) => containment,
            None => return titan_read_failure(TITAN_EXEC_HOOK_MMAP, prot),
        }
    };
    let policy = titan_policy(&file, &global);
    let mut ctime_mismatch = false;
    if policy.require_ctime {
        match titan_ctime_mismatch(&file, &offsets, policy.ctime_ns) {
            Some(mismatch) => {
                ctime_mismatch = mismatch;
                if mismatch {
                    increment_counter(&TITAN_EXEC_CTIME_REJECTS);
                }
            }
            None => return titan_read_failure(TITAN_EXEC_HOOK_MMAP, prot),
        }
    }
    // UNTRUSTED path facts are an execve (bprm) gate; an mmap of a file that
    // cannot be execve'd is covered by the containment rules and never grants a
    // new capability, so the mmap hook passes the neutral fact set.
    let reason = titan_decide(
        scope.mode,
        scope.jit_allow,
        TITAN_EXEC_HOOK_MMAP,
        prot,
        false,
        containment,
        TitanUntrusted::default(),
        &offsets,
        policy.allow && !ctime_mismatch,
        ctime_mismatch,
    );
    titan_finish(
        TITAN_EXEC_HOOK_MMAP,
        scope,
        reason,
        file.dev,
        file.inode_mode,
        file.ino,
        file.generation,
        prot,
        ctime_mismatch,
    )
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
    xdr_kernel::flush_pending_exec_argv(pid_tgid as u32, comm);
    0
}

// ---------------------------------------------------------------------------
// Point 5 (§4): lockdown fastpath shared by XDP, TC-ingress and cgroup-egress.
//
// Each program reads the state word before its pre-existing pipeline. OFF, an
// absent map entry or a foreign magic/ABI/mode leaves the verdict path
// byte-identical to 5.2.0 (fail-safe, no drop); the only added cost is one
// array lookup. Unknown flag bits are ignored exactly like the core decoder.
// ---------------------------------------------------------------------------

/// Reads the §3 state word. `None` = absent/zero word, foreign magic/ABI or an
/// out-of-range mode; a valid `OFF` word also yields `None` because it is not
/// armed and therefore must not alter any verdict.
#[inline(always)]
fn lockdown_flags() -> Option<u8> {
    let word = *LOCKDOWN_STATE.get(LOCKDOWN_STATE_INDEX)?;
    let magic = ((word >> LOCKDOWN_STATE_MAGIC_SHIFT) & LOCKDOWN_STATE_BYTE_MASK) as u8;
    let abi = ((word >> LOCKDOWN_STATE_ABI_SHIFT) & LOCKDOWN_STATE_BYTE_MASK) as u8;
    let mode = ((word >> LOCKDOWN_STATE_MODE_SHIFT) & LOCKDOWN_STATE_BYTE_MASK) as u8;
    if magic != LOCKDOWN_STATE_MAGIC || abi != LOCKDOWN_STATE_ABI || mode != LOCKDOWN_MODE_ARMED {
        return None;
    }
    let flags = ((word >> LOCKDOWN_STATE_FLAGS_SHIFT) & LOCKDOWN_STATE_BYTE_MASK) as u8;
    Some(flags)
}

/// §4 XDP/TC-ingress condition: armed word with `DROP_ALL`. Loopback is
/// irrelevant on an external ingress path, so there is no exception there.
#[inline(always)]
fn lockdown_drop_active() -> bool {
    match lockdown_flags() {
        Some(flags) => (flags & LOCKDOWN_FLAG_DROP_ALL) != 0,
        None => false,
    }
}

/// §4 cgroup-egress fastpath: `Some(0)` = DROP, `Some(1)` = PASS because of
/// the `ALLOW_LOOPBACK` exception, `None` = no active lockdown (legacy path).
/// A packet whose fixed L3 header cannot be read is DROPped while locked down
/// (fail-closed, §4); only a proven loopback packet may pass.
#[inline(always)]
fn lockdown_egress_verdict(ctx: &SkBuffContext) -> Option<i32> {
    let flags = lockdown_flags()?;
    if (flags & LOCKDOWN_FLAG_DROP_ALL) == 0 {
        return None;
    }
    if (flags & LOCKDOWN_FLAG_ALLOW_LOOPBACK) != 0 && lockdown_loopback_packet(ctx) == Some(true) {
        increment_counter(&LOCKDOWN_WITNESS_PASSES);
        return Some(1);
    }
    increment_counter(&LOCKDOWN_DROPS);
    Some(0)
}

/// Minimal L3 loopback proof for §4 `ALLOW_LOOPBACK`: `127.0.0.0/8` and `::1`
/// on both endpoints (a non-loopback source cannot tunnel through the
/// exception). `None` = truncated/unparseable header. Kept as a BPF subprogram
/// (`#[inline(never)]`) so the 2x16/2x4 address temporaries own their own
/// stack frame instead of the hot path (512-byte eBPF stack limit).
#[inline(never)]
fn lockdown_loopback_packet(ctx: &SkBuffContext) -> Option<bool> {
    let version: u8 = ctx.load(0).ok()?;
    match version >> 4 {
        NETWORK_FAMILY_V4 => {
            let src: [u8; 4] = ctx.load(12).ok()?;
            let dst: [u8; 4] = ctx.load(16).ok()?;
            Some(src[0] == 127 && dst[0] == 127)
        }
        NETWORK_FAMILY_V6 => {
            let src: [u8; 16] = ctx.load(8).ok()?;
            let dst: [u8; 16] = ctx.load(24).ok()?;
            Some(ipv6_loopback(&src) && ipv6_loopback(&dst))
        }
        _ => None,
    }
}

/// True for the IPv6 loopback address `::1`.
#[inline(always)]
fn ipv6_loopback(address: &[u8; 16]) -> bool {
    let mut index = 0usize;
    while index < 15 {
        if address[index] != 0 {
            return false;
        }
        index += 1;
    }
    address[15] == 1
}

#[xdp]
pub fn gedefense_xdp(ctx: XdpContext) -> u32 {
    // Point 5 (§4): lockdown is the first statement of the program. It drops
    // every frame on the external interface without L3/L4 parsing.
    if lockdown_drop_active() {
        increment_counter(&LOCKDOWN_DROPS);
        return xdp_action::XDP_DROP;
    }
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
    // Point 5 (§4): lockdown shot before the ingress sensor/policy pipeline.
    if lockdown_drop_active() {
        increment_counter(&LOCKDOWN_DROPS);
        return TC_ACT_SHOT;
    }
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
    // Point 5 (§4): lockdown precedes the Point-3 STYX_GLOBAL lookup and every
    // other egress decision. Only a proven loopback packet may pass while
    // ALLOW_LOOPBACK is set; everything else (including parse failures) drops.
    if let Some(verdict) = lockdown_egress_verdict(&ctx) {
        return verdict;
    }
    match inspect_egress(&ctx) {
        // 0 = DROP, 1 = PASS (pre-existing return contract, §6.11).
        Ok(true) => 0,
        Ok(false) | Err(()) => 1,
    }
}

/// Ordered Point-3 egress pipeline (§6). `Ok(true)` means DROP, `Ok(false)`
/// means PASS. `Err(())` is only produced by the byte-identical 5.2.0 fallback
/// path for malformed L3 frames (PASS, as before).
#[inline(always)]
fn inspect_egress(ctx: &SkBuffContext) -> Result<bool, ()> {
    // §6.1: one array lookup on the hot path. A missing global word means the
    // core has not initialised Point 3, so behave exactly like 5.2.0.
    let global = match STYX_GLOBAL.get(STYX_GLOBAL_INDEX) {
        Some(value) => *value,
        None => return legacy_inspect_egress(ctx),
    };
    let global_mode = decode_global_mode(global);
    let global_flags = decode_global_flags(global);
    if global_mode == STYX_MODE_OFF && (global_flags & STYX_FLAG_LOG_FLOWS) == 0 {
        // Default deployment after upgrade: byte-identical 5.2.0 verdicts, no
        // IPv4-mapped normalisation, no flow telemetry, no new counters. The
        // only added cost is the array lookup above (§12).
        return legacy_inspect_egress(ctx);
    }
    let epoch = (global & u64::from(u32::MAX)) as u32;

    // §6.2: L3 parse. A malformed frame is only dropped when the resolved scope
    // enforces; otherwise it stays on the pre-existing PASS path.
    let mut packet = EgressPacket::zeroed();
    if !parse_egress_packet(ctx, &mut packet) {
        increment_counter(&EGRESS_PARSE_ERRORS);
        let scope = resolve_egress_scope(ctx, epoch);
        let (mode, _flags) = scope_mode_flags(&scope, global_mode, global_flags);
        if mode == STYX_MODE_ENFORCE {
            increment_counter(&EGRESS_DROPS_TOTAL);
            return Ok(true);
        }
        return Ok(false);
    }

    // §6.3/§6.4: IPv4-mapped/compatible normalisation happened in the parser;
    // attribute the skb to its enforcing cgroup scope (bounded ancestor walk).
    let scope = resolve_egress_scope(ctx, epoch);
    let (mode, flags) = scope_mode_flags(&scope, global_mode, global_flags);
    // §6.7-§6.10: mandatory veto, DNS pinning, allow order, default verdict.
    let decision = evaluate_egress_policy(&packet, &scope, mode, flags, global_flags);

    // §6.5: aggregate per flow and emit bounded FlowEvents - never one event per
    // packet. Telemetry is on when the cgroup (or global scope) logs flows, and
    // always in monitor/enforce mode.
    if (flags & STYX_FLAG_LOG_FLOWS) != 0
        || (global_flags & STYX_FLAG_LOG_FLOWS) != 0
        || mode >= STYX_MODE_MONITOR
    {
        observe_flow(ctx, &packet, scope.cell_cgroup, decision.verdict);
    }

    if decision.drop {
        increment_counter(&EGRESS_DROPS_TOTAL);
        if decision.policy_drop {
            increment_counter(&EGRESS_POLICY_DROPS);
        }
        return Ok(true);
    }
    Ok(false)
}

/// 5.2.0 egress verdict path, kept byte-identical for the default `off` state:
/// allowlist PASS, threat-intel blocklist DROP (with the existing event), else PASS.
/// Kept as a BPF subprogram (`#[inline(never)]`) for stack-frame separation.
#[inline(never)]
fn legacy_inspect_egress(ctx: &SkBuffContext) -> Result<bool, ()> {
    let version: u8 = ctx.load(0).map_err(|_| ())?;
    match version >> 4 {
        NETWORK_FAMILY_V4 => inspect_egress_v4(ctx),
        NETWORK_FAMILY_V6 => inspect_egress_v6(ctx),
        _ => Err(()),
    }
}

#[inline(always)]
fn decode_global_mode(global: u64) -> u8 {
    ((global >> STYX_GLOBAL_MODE_SHIFT) & STYX_GLOBAL_MODE_MASK) as u8
}

#[inline(always)]
fn decode_global_flags(global: u64) -> u8 {
    ((global >> STYX_GLOBAL_FLAGS_SHIFT) & STYX_GLOBAL_FLAGS_MASK) as u8
}

/// Enforcing cgroup scope of one skb (§6.4).
#[derive(Clone, Copy)]
struct EgressScope {
    /// First ancestor with a cell policy, or the skb cgroup when no cell policy
    /// matched (then the global mode applies). 0 = no cgroup at all.
    cell_cgroup: u64,
    /// Raw `CELL_EGRESS_MODE` byte (mode in bits 0..2, flags above); `None`
    /// means the global default applies.
    mode_flags: Option<u8>,
}

#[inline(always)]
fn scope_mode_flags(scope: &EgressScope, global_mode: u8, global_flags: u8) -> (u8, u8) {
    match scope.mode_flags {
        Some(raw) => (raw & STYX_MODE_MASK, raw & !STYX_MODE_MASK),
        None => (global_mode, global_flags),
    }
}

/// §6.4: attribute an skb to its enforcing cgroup scope. Positive results are
/// cached in `STYX_RESOLVED` per skb cgroup together with the core epoch. The
/// resolution walk is bounded to level 0..63 like the existing LSM ancestor
/// walk. Negative results are deliberately not cached: a cell policy installed
/// on an existing ancestor must take effect immediately instead of after the
/// next core restart (the walk is bounded by the real cgroup depth, the kernel
/// returns 0 for levels below the current cgroup).
///
/// Kept as a BPF subprogram (`#[inline(never)]`): the cgroup-attribution state
/// and the LPM key temporaries must not share the hot-path stack frame of the
/// event emission, otherwise the 512-byte eBPF stack limit is exceeded.
#[inline(never)]
fn resolve_egress_scope(ctx: &SkBuffContext, epoch: u32) -> EgressScope {
    let skb_cgroup = unsafe { bpf_skb_cgroup_id(ctx.as_ptr().cast()) };
    if skb_cgroup == 0 {
        return EgressScope { cell_cgroup: 0, mode_flags: None };
    }
    if let Some(cached) = unsafe { STYX_RESOLVED.get(&skb_cgroup) } {
        let cached_epoch = u32::from_le_bytes([cached[8], cached[9], cached[10], cached[11]]);
        if cached_epoch == epoch {
            let cell = u64::from_le_bytes([
                cached[0], cached[1], cached[2], cached[3], cached[4], cached[5], cached[6],
                cached[7],
            ]);
            if let Some(mode_flags) = unsafe { CELL_EGRESS_MODE.get(&cell) } {
                // Re-read the mode byte so STYX_MODE_SET/DEL takes effect for
                // already-cached cgroups without waiting for an epoch change.
                return EgressScope { cell_cgroup: cell, mode_flags: Some(*mode_flags) };
            }
        }
    }
    let mut level: i32 = 0;
    while level < MAX_CGROUP_ANCESTOR_LEVELS {
        let ancestor = unsafe { bpf_skb_ancestor_cgroup_id(ctx.as_ptr().cast(), level) };
        if ancestor == 0 {
            break;
        }
        if let Some(mode_flags) = unsafe { CELL_EGRESS_MODE.get(&ancestor) } {
            cache_egress_resolution(skb_cgroup, ancestor, epoch, *mode_flags);
            return EgressScope { cell_cgroup: ancestor, mode_flags: Some(*mode_flags) };
        }
        level += 1;
    }
    EgressScope { cell_cgroup: skb_cgroup, mode_flags: None }
}

#[inline(always)]
fn cache_egress_resolution(skb_cgroup: u64, cell_cgroup: u64, epoch: u32, mode_flags: u8) {
    // §4 value layout: [cell_cgroup LE 8][epoch LE 4][mode+flags 2][pad 2].
    let mut cached = [0u8; 16];
    cached[0..8].copy_from_slice(&cell_cgroup.to_le_bytes());
    cached[8..12].copy_from_slice(&epoch.to_le_bytes());
    cached[12] = mode_flags & STYX_MODE_MASK;
    cached[13] = mode_flags & !STYX_MODE_MASK;
    // Cache pressure only costs the next packet one bounded walk; ABI-2 has no
    // dedicated health counter for a failed resolve-cache insertion.
    let _ = STYX_RESOLVED.insert(&skb_cgroup, &cached, 0);
}

/// L3/L4 metadata of one egress packet, normalised for policy evaluation.
#[derive(Clone, Copy)]
struct EgressPacket {
    /// 4 or 6. IPv4-mapped/compatible IPv6 destinations are normalised to 4.
    family: u8,
    /// Wire protocol marker for FlowEvent (0/6/17).
    proto: u8,
    /// Actual L4 protocol byte (6/17/1/58/..., 0 when an extension-header chain
    /// was cut by the bound).
    protocol: u8,
    /// Canonical address: IPv4 in the last four bytes, first twelve zero.
    src: [u8; NETWORK_ADDRESS_BYTES],
    dst: [u8; NETWORK_ADDRESS_BYTES],
    src_port: u16,
    dst_port: u16,
    tcp_flags: u8,
    icmpv6_type: u8,
    packet_len: u32,
}

impl EgressPacket {
    const fn zeroed() -> Self {
        Self {
            family: 0,
            proto: 0,
            protocol: 0,
            src: [0u8; NETWORK_ADDRESS_BYTES],
            dst: [0u8; NETWORK_ADDRESS_BYTES],
            src_port: 0,
            dst_port: 0,
            tcp_flags: 0,
            icmpv6_type: 0,
            packet_len: 0,
        }
    }
}

/// Inlined dispatcher into the v4/v6 subprograms so it adds neither a stack
/// frame nor an `Option<EgressPacket>` return buffer (`parse_egress_v4`/`_v6`
/// write directly into `out`, staying well below the 512-byte BPF stack limit).
#[inline(always)]
fn parse_egress_packet(ctx: &SkBuffContext, out: &mut EgressPacket) -> bool {
    let Ok(version) = ctx.load::<u8>(0) else {
        return false;
    };
    match version >> 4 {
        NETWORK_FAMILY_V4 => parse_egress_v4(ctx, out),
        NETWORK_FAMILY_V6 => parse_egress_v6(ctx, out),
        _ => false,
    }
}

/// Kept as a BPF subprogram (`#[inline(never)]`) so the IPv4 header/temporary
/// stack objects do not join the IPv6 parser or hot-path frames.
#[inline(never)]
fn parse_egress_v4(ctx: &SkBuffContext, out: &mut EgressPacket) -> bool {
    let Ok(header) = ctx.load::<Ipv4Hdr>(0) else {
        return false;
    };
    if header.version_ihl >> 4 != NETWORK_FAMILY_V4 || header.version_ihl & 0x0f < 5 {
        return false;
    }
    let transport_offset = usize::from(header.version_ihl & 0x0f) * 4;
    // Non-first fragments carry no L4 header: IP policy only (§6.8).
    let fragment_offset = u16::from_be_bytes(header.frag) & 0x1fff;
    let (src_port, dst_port, tcp_flags) = if fragment_offset == 0 {
        skb_transport_metadata(ctx, transport_offset, header.protocol)
    } else {
        (0, 0, 0)
    };
    let proto = if fragment_offset == 0 {
        wire_protocol(header.protocol)
    } else {
        STYX_PROTO_UNKNOWN
    };
    out.family = NETWORK_FAMILY_V4;
    out.proto = proto;
    out.protocol = header.protocol;
    out.src = canonical_ipv4(header.src);
    out.dst = canonical_ipv4(header.dst);
    out.src_port = src_port;
    out.dst_port = dst_port;
    out.tcp_flags = tcp_flags;
    out.icmpv6_type = 0;
    out.packet_len = ctx.len();
    true
}

/// Kept as a BPF subprogram (`#[inline(never)]`): writes directly into `out` to
/// avoid keeping a 40-byte `Ipv6Hdr`, scratch addresses, and a `sret` return
/// buffer live across subprogram calls on the 512-byte eBPF stack.
#[inline(never)]
fn parse_egress_v6(ctx: &SkBuffContext, out: &mut EgressPacket) -> bool {
    let Ok(version_flow) = ctx.load::<[u8; 4]>(0) else {
        return false;
    };
    if u32::from_be_bytes(version_flow) >> 28 != u32::from(NETWORK_FAMILY_V6) {
        return false;
    }
    let Ok(mut next_header) = ctx.load::<u8>(6) else {
        return false;
    };
    let Ok(src) = ctx.load::<[u8; NETWORK_ADDRESS_BYTES]>(8) else {
        return false;
    };
    let Ok(dst) = ctx.load::<[u8; NETWORK_ADDRESS_BYTES]>(24) else {
        return false;
    };
    out.src = src;
    out.dst = dst;
    // §6.8: walk at most `IPV6_EXT_HEADER_HOPS` extension headers. The transport
    // offset stays a bounded constant expression; malformed/truncated headers
    // fail the bounded `ctx.load` and abort the parse (fail closed in enforce).
    let mut transport_offset = mem::size_of::<Ipv6Hdr>();
    let mut hops: u8 = 0;
    let mut fragmented = false;
    let mut transport_known = true;
    loop {
        let next = next_header;
        let header_len = match next {
            // Hop-by-Hop Options, Routing, Destination Options: (len + 1) * 8.
            0 | 43 | 60 => {
                if hops >= IPV6_EXT_HEADER_HOPS {
                    transport_known = false;
                    break;
                }
                let Ok(following) = ctx.load::<u8>(transport_offset) else {
                    return false;
                };
                let Ok(length) = ctx.load::<u8>(transport_offset + 1) else {
                    return false;
                };
                next_header = following;
                (usize::from(length) + 1) * 8
            }
            // Authentication Header: (len + 2) * 4.
            51 => {
                if hops >= IPV6_EXT_HEADER_HOPS {
                    transport_known = false;
                    break;
                }
                let Ok(following) = ctx.load::<u8>(transport_offset) else {
                    return false;
                };
                let Ok(length) = ctx.load::<u8>(transport_offset + 1) else {
                    return false;
                };
                next_header = following;
                (usize::from(length) + 2) * 4
            }
            // Fragment header: fixed eight bytes. A non-zero fragment offset has
            // no L4 header, so only the IP policy applies.
            44 => {
                if hops >= IPV6_EXT_HEADER_HOPS {
                    transport_known = false;
                    break;
                }
                let Ok(following) = ctx.load::<u8>(transport_offset) else {
                    return false;
                };
                let Ok(fragment) = ctx.load::<[u8; 2]>(transport_offset + 2) else {
                    return false;
                };
                if u16::from_be_bytes(fragment) & 0xfff8 != 0 {
                    fragmented = true;
                }
                next_header = following;
                8
            }
            _ => break,
        };
        let Some(next_offset) = transport_offset.checked_add(header_len) else {
            return false;
        };
        transport_offset = next_offset;
        hops += 1;
    }
    let protocol = if transport_known { next_header } else { 0 };
    let (src_port, dst_port, tcp_flags, icmpv6_type) = if transport_known && !fragmented {
        let (src_port, dst_port, tcp_flags) =
            skb_transport_metadata(ctx, transport_offset, protocol);
        let icmpv6_type = if protocol == IPV6_PROTOCOL_ICMPV6 {
            ctx.load::<u8>(transport_offset).ok().unwrap_or(0)
        } else {
            0
        };
        (src_port, dst_port, tcp_flags, icmpv6_type)
    } else {
        (0, 0, 0, 0)
    };
    let mut family = NETWORK_FAMILY_V6;
    let mut embedded_dst = [0u8; 4];
    if embedded_ipv4(&out.dst, &mut embedded_dst) {
        family = NETWORK_FAMILY_V4;
        out.dst = canonical_ipv4(embedded_dst);
        let mut embedded_src = [0u8; 4];
        out.src = if embedded_ipv4(&out.src, &mut embedded_src) {
            canonical_ipv4(embedded_src)
        } else {
            [0u8; NETWORK_ADDRESS_BYTES]
        };
    }
    let proto = if fragmented {
        STYX_PROTO_UNKNOWN
    } else {
        wire_protocol(protocol)
    };
    out.family = family;
    out.proto = proto;
    out.protocol = protocol;
    out.src_port = src_port;
    out.dst_port = dst_port;
    out.tcp_flags = tcp_flags;
    out.icmpv6_type = icmpv6_type;
    out.packet_len = ctx.len();
    true
}

/// Kept as a BPF subprogram (`#[inline(never)]`): its header-prefix loads would
/// otherwise grow the IPv6 parser frame, and three arguments fit the BPF
/// subprogram ABI.
#[inline(never)]
fn skb_transport_metadata(ctx: &SkBuffContext, offset: usize, protocol: u8) -> (u16, u16, u8) {
    if protocol == NETWORK_PROTOCOL_TCP {
        if let Ok(tcp) = ctx.load::<TcpPrefix>(offset) {
            return (
                u16::from_be_bytes(tcp.src_port),
                u16::from_be_bytes(tcp.dst_port),
                tcp.flags,
            );
        }
    } else if protocol == STYX_PROTO_UDP {
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

/// IPv4-mapped (`::ffff:a.b.c.d`) or IPv4-compatible (`::a.b.c.d`) embedded
/// address. `::` and `::1` keep their IPv6 meaning and are not normalised.
/// Kept as a BPF subprogram (`#[inline(never)]`) for stack-frame separation of
/// the 16-byte address copies from the rest of the IPv6 parser. Writes the
/// extracted IPv4 bytes into `out` and returns `bool` (`r0` stays a scalar so
/// LLVM never shifts uninitialized `Option<[u8; 4]>` payload bits into `r0`).
#[inline(never)]
fn embedded_ipv4(address: &[u8; NETWORK_ADDRESS_BYTES], out: &mut [u8; 4]) -> bool {
    let mapped =
        address[0..10].iter().all(|byte| *byte == 0) && address[10] == 0xff && address[11] == 0xff;
    if mapped {
        *out = [address[12], address[13], address[14], address[15]];
        return true;
    }
    if address[0..12].iter().all(|byte| *byte == 0) {
        let ipv4 = [address[12], address[13], address[14], address[15]];
        if ipv4 != [0, 0, 0, 0] && ipv4 != [0, 0, 0, 1] {
            *out = ipv4;
            return true;
        }
    }
    false
}

#[inline(always)]
const fn canonical_ipv4(address: [u8; 4]) -> [u8; NETWORK_ADDRESS_BYTES] {
    [
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, address[0], address[1], address[2], address[3],
    ]
}

#[inline(always)]
const fn wire_protocol(protocol: u8) -> u8 {
    if protocol == NETWORK_PROTOCOL_TCP {
        STYX_PROTO_TCP
    } else if protocol == STYX_PROTO_UDP {
        STYX_PROTO_UDP
    } else {
        STYX_PROTO_UNKNOWN
    }
}

#[inline(always)]
fn ipv4_octets(packet: &EgressPacket) -> [u8; 4] {
    [
        packet.dst[12],
        packet.dst[13],
        packet.dst[14],
        packet.dst[15],
    ]
}

/// Final verdict for one packet plus whether it is actually dropped.
#[derive(Clone, Copy)]
struct EgressDecision {
    verdict: u8,
    /// True when the packet is dropped: new enforcement in enforce mode, or the
    /// pre-existing threat-intel blocklist (which keeps its 5.2.0 behaviour).
    drop: bool,
    /// True when the drop is caused by new Point-3 enforcement (veto, DNS pin,
    /// default deny) and therefore feeds EGRESS_POLICY_DROPS.
    policy_drop: bool,
}

impl EgressDecision {
    const fn allow() -> Self {
        Self { verdict: STYX_VERDICT_ALLOW, drop: false, policy_drop: false }
    }
}

/// Kept as a BPF subprogram (`#[inline(never)]`): the LPM key temporaries of the
/// individual policy lookups would otherwise inflate the main program frame
/// beyond the 512-byte eBPF stack limit.
#[inline(never)]
fn evaluate_egress_policy(
    packet: &EgressPacket,
    scope: &EgressScope,
    mode: u8,
    flags: u8,
    global_flags: u8,
) -> EgressDecision {
    let enforce = mode == STYX_MODE_ENFORCE;
    let loopback = is_loopback(packet);

    // §6.7: mandatory veto before every allow rule. Loopback is exempt (§6.7);
    // the ICMPv6 ND exception is applied inside `egress_vetoed`.
    if !loopback && egress_vetoed(packet, flags) {
        return EgressDecision {
            verdict: STYX_VERDICT_METADATA_VETO,
            drop: enforce,
            policy_drop: enforce,
        };
    }

    // §6.8: DNS/DoT pinning. Only configured resolver destinations may be
    // reached on 53/853, and only with DNS_RESOLVER on the cell or globally.
    if !loopback && dns_pinning_violated(packet, flags, global_flags) {
        return EgressDecision {
            verdict: STYX_VERDICT_DNS_PIN,
            drop: enforce,
            policy_drop: enforce,
        };
    }

    // §6.9a: per-cell allow, longest prefix match.
    if cell_allow_matches(scope.cell_cgroup, packet) {
        return EgressDecision::allow();
    }
    // §6.9b/§6.9c: global allow and the pre-existing host allowlist apply only
    // when the cgroup opted in with ALLOW_HOST_ALLOWLIST.
    if flags & STYX_FLAG_ALLOW_HOST_ALLOWLIST != 0
        && (global_allow_matches(packet) || legacy_allowlist_matches(packet))
    {
        return EgressDecision::allow();
    }
    // §6.9d: the pre-existing threat-intel blocklist keeps the exact 5.2.0
    // behaviour (DROP plus the unchanged EgressDropEvent wire format) in every
    // mode, so enabling Point-3 telemetry never weakens it.
    if legacy_blocklist_matches(packet) {
        emit_egress_drop(packet.family, packet.protocol, legacy_destination(packet));
        return EgressDecision {
            verdict: STYX_VERDICT_DROP,
            drop: true,
            policy_drop: false,
        };
    }
    // Loopback is never default-denied: local IPC must keep working (no lockout,
    // §1.2). It is evaluated after the blocklist so operator blocklist prefixes
    // that cover 127/8 or ::1 keep their pre-existing effect.
    if loopback {
        return EgressDecision::allow();
    }
    // §6.10: default depends on the mode. Monitor never drops, enforce fails
    // closed; OFF with flow logging records the packet without blocking.
    if enforce {
        return EgressDecision {
            verdict: STYX_VERDICT_DEFAULT_DENY,
            drop: true,
            policy_drop: true,
        };
    }
    if mode == STYX_MODE_MONITOR {
        return EgressDecision {
            verdict: STYX_VERDICT_AUDIT_DROP,
            drop: false,
            policy_drop: false,
        };
    }
    EgressDecision::allow()
}

/// §6.7: mandatory veto against `STYX_BLOCK_*` (the core seeds metadata,
/// link-local and multicast prefixes). `ALLOW_METADATA` only exempts targets
/// outside link-local/multicast scopes: metadata endpoints inside fe80::/10 or
/// a multicast scope remain vetoed.
#[inline(always)]
fn egress_vetoed(packet: &EgressPacket, flags: u8) -> bool {
    if is_nd_exception(packet) {
        return false;
    }
    let blocked = match packet.family {
        NETWORK_FAMILY_V4 => STYX_BLOCK_V4.get(&Key::new(32, ipv4_octets(packet))).is_some(),
        NETWORK_FAMILY_V6 => STYX_BLOCK_V6.get(&Key::new(128, packet.dst)).is_some(),
        _ => false,
    };
    if !blocked {
        return false;
    }
    (flags & STYX_FLAG_ALLOW_METADATA) == 0 || is_link_local_or_multicast(packet)
}

/// §6.8: `dst_port = 53/853` is only allowed to configured resolvers and only
/// with the DNS_RESOLVER flag on the cgroup scope (or globally).
#[inline(always)]
fn dns_pinning_violated(packet: &EgressPacket, flags: u8, global_flags: u8) -> bool {
    if !is_dns_transport_port(packet.dst_port) {
        return false;
    }
    let resolver_known = match packet.family {
        NETWORK_FAMILY_V4 => STYX_RESOLVER_V4.get(&Key::new(32, ipv4_octets(packet))).is_some(),
        NETWORK_FAMILY_V6 => STYX_RESOLVER_V6.get(&Key::new(128, packet.dst)).is_some(),
        _ => false,
    };
    if !resolver_known {
        return true;
    }
    (flags & STYX_FLAG_DNS_RESOLVER) == 0 && (global_flags & STYX_FLAG_DNS_RESOLVER) == 0
}

/// §6.9a: per-cell allow trie. Key (§4): [cgroup LE 8][addr 4][dst_port BE 2]
/// [proto 1][pad 1]; prefix 64 = any destination, 96 = cgroup+IP, 112 = +port,
/// 120 = +protocol. A single lookup returns the longest matching prefix.
#[inline(always)]
fn cell_allow_matches(cell_cgroup: u64, packet: &EgressPacket) -> bool {
    if cell_cgroup == 0 {
        return false;
    }
    match packet.family {
        NETWORK_FAMILY_V4 => {
            let mut key = [0u8; 16];
            key[0..8].copy_from_slice(&cell_cgroup.to_le_bytes());
            key[8..12].copy_from_slice(&ipv4_octets(packet));
            key[12..14].copy_from_slice(&packet.dst_port.to_be_bytes());
            key[14] = packet.proto;
            CELL_EGRESS_ALLOW_V4.get(&Key::new(120, key)).is_some()
        }
        NETWORK_FAMILY_V6 => {
            // Phase 1 v6 cell key (§4): [cgroup LE 8][addr 16], no port/proto
            // slot. The core installs v6 rules as CIDR-only entries.
            let mut key = [0u8; 24];
            key[0..8].copy_from_slice(&cell_cgroup.to_le_bytes());
            key[8..24].copy_from_slice(&packet.dst);
            CELL_EGRESS_ALLOW_V6.get(&Key::new(192, key)).is_some()
        }
        _ => false,
    }
}

/// §6.9b: global host allowlist. Key (§4): [addr][dst_port BE 2][proto 1][pad];
/// prefix 32 = any port/proto, 48 = +port, 56 = +protocol.
#[inline(always)]
fn global_allow_matches(packet: &EgressPacket) -> bool {
    match packet.family {
        NETWORK_FAMILY_V4 => {
            let mut key = [0u8; 8];
            key[0..4].copy_from_slice(&ipv4_octets(packet));
            key[4..6].copy_from_slice(&packet.dst_port.to_be_bytes());
            key[6] = packet.proto;
            STYX_ALLOW_GLOBAL_V4.get(&Key::new(56, key)).is_some()
        }
        NETWORK_FAMILY_V6 => {
            let mut key = [0u8; 20];
            key[0..16].copy_from_slice(&packet.dst);
            key[16..18].copy_from_slice(&packet.dst_port.to_be_bytes());
            key[18] = packet.proto;
            STYX_ALLOW_GLOBAL_V6.get(&Key::new(152, key)).is_some()
        }
        _ => false,
    }
}

#[inline(always)]
fn legacy_allowlist_matches(packet: &EgressPacket) -> bool {
    match packet.family {
        NETWORK_FAMILY_V4 => ALLOWLIST_V4.get(&Key::new(32, ipv4_octets(packet))).is_some(),
        NETWORK_FAMILY_V6 => ALLOWLIST_V6.get(&Key::new(128, packet.dst)).is_some(),
        _ => false,
    }
}

#[inline(always)]
fn legacy_blocklist_matches(packet: &EgressPacket) -> bool {
    match packet.family {
        NETWORK_FAMILY_V4 => BLOCKLIST_V4
            .get(&Key::new(32, ipv4_octets(packet)))
            .is_some_and(|action| *action == ACTION_DROP),
        NETWORK_FAMILY_V6 => BLOCKLIST_V6
            .get(&Key::new(128, packet.dst))
            .is_some_and(|action| *action == ACTION_DROP),
        _ => false,
    }
}

/// Legacy `EgressDropEvent` destination convention (wire format unchanged):
/// IPv4 in the first four bytes, IPv6 in all sixteen.
#[inline(always)]
fn legacy_destination(packet: &EgressPacket) -> [u8; NETWORK_ADDRESS_BYTES] {
    let mut destination = [0u8; NETWORK_ADDRESS_BYTES];
    if packet.family == NETWORK_FAMILY_V4 {
        destination[0..4].copy_from_slice(&ipv4_octets(packet));
    } else {
        destination = packet.dst;
    }
    destination
}

#[inline(always)]
fn is_loopback(packet: &EgressPacket) -> bool {
    match packet.family {
        NETWORK_FAMILY_V4 => packet.dst[12] == 127,
        NETWORK_FAMILY_V6 => {
            packet.dst[0..15].iter().all(|byte| *byte == 0) && packet.dst[15] == 1
        }
        _ => false,
    }
}

#[inline(always)]
fn is_ipv6_link_local(address: &[u8; NETWORK_ADDRESS_BYTES]) -> bool {
    address[0] == 0xfe && (address[1] & 0xc0) == 0x80
}

#[inline(always)]
fn is_link_local_or_multicast(packet: &EgressPacket) -> bool {
    match packet.family {
        NETWORK_FAMILY_V4 => {
            let first = packet.dst[12];
            (first == 169 && packet.dst[13] == 254) || (224..=239).contains(&first)
        }
        NETWORK_FAMILY_V6 => is_ipv6_link_local(&packet.dst) || packet.dst[0] == 0xff,
        _ => false,
    }
}

/// §6.7/§4: NS/NA towards a link-local IPv6 address is exempt from the seeded
/// fe80::/10 veto, otherwise IPv6 neighbour discovery would be vetoed. Only the
/// two neighbour-discovery types are exempt; from a socket this is a local,
/// non-routable scope (kernel-generated ND does not pass the cgroup hook).
#[inline(always)]
fn is_nd_exception(packet: &EgressPacket) -> bool {
    packet.family == NETWORK_FAMILY_V6
        && packet.protocol == IPV6_PROTOCOL_ICMPV6
        && (packet.icmpv6_type == ICMPV6_NEIGHBOR_SOLICITATION
            || packet.icmpv6_type == ICMPV6_NEIGHBOR_ADVERTISEMENT)
        && is_ipv6_link_local(&packet.dst)
}

#[inline(always)]
const fn is_dns_transport_port(port: u16) -> bool {
    port == DNS_TRANSPORT_PORT || port == DOT_TRANSPORT_PORT
}

/// §6.5: aggregate one egress packet into the per-flow LRU map and emit a
/// bounded FlowEvent once a threshold is crossed (first packet of the flow,
/// epoch-second change, >= 64 KiB or >= 256 packets since the last event).
/// No event is ever emitted per packet.
///
/// Kept as a BPF subprogram (`#[inline(never)]`) to keep the flow-aggregation
/// scratch state out of the main program's stack frame.
#[inline(never)]
fn observe_flow(ctx: &SkBuffContext, packet: &EgressPacket, cell_cgroup: u64, verdict: u8) {
    match packet.family {
        NETWORK_FAMILY_V4 => {
            let mut key = [0u8; 16];
            key[0..8].copy_from_slice(&cell_cgroup.to_le_bytes());
            key[8..12].copy_from_slice(&ipv4_octets(packet));
            key[12..14].copy_from_slice(&packet.dst_port.to_be_bytes());
            key[14] = packet.proto;
            observe_flow_aggregate(&FLOW_AGG_V4, &key, ctx, packet, cell_cgroup, verdict);
        }
        NETWORK_FAMILY_V6 => {
            let mut key = [0u8; 32];
            key[0..8].copy_from_slice(&cell_cgroup.to_le_bytes());
            key[8..24].copy_from_slice(&packet.dst);
            key[24..26].copy_from_slice(&packet.dst_port.to_be_bytes());
            key[26] = packet.proto;
            observe_flow_aggregate(&FLOW_AGG_V6, &key, ctx, packet, cell_cgroup, verdict);
        }
        _ => {}
    }
}

/// Inlined into its caller: BPF subprograms only receive five argument
/// registers, and this helper needs six. The caller's frame plus this state
/// still stays below the 512-byte eBPF stack limit.
#[inline(always)]
fn observe_flow_aggregate<K>(
    map: &LruPerCpuHashMap<K, [u8; 40]>,
    key: &K,
    ctx: &SkBuffContext,
    packet: &EgressPacket,
    cell_cgroup: u64,
    verdict: u8,
) {
    let now = unsafe { bpf_ktime_get_ns() };
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    if let Some(value_ptr) = map.get_ptr_mut(key) {
        // SAFETY: the per-CPU map owns this value for the current CPU and no
        // other CPU can observe the in-place mutation until the program returns.
        let value = unsafe { &mut *value_ptr };
        let last_ts = read_agg_u64(value, FLOW_AGG_LAST_TS);
        let tx_bytes =
            read_agg_u64(value, FLOW_AGG_TX).saturating_add(u64::from(packet.packet_len));
        let packets = read_agg_u32(value, FLOW_AGG_PACKETS).saturating_add(1);
        write_agg_u64(value, FLOW_AGG_LAST_TS, now);
        write_agg_u64(value, FLOW_AGG_TX, tx_bytes);
        write_agg_u32(value, FLOW_AGG_PACKETS, packets);
        value[FLOW_AGG_TCP_FLAGS] |= packet.tcp_flags;
        value[FLOW_AGG_VERDICT] = verdict;
        let second_changed = last_ts / NS_PER_SECOND != now / NS_PER_SECOND;
        if !second_changed && tx_bytes < FLOW_EMIT_BYTES && packets < FLOW_EMIT_PACKETS {
            return;
        }
        let stored_pid = read_agg_u32(value, FLOW_AGG_PID);
        let tcp_flags = value[FLOW_AGG_TCP_FLAGS];
        emit_flow_event(
            ctx,
            cell_cgroup,
            packet,
            tx_bytes,
            packets,
            tcp_flags,
            verdict,
            stored_pid,
            now,
        );
        // Start a new aggregation window: the next FlowEvent reports the delta.
        write_agg_u64(value, FLOW_AGG_FIRST_TS, now);
        write_agg_u64(value, FLOW_AGG_TX, 0);
        write_agg_u32(value, FLOW_AGG_PACKETS, 0);
        value[FLOW_AGG_TCP_FLAGS] = packet.tcp_flags;
    } else {
        // §6.5: first packet of a new aggregate - emit immediately and start the
        // window at zero so the next event needs a threshold.
        let mut value = [0u8; 40];
        write_agg_u64(&mut value, FLOW_AGG_FIRST_TS, now);
        write_agg_u64(&mut value, FLOW_AGG_LAST_TS, now);
        write_agg_u64(&mut value, FLOW_AGG_TX, 0);
        write_agg_u32(&mut value, FLOW_AGG_PACKETS, 0);
        write_agg_u32(&mut value, FLOW_AGG_PID, pid);
        value[FLOW_AGG_TCP_FLAGS] = packet.tcp_flags;
        value[FLOW_AGG_VERDICT] = verdict;
        if map.insert(key, &value, 0).is_ok() {
            emit_flow_event(
                ctx,
                cell_cgroup,
                packet,
                u64::from(packet.packet_len),
                1,
                packet.tcp_flags,
                verdict,
                pid,
                now,
            );
        } else {
            increment_counter(&FLOW_AGG_INSERT_FAILURES);
        }
    }
}

/// Emits one native-endian 104-byte `FlowEvent` (§3.2). The struct is shared
/// with the core decoder, so the wire layout is the `repr(C)` layout; the
/// helper skips records the decoder would reject instead of emitting garbage.
/// Inlined into its caller: BPF subprograms only receive five argument
/// registers, and this helper needs more; the 104-byte record is written
/// directly into the ring-buffer reservation and never copied onto the stack.
#[inline(always)]
fn emit_flow_event(
    ctx: &SkBuffContext,
    cell_cgroup: u64,
    packet: &EgressPacket,
    tx_bytes: u64,
    packets: u32,
    tcp_flags: u8,
    verdict: u8,
    pid: u32,
    ts_ns: u64,
) {
    if packets == 0 || ts_ns == 0 {
        return;
    }
    // `decode_styx_flow_event` rejects family 4 with a non-canonical or
    // unspecified destination; never produce such a record.
    if packet.family == NETWORK_FAMILY_V4 && ipv4_octets(packet) == [0, 0, 0, 0] {
        return;
    }
    let uid = unsafe { bpf_get_socket_uid(ctx.as_ptr().cast()) };
    let comm = bpf_get_current_comm().unwrap_or([0u8; EXEC_COMM_BYTES]);
    // Write the record directly into the ring-buffer reservation: a 104-byte
    // stack copy would exceed the 512-byte eBPF stack together with the parse
    // state, and the reservation is the exact destination the record needs.
    if let Some(mut entry) = FLOW_EVENTS.reserve::<FlowEvent>(0) {
        let event = entry.as_mut_ptr();
        // SAFETY: the reservation is exactly `size_of::<FlowEvent>()` bytes and
        // aligned for the struct. Every field is written through the raw pointer
        // before the entry is submitted; no reference to uninitialised memory is
        // created and the entry is submitted before this scope ends.
        unsafe {
            core::ptr::addr_of_mut!((*event).cgroup_id).write(cell_cgroup);
            core::ptr::addr_of_mut!((*event).ts_ns).write(ts_ns);
            core::ptr::addr_of_mut!((*event).tx_bytes).write(tx_bytes);
            core::ptr::addr_of_mut!((*event).rx_bytes).write(0);
            core::ptr::addr_of_mut!((*event).pid).write(pid);
            core::ptr::addr_of_mut!((*event).uid).write(uid);
            core::ptr::addr_of_mut!((*event).dst).write(packet.dst);
            core::ptr::addr_of_mut!((*event).src).write(packet.src);
            core::ptr::addr_of_mut!((*event).dst_port).write(packet.dst_port);
            core::ptr::addr_of_mut!((*event).src_port).write(packet.src_port);
            core::ptr::addr_of_mut!((*event).packets).write(packets);
            core::ptr::addr_of_mut!((*event).proto).write(packet.proto);
            core::ptr::addr_of_mut!((*event).family).write(packet.family);
            core::ptr::addr_of_mut!((*event).direction).write(STYX_DIR_EGRESS);
            core::ptr::addr_of_mut!((*event).tcp_flags).write(if packet.proto == STYX_PROTO_TCP {
                tcp_flags
            } else {
                0
            });
            core::ptr::addr_of_mut!((*event).verdict).write(verdict);
            core::ptr::addr_of_mut!((*event).reserved).write([0u8; 3]);
            core::ptr::addr_of_mut!((*event).comm).write(comm);
        }
        entry.submit(0);
        increment_counter(&FLOW_EVENTS_EMITTED);
    } else {
        // Ring full: visibility loss is reported through the health counter, the
        // enforcement verdict above is unaffected.
        increment_counter(&FLOW_RING_DROPS);
    }
}

#[inline(always)]
fn read_agg_u32(value: &[u8; 40], offset: usize) -> u32 {
    u32::from_le_bytes([
        value[offset],
        value[offset + 1],
        value[offset + 2],
        value[offset + 3],
    ])
}

#[inline(always)]
fn read_agg_u64(value: &[u8; 40], offset: usize) -> u64 {
    u64::from_le_bytes([
        value[offset],
        value[offset + 1],
        value[offset + 2],
        value[offset + 3],
        value[offset + 4],
        value[offset + 5],
        value[offset + 6],
        value[offset + 7],
    ])
}

#[inline(always)]
fn write_agg_u32(value: &mut [u8; 40], offset: usize, new_value: u32) {
    let bytes = new_value.to_le_bytes();
    value[offset] = bytes[0];
    value[offset + 1] = bytes[1];
    value[offset + 2] = bytes[2];
    value[offset + 3] = bytes[3];
}

#[inline(always)]
fn write_agg_u64(value: &mut [u8; 40], offset: usize, new_value: u64) {
    let bytes = new_value.to_le_bytes();
    value[offset] = bytes[0];
    value[offset + 1] = bytes[1];
    value[offset + 2] = bytes[2];
    value[offset + 3] = bytes[3];
    value[offset + 4] = bytes[4];
    value[offset + 5] = bytes[5];
    value[offset + 6] = bytes[6];
    value[offset + 7] = bytes[7];
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
fn increment_counter(counter: &PerCpuArray<u64>) {
    // Every health counter map has exactly one per-CPU slot at key 0 (§4).
    if let Some(ptr) = counter.get_ptr_mut(INGRESS_HEALTH_KEY) {
        let value = unsafe { &mut *ptr };
        *value = value.saturating_add(1);
    }
}

#[inline(always)]
fn increment_ingress_counter(counter: &PerCpuArray<u64>) {
    increment_counter(counter);
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
