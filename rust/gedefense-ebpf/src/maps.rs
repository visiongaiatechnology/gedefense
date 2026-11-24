use aya_ebpf::{
    bindings::BPF_F_NO_PREALLOC,
    macros::map,
    maps::{Array, HashMap, LpmTrie, LruHashMap, LruPerCpuHashMap, PerCpuArray, RingBuf},
};
use core::mem;
use gedefense_common::{
    FlowEvent, TitanExecEvent, MAX_BLOCKLIST_ENTRIES_V4, MAX_BLOCKLIST_ENTRIES_V6,
    STYX_FLOW_EVENT_WIRE_BYTES, TITAN_EXEC_EVENT_WIRE_BYTES,
};
use crate::net_parse::IngressWindow;
use crate::titan_exec::{
    MAX_TITAN_EXEC_POLICIES, MAX_TITAN_EXEC_SCOPES, TITAN_EXEC_EVENT_RING_BYTES,
    TITAN_EXEC_OFFSETS_ENTRIES,
};

const MAX_ALLOWLIST_ENTRIES: u32 = 65_536;
const EXEC_EVENT_RING_BYTES: u32 = 1 << 20;
const EGRESS_EVENT_RING_BYTES: u32 = 1 << 20;
const CELL_LSM_EVENT_RING_BYTES: u32 = 1 << 20;
const INGRESS_EVENT_RING_BYTES: u32 = 8 << 20;
const MAX_INGRESS_TRACKED_SOURCES: u32 = 8_192;

const MAX_CELL_LSM_POLICIES: u32 = 4096;

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

#[map]
pub(crate) static ALLOWLIST_V4: LpmTrie<[u8; 4], u8> =
    LpmTrie::with_max_entries(MAX_ALLOWLIST_ENTRIES, BPF_F_NO_PREALLOC);
#[map]
pub(crate) static ALLOWLIST_V6: LpmTrie<[u8; 16], u8> =
    LpmTrie::with_max_entries(MAX_ALLOWLIST_ENTRIES, BPF_F_NO_PREALLOC);
#[map]
pub(crate) static BLOCKLIST_V4: LpmTrie<[u8; 4], u8> =
    LpmTrie::with_max_entries(MAX_BLOCKLIST_ENTRIES_V4, BPF_F_NO_PREALLOC);
#[map]
pub(crate) static BLOCKLIST_V6: LpmTrie<[u8; 16], u8> =
    LpmTrie::with_max_entries(MAX_BLOCKLIST_ENTRIES_V6, BPF_F_NO_PREALLOC);
#[map]
pub(crate) static EXEC_EVENTS: RingBuf = RingBuf::with_byte_size(EXEC_EVENT_RING_BYTES, 0);
#[map]
pub(crate) static EGRESS_EVENTS: RingBuf = RingBuf::with_byte_size(EGRESS_EVENT_RING_BYTES, 0);
#[map]
pub(crate) static INGRESS_EVENTS: RingBuf = RingBuf::with_byte_size(INGRESS_EVENT_RING_BYTES, 0);
#[map]
pub(crate) static INGRESS_TRACK_V4: LruPerCpuHashMap<[u8; 4], IngressWindow> =
    LruPerCpuHashMap::with_max_entries(MAX_INGRESS_TRACKED_SOURCES, 0);
#[map]
pub(crate) static INGRESS_TRACK_V6: LruPerCpuHashMap<[u8; 16], IngressWindow> =
    LruPerCpuHashMap::with_max_entries(MAX_INGRESS_TRACKED_SOURCES, 0);
#[map]
pub(crate) static INGRESS_EVENTS_EMITTED: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);
#[map]
pub(crate) static INGRESS_RING_DROPS: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);
#[map]
pub(crate) static INGRESS_TRACK_INSERT_FAILURES: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);

#[map]
pub(crate) static CELL_LSM_POLICIES: HashMap<u64, u8> =
    HashMap::with_max_entries(MAX_CELL_LSM_POLICIES, BPF_F_NO_PREALLOC);
#[map]
pub(crate) static CELL_LSM_EVENTS: RingBuf = RingBuf::with_byte_size(CELL_LSM_EVENT_RING_BYTES, 0);

// Point 3 egress enforcement maps (ABI-2, §4). Keys/values are plain byte
// arrays so the core can populate them without depending on kernel struct
// layouts; all multi-byte integers are little endian (native) except the L4
// port fields of the LPM keys, which are big endian to make the prefix bits
// follow the wire order of the port.
#[map]
pub(crate) static CELL_EGRESS_MODE: HashMap<u64, u8> =
    HashMap::with_max_entries(MAX_CELL_EGRESS_MODES, BPF_F_NO_PREALLOC);
#[map]
pub(crate) static CELL_EGRESS_ALLOW_V4: LpmTrie<[u8; 16], u8> =
    LpmTrie::with_max_entries(MAX_CELL_ALLOW_ENTRIES, BPF_F_NO_PREALLOC);
#[map]
pub(crate) static CELL_EGRESS_ALLOW_V6: LpmTrie<[u8; 24], u8> =
    LpmTrie::with_max_entries(MAX_CELL_ALLOW_ENTRIES, BPF_F_NO_PREALLOC);
#[map]
pub(crate) static STYX_ALLOW_GLOBAL_V4: LpmTrie<[u8; 8], u8> =
    LpmTrie::with_max_entries(MAX_GLOBAL_ALLOW_ENTRIES, BPF_F_NO_PREALLOC);
#[map]
pub(crate) static STYX_ALLOW_GLOBAL_V6: LpmTrie<[u8; 20], u8> =
    LpmTrie::with_max_entries(MAX_GLOBAL_ALLOW_ENTRIES, BPF_F_NO_PREALLOC);
#[map]
pub(crate) static STYX_BLOCK_V4: LpmTrie<[u8; 4], u8> =
    LpmTrie::with_max_entries(MAX_STYX_BLOCK_ENTRIES, BPF_F_NO_PREALLOC);
#[map]
pub(crate) static STYX_BLOCK_V6: LpmTrie<[u8; 16], u8> =
    LpmTrie::with_max_entries(MAX_STYX_BLOCK_ENTRIES, BPF_F_NO_PREALLOC);
#[map]
pub(crate) static STYX_RESOLVER_V4: LpmTrie<[u8; 4], u8> =
    LpmTrie::with_max_entries(MAX_STYX_RESOLVER_ENTRIES, BPF_F_NO_PREALLOC);
#[map]
pub(crate) static STYX_RESOLVER_V6: LpmTrie<[u8; 16], u8> =
    LpmTrie::with_max_entries(MAX_STYX_RESOLVER_ENTRIES, BPF_F_NO_PREALLOC);
#[map]
pub(crate) static STYX_GLOBAL: Array<u64> = Array::with_max_entries(1, 0);
#[map]
pub(crate) static STYX_RESOLVED: LruHashMap<u64, [u8; 16]> =
    LruHashMap::with_max_entries(MAX_STYX_RESOLVED_ENTRIES, 0);
#[map]
pub(crate) static FLOW_AGG_V4: LruPerCpuHashMap<[u8; 16], [u8; 40]> =
    LruPerCpuHashMap::with_max_entries(MAX_FLOW_AGG_ENTRIES, 0);
#[map]
pub(crate) static FLOW_AGG_V6: LruPerCpuHashMap<[u8; 32], [u8; 40]> =
    LruPerCpuHashMap::with_max_entries(MAX_FLOW_AGG_ENTRIES, 0);
#[map]
pub(crate) static FLOW_EVENTS: RingBuf = RingBuf::with_byte_size(MAX_STYX_FLOW_EVENT_BYTES, 0);
#[map]
pub(crate) static FLOW_EVENTS_EMITTED: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);
#[map]
pub(crate) static FLOW_RING_DROPS: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);
#[map]
pub(crate) static FLOW_AGG_INSERT_FAILURES: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);
#[map]
pub(crate) static EGRESS_PARSE_ERRORS: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);
#[map]
pub(crate) static EGRESS_DROPS_TOTAL: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);
#[map]
pub(crate) static EGRESS_POLICY_DROPS: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);

// Point 1 Titan exec-gate maps (ABI-2, §4). The core `take_map`s every one of
// them by name at startup and refuses to run silently if one is missing.
#[map]
pub(crate) static TITAN_EXEC_STATE: Array<u64> = Array::with_max_entries(1, 0);
#[map]
pub(crate) static TITAN_EXEC_OFFSETS: Array<u32> = Array::with_max_entries(TITAN_EXEC_OFFSETS_ENTRIES, 0);
#[map]
pub(crate) static TITAN_EXEC_MODE: HashMap<u64, u8> =
    HashMap::with_max_entries(MAX_TITAN_EXEC_SCOPES, BPF_F_NO_PREALLOC);
#[map]
pub(crate) static TITAN_EXEC_POLICY: HashMap<[u8; 16], [u8; 16]> =
    HashMap::with_max_entries(MAX_TITAN_EXEC_POLICIES, BPF_F_NO_PREALLOC);
#[map]
pub(crate) static TITAN_EXEC_EVENTS: RingBuf = RingBuf::with_byte_size(TITAN_EXEC_EVENT_RING_BYTES, 0);
#[map]
pub(crate) static TITAN_EXEC_EVENTS_EMITTED: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);
#[map]
pub(crate) static TITAN_EXEC_RING_DROPS: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);
#[map]
pub(crate) static TITAN_EXEC_READ_FAILURES: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);
#[map]
pub(crate) static TITAN_EXEC_POLICY_DENIES: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);
#[map]
pub(crate) static TITAN_EXEC_POLICY_AUDITS: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);
#[map]
pub(crate) static TITAN_EXEC_CTIME_REJECTS: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);

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

/// §3 state word: epoch 0..31, mode 32..39, flags 40..47, ABI 48..55, magic
/// 56..63. Default 0 (kernel map zero-init) = not a valid word = OFF.
#[map]
pub(crate) static LOCKDOWN_STATE: Array<u64> = Array::with_max_entries(1, 0);
/// Packets dropped by the lockdown fastpath, per CPU (§4/§5 health).
#[map]
pub(crate) static LOCKDOWN_DROPS: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);
/// Lockdown packets that passed through the `ALLOW_LOOPBACK` exception (§4).
#[map]
pub(crate) static LOCKDOWN_WITNESS_PASSES: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);

/// Wire size guard: the ring record is emitted as the shared `FlowEvent` struct.
const _: () = assert!(mem::size_of::<FlowEvent>() == STYX_FLOW_EVENT_WIRE_BYTES);

// The ring record is exactly the §3.2 wire record shared with the core decoder;
// a layout drift would make the core drain counter climb without an event.
const _: () = assert!(mem::size_of::<TitanExecEvent>() == TITAN_EXEC_EVENT_WIRE_BYTES);
const _: () = assert!(mem::align_of::<TitanExecEvent>() <= 8);
