//! V6.3.0 AP-3 — 8-domain cross-view verifier (`CROSS_VIEW_*`).
//!
//! The verifier compares independent kernel/userland views of the same state
//! and reports contradictions (never a block):
//!
//! 1. **eBPF id gap** (`CROSS_VIEW_DOMAIN_EBPF_ID_GAP`): `BPF_PROG/MAP/LINK_
//!    GET_NEXT_ID` (what `bpftool prog list` sees) against sequential
//!    `*_GET_FD_BY_ID` probing, plus link→program references → `HIDDEN_PROG` /
//!    `HIDDEN_MAP` / `HIDDEN_LINK` / `LINK_TAMPER`.
//! 2. **Socket view** (`..._SOCKET_VIEW`): direct `NETLINK_SOCK_DIAG` (inet
//!    `inet_diag_req_v2`, `packet_diag_req` with `PACKET_SHOW_FILTER`) against
//!    `/proc/net/{tcp,tcp6,udp,udp6,packet}` and the eBPF tap ring → `HIDDEN_
//!    SOCKET` / `PORTLESS_RAW_TAP`.
//! 3. **Process view** (`..._PROCESS_VIEW`): `/proc` directory listing against
//!    `open("/proc/<pid>/stat")` and the tap-evidence pid memory → `HIDDEN_
//!    PROCESS`.
//! 4. **Module/trace view** (`..._MODULE_TRACE_VIEW`): `/proc/modules` against
//!    `/sys/module/*` (only entries with `coresize` are loadable modules) plus
//!    `/proc/sys/kernel/tainted` and `/sys/kernel/tracing/enabled_functions` →
//!    `LKM_HIDDEN` / `FTRACE_HOOK`.
//! 5. **Library view** (`..._LIBRARY_VIEW`): `/proc/<pid>/maps` of security-
//!    relevant processes against Debian (`/var/lib/dpkg/info/*.list`) or Arch
//!    (`/var/lib/pacman/local/*/files`) package ownership → `LIBRARY_MISMATCH`;
//!    every other package DB is reported `pkgdb=unsupported`, never guessed.
//! 6. **Pin view** (`..._PIN_VIEW`): the self-defence bpffs pin root against a
//!    load-time baseline and live `BPF_OBJ_GET` resolution → `PIN_MISMATCH`.
//! 7. **Netlink filter view** (`..._NETLINK_FILTER`): the kernel tap records
//!    (AF_PACKET creation / filter attach / classic cBPF) → `RAW_TAP_FILTER`,
//!    escalated by the core to `PORTLESS_RAW_TAP` when `/proc/<pid>/exe`
//!    resolves into a writable/deleted location.
//! 8. **Map-name view** (`..._MAP_NAME_VIEW`): visible BPF object names matching
//!    hide/masquerade markers → `HIDDEN_MAP`/`HIDDEN_PROG` name evidence.
//!
//! Everything is bounded: the scan cadence is [`CROSS_VIEW_SCAN_INTERVAL_MS`]
//! with an event-triggered early scan, one scan has a
//! [`CROSS_VIEW_SCAN_BUDGET_MS`] wall-clock budget (below the 1500 ms core IPC
//! deadline), every list/map/queue has a documented cap, and the contradiction
//! queue is a bounded `VecDeque`. No production path unwraps or panics; kernel
//! refusals (EPERM/EINVAL) degrade the matching domain honestly.
//!
//! The verifier is observe-only: every record is evidence, no record feeds the
//! kill gate and nothing here denies or kills.

mod attach;
mod scan;
mod procfs;
mod modtrace;
mod libraries;
mod bpf_ids;
mod netlink;
mod sockets;
mod wire;

use self::scan::*;
use self::procfs::*;
use self::libraries::*;
use self::bpf_ids::*;
use self::netlink::*;
use self::sockets::*;
use self::wire::*;
use aya::{
    maps::{Array as AyaArray, MapData, PerCpuArray, RingBuf},
    programs::{KProbe, Lsm},
    Btf, Ebpf,
};
use gedefense_common::{
    cross_view_state_word, decode_cross_view_event, CrossViewEvent,
    CROSS_VIEW_ACTION_AUDIT, CROSS_VIEW_ACTION_OBSERVE, CROSS_VIEW_DETAIL_ID_GAP,
    CROSS_VIEW_DETAIL_LIB_DELETED, CROSS_VIEW_DETAIL_LIB_FOREIGN, CROSS_VIEW_DETAIL_LISTING_MISS,
    CROSS_VIEW_DETAIL_NAME_HEURISTIC, CROSS_VIEW_DETAIL_NETLINK_ONLY,
    CROSS_VIEW_DETAIL_PIN_DANGLING, CROSS_VIEW_DETAIL_PIN_MISSING,
    CROSS_VIEW_DETAIL_PIN_REPLACED, CROSS_VIEW_DETAIL_PIN_UNEXPECTED,
    CROSS_VIEW_DETAIL_PROC_ONLY, CROSS_VIEW_DETAIL_STAT_FAILED, CROSS_VIEW_DETAIL_SYSFS_ONLY,
    CROSS_VIEW_DETAIL_TAP_FILTER, CROSS_VIEW_DETAIL_TAP_SUSPICIOUS_PATH,
    CROSS_VIEW_DOMAIN_EBPF_ID_GAP, CROSS_VIEW_DOMAIN_LIBRARY_VIEW,
    CROSS_VIEW_DOMAIN_MAP_NAME_VIEW, CROSS_VIEW_DOMAIN_MODULE_TRACE_VIEW,
    CROSS_VIEW_DOMAIN_NETLINK_FILTER, CROSS_VIEW_DOMAIN_PIN_VIEW,
    CROSS_VIEW_DOMAIN_PROCESS_VIEW, CROSS_VIEW_DOMAIN_SOCKET_VIEW,
    CROSS_VIEW_EVENT_SCAN_MIN_GAP_MS, CROSS_VIEW_EVIDENCE_TTL_MS,
    CROSS_VIEW_FNV64_OFFSET, CROSS_VIEW_FNV64_PRIME, CROSS_VIEW_KIND_FTRACE_HOOK,
    CROSS_VIEW_KIND_HIDDEN_LINK, CROSS_VIEW_KIND_HIDDEN_MAP, CROSS_VIEW_KIND_HIDDEN_PROCESS,
    CROSS_VIEW_KIND_HIDDEN_PROG, CROSS_VIEW_KIND_HIDDEN_SOCKET, CROSS_VIEW_KIND_LIBRARY_MISMATCH,
    CROSS_VIEW_KIND_LINK_TAMPER, CROSS_VIEW_KIND_LKM_HIDDEN, CROSS_VIEW_KIND_PIN_MISMATCH,
    CROSS_VIEW_KIND_PORTLESS_RAW_TAP, CROSS_VIEW_KIND_RAW_TAP_FILTER,
    CROSS_VIEW_MAX_BPF_OBJECTS, CROSS_VIEW_MAX_BPF_PROBES, CROSS_VIEW_MAX_DRAIN_PAYLOAD_BYTES,
    CROSS_VIEW_MAX_EVENTS_PER_DRAIN, CROSS_VIEW_MAX_EVIDENCE_PIDS, CROSS_VIEW_MAX_PIDS,
    CROSS_VIEW_MAX_PINS, CROSS_VIEW_MAX_PKGDB_ENTRIES, CROSS_VIEW_MAX_PKGDB_FILES,
    CROSS_VIEW_MAX_QUEUED_EVENTS, CROSS_VIEW_MAX_REPORT_BYTES, CROSS_VIEW_PKGDB_ARCH,
    CROSS_VIEW_PKGDB_DEBIAN, CROSS_VIEW_PKGDB_DEGRADED, CROSS_VIEW_PKGDB_UNSUPPORTED,
    CROSS_VIEW_REPORT_BOUNDS_DEGRADED, CROSS_VIEW_REPORT_BOUNDS_OK, CROSS_VIEW_SCAN_BUDGET_MS,
    CROSS_VIEW_SCAN_INTERVAL_MS, CROSS_VIEW_SEVERITY_CRITICAL, CROSS_VIEW_SEVERITY_HIGH,
    CROSS_VIEW_SEVERITY_MEDIUM, CROSS_VIEW_STATE_KPROBE_BIT,
    CROSS_VIEW_STATE_LSM_CREATE_BIT, CROSS_VIEW_STATE_LSM_SETSOCKOPT_BIT,
};
use std::{
    collections::{HashMap, HashSet, VecDeque},
    error::Error,
    ffi::CString,
    fmt::Write as _,
    fs,
    io::Read as _,
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
    os::unix::fs::MetadataExt as _,
    path::Path,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

type BoxError = Box<dyn Error + Send + Sync + 'static>;

// ---------------------------------------------------------------- kernel maps

/// Index of the single state word in `CROSS_VIEW_STATE`.
const CROSS_VIEW_STATE_INDEX: u32 = 0;
/// `CROSS_VIEW_COUNTERS` lane indices (ABI with the eBPF object): index 0 is
/// the per-CPU emitted counter, index 1 the ring-drop counter.
const COUNTER_DROPS: u32 = 1;
/// Ring drain cap per poll (the scheduler tick also drains, so this stays short).
const RING_DRAIN_PER_POLL: usize = 64;
/// eBPF program/hook names (ABI with `rust/gedefense-ebpf/src/iter.rs`).
const LSM_CREATE_PROGRAM: &str = "gedefense_crossview_socket_create";
const LSM_CREATE_HOOK: &str = "socket_create";
const LSM_SETSOCKOPT_PROGRAM: &str = "gedefense_crossview_socket_setsockopt";
const LSM_SETSOCKOPT_HOOK: &str = "socket_setsockopt";
const SK_ATTACH_FILTER_PROGRAM: &str = "gedefense_crossview_sk_attach_filter";
const SK_ATTACH_FILTER_SYMBOL: &str = "sk_attach_filter";
/// Default self-defence bpffs pin root (mirrors `main.rs`).
const DEFAULT_BPF_PIN_ROOT: &str = "/sys/fs/bpf/gedefense";

// ------------------------------------------------------ UAPI bpf() command ids

// `enum bpf_cmd`, verified against `include/uapi/linux/bpf.h` and the vendored
// aya 0.14 bindings (BPF_PROG_GET_NEXT_ID=11, BPF_MAP_GET_NEXT_ID=12,
// BPF_PROG_GET_FD_BY_ID=13, BPF_MAP_GET_FD_BY_ID=14, BPF_OBJ_GET_INFO_BY_FD=15,
// BPF_OBJ_GET=7, BPF_LINK_GET_FD_BY_ID=30, BPF_LINK_GET_NEXT_ID=31).
const BPF_CMD_OBJ_GET: u32 = 7;
const BPF_CMD_PROG_GET_NEXT_ID: u32 = 11;
const BPF_CMD_MAP_GET_NEXT_ID: u32 = 12;
const BPF_CMD_PROG_GET_FD_BY_ID: u32 = 13;
const BPF_CMD_MAP_GET_FD_BY_ID: u32 = 14;
const BPF_CMD_OBJ_GET_INFO_BY_FD: u32 = 15;
const BPF_CMD_LINK_GET_FD_BY_ID: u32 = 30;
const BPF_CMD_LINK_GET_NEXT_ID: u32 = 31;

/// `union bpf_attr` is 128 bytes in every kernel since 4.13; passing the full
/// union keeps every `CHECK_ATTR` tail-zero rule satisfied.
const BPF_ATTR_BYTES: usize = 128;
/// `union bpf_attr` field offsets used here (all stable UAPI).
const ATTR_OBJ_ID_OFF: usize = 0; // __u32 id / start_id
const ATTR_NEXT_ID_OFF: usize = 4; // __u32 next_id (out)
const ATTR_INFO_FD_OFF: usize = 0;
const ATTR_INFO_LEN_OFF: usize = 4;
const ATTR_INFO_PTR_OFF: usize = 8;
const ATTR_PATHNAME_OFF: usize = 0; // __aligned_u64
/// Bounded info buffer handed to `BPF_OBJ_GET_INFO_BY_FD` (zero-tail safe).
const INFO_BUF_BYTES: usize = 256;
/// `struct bpf_prog_info.name` offset 64; `struct bpf_map_info.name` offset 24
/// (both append-only UAPI layouts, verified against linux/bpf.h).
const PROG_INFO_NAME_OFF: usize = 64;
const MAP_INFO_NAME_OFF: usize = 24;
const BPF_OBJ_NAME_BYTES: usize = 16;

// --------------------------------------------------------- netlink sock_diag

const NETLINK_SOCK_DIAG: i32 = 4;
const SOCK_DIAG_BY_FAMILY: u16 = 20;
const NLM_F_REQUEST: u16 = 1;
const NLM_F_DUMP: u16 = 0x300;
const NLMSG_ERROR: u16 = 2;
const NLMSG_DONE: u16 = 3;
const NLMSG_HDRLEN: usize = 16;
const NETLINK_REQ_SEQ: u32 = 0x4356_0001;
/// Bounded dump: at most 4 MiB / 32768 messages per request.
const NETLINK_MAX_BYTES: usize = 4 * 1024 * 1024;
const NETLINK_MAX_MESSAGES: usize = 32_768;
const NETLINK_RECV_BUF: usize = 64 * 1024;
const NETLINK_RCV_TIMEOUT_US: i64 = 300_000;
const INET_DIAG_REQ_V2_BYTES: usize = 56;
const INET_DIAG_MSG_BYTES: usize = 72;
const INET_DIAG_MSG_INODE_OFF: usize = 68;
const INET_DIAG_MSG_UID_OFF: usize = 64;
const PACKET_DIAG_REQ_BYTES: usize = 20;
const PACKET_DIAG_MSG_BYTES: usize = 16;
const PACKET_DIAG_MSG_INODE_OFF: usize = 4;
const PACKET_DIAG_UID: u16 = 5;
const PACKET_DIAG_FILTER: u16 = 7;
const PACKET_SHOW_INFO: u32 = 0x1;
const PACKET_SHOW_FILTER: u32 = 0x20;
const AF_INET_U8: u8 = 2;
const AF_INET6_U8: u8 = 10;
const AF_PACKET_U8: u8 = 17;
const IPPROTO_TCP_U8: u8 = 6;
const IPPROTO_UDP_U8: u8 = 17;
/// Core-side cross-view engine.
pub(crate) struct CrossViewCore {
    // mandatory kernel objects
    events: RingBuf<MapData>,
    state: AyaArray<MapData, u64>,
    counters: PerCpuArray<MapData, u64>,
    epoch: u64,
    enabled: bool,
    lsm_create_attached: bool,
    lsm_setsockopt_attached: bool,
    kprobe_attached: bool,
    // cadence/accounting
    scans: u64,
    contradictions: u64,
    events_total: u64,
    queue: VecDeque<CrossViewEvent>,
    queue_drops: u64,
    rejected: u64,
    last_ring_drops: u64,
    last_queue_drops: u64,
    last_rejected: u64,
    last_scan_ms: u64,
    last_bounds_ok: bool,
    last_domains: u8,
    last_reasons: Vec<&'static str>,
    // per-domain capability from the last scan
    bpf_available: bool,
    socket_available: bool,
    proc_available: bool,
    module_available: bool,
    trace_available: bool,
    pkgdb: PkgDbState,
    pins_available: bool,
    pins_count: u64,
    // bounded memories
    evidence_pids: HashMap<u32, u64>,
    known_pids: HashMap<u32, u64>,
    tap_dedupe: HashMap<(u32, u32), u64>,
    // self-defence pin cross-check
    pin_root: String,
    pin_baseline: Vec<String>,
}

/// Package-DB ownership index for the library view. Only `.so` paths are
/// indexed (a few thousand entries instead of the full file list), and a
/// truncated/incomplete build is marked incomplete so a missing entry is never
/// reported as a foreign library.
enum PkgDbState {
    Unbuilt,
    Indexed {
        token: &'static str,
        complete: bool,
        libraries: HashSet<u64>,
    },
    Unsupported,
}


impl CrossViewCore {
    /// `CROSS_VIEW_REPORT`: force one scan and return the compact bounded report.
    pub(crate) fn report(&mut self) -> Result<String, BoxError> {
        let now_ms = unix_millis();
        if self.enabled {
            self.run_scan(now_ms);
        }
        let age_ms = if self.last_scan_ms == 0 {
            0
        } else {
            now_ms.saturating_sub(self.last_scan_ms)
        };
        let mut out = String::with_capacity(512);
        out.push_str(if self.last_bounds_ok {
            CROSS_VIEW_REPORT_BOUNDS_OK
        } else {
            CROSS_VIEW_REPORT_BOUNDS_DEGRADED
        });
        let _ = write!(
            out,
            ":domains={}:contradictions={}:events={}:scans={}:drops={}:age_ms={}:tap={}:mods={}:procs={}:bpf={}:pkgdb={}:trace={}:pins={}",
            self.last_domains,
            self.contradictions,
            self.events_total,
            self.scans,
            self.total_drops(),
            age_ms,
            u8::from(self.lsm_create_attached || self.lsm_setsockopt_attached || self.kprobe_attached),
            u8::from(self.module_available),
            u8::from(self.proc_available),
            u8::from(self.bpf_available),
            self.pkgdb_token(),
            u8::from(self.trace_available),
            self.pins_count,
        );
        if !self.last_reasons.is_empty() {
            out.push_str(":reason=");
            out.push_str(&self.last_reasons.join(","));
        }
        if out.len() > CROSS_VIEW_MAX_REPORT_BYTES {
            out.truncate(CROSS_VIEW_MAX_REPORT_BYTES);
        }
        Ok(out)
    }

    /// `CROSS_VIEW_EVENTS`: `<dropped>|<record>[,<record>…]` or `empty`, with the
    /// documented record text:
    /// `<ts>:<pid>:<uid>:<dev>:<ino>:<domain>:<kind>:<severity>:<detail_code>:<comm_hex>`.
    pub(crate) fn take_events(&mut self) -> Result<String, BoxError> {
        let mut records: Vec<String> = Vec::with_capacity(CROSS_VIEW_MAX_EVENTS_PER_DRAIN);
        let mut payload = 0usize;
        while records.len() < CROSS_VIEW_MAX_EVENTS_PER_DRAIN {
            let Some(event) = self.queue.pop_front() else {
                break;
            };
            let record = encode_event_text(&event);
            let separator = usize::from(!records.is_empty());
            if payload
                .saturating_add(separator)
                .saturating_add(record.len())
                .saturating_add(24)
                > CROSS_VIEW_MAX_DRAIN_PAYLOAD_BYTES
            {
                // Defensive: a 64-byte record batch is far below the budget; this
                // only guards a future record-width change.
                self.queue.push_front(event);
                break;
            }
            payload = payload.saturating_add(separator).saturating_add(record.len());
            records.push(record);
        }

        let ring_drops = self.counter_sum(COUNTER_DROPS);
        let ring_delta = ring_drops.saturating_sub(self.last_ring_drops);
        self.last_ring_drops = ring_drops;
        let queue_delta = self.queue_drops.saturating_sub(self.last_queue_drops);
        self.last_queue_drops = self.queue_drops;
        let rejected_delta = self.rejected.saturating_sub(self.last_rejected);
        self.last_rejected = self.rejected;
        let dropped = ring_delta
            .saturating_add(queue_delta)
            .saturating_add(rejected_delta);
        if records.is_empty() {
            if dropped == 0 {
                return Ok("empty".to_owned());
            }
            return Ok(format!("{dropped}|"));
        }
        Ok(format!("{dropped}|{}", records.join(",")))
    }

}





/// One program/map/link class enumeration result.
#[derive(Default)]
struct ClassScan {
    visible: Vec<u32>,
    gaps: Vec<u32>,
    name_hits: Vec<(u32, u8, u8)>,
    truncated: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ViewError {
    Denied,
    Unsupported,
    Failed,
}





#[cfg(test)]
mod tests;
