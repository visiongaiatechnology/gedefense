//! V6.3.0 AP-3 — cross-view verifier wire contract (`CROSS_VIEW_EVENTS`).
//!
//! The kernel half (`rust/gedefense-ebpf/src/iter.rs`) observes the raw-socket
//! tap surface (BPFDoor/VoidLink class): AF_PACKET socket creation and
//! `SO_ATTACH_FILTER`/`SO_ATTACH_BPF` filter attachment, plus a best-effort
//! `sk_attach_filter` kprobe for the classic-cBPF path. Every tap observation is
//! one fixed-size [`CrossViewEvent`] in the `CROSS_VIEW_EVENTS` ring.
//!
//! The privileged core (`rust/gedefense-core/src/cross_view.rs`) compares eight
//! independent kernel/userland views of the same state and writes contradiction
//! records into the same wire shape (with identities resolved by the core). It
//! is a pure userland verifier: no hook ever denies and no contradiction alone
//! can authorise a kill.
//!
//! # Wire layout (64 bytes, native endian, `#[repr(C)]`, no implicit padding)
//!
//! ```text
//! offset  size  field
//!      0     8  ts_ns: u64            CLOCK_MONOTONIC ns (`bpf_ktime_get_ns`)
//!      8     8  ino: u64              object inode / stable identity hash
//!                                    (0 = none). Kernel tap records carry the
//!                                    emitting process tgid here as a fallback
//!                                    attribution identity because the hook runs
//!                                    in a thread that may already be gone when
//!                                    the core drains the ring.
//!     16     4  pid: u32              acting task id (0 = unresolved kernel object)
//!     20     4  uid: u32
//!     24     4  dev: u32              `st_dev`/object dev (0 = none)
//!     28     4  detail_code: u32      kind-specific bounded code (see below)
//!     32     1  domain: u8            1..=8 (CROSS_VIEW_DOMAIN_*)
//!     33     1  kind: u8              1..=12 (CROSS_VIEW_KIND_*)
//!     34     1  severity: u8          1=INFO 2=MEDIUM 3=HIGH 4=CRITICAL
//!     35     1  action: u8            1=AUDIT 2=OBSERVE (both observe-only)
//!     36    16  comm: [u8;16]         NUL-padded printable task name/label
//!     52    12  reserved: [u8;12]     must be zero
//!     64
//! ```
//!
//! The layout follows the AP-3 enumeration exactly: every byte is a named field
//! or the checked reserved tail, so a stored record can never leak uninitialised
//! stack bytes and the decoder is byte-exact across the eBPF/core/Go boundary.
//!
//! The decoder rejects rather than repairs: any record the kernel/core producer
//! cannot have emitted (length, unknown/closed field values, a kind that does not
//! belong to its domain, zero timestamp, non-NUL-padded or non-printable `comm`,
//! non-zero reserved bytes) decodes to `None`.

// ---------------------------------------------------------------- size bounds

/// Wire size of one [`CrossViewEvent`].
pub const CROSS_VIEW_EVENT_WIRE_BYTES: usize = 64;
/// `CROSS_VIEW_EVENTS` ring size (64 KiB = 1024 queued 64-byte records).
pub const CROSS_VIEW_EVENT_RING_BYTES: u32 = 64 * 1024;
/// Maximum records the core returns per `CROSS_VIEW_EVENTS` drain.
pub const CROSS_VIEW_MAX_EVENTS_PER_DRAIN: usize = 16;
/// Maximum text payload bytes the core returns per drain.
pub const CROSS_VIEW_MAX_DRAIN_PAYLOAD_BYTES: usize = 4096;
/// Maximum text bytes of one `CROSS_VIEW_REPORT` answer.
pub const CROSS_VIEW_MAX_REPORT_BYTES: usize = 2048;
/// Maximum text bytes of one `CROSS_VIEW_STATUS` answer.
pub const CROSS_VIEW_MAX_STATUS_BYTES: usize = 512;
/// Internal bounded contradiction queue owned by the core.
pub const CROSS_VIEW_MAX_QUEUED_EVENTS: usize = 256;
/// Objects enumerated per BPF id class (`GET_NEXT_ID` list cap).
pub const CROSS_VIEW_MAX_BPF_OBJECTS: usize = 4096;
/// Sequential `GET_FD_BY_ID` probe budget shared by progs/maps/links.
pub const CROSS_VIEW_MAX_BPF_PROBES: u64 = 1 << 18;
/// Scan cadence when no tap event arrives.
pub const CROSS_VIEW_SCAN_INTERVAL_MS: u64 = 20_000;
/// Minimum distance between two event-triggered scans.
pub const CROSS_VIEW_EVENT_SCAN_MIN_GAP_MS: u64 = 2_000;
/// Wall-clock budget of one scan (kept below the 1500 ms core IPC deadline).
pub const CROSS_VIEW_SCAN_BUDGET_MS: u64 = 900;
/// Process-view pid memory cap.
pub const CROSS_VIEW_MAX_PIDS: usize = 8192;
/// Tap-evidence pid memory cap.
pub const CROSS_VIEW_MAX_EVIDENCE_PIDS: usize = 512;
/// How long a tap-observed pid stays "kernel evidence" for the process view.
pub const CROSS_VIEW_EVIDENCE_TTL_MS: u64 = 120_000;
/// Pin cross-view baseline cap.
pub const CROSS_VIEW_MAX_PINS: usize = 4096;
/// Package-DB index caps (library view).
pub const CROSS_VIEW_MAX_PKGDB_FILES: usize = 20_000;
pub const CROSS_VIEW_MAX_PKGDB_ENTRIES: usize = 200_000;
/// FNV-1a offset basis (documented identity hash for bounded evidence keys).
pub const CROSS_VIEW_FNV64_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
/// FNV-1a prime.
pub const CROSS_VIEW_FNV64_PRIME: u64 = 0x0000_0100_0000_01b3;

mod helpers;

pub use self::helpers::*;

// ------------------------------------------------------------------ domains

/// eBPF ID-gap domain: `*_GET_NEXT_ID` vs sequential `*_GET_FD_BY_ID`.
pub const CROSS_VIEW_DOMAIN_EBPF_ID_GAP: u8 = 1;
/// Socket domain: direct `NETLINK_SOCK_DIAG` vs `/proc/net/*` vs tap evidence.
pub const CROSS_VIEW_DOMAIN_SOCKET_VIEW: u8 = 2;
/// Process domain: `/proc` directory listing vs `stat`/pid evidence.
pub const CROSS_VIEW_DOMAIN_PROCESS_VIEW: u8 = 3;
/// Module/trace domain: `/proc/modules` vs `/sys/module` vs taint/ftrace.
pub const CROSS_VIEW_DOMAIN_MODULE_TRACE_VIEW: u8 = 4;
/// Library domain: `/proc/<pid>/maps` vs package-DB ownership.
pub const CROSS_VIEW_DOMAIN_LIBRARY_VIEW: u8 = 5;
/// Pin domain: `/sys/fs/bpf` pin existence vs the self-defence pin root.
pub const CROSS_VIEW_DOMAIN_PIN_VIEW: u8 = 6;
/// Netlink filter domain: packet-diag filter view and kernel tap records.
pub const CROSS_VIEW_DOMAIN_NETLINK_FILTER: u8 = 7;
/// Map-name domain: visible BPF object names matching hide/masquerade markers.
pub const CROSS_VIEW_DOMAIN_MAP_NAME_VIEW: u8 = 8;
/// Number of cross-view domains the verifier implements.
pub const CROSS_VIEW_DOMAIN_COUNT: u8 = 8;

// -------------------------------------------------------------------- kinds

/// A BPF program id reachable by fd-by-id but absent from `GET_NEXT_ID`.
pub const CROSS_VIEW_KIND_HIDDEN_PROG: u8 = 1;
/// A BPF map id reachable by fd-by-id but absent from `GET_NEXT_ID`.
pub const CROSS_VIEW_KIND_HIDDEN_MAP: u8 = 2;
/// A BPF link id reachable by fd-by-id but absent from `GET_NEXT_ID`.
pub const CROSS_VIEW_KIND_HIDDEN_LINK: u8 = 3;
/// A visible link whose `prog_id` is not in the visible program id set.
pub const CROSS_VIEW_KIND_LINK_TAMPER: u8 = 4;
/// A socket visible through netlink but not through `/proc/net/*`.
pub const CROSS_VIEW_KIND_HIDDEN_SOCKET: u8 = 5;
/// A filtered packet tap owned by a suspicious executable (BPFDoor class).
pub const CROSS_VIEW_KIND_PORTLESS_RAW_TAP: u8 = 6;
/// A process visible through kernel evidence but missing from `/proc`.
pub const CROSS_VIEW_KIND_HIDDEN_PROCESS: u8 = 7;
/// A loaded module hidden from one of the two module views.
pub const CROSS_VIEW_KIND_LKM_HIDDEN: u8 = 8;
/// An ftrace hook enabled on a rootkit-relevant hiding/kernel function.
pub const CROSS_VIEW_KIND_FTRACE_HOOK: u8 = 9;
/// A security-relevant process maps an unowned foreign shared library.
pub const CROSS_VIEW_KIND_LIBRARY_MISMATCH: u8 = 10;
/// A self-defence bpffs pin is missing, dangling or replaced.
pub const CROSS_VIEW_KIND_PIN_MISMATCH: u8 = 11;
/// A raw (`AF_PACKET`) tap socket/filter created, observed by the kernel hook.
pub const CROSS_VIEW_KIND_RAW_TAP_FILTER: u8 = 12;

/// One fixed-size cross-view record (see the module-level wire layout).
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CrossViewEvent {
    pub ts_ns: u64,
    pub ino: u64,
    pub pid: u32,
    pub uid: u32,
    pub dev: u32,
    pub detail_code: u32,
    pub domain: u8,
    pub kind: u8,
    pub severity: u8,
    pub action: u8,
    pub comm: [u8; 16],
    pub reserved: [u8; 12],
}

// Compile-time coupling to the wire contract: a layout drift must fail the eBPF
// and core builds, not silently corrupt a ring record.
const _: () = assert!(core::mem::size_of::<CrossViewEvent>() == CROSS_VIEW_EVENT_WIRE_BYTES);
const _: () = assert!(core::mem::align_of::<CrossViewEvent>() == 8);

/// Decodes one fixed-size cross-view record; `None` for every record the
/// producers cannot have emitted.
pub fn decode_cross_view_event(bytes: &[u8]) -> Option<CrossViewEvent> {
    if bytes.len() != CROSS_VIEW_EVENT_WIRE_BYTES {
        return None;
    }
    let ts_ns = u64::from_ne_bytes(bytes[0..8].try_into().ok()?);
    let ino = u64::from_ne_bytes(bytes[8..16].try_into().ok()?);
    let pid = u32::from_ne_bytes(bytes[16..20].try_into().ok()?);
    let uid = u32::from_ne_bytes(bytes[20..24].try_into().ok()?);
    let dev = u32::from_ne_bytes(bytes[24..28].try_into().ok()?);
    let detail_code = u32::from_ne_bytes(bytes[28..32].try_into().ok()?);
    let domain = bytes[32];
    let kind = bytes[33];
    let severity = bytes[34];
    let action = bytes[35];
    let comm: [u8; 16] = bytes[36..52].try_into().ok()?;
    let reserved: [u8; 12] = bytes[52..64].try_into().ok()?;

    if ts_ns == 0
        || !cross_view_kind_domain_valid(domain, kind)
        || !matches!(
            severity,
            CROSS_VIEW_SEVERITY_INFO
                | CROSS_VIEW_SEVERITY_MEDIUM
                | CROSS_VIEW_SEVERITY_HIGH
                | CROSS_VIEW_SEVERITY_CRITICAL
        )
        || !matches!(action, CROSS_VIEW_ACTION_AUDIT | CROSS_VIEW_ACTION_OBSERVE)
        || reserved != [0u8; 12]
        || !comm_is_nul_padded(&comm)
    {
        return None;
    }

    Some(CrossViewEvent {
        ts_ns,
        ino,
        pid,
        uid,
        dev,
        detail_code,
        domain,
        kind,
        severity,
        action,
        comm,
        reserved,
    })
}

/// The producer contract for `comm`: at least one NUL, every byte before it
/// printable ASCII. A kernel task name is attacker-controlled
/// (`prctl(PR_SET_NAME)`), so a record that would smuggle control bytes into an
/// operator/terminal surface is rejected instead of escaped downstream.
fn comm_is_nul_padded(comm: &[u8; 16]) -> bool {
    let mut have_payload = false;
    let mut padding = false;
    for &byte in comm.iter() {
        if padding {
            if byte != 0 {
                return false;
            }
            continue;
        }
        if byte == 0 {
            padding = true;
        } else if (0x20..=0x7e).contains(&byte) {
            have_payload = true;
        } else {
            return false;
        }
    }
    have_payload && padding
}

#[cfg(test)]
mod tests;
