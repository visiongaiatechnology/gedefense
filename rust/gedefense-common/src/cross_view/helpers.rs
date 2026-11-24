//! Severity/action/detail/token constants, the `CROSS_VIEW_STATE` word ABI
//! and the closed domain/kind cross product of the AP-3 contract.

use super::*;

// --------------------------------------------------------------- severities

/// Informational record; never an incident on its own.
pub const CROSS_VIEW_SEVERITY_INFO: u8 = 1;
/// Observation worth operator attention, no incident on its own.
pub const CROSS_VIEW_SEVERITY_MEDIUM: u8 = 2;
/// Contradiction that maps onto a high-severity XDR rule.
pub const CROSS_VIEW_SEVERITY_HIGH: u8 = 3;
/// Contradiction that maps onto a critical-severity XDR rule.
pub const CROSS_VIEW_SEVERITY_CRITICAL: u8 = 4;

// ------------------------------------------------------------------ actions

/// Audit record: the fact is reported, nothing is blocked.
pub const CROSS_VIEW_ACTION_AUDIT: u8 = 1;
/// Passive observation (e.g. a suspicious-name heuristic): no enforcement.
pub const CROSS_VIEW_ACTION_OBSERVE: u8 = 2;

// -------------------------------------------------------------- detail codes

/// eBPF id gap: object reachable by id but hidden from the id iterator.
pub const CROSS_VIEW_DETAIL_ID_GAP: u32 = 1;
/// Visible object name matches a hide/masquerade marker (heuristic, not a gap).
pub const CROSS_VIEW_DETAIL_NAME_HEURISTIC: u32 = 2;
/// Socket: visible through netlink but absent from the procfs view.
pub const CROSS_VIEW_DETAIL_NETLINK_ONLY: u32 = 1;
/// Socket: visible through procfs but absent from the netlink view.
pub const CROSS_VIEW_DETAIL_PROCFS_ONLY: u32 = 2;
/// Tap: `AF_PACKET` socket creation observed.
pub const CROSS_VIEW_DETAIL_TAP_CREATE: u32 = 1;
/// Tap: `SO_ATTACH_FILTER`/`SO_ATTACH_BPF` observed.
pub const CROSS_VIEW_DETAIL_TAP_FILTER: u32 = 2;
/// Tap: classic cBPF `sk_attach_filter` observed.
pub const CROSS_VIEW_DETAIL_TAP_CBPF: u32 = 3;
/// Tap: executable path resolves into a writable/deleted location.
pub const CROSS_VIEW_DETAIL_TAP_SUSPICIOUS_PATH: u32 = 4;
/// Process: `/proc/<pid>/stat` unreadable while the pid exists.
pub const CROSS_VIEW_DETAIL_STAT_FAILED: u32 = 1;
/// Process: kernel-evidenced pid missing from two consecutive listings.
pub const CROSS_VIEW_DETAIL_LISTING_MISS: u32 = 2;
/// Module: present in `/proc/modules`, missing from `/sys/module`.
pub const CROSS_VIEW_DETAIL_PROC_ONLY: u32 = 1;
/// Module: present in `/sys/module`, missing from `/proc/modules`.
pub const CROSS_VIEW_DETAIL_SYSFS_ONLY: u32 = 2;
/// Module: one view is tainted (O/E force-load/out-of-tree) while views differ.
pub const CROSS_VIEW_DETAIL_TAINTED: u32 = 4;
/// Library: mapped `.so` under a system lib root with no package owner.
pub const CROSS_VIEW_DETAIL_LIB_FOREIGN: u32 = 1;
/// Library: mapped `.so` was deleted after being mapped.
pub const CROSS_VIEW_DETAIL_LIB_DELETED: u32 = 2;
/// Pin: an expected pin is missing from the self-defence pin root.
pub const CROSS_VIEW_DETAIL_PIN_MISSING: u32 = 1;
/// Pin: a pinned object name does not match the pin file name.
pub const CROSS_VIEW_DETAIL_PIN_REPLACED: u32 = 2;
/// Pin: an unexpected pin appeared under the self-defence pin root.
pub const CROSS_VIEW_DETAIL_PIN_UNEXPECTED: u32 = 3;
/// Pin: a pin entry no longer resolves to a live BPF object.
pub const CROSS_VIEW_DETAIL_PIN_DANGLING: u32 = 4;

// --------------------------------------------------------- report/status tokens

/// Report prefix: the scan completed inside its documented bounds.
pub const CROSS_VIEW_REPORT_BOUNDS_OK: &str = "bounds=ok";
/// Report prefix: at least one bounded view was truncated or refused.
pub const CROSS_VIEW_REPORT_BOUNDS_DEGRADED: &str = "bounds=degraded";
/// Status/report field tokens (stable wire vocabulary).
pub const CROSS_VIEW_TOKEN_ENABLED: &str = "enabled";
pub const CROSS_VIEW_TOKEN_SCANS: &str = "scans";
pub const CROSS_VIEW_TOKEN_CONTRADICTIONS: &str = "contradictions";
pub const CROSS_VIEW_TOKEN_EVENTS: &str = "events";
pub const CROSS_VIEW_TOKEN_DROPS: &str = "drops";
pub const CROSS_VIEW_TOKEN_DOMAINS: &str = "domains";
pub const CROSS_VIEW_TOKEN_AGE_MS: &str = "age_ms";
pub const CROSS_VIEW_TOKEN_TAP: &str = "tap";
pub const CROSS_VIEW_TOKEN_MODS: &str = "mods";
pub const CROSS_VIEW_TOKEN_PROCS: &str = "procs";
pub const CROSS_VIEW_TOKEN_BPF: &str = "bpf";
pub const CROSS_VIEW_TOKEN_PKGDB: &str = "pkgdb";
pub const CROSS_VIEW_TOKEN_TRACE: &str = "trace";
pub const CROSS_VIEW_TOKEN_PINS: &str = "pins";
pub const CROSS_VIEW_TOKEN_REASON: &str = "reason";
/// Package-DB capability tokens.
pub const CROSS_VIEW_PKGDB_DEBIAN: &str = "debian";
pub const CROSS_VIEW_PKGDB_ARCH: &str = "arch";
pub const CROSS_VIEW_PKGDB_UNSUPPORTED: &str = "unsupported";
pub const CROSS_VIEW_PKGDB_DEGRADED: &str = "degraded";

// ------------------------------------------------------------- state word ABI

/// `CROSS_VIEW_STATE` magic byte for the armed word.
pub const CROSS_VIEW_STATE_MAGIC: u8 = 0x58;
/// `CROSS_VIEW_STATE` ABI version.
pub const CROSS_VIEW_STATE_ABI: u8 = 1;
/// Armed bit position (bit 32).
pub const CROSS_VIEW_STATE_ARMED_SHIFT: u64 = 32;
/// Attach flag: the `socket_create` LSM hook is attached (bit 33).
pub const CROSS_VIEW_STATE_LSM_CREATE_BIT: u64 = 33;
/// Attach flag: the `socket_setsockopt` LSM hook is attached (bit 34).
pub const CROSS_VIEW_STATE_LSM_SETSOCKOPT_BIT: u64 = 34;
/// Attach flag: the `sk_attach_filter` kprobe is attached (bit 35).
pub const CROSS_VIEW_STATE_KPROBE_BIT: u64 = 35;
/// Magic byte shift.
pub const CROSS_VIEW_STATE_MAGIC_SHIFT: u64 = 40;
/// ABI byte shift.
pub const CROSS_VIEW_STATE_ABI_SHIFT: u64 = 48;
/// One-byte mask.
pub const CROSS_VIEW_STATE_BYTE_MASK: u64 = 0xff;

/// Packs the `CROSS_VIEW_STATE` word (epoch | armed | attach flags | magic | ABI).
#[inline(always)]
pub const fn cross_view_state_word(epoch: u32, armed: bool, attach_flags: u64) -> u64 {
    (epoch as u64)
        | ((armed as u64) << CROSS_VIEW_STATE_ARMED_SHIFT)
        | (attach_flags
            & ((1 << CROSS_VIEW_STATE_LSM_CREATE_BIT)
                | (1 << CROSS_VIEW_STATE_LSM_SETSOCKOPT_BIT)
                | (1 << CROSS_VIEW_STATE_KPROBE_BIT)))
        | ((CROSS_VIEW_STATE_MAGIC as u64) << CROSS_VIEW_STATE_MAGIC_SHIFT)
        | ((CROSS_VIEW_STATE_ABI as u64) << CROSS_VIEW_STATE_ABI_SHIFT)
}

/// True only for an armed, magic/ABI-valid state word. Every eBPF program calls
/// this before emitting: absent/foreign/stale words are disarmed (fail-open).
#[inline(always)]
pub const fn cross_view_state_armed(word: u64) -> bool {
    let magic = ((word >> CROSS_VIEW_STATE_MAGIC_SHIFT) & CROSS_VIEW_STATE_BYTE_MASK) as u8;
    let abi = ((word >> CROSS_VIEW_STATE_ABI_SHIFT) & CROSS_VIEW_STATE_BYTE_MASK) as u8;
    let armed = (word >> CROSS_VIEW_STATE_ARMED_SHIFT) & 1;
    magic == CROSS_VIEW_STATE_MAGIC && abi == CROSS_VIEW_STATE_ABI && armed == 1
}

/// True when the given attach flag bit is set in an armed state word.
#[inline(always)]
pub const fn cross_view_state_flag(word: u64, bit: u64) -> bool {
    (word >> bit) & 1 == 1
}

/// True when `kind` is a contradiction kind the `domain` can emit. This is the
/// closed domain/kind cross product; the decoder and the Go parser both use it.
#[inline(always)]
pub const fn cross_view_kind_domain_valid(domain: u8, kind: u8) -> bool {
    match domain {
        CROSS_VIEW_DOMAIN_EBPF_ID_GAP => matches!(
            kind,
            CROSS_VIEW_KIND_HIDDEN_PROG
                | CROSS_VIEW_KIND_HIDDEN_MAP
                | CROSS_VIEW_KIND_HIDDEN_LINK
                | CROSS_VIEW_KIND_LINK_TAMPER
        ),
        CROSS_VIEW_DOMAIN_SOCKET_VIEW => matches!(
            kind,
            CROSS_VIEW_KIND_HIDDEN_SOCKET | CROSS_VIEW_KIND_PORTLESS_RAW_TAP
        ),
        CROSS_VIEW_DOMAIN_PROCESS_VIEW => kind == CROSS_VIEW_KIND_HIDDEN_PROCESS,
        CROSS_VIEW_DOMAIN_MODULE_TRACE_VIEW => matches!(
            kind,
            CROSS_VIEW_KIND_LKM_HIDDEN | CROSS_VIEW_KIND_FTRACE_HOOK
        ),
        CROSS_VIEW_DOMAIN_LIBRARY_VIEW => kind == CROSS_VIEW_KIND_LIBRARY_MISMATCH,
        CROSS_VIEW_DOMAIN_PIN_VIEW => kind == CROSS_VIEW_KIND_PIN_MISMATCH,
        CROSS_VIEW_DOMAIN_NETLINK_FILTER => kind == CROSS_VIEW_KIND_RAW_TAP_FILTER,
        CROSS_VIEW_DOMAIN_MAP_NAME_VIEW => {
            matches!(kind, CROSS_VIEW_KIND_HIDDEN_PROG | CROSS_VIEW_KIND_HIDDEN_MAP)
        }
        _ => false,
    }
}
