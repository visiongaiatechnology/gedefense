//! V6.3.0 AP-3 — cross-view kernel supports (eBPF half).
//!
//! The aya-ebpf 0.2.1 macro crate pinned by this workspace has **no `#[iter]`
//! proc-macro** (only map/kprobe/tracepoint/lsm/... exist), so the iter views
//! from `docs/V6.3.0-PLAN.md` are implemented in the privileged core through
//! direct `BPF_*_GET_NEXT_ID` / `BPF_*_GET_FD_BY_ID` syscalls instead of
//! `bpf_iter` programs. This module owns only the part the kernel must see:
//!
//! - [`gedefense_crossview_socket_create`] `#[lsm(hook = "socket_create")]`
//!   (`security_socket_create(int family, int type, int protocol, int kern)`):
//!   emits one `RAW_TAP_FILTER` record when an `AF_PACKET` `SOCK_RAW`/
//!   `SOCK_DGRAM` tap socket is created (BPFDoor/VoidLink class).
//! - [`gedefense_crossview_socket_setsockopt`] `#[lsm(hook = "socket_setsockopt")]`
//!   (`security_socket_setsockopt(struct socket *sock, int level, int optname)`):
//!   emits one `RAW_TAP_FILTER` record for `SO_ATTACH_FILTER`,
//!   `SO_ATTACH_BPF`, `SO_ATTACH_REUSEPORT_CBPF` and
//!   `SO_ATTACH_REUSEPORT_EBPF`.
//! - [`gedefense_crossview_sk_attach_filter`] `#[kprobe]` on
//!   `sk_attach_filter(struct sock_fprog *fprog, struct sock *sk)`: the classic
//!   cBPF path BPFDoor actually uses; it never calls `BPF_PROG_LOAD`. The symbol
//!   is not present in every kernel build, so the core attaches it best-effort
//!   and reports `kprobe=0` honestly when the attach fails.
//!
//! LSM arity/positions are the ones exposed by the kernel BTF: the BPF LSM
//! context is the hook parameter list followed by the previous LSM program's
//! `retval` (`kernel/bpf/bpf_lsm.c`, `include/linux/lsm_hook_defs.h`). Verified
//! against a live `/sys/kernel/btf/vmlinux` (`bpf_lsm_socket_create` has four
//! parameters `family, type, protocol, kern`; `bpf_lsm_socket_setsockopt` has
//! `sock, level, optname`), which is also why the programs read fixed,
//! BTF-stable argument slots.
//!
//! Every program is observe-only and fail-open: the first check is the
//! `CROSS_VIEW_STATE` magic/ABI/armed word (absent/foreign/stale = disarm, no
//! event), the hooks always return the previous LSM verdict or 0, and the
//! kprobe always returns 0. No allocation, no unbounded loops, no static
//! `&[&str]` tables. The `socket_create` program suppresses nothing; the
//! `sk_attach_filter` kprobe is suppressed when the `socket_setsockopt` LSM hook
//! is attached (state bit 34) so one filter attach is not reported twice.
//!
//! Maps (mandatory for the core):
//! - `CROSS_VIEW_STATE` — one ABI word (`epoch | armed | attach flags | magic |
//!   ABI`, see `gedefense_common`),
//! - `CROSS_VIEW_EVENTS` — 64 KiB ring of 64-byte `CrossViewEvent` records,
//! - `CROSS_VIEW_COUNTERS` — per-CPU counters: index 0 emitted, 1 ring drops,
//!   2 read failures.

use aya_ebpf::{
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid, bpf_ktime_get_ns,
    },
    macros::{kprobe, lsm, map},
    maps::{Array, PerCpuArray, RingBuf},
    programs::{LsmContext, ProbeContext},
};
use gedefense_common::{
    cross_view_state_armed, cross_view_state_flag, CrossViewEvent, CROSS_VIEW_ACTION_AUDIT,
    CROSS_VIEW_DETAIL_TAP_CBPF, CROSS_VIEW_DETAIL_TAP_CREATE, CROSS_VIEW_DETAIL_TAP_FILTER,
    CROSS_VIEW_DOMAIN_NETLINK_FILTER, CROSS_VIEW_EVENT_RING_BYTES, CROSS_VIEW_EVENT_WIRE_BYTES,
    CROSS_VIEW_KIND_RAW_TAP_FILTER, CROSS_VIEW_SEVERITY_MEDIUM, CROSS_VIEW_STATE_ARMED_SHIFT,
    CROSS_VIEW_STATE_LSM_SETSOCKOPT_BIT,
};

/// Index of the single state word in `CROSS_VIEW_STATE`.
const CROSS_VIEW_STATE_INDEX: u32 = 0;
/// `CROSS_VIEW_COUNTERS` lane indices.
const COUNTER_EMITTED: u32 = 0;
const COUNTER_DROPS: u32 = 1;
const COUNTER_READ_FAILURES: u32 = 2;
const CROSS_VIEW_COUNTERS_ENTRIES: u32 = 3;

// UAPI values used by the LSM hooks (stable, `include/uapi/linux/socket.h`,
// `include/linux/net.h`, `include/uapi/asm-generic/socket.h`).
const AF_PACKET: u32 = 17;
const SOCK_TYPE_MASK: u32 = 0xf;
const SOCK_DGRAM: u32 = 2;
const SOCK_RAW: u32 = 3;
const SOL_SOCKET: u32 = 1;
const SO_ATTACH_FILTER: u32 = 26;
const SO_ATTACH_BPF: u32 = 50;
const SO_ATTACH_REUSEPORT_CBPF: u32 = 51;
const SO_ATTACH_REUSEPORT_EBPF: u32 = 52;

#[map]
pub(crate) static CROSS_VIEW_STATE: Array<u64> = Array::with_max_entries(1, 0);
#[map]
pub(crate) static CROSS_VIEW_EVENTS: RingBuf =
    RingBuf::with_byte_size(CROSS_VIEW_EVENT_RING_BYTES, 0);
#[map]
pub(crate) static CROSS_VIEW_COUNTERS: PerCpuArray<u64> =
    PerCpuArray::with_max_entries(CROSS_VIEW_COUNTERS_ENTRIES, 0);

const _: () = assert!(core::mem::size_of::<CrossViewEvent>() == CROSS_VIEW_EVENT_WIRE_BYTES);
const _: () = assert!(
    core::mem::align_of::<CrossViewEvent>() <= 8,
    "ring record must stay 8-aligned"
);

#[inline(always)]
fn increment_counter(index: u32) {
    if let Some(value) = CROSS_VIEW_COUNTERS.get_ptr_mut(index) {
        // SAFETY: per-CPU array lane index is owned by this CPU for this update.
        unsafe { *value = (*value).wrapping_add(1) };
    }
}

/// Reads and validates the cross-view state word. Absent/foreign/stale = not
/// armed, which means "emit nothing" (fail-open and silent).
#[inline(always)]
fn cross_view_active() -> bool {
    match CROSS_VIEW_STATE.get(CROSS_VIEW_STATE_INDEX) {
        Some(word) => cross_view_state_armed(*word),
        None => false,
    }
}

/// True when the `socket_setsockopt` LSM hook is attached, so the
/// `sk_attach_filter` kprobe can stay silent and one attach is reported once.
#[inline(always)]
fn setsockopt_hook_attached() -> bool {
    match CROSS_VIEW_STATE.get(CROSS_VIEW_STATE_INDEX) {
        Some(word) => {
            cross_view_state_armed(*word)
                && cross_view_state_flag(*word, CROSS_VIEW_STATE_LSM_SETSOCKOPT_BIT)
        }
        None => false,
    }
}

/// The eBPF ring writer only rejects/truncates the *tail* of a comm: a 16-byte
/// task name is truncated to 15 bytes so the record always carries a NUL, and
/// every control/high-bit byte becomes `?` (terminal-injection guard shared with
/// the other event producers).
#[inline(always)]
fn normalize_comm(raw: [u8; 16]) -> [u8; 16] {
    let mut out = [0u8; 16];
    let mut index = 0usize;
    while index < out.len() {
        let byte = raw[index];
        if byte == 0 {
            break;
        }
        out[index] = if (0x20..=0x7e).contains(&byte) {
            byte
        } else {
            b'?'
        };
        index += 1;
    }
    if index == out.len() {
        out[15] = 0;
    }
    out
}

/// Emits one bounded tap record for the current task. Returns `false` when no
/// event could be emitted (all failures are counted, never silent).
#[inline(always)]
fn emit_tap_event(detail_code: u32) -> bool {
    let ts_ns = unsafe { bpf_ktime_get_ns() };
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = pid_tgid as u32;
    if ts_ns == 0 || pid == 0 {
        increment_counter(COUNTER_READ_FAILURES);
        return false;
    }
    let uid_gid = bpf_get_current_uid_gid();
    let comm = match bpf_get_current_comm() {
        Ok(raw) => normalize_comm(raw),
        Err(_) => {
            increment_counter(COUNTER_READ_FAILURES);
            [0u8; 16]
        }
    };
    let event = CrossViewEvent {
        ts_ns,
        // Tap records carry the *process* id (tgid) in `ino`: the hook fires in
        // the calling thread, and a short-lived thread id may already be gone
        // when the core drains the ring. The core resolves `/proc/<tgid>/exe`
        // from this fallback identity; no file inode is fabricated here.
        ino: u64::from((pid_tgid >> 32) as u32),
        pid,
        uid: uid_gid as u32,
        dev: 0,
        detail_code,
        domain: CROSS_VIEW_DOMAIN_NETLINK_FILTER,
        kind: CROSS_VIEW_KIND_RAW_TAP_FILTER,
        severity: CROSS_VIEW_SEVERITY_MEDIUM,
        action: CROSS_VIEW_ACTION_AUDIT,
        comm,
        reserved: [0u8; 12],
    };
    if let Some(mut entry) = CROSS_VIEW_EVENTS.reserve::<CrossViewEvent>(0) {
        // SAFETY: the reservation is exactly size_of::<CrossViewEvent>() bytes,
        // 8-aligned, written once and submitted below.
        unsafe { entry.as_mut_ptr().write(event) };
        entry.submit(0);
        increment_counter(COUNTER_EMITTED);
        true
    } else {
        increment_counter(COUNTER_DROPS);
        false
    }
}

/// `#[lsm(hook = "socket_create")]` — `security_socket_create(family, type,
/// protocol, kern)`, retval at slot 4. Observe-only: returns the previous LSM
/// verdict (never a denial of its own).
#[lsm(hook = "socket_create")]
pub fn gedefense_crossview_socket_create(ctx: LsmContext) -> i32 {
    let previous: i32 = ctx.arg(4);
    if previous != 0 {
        return previous;
    }
    if !cross_view_active() {
        return 0;
    }
    let family: u32 = ctx.arg(0);
    if family != AF_PACKET {
        return 0;
    }
    let socket_type: u32 = ctx.arg(1);
    match socket_type & SOCK_TYPE_MASK {
        SOCK_RAW | SOCK_DGRAM => {
            emit_tap_event(CROSS_VIEW_DETAIL_TAP_CREATE);
        }
        _ => {}
    }
    0
}

/// `#[lsm(hook = "socket_setsockopt")]` — `security_socket_setsockopt(sock,
/// level, optname)`, retval at slot 3. Observe-only.
#[lsm(hook = "socket_setsockopt")]
pub fn gedefense_crossview_socket_setsockopt(ctx: LsmContext) -> i32 {
    let previous: i32 = ctx.arg(3);
    if previous != 0 {
        return previous;
    }
    if !cross_view_active() {
        return 0;
    }
    let level: u32 = ctx.arg(1);
    if level != SOL_SOCKET {
        return 0;
    }
    let optname: u32 = ctx.arg(2);
    match optname {
        SO_ATTACH_FILTER | SO_ATTACH_BPF | SO_ATTACH_REUSEPORT_CBPF | SO_ATTACH_REUSEPORT_EBPF => {
            emit_tap_event(CROSS_VIEW_DETAIL_TAP_FILTER);
        }
        _ => {}
    }
    0
}

/// Best-effort `#[kprobe]` on the classic cBPF attach path
/// (`sk_attach_filter`), which BPFDoor uses instead of `BPF_PROG_LOAD`.
///
/// The program does not need any function argument: the task identity and the
/// timestamp are the evidence, and the core correlates them with the
/// packet_diag filter view. It is skipped when the `socket_setsockopt` LSM hook
/// is attached, so one attach produces one record.
#[kprobe]
pub fn gedefense_crossview_sk_attach_filter(_ctx: ProbeContext) -> u32 {
    if !cross_view_active() || setsockopt_hook_attached() {
        return 0;
    }
    emit_tap_event(CROSS_VIEW_DETAIL_TAP_CBPF);
    0
}

/// Compile-time coupling to the state-word ABI read above: a drift must fail the
/// eBPF build instead of silently disabling the tap programs.
const _: () = assert!(CROSS_VIEW_STATE_ARMED_SHIFT == 32);
const _: () = assert!(CROSS_VIEW_STATE_LSM_SETSOCKOPT_BIT == 34);
