//! V6.3.0 AP-4 — `io_uring`/LKM hook sensors (eBPF half).
//!
//! Programs (each one checks the [`KERNEL_HOOK_STATE`] armed word first and
//! emits at most one bounded [`KernelHookEvent`] per invocation, never blocking,
//! never denying, never allocating):
//!
//! - [`gedefense_io_uring_create`] `#[tracepoint]` on
//!   `io_uring/io_uring_create`: ring fd + setup flags (flags carry the
//!   `IORING_SETUP_SQPOLL`/`IOPOLL` bits a syscall-only sensor cannot see),
//! - [`gedefense_io_uring_register`] `#[tracepoint]` on
//!   `io_uring/io_uring_register`: registration opcode + nr_files,
//! - [`gedefense_io_uring_submit_req`] `#[tracepoint]` on
//!   `io_uring/io_uring_submit_req`: per-TGID sampled (one aggregate record per
//!   one-second window) because a busy ring submits thousands of requests per
//!   second and would otherwise flood the 64 KiB ring; requests that are
//!   suppressed are not counted as drops,
//! - [`gedefense_module_load`] `#[tracepoint]` on `module/module_load`: kernel
//!   taint mask + module name; a non-zero taint mask is reported as
//!   [`KERNEL_HOOK_KIND_LKM_TAINT`] instead of `MODULE_LOAD`,
//! - [`gedefense_init_module`], [`gedefense_finit_module`],
//!   [`gedefense_delete_module`] `#[kprobe]`: pre-stealth capture of the
//!   load/unload syscall *before* a rootkit can unlink the module from
//!   `mod_list`. The core only attaches these when the symbol exists in
//!   `/proc/kallsyms` (compiler clones such as `.isra.N` included),
//! - [`gedefense_lsm_uring_override_creds`], [`gedefense_lsm_uring_sqpoll`],
//!   [`gedefense_lsm_uring_cmd`] `#[lsm]`: BTF-optional LSM hooks that exist
//!   only on kernels which expose them. They defer to the previous LSM
//!   program's verdict and otherwise return `0`: the hook is observe-only by
//!   construction.
//!
//! # Layout handling (honest degradation)
//!
//! Tracepoint context layouts are kernel-version specific. The core reads the
//! kernel's `/sys/kernel/tracing/events/.../format` files at load time and
//! publishes the byte offsets of the fields this contract carries into the
//! [`KERNEL_HOOK_OFFSETS`] array ([`KERNEL_HOOK_OFFSET_*`] slots). Every payload
//! read is a bounded `bpf_probe_read_kernel` at one of those offsets; a slot
//! value of `0` means "unknown on this kernel" and the program emits the event
//! identity-only (pid/tgid/uid/comm/timestamp) plus one read-failure counter
//! increment. It never reads a guessed offset.
//!
//! # Verifier discipline
//!
//! No static `&[&str]` tables, no allocation, no unbounded loops: every loop is
//! a fixed 16/20-iteration loop or a 2-way if-chain. The `__data_loc` module
//! name is resolved as `record pointer + (data_loc & 0xffff)` with a hard
//! [`KERNEL_HOOK_MAX_RECORD_OFFSET`] bound, which the verifier accepts as a
//! bounded variable-offset probe read (validated on a 6.18 kernel). The
//! per-TGID sampling window lives in one bounded LRU map keyed by
//! `(tgid, kind)`.


use aya_ebpf::{
    helpers::{bpf_get_current_comm, bpf_get_current_pid_tgid},
    macros::{kprobe, lsm, map, tracepoint},
    maps::{Array, LruHashMap, PerCpuArray, RingBuf},
    programs::{LsmContext, ProbeContext, TracePointContext},
};
use gedefense_common::{
    KernelHookEvent, KERNEL_HOOK_COMM_BYTES, KERNEL_HOOK_EVENT_RING_BYTES,
    KERNEL_HOOK_EVENT_WIRE_BYTES, KERNEL_HOOK_KIND_LSM_URING_CMD,
    KERNEL_HOOK_KIND_LSM_URING_OVERRIDE_CREDS, KERNEL_HOOK_KIND_LSM_URING_SQPOLL,
    KERNEL_HOOK_KIND_MODULE_DELETE, KERNEL_HOOK_KIND_MODULE_FINIT, KERNEL_HOOK_KIND_MODULE_LOAD,
    KERNEL_HOOK_OFFSET_SLOTS, KERNEL_HOOK_WINDOW_ENTRIES, SEC_CRIT_ACTION_OBSERVE,
    SEC_CRIT_SOURCE_KERNEL_HOOKS,
};
use crate::sec_crit::{sec_crit_emit, SEC_CRIT_KIND_LKM_LOAD};

use emit::{emit_event, increment_counter, normalize_comm};
use io_uring::{try_io_uring_create, try_io_uring_register, try_io_uring_submit_req};
use layout::hooks_active;
use modules::{try_module_kprobe, try_module_load};
use window::window_allows;

mod emit;
mod io_uring;
mod layout;
mod modules;
mod window;

#[map]
pub(crate) static KERNEL_HOOK_STATE: Array<u64> = Array::with_max_entries(1, 0);
#[map]
pub(crate) static KERNEL_HOOK_EVENTS: RingBuf =
    RingBuf::with_byte_size(KERNEL_HOOK_EVENT_RING_BYTES, 0);
/// Tracepoint field byte offsets derived by the core from the kernel's format
/// files (slot constants in `gedefense-common`).
#[map]
pub(crate) static KERNEL_HOOK_OFFSETS: Array<u32> =
    Array::with_max_entries(KERNEL_HOOK_OFFSET_SLOTS, 0);
/// Per-TGID sampling window for the high-frequency hooks (`submit_req`,
/// `uring_cmd`). Key: `(tgid << 8) | kind`; value: last emit timestamp (ns).
#[map]
pub(crate) static KERNEL_HOOK_WINDOWS: LruHashMap<u64, u64> =
    LruHashMap::with_max_entries(KERNEL_HOOK_WINDOW_ENTRIES, 0);

#[map]
pub(crate) static KERNEL_HOOK_EVENTS_EMITTED: PerCpuArray<u64> =
    PerCpuArray::with_max_entries(1, 0);
#[map]
pub(crate) static KERNEL_HOOK_RING_DROPS: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);
#[map]
pub(crate) static KERNEL_HOOK_READ_FAILURES: PerCpuArray<u64> =
    PerCpuArray::with_max_entries(1, 0);
#[map]
pub(crate) static KERNEL_HOOK_MODULE_LOADS: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);
#[map]
pub(crate) static KERNEL_HOOK_RING_CREATES: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);

const _: () = assert!(core::mem::size_of::<KernelHookEvent>() == KERNEL_HOOK_EVENT_WIRE_BYTES);
const _: () = assert!(
    core::mem::align_of::<KernelHookEvent>() <= 8,
    "ring record must stay 8-aligned"
);
const _: () = assert!(KERNEL_HOOK_OFFSET_SLOTS == 8);

/// V6.3.0 AP-9 (S12): duplicates one module load/unload record into the
/// independent high-priority ring (`source = KERNEL_HOOKS`,
/// `kind = LKM_LOAD`, `action = OBSERVE`). `extra[0..4]` carries the LE u32
/// kernel taint mask and `extra[4..8]` up to four printable module-name bytes
/// (zero padded; the full name stays in the family ring). `detail_code` keeps
/// the caller's family detail (taints on `module/load`, fd/flags on the
/// syscall kprobes), so the control plane can still tell the record apart.
#[inline(always)]
fn sec_crit_duplicate_lkm(taints: u32, name: &[u8]) {
    let mut extra = [0u8; 8];
    extra[0..4].copy_from_slice(&taints.to_le_bytes());
    let mut index = 0usize;
    while index < 4 {
        let Some(&byte) = name.get(index) else {
            break;
        };
        if byte == 0 {
            break;
        }
        extra[4 + index] = if (0x20..=0x7e).contains(&byte) {
            byte
        } else {
            b'?'
        };
        index += 1;
    }
    let comm = normalize_comm(bpf_get_current_comm().unwrap_or([0u8; KERNEL_HOOK_COMM_BYTES]));
    sec_crit_emit(
        SEC_CRIT_SOURCE_KERNEL_HOOKS,
        SEC_CRIT_KIND_LKM_LOAD,
        SEC_CRIT_ACTION_OBSERVE,
        taints,
        0,
        0,
        comm,
        extra,
    );
}

#[tracepoint]
pub fn gedefense_io_uring_create(ctx: TracePointContext) -> u32 {
    let _ = try_io_uring_create(&ctx);
    0
}

#[tracepoint]
pub fn gedefense_io_uring_register(ctx: TracePointContext) -> u32 {
    let _ = try_io_uring_register(&ctx);
    0
}

#[tracepoint]
pub fn gedefense_io_uring_submit_req(ctx: TracePointContext) -> u32 {
    let _ = try_io_uring_submit_req(&ctx);
    0
}

#[tracepoint]
pub fn gedefense_module_load(ctx: TracePointContext) -> u32 {
    let _ = try_module_load(&ctx);
    0
}

#[kprobe]
pub fn gedefense_init_module(ctx: ProbeContext) -> u32 {
    let _ = try_module_kprobe(&ctx, KERNEL_HOOK_KIND_MODULE_LOAD, false, false);
    0
}

#[kprobe]
pub fn gedefense_finit_module(ctx: ProbeContext) -> u32 {
    // fd is only carried when the core attached a direct-argument symbol (see
    // KERNEL_HOOK_FLAG_FINIT_DIRECT_ARGS); on a syscall wrapper the first
    // argument is a pt_regs pointer and must never be reported as a fd.
    let _ = try_module_kprobe(&ctx, KERNEL_HOOK_KIND_MODULE_FINIT, true, false);
    0
}

#[kprobe]
pub fn gedefense_delete_module(ctx: ProbeContext) -> u32 {
    let _ = try_module_kprobe(&ctx, KERNEL_HOOK_KIND_MODULE_DELETE, false, true);
    0
}

/// `security_uring_override_creds(const struct cred *new)`: one real argument,
/// the previous LSM verdict is the trailing `retval` argument.
#[lsm(hook = "uring_override_creds")]
pub fn gedefense_lsm_uring_override_creds(ctx: LsmContext) -> i32 {
    let previous: i32 = ctx.arg(1);
    if previous != 0 {
        return previous;
    }
    if hooks_active() {
        emit_event(KERNEL_HOOK_KIND_LSM_URING_OVERRIDE_CREDS, 0, &[]);
    }
    // Observe-only: never deny; defer to the rest of the LSM chain.
    0
}

/// `security_uring_sqpoll(void)`: no real argument, the previous LSM verdict is
/// the only context slot.
#[lsm(hook = "uring_sqpoll")]
pub fn gedefense_lsm_uring_sqpoll(ctx: LsmContext) -> i32 {
    let previous: i32 = ctx.arg(0);
    if previous != 0 {
        return previous;
    }
    if hooks_active() {
        emit_event(KERNEL_HOOK_KIND_LSM_URING_SQPOLL, 0, &[]);
    }
    0
}

/// `security_uring_cmd(struct io_uring_cmd *ioucmd)`: the command structure is
/// kernel-private (no stable byte offset), so only the hook invocation + task
/// identity are carried. Sampled per TGID because passthrough users issue
/// commands per I/O.
#[lsm(hook = "uring_cmd")]
pub fn gedefense_lsm_uring_cmd(ctx: LsmContext) -> i32 {
    let previous: i32 = ctx.arg(1);
    if previous != 0 {
        return previous;
    }
    if !hooks_active() {
        return 0;
    }
    let pid_tgid = bpf_get_current_pid_tgid();
    let tgid = (pid_tgid >> 32) as u32;
    if tgid == 0 {
        increment_counter(&KERNEL_HOOK_READ_FAILURES);
        return 0;
    }
    if window_allows(tgid, KERNEL_HOOK_KIND_LSM_URING_CMD) {
        emit_event(KERNEL_HOOK_KIND_LSM_URING_CMD, 0, &[]);
    }
    0
}
