//! V6.3.0 AP-5 — persistence/linker/sshd/peripheral sensors (eBPF half).
//!
//! Observe-only kernel sensors for the AP-5 persistence and desktop-peripheral
//! attack surface. No program in this module denies, kills or alters a kernel
//! decision: every hook returns the previous LSM verdict (or 0) and only writes
//! bounded evidence into `PERSIST_GUARD_EVENTS`.
//!
//! Programs:
//! - `#[lsm(hook = "file_open")]` [`gedefense_persistence_file_open`]: opens of
//!   watched linker/PAM/systemd/udev/auth/shell paths, direct children of a
//!   watched directory (one bounded `dentry->d_parent` step), desktop peripheral
//!   devices and user secret stores,
//! - `#[lsm(hook = "mmap_file")]` [`gedefense_persistence_mmap`]: a library
//!   mapped into a protected executable (`sshd`/`sshd-session`/`sudo`/`su`/
//!   `login`/`curl`); the core cross-checks the mapped inode against the package
//!   database,
//! - `#[lsm(hook = "ptrace_access_check")]` [`gedefense_persistence_ptrace`]:
//!   tracer attachment (`child tgid` in `detail_code`, ptrace mode in `detail`),
//! - `#[tracepoint]` [`gedefense_process_vm_readv`] /
//!   [`gedefense_process_vm_writev`] on
//!   `syscalls/sys_enter_process_vm_readv|writev` (target pid in `detail_code`).
//!
//! Every kernel structure offset, LSM hook arity and syscall-tracepoint field
//! offset is resolved from vmlinux BTF / the tracefs `format` files by the
//! privileged core and published into `PERSIST_GUARD_OFFSETS`. Nothing is
//! hard-coded here. An absent/stale table or a hook-arity mismatch makes the
//! affected program fail open (return the previous verdict / 0, emit nothing)
//! and increment `PERSIST_GUARD_READ_FAILURES`; a hook that was never attached
//! is reported as such in the core status, never as enforcement.
//!
//! The syscall tracepoints additionally degrade honestly to a
//! `pid`/`comm`-only record when the core could not parse the tracefs format
//! (the target pid then stays 0). The `socket_connect` capture-socket hook is
//! deliberately omitted: the bound Unix-socket inode is only reachable through
//! the `unix_sock.path.dentry` offset chain, which this contract does not
//! publish (the device roots themselves are covered by `file_open` and the
//! declared device class list, and the omission is documented in the AP-5
//! report instead of shipping a hook that cannot identify its target).
//!
//! Verifier discipline: no allocations, no static `&[&str]` tables, no
//! unbounded loops; only bounded `bpf_probe_read_kernel` reads and hash-map
//! lookups.

use aya_ebpf::{
    helpers::{bpf_get_current_pid_tgid, bpf_get_current_uid_gid, bpf_ktime_get_ns},
    macros::{lsm, map, tracepoint},
    maps::{Array, HashMap, PerCpuArray, RingBuf},
    programs::{LsmContext, TracePointContext},
};
use gedefense_common::{
    PersistenceEvent, PERSIST_ACTION_AUDIT, PERSIST_CLASS_LD_PRELOAD, PERSIST_CLASS_SHELL_PROFILE,
    PERSIST_EVENT_RING_BYTES, PERSIST_EVENT_WIRE_BYTES, PERSIST_EXEC_MAP_ENTRIES,
    PERSIST_KIND_INTEGRITY_WRITE, PERSIST_KIND_LIBRARY_MMAP, PERSIST_OFFSETS_TABLE_LEN,
    PERSIST_PATH_MAP_ENTRIES, SEC_CRIT_ACTION_OBSERVE, SEC_CRIT_SOURCE_PERSISTENCE,
};
use crate::exec_inode::current_comm;
use crate::sec_crit::{sec_crit_emit, SEC_CRIT_KIND_PERSIST_CRIT};

use events::{increment_counter, normalize_comm};
use hooks::{
    try_persistence_file_open, try_persistence_mmap, try_persistence_ptrace, try_process_vm,
};
use paths::{mmap_abi, ptrace_abi};

mod events;
mod hooks;
mod paths;

/// `PERSIST_GUARD_OFFSETS` array length.
const PERSIST_OFFSETS_ENTRIES: u32 = PERSIST_OFFSETS_TABLE_LEN as u32;

#[map]
pub(crate) static PERSIST_GUARD_STATE: Array<u64> = Array::with_max_entries(1, 0);
/// Watched file/directory identities: `(dev, ino)` -> path map value
/// (`class | owner_uid << 8 | directory bit 63`).
#[map]
pub(crate) static PERSIST_GUARD_PATHS: HashMap<[u8; 16], u64> =
    HashMap::with_max_entries(PERSIST_PATH_MAP_ENTRIES, 0);
/// Protected executable identities (`sshd`, `sshd-session`, `sudo`, `su`,
/// `login`, `curl`) -> executable class.
#[map]
pub(crate) static PERSIST_GUARD_EXECS: HashMap<[u8; 16], u8> =
    HashMap::with_max_entries(PERSIST_EXEC_MAP_ENTRIES, 0);
/// BTF/tracefs-resolved offsets and hook arities (see `PERSIST_OFF_*`).
#[map]
pub(crate) static PERSIST_GUARD_OFFSETS: Array<u32> =
    Array::with_max_entries(PERSIST_OFFSETS_ENTRIES, 0);
/// Bounded evidence ring (128 KiB = 2048 queued 64-byte records).
#[map]
pub(crate) static PERSIST_GUARD_EVENTS: RingBuf =
    RingBuf::with_byte_size(PERSIST_EVENT_RING_BYTES, 0);
#[map]
pub(crate) static PERSIST_GUARD_EVENTS_EMITTED: PerCpuArray<u64> =
    PerCpuArray::with_max_entries(1, 0);
#[map]
pub(crate) static PERSIST_GUARD_RING_DROPS: PerCpuArray<u64> = PerCpuArray::with_max_entries(1, 0);
#[map]
pub(crate) static PERSIST_GUARD_READ_FAILURES: PerCpuArray<u64> =
    PerCpuArray::with_max_entries(1, 0);
#[map]
pub(crate) static PERSIST_GUARD_DEVICE_EVENTS: PerCpuArray<u64> =
    PerCpuArray::with_max_entries(1, 0);
#[map]
pub(crate) static PERSIST_GUARD_SECRET_EVENTS: PerCpuArray<u64> =
    PerCpuArray::with_max_entries(1, 0);
#[map]
pub(crate) static PERSIST_GUARD_MMAP_EVENTS: PerCpuArray<u64> =
    PerCpuArray::with_max_entries(1, 0);

/// Wire-layout guard shared with the core decoder.
const _: () = assert!(core::mem::size_of::<PersistenceEvent>() == PERSIST_EVENT_WIRE_BYTES);

#[inline(always)]
fn emit_persistence_event(
    dev: u32,
    ino: u64,
    class: u8,
    kind: u8,
    detail_code: u32,
    detail: &[u8; 8],
) {
    let ts_ns = unsafe { bpf_ktime_get_ns() };
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = pid_tgid as u32;
    if ts_ns == 0 || pid == 0 {
        return;
    }
    let comm = normalize_comm(current_comm());
    // V6.3.0 AP-9 (S12): "critical persistence" records are duplicated into the
    // independent high-priority ring before the family ring is written:
    //   * a library mapped into a protected executable (foreign-library finding
    //     is decided by the control plane's package-database cross-check),
    //   * an integrity write to a persistence path class (LD_PRELOAD, ld.so.conf,
    //     ld.so.preload, TLS, PAM, systemd generator/drop-in, udev,
    //     authorized_keys, ssh rc, shell profile).
    // Peripheral/secret opens, ptrace and memory scrapes are high-volume sensor
    // telemetry and stay on the family ring only (they are not "critical" in the
    // S12 two-class contract). `detail_code` carries `class << 8 OR kind` and
    // `extra[0..4]` the original family detail code.
    let critical = kind == PERSIST_KIND_LIBRARY_MMAP
        || (kind == PERSIST_KIND_INTEGRITY_WRITE
            && class >= PERSIST_CLASS_LD_PRELOAD
            && class <= PERSIST_CLASS_SHELL_PROFILE);
    if critical {
        let mut extra = [0u8; 8];
        extra[0..4].copy_from_slice(&detail_code.to_le_bytes());
        sec_crit_emit(
            SEC_CRIT_SOURCE_PERSISTENCE,
            SEC_CRIT_KIND_PERSIST_CRIT,
            SEC_CRIT_ACTION_OBSERVE,
            (u32::from(class) << 8) | u32::from(kind),
            dev,
            ino,
            comm,
            extra,
        );
    }
    let event = PersistenceEvent {
        ts_ns,
        ino,
        dev,
        pid,
        tgid: (pid_tgid >> 32) as u32,
        uid: bpf_get_current_uid_gid() as u32,
        detail_code,
        class,
        kind,
        action: PERSIST_ACTION_AUDIT,
        reserved: 0,
        comm,
        detail: *detail,
    };
    if let Some(mut entry) = PERSIST_GUARD_EVENTS.reserve::<PersistenceEvent>(0) {
        // SAFETY: the reservation is exactly size_of::<PersistenceEvent>() bytes,
        // 8-aligned, written once and submitted below.
        unsafe { entry.as_mut_ptr().write(event) };
        entry.submit(0);
        increment_counter(&PERSIST_GUARD_EVENTS_EMITTED);
    } else {
        // Ring full: visibility loss is counted, never an action change.
        increment_counter(&PERSIST_GUARD_RING_DROPS);
    }
}

/// `#[lsm(hook = "file_open")]` — `security_file_open(struct file *file)`.
///
/// Observe-only: the previous LSM verdict is always returned and the hook
/// returns 0 (allow) for every observation.
#[lsm(hook = "file_open")]
pub fn gedefense_persistence_file_open(ctx: LsmContext) -> i32 {
    // Defer to a previously attached LSM program exactly like the kernel chain.
    let previous: i32 = ctx.arg(1);
    if previous != 0 {
        return previous;
    }
    let _ = try_persistence_file_open(&ctx);
    0
}

/// `#[lsm(hook = "mmap_file")]` — library mapping into a protected executable.
///
/// Only an mmap performed by one of the protected executables (`PERSIST_GUARD_EXECS`)
/// is recorded; the core cross-checks the mapped dev/ino against its package
/// database and only turns foreign libraries into findings.
#[lsm(hook = "mmap_file")]
pub fn gedefense_persistence_mmap(ctx: LsmContext) -> i32 {
    let Some((prot_arg, previous_slot)) = mmap_abi() else {
        // A different `security_mmap_file` ABI cannot be indexed safely: fail
        // open, count the structural failure and emit nothing.
        increment_counter(&PERSIST_GUARD_READ_FAILURES);
        return 0;
    };
    let previous: i32 = ctx.arg(previous_slot as usize);
    if previous != 0 {
        return previous;
    }
    let _ = try_persistence_mmap(&ctx, prot_arg);
    0
}

/// `#[lsm(hook = "ptrace_access_check")]` — tracer attaches to a target task.
///
/// `detail_code` carries the child tgid (so the control plane can enrich the
/// target through `/proc`), `detail` carries the ptrace mode as decimal text.
#[lsm(hook = "ptrace_access_check")]
pub fn gedefense_persistence_ptrace(ctx: LsmContext) -> i32 {
    let Some(abi) = ptrace_abi() else {
        increment_counter(&PERSIST_GUARD_READ_FAILURES);
        return 0;
    };
    let previous: i32 = ctx.arg(abi.previous_slot as usize);
    if previous != 0 {
        return previous;
    }
    let _ = try_persistence_ptrace(&ctx, &abi);
    0
}

/// `tp/syscalls/sys_enter_process_vm_readv`.
#[tracepoint]
pub fn gedefense_process_vm_readv(ctx: TracePointContext) -> u32 {
    let _ = try_process_vm(&ctx, true);
    0
}

/// `tp/syscalls/sys_enter_process_vm_writev`.
#[tracepoint]
pub fn gedefense_process_vm_writev(ctx: TracePointContext) -> u32 {
    let _ = try_process_vm(&ctx, false);
    0
}
