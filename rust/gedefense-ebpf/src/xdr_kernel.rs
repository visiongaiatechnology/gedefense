//! Kernel-side XDR behavioral tracepoints & probe emitters:
//! - `gedefense_sys_enter_execve`: captures bounded `filename` + `argv` into
//!   `EXEC_ARGV_EVENTS` using per-CPU scratch memory so short-lived subshells
//!   retain full command-line context even if they exit before `/proc` polling.
//! - `gedefense_sys_enter_ptrace`: emits `KernelProbeEvent` for `ptrace`
//!   attach/seize/memory-access calls.
//! - `gedefense_openat_cred_probe`: pre-DAC telemetry on `/etc/shadow`,
//!   `/etc/gshadow` and `/etc/vgt/gedefense/secrets/` for untrusted tasks.
//! - `gedefense_symlinkat_sensitive`: detects symlink creation over sensitive
//!   credential/config paths.

use aya_ebpf::{
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid, bpf_ktime_get_ns,
        bpf_probe_read_kernel, bpf_probe_read_kernel_str_bytes, bpf_probe_read_user,
        bpf_probe_read_user_str_bytes,
    },
    macros::{kretprobe, map, tracepoint},
    maps::{LruHashMap, PerCpuArray, RingBuf},
    programs::{RetProbeContext, TracePointContext},
};
use gedefense_common::{
    credential_reader_allowed, ExecArgvEvent, KernelProbeEvent, EXEC_ARGV_EVENT_RING_BYTES,
    EXEC_ARGV_EVENT_WIRE_BYTES, KERNEL_PROBE_ACTION_AUDIT, KERNEL_PROBE_DETAIL_BYTES,
    KERNEL_PROBE_EVENT_RING_BYTES, KERNEL_PROBE_EVENT_WIRE_BYTES,
    KERNEL_PROBE_KIND_CRED_OPENAT, KERNEL_PROBE_KIND_PTRACE, KERNEL_PROBE_KIND_SYMLINK,
    SEC_CRIT_BUCKET_EXEC_ARGV, SEC_CRIT_BUCKET_KERNEL_PROBE,
};
use crate::sec_crit::{
    telemetry_budget_allow, telemetry_current_cgroup_id, telemetry_note_suppressed,
};

const EXEC_SLOT_FILENAME_END: usize = 64;
const EXEC_SLOT_ARG1_END: usize = 128;
const EXEC_SLOT_ARG2_END: usize = 320;
const EXEC_SLOT_ARG3_END: usize = 384;
const EXEC_SLOT_ARG4_END: usize = 448;
const PATH_PROBE_BYTES: usize = 48;

const PTRACE_TRACEME: u64 = 0;
const PTRACE_PEEKTEXT: u64 = 1;
const PTRACE_PEEKDATA: u64 = 2;
const PTRACE_POKETEXT: u64 = 4;
const PTRACE_POKEDATA: u64 = 5;
const PTRACE_ATTACH: u64 = 16;
const PTRACE_SEIZE: u64 = 0x4206;

const COLD_PATH_CRED_OPENAT: u8 = 1;
const COLD_PATH_SYMLINK: u8 = 2;
const COLD_EXEC_FILENAME: u8 = 3;

#[map]
pub(crate) static EXEC_ARGV_SCRATCH: PerCpuArray<ExecArgvEvent> =
    PerCpuArray::with_max_entries(1, 0);
#[map]
pub(crate) static PENDING_EXEC_ARGV: LruHashMap<u32, ExecArgvEvent> =
    LruHashMap::with_max_entries(4_096, 0);
#[map]
pub(crate) static PENDING_COLD_OPEN: LruHashMap<u32, u8> =
    LruHashMap::with_max_entries(2_048, 0);
#[map]
pub(crate) static EXEC_ARGV_EVENTS: RingBuf =
    RingBuf::with_byte_size(EXEC_ARGV_EVENT_RING_BYTES, 0);
#[map]
pub(crate) static KERNEL_PROBE_EVENTS: RingBuf =
    RingBuf::with_byte_size(KERNEL_PROBE_EVENT_RING_BYTES, 0);

const _: () = assert!(core::mem::size_of::<ExecArgvEvent>() == EXEC_ARGV_EVENT_WIRE_BYTES);
const _: () = assert!(core::mem::size_of::<KernelProbeEvent>() == KERNEL_PROBE_EVENT_WIRE_BYTES);

#[inline(always)]
fn comm_trimmed_len(comm: &[u8; 16]) -> usize {
    let mut len = 0usize;
    while len < 16 {
        let Some(&b) = comm.get(len) else {
            break;
        };
        if b == 0 {
            break;
        }
        len += 1;
    }
    len
}

#[inline(always)]
fn normalize_comm(raw: [u8; 16]) -> [u8; 16] {
    let mut out = raw;
    if comm_trimmed_len(&out) == 16 {
        out[15] = 0;
    }
    out
}

#[inline(always)]
fn prefix_match(buf: &[u8], prefix: &[u8]) -> bool {
    if buf.len() < prefix.len() {
        return false;
    }
    let mut i = 0usize;
    while i < prefix.len() {
        let Some(&a) = buf.get(i) else {
            return false;
        };
        let Some(&b) = prefix.get(i) else {
            return false;
        };
        if a != b {
            return false;
        }
        i += 1;
    }
    true
}

#[inline(always)]
fn read_user_slot(user_ptr: u64, dst: &mut [u8]) {
    if let Some(first) = dst.first_mut() {
        *first = 0;
    }
    if user_ptr == 0 {
        return;
    }
    if unsafe { bpf_probe_read_user_str_bytes(user_ptr as *const u8, dst) }.is_err() {
        if let Some(first) = dst.first_mut() {
            *first = 0;
        }
    }
}

#[tracepoint]
pub fn gedefense_sys_enter_execve(ctx: TracePointContext) -> u32 {
    let _ = try_sys_enter_execve_at_offsets(&ctx, 16, 24);
    0
}

#[tracepoint]
pub fn gedefense_sys_enter_execveat(ctx: TracePointContext) -> u32 {
    let _ = try_sys_enter_execve_at_offsets(&ctx, 24, 32);
    0
}

#[inline(always)]
fn try_sys_enter_execve_at_offsets(
    ctx: &TracePointContext,
    filename_offset: usize,
    argv_offset: usize,
) -> Option<()> {
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;
    let tid = pid_tgid as u32;
    if pid == 0 || tid == 0 {
        return None;
    }
    let filename_ptr: u64 = unsafe { ctx.read_at(filename_offset).ok()? };
    let argv_ptr: u64 = unsafe { ctx.read_at(argv_offset).ok()? };
    if filename_ptr == 0 {
        return None;
    }
    let scratch_ptr = EXEC_ARGV_SCRATCH.get_ptr_mut(0)?;
    // SAFETY: per-CPU scratch element index 0 is owned by the current CPU.
    let event = unsafe { &mut *scratch_ptr };
    let uid_gid = bpf_get_current_uid_gid();
    event.pid = pid;
    event.ppid = 0;
    event.uid = uid_gid as u32;
    event.gid = (uid_gid >> 32) as u32;
    event.filename_len = EXEC_SLOT_FILENAME_END as u16;
    event.argv_len = EXEC_SLOT_ARG4_END as u16;
    event.reserved = 0;
    event.comm = normalize_comm(bpf_get_current_comm().ok()?);

    read_user_slot(filename_ptr, &mut event.buf[0..EXEC_SLOT_FILENAME_END]);
    if event.buf[0] == 0 {
        let _ = PENDING_COLD_OPEN.insert(&tid, &COLD_EXEC_FILENAME, 0);
    }

    let p1 = if argv_ptr != 0 {
        unsafe { bpf_probe_read_user((argv_ptr.wrapping_add(8)) as *const u64) }.unwrap_or(0)
    } else {
        0
    };
    read_user_slot(p1, &mut event.buf[EXEC_SLOT_FILENAME_END..EXEC_SLOT_ARG1_END]);

    let p2 = if argv_ptr != 0 && p1 != 0 {
        unsafe { bpf_probe_read_user((argv_ptr.wrapping_add(16)) as *const u64) }.unwrap_or(0)
    } else {
        0
    };
    read_user_slot(p2, &mut event.buf[EXEC_SLOT_ARG1_END..EXEC_SLOT_ARG2_END]);

    let p3 = if argv_ptr != 0 && p2 != 0 {
        unsafe { bpf_probe_read_user((argv_ptr.wrapping_add(24)) as *const u64) }.unwrap_or(0)
    } else {
        0
    };
    read_user_slot(p3, &mut event.buf[EXEC_SLOT_ARG2_END..EXEC_SLOT_ARG3_END]);

    let p4 = if argv_ptr != 0 && p3 != 0 {
        unsafe { bpf_probe_read_user((argv_ptr.wrapping_add(32)) as *const u64) }.unwrap_or(0)
    } else {
        0
    };
    read_user_slot(p4, &mut event.buf[EXEC_SLOT_ARG3_END..EXEC_SLOT_ARG4_END]);

    // Stash per-TID until `sched_process_exec` confirms execve succeeded (eliminates
    // `-ENOENT` PATH-search noise and captures the post-exec `comm`).
    let _ = PENDING_EXEC_ARGV.insert(&tid, event, 0);
    Some(())
}

#[inline(always)]
pub(crate) fn flush_pending_exec_argv(tid: u32, comm: [u8; 16]) {
    let Some(pending) = (unsafe { PENDING_EXEC_ARGV.get(&tid) }) else {
        return;
    };
    // V6.3.0 AP-9 (S12): bulk telemetry passes the per-(class, cgroup, uid)
    // token bucket before a ring slot is reserved. A flooding cgroup is
    // throttled (counted), every other workload keeps its normal rate, and the
    // dedicated critical rings are unaffected by this path. The bucket is only
    // charged once a record actually exists (the pending lookup above), so a
    // flush without a pending exec cannot consume a token.
    let uid = bpf_get_current_uid_gid() as u32;
    if !telemetry_budget_allow(
        SEC_CRIT_BUCKET_EXEC_ARGV,
        telemetry_current_cgroup_id(),
        uid,
    ) {
        telemetry_note_suppressed(SEC_CRIT_BUCKET_EXEC_ARGV);
        let _ = PENDING_EXEC_ARGV.remove(&tid);
        return;
    }
    let Some(scratch_ptr) = EXEC_ARGV_SCRATCH.get_ptr_mut(0) else {
        let _ = PENDING_EXEC_ARGV.remove(&tid);
        return;
    };
    let scratch = unsafe { &mut *scratch_ptr };
    *scratch = *pending;
    scratch.comm = normalize_comm(comm);
    let _ = PENDING_EXEC_ARGV.remove(&tid);
    if let Some(mut entry) = EXEC_ARGV_EVENTS.reserve::<ExecArgvEvent>(0) {
        unsafe { entry.as_mut_ptr().write(*scratch) };
        entry.submit(0);
    }
}

#[inline(always)]
pub(crate) fn emit_kernel_probe(
    kind: u8,
    action: u8,
    target_pid: u32,
    detail_code: u32,
    detail_bytes: &[u8],
) {
    let ts_ns = unsafe { bpf_ktime_get_ns() };
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = (pid_tgid >> 32) as u32;
    if ts_ns == 0 || pid == 0 {
        return;
    }
    let uid_gid = bpf_get_current_uid_gid();
    // V6.3.0 AP-9 (S12): kernel-probe telemetry is bulk telemetry; a flooding
    // cgroup/uid is throttled per class and the refusal is counted.
    if !telemetry_budget_allow(
        SEC_CRIT_BUCKET_KERNEL_PROBE,
        telemetry_current_cgroup_id(),
        uid_gid as u32,
    ) {
        telemetry_note_suppressed(SEC_CRIT_BUCKET_KERNEL_PROBE);
        return;
    }
    let comm = normalize_comm(bpf_get_current_comm().unwrap_or([0u8; 16]));
    let mut detail = [0u8; KERNEL_PROBE_DETAIL_BYTES];
    let mut dlen = 0usize;
    while dlen < KERNEL_PROBE_DETAIL_BYTES && dlen < detail_bytes.len() {
        let Some(&b) = detail_bytes.get(dlen) else {
            break;
        };
        if b == 0 {
            break;
        }
        detail[dlen] = b;
        dlen += 1;
    }
    let event = KernelProbeEvent {
        ts_ns,
        pid,
        uid: uid_gid as u32,
        target_pid,
        detail_code,
        kind,
        action,
        detail_len: dlen as u8,
        reserved: 0,
        comm,
        detail,
    };
    if let Some(mut entry) = KERNEL_PROBE_EVENTS.reserve::<KernelProbeEvent>(0) {
        unsafe { entry.as_mut_ptr().write(event) };
        entry.submit(0);
    }
}

#[tracepoint]
pub fn gedefense_sys_enter_ptrace(ctx: TracePointContext) -> u32 {
    let _ = try_sys_enter_ptrace(&ctx);
    0
}

#[inline(always)]
fn try_sys_enter_ptrace(ctx: &TracePointContext) -> Option<()> {
    let req: u64 = unsafe { ctx.read_at(16).ok()? };
    if !matches!(
        req,
        PTRACE_TRACEME
            | PTRACE_PEEKTEXT
            | PTRACE_PEEKDATA
            | PTRACE_POKETEXT
            | PTRACE_POKEDATA
            | PTRACE_ATTACH
            | PTRACE_SEIZE
    ) {
        return None;
    }
    let target_pid: u64 = unsafe { ctx.read_at(24).ok()? };
    emit_kernel_probe(
        KERNEL_PROBE_KIND_PTRACE,
        KERNEL_PROBE_ACTION_AUDIT,
        target_pid as u32,
        req as u32,
        b"ptrace",
    );
    Some(())
}

#[inline(always)]
fn is_exact_bytes(buf: &[u8], expected: &[u8]) -> bool {
    buf.len() == expected.len() && prefix_match(buf, expected)
}

#[inline(always)]
fn is_cred_open_sensitive(path_bytes: &[u8]) -> bool {
    prefix_match(path_bytes, b"/etc/shadow")
        || prefix_match(path_bytes, b"/etc/gshadow")
        || prefix_match(path_bytes, b"/etc/vgt/gedefense/secrets/")
}

#[tracepoint]
pub fn gedefense_openat_cred_probe(ctx: TracePointContext) -> u32 {
    let _ = try_openat_cred_probe(&ctx);
    0
}

#[tracepoint]
pub fn gedefense_openat2_cred_probe(ctx: TracePointContext) -> u32 {
    let _ = try_openat_cred_probe(&ctx);
    0
}

#[inline(always)]
fn try_openat_cred_probe(ctx: &TracePointContext) -> Option<()> {
    let filename_ptr: u64 = unsafe { ctx.read_at(24).ok()? };
    if filename_ptr == 0 {
        return None;
    }
    let comm = bpf_get_current_comm().unwrap_or([0u8; 16]);
    let clen = comm_trimmed_len(&comm);
    if credential_reader_allowed(&comm[..clen]) {
        return None;
    }
    let mut path = [0u8; PATH_PROBE_BYTES];
    let path_bytes = match unsafe { bpf_probe_read_user_str_bytes(filename_ptr as *const u8, &mut path) } {
        Ok(bytes) => bytes,
        Err(_) => {
            // Cold userspace `.rodata` string pages often fault inside `getname_flags`;
            // defer this single syscall to the kretprobe instead of guessing in user space.
            let tid = bpf_get_current_pid_tgid() as u32;
            if tid != 0 {
                let _ = PENDING_COLD_OPEN.insert(&tid, &COLD_PATH_CRED_OPENAT, 0);
            }
            return None;
        }
    };
    if !is_cred_open_sensitive(path_bytes) {
        return None;
    }
    emit_kernel_probe(
        KERNEL_PROBE_KIND_CRED_OPENAT,
        KERNEL_PROBE_ACTION_AUDIT,
        0,
        0,
        path_bytes,
    );
    Some(())
}

#[tracepoint]
pub fn gedefense_symlinkat_sensitive(ctx: TracePointContext) -> u32 {
    let _ = try_symlinkat_sensitive(&ctx);
    0
}

#[inline(always)]
fn is_sensitive_cred_path(path_bytes: &[u8]) -> bool {
    is_exact_bytes(path_bytes, b"/etc")
        || is_exact_bytes(path_bytes, b"/etc/")
        || prefix_match(path_bytes, b"/etc/shadow")
        || prefix_match(path_bytes, b"/etc/gshadow")
        || prefix_match(path_bytes, b"/etc/passwd")
        || prefix_match(path_bytes, b"/etc/sudoers")
        || prefix_match(path_bytes, b"/etc/cron")
        || prefix_match(path_bytes, b"/etc/pam.d")
        || prefix_match(path_bytes, b"/etc/vgt/gedefense")
        || prefix_match(path_bytes, b"/root/.ssh")
}

#[tracepoint]
pub fn gedefense_symlink_sensitive(ctx: TracePointContext) -> u32 {
    let _ = try_symlink_two_ptrs(&ctx, 16, 24);
    0
}

#[inline(always)]
fn try_symlinkat_sensitive(ctx: &TracePointContext) -> Option<()> {
    try_symlink_two_ptrs(ctx, 16, 32)
}

#[inline(always)]
fn try_symlink_two_ptrs(
    ctx: &TracePointContext,
    oldname_offset: usize,
    newname_offset: usize,
) -> Option<()> {
    let oldname_ptr: u64 = unsafe { ctx.read_at(oldname_offset).ok()? };
    let newname_ptr: u64 = unsafe { ctx.read_at(newname_offset).ok()? };
    let mut path = [0u8; PATH_PROBE_BYTES];
    if oldname_ptr != 0 {
        match unsafe { bpf_probe_read_user_str_bytes(oldname_ptr as *const u8, &mut path) } {
            Ok(old_bytes) => {
                if is_sensitive_cred_path(old_bytes) {
                    emit_kernel_probe(
                        KERNEL_PROBE_KIND_SYMLINK,
                        KERNEL_PROBE_ACTION_AUDIT,
                        0,
                        0,
                        old_bytes,
                    );
                    return Some(());
                }
            }
            Err(_) => {
                let tid = bpf_get_current_pid_tgid() as u32;
                if tid != 0 {
                    let _ = PENDING_COLD_OPEN.insert(&tid, &COLD_PATH_SYMLINK, 0);
                }
            }
        }
    }
    if newname_ptr != 0 {
        if let Ok(new_bytes) =
            unsafe { bpf_probe_read_user_str_bytes(newname_ptr as *const u8, &mut path) }
        {
            if is_sensitive_cred_path(new_bytes) {
                emit_kernel_probe(
                    KERNEL_PROBE_KIND_SYMLINK,
                    KERNEL_PROBE_ACTION_AUDIT,
                    0,
                    0,
                    new_bytes,
                );
                return Some(());
            }
        }
    }
    None
}

#[kretprobe]
pub fn gedefense_getname_flags_ret(ctx: RetProbeContext) -> u32 {
    let _ = try_getname_flags_ret(&ctx);
    0
}

#[inline(always)]
fn try_getname_flags_ret(ctx: &RetProbeContext) -> Option<()> {
    let tid = bpf_get_current_pid_tgid() as u32;
    if tid == 0 {
        return None;
    }
    let kind_tag = unsafe { PENDING_COLD_OPEN.get(&tid).copied() }?;
    let _ = PENDING_COLD_OPEN.remove(&tid);
    let filename_struct: u64 = ctx.ret();
    if filename_struct == 0 {
        return None;
    }
    // `struct filename` begins with `struct __filename_head { const char *name; ... }`.
    // `bpf_probe_read_kernel` safely faults and returns `Err` on `ERR_PTR(-errno)`.
    let name_ptr: u64 = unsafe { bpf_probe_read_kernel(filename_struct as *const u64).ok()? };
    if name_ptr == 0 {
        return None;
    }
    let mut path = [0u8; PATH_PROBE_BYTES];
    let path_bytes =
        unsafe { bpf_probe_read_kernel_str_bytes(name_ptr as *const u8, &mut path).ok()? };
    match kind_tag {
        COLD_PATH_CRED_OPENAT => {
            let comm = bpf_get_current_comm().unwrap_or([0u8; 16]);
            let clen = comm_trimmed_len(&comm);
            if credential_reader_allowed(&comm[..clen]) || !is_cred_open_sensitive(path_bytes) {
                return None;
            }
            emit_kernel_probe(
                KERNEL_PROBE_KIND_CRED_OPENAT,
                KERNEL_PROBE_ACTION_AUDIT,
                0,
                0,
                path_bytes,
            );
        }
        COLD_PATH_SYMLINK => {
            if !is_sensitive_cred_path(path_bytes) {
                return None;
            }
            emit_kernel_probe(
                KERNEL_PROBE_KIND_SYMLINK,
                KERNEL_PROBE_ACTION_AUDIT,
                0,
                0,
                path_bytes,
            );
        }
        COLD_EXEC_FILENAME => {
            if let Some(pending_ptr) = PENDING_EXEC_ARGV.get_ptr_mut(&tid) {
                // SAFETY: map element pointer is valid within this eBPF hook execution.
                let pending = unsafe { &mut *pending_ptr };
                if pending.buf[0] == 0 {
                    let mut i = 0usize;
                    while i < EXEC_SLOT_FILENAME_END && i < path_bytes.len() {
                        let Some(&b) = path_bytes.get(i) else {
                            break;
                        };
                        pending.buf[i] = b;
                        i += 1;
                    }
                    if i < EXEC_SLOT_FILENAME_END {
                        pending.buf[i] = 0;
                    }
                }
            }
        }
        _ => {}
    }
    Some(())
}
