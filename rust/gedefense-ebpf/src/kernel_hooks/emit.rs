//! Bounded event emission for the AP-4 kernel-hook ring (child module of
//! `kernel_hooks`): one 64-byte record per calling program invocation,
//! terminal-safe `comm`, per-CPU counters, no allocation.

use aya_ebpf::{
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid,
        bpf_ktime_get_ns,
    },
    maps::PerCpuArray,
};
use gedefense_common::{
    KernelHookEvent, KERNEL_HOOK_ACTION_AUDIT, KERNEL_HOOK_COMM_BYTES, KERNEL_HOOK_DETAIL_BYTES,
};

use super::{
    KERNEL_HOOK_EVENTS, KERNEL_HOOK_EVENTS_EMITTED, KERNEL_HOOK_READ_FAILURES,
    KERNEL_HOOK_RING_DROPS,
};

#[inline(always)]
pub(crate) fn increment_counter(counter: &PerCpuArray<u64>) {
    if let Some(value) = counter.get_ptr_mut(0) {
        // SAFETY: per-CPU array index 0 is owned by this CPU for this update.
        unsafe { *value = (*value).wrapping_add(1) };
    }
}

/// The decoder requires NUL-terminated printable `comm`. Kernel task names are
/// attacker-controlled (`prctl(PR_SET_NAME)`), so every control byte before the
/// NUL is replaced with `?` (terminal-injection guard for operator surfaces) and
/// a full 16-byte name is truncated to 15 bytes plus NUL.
#[inline(always)]
pub(crate) fn normalize_comm(raw: [u8; KERNEL_HOOK_COMM_BYTES]) -> [u8; KERNEL_HOOK_COMM_BYTES] {
    let mut out = [0u8; KERNEL_HOOK_COMM_BYTES];
    let mut index = 0usize;
    while index < out.len() {
        let byte = raw[index];
        if byte == 0 {
            break;
        }
        out[index] = if byte < 0x20 || byte == 0x7f || byte >= 0x80 {
            b'?'
        } else {
            byte
        };
        index += 1;
    }
    if index == out.len() {
        out[KERNEL_HOOK_COMM_BYTES - 1] = 0;
    }
    out
}

/// Emits one bounded record; exactly one event per calling program invocation.
#[inline(always)]
pub(crate) fn emit_event(kind: u8, detail_code: u32, detail: &[u8]) {
    let ts_ns = unsafe { bpf_ktime_get_ns() };
    if ts_ns == 0 {
        increment_counter(&KERNEL_HOOK_READ_FAILURES);
        return;
    }
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = pid_tgid as u32;
    let tgid = (pid_tgid >> 32) as u32;
    if pid == 0 || tgid == 0 {
        increment_counter(&KERNEL_HOOK_READ_FAILURES);
        return;
    }
    let uid_gid = bpf_get_current_uid_gid();
    let comm = match bpf_get_current_comm() {
        Ok(raw) => normalize_comm(raw),
        Err(_) => {
            increment_counter(&KERNEL_HOOK_READ_FAILURES);
            [0u8; KERNEL_HOOK_COMM_BYTES]
        }
    };
    let mut detail_bytes = [0u8; KERNEL_HOOK_DETAIL_BYTES];
    let mut detail_len = 0usize;
    while detail_len < KERNEL_HOOK_DETAIL_BYTES {
        let Some(&byte) = detail.get(detail_len) else {
            break;
        };
        detail_bytes[detail_len] = byte;
        detail_len += 1;
    }
    let event = KernelHookEvent {
        ts_ns,
        pid,
        tgid,
        uid: uid_gid as u32,
        kind,
        action: KERNEL_HOOK_ACTION_AUDIT,
        detail_len: detail_len as u8,
        reserved: 0,
        detail_code,
        detail: detail_bytes,
        comm,
    };
    if let Some(mut entry) = KERNEL_HOOK_EVENTS.reserve::<KernelHookEvent>(0) {
        // SAFETY: the reservation is exactly size_of::<KernelHookEvent>() bytes,
        // 8-aligned, written once and submitted below.
        unsafe { entry.as_mut_ptr().write(event) };
        entry.submit(0);
        increment_counter(&KERNEL_HOOK_EVENTS_EMITTED);
    } else {
        increment_counter(&KERNEL_HOOK_RING_DROPS);
    }
}
