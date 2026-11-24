//! `io_uring` tracepoint bodies of the AP-4 kernel-hook sensors (child module
//! of `kernel_hooks`); the public `#[tracepoint]` entry points stay in the
//! parent module.

use aya_ebpf::{helpers::bpf_get_current_pid_tgid, programs::TracePointContext};
use gedefense_common::{
    KERNEL_HOOK_DETAIL_BYTES, KERNEL_HOOK_KIND_IO_URING_CREATE, KERNEL_HOOK_KIND_IO_URING_REGISTER,
    KERNEL_HOOK_KIND_IO_URING_SUBMIT, KERNEL_HOOK_OFFSET_IO_URING_CREATE_FD,
    KERNEL_HOOK_OFFSET_IO_URING_CREATE_FLAGS, KERNEL_HOOK_OFFSET_IO_URING_REGISTER_NR_FILES,
    KERNEL_HOOK_OFFSET_IO_URING_REGISTER_OPCODE, KERNEL_HOOK_OFFSET_IO_URING_SUBMIT_OPCODE,
};

use super::emit::{emit_event, increment_counter};
use super::layout::{hooks_active, read_payload_u32, read_payload_u8};
use super::window::window_allows;
use super::{KERNEL_HOOK_READ_FAILURES, KERNEL_HOOK_RING_CREATES};

#[inline(always)]
pub(crate) fn try_io_uring_create(ctx: &TracePointContext) -> Option<()> {
    if !hooks_active() {
        return None;
    }
    increment_counter(&KERNEL_HOOK_RING_CREATES);
    let fd = read_payload_u32(ctx, KERNEL_HOOK_OFFSET_IO_URING_CREATE_FD).unwrap_or(0);
    let mut detail = [0u8; KERNEL_HOOK_DETAIL_BYTES];
    let mut detail_len = 0usize;
    if let Some(flags) = read_payload_u32(ctx, KERNEL_HOOK_OFFSET_IO_URING_CREATE_FLAGS) {
        detail[0..4].copy_from_slice(&flags.to_ne_bytes());
        detail_len = 4;
    }
    emit_event(
        KERNEL_HOOK_KIND_IO_URING_CREATE,
        fd,
        &detail[..detail_len],
    );
    Some(())
}

#[inline(always)]
pub(crate) fn try_io_uring_register(ctx: &TracePointContext) -> Option<()> {
    if !hooks_active() {
        return None;
    }
    let opcode = read_payload_u32(ctx, KERNEL_HOOK_OFFSET_IO_URING_REGISTER_OPCODE).unwrap_or(0);
    let mut detail = [0u8; KERNEL_HOOK_DETAIL_BYTES];
    let mut detail_len = 0usize;
    if let Some(nr_files) = read_payload_u32(ctx, KERNEL_HOOK_OFFSET_IO_URING_REGISTER_NR_FILES) {
        detail[0..4].copy_from_slice(&nr_files.to_ne_bytes());
        detail_len = 4;
    }
    emit_event(
        KERNEL_HOOK_KIND_IO_URING_REGISTER,
        opcode,
        &detail[..detail_len],
    );
    Some(())
}

#[inline(always)]
pub(crate) fn try_io_uring_submit_req(ctx: &TracePointContext) -> Option<()> {
    if !hooks_active() {
        return None;
    }
    let pid_tgid = bpf_get_current_pid_tgid();
    let tgid = (pid_tgid >> 32) as u32;
    if tgid == 0 {
        increment_counter(&KERNEL_HOOK_READ_FAILURES);
        return None;
    }
    if !window_allows(tgid, KERNEL_HOOK_KIND_IO_URING_SUBMIT) {
        return None;
    }
    let opcode = read_payload_u8(ctx, KERNEL_HOOK_OFFSET_IO_URING_SUBMIT_OPCODE)
        .map(u32::from)
        .unwrap_or(0);
    emit_event(KERNEL_HOOK_KIND_IO_URING_SUBMIT, opcode, &[]);
    Some(())
}
