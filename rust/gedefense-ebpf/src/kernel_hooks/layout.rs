//! Armed-state, offset and payload-read helpers of the AP-4 kernel-hook
//! sensors (child module of `kernel_hooks`). Every payload read is a bounded
//! `bpf_probe_read_kernel` at a core-published offset; an unknown or faulting
//! slot is a counted read failure, never a guessed read.

use aya_ebpf::{helpers::bpf_probe_read_kernel_str_bytes, programs::TracePointContext, EbpfContext};
use gedefense_common::{
    kernel_hook_state_armed, KERNEL_HOOK_DETAIL_BYTES, KERNEL_HOOK_MAX_RECORD_OFFSET,
    KERNEL_HOOK_OFFSET_MODULE_LOAD_NAME,
};

use super::emit::increment_counter;
use super::{KERNEL_HOOK_OFFSETS, KERNEL_HOOK_READ_FAILURES, KERNEL_HOOK_STATE};

/// Index of the single armed-state word in `KERNEL_HOOK_STATE`.
const KERNEL_HOOK_STATE_INDEX: u32 = 0;

/// Reads the armed state word. Absent/foreign/stale words are disarmed.
#[inline(always)]
pub(crate) fn state_word() -> Option<u64> {
    KERNEL_HOOK_STATE.get(KERNEL_HOOK_STATE_INDEX).copied()
}

/// True only when the core armed this hook family with the current magic/ABI.
#[inline(always)]
pub(crate) fn hooks_active() -> bool {
    match state_word() {
        Some(word) => kernel_hook_state_armed(word),
        None => false,
    }
}

/// Core-published byte offset of one tracepoint field; `0` = unknown on this
/// kernel (the caller then emits identity-only and counts a read failure).
#[inline(always)]
pub(crate) fn offset_at(slot: u32) -> u32 {
    KERNEL_HOOK_OFFSETS.get(slot).copied().unwrap_or(0)
}

/// Reads a `u32` tracepoint payload field at a core-published offset. `None`
/// (plus a read-failure count) when the layout is unknown or the read faults.
#[inline(always)]
pub(crate) fn read_payload_u32(ctx: &TracePointContext, slot: u32) -> Option<u32> {
    let offset = offset_at(slot);
    if offset == 0 {
        increment_counter(&KERNEL_HOOK_READ_FAILURES);
        return None;
    }
    match unsafe { ctx.read_at::<u32>(offset as usize) } {
        Ok(value) => Some(value),
        Err(_) => {
            increment_counter(&KERNEL_HOOK_READ_FAILURES);
            None
        }
    }
}

/// Reads a `u8` tracepoint payload field at a core-published offset.
#[inline(always)]
pub(crate) fn read_payload_u8(ctx: &TracePointContext, slot: u32) -> Option<u8> {
    let offset = offset_at(slot);
    if offset == 0 {
        increment_counter(&KERNEL_HOOK_READ_FAILURES);
        return None;
    }
    match unsafe { ctx.read_at::<u8>(offset as usize) } {
        Ok(value) => Some(value),
        Err(_) => {
            increment_counter(&KERNEL_HOOK_READ_FAILURES);
            None
        }
    }
}

/// Resolves the `__data_loc char[] name` module name from a tracepoint record:
/// the 32-bit data_loc value carries the name's byte offset in its low 16 bits.
/// Bounded by [`KERNEL_HOOK_MAX_RECORD_OFFSET`]; a fault or an unknown layout is
/// a counted read failure, never a guessed read.
#[inline(always)]
pub(crate) fn read_module_name(ctx: &TracePointContext, detail: &mut [u8; KERNEL_HOOK_DETAIL_BYTES]) -> usize {
    let Some(data_loc) = read_payload_u32(ctx, KERNEL_HOOK_OFFSET_MODULE_LOAD_NAME) else {
        return 0;
    };
    let name_offset = data_loc & 0xffff;
    if name_offset == 0 || name_offset > KERNEL_HOOK_MAX_RECORD_OFFSET {
        increment_counter(&KERNEL_HOOK_READ_FAILURES);
        return 0;
    }
    let base: *const u8 = ctx.as_ptr().cast::<u8>();
    let source = unsafe { base.add(name_offset as usize) };
    match unsafe { bpf_probe_read_kernel_str_bytes(source, &mut detail[..]) } {
        Ok(name) => name.len(),
        Err(_) => {
            increment_counter(&KERNEL_HOOK_READ_FAILURES);
            0
        }
    }
}
