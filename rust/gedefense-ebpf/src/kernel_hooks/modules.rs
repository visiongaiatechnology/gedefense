//! `module/load` tracepoint and module-syscall kprobe bodies of the AP-4
//! kernel-hook sensors (child module of `kernel_hooks`); the public
//! `#[tracepoint]`/`#[kprobe]` entry points stay in the parent module.

use aya_ebpf::{
    helpers::bpf_probe_read_user_str_bytes,
    programs::{ProbeContext, TracePointContext},
};
use gedefense_common::{
    kernel_hook_state_armed, kernel_hook_state_flags, KERNEL_HOOK_DETAIL_BYTES,
    KERNEL_HOOK_FLAG_DELETE_DIRECT_ARGS, KERNEL_HOOK_FLAG_FINIT_DIRECT_ARGS,
    KERNEL_HOOK_KIND_LKM_TAINT, KERNEL_HOOK_KIND_MODULE_LOAD,
    KERNEL_HOOK_OFFSET_MODULE_LOAD_TAINTS,
};

use super::emit::{emit_event, increment_counter};
use super::layout::{hooks_active, read_module_name, read_payload_u32, state_word};
use super::sec_crit_duplicate_lkm;
use super::{KERNEL_HOOK_MODULE_LOADS, KERNEL_HOOK_READ_FAILURES};

#[inline(always)]
pub(crate) fn try_module_load(ctx: &TracePointContext) -> Option<()> {
    if !hooks_active() {
        return None;
    }
    increment_counter(&KERNEL_HOOK_MODULE_LOADS);
    let taints =
        read_payload_u32(ctx, KERNEL_HOOK_OFFSET_MODULE_LOAD_TAINTS).unwrap_or(0);
    let mut detail = [0u8; KERNEL_HOOK_DETAIL_BYTES];
    let detail_len = read_module_name(ctx, &mut detail);
    // A tainted load (unsigned/out-of-tree/forced module) is the more precise
    // signal; the module name is carried either way.
    let kind = if taints == 0 {
        KERNEL_HOOK_KIND_MODULE_LOAD
    } else {
        KERNEL_HOOK_KIND_LKM_TAINT
    };
    emit_event(kind, taints, &detail[..detail_len]);
    // V6.3.0 AP-9 (S12): module loads are critical evidence; the independent
    // ring receives the taint mask + a bounded name prefix in `extra`.
    sec_crit_duplicate_lkm(taints, &detail[..detail_len]);
    Some(())
}

/// Shared body of the three module-syscall kprobes. `carry_fd`/`carry_name` are
/// gated on the core-published kprobe tier flags: the syscall wrapper receives
/// a `struct pt_regs *` instead of the real arguments, so a raw argument read
/// would be wrong and is therefore never attempted on that tier.
#[inline(always)]
pub(crate) fn try_module_kprobe(
    ctx: &ProbeContext,
    kind: u8,
    carry_fd: bool,
    carry_name: bool,
) -> Option<()> {
    let word = state_word()?;
    if !kernel_hook_state_armed(word) {
        return None;
    }
    let flags = kernel_hook_state_flags(word);
    let mut detail = [0u8; KERNEL_HOOK_DETAIL_BYTES];
    let mut detail_len = 0usize;
    let mut detail_code = 0u32;
    if carry_fd && flags & KERNEL_HOOK_FLAG_FINIT_DIRECT_ARGS != 0 {
        let fd: u64 = ctx.arg(0)?;
        detail_code = fd as u32;
    }
    if carry_name && flags & KERNEL_HOOK_FLAG_DELETE_DIRECT_ARGS != 0 {
        let name_ptr: u64 = ctx.arg(0)?;
        if name_ptr != 0 {
            match unsafe { bpf_probe_read_user_str_bytes(name_ptr as *const u8, &mut detail[..]) } {
                Ok(name) => detail_len = name.len(),
                Err(_) => increment_counter(&KERNEL_HOOK_READ_FAILURES),
            }
        }
        if let Some(unload_flags) = ctx.arg::<u64>(1) {
            detail_code = unload_flags as u32;
        }
    }
    emit_event(kind, detail_code, &detail[..detail_len]);
    // V6.3.0 AP-9 (S12): pre-stealth module syscall capture is critical
    // evidence. The kernel taint mask is unknown on this tier (0) and the
    // module name is only carried when the core attached a direct-argument
    // symbol; both limits are documented and never guessed.
    let name: &[u8] = if carry_name {
        &detail[..detail_len]
    } else {
        &[]
    };
    sec_crit_duplicate_lkm(0, name);
    Some(())
}
