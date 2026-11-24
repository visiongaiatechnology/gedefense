//! Per-TGID sampling window of the high-frequency AP-4 hooks (`submit_req`,
//! `uring_cmd`; child module of `kernel_hooks`): one bounded LRU keyed by
//! `(tgid, kind)`; a suppressed invocation is intentional sampling, not a drop.

use aya_ebpf::helpers::bpf_ktime_get_ns;
use gedefense_common::KERNEL_HOOK_WINDOW_NS;

use super::emit::increment_counter;
use super::{KERNEL_HOOK_READ_FAILURES, KERNEL_HOOK_WINDOWS};

/// One-event-per-TGID-per-window gate (LRU bounded). A suppressed invocation is
/// intentional sampling, not a ring drop.
#[inline(always)]
pub(crate) fn window_allows(tgid: u32, kind: u8) -> bool {
    let now = unsafe { bpf_ktime_get_ns() };
    if now == 0 {
        increment_counter(&KERNEL_HOOK_READ_FAILURES);
        return false;
    }
    let key = ((tgid as u64) << 8) | (kind as u64);
    let previous = unsafe { KERNEL_HOOK_WINDOWS.get(&key) }
        .copied()
        .unwrap_or(0);
    if previous != 0 && now.wrapping_sub(previous) < KERNEL_HOOK_WINDOW_NS {
        return false;
    }
    let _ = KERNEL_HOOK_WINDOWS.insert(&key, &now, 0);
    true
}
