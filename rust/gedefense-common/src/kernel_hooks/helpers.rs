//! Action constants and the `KERNEL_HOOK_STATE` word ABI of the AP-4
//! kernel-hook contract.

/// Event action: observed/audited (the only action a producer emits).
pub const KERNEL_HOOK_ACTION_AUDIT: u8 = 1;
/// Event action: reserved for a future kernel denial. The shipped hooks are
/// observe-only and never emit it; the decoder accepts it as a closed value.
pub const KERNEL_HOOK_ACTION_DENY: u8 = 2;

/// `KERNEL_HOOK_STATE` magic byte (`K`).
pub const KERNEL_HOOK_STATE_MAGIC: u8 = 0x4b;
/// `KERNEL_HOOK_STATE` ABI version.
pub const KERNEL_HOOK_STATE_ABI: u8 = 1;
/// Armed bit inside the state word.
pub const KERNEL_HOOK_STATE_ARMED_SHIFT: u64 = 32;
/// Producer-flag bits inside the state word (7 bits).
pub const KERNEL_HOOK_STATE_FLAGS_SHIFT: u64 = 33;
/// Magic byte position inside the state word.
pub const KERNEL_HOOK_STATE_MAGIC_SHIFT: u64 = 40;
/// ABI byte position inside the state word.
pub const KERNEL_HOOK_STATE_ABI_SHIFT: u64 = 48;
/// One-byte mask for the magic/ABI bytes.
pub const KERNEL_HOOK_STATE_BYTE_MASK: u64 = 0xff;
/// Seven-bit mask for the producer flags.
pub const KERNEL_HOOK_STATE_FLAGS_MASK: u64 = 0x7f;

/// State flag: the `finit_module` kprobe attached to a direct-argument symbol
/// (`finit_module`, `__do_sys_finit_module`, `__se_sys_finit_module`), so its
/// first argument really is the module fd.
pub const KERNEL_HOOK_FLAG_FINIT_DIRECT_ARGS: u8 = 1 << 0;
/// State flag: the `delete_module` kprobe attached to a direct-argument symbol,
/// so its first argument really is the module-name user pointer.
pub const KERNEL_HOOK_FLAG_DELETE_DIRECT_ARGS: u8 = 1 << 1;

/// Per-TGID sampling window for `io_uring_submit_req` and `uring_cmd` (1 s).
pub const KERNEL_HOOK_WINDOW_NS: u64 = 1_000_000_000;
/// `KERNEL_HOOK_WINDOWS` LRU capacity (per-TGID sampling windows).
pub const KERNEL_HOOK_WINDOW_ENTRIES: u32 = 4096;

/// Packs the `KERNEL_HOOK_STATE` word (epoch | armed | flags | magic | ABI).
#[inline(always)]
pub const fn kernel_hook_state_word(epoch: u32, armed: bool, flags: u8) -> u64 {
    (epoch as u64)
        | ((armed as u64) << KERNEL_HOOK_STATE_ARMED_SHIFT)
        | (((flags & KERNEL_HOOK_FLAG_ALL) as u64) << KERNEL_HOOK_STATE_FLAGS_SHIFT)
        | ((KERNEL_HOOK_STATE_MAGIC as u64) << KERNEL_HOOK_STATE_MAGIC_SHIFT)
        | ((KERNEL_HOOK_STATE_ABI as u64) << KERNEL_HOOK_STATE_ABI_SHIFT)
}

/// Every state flag the contract currently defines.
pub const KERNEL_HOOK_FLAG_ALL: u8 =
    KERNEL_HOOK_FLAG_FINIT_DIRECT_ARGS | KERNEL_HOOK_FLAG_DELETE_DIRECT_ARGS;

/// True only for an armed, magic/ABI-valid state word. Every eBPF program calls
/// this before any payload read; absent/foreign/stale words are disarmed
/// (fail-open, no event).
#[inline(always)]
pub const fn kernel_hook_state_armed(word: u64) -> bool {
    let magic = ((word >> KERNEL_HOOK_STATE_MAGIC_SHIFT) & KERNEL_HOOK_STATE_BYTE_MASK) as u8;
    let abi = ((word >> KERNEL_HOOK_STATE_ABI_SHIFT) & KERNEL_HOOK_STATE_BYTE_MASK) as u8;
    let armed = (word >> KERNEL_HOOK_STATE_ARMED_SHIFT) & 1;
    magic == KERNEL_HOOK_STATE_MAGIC && abi == KERNEL_HOOK_STATE_ABI && armed == 1
}

/// Producer flags of an armed state word; `0` for a disarmed/foreign word.
#[inline(always)]
pub const fn kernel_hook_state_flags(word: u64) -> u8 {
    if !kernel_hook_state_armed(word) {
        return 0;
    }
    ((word >> KERNEL_HOOK_STATE_FLAGS_SHIFT) & KERNEL_HOOK_STATE_FLAGS_MASK) as u8
}
