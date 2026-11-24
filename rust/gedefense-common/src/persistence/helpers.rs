//! Event-kind/action/detail constants, the state-word and offsets ABI and
//! the closed-set predicates of the AP-5 persistence contract.

// ---------------------------------------------------------------------------
// Event kinds
// ---------------------------------------------------------------------------

/// A watched persistence path was opened (linker/PAM/systemd/udev/auth/shell).
pub const PERSIST_KIND_INTEGRITY_WRITE: u8 = 1;
/// A library was mapped into a protected executable (`sshd`/`sudo`/...).
pub const PERSIST_KIND_LIBRARY_MMAP: u8 = 2;
/// A desktop peripheral device or capture socket was opened.
pub const PERSIST_KIND_PERIPHERAL_OPEN: u8 = 3;
/// A user secret store was opened.
pub const PERSIST_KIND_SECRET_OPEN: u8 = 4;
/// `process_vm_readv`/`writev` cross-process memory access.
pub const PERSIST_KIND_MEMORY_SCRAPE: u8 = 5;
/// `ptrace_access_check` (tracer attaches to a target task).
pub const PERSIST_KIND_PTRACE_ACCESS: u8 = 6;
/// Userspace SHA-256 drift on a watched exact file.
pub const PERSIST_KIND_DRIFT: u8 = 7;
/// Userspace baseline capture marker (operator-visible reference point).
pub const PERSIST_KIND_BASELINE: u8 = 8;

// ---------------------------------------------------------------------------
// Actions
// ---------------------------------------------------------------------------

/// Audit only: the observation is evidence, the operation proceeds.
pub const PERSIST_ACTION_AUDIT: u8 = 1;
/// Reserved for future kernel enforcement; the AP-5 guard is observe-only and
/// never produces it.
pub const PERSIST_ACTION_DENY: u8 = 2;
/// Observation recorded with an explicit "no decision" semantic.
pub const PERSIST_ACTION_OBSERVE: u8 = 3;

// ---------------------------------------------------------------------------
// Detail codes / constants
// ---------------------------------------------------------------------------

/// `KIND_INTEGRITY_WRITE` detail: open access mode lower bits
/// (`O_RDONLY == 0`, `O_WRONLY == 1`, `O_RDWR == 2`).
pub const PERSIST_DETAIL_ACC_MASK: u32 = 0x3;
/// `KIND_INTEGRITY_WRITE` detail: access intent could not be resolved (the
/// `file.f_flags` offset was unavailable). The control plane must treat this as
/// the conservative "may be a write" case and say so.
pub const PERSIST_DETAIL_ACC_UNKNOWN: u32 = 0xffff_ffff;
/// `KIND_MEMORY_SCRAPE` detail slot: a `process_vm_readv` syscall.
pub const PERSIST_DETAIL_READV: [u8; 8] = *b"readv\0\0\0";
/// `KIND_MEMORY_SCRAPE` detail slot: a `process_vm_writev` syscall.
pub const PERSIST_DETAIL_WRITEV: [u8; 8] = *b"writev\0\0";
/// `KIND_PERIPHERAL_OPEN` detail bit: the process uid has a local
/// systemd-logind session (session directory was readable).
pub const PERSIST_DETAIL_SESSION_KNOWN: u32 = 1 << 0;
/// `KIND_PERIPHERAL_OPEN` detail bit: that session is active (`ACTIVE=yes`,
/// `STATE=active`). With [`PERSIST_DETAIL_SESSION_KNOWN`] clear the session
/// correlation is unavailable and must be reported as `NONE`, not guessed.
pub const PERSIST_DETAIL_SESSION_ACTIVE: u32 = 1 << 1;
/// Drift reason: file content SHA-256 changed since the baseline.
pub const PERSIST_DRIFT_CONTENT: u32 = 1;
/// Drift reason: watched file disappeared since the baseline.
pub const PERSIST_DRIFT_MISSING: u32 = 2;
/// Drift reason: watched file appeared after being absent at baseline.
pub const PERSIST_DRIFT_APPEARED: u32 = 3;
/// Drift reason: inode identity changed (file replaced/renamed).
pub const PERSIST_DRIFT_REPLACED: u32 = 4;
/// Protected executable classes (`PERSIST_GUARD_EXECS` values).
pub const PERSIST_EXEC_CLASS_SSHD: u8 = 1;
pub const PERSIST_EXEC_CLASS_SSHD_SESSION: u8 = 2;
pub const PERSIST_EXEC_CLASS_SUDO: u8 = 3;
pub const PERSIST_EXEC_CLASS_SU: u8 = 4;
pub const PERSIST_EXEC_CLASS_LOGIN: u8 = 5;
pub const PERSIST_EXEC_CLASS_CURL: u8 = 6;

// ---------------------------------------------------------------------------
// State word / offsets ABI
// ---------------------------------------------------------------------------

/// `PERSIST_GUARD_STATE` word layout (ABI 1): epoch 0..31, armed bit 32, magic
/// 40..47, ABI 48..55. An absent/zero word means "not armed": every eBPF
/// program returns its fail-open verdict and emits nothing.
pub const PERSIST_STATE_MAGIC: u8 = 0x50;
pub const PERSIST_STATE_ABI: u8 = 1;
pub const PERSIST_STATE_ARMED_SHIFT: u64 = 32;
pub const PERSIST_STATE_MAGIC_SHIFT: u64 = 40;
pub const PERSIST_STATE_ABI_SHIFT: u64 = 48;
pub const PERSIST_STATE_BYTE_MASK: u64 = 0xff;

/// `PERSIST_GUARD_OFFSETS` magic/ABI words (index 0/1); the eBPF readers refuse
/// a table without both words before they dereference anything.
pub const PERSIST_OFFSETS_MAGIC: u32 = 0x5045_5253;
pub const PERSIST_OFFSETS_ABI: u32 = 1;
/// `PERSIST_GUARD_OFFSETS` index enum shared by the core publisher and eBPF.
pub const PERSIST_OFF_MAGIC: u32 = 0;
pub const PERSIST_OFF_ABI: u32 = 1;
pub const PERSIST_OFF_FILE_OPEN_NARGS: u32 = 2;
pub const PERSIST_OFF_FILE_OPEN_PREV: u32 = 3;
pub const PERSIST_OFF_MMAP_NARGS: u32 = 4;
pub const PERSIST_OFF_MMAP_FILE_ARG: u32 = 5;
pub const PERSIST_OFF_MMAP_PROT_ARG: u32 = 6;
pub const PERSIST_OFF_MMAP_PREV: u32 = 7;
pub const PERSIST_OFF_PTRACE_NARGS: u32 = 8;
pub const PERSIST_OFF_PTRACE_CHILD_ARG: u32 = 9;
pub const PERSIST_OFF_PTRACE_MODE_ARG: u32 = 10;
pub const PERSIST_OFF_PTRACE_PREV: u32 = 11;
pub const PERSIST_OFF_FILE_F_INODE: u32 = 12;
pub const PERSIST_OFF_FILE_F_FLAGS: u32 = 13;
pub const PERSIST_OFF_FILE_SIZE: u32 = 14;
pub const PERSIST_OFF_FILE_F_PATH_DENTRY: u32 = 15;
pub const PERSIST_OFF_INODE_I_INO: u32 = 16;
pub const PERSIST_OFF_INODE_I_SB: u32 = 17;
pub const PERSIST_OFF_INODE_I_MODE: u32 = 18;
pub const PERSIST_OFF_INODE_SIZE: u32 = 19;
pub const PERSIST_OFF_SUPER_S_DEV: u32 = 20;
pub const PERSIST_OFF_SUPER_SIZE: u32 = 21;
pub const PERSIST_OFF_DENTRY_D_PARENT: u32 = 22;
pub const PERSIST_OFF_DENTRY_D_INODE: u32 = 23;
pub const PERSIST_OFF_DENTRY_SIZE: u32 = 24;
pub const PERSIST_OFF_TASK_PID: u32 = 25;
pub const PERSIST_OFF_TASK_TGID: u32 = 26;
pub const PERSIST_OFF_TASK_MM: u32 = 27;
pub const PERSIST_OFF_TASK_SIZE: u32 = 28;
pub const PERSIST_OFF_MM_EXE_FILE: u32 = 29;
pub const PERSIST_OFF_MM_SIZE: u32 = 30;
pub const PERSIST_OFF_READV_PID: u32 = 31;
pub const PERSIST_OFF_READV_TARGET: u32 = 32;
pub const PERSIST_OFF_READV_SIZE: u32 = 33;
pub const PERSIST_OFF_WRITEV_PID: u32 = 34;
pub const PERSIST_OFF_WRITEV_TARGET: u32 = 35;
pub const PERSIST_OFF_WRITEV_SIZE: u32 = 36;
/// First reserved index after the AP-5 offset set.
pub const PERSIST_OFF_RESERVED_FIRST: u32 = 37;
/// LSM hook arities the kernel ABI is validated against at runtime. The eBPF
/// programs verify the *published* values against these expectations before
/// they read a single argument slot.
pub const PERSIST_FILE_OPEN_NARGS_EXPECTED: u32 = 1;
pub const PERSIST_PTRACE_NARGS_EXPECTED: u32 = 2;
pub const PERSIST_PTRACE_CHILD_ARG: u32 = 0;
pub const PERSIST_PTRACE_MODE_ARG: u32 = 1;
pub const PERSIST_MMAP_FILE_ARG: u32 = 0;
/// Defensive bound for a published `task_struct`/`file`/`inode`/`dentry`/
/// `super_block` size and for a syscall tracepoint record extent.
pub const PERSIST_MAX_STRUCT_SIZE: u32 = 65_536;
pub const PERSIST_MAX_TRACEPOINT_BYTES: u32 = 512;

/// Packs the `PERSIST_GUARD_STATE` word (epoch | armed | magic | ABI).
#[inline(always)]
pub const fn persistence_state_word(epoch: u32, armed: bool) -> u64 {
    (epoch as u64)
        | ((armed as u64) << PERSIST_STATE_ARMED_SHIFT)
        | ((PERSIST_STATE_MAGIC as u64) << PERSIST_STATE_MAGIC_SHIFT)
        | ((PERSIST_STATE_ABI as u64) << PERSIST_STATE_ABI_SHIFT)
}

/// True only for an armed, magic/ABI-valid state word.
#[inline(always)]
pub const fn persistence_state_armed(word: u64) -> bool {
    let magic = ((word >> PERSIST_STATE_MAGIC_SHIFT) & PERSIST_STATE_BYTE_MASK) as u8;
    let abi = ((word >> PERSIST_STATE_ABI_SHIFT) & PERSIST_STATE_BYTE_MASK) as u8;
    let armed = (word >> PERSIST_STATE_ARMED_SHIFT) & 1;
    magic == PERSIST_STATE_MAGIC && abi == PERSIST_STATE_ABI && armed == 1
}

/// True for every event kind the ABI defines.
#[inline(always)]
pub const fn persistence_kind_known(kind: u8) -> bool {
    matches!(kind, 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8)
}

/// True for every action value the ABI defines.
#[inline(always)]
pub const fn persistence_action_known(action: u8) -> bool {
    matches!(
        action,
        PERSIST_ACTION_AUDIT | PERSIST_ACTION_DENY | PERSIST_ACTION_OBSERVE
    )
}
