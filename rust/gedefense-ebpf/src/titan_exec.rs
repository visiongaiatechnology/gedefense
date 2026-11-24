use aya_ebpf::{
    helpers::{
        bpf_get_current_ancestor_cgroup_id, bpf_get_current_cgroup_id, bpf_get_current_comm,
        bpf_get_current_pid_tgid, bpf_get_current_uid_gid, bpf_ktime_get_ns,
        bpf_probe_read_kernel, bpf_probe_read_kernel_str_bytes,
    },
    macros::lsm,
    programs::LsmContext,
};
use gedefense_common::{
    kernel_s_dev_to_stat_u32, strip_ctime_queried_flag, EXEC_COMM_BYTES,
    TITAN_EXEC_ACTION_AUDIT, TITAN_EXEC_ACTION_DENY, TITAN_EXEC_HOOK_BPRM, TITAN_EXEC_HOOK_MMAP,
    TITAN_EXEC_MODE_OFF, TITAN_EXEC_MODE_OBSERVE, TITAN_EXEC_MODE_STRICT,
    TITAN_EXEC_MODE_UNTRUSTED, TITAN_EXEC_OFFSETS_ABI, TITAN_EXEC_OFFSETS_MAGIC,
    TITAN_EXEC_REASON_ANON_NO_JIT, TITAN_EXEC_REASON_CTIME_MISMATCH, TITAN_EXEC_REASON_FS_HARD,
    TITAN_EXEC_REASON_MEMFD, TITAN_EXEC_REASON_NON_ROOT_OWNER, TITAN_EXEC_REASON_NOT_ALLOWLISTED,
    TITAN_EXEC_REASON_READ_FAILURE, TITAN_EXEC_REASON_TMPFS, TITAN_EXEC_REASON_UNLINKED,
    TITAN_EXEC_REASON_UNTRUSTED_PATH, TITAN_EXEC_REASON_WORLD_WRITABLE_PATH,
    TITAN_EXEC_REASON_WX, TITAN_EXEC_SCOPE_FLAG_JIT_ALLOW, TITAN_EXEC_STATE_ABI,
    TITAN_EXEC_STATE_MAGIC, TitanExecEvent,
};
use crate::maps::{
    TITAN_EXEC_CTIME_REJECTS, TITAN_EXEC_EVENTS, TITAN_EXEC_EVENTS_EMITTED, TITAN_EXEC_MODE,
    TITAN_EXEC_OFFSETS, TITAN_EXEC_POLICY, TITAN_EXEC_POLICY_AUDITS, TITAN_EXEC_POLICY_DENIES,
    TITAN_EXEC_READ_FAILURES, TITAN_EXEC_RING_DROPS, TITAN_EXEC_STATE,
};
use crate::util::{increment_counter, EPERM, MAX_CGROUP_ANCESTOR_LEVELS, NS_PER_SECOND};

// ---------------------------------------------------------------------------
// Point 1 (Phase 1): Titan exec/library gate.
//
// Contract: docs/POINT1-TITAN-EXEC-GATE.md §4 (map ABI-2) and §4.2 (decision
// semantics). The map names, key/value byte layouts and max_entries below are
// looked up by name from rust/gedefense-core; do not rename or reshape them.
//
// The verifier forbids variable offsets on a BPF context, so the LSM ctx slots
// are fixed compile-time hook ABI values (`LSM_HOOK` definitions) and the
// core-provided §4.1 argument indices are used to *validate* that ABI before
// any decision. Kernel structures are read exclusively through
// `bpf_probe_read_kernel` with runtime offsets from `TITAN_EXEC_OFFSETS`: the
// pointer is treated as a scalar and the helper performs the bounded read.
// ---------------------------------------------------------------------------

/// Maximum number of per-cgroup exec-gate scopes (§4).
pub(crate) const MAX_TITAN_EXEC_SCOPES: u32 = 4_096;
/// Maximum number of inode-policy entries (§4).
pub(crate) const MAX_TITAN_EXEC_POLICIES: u32 = 65_536;
/// `TITAN_EXEC_OFFSETS` entry count (§4.1: 28 used, 28..47 reserved).
pub(crate) const TITAN_EXEC_OFFSETS_ENTRIES: u32 = 48;
/// `TITAN_EXEC_EVENTS` ring size: 1 MiB (§4).
pub(crate) const TITAN_EXEC_EVENT_RING_BYTES: u32 = 1 << 20;
/// `TITAN_EXEC_STATE` has exactly one word at index 0 (§4).
const TITAN_EXEC_STATE_INDEX: u32 = 0;
/// `TITAN_EXEC_STATE` bit layout (§4): epoch 0..31, mode 32..39, flags 40..47,
/// abi 48..55, magic 56..63.
const TITAN_EXEC_STATE_MODE_SHIFT: u64 = 32;
const TITAN_EXEC_STATE_FLAGS_SHIFT: u64 = 40;
const TITAN_EXEC_STATE_ABI_SHIFT: u64 = 48;
const TITAN_EXEC_STATE_MAGIC_SHIFT: u64 = 56;
const TITAN_EXEC_STATE_BYTE_MASK: u64 = 0xff;
/// STATE flag bit2 `ctime_check_enabled` (§4); part of the REQUIRE_CTIME
/// source agreed with the core (STATE bit2 AND policy value flag bit0).
const TITAN_EXEC_STATE_FLAG_CTIME_CHECK: u8 = 1 << 2;
/// `TITAN_EXEC_MODE` value layout agreed with the core (§4 is otherwise
/// ambiguous with `JIT_ALLOW = 1<<0`): mode bits 2..3, scope flag bit0.
const TITAN_EXEC_SCOPE_MODE_SHIFT: u8 = 2;
const TITAN_EXEC_SCOPE_MODE_MASK: u8 = 0x03;
/// `TITAN_EXEC_POLICY` value layout (§4): action u8, flags u8, reserved u16,
/// ctime_ns u64 LE at byte 4 (packed 1+1+2 = 4, then 8 bytes, then pad 4).
const TITAN_EXEC_POLICY_ACTION_ALLOW: u8 = 1;
const TITAN_EXEC_POLICY_FLAG_REQUIRE_CTIME: u8 = 1 << 0;
const TITAN_EXEC_POLICY_ACTION_OFFSET: usize = 0;
const TITAN_EXEC_POLICY_FLAGS_OFFSET: usize = 1;
const TITAN_EXEC_POLICY_CTIME_OFFSET: usize = 4;
/// uapi `PROT_*` bits relevant to the mmap gate.
const PROT_WRITE: u32 = 0x2;
const PROT_EXEC: u32 = 0x4;
/// Defensive upper bound for the core-provided structure sizes (§4.1 indexes
/// 25..27); a value above it can only come from a partial/stale offsets map.
const TITAN_EXEC_MAX_STRUCT_SIZE: u32 = 65_536;
/// UNTRUSTED mode (§4.2 ABI 2): first 15 path bytes are enough to recognise the
/// three drop-root prefixes (`/tmp/`, `/var/tmp/`, `/dev/shm/`); the read is a
/// bounded kernel string helper, never a pointer dereference.
const TITAN_UNTRUSTED_PATH_BYTES: usize = 16;
/// Bounded `dentry -> d_parent` ancestor walk of the UNTRUSTED mode. Four levels
/// cover the documented drop layouts (`/tmp/dir/file`, `/var/www/uploads/x`)
/// without an unbounded loop; deeper nesting is caught by the drop-root prefix
/// check and the non-root-owner rule.
const TITAN_UNTRUSTED_ANCESTOR_LEVELS: u8 = 4;
/// `S_IWOTH`: a world-writable executable or any world-writable directory among
/// the first four ancestors is exactly the shared drop-path pattern (/tmp,
/// /var/tmp, /dev/shm, a 0777 upload directory); the sticky bit is irrelevant
/// for the refusal because both variants are untrusted for execution.
const TITAN_S_IWOTH: u16 = 0o002;
const UNTRUSTED_ROOT_TMP: &[u8] = b"/tmp/";
const UNTRUSTED_ROOT_VAR_TMP: &[u8] = b"/var/tmp/";
const UNTRUSTED_ROOT_DEV_SHM: &[u8] = b"/dev/shm/";

/// `TITAN_EXEC_OFFSETS` index enum (§4.1): the core resolves these from vmlinux
/// BTF and validates them; eBPF re-checks everything it dereferences.
const TITAN_OFF_MAGIC: u32 = 0;
const TITAN_OFF_ABI: u32 = 1;
const TITAN_OFF_BPRM_FILE: u32 = 2;
const TITAN_OFF_FILE_INODE: u32 = 3;
const TITAN_OFF_INODE_INO: u32 = 4;
const TITAN_OFF_INODE_SB: u32 = 5;
const TITAN_OFF_INODE_NLINK: u32 = 6;
const TITAN_OFF_INODE_MODE: u32 = 7;
const TITAN_OFF_INODE_GEN: u32 = 8;
const TITAN_OFF_SB_DEV: u32 = 9;
const TITAN_OFF_SB_MAGIC: u32 = 10;
const TITAN_OFF_INODE_CTIME_SEC: u32 = 11;
const TITAN_OFF_INODE_CTIME_NSEC: u32 = 12;
const TITAN_OFF_BPRM_NARGS: u32 = 13;
const TITAN_OFF_MMAP_NARGS: u32 = 14;
const TITAN_OFF_MMAP_FILE_ARG: u32 = 15;
const TITAN_OFF_MMAP_PROT_ARG: u32 = 16;
const TITAN_OFF_TMPFS_MAGIC: u32 = 18;
const TITAN_OFF_DEVTMPFS_MAGIC: u32 = 19;
const TITAN_OFF_PROC_MAGIC: u32 = 20;
const TITAN_OFF_SYSFS_MAGIC: u32 = 21;
const TITAN_OFF_BPRM_RETVAL_SLOT: u32 = 23;
const TITAN_OFF_MMAP_RETVAL_SLOT: u32 = 24;
const TITAN_OFF_INODE_SIZE: u32 = 25;
const TITAN_OFF_FILE_SIZE: u32 = 26;
const TITAN_OFF_BPRM_SIZE: u32 = 27;
/// Kernels 6.18/7.0 split `i_ctime` into `i_ctime_sec` (8 B) plus
/// `i_ctime_nsec` (4 B); older kernels keep the `timespec64` pair (8 B each).
/// The core reports the nsec half's width in this §4.1 entry (4 or 8).
const TITAN_OFF_INODE_CTIME_NSEC_WIDTH: u32 = 28;
/// §4.1 ABI 2 (6.2.0): UNTRUSTED-mode facts — `linux_binprm.filename`,
/// `inode.i_uid`, `file.f_path.dentry`, `dentry.d_parent`, `dentry.d_inode` and
/// the `struct dentry` size.
const TITAN_OFF_BPRM_FILENAME: u32 = 29;
const TITAN_OFF_INODE_I_UID: u32 = 30;
const TITAN_OFF_FILE_F_PATH_DENTRY: u32 = 31;
const TITAN_OFF_DENTRY_D_PARENT: u32 = 32;
const TITAN_OFF_DENTRY_D_INODE: u32 = 33;
const TITAN_OFF_DENTRY_SIZE: u32 = 34;
const TITAN_CTIME_NSEC_WIDTH_32: u32 = 4;
const TITAN_CTIME_NSEC_WIDTH_64: u32 = 8;
/// LSM ctx slots of the two hooks: compile-time kernel ABI, validated against
/// the core's §4.1 argument indices (BPRM_NARGS/MMAP_NARGS/…_ARG_IDX) first.
const TITAN_LSM_BPRM_FILE_ARG: usize = 0;
const TITAN_LSM_BPRM_PREVIOUS_ARG: usize = 1;
const TITAN_LSM_MMAP_FILE_ARG: usize = 0;
const TITAN_LSM_MMAP_PROT_ARG: usize = 2;
const TITAN_LSM_MMAP_PREVIOUS_ARG: usize = 4;
const TITAN_BPRM_NARGS: u32 = 1;
const TITAN_MMAP_NARGS: u32 = 4;
/// The previous-LSM return value is always the slot right after the hook args.
const _: () = assert!(TITAN_LSM_BPRM_PREVIOUS_ARG == TITAN_BPRM_NARGS as usize);
const _: () = assert!(TITAN_LSM_MMAP_PREVIOUS_ARG == TITAN_MMAP_NARGS as usize);

// ---------------------------------------------------------------------------
// Point 1 (Phase 1): Titan exec/library gate — §4.2 decision engine.
//
// Failure contract (§4.2): every offsets/read failure is fail-safe (allow 0),
// but never silent: TITAN_EXEC_READ_FAILURES increases and one AUDIT event with
// reason READ_FAILURE is emitted. The only deny value is -EPERM (same LSM
// semantics as the pre-existing socket_create cell gate).
// ---------------------------------------------------------------------------

/// Global gate state decoded from `TITAN_EXEC_STATE` (§4).
#[derive(Clone, Copy)]
struct TitanGlobal {
    mode: u8,
    flags: u8,
}

/// Per-cgroup gate scope resolved from `TITAN_EXEC_MODE` (§4/§4.2).
#[derive(Clone, Copy)]
struct TitanScope {
    mode: u8,
    jit_allow: bool,
    cgroup_id: u64,
    /// True when the mode came from a per-cgroup scope instead of the global word.
    matched: bool,
}

/// File/inode identity of the executable under evaluation. The `inode`/`sb`
/// pointers stay internal to the read chain (the event carries no pointers);
/// `dev`/`ino` are the §4 policy key.
#[derive(Clone, Copy)]
struct TitanFile {
    dev: u32,
    inode_mode: u32,
    ino: u64,
    generation: u32,
    inode: u64,
    sb: u64,
    /// `struct file *` itself: needed for `f_path.dentry` in UNTRUSTED mode.
    file_ptr: u64,
}

/// §4.2 ABI 2 UNTRUSTED-mode facts of one executable. All three are lifted by a
/// configured `TITAN_EXEC_POLICY` allow entry, exactly like the CONTAIN rules.
#[derive(Clone, Copy, Default)]
struct TitanUntrusted {
    /// `bprm->filename` starts with `/tmp/`, `/var/tmp/` or `/dev/shm/`.
    path_denied: bool,
    /// `inode.i_uid != 0` (the file itself is not root-owned).
    non_root_owner: bool,
    /// The file or one of its first four ancestor directories is world-writable.
    world_writable_path: bool,
}

/// CONTAIN rules need the link count and the super-block magic; STRICT does not.
#[derive(Clone, Copy)]
struct TitanContainment {
    nlink: u32,
    fs_magic: u32,
}

/// Decoded `TITAN_EXEC_POLICY` value (§4); only action == ALLOW counts.
#[derive(Clone, Copy)]
struct TitanPolicy {
    allow: bool,
    require_ctime: bool,
    ctime_ns: u64,
}

/// Runtime offset table re-read from `TITAN_EXEC_OFFSETS` (§4.1).
#[derive(Clone, Copy)]
pub(crate) struct TitanOffsets {
    pub(crate) bprm_file: u32,
    pub(crate) file_inode: u32,
    pub(crate) inode_ino: u32,
    pub(crate) inode_sb: u32,
    inode_nlink: u32,
    pub(crate) inode_mode: u32,
    inode_gen: u32,
    pub(crate) sb_dev: u32,
    sb_magic: u32,
    ctime_sec: u32,
    ctime_nsec: u32,
    /// Width of the nsec half in bytes (4 or 8, §4.1 index 28).
    ctime_nsec_width: u32,
    tmpfs_magic: u32,
    devtmpfs_magic: u32,
    proc_magic: u32,
    sysfs_magic: u32,
    /// §4.1 ABI 2 (UNTRUSTED mode) offsets.
    bprm_filename: u32,
    inode_uid: u32,
    pub(crate) file_f_path_dentry: u32,
    pub(crate) dentry_parent: u32,
    pub(crate) dentry_inode: u32,
    dentry_size: u32,
}

/// Reads one `TITAN_EXEC_OFFSETS` entry; an absent array slot is a read failure.
#[inline(always)]
fn titan_offset(index: u32) -> Option<u32> {
    TITAN_EXEC_OFFSETS.get(index).copied()
}

/// Reads and validates the §4.1 offset table. Returns `None` for every
/// partial/stale/inconsistent table, so callers fail open with a READ_FAILURE
/// event instead of reading a kernel structure at a guessed offset.
#[inline(always)]
pub(crate) fn titan_offsets() -> Option<TitanOffsets> {
    if titan_offset(TITAN_OFF_MAGIC)? != TITAN_EXEC_OFFSETS_MAGIC {
        return None;
    }
    if titan_offset(TITAN_OFF_ABI)? != TITAN_EXEC_OFFSETS_ABI {
        return None;
    }
    let bprm_size = titan_offset(TITAN_OFF_BPRM_SIZE)?;
    let file_size = titan_offset(TITAN_OFF_FILE_SIZE)?;
    let inode_size = titan_offset(TITAN_OFF_INODE_SIZE)?;
    // §4.1 index 28: only the two documented nsec widths are valid. A missing or
    // unknown width would make the ctime comparison read a neighbouring field.
    let ctime_nsec_width = titan_offset(TITAN_OFF_INODE_CTIME_NSEC_WIDTH)?;
    if ctime_nsec_width != TITAN_CTIME_NSEC_WIDTH_32
        && ctime_nsec_width != TITAN_CTIME_NSEC_WIDTH_64
    {
        return None;
    }
    let offsets = TitanOffsets {
        bprm_file: titan_offset(TITAN_OFF_BPRM_FILE)?,
        file_inode: titan_offset(TITAN_OFF_FILE_INODE)?,
        inode_ino: titan_offset(TITAN_OFF_INODE_INO)?,
        inode_sb: titan_offset(TITAN_OFF_INODE_SB)?,
        inode_nlink: titan_offset(TITAN_OFF_INODE_NLINK)?,
        inode_mode: titan_offset(TITAN_OFF_INODE_MODE)?,
        inode_gen: titan_offset(TITAN_OFF_INODE_GEN)?,
        sb_dev: titan_offset(TITAN_OFF_SB_DEV)?,
        sb_magic: titan_offset(TITAN_OFF_SB_MAGIC)?,
        ctime_sec: titan_offset(TITAN_OFF_INODE_CTIME_SEC)?,
        ctime_nsec: titan_offset(TITAN_OFF_INODE_CTIME_NSEC)?,
        ctime_nsec_width,
        tmpfs_magic: titan_offset(TITAN_OFF_TMPFS_MAGIC)?,
        devtmpfs_magic: titan_offset(TITAN_OFF_DEVTMPFS_MAGIC)?,
        proc_magic: titan_offset(TITAN_OFF_PROC_MAGIC)?,
        sysfs_magic: titan_offset(TITAN_OFF_SYSFS_MAGIC)?,
        bprm_filename: titan_offset(TITAN_OFF_BPRM_FILENAME)?,
        inode_uid: titan_offset(TITAN_OFF_INODE_I_UID)?,
        file_f_path_dentry: titan_offset(TITAN_OFF_FILE_F_PATH_DENTRY)?,
        dentry_parent: titan_offset(TITAN_OFF_DENTRY_D_PARENT)?,
        dentry_inode: titan_offset(TITAN_OFF_DENTRY_D_INODE)?,
        dentry_size: titan_offset(TITAN_OFF_DENTRY_SIZE)?,
    };
    // Every runtime offset must place the complete field inside the structure
    // size the core resolved from BTF; a zero/garbage size is invalid as well.
    if bprm_size > TITAN_EXEC_MAX_STRUCT_SIZE
        || file_size > TITAN_EXEC_MAX_STRUCT_SIZE
        || inode_size > TITAN_EXEC_MAX_STRUCT_SIZE
        || !titan_field_fits(offsets.bprm_file, 8, bprm_size)
        || !titan_field_fits(offsets.file_inode, 8, file_size)
        || !titan_field_fits(offsets.inode_ino, 8, inode_size)
        || !titan_field_fits(offsets.inode_sb, 8, inode_size)
        || !titan_field_fits(offsets.inode_nlink, 4, inode_size)
        || !titan_field_fits(offsets.inode_mode, 2, inode_size)
        || !titan_field_fits(offsets.inode_gen, 4, inode_size)
        || !titan_field_fits(offsets.ctime_sec, 8, inode_size)
        || !titan_field_fits(
            offsets.ctime_nsec,
            u64::from(offsets.ctime_nsec_width),
            inode_size,
        )
        // §4.1 ABI 2 (UNTRUSTED mode): the six new entries must fit the real
        // structure sizes and the dentry size must be a plausible struct.
        || !titan_field_fits(offsets.bprm_filename, 8, bprm_size)
        || !titan_field_fits(offsets.inode_uid, 4, inode_size)
        || !titan_field_fits(offsets.file_f_path_dentry, 8, file_size)
        || offsets.dentry_size == 0
        || offsets.dentry_size > TITAN_EXEC_MAX_STRUCT_SIZE
        || !titan_field_fits(offsets.dentry_parent, 8, offsets.dentry_size)
        || !titan_field_fits(offsets.dentry_inode, 8, offsets.dentry_size)
        // §4.1 has no super_block size entry; bound the two fields defensively.
        || offsets.sb_dev > TITAN_EXEC_MAX_STRUCT_SIZE
        || offsets.sb_magic > TITAN_EXEC_MAX_STRUCT_SIZE
    {
        return None;
    }
    Some(offsets)
}

#[inline(always)]
fn titan_field_fits(offset: u32, width: u64, size: u32) -> bool {
    u64::from(offset).saturating_add(width) <= u64::from(size)
}

/// The kernel-side LSM ctx ABI is compile-time (the verifier has to know each
/// slot); the core's §4.1 argument indices are the mandate to run. If they do
/// not describe exactly this ABI, the gate fails open instead of enforcing a
/// decision made from the wrong slot.
#[inline(always)]
fn titan_arguments_match(hook: u8) -> bool {
    if hook == TITAN_EXEC_HOOK_BPRM {
        titan_offset(TITAN_OFF_BPRM_NARGS) == Some(TITAN_BPRM_NARGS)
            && titan_offset(TITAN_OFF_BPRM_RETVAL_SLOT)
                == Some(TITAN_LSM_BPRM_PREVIOUS_ARG as u32)
    } else {
        titan_offset(TITAN_OFF_MMAP_NARGS) == Some(TITAN_MMAP_NARGS)
            && titan_offset(TITAN_OFF_MMAP_FILE_ARG) == Some(TITAN_LSM_MMAP_FILE_ARG as u32)
            && titan_offset(TITAN_OFF_MMAP_PROT_ARG) == Some(TITAN_LSM_MMAP_PROT_ARG as u32)
            && titan_offset(TITAN_OFF_MMAP_RETVAL_SLOT)
                == Some(TITAN_LSM_MMAP_PREVIOUS_ARG as u32)
    }
}

/// Decodes `TITAN_EXEC_STATE`; `None` for an absent/uninitialised word and for
/// a magic/ABI mismatch or an out-of-range mode (§4: fail-safe, counter).
#[inline(always)]
fn titan_global() -> Option<TitanGlobal> {
    let word = *TITAN_EXEC_STATE.get(TITAN_EXEC_STATE_INDEX)?;
    let magic = ((word >> TITAN_EXEC_STATE_MAGIC_SHIFT) & TITAN_EXEC_STATE_BYTE_MASK) as u8;
    let abi = ((word >> TITAN_EXEC_STATE_ABI_SHIFT) & TITAN_EXEC_STATE_BYTE_MASK) as u8;
    let mode = ((word >> TITAN_EXEC_STATE_MODE_SHIFT) & TITAN_EXEC_STATE_BYTE_MASK) as u8;
    let flags = ((word >> TITAN_EXEC_STATE_FLAGS_SHIFT) & TITAN_EXEC_STATE_BYTE_MASK) as u8;
    if magic != TITAN_EXEC_STATE_MAGIC || abi != TITAN_EXEC_STATE_ABI
        || mode > TITAN_EXEC_MODE_UNTRUSTED
    {
        return None;
    }
    Some(TitanGlobal { mode, flags })
}

/// Resolves the effective mode/flags: first ancestor scope hit wins (cell-root
/// scope, children inherit §4.2), otherwise the global mode. The walk reuses
/// the bounded Level 0..63 pattern of the pre-existing socket_create hook.
#[inline(always)]
fn titan_scope(global_mode: u8) -> TitanScope {
    let mut level: i32 = 0;
    while level < MAX_CGROUP_ANCESTOR_LEVELS {
        let cgroup_id = unsafe { bpf_get_current_ancestor_cgroup_id(level) };
        if cgroup_id == 0 {
            break;
        }
        if let Some(raw) = unsafe { TITAN_EXEC_MODE.get(&cgroup_id) } {
            return TitanScope {
                mode: (*raw >> TITAN_EXEC_SCOPE_MODE_SHIFT) & TITAN_EXEC_SCOPE_MODE_MASK,
                jit_allow: (*raw & TITAN_EXEC_SCOPE_FLAG_JIT_ALLOW) != 0,
                cgroup_id,
                matched: true,
            };
        }
        level += 1;
    }
    TitanScope {
        mode: global_mode,
        jit_allow: false,
        cgroup_id: unsafe { bpf_get_current_cgroup_id() },
        matched: false,
    }
}

/// Reads a kernel structure field through `bpf_probe_read_kernel`. The kernel
/// pointer is deliberately kept as a scalar (`u64`) and only the helper turns
/// the computed address into a real kernel access — that is the verifier-safe
/// pattern for runtime offsets (§4.1).
#[inline(always)]
pub(crate) fn titan_probe<T>(base: u64, offset: u32) -> Option<T> {
    let address = base.wrapping_add(u64::from(offset)) as *const T;
    unsafe { bpf_probe_read_kernel(address).ok() }
}

/// `linux_binprm -> file -> inode` identity chain for `bprm_check_security`.
#[inline(always)]
fn titan_read_bprm(bprm: u64, offsets: &TitanOffsets) -> Option<TitanFile> {
    let file = titan_probe::<u64>(bprm, offsets.bprm_file)?;
    if file == 0 {
        return None;
    }
    titan_read_file(file, offsets)
}

/// `struct file -> f_inode -> struct inode -> i_sb` identity chain.
#[inline(always)]
fn titan_read_file(file: u64, offsets: &TitanOffsets) -> Option<TitanFile> {
    let inode = titan_probe::<u64>(file, offsets.file_inode)?;
    if inode == 0 {
        return None;
    }
    let sb = titan_probe::<u64>(inode, offsets.inode_sb)?;
    if sb == 0 {
        return None;
    }
    let ino = titan_probe::<u64>(inode, offsets.inode_ino)?;
    let inode_mode = titan_probe::<u16>(inode, offsets.inode_mode)? as u32;
    let generation = titan_probe::<u32>(inode, offsets.inode_gen)?;
    let dev = kernel_s_dev_to_stat_u32(titan_probe::<u32>(sb, offsets.sb_dev)?);
    Some(TitanFile { dev, inode_mode, ino, generation, inode, sb, file_ptr: file })
}

#[inline(always)]
fn titan_read_containment(file: &TitanFile, offsets: &TitanOffsets) -> Option<TitanContainment> {
    Some(TitanContainment {
        nlink: titan_probe::<u32>(file.inode, offsets.inode_nlink)?,
        fs_magic: titan_probe::<u32>(file.sb, offsets.sb_magic)?,
    })
}

/// Policy key = `s_dev u32 LE | i_ino u64 LE | pad[4]` (§4). A zero identity can
/// never match a policy entry because the core rejects zero dev/ino on write.
#[inline(always)]
fn titan_policy(file: &TitanFile, global: &TitanGlobal) -> TitanPolicy {
    let mut policy = TitanPolicy { allow: false, require_ctime: false, ctime_ns: 0 };
    if file.dev == 0 || file.ino == 0 {
        return policy;
    }
    let mut key = [0u8; 16];
    key[0..4].copy_from_slice(&file.dev.to_le_bytes());
    key[4..12].copy_from_slice(&file.ino.to_le_bytes());
    if let Some(value) = unsafe { TITAN_EXEC_POLICY.get(&key) } {
        if value[TITAN_EXEC_POLICY_ACTION_OFFSET] == TITAN_EXEC_POLICY_ACTION_ALLOW {
            policy.allow = true;
            policy.require_ctime = (value[TITAN_EXEC_POLICY_FLAGS_OFFSET]
                & TITAN_EXEC_POLICY_FLAG_REQUIRE_CTIME)
                != 0
                && (global.flags & TITAN_EXEC_STATE_FLAG_CTIME_CHECK) != 0;
            let ctime = &value[TITAN_EXEC_POLICY_CTIME_OFFSET..TITAN_EXEC_POLICY_CTIME_OFFSET + 8];
            policy.ctime_ns = u64::from_le_bytes([
                ctime[0], ctime[1], ctime[2], ctime[3], ctime[4], ctime[5], ctime[6], ctime[7],
            ]);
        }
    }
    policy
}

/// `i_ctime` (sec, nsec) as nanoseconds since the Unix epoch. The nsec half is
/// read with the core-provided width (4 B on the 6.18/7.0 split-inode layout,
/// 8 B for the historical `timespec64` pair) and zero-extended; the sum is
/// saturated so a corrupt timestamp can never wrap into a "match". `None` is a
/// read failure, not a mismatch: callers fail open with READ_FAILURES (§4.2).
#[inline(always)]
fn titan_ctime_mismatch(
    file: &TitanFile,
    offsets: &TitanOffsets,
    expected_ns: u64,
) -> Option<bool> {
    let sec: u64 = titan_probe(file.inode, offsets.ctime_sec)?;
    let nsec: u64 = if offsets.ctime_nsec_width == TITAN_CTIME_NSEC_WIDTH_32 {
        u64::from(strip_ctime_queried_flag(titan_probe::<u32>(file.inode, offsets.ctime_nsec)?))
    } else {
        titan_probe::<u64>(file.inode, offsets.ctime_nsec)?
    };
    // `tv_nsec` is always in [0, 1e9); anything else is a corrupt read.
    if nsec >= NS_PER_SECOND {
        return None;
    }
    // Saturation without `u64::saturating_mul`: Rust's u64 saturating multiply
    // is lowered to the 128-bit `__multi3` builtin on the BPF target (unsupported
    // by bpf-linker). The division guard folds to a compile-time constant, so the
    // multiply below cannot overflow and `saturating_add` keeps the contract.
    let seconds_ns = if sec > u64::MAX / NS_PER_SECOND {
        u64::MAX
    } else {
        sec * NS_PER_SECOND
    };
    let actual_ns = seconds_ns.saturating_add(nsec);
    Some(actual_ns != expected_ns)
}

/// §4.2 ABI 2: lifts the three UNTRUSTED-mode facts with bounded reads only.
/// `None` is a read failure and keeps the §4.2 fail-safe contract (allow + a
/// READ_FAILURE audit event that the control plane counts and alarms on).
#[inline(always)]
fn titan_untrusted(bprm: u64, file: &TitanFile, offsets: &TitanOffsets) -> Option<TitanUntrusted> {
    let mut facts = TitanUntrusted::default();
    let filename: u64 = titan_probe(bprm, offsets.bprm_filename)?;
    if filename == 0 {
        return None;
    }
    let mut path = [0u8; TITAN_UNTRUSTED_PATH_BYTES];
    let path = unsafe { bpf_probe_read_kernel_str_bytes(filename as *const u8, &mut path).ok()? };
    facts.path_denied = path.starts_with(UNTRUSTED_ROOT_TMP)
        || path.starts_with(UNTRUSTED_ROOT_VAR_TMP)
        || path.starts_with(UNTRUSTED_ROOT_DEV_SHM);
    let owner: u32 = titan_probe(file.inode, offsets.inode_uid)?;
    facts.non_root_owner = owner != 0;
    // World-writable file or a bounded ancestor-directory walk. `/` is 0755 and
    // the loop is capped, so the cost is at most four pointer + mode reads.
    if file.inode_mode as u16 & TITAN_S_IWOTH != 0 {
        facts.world_writable_path = true;
    }
    let mut dentry: u64 = titan_probe(file.file_ptr, offsets.file_f_path_dentry)?;
    let mut level = 0u8;
    while level < TITAN_UNTRUSTED_ANCESTOR_LEVELS && !facts.world_writable_path {
        if dentry == 0 {
            break;
        }
        let inode: u64 = titan_probe(dentry, offsets.dentry_inode)?;
        if inode != 0 {
            let mode: u16 = titan_probe(inode, offsets.inode_mode)?;
            if mode & TITAN_S_IWOTH != 0 {
                facts.world_writable_path = true;
            }
        }
        dentry = titan_probe(dentry, offsets.dentry_parent)?;
        level += 1;
    }
    Some(facts)
}

/// §4.2 verdict: `Some(reason)` means the gate acts on this ground (audit in
/// OBSERVE, deny in CONTAIN/STRICT); `None` means allow silently. Modes OFF and
/// scope-OFF never reach this function. UNTRUSTED (mode 4, ABI 2) applies the
/// three drop-root/owner gates on top of the CONTAIN containment rules; the
/// configured inode allowlist lifts them exactly like the CONTAIN rules.
#[inline(always)]
fn titan_decide(
    mode: u8,
    jit_allow: bool,
    hook: u8,
    prot: u32,
    anon: bool,
    containment: TitanContainment,
    untrusted: TitanUntrusted,
    offsets: &TitanOffsets,
    policy_allow: bool,
    ctime_mismatch: bool,
) -> Option<u8> {
    // Anonymous executable mappings carry no file/inode identity. They are only
    // permitted through a per-cgroup JIT_ALLOW scope (§4.2); a W|X rule is not
    // applied here because §3.2 cannot represent an identity-less WX record.
    if anon {
        return if jit_allow {
            None
        } else {
            Some(TITAN_EXEC_REASON_ANON_NO_JIT)
        };
    }
    // §4.2 CONTAIN/STRICT: W|X file mappings are always a ground; an inode
    // policy ALLOW never lifts a W^X violation.
    if hook == TITAN_EXEC_HOOK_MMAP
        && prot & (PROT_WRITE | PROT_EXEC) == (PROT_WRITE | PROT_EXEC)
    {
        return Some(TITAN_EXEC_REASON_WX);
    }
    if ctime_mismatch {
        return Some(TITAN_EXEC_REASON_CTIME_MISMATCH);
    }
    if mode == TITAN_EXEC_MODE_STRICT {
        return if policy_allow {
            None
        } else {
            Some(TITAN_EXEC_REASON_NOT_ALLOWLISTED)
        };
    }
    // §4.2 UNTRUSTED (ABI 2): the CONTAIN rules plus the drop-path gates. A
    // configured TITAN_EXEC_POLICY allow entry lifts all three, so legitimate
    // operator-approved binaries keep working. This runs before the shared
    // containment block below so the event names the most specific ground.
    if mode == TITAN_EXEC_MODE_UNTRUSTED && !policy_allow {
        if untrusted.path_denied {
            return Some(TITAN_EXEC_REASON_UNTRUSTED_PATH);
        }
        if untrusted.non_root_owner {
            return Some(TITAN_EXEC_REASON_NON_ROOT_OWNER);
        }
        if untrusted.world_writable_path {
            return Some(TITAN_EXEC_REASON_WORLD_WRITABLE_PATH);
        }
    }
    // OBSERVE and CONTAIN share the containment rules. An inode-policy ALLOW
    // only lifts the file-system/unlinked-inode rules (§4.2 documented exception).
    if policy_allow {
        return None;
    }
    if containment.nlink == 0 {
        return Some(if containment.fs_magic == offsets.tmpfs_magic {
            TITAN_EXEC_REASON_MEMFD
        } else {
            TITAN_EXEC_REASON_UNLINKED
        });
    }
    if containment.fs_magic == offsets.tmpfs_magic {
        return Some(TITAN_EXEC_REASON_TMPFS);
    }
    if containment.fs_magic == offsets.devtmpfs_magic
        || containment.fs_magic == offsets.proc_magic
        || containment.fs_magic == offsets.sysfs_magic
    {
        return Some(TITAN_EXEC_REASON_FS_HARD);
    }
    None
}

/// Turns the §4.2 reason into the kernel verdict and the audit/deny event.
#[inline(always)]
fn titan_finish(
    hook: u8,
    scope: TitanScope,
    reason: Option<u8>,
    dev: u32,
    inode_mode: u32,
    ino: u64,
    generation: u32,
    prot: u32,
    ctime_mismatch: bool,
) -> i32 {
    let reason = match reason {
        Some(reason) => reason,
        None => return 0,
    };
    let action = if scope.mode == TITAN_EXEC_MODE_OBSERVE {
        TITAN_EXEC_ACTION_AUDIT
    } else {
        TITAN_EXEC_ACTION_DENY
    };
    // §3.2 event flags: bit0 ctime mismatch observed, bit1 scope snapshot.
    let flags = (ctime_mismatch as u8) | ((scope.matched as u8) << 1);
    emit_titan_exec_event(
        hook, action, reason, scope.cgroup_id, dev, inode_mode, ino, generation, prot, flags,
    );
    if action == TITAN_EXEC_ACTION_DENY {
        increment_counter(&TITAN_EXEC_POLICY_DENIES);
        -EPERM
    } else {
        increment_counter(&TITAN_EXEC_POLICY_AUDITS);
        0
    }
}

/// Records an offsets/read failure and fails open (§4.2). The event proof is
/// mandatory: READ_FAILURE + AUDIT is the only §3.2 record where a zero
/// identity is allowed, so it is representable even when no inode was read.
#[inline(always)]
fn titan_read_failure(hook: u8, prot: u32) -> i32 {
    increment_counter(&TITAN_EXEC_READ_FAILURES);
    emit_titan_exec_event(
        hook,
        TITAN_EXEC_ACTION_AUDIT,
        TITAN_EXEC_REASON_READ_FAILURE,
        0,
        0,
        0,
        0,
        0,
        prot,
        0,
    );
    0
}

/// Emits one native-endian 88-byte `TitanExecEvent` (§3.2). The record is
/// written directly into the ring-buffer reservation: a stack copy would add
/// 88 bytes to the 512-byte eBPF stack frame that already holds the read chain.
#[inline(always)]
fn emit_titan_exec_event(
    hook: u8,
    action: u8,
    reason: u8,
    cgroup_id: u64,
    dev: u32,
    inode_mode: u32,
    ino: u64,
    generation: u32,
    prot: u32,
    flags: u8,
) {
    let ts_ns = unsafe { bpf_ktime_get_ns() };
    let pid_tgid = bpf_get_current_pid_tgid();
    let pid = pid_tgid as u32;
    // The core decoder rejects pid/ts 0 records; never produce one.
    if pid == 0 || ts_ns == 0 {
        return;
    }
    let tgid = (pid_tgid >> 32) as u32;
    let uid_gid = bpf_get_current_uid_gid();
    let comm = bpf_get_current_comm().unwrap_or([0u8; EXEC_COMM_BYTES]);
    if let Some(mut entry) = TITAN_EXEC_EVENTS.reserve::<TitanExecEvent>(0) {
        let event = entry.as_mut_ptr();
        // SAFETY: the reservation is exactly size_of::<TitanExecEvent>() bytes
        // and 8-aligned; every field is written through the raw pointer before
        // the entry is submitted, and the entry is submitted before scope end.
        unsafe {
            core::ptr::addr_of_mut!((*event).cgroup_id).write(cgroup_id);
            core::ptr::addr_of_mut!((*event).ts_ns).write(ts_ns);
            core::ptr::addr_of_mut!((*event).dev).write(dev);
            core::ptr::addr_of_mut!((*event).inode_mode).write(inode_mode);
            core::ptr::addr_of_mut!((*event).ino).write(ino);
            core::ptr::addr_of_mut!((*event).generation).write(generation);
            core::ptr::addr_of_mut!((*event).pid).write(pid);
            core::ptr::addr_of_mut!((*event).tgid).write(tgid);
            core::ptr::addr_of_mut!((*event).uid).write(uid_gid as u32);
            core::ptr::addr_of_mut!((*event).gid).write((uid_gid >> 32) as u32);
            core::ptr::addr_of_mut!((*event).prot).write(prot);
            // §4.1 has no file.f_flags offset, so the field stays 0 (unknown);
            // the core decoder does not interpret it.
            core::ptr::addr_of_mut!((*event).f_flags).write(0);
            core::ptr::addr_of_mut!((*event).hook).write(hook);
            core::ptr::addr_of_mut!((*event).action).write(action);
            core::ptr::addr_of_mut!((*event).reason).write(reason);
            core::ptr::addr_of_mut!((*event).flags).write(flags);
            core::ptr::addr_of_mut!((*event).comm).write(comm);
            core::ptr::addr_of_mut!((*event).reserved).write([0u8; 8]);
        }
        entry.submit(0);
        increment_counter(&TITAN_EXEC_EVENTS_EMITTED);
    } else {
        // Ring full: visibility loss is reported, the verdict is unaffected.
        increment_counter(&TITAN_EXEC_RING_DROPS);
    }
}

#[lsm(hook = "bprm_check_security")]
pub fn gedefense_titan_exec_bprm(ctx: LsmContext) -> i32 {
    try_titan_exec_bprm(ctx)
}

#[inline(always)]
fn try_titan_exec_bprm(ctx: LsmContext) -> i32 {
    // Defer to a previously attached LSM program exactly like the kernel chain.
    let previous: i32 = ctx.arg(TITAN_LSM_BPRM_PREVIOUS_ARG);
    if previous != 0 {
        return previous;
    }
    let global = match titan_global() {
        Some(global) => global,
        None => return titan_read_failure(TITAN_EXEC_HOOK_BPRM, 0),
    };
    // §4.2: a default-OFF gate returns before any structure read or event.
    if global.mode == TITAN_EXEC_MODE_OFF {
        return 0;
    }
    let offsets = match titan_offsets() {
        Some(offsets) => offsets,
        None => return titan_read_failure(TITAN_EXEC_HOOK_BPRM, 0),
    };
    if !titan_arguments_match(TITAN_EXEC_HOOK_BPRM) {
        return titan_read_failure(TITAN_EXEC_HOOK_BPRM, 0);
    }
    let scope = titan_scope(global.mode);
    if scope.mode == TITAN_EXEC_MODE_OFF {
        return 0;
    }
    let bprm: u64 = ctx.arg(TITAN_LSM_BPRM_FILE_ARG);
    if bprm == 0 {
        return titan_read_failure(TITAN_EXEC_HOOK_BPRM, 0);
    }
    let file = match titan_read_bprm(bprm, &offsets) {
        Some(file) => file,
        None => return titan_read_failure(TITAN_EXEC_HOOK_BPRM, 0),
    };
    // §4.2 STRICT does not use the containment facts; skip those two reads.
    let containment = if scope.mode == TITAN_EXEC_MODE_STRICT {
        TitanContainment { nlink: 1, fs_magic: 0 }
    } else {
        match titan_read_containment(&file, &offsets) {
            Some(containment) => containment,
            None => return titan_read_failure(TITAN_EXEC_HOOK_BPRM, 0),
        }
    };
    let policy = titan_policy(&file, &global);
    // §4.2 ABI 2: UNTRUSTED-mode path/owner/world-writable facts. Unavailable
    // facts are a READ_FAILURE (visible audit + counter), never a silent allow.
    let untrusted = if scope.mode == TITAN_EXEC_MODE_UNTRUSTED {
        match titan_untrusted(bprm, &file, &offsets) {
            Some(untrusted) => untrusted,
            None => return titan_read_failure(TITAN_EXEC_HOOK_BPRM, 0),
        }
    } else {
        TitanUntrusted::default()
    };
    let mut ctime_mismatch = false;
    if policy.require_ctime {
        match titan_ctime_mismatch(&file, &offsets, policy.ctime_ns) {
            Some(mismatch) => {
                ctime_mismatch = mismatch;
                if mismatch {
                    increment_counter(&TITAN_EXEC_CTIME_REJECTS);
                }
            }
            None => return titan_read_failure(TITAN_EXEC_HOOK_BPRM, 0),
        }
    }
    let reason = titan_decide(
        scope.mode,
        scope.jit_allow,
        TITAN_EXEC_HOOK_BPRM,
        0,
        false,
        containment,
        untrusted,
        &offsets,
        policy.allow && !ctime_mismatch,
        ctime_mismatch,
    );
    titan_finish(
        TITAN_EXEC_HOOK_BPRM,
        scope,
        reason,
        file.dev,
        file.inode_mode,
        file.ino,
        file.generation,
        0,
        ctime_mismatch,
    )
}

#[lsm(hook = "mmap_file")]
pub fn gedefense_titan_exec_mmap(ctx: LsmContext) -> i32 {
    try_titan_exec_mmap(ctx)
}

#[inline(always)]
fn try_titan_exec_mmap(ctx: LsmContext) -> i32 {
    // Defer to a previously attached LSM program exactly like the kernel chain.
    let previous: i32 = ctx.arg(TITAN_LSM_MMAP_PREVIOUS_ARG);
    if previous != 0 {
        return previous;
    }
    // §4.2 performance rule: the requested protection is a ctx scalar slot and
    // must be read before any map/kernel read; non-executable mappings (the vast
    // majority of library mappings) leave the hook immediately. The slot is
    // declared `unsigned long` in the hook proto, so it is read as the full
    // 8-byte argument and then truncated to the uapi `PROT_*` bit width — a
    // 4-byte context read of an 8-byte proto argument is not portable across
    // verifier versions.
    let prot_raw: u64 = ctx.arg(TITAN_LSM_MMAP_PROT_ARG);
    let prot = prot_raw as u32;
    if prot & PROT_EXEC == 0 {
        return 0;
    }
    let global = match titan_global() {
        Some(global) => global,
        None => return titan_read_failure(TITAN_EXEC_HOOK_MMAP, prot),
    };
    if global.mode == TITAN_EXEC_MODE_OFF {
        return 0;
    }
    let offsets = match titan_offsets() {
        Some(offsets) => offsets,
        None => return titan_read_failure(TITAN_EXEC_HOOK_MMAP, prot),
    };
    if !titan_arguments_match(TITAN_EXEC_HOOK_MMAP) {
        return titan_read_failure(TITAN_EXEC_HOOK_MMAP, prot);
    }
    let scope = titan_scope(global.mode);
    if scope.mode == TITAN_EXEC_MODE_OFF {
        return 0;
    }
    let file: u64 = ctx.arg(TITAN_LSM_MMAP_FILE_ARG);
    if file == 0 {
        // Anonymous executable mapping: no file/inode identity (§3.2 exception).
        let reason = titan_decide(
            scope.mode,
            scope.jit_allow,
            TITAN_EXEC_HOOK_MMAP,
            prot,
            true,
            TitanContainment { nlink: 1, fs_magic: 0 },
            TitanUntrusted::default(),
            &offsets,
            false,
            false,
        );
        return titan_finish(TITAN_EXEC_HOOK_MMAP, scope, reason, 0, 0, 0, 0, prot, false);
    }
    let file = match titan_read_file(file, &offsets) {
        Some(file) => file,
        None => return titan_read_failure(TITAN_EXEC_HOOK_MMAP, prot),
    };
    let containment = if scope.mode == TITAN_EXEC_MODE_STRICT {
        TitanContainment { nlink: 1, fs_magic: 0 }
    } else {
        match titan_read_containment(&file, &offsets) {
            Some(containment) => containment,
            None => return titan_read_failure(TITAN_EXEC_HOOK_MMAP, prot),
        }
    };
    let policy = titan_policy(&file, &global);
    let mut ctime_mismatch = false;
    if policy.require_ctime {
        match titan_ctime_mismatch(&file, &offsets, policy.ctime_ns) {
            Some(mismatch) => {
                ctime_mismatch = mismatch;
                if mismatch {
                    increment_counter(&TITAN_EXEC_CTIME_REJECTS);
                }
            }
            None => return titan_read_failure(TITAN_EXEC_HOOK_MMAP, prot),
        }
    }
    // UNTRUSTED path facts are an execve (bprm) gate; an mmap of a file that
    // cannot be execve'd is covered by the containment rules and never grants a
    // new capability, so the mmap hook passes the neutral fact set.
    let reason = titan_decide(
        scope.mode,
        scope.jit_allow,
        TITAN_EXEC_HOOK_MMAP,
        prot,
        false,
        containment,
        TitanUntrusted::default(),
        &offsets,
        policy.allow && !ctime_mismatch,
        ctime_mismatch,
    );
    titan_finish(
        TITAN_EXEC_HOOK_MMAP,
        scope,
        reason,
        file.dev,
        file.inode_mode,
        file.ino,
        file.generation,
        prot,
        ctime_mismatch,
    )
}
