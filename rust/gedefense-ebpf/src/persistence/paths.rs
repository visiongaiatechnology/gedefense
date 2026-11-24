//! BTF/tracefs-resolved offset and identity ladder of the AP-5 persistence
//! sensors (child module of `persistence`).
//!
//! Every entry point validates the published `PERSIST_GUARD_OFFSETS` table
//! (magic/ABI words, structure bounds) before the first `bpf_probe_read_kernel`;
//! an absent/partial/implausible table returns `None`, the caller fails open and
//! counts a structural read failure. Nothing is hard-coded here.

use aya_ebpf::helpers::bpf_get_current_task;
use gedefense_common::{
    kernel_s_dev_to_stat_u32, persistence_identity_key, PERSIST_FILE_OPEN_NARGS_EXPECTED,
    PERSIST_MAX_STRUCT_SIZE, PERSIST_MAX_TRACEPOINT_BYTES, PERSIST_MMAP_FILE_ARG,
    PERSIST_OFFSETS_ABI, PERSIST_OFFSETS_MAGIC, PERSIST_OFF_ABI, PERSIST_OFF_DENTRY_D_INODE,
    PERSIST_OFF_DENTRY_D_PARENT, PERSIST_OFF_DENTRY_SIZE, PERSIST_OFF_FILE_F_FLAGS,
    PERSIST_OFF_FILE_F_INODE, PERSIST_OFF_FILE_F_PATH_DENTRY, PERSIST_OFF_FILE_OPEN_NARGS,
    PERSIST_OFF_FILE_OPEN_PREV, PERSIST_OFF_FILE_SIZE, PERSIST_OFF_INODE_I_INO,
    PERSIST_OFF_INODE_I_SB, PERSIST_OFF_INODE_SIZE, PERSIST_OFF_MAGIC, PERSIST_OFF_MM_EXE_FILE,
    PERSIST_OFF_MM_SIZE, PERSIST_OFF_MMAP_FILE_ARG, PERSIST_OFF_MMAP_NARGS, PERSIST_OFF_MMAP_PREV,
    PERSIST_OFF_MMAP_PROT_ARG, PERSIST_OFF_PTRACE_CHILD_ARG, PERSIST_OFF_PTRACE_MODE_ARG,
    PERSIST_OFF_PTRACE_NARGS, PERSIST_OFF_PTRACE_PREV, PERSIST_OFF_READV_PID,
    PERSIST_OFF_READV_SIZE, PERSIST_OFF_READV_TARGET, PERSIST_OFF_SUPER_S_DEV,
    PERSIST_OFF_SUPER_SIZE, PERSIST_OFF_TASK_MM, PERSIST_OFF_TASK_PID, PERSIST_OFF_TASK_SIZE,
    PERSIST_OFF_TASK_TGID, PERSIST_OFF_WRITEV_PID, PERSIST_OFF_WRITEV_SIZE,
    PERSIST_OFF_WRITEV_TARGET, PERSIST_PTRACE_CHILD_ARG, PERSIST_PTRACE_MODE_ARG,
    PERSIST_PTRACE_NARGS_EXPECTED, PERSIST_STATE_ABI, PERSIST_STATE_ABI_SHIFT,
    PERSIST_STATE_ARMED_SHIFT, PERSIST_STATE_BYTE_MASK, PERSIST_STATE_MAGIC,
    PERSIST_STATE_MAGIC_SHIFT,
};
use crate::titan_exec::titan_probe;

use super::{PERSIST_GUARD_OFFSETS, PERSIST_GUARD_STATE};

/// Index of the single armed state word in `PERSIST_GUARD_STATE`.
const PERSIST_STATE_INDEX: u32 = 0;

/// Reads and validates the armed state word. Any absent/foreign/stale word is
/// "not armed" (fail-open, no event).
#[inline(always)]
pub(crate) fn persistence_armed() -> bool {
    let Some(word) = PERSIST_GUARD_STATE.get(PERSIST_STATE_INDEX) else {
        return false;
    };
    let magic = ((*word >> PERSIST_STATE_MAGIC_SHIFT) & PERSIST_STATE_BYTE_MASK) as u8;
    let abi = ((*word >> PERSIST_STATE_ABI_SHIFT) & PERSIST_STATE_BYTE_MASK) as u8;
    let armed = (*word >> PERSIST_STATE_ARMED_SHIFT) & 1;
    magic == PERSIST_STATE_MAGIC && abi == PERSIST_STATE_ABI && armed == 1
}

#[inline(always)]
pub(crate) fn persistence_offset(index: u32) -> Option<u32> {
    PERSIST_GUARD_OFFSETS.get(index).copied()
}

/// True when the published table carries the current magic/ABI words.
#[inline(always)]
pub(crate) fn offsets_table_ok() -> bool {
    persistence_offset(PERSIST_OFF_MAGIC) == Some(PERSIST_OFFSETS_MAGIC)
        && persistence_offset(PERSIST_OFF_ABI) == Some(PERSIST_OFFSETS_ABI)
}

/// A field of `width` bytes at `offset` lies inside a structure of `size` bytes.
#[inline(always)]
pub(crate) fn field_fits(offset: u32, width: u32, size: u32) -> bool {
    size > 0
        && size <= PERSIST_MAX_STRUCT_SIZE
        && offset.saturating_add(width) <= size
}

/// BTF-resolved `file`/`inode`/`super_block`/`dentry` identity offsets.
///
/// `f_flags` (access intent) and the dentry parent chain (dynamic children of a
/// watched directory) are optional: an unresolved optional offset fails only the
/// feature that needs it (`UNKNOWN` access intent / no parent step), never the
/// whole identity ladder.
#[derive(Clone, Copy)]
pub(crate) struct FileOffsets {
    pub(crate) f_inode: u32,
    pub(crate) f_flags: u32,
    pub(crate) file_size: u32,
    pub(crate) f_dentry: u32,
    pub(crate) i_ino: u32,
    pub(crate) i_sb: u32,
    pub(crate) inode_size: u32,
    pub(crate) s_dev: u32,
    pub(crate) super_size: u32,
    pub(crate) dentry_parent: u32,
    pub(crate) dentry_inode: u32,
    pub(crate) dentry_size: u32,
}

/// BTF-resolved `task_struct`/`mm_struct` executable identity offsets.
#[derive(Clone, Copy)]
pub(crate) struct ExecOffsets {
    pub(crate) task_mm: u32,
    pub(crate) task_size: u32,
    pub(crate) mm_exe_file: u32,
    pub(crate) mm_size: u32,
}

/// `task_struct.pid`/`tgid` offsets for the ptrace record.
#[derive(Clone, Copy)]
pub(crate) struct TaskOffsets {
    pub(crate) pid: u32,
    pub(crate) tgid: u32,
    pub(crate) size: u32,
}

/// `task_struct.pid`/`tgid` offsets for the ptrace record.
#[derive(Clone, Copy)]
pub(crate) struct PtraceAbi {
    pub(crate) child_arg: u32,
    pub(crate) mode_arg: u32,
    pub(crate) previous_slot: u32,
    pub(crate) task: TaskOffsets,
}

/// Reads and validates every identity offset the file ladder needs. `None` for
/// an absent/partial/implausible table; the callers then fail open and count a
/// structural read failure.
#[inline(always)]
pub(crate) fn file_offsets() -> Option<FileOffsets> {
    if !offsets_table_ok() {
        return None;
    }
    let offsets = FileOffsets {
        f_inode: persistence_offset(PERSIST_OFF_FILE_F_INODE)?,
        f_flags: persistence_offset(PERSIST_OFF_FILE_F_FLAGS)?,
        file_size: persistence_offset(PERSIST_OFF_FILE_SIZE)?,
        f_dentry: persistence_offset(PERSIST_OFF_FILE_F_PATH_DENTRY)?,
        i_ino: persistence_offset(PERSIST_OFF_INODE_I_INO)?,
        i_sb: persistence_offset(PERSIST_OFF_INODE_I_SB)?,
        inode_size: persistence_offset(PERSIST_OFF_INODE_SIZE)?,
        s_dev: persistence_offset(PERSIST_OFF_SUPER_S_DEV)?,
        super_size: persistence_offset(PERSIST_OFF_SUPER_SIZE)?,
        dentry_parent: persistence_offset(PERSIST_OFF_DENTRY_D_PARENT)?,
        dentry_inode: persistence_offset(PERSIST_OFF_DENTRY_D_INODE)?,
        dentry_size: persistence_offset(PERSIST_OFF_DENTRY_SIZE)?,
    };
    // Mandatory identity chain; the optional f_flags/dentry offsets are
    // validated where they are used.
    if !field_fits(offsets.f_inode, 8, offsets.file_size)
        || !field_fits(offsets.i_ino, 8, offsets.inode_size)
        || !field_fits(offsets.i_sb, 8, offsets.inode_size)
        || !field_fits(offsets.s_dev, 4, offsets.super_size)
    {
        return None;
    }
    Some(offsets)
}

/// Reads and validates the `task_struct -> mm -> exe_file` offsets.
#[inline(always)]
pub(crate) fn exec_offsets() -> Option<ExecOffsets> {
    if !offsets_table_ok() {
        return None;
    }
    let offsets = ExecOffsets {
        task_mm: persistence_offset(PERSIST_OFF_TASK_MM)?,
        task_size: persistence_offset(PERSIST_OFF_TASK_SIZE)?,
        mm_exe_file: persistence_offset(PERSIST_OFF_MM_EXE_FILE)?,
        mm_size: persistence_offset(PERSIST_OFF_MM_SIZE)?,
    };
    if !field_fits(offsets.task_mm, 8, offsets.task_size)
        || !field_fits(offsets.mm_exe_file, 8, offsets.mm_size)
    {
        return None;
    }
    Some(offsets)
}

#[inline(always)]
pub(crate) fn task_offsets() -> Option<TaskOffsets> {
    if !offsets_table_ok() {
        return None;
    }
    let offsets = TaskOffsets {
        pid: persistence_offset(PERSIST_OFF_TASK_PID)?,
        tgid: persistence_offset(PERSIST_OFF_TASK_TGID)?,
        size: persistence_offset(PERSIST_OFF_TASK_SIZE)?,
    };
    if !field_fits(offsets.pid, 4, offsets.size) || !field_fits(offsets.tgid, 4, offsets.size) {
        return None;
    }
    Some(offsets)
}

/// `file_open` LSM ABI validation: exactly one argument plus the chained verdict.
#[inline(always)]
pub(crate) fn file_open_abi_ok() -> bool {
    offsets_table_ok()
        && persistence_offset(PERSIST_OFF_FILE_OPEN_NARGS)
            == Some(PERSIST_FILE_OPEN_NARGS_EXPECTED)
        && persistence_offset(PERSIST_OFF_FILE_OPEN_PREV)
            == Some(PERSIST_FILE_OPEN_NARGS_EXPECTED)
}

/// `mmap_file` LSM ABI validation: returns `(prot_arg_slot, previous_verdict_slot)`.
#[inline(always)]
pub(crate) fn mmap_abi() -> Option<(u32, u32)> {
    if !offsets_table_ok() {
        return None;
    }
    let nargs = persistence_offset(PERSIST_OFF_MMAP_NARGS)?;
    let file_arg = persistence_offset(PERSIST_OFF_MMAP_FILE_ARG)?;
    let prot_arg = persistence_offset(PERSIST_OFF_MMAP_PROT_ARG)?;
    let previous = persistence_offset(PERSIST_OFF_MMAP_PREV)?;
    // `security_mmap_file(struct file *file, unsigned long reqprot,
    //  unsigned long prot, unsigned long flags)`: the file argument is slot 0,
    // `prot` is two slots before the chained verdict and the verdict slot is the
    // argument count. Any other arity is a different kernel ABI: fail open.
    if nargs >= 3
        && nargs <= 8
        && file_arg == PERSIST_MMAP_FILE_ARG
        && prot_arg.saturating_add(2) == nargs
        && previous == nargs
    {
        Some((prot_arg, previous))
    } else {
        None
    }
}

#[inline(always)]
pub(crate) fn ptrace_abi() -> Option<PtraceAbi> {
    if !offsets_table_ok()
        || persistence_offset(PERSIST_OFF_PTRACE_NARGS) != Some(PERSIST_PTRACE_NARGS_EXPECTED)
        || persistence_offset(PERSIST_OFF_PTRACE_CHILD_ARG) != Some(PERSIST_PTRACE_CHILD_ARG)
        || persistence_offset(PERSIST_OFF_PTRACE_MODE_ARG) != Some(PERSIST_PTRACE_MODE_ARG)
        || persistence_offset(PERSIST_OFF_PTRACE_PREV) != Some(PERSIST_PTRACE_NARGS_EXPECTED)
    {
        return None;
    }
    Some(PtraceAbi {
        child_arg: PERSIST_PTRACE_CHILD_ARG,
        mode_arg: PERSIST_PTRACE_MODE_ARG,
        previous_slot: PERSIST_PTRACE_NARGS_EXPECTED,
        task: task_offsets()?,
    })
}

/// Tracepoint field offsets: `(pid_offset, target_pid_offset, record_size)`.
#[inline(always)]
pub(crate) fn vm_offsets(readv: bool) -> Option<(u32, u32, u32)> {
    if !offsets_table_ok() {
        return None;
    }
    let (pid_index, target_index, size_index) = if readv {
        (PERSIST_OFF_READV_PID, PERSIST_OFF_READV_TARGET, PERSIST_OFF_READV_SIZE)
    } else {
        (
            PERSIST_OFF_WRITEV_PID,
            PERSIST_OFF_WRITEV_TARGET,
            PERSIST_OFF_WRITEV_SIZE,
        )
    };
    let pid = persistence_offset(pid_index)?;
    let target = persistence_offset(target_index)?;
    let size = persistence_offset(size_index)?;
    // The tracepoint record always starts with the 8-byte common header; both
    // `pid_t` fields are 4-byte slots inside the record. A zero/duplicate/out of
    // range pair is an unreadable format: the caller degrades honestly.
    if pid < 8
        || target < 8
        || pid == target
        || size < 16
        || size > PERSIST_MAX_TRACEPOINT_BYTES
        || pid.saturating_add(4) > size
        || target.saturating_add(4) > size
    {
        return None;
    }
    Some((pid, target, size))
}

/// `(s_dev, i_ino)` identity of one kernel inode through the published offsets.
#[inline(always)]
pub(crate) fn inode_identity(inode: u64, offsets: &FileOffsets) -> Option<(u32, u64)> {
    if inode == 0 {
        return None;
    }
    let super_block: u64 = titan_probe(inode, offsets.i_sb)?;
    if super_block == 0 {
        return None;
    }
    let raw_dev: u32 = titan_probe(super_block, offsets.s_dev)?;
    let dev = kernel_s_dev_to_stat_u32(raw_dev);
    let ino: u64 = titan_probe(inode, offsets.i_ino)?;
    if dev == 0 || ino == 0 {
        return None;
    }
    Some((dev, ino))
}

/// Identity of one `struct file *`.
#[inline(always)]
pub(crate) fn file_identity(file: u64, offsets: &FileOffsets) -> Option<(u32, u64)> {
    if file == 0 {
        return None;
    }
    let inode: u64 = titan_probe(file, offsets.f_inode)?;
    inode_identity(inode, offsets)
}

/// Immediate-parent inode identity of one `struct file *` (one bounded step).
#[inline(always)]
pub(crate) fn parent_identity(file: u64, offsets: &FileOffsets) -> Option<[u8; 16]> {
    // The dentry chain is optional: a kernel/BTF without these offsets only
    // loses the dynamic-children coverage of a watched directory.
    if !field_fits(offsets.f_dentry, 8, offsets.file_size)
        || !field_fits(offsets.dentry_parent, 8, offsets.dentry_size)
        || !field_fits(offsets.dentry_inode, 8, offsets.dentry_size)
    {
        return None;
    }
    let dentry: u64 = titan_probe(file, offsets.f_dentry)?;
    if dentry == 0 {
        return None;
    }
    let parent: u64 = titan_probe(dentry, offsets.dentry_parent)?;
    if parent == 0 {
        return None;
    }
    let parent_inode: u64 = titan_probe(parent, offsets.dentry_inode)?;
    let (dev, ino) = inode_identity(parent_inode, offsets)?;
    Some(persistence_identity_key(dev, ino))
}

/// Identity of the current task's real executable
/// (`task->mm->exe_file->f_inode`).
#[inline(always)]
pub(crate) fn current_exe_identity(offsets: &FileOffsets, exec: &ExecOffsets) -> Option<[u8; 16]> {
    if exec.task_size == 0 || exec.mm_size == 0 {
        return None;
    }
    // SAFETY: bpf_get_current_task returns the current task_struct pointer.
    let task: u64 = unsafe { bpf_get_current_task() };
    if task == 0 {
        return None;
    }
    let mm: u64 = titan_probe(task, exec.task_mm)?;
    if mm == 0 {
        // Kernel threads and tasks between exec/exit have no user mm.
        return None;
    }
    let exe_file: u64 = titan_probe(mm, exec.mm_exe_file)?;
    let (dev, ino) = file_identity(exe_file, offsets)?;
    Some(persistence_identity_key(dev, ino))
}
