use super::*;

/// LSM/TracePoint program names and kernel hook names (ABI with the eBPF object).
pub(super) const PROGRAM_FILE_OPEN: &str = "gedefense_persistence_file_open";
pub(super) const HOOK_FILE_OPEN: &str = "file_open";
pub(super) const PROGRAM_MMAP: &str = "gedefense_persistence_mmap";
pub(super) const HOOK_MMAP: &str = "mmap_file";
pub(super) const PROGRAM_PTRACE: &str = "gedefense_persistence_ptrace";
pub(super) const HOOK_PTRACE: &str = "ptrace_access_check";
pub(super) const PROGRAM_READV: &str = "gedefense_process_vm_readv";
pub(super) const PROGRAM_WRITEV: &str = "gedefense_process_vm_writev";
pub(super) const TRACEPOINT_CATEGORY: &str = "syscalls";
pub(super) const TRACEPOINT_READV: &str = "sys_enter_process_vm_readv";
pub(super) const TRACEPOINT_WRITEV: &str = "sys_enter_process_vm_writev";

/// Status `attached` bitmask (documented in the Go parser as well).
pub(crate) const PERSIST_HOOK_FILE_OPEN: u64 = 1 << 0;
pub(crate) const PERSIST_HOOK_MMAP: u64 = 1 << 1;
pub(crate) const PERSIST_HOOK_PTRACE: u64 = 1 << 2;
pub(crate) const PERSIST_HOOK_READV: u64 = 1 << 3;
pub(crate) const PERSIST_HOOK_WRITEV: u64 = 1 << 4;
pub(crate) const PERSIST_STATUS_IDENTITY_OFFSETS: u64 = 1 << 5;
pub(crate) const PERSIST_STATUS_PKGDB_READY: u64 = 1 << 6;
pub(crate) const PERSIST_STATUS_READV_OFFSETS: u64 = 1 << 7;
pub(crate) const PERSIST_STATUS_WRITEV_OFFSETS: u64 = 1 << 8;
pub(crate) const PERSIST_STATUS_READ_FAILURES: u64 = 1 << 9;
pub(crate) const PERSIST_STATUS_SESSIONS_KNOWN: u64 = 1 << 10;

impl PersistenceCore {
    pub(super) fn resolve_and_publish_offsets(&mut self) {
        let resolved = match resolve_persistence_offsets() {
            Ok(resolved) => resolved,
            Err(error) => {
                eprintln!(
                    "GeDefense persistence guard: BTF/tracefs offsets unavailable ({error}); the file ladder stays fail-open and reports offsets=0"
                );
                self.publish_offset_table(&ResolvedOffsets::default());
                return;
            }
        };
        self.identity_offsets_ok = resolved.file_f_inode != u32::MAX
            && resolved.inode_i_ino != u32::MAX
            && resolved.inode_i_sb != u32::MAX
            && resolved.super_s_dev != u32::MAX
            && resolved.file_file_size != u32::MAX
            && resolved.inode_size != u32::MAX
            && resolved.super_size != u32::MAX
            && resolved.file_open_nargs == PERSIST_FILE_OPEN_NARGS_EXPECTED;
        self.readv_offsets_ok = resolved.readv_ready;
        self.writev_offsets_ok = resolved.writev_ready;
        self.publish_offset_table(&resolved);
    }
}

impl PersistenceCore {
    pub(super) fn publish_offset_table(&mut self, offsets: &ResolvedOffsets) {
        let mut table = [0u32; PERSIST_OFFSETS_TABLE_LEN];
        table[PERSIST_OFF_MAGIC as usize] = PERSIST_OFFSETS_MAGIC;
        table[PERSIST_OFF_ABI as usize] = PERSIST_OFFSETS_ABI;
        table[PERSIST_OFF_FILE_OPEN_NARGS as usize] = offsets.file_open_nargs;
        table[PERSIST_OFF_FILE_OPEN_PREV as usize] = offsets.file_open_nargs;
        table[PERSIST_OFF_MMAP_NARGS as usize] = offsets.mmap_nargs;
        table[PERSIST_OFF_MMAP_FILE_ARG as usize] = PERSIST_MMAP_FILE_ARG_PLACEHOLDER;
        if offsets.mmap_nargs >= 3 {
            table[PERSIST_OFF_MMAP_PROT_ARG as usize] = offsets.mmap_nargs - 2;
            table[PERSIST_OFF_MMAP_PREV as usize] = offsets.mmap_nargs;
        }
        table[PERSIST_OFF_PTRACE_NARGS as usize] = offsets.ptrace_nargs;
        table[PERSIST_OFF_PTRACE_CHILD_ARG as usize] = PERSIST_PTRACE_CHILD_ARG;
        table[PERSIST_OFF_PTRACE_MODE_ARG as usize] = PERSIST_PTRACE_MODE_ARG;
        if offsets.ptrace_nargs == PERSIST_PTRACE_NARGS_EXPECTED {
            table[PERSIST_OFF_PTRACE_PREV as usize] = offsets.ptrace_nargs;
        }
        table[PERSIST_OFF_FILE_F_INODE as usize] = offsets.file_f_inode;
        table[PERSIST_OFF_FILE_F_FLAGS as usize] = offsets.file_f_flags;
        table[PERSIST_OFF_FILE_SIZE as usize] = offsets.file_file_size;
        table[PERSIST_OFF_FILE_F_PATH_DENTRY as usize] = offsets.file_f_dentry;
        table[PERSIST_OFF_INODE_I_INO as usize] = offsets.inode_i_ino;
        table[PERSIST_OFF_INODE_I_SB as usize] = offsets.inode_i_sb;
        table[PERSIST_OFF_INODE_I_MODE as usize] = offsets.inode_i_mode;
        table[PERSIST_OFF_INODE_SIZE as usize] = offsets.inode_size;
        table[PERSIST_OFF_SUPER_S_DEV as usize] = offsets.super_s_dev;
        table[PERSIST_OFF_SUPER_SIZE as usize] = offsets.super_size;
        table[PERSIST_OFF_DENTRY_D_PARENT as usize] = offsets.dentry_parent;
        table[PERSIST_OFF_DENTRY_D_INODE as usize] = offsets.dentry_inode;
        table[PERSIST_OFF_DENTRY_SIZE as usize] = offsets.dentry_size;
        table[PERSIST_OFF_TASK_PID as usize] = offsets.task_pid;
        table[PERSIST_OFF_TASK_TGID as usize] = offsets.task_tgid;
        table[PERSIST_OFF_TASK_MM as usize] = offsets.task_mm;
        table[PERSIST_OFF_TASK_SIZE as usize] = offsets.task_size;
        table[PERSIST_OFF_MM_EXE_FILE as usize] = offsets.mm_exe_file;
        table[PERSIST_OFF_MM_SIZE as usize] = offsets.mm_size;
        table[PERSIST_OFF_READV_PID as usize] = offsets.readv_pid;
        table[PERSIST_OFF_READV_TARGET as usize] = offsets.readv_target;
        table[PERSIST_OFF_READV_SIZE as usize] = offsets.readv_size;
        table[PERSIST_OFF_WRITEV_PID as usize] = offsets.writev_pid;
        table[PERSIST_OFF_WRITEV_TARGET as usize] = offsets.writev_target;
        table[PERSIST_OFF_WRITEV_SIZE as usize] = offsets.writev_size;
        for (index, value) in table.iter().enumerate() {
            if let Err(error) = self.offsets_map.set(index as u32, *value, 0) {
                eprintln!(
                    "GeDefense persistence guard: offsets map write at {index} failed: {error}"
                );
                break;
            }
        }
    }

    // -- hook ladder --------------------------------------------------------
}

impl PersistenceCore {
    pub(super) fn attach_hooks(
        &mut self,
        ebpf: &mut Ebpf,
        btf: Option<&Btf>,
        bpf_lsm_active: bool,
    ) {
        if !bpf_lsm_active {
            eprintln!(
                "persistence guard LSM hooks inactive: BPF-LSM is not active (no attach, no visibility claim)"
            );
        } else if let Some(btf) = btf {
            self.hook_file_open = attach_lsm_program(ebpf, btf, PROGRAM_FILE_OPEN, HOOK_FILE_OPEN);
            self.hook_mmap = attach_lsm_program(ebpf, btf, PROGRAM_MMAP, HOOK_MMAP);
            self.hook_ptrace = attach_lsm_program(ebpf, btf, PROGRAM_PTRACE, HOOK_PTRACE);
        } else {
            eprintln!("persistence guard LSM hooks inactive: BPF-LSM BTF unavailable");
        }
        self.hook_readv =
            attach_tracepoint_program(ebpf, PROGRAM_READV, TRACEPOINT_CATEGORY, TRACEPOINT_READV);
        self.hook_writev =
            attach_tracepoint_program(ebpf, PROGRAM_WRITEV, TRACEPOINT_CATEGORY, TRACEPOINT_WRITEV);
    }

    // -- path contract ------------------------------------------------------
}

/// Constant used for the `PERSIST_GUARD_OFFSETS` mmap file-argument slot: the
/// `security_mmap_file` file argument is slot 0 by kernel ABI (published for the
/// eBPF reader to validate rather than assume).
pub(super) const PERSIST_MMAP_FILE_ARG_PLACEHOLDER: u32 = 0;

/// Attaches one LSM program; a missing program or an unsupported hook is logged
/// and reported as not attached, never hidden.
pub(super) fn attach_lsm_program(ebpf: &mut Ebpf, btf: &Btf, program: &str, hook: &str) -> bool {
    let Some(program) = ebpf.program_mut(&crate::chameleon::program_name(program)) else {
        eprintln!("persistence guard: LSM program {program} missing; not attached");
        return false;
    };
    let result = (|| -> Result<(), BoxError> {
        let lsm: &mut Lsm = program.try_into()?;
        lsm.load(hook, btf)?;
        lsm.attach()?;
        Ok(())
    })();
    match result {
        Ok(()) => true,
        Err(error) => {
            eprintln!("persistence guard: LSM {hook} attach failed ({error}); not attached");
            false
        }
    }
}

/// Attaches one syscall tracepoint program best-effort.
pub(super) fn attach_tracepoint_program(
    ebpf: &mut Ebpf,
    program: &str,
    category: &str,
    name: &str,
) -> bool {
    let Some(program) = ebpf.program_mut(&crate::chameleon::program_name(program)) else {
        eprintln!("persistence guard: tracepoint program {program} missing; not attached");
        return false;
    };
    let result = (|| -> Result<(), BoxError> {
        let tracepoint: &mut TracePoint = program.try_into()?;
        tracepoint.load()?;
        tracepoint.attach(category, name)?;
        Ok(())
    })();
    match result {
        Ok(()) => true,
        Err(error) => {
            eprintln!(
                "persistence guard: tracepoint {category}:{name} unavailable ({error}); not attached"
            );
            false
        }
    }
}
