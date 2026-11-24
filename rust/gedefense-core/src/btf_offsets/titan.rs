//! §4.1 Titan exec-gate offsets: resolves `struct linux_binprm`/`file`/`inode`/
//! `super_block`/`dentry` byte offsets and the LSM hook arities from a parsed
//! BTF image and publishes them through `resolve_vmlinux_offsets`.

use super::layout::VMLINUX_BTF_PATH;
use super::parser::VmlinuxBtf;

/// Resolved §4.1 offsets: byte offsets, hook arities, arg indices and sizes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TitanExecOffsets {
    pub bprm_file_off: u32,
    pub file_f_inode_off: u32,
    pub inode_i_ino_off: u32,
    pub inode_i_sb_off: u32,
    pub inode_i_nlink_off: u32,
    pub inode_i_mode_off: u32,
    pub inode_i_generation_off: u32,
    pub super_s_dev_off: u32,
    pub super_s_magic_off: u32,
    pub inode_i_ctime_sec_off: u32,
    pub inode_i_ctime_nsec_off: u32,
    pub inode_i_ctime_nsec_width: u32,
    pub bprm_filename_off: u32,
    pub inode_i_uid_off: u32,
    pub file_f_path_dentry_off: u32,
    pub dentry_d_parent_off: u32,
    pub dentry_d_inode_off: u32,
    pub dentry_size: u32,
    pub bprm_nargs: u32,
    pub mmap_nargs: u32,
    pub mmap_file_arg_idx: u32,
    pub mmap_prot_arg_idx: u32,
    pub mmap_flags_arg_idx: u32,
    pub bprm_retval_slot: u32,
    pub mmap_retval_slot: u32,
    pub inode_size: u32,
    pub file_size: u32,
    pub bprm_size: u32,
    pub super_size: u32,
}

impl VmlinuxBtf {
    /// Resolves and validates the §4.1 offsets from this image.
    pub fn resolve_titan_exec(&self) -> Result<TitanExecOffsets, String> {
        let inode = self.struct_by_name("inode")?;
        let file = self.struct_by_name("file")?;
        let bprm = self.struct_by_name("linux_binprm")?;
        let super_block = self.struct_by_name("super_block")?;
        // §4.1 ABI 2: struct dentry carries the bounded ancestor walk used by
        // the UNTRUSTED exec mode (world-writable drop path detection).
        let dentry = self.struct_by_name("dentry")?;
        let byte = |root: u32, path: &[&str]| -> Result<u32, String> {
            Ok(self.field_ref(root, path)?.0)
        };
        // §4.1 ctime-Layout-Vertrag: modern kernels split the timestamp into
        // `i_ctime_sec` (8 B) + `i_ctime_nsec` (4 B); older ones keep a
        // timespec64. Both publish SEC_OFF, NSEC_OFF and NSEC_WIDTH; a missing
        // or implausible pair is an Err (§8 fail-safe, no attach).
        let ctime = match (
            self.field_ref(inode, &["i_ctime_sec"]),
            self.field_ref(inode, &["i_ctime_nsec"]),
        ) {
            (Ok(sec), Ok(nsec)) => Some((sec, nsec)),
            _ => None,
        };
        let ((sec_off, sec_type), (nsec_off, nsec_type)) = match ctime {
            Some(fields) => fields,
            None => (
                self.field_ref(inode, &["i_ctime", "tv_sec"])?,
                self.field_ref(inode, &["i_ctime", "tv_nsec"])?,
            ),
        };
        let sec_width = self.type_size(sec_type)?;
        let nsec_width = self.type_size(nsec_type)?;
        if sec_width != 8 || !matches!(nsec_width, 4 | 8) {
            return Err(format!(
                "BTF inode i_ctime widths are implausible (sec {sec_width}, nsec {nsec_width})"
            ));
        }
        let bprm_nargs = self.func_nargs("bpf_lsm_bprm_check_security")?;
        let mmap_nargs = self.func_nargs("bpf_lsm_mmap_file")?;
        let offsets = TitanExecOffsets {
            bprm_file_off: byte(bprm, &["file"])?,
            file_f_inode_off: byte(file, &["f_inode"])?,
            inode_i_ino_off: byte(inode, &["i_ino"])?,
            inode_i_sb_off: byte(inode, &["i_sb"])?,
            inode_i_nlink_off: byte(inode, &["i_nlink"])?,
            inode_i_mode_off: byte(inode, &["i_mode"])?,
            inode_i_generation_off: byte(inode, &["i_generation"])?,
            super_s_dev_off: byte(super_block, &["s_dev"])?,
            super_s_magic_off: byte(super_block, &["s_magic"])?,
            inode_i_ctime_sec_off: sec_off,
            inode_i_ctime_nsec_off: nsec_off,
            inode_i_ctime_nsec_width: nsec_width,
            bprm_filename_off: byte(bprm, &["filename"])?,
            inode_i_uid_off: byte(inode, &["i_uid"])?,
            file_f_path_dentry_off: byte(file, &["f_path", "dentry"])?,
            dentry_d_parent_off: byte(dentry, &["d_parent"])?,
            dentry_d_inode_off: byte(dentry, &["d_inode"])?,
            dentry_size: self.type_size(dentry)?,
            bprm_nargs,
            mmap_nargs,
            mmap_file_arg_idx: 0,
            mmap_prot_arg_idx: mmap_nargs.checked_sub(2).ok_or("mmap_file has < 2 args")?,
            mmap_flags_arg_idx: mmap_nargs.checked_sub(1).ok_or("mmap_file has 0 args")?,
            bprm_retval_slot: bprm_nargs,
            mmap_retval_slot: mmap_nargs,
            inode_size: self.type_size(inode)?,
            file_size: self.type_size(file)?,
            bprm_size: self.type_size(bprm)?,
            super_size: self.type_size(super_block)?,
        };
        crate::btf_validate::validate_offsets(&offsets)?;
        Ok(offsets)
    }
}

/// Reads `/sys/kernel/btf/vmlinux` and resolves the validated §4.1 offsets.
pub fn resolve_vmlinux_offsets() -> Result<TitanExecOffsets, String> {
    VmlinuxBtf::from_path(VMLINUX_BTF_PATH)?.resolve_titan_exec()
}
