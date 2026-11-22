//! Point 1 (§4.1/§6): plausibility gate for the resolved Titan runtime offsets.
//!
//! Split out of `btf_offsets.rs` (module size cap): the BTF parser only resolves
//! byte offsets, this module decides whether the resolved table may ever be
//! published to eBPF. Every violation is an `Err` (`unavailable`, no attach).

use crate::btf_offsets::TitanExecOffsets;

pub(crate) fn validate_offsets(offsets: &TitanExecOffsets) -> Result<(), String> {let fields = [
        ("linux_binprm.file", offsets.bprm_file_off, 8, offsets.bprm_size),
        ("file.f_inode", offsets.file_f_inode_off, 8, offsets.file_size),
        ("inode.i_ino", offsets.inode_i_ino_off, 8, offsets.inode_size),
        ("inode.i_sb", offsets.inode_i_sb_off, 8, offsets.inode_size),
        ("inode.i_nlink", offsets.inode_i_nlink_off, 4, offsets.inode_size),
        ("inode.i_mode", offsets.inode_i_mode_off, 2, offsets.inode_size),
        ("inode.i_generation", offsets.inode_i_generation_off, 4, offsets.inode_size),
        ("super_block.s_dev", offsets.super_s_dev_off, 4, offsets.super_size),
        ("super_block.s_magic", offsets.super_s_magic_off, 8, offsets.super_size),
        ("inode.i_ctime_sec", offsets.inode_i_ctime_sec_off, 8, offsets.inode_size),
        // §4.1 ABI 2 (UNTRUSTED mode facts).
        ("linux_binprm.filename", offsets.bprm_filename_off, 8, offsets.bprm_size),
        ("inode.i_uid", offsets.inode_i_uid_off, 4, offsets.inode_size),
        ("file.f_path.dentry", offsets.file_f_path_dentry_off, 8, offsets.file_size),
        ("dentry.d_parent", offsets.dentry_d_parent_off, 8, offsets.dentry_size),
        ("dentry.d_inode", offsets.dentry_d_inode_off, 8, offsets.dentry_size),
    ];
    for (label, offset, width, size) in fields {
        let end = offset.checked_add(width).ok_or_else(|| format!("{label}: offset overflows"))?;
        if end > size {
            return Err(format!("{label}: {offset}+{width} exceeds size {size}"));
        }
    }
    if offsets.inode_i_ctime_nsec_off <= offsets.inode_i_ctime_sec_off {
        return Err("inode.i_ctime: nsec does not follow sec".to_owned());
    }
    let nsec_end = offsets.inode_i_ctime_nsec_off + offsets.inode_i_ctime_nsec_width;
    if !matches!(offsets.inode_i_ctime_nsec_width, 4 | 8) || nsec_end > offsets.inode_size {
        return Err("inode.i_ctime: nsec width or offset range is implausible".to_owned());
    }
    // §4.1: bprm_check_security carries the binprm only, mmap_file has 3..=5
    // (6.18/7.0: 4) arguments; retval slot and indices follow from the arity.
    if offsets.bprm_nargs != 1 {
        return Err(format!("bpf_lsm_bprm_check_security has {} args, expected 1", offsets.bprm_nargs));
    }
    if !(3..=5).contains(&offsets.mmap_nargs) {
        return Err(format!("bpf_lsm_mmap_file has {} args, expected 3..=5", offsets.mmap_nargs));
    }
    if offsets.mmap_file_arg_idx != 0
        || offsets.mmap_prot_arg_idx + 2 != offsets.mmap_nargs
        || offsets.mmap_flags_arg_idx + 1 != offsets.mmap_nargs
        || offsets.bprm_retval_slot != offsets.bprm_nargs
        || offsets.mmap_retval_slot != offsets.mmap_nargs
    {
        return Err("Titan exec hook argument indices are inconsistent".to_owned());
    }
    if [offsets.inode_size, offsets.file_size, offsets.bprm_size, offsets.super_size,
        offsets.dentry_size]
        .iter()
        .any(|size| *size == 0 || *size > 64 * 1024)
    {
        return Err("Titan exec struct size is zero or implausible".to_owned());
    }
    Ok(())
}
