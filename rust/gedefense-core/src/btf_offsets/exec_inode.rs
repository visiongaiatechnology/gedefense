//! V6.3.0 AP-1 executable-inode identity offsets: resolves the independent
//! `task_struct.mm -> mm_struct.exe_file -> file.f_inode -> inode.i_ino/i_sb ->
//! super_block.s_dev` chain and publishes it through
//! `resolve_vmlinux_exec_inode_offsets`.

use super::layout::VMLINUX_BTF_PATH;
use super::parser::VmlinuxBtf;

/// V6.3.0 AP-1: resolved executable-inode identity offsets
/// (`task_struct.mm -> mm_struct.exe_file -> file.f_inode ->
/// inode.i_ino / inode.i_sb -> super_block.s_dev`).
///
/// Deliberately a *second*, independent table: the 6.2 `TitanExecOffsets`
/// layout/indices must not change (the existing `TITAN_EXEC_OFFSETS` ABI is
/// frozen), while this resolver also needs the `task_struct`/`mm_struct` sizes
/// that the Titan table never carried. The core publishes the offsets through
/// the AP-1 `EXEC_INODE_OFFSETS` eBPF map; the eBPF helpers re-validate them.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExecInodeOffsets {
    pub task_mm_off: u32,
    pub task_size: u32,
    pub mm_exe_file_off: u32,
    pub mm_size: u32,
    pub file_f_inode_off: u32,
    pub inode_i_ino_off: u32,
    pub inode_i_sb_off: u32,
    pub super_s_dev_off: u32,
    /// Structure sizes used to prove every offset is inside its structure.
    /// They stay in the resolver/validator: only the two shipped identity-map
    /// sizes (`task_size`/`mm_size`) are published to eBPF.
    pub file_size: u32,
    pub inode_size: u32,
    pub super_size: u32,
}

impl VmlinuxBtf {
    /// V6.3.0 AP-1: resolves and validates the executable-inode identity offsets
    /// (`task_struct.mm -> mm_struct.exe_file -> file.f_inode ->
    /// inode.i_ino / inode.i_sb -> super_block.s_dev`). Independent of
    /// [`Self::resolve_titan_exec`] so the frozen 6.2 `TITAN_EXEC_OFFSETS`
    /// layout/indices stay untouched. Every missing field, implausible struct
    /// size or out-of-bounds/misaligned offset is an `Err`: the caller then keeps
    /// the AP-1 gate fail-open (comm fallback) and reports the degradation.
    pub fn resolve_exec_inode(&self) -> Result<ExecInodeOffsets, String> {
        let task = self.struct_by_name("task_struct")?;
        let mm = self.struct_by_name("mm_struct")?;
        let file = self.struct_by_name("file")?;
        let inode = self.struct_by_name("inode")?;
        let super_block = self.struct_by_name("super_block")?;
        let byte = |root: u32, path: &[&str]| -> Result<u32, String> {
            Ok(self.field_ref(root, path)?.0)
        };
        let offsets = ExecInodeOffsets {
            task_mm_off: byte(task, &["mm"])?,
            task_size: self.type_size(task)?,
            mm_exe_file_off: byte(mm, &["exe_file"])?,
            mm_size: self.type_size(mm)?,
            file_f_inode_off: byte(file, &["f_inode"])?,
            inode_i_ino_off: byte(inode, &["i_ino"])?,
            inode_i_sb_off: byte(inode, &["i_sb"])?,
            super_s_dev_off: byte(super_block, &["s_dev"])?,
            file_size: self.type_size(file)?,
            inode_size: self.type_size(inode)?,
            super_size: self.type_size(super_block)?,
        };
        crate::btf_validate::validate_exec_inode_offsets(&offsets)?;
        Ok(offsets)
    }
}

/// V6.3.0 AP-1: reads `/sys/kernel/btf/vmlinux` and resolves the validated
/// executable-inode identity offsets. Kept as a separate entry point because the
/// AP-1 gate must be able to load independently of the Titan exec gate.
pub fn resolve_vmlinux_exec_inode_offsets() -> Result<ExecInodeOffsets, String> {
    VmlinuxBtf::from_path(VMLINUX_BTF_PATH)?.resolve_exec_inode()
}
