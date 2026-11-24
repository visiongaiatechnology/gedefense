//! §6/§4.1 layout: vmlinux-BTF read bounds and header contract, the frozen
//! `TITAN_EXEC_OFFSETS` golden index table and the stable filesystem magics.

/// §6: read bound; header magic/version/size and canonical path.
pub const MAX_VMLINUX_BTF_BYTES: usize = 64 * 1024 * 1024;
pub const VMLINUX_BTF_PATH: &str = "/sys/kernel/btf/vmlinux";
pub const BTF_MAGIC: u16 = 0xeb9f;
pub const BTF_VERSION: u8 = 1;
pub const BTF_HEADER_BYTES: usize = 24;

// §4.1 `TITAN_EXEC_OFFSETS` index enum; the eBPF side reads these indices.
pub const TITAN_EXEC_OFFSETS_TABLE_LEN: usize = 48;
pub const OFF_MAGIC: usize = 0; pub const OFF_ABI: usize = 1;
pub const OFF_BPRM_FILE: usize = 2;
pub const OFF_FILE_F_INODE: usize = 3;
pub const OFF_INODE_I_INO: usize = 4;
pub const OFF_INODE_I_SB: usize = 5;
pub const OFF_INODE_I_NLINK: usize = 6;
pub const OFF_INODE_I_MODE: usize = 7;
pub const OFF_INODE_I_GEN: usize = 8;
pub const OFF_SUPER_S_DEV: usize = 9;
pub const OFF_SUPER_S_MAGIC: usize = 10;
pub const OFF_INODE_I_CTIME_SEC: usize = 11;
pub const OFF_INODE_I_CTIME_NSEC: usize = 12;
pub const OFF_BPRM_NARGS: usize = 13;
pub const OFF_MMAP_NARGS: usize = 14;
pub const OFF_MMAP_FILE_ARG: usize = 15;
pub const OFF_MMAP_PROT_ARG: usize = 16;
pub const OFF_MMAP_FLAGS_ARG: usize = 17;
pub const OFF_TMPFS_MAGIC: usize = 18;
pub const OFF_DEVTMPFS_MAGIC: usize = 19;
pub const OFF_PROC_MAGIC: usize = 20;
pub const OFF_SYSFS_MAGIC: usize = 21;
pub const OFF_OVERLAY_MAGIC: usize = 22;
pub const OFF_BPRM_RETVAL_SLOT: usize = 23;
pub const OFF_MMAP_RETVAL_SLOT: usize = 24;
pub const OFF_INODE_SIZE: usize = 25;
pub const OFF_FILE_SIZE: usize = 26;
pub const OFF_BPRM_SIZE: usize = 27;
/// §4.1 (ctime-Layout-Vertrag): byte width of `inode.i_ctime_nsec` (4|8).
pub const OFF_INODE_I_CTIME_NSEC_WIDTH: usize = 28;
// §4.1 ABI 2 (6.2.0): the UNTRUSTED execution-mode facts. `file.f_path.dentry`
// is the resolved absolute pointer offset inside `struct file` (nested member),
// the dentry walk is bounded by the eBPF program, and `dentry_size` bounds both
// pointer reads against the real structure size.
pub const OFF_BPRM_FILENAME: usize = 29;
pub const OFF_INODE_I_UID: usize = 30;
pub const OFF_FILE_F_PATH_DENTRY: usize = 31;
pub const OFF_DENTRY_D_PARENT: usize = 32;
pub const OFF_DENTRY_D_INODE: usize = 33;
pub const OFF_DENTRY_SIZE: usize = 34;
/// First reserved index after the ABI-2 offset set; asserted by the golden
/// layout tests so a future index cannot silently reuse a reserved slot.
#[allow(dead_code)]
pub const OFF_RESERVED_FIRST: usize = 35;

// §4.1 filesystem magic values (linux/magic.h UAPI, stable numbers).
pub const TMPFS_MAGIC: u32 = 0x0102_1994;
pub const DEVTMPFS_MAGIC: u32 = 0x0000_1cd1;
pub const PROC_SUPER_MAGIC: u32 = 0x0000_9fa0;
pub const SYSFS_MAGIC: u32 = 0x6265_6572;
pub const OVERLAYFS_SUPER_MAGIC: u32 = 0x794c_7630;
