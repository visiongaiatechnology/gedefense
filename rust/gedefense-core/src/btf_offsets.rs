//! Point 1 (§4.1/§6): mini-BTF parser and Titan exec-gate runtime offsets.
//!
//! Reads `/sys/kernel/btf/vmlinux` (64 MiB bound), accepts BTF v1 with
//! `hdr_len >= 24`, walks STRUCT/UNION/FUNC/FUNC_PROTO (other documented kinds
//! are skipped by their exact length) and resolves the §4.1 byte offsets,
//! including both ctime layouts (`i_ctime_sec`/`i_ctime_nsec` split or
//! `i_ctime.tv_sec`/`tv_nsec`). Anonymous members recurse, `kind_flag`
//! bitfields are masked, TYPEDEF/CONST chains stripped. Every missing or
//! implausible type/field/size/width/arity is an `Err`: the gate reports
//! `unavailable` and attaches nothing (§8). Fixtures live in `main.rs` tests.

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

const KIND_INT: u8 = 1;
const KIND_PTR: u8 = 2;
const KIND_ARRAY: u8 = 3;
const KIND_STRUCT: u8 = 4;
const KIND_UNION: u8 = 5;
const KIND_ENUM: u8 = 6;
const KIND_FWD: u8 = 7;
const KIND_TYPEDEF: u8 = 8;
const KIND_VOLATILE: u8 = 9;
const KIND_CONST: u8 = 10;
const KIND_RESTRICT: u8 = 11;
const KIND_FUNC: u8 = 12;
const KIND_FUNC_PROTO: u8 = 13;
const KIND_VAR: u8 = 14;
const KIND_DATASEC: u8 = 15;
const KIND_FLOAT: u8 = 16;
const KIND_DECL_TAG: u8 = 17;
const KIND_TYPE_TAG: u8 = 18;
const KIND_ENUM64: u8 = 19;
const DEPTH_LIMIT: u8 = 16;

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

fn u16_at(data: &[u8], at: usize) -> Result<u16, String> {
    let slice = data.get(at..at + 2).ok_or_else(|| format!("truncated BTF at {at}"))?;
    Ok(u16::from_le_bytes(slice.try_into().expect("2 bytes")))
}

fn u32_at(data: &[u8], at: usize) -> Result<u32, String> {
    let slice = data.get(at..at + 4).ok_or_else(|| format!("truncated BTF at {at}"))?;
    Ok(u32::from_le_bytes(slice.try_into().expect("4 bytes")))
}

#[derive(Clone, Copy, Default)]
struct Member {
    name_off: u32,
    type_id: u32,
    bit_off: u32,
}

struct BtfType {
    name_off: u32,
    kind: u8,
    value: u32,
    members: Vec<Member>,
    params: Vec<u32>,
}

/// Parsed BTF image (types retained, strings referenced in place).
pub struct VmlinuxBtf {
    data: Vec<u8>,
    str_start: usize,
    str_end: usize,
    types: Vec<BtfType>,
}

impl VmlinuxBtf {
    /// Bounded read of `path` followed by [`Self::parse`].
    pub fn from_path(path: &str) -> Result<Self, String> {
        use std::io::Read as _;
        let file = std::fs::File::open(path).map_err(|error| format!("open {path}: {error}"))?;
        let length = file.metadata().map_err(|error| format!("stat {path}: {error}"))?.len();
        if length > MAX_VMLINUX_BTF_BYTES as u64 {
            return Err(format!("BTF length {length} exceeds the 64 MiB bound"));
        }
        let mut data = Vec::with_capacity(length as usize + 1);
        file.take(MAX_VMLINUX_BTF_BYTES as u64 + 1)
            .read_to_end(&mut data)
            .map_err(|error| format!("read {path}: {error}"))?;
        if data.len() > MAX_VMLINUX_BTF_BYTES {
            return Err("BTF grew beyond the 64 MiB read bound".to_owned());
        }
        Self::parse(data)
    }

    /// Parses a raw BTF image; every structurally impossible byte is an `Err`.
    pub fn parse(data: Vec<u8>) -> Result<Self, String> {
        if data.len() < BTF_HEADER_BYTES {
            return Err("BTF is shorter than its 24-byte header".to_owned());
        }
        let magic = u16_at(&data, 0)?;
        let version = data[2];
        let hdr_len = u32_at(&data, 4)? as usize;
        if magic != BTF_MAGIC {
            return Err(format!("BTF magic {magic:#06x} is not {BTF_MAGIC:#06x}"));
        }
        // BTF v1 allows a header longer than 24 bytes (the kernel grew it to 32
        // bytes in 7.3). hdr_len is the base of both section offsets, so only
        // an undersized or structurally impossible header is rejected.
        if version != BTF_VERSION {
            return Err(format!("BTF version {version} is not {BTF_VERSION}"));
        }
        if hdr_len < BTF_HEADER_BYTES || hdr_len > data.len() {
            return Err(format!(
                "BTF hdr_len {hdr_len} is outside {BTF_HEADER_BYTES}..={}",
                data.len()
            ));
        }
        let type_off = u32_at(&data, 8)? as usize;
        let type_len = u32_at(&data, 12)? as usize;
        let str_off = u32_at(&data, 16)? as usize;
        let str_len = u32_at(&data, 20)? as usize;
        if str_len == 0 {
            return Err("BTF string section is empty".to_owned());
        }
        let type_start = hdr_len.checked_add(type_off).ok_or("BTF type section overflows")?;
        let type_end = type_start.checked_add(type_len).ok_or("BTF type section overflows")?;
        let str_start = hdr_len.checked_add(str_off).ok_or("BTF string section overflows")?;
        let str_end = str_start.checked_add(str_len).ok_or("BTF string section overflows")?;
        if type_end > data.len() || str_end > data.len() {
            return Err("BTF section lies outside the image".to_owned());
        }
        if type_end > str_start {
            return Err("BTF type and string sections overlap".to_owned());
        }
        let mut types = Vec::new();
        let mut at = type_start;
        while at < type_end {
            if at + 12 > type_end {
                return Err("truncated BTF type header".to_owned());
            }
            let name_off = u32_at(&data, at)?;
            let info = u32_at(&data, at + 4)?;
            let value = u32_at(&data, at + 8)?;
            let kind = ((info >> 24) & 0x1f) as u8;
            let kind_flag = info & (1 << 31) != 0;
            let vlen = (info & 0xffff) as usize;
            at += 12;
            let extra = match kind {
                KIND_INT | KIND_VAR | KIND_DECL_TAG => 4,
                KIND_ARRAY => 12,
                KIND_ENUM => vlen * 8,
                KIND_STRUCT | KIND_UNION | KIND_DATASEC => vlen * 12,
                KIND_FUNC_PROTO => vlen * 8,
                KIND_ENUM64 => vlen * 12,
                KIND_PTR | KIND_FWD | KIND_TYPEDEF | KIND_VOLATILE | KIND_CONST | KIND_RESTRICT
                | KIND_FUNC | KIND_FLOAT | KIND_TYPE_TAG => 0,
                other => return Err(format!("unsupported BTF kind {other}")),
            };
            if at + extra > type_end {
                return Err("truncated BTF type body".to_owned());
            }
            let mut parsed = BtfType {
                name_off,
                kind,
                value,
                members: Vec::new(),
                params: Vec::new(),
            };
            if matches!(kind, KIND_STRUCT | KIND_UNION) {
                for index in 0..vlen {
                    let base = at + index * 12;
                    let raw = u32_at(&data, base + 8)?;
                    parsed.members.push(Member {
                        name_off: u32_at(&data, base)?,
                        type_id: u32_at(&data, base + 4)?,
                        bit_off: if kind_flag { raw & 0x00ff_ffff } else { raw },
                    });
                }
            } else if kind == KIND_FUNC_PROTO {
                for index in 0..vlen {
                    parsed.params.push(u32_at(&data, at + index * 8 + 4)?);
                }
            }
            types.push(parsed);
            at += extra;
        }
        if at != type_end {
            return Err("BTF type section length mismatch".to_owned());
        }
        Ok(Self {
            data,
            str_start,
            str_end,
            types,
        })
    }

    fn name(&self, offset: u32) -> Result<&str, String> {
        let offset = offset as usize;
        if offset >= self.str_end - self.str_start {
            return Err(format!("BTF string offset {offset} is out of range"));
        }
        let tail = &self.data[self.str_start + offset..self.str_end];
        let length = tail.iter().position(|byte| *byte == 0).ok_or("unterminated BTF string")?;
        std::str::from_utf8(&tail[..length]).map_err(|_| "non-UTF8 BTF string".to_owned())
    }

    fn ty(&self, id: u32) -> Result<&BtfType, String> {
        let index = (id as usize)
            .checked_sub(1)
            .filter(|index| *index < self.types.len())
            .ok_or_else(|| format!("BTF type id {id} is out of range"))?;
        Ok(&self.types[index])
    }

    /// Follows TYPEDEF/CONST/VOLATILE/RESTRICT/TYPE_TAG chains to the real type.
    fn strip(&self, mut id: u32) -> Result<u32, String> {
        for _ in 0..DEPTH_LIMIT {
            let ty = self.ty(id)?;
            match ty.kind {
                KIND_TYPEDEF | KIND_VOLATILE | KIND_CONST | KIND_RESTRICT | KIND_TYPE_TAG => {
                    id = ty.value
                }
                _ => return Ok(id),
            }
        }
        Err("BTF type alias chain is too deep".to_owned())
    }

    fn struct_by_name(&self, name: &str) -> Result<u32, String> {
        let mut found = None;
        for (index, ty) in self.types.iter().enumerate() {
            if ty.kind == KIND_STRUCT && self.name(ty.name_off)? == name {
                if found.is_some() {
                    return Err(format!("BTF struct {name} is ambiguous"));
                }
                found = Some(index as u32 + 1);
            }
        }
        found.ok_or_else(|| format!("BTF struct {name} is missing"))
    }

    fn type_size(&self, id: u32) -> Result<u32, String> {
        let id = self.strip(id)?;
        let ty = self.ty(id)?;
        match ty.kind {
            KIND_STRUCT | KIND_UNION | KIND_INT | KIND_ENUM | KIND_FLOAT | KIND_ENUM64
            | KIND_DATASEC => Ok(ty.value),
            _ => Err(format!("BTF type {id} has no size")),
        }
    }

    /// Resolves a field path to `(byte offset, BTF type id of the final member)`;
    /// the type id lets callers ask for the real member width (ctime layout).
    fn field_ref(&self, root: u32, path: &[&str]) -> Result<(u32, u32), String> {
        let (bits, type_id) = self.field_in(root, path, 0)?;
        if bits % 8 != 0 {
            return Err(format!("BTF field {path:?} is not byte aligned"));
        }
        Ok((bits / 8, type_id))
    }

    fn field_in(&self, type_id: u32, path: &[&str], depth: u8) -> Result<(u32, u32), String> {
        let Some((first, rest)) = path.split_first() else {
            return Ok((0, type_id));
        };
        if depth > DEPTH_LIMIT {
            return Err("BTF field path is too deep".to_owned());
        }
        let id = self.strip(type_id)?;
        let ty = self.ty(id)?;
        if !matches!(ty.kind, KIND_STRUCT | KIND_UNION) {
            return Err(format!("BTF type {id} is not a struct or union"));
        }
        for member in &ty.members {
            if member.name_off != 0 && self.name(member.name_off)? == *first {
                let (nested, nested_type) = self.field_in(member.type_id, rest, depth + 1)?;
                let bits = member
                    .bit_off
                    .checked_add(nested)
                    .ok_or_else(|| "BTF member offset overflows".to_owned())?;
                return Ok((bits, nested_type));
            }
        }
        // Anonymous struct/union members share the parent namespace at their
        // own bit offset (the kernel keeps `i_nlink`/`i_ctime` inside one).
        for member in &ty.members {
            if member.name_off == 0
                && matches!(self.ty(self.strip(member.type_id)?)?.kind, KIND_STRUCT | KIND_UNION)
            {
                if let Ok((nested, nested_type)) = self.field_in(member.type_id, path, depth + 1) {
                    let bits = member
                        .bit_off
                        .checked_add(nested)
                        .ok_or_else(|| "BTF member offset overflows".to_owned())?;
                    return Ok((bits, nested_type));
                }
            }
        }
        Err(format!("BTF field {first} is missing"))
    }

    fn func_nargs(&self, name: &str) -> Result<u32, String> {
        let mut proto = None;
        for ty in &self.types {
            if ty.kind == KIND_FUNC && self.name(ty.name_off)? == name {
                if proto.is_some() {
                    return Err(format!("BTF function {name} is ambiguous"));
                }
                proto = Some(ty.value);
            }
        }
        let proto_id = self.strip(proto.ok_or_else(|| format!("BTF function {name} is missing"))?)?;
        let ty = self.ty(proto_id)?;
        if ty.kind != KIND_FUNC_PROTO {
            return Err(format!("BTF function {name} has no FUNC_PROTO"));
        }
        u32::try_from(ty.params.len()).map_err(|_| format!("BTF function {name} is oversized"))
    }

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
