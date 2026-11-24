use super::*;

pub(super) const PERSIST_BTF_MAGIC: u16 = 0xeb9f;
pub(super) const PERSIST_BTF_VERSION: u8 = 1;
pub(super) const PERSIST_BTF_HEADER_BYTES: usize = 24;
pub(super) const KIND_INT: u8 = 1;
pub(super) const KIND_PTR: u8 = 2;
pub(super) const KIND_ARRAY: u8 = 3;
pub(super) const KIND_STRUCT: u8 = 4;
pub(super) const KIND_UNION: u8 = 5;
pub(super) const KIND_ENUM: u8 = 6;
pub(super) const KIND_FWD: u8 = 7;
pub(super) const KIND_TYPEDEF: u8 = 8;
pub(super) const KIND_VOLATILE: u8 = 9;
pub(super) const KIND_CONST: u8 = 10;
pub(super) const KIND_RESTRICT: u8 = 11;
pub(super) const KIND_FUNC: u8 = 12;
pub(super) const KIND_FUNC_PROTO: u8 = 13;
pub(super) const KIND_VAR: u8 = 14;
pub(super) const KIND_DATASEC: u8 = 15;
pub(super) const KIND_FLOAT: u8 = 16;
pub(super) const KIND_DECL_TAG: u8 = 17;
pub(super) const KIND_TYPE_TAG: u8 = 18;
pub(super) const KIND_ENUM64: u8 = 19;
pub(super) const PERSIST_BTF_STRUCTS: [&str; 7] = [
    "task_struct",
    "file",
    "inode",
    "super_block",
    "dentry",
    "mm_struct",
    "path",
];
pub(super) const PERSIST_BTF_FUNCS: [&str; 3] = [
    "bpf_lsm_file_open",
    "bpf_lsm_mmap_file",
    "bpf_lsm_ptrace_access_check",
];

#[derive(Default)]
pub(super) struct BtfStructFacts {
    pub(super) size: u32,
    /// Named members of interest as `(bit offset)`; a non-byte-aligned member is
    /// stored as `u32::MAX` so a caller can never use a partial-byte field.
    pub(super) members: BTreeMap<String, u32>,
}

pub(super) struct BtfFacts {
    pub(super) structs: BTreeMap<&'static str, BtfStructFacts>,
    pub(super) func_nargs: BTreeMap<&'static str, u32>,
}

pub(super) fn btf_u16(data: &[u8], at: usize) -> Result<u16, String> {
    let slice = data
        .get(at..at + 2)
        .ok_or_else(|| format!("truncated BTF at {at}"))?;
    Ok(u16::from_le_bytes([slice[0], slice[1]]))
}

pub(super) fn btf_u32(data: &[u8], at: usize) -> Result<u32, String> {
    let slice = data
        .get(at..at + 4)
        .ok_or_else(|| format!("truncated BTF at {at}"))?;
    Ok(u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]))
}

pub(super) fn btf_string(
    data: &[u8],
    str_start: usize,
    str_end: usize,
    offset: u32,
) -> Result<&str, String> {
    let offset = offset as usize;
    if offset >= str_end.saturating_sub(str_start) {
        return Err(format!("BTF string offset {offset} is out of range"));
    }
    let tail = &data[str_start + offset..str_end];
    let length = tail
        .iter()
        .position(|byte| *byte == 0)
        .ok_or("unterminated BTF string")?;
    std::str::from_utf8(&tail[..length]).map_err(|_| "non-UTF8 BTF string".to_owned())
}

pub(super) fn interest_struct(name: &str) -> Option<&'static str> {
    PERSIST_BTF_STRUCTS
        .iter()
        .copied()
        .find(|candidate| *candidate == name)
}

pub(super) fn interest_func(name: &str) -> Option<&'static str> {
    PERSIST_BTF_FUNCS
        .iter()
        .copied()
        .find(|candidate| *candidate == name)
}

/// Parses just enough of the vmlinux BTF to resolve the AP-5 structure members
/// and LSM hook arities. Every structurally impossible byte is an `Err`; nothing
/// is inferred from a partial table.
pub(super) fn parse_persistence_btf(data: &[u8]) -> Result<BtfFacts, String> {
    if data.len() < PERSIST_BTF_HEADER_BYTES {
        return Err("BTF is shorter than its 24-byte header".to_owned());
    }
    if btf_u16(data, 0)? != PERSIST_BTF_MAGIC {
        return Err("BTF magic mismatch".to_owned());
    }
    if data[2] != PERSIST_BTF_VERSION {
        return Err(format!(
            "BTF version {} is not {PERSIST_BTF_VERSION}",
            data[2]
        ));
    }
    let hdr_len = btf_u32(data, 4)? as usize;
    let type_off = btf_u32(data, 8)? as usize;
    let type_len = btf_u32(data, 12)? as usize;
    let str_off = btf_u32(data, 16)? as usize;
    let str_len = btf_u32(data, 20)? as usize;
    if hdr_len < PERSIST_BTF_HEADER_BYTES || hdr_len > data.len() {
        return Err(format!("BTF hdr_len {hdr_len} is out of range"));
    }
    if str_len == 0 {
        return Err("BTF string section is empty".to_owned());
    }
    let type_start = hdr_len
        .checked_add(type_off)
        .ok_or("BTF type section overflows")?;
    let type_end = type_start
        .checked_add(type_len)
        .ok_or("BTF type section overflows")?;
    let str_start = hdr_len
        .checked_add(str_off)
        .ok_or("BTF string section overflows")?;
    let str_end = str_start
        .checked_add(str_len)
        .ok_or("BTF string section overflows")?;
    if type_end > data.len() || str_end > data.len() {
        return Err("BTF section lies outside the image".to_owned());
    }
    if type_end > str_start {
        return Err("BTF type and string sections overlap".to_owned());
    }

    let mut structs: BTreeMap<&'static str, BtfStructFacts> = BTreeMap::new();
    let mut func_proto_ids: BTreeMap<&'static str, u32> = BTreeMap::new();
    let mut proto_vlens: Vec<(u32, u32)> = Vec::new();
    let mut type_id: u32 = 0;
    let mut at = type_start;
    while at < type_end {
        if at + 12 > type_end {
            return Err("truncated BTF type header".to_owned());
        }
        let name_off = btf_u32(data, at)?;
        let info = btf_u32(data, at + 4)?;
        let value = btf_u32(data, at + 8)?;
        let kind = ((info >> 24) & 0x1f) as u8;
        let kind_flag = info & (1 << 31) != 0;
        let vlen = (info & 0xffff) as usize;
        let body = at + 12;
        let extra = match kind {
            KIND_INT | KIND_VAR | KIND_DECL_TAG => 4,
            KIND_ARRAY => 12,
            KIND_ENUM => vlen.checked_mul(8).ok_or("BTF enum overflows")?,
            KIND_STRUCT | KIND_UNION | KIND_DATASEC => {
                vlen.checked_mul(12).ok_or("BTF struct overflows")?
            }
            KIND_FUNC_PROTO => vlen.checked_mul(8).ok_or("BTF proto overflows")?,
            KIND_ENUM64 => vlen.checked_mul(12).ok_or("BTF enum64 overflows")?,
            KIND_PTR | KIND_FWD | KIND_TYPEDEF | KIND_VOLATILE | KIND_CONST | KIND_RESTRICT
            | KIND_FUNC | KIND_FLOAT | KIND_TYPE_TAG => 0,
            other => return Err(format!("unsupported BTF kind {other}")),
        };
        if body.checked_add(extra).map_or(true, |end| end > type_end) {
            return Err("truncated BTF type body".to_owned());
        }
        type_id = type_id.checked_add(1).ok_or("BTF type id overflow")?;
        if kind == KIND_FUNC_PROTO {
            proto_vlens.push((type_id, vlen as u32));
        } else if kind == KIND_FUNC {
            let name = btf_string(data, str_start, str_end, name_off)?;
            if let Some(interest) = interest_func(name) {
                func_proto_ids.insert(interest, value);
            }
        } else if matches!(kind, KIND_STRUCT | KIND_UNION) {
            let name = btf_string(data, str_start, str_end, name_off)?;
            if let Some(interest) = interest_struct(name) {
                let mut facts = BtfStructFacts {
                    size: value,
                    members: BTreeMap::new(),
                };
                for index in 0..vlen {
                    let member = body + index * 12;
                    let member_name = btf_string(data, str_start, str_end, btf_u32(data, member)?)?;
                    let raw = btf_u32(data, member + 8)?;
                    let bit_offset = if kind_flag { raw & 0x00ff_ffff } else { raw };
                    let offset = if bit_offset % 8 == 0 {
                        bit_offset / 8
                    } else {
                        u32::MAX
                    };
                    if !member_name.is_empty() {
                        facts.members.insert(member_name.to_owned(), offset);
                    }
                }
                structs.insert(interest, facts);
            }
        }
        at = body + extra;
    }
    if at != type_end {
        return Err("BTF type section length mismatch".to_owned());
    }
    let mut func_nargs: BTreeMap<&'static str, u32> = BTreeMap::new();
    for (name, proto_id) in func_proto_ids {
        let Some((_, nargs)) = proto_vlens.iter().find(|(id, _)| *id == proto_id) else {
            continue;
        };
        func_nargs.insert(name, *nargs);
    }
    Ok(BtfFacts {
        structs,
        func_nargs,
    })
}

/// Resolved AP-5 offsets. `u32::MAX` marks an unresolved field (the eBPF readers
/// reject it through their structure-size bound); `0` marks an unresolved arity.
#[derive(Clone, Copy)]
pub(super) struct ResolvedOffsets {
    pub(super) file_open_nargs: u32,
    pub(super) mmap_nargs: u32,
    pub(super) ptrace_nargs: u32,
    pub(super) file_f_inode: u32,
    pub(super) file_f_flags: u32,
    pub(super) file_file_size: u32,
    pub(super) file_f_dentry: u32,
    pub(super) inode_i_ino: u32,
    pub(super) inode_i_sb: u32,
    pub(super) inode_i_mode: u32,
    pub(super) inode_size: u32,
    pub(super) super_s_dev: u32,
    pub(super) super_size: u32,
    pub(super) dentry_parent: u32,
    pub(super) dentry_inode: u32,
    pub(super) dentry_size: u32,
    pub(super) task_pid: u32,
    pub(super) task_tgid: u32,
    pub(super) task_mm: u32,
    pub(super) task_size: u32,
    pub(super) mm_exe_file: u32,
    pub(super) mm_size: u32,
    pub(super) readv_pid: u32,
    pub(super) readv_target: u32,
    pub(super) readv_size: u32,
    pub(super) writev_pid: u32,
    pub(super) writev_target: u32,
    pub(super) writev_size: u32,
    /// True when `readv_pid/target/size` describe one usable record layout.
    pub(super) readv_ready: bool,
    pub(super) writev_ready: bool,
}

impl Default for ResolvedOffsets {
    fn default() -> Self {
        Self {
            file_open_nargs: 0,
            mmap_nargs: 0,
            ptrace_nargs: 0,
            file_f_inode: u32::MAX,
            file_f_flags: u32::MAX,
            file_file_size: u32::MAX,
            file_f_dentry: u32::MAX,
            inode_i_ino: u32::MAX,
            inode_i_sb: u32::MAX,
            inode_i_mode: u32::MAX,
            inode_size: u32::MAX,
            super_s_dev: u32::MAX,
            super_size: u32::MAX,
            dentry_parent: u32::MAX,
            dentry_inode: u32::MAX,
            dentry_size: u32::MAX,
            task_pid: u32::MAX,
            task_tgid: u32::MAX,
            task_mm: u32::MAX,
            task_size: u32::MAX,
            mm_exe_file: u32::MAX,
            mm_size: u32::MAX,
            readv_pid: u32::MAX,
            readv_target: u32::MAX,
            readv_size: u32::MAX,
            writev_pid: u32::MAX,
            writev_target: u32::MAX,
            writev_size: u32::MAX,
            readv_ready: false,
            writev_ready: false,
        }
    }
}

/// Extracts one member byte offset, validating alignment and structure bounds.
pub(super) fn btf_member(
    facts: &BtfFacts,
    structure: &str,
    member: &str,
    width: u32,
    alignment: u32,
) -> u32 {
    let Some(struct_facts) = facts
        .structs
        .iter()
        .find(|(name, _)| **name == structure)
        .map(|(_, facts)| facts)
    else {
        return u32::MAX;
    };
    let Some(offset) = struct_facts.members.get(member).copied() else {
        return u32::MAX;
    };
    if offset == u32::MAX
        || alignment == 0
        || offset % alignment != 0
        || offset.saturating_add(width) > struct_facts.size
        || struct_facts.size == 0
        || struct_facts.size > PERSIST_MAX_STRUCT_SIZE
    {
        return u32::MAX;
    }
    offset
}

/// Resolves one member of an embedded structure (`outer.member.inner_field`),
/// e.g. `file.f_path.dentry` (`struct file { struct path f_path; }`).
pub(super) fn resolve_nested_member(
    facts: &BtfFacts,
    outer_struct: &str,
    outer_member: &str,
    inner_struct: &str,
    inner_member: &str,
) -> u32 {
    let outer = btf_member(facts, outer_struct, outer_member, 8, 8);
    if outer == u32::MAX {
        return u32::MAX;
    }
    let inner = btf_member(facts, inner_struct, inner_member, 8, 8);
    if inner == u32::MAX {
        return u32::MAX;
    }
    match outer.checked_add(inner) {
        Some(offset) => offset,
        None => u32::MAX,
    }
}
