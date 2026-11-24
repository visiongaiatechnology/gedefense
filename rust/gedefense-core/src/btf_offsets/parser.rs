//! §6/§4.1 bounded BTF image parser: header/section validation, the type
//! walk and the field/arity lookups shared by the Titan and executable-inode
//! offset resolvers (every structurally impossible byte is an `Err`).

use super::layout::{BTF_HEADER_BYTES, BTF_MAGIC, BTF_VERSION, MAX_VMLINUX_BTF_BYTES};

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

    pub(super) fn struct_by_name(&self, name: &str) -> Result<u32, String> {
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

    pub(super) fn type_size(&self, id: u32) -> Result<u32, String> {
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
    pub(super) fn field_ref(&self, root: u32, path: &[&str]) -> Result<(u32, u32), String> {
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

    pub(super) fn func_nargs(&self, name: &str) -> Result<u32, String> {
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
}
