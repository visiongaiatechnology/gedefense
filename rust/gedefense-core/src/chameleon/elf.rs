//! Minimal ELF64 little-endian section/symbol parser used by the
//! in-memory object neutraliser (read-only, bounds-checked).

use super::*;

// --------------------------------------------------------------------- ELF

/// One entry of the ELF section header table, reduced to the fields the patcher
/// needs. `file_start`/`file_size` are the byte range in the object file.
pub(super) struct SectionInfo {
    pub(super) index: usize,
    pub(super) name: String,
    pub(super) sh_type: u32,
    pub(super) sh_link: u32,
    pub(super) sh_entsize: u64,
    pub(super) file_start: usize,
    pub(super) file_size: usize,
}

/// One symbol-table entry that carries a managed public identifier.
pub(super) struct ManagedSymbol {
    pub(super) symtab_section: usize,
    pub(super) entry_offset: usize,
    pub(super) public_name: String,
}

pub(super) fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, BoxError> {
    let slice = bytes
        .get(offset..offset + 2)
        .ok_or("chameleon ELF parse: truncated u16")?;
    Ok(u16::from_le_bytes([slice[0], slice[1]]))
}

pub(super) fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, BoxError> {
    let slice = bytes
        .get(offset..offset + 4)
        .ok_or("chameleon ELF parse: truncated u32")?;
    Ok(u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]))
}

pub(super) fn read_u64(bytes: &[u8], offset: usize) -> Result<u64, BoxError> {
    let slice = bytes
        .get(offset..offset + 8)
        .ok_or("chameleon ELF parse: truncated u64")?;
    Ok(u64::from_le_bytes([
        slice[0], slice[1], slice[2], slice[3], slice[4], slice[5], slice[6], slice[7],
    ]))
}

pub(super) fn write_u64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

pub(super) fn checked_range(start: u64, size: u64, total: usize) -> Result<(usize, usize), BoxError> {
    let start = usize::try_from(start).map_err(|_| "chameleon ELF parse: offset overflow")?;
    let size = usize::try_from(size).map_err(|_| "chameleon ELF parse: size overflow")?;
    let end = start
        .checked_add(size)
        .ok_or("chameleon ELF parse: range overflow")?;
    if end > total {
        return Err("chameleon ELF parse: section outside the file bounds".into());
    }
    Ok((start, end))
}

pub(super) fn string_at(table: &[u8], offset: usize) -> Option<String> {
    let tail = table.get(offset..)?;
    let end = tail.iter().position(|byte| *byte == 0)? + offset;
    std::str::from_utf8(&table[offset..end])
        .ok()
        .map(str::to_owned)
}

/// Minimal ELF64 little-endian section parser: only what the patcher needs.
pub(super) fn parse_elf_sections(bytes: &[u8]) -> Result<(usize, usize, usize, Vec<SectionInfo>), BoxError> {
    if bytes.len() < 64 {
        return Err("chameleon ELF parse: file is too small".into());
    }
    if &bytes[0..4] != b"\x7fELF" {
        return Err("chameleon ELF parse: bad magic".into());
    }
    if bytes[4] != 2 || bytes[5] != 1 || bytes[6] != 1 {
        return Err("chameleon ELF parse requires ELF64 little-endian".into());
    }
    let shoff = read_u64(bytes, 0x28)?;
    let shentsize = read_u16(bytes, 0x3a)? as usize;
    let shnum = read_u16(bytes, 0x3c)? as usize;
    let shstrndx = read_u16(bytes, 0x3e)? as usize;
    if shentsize != 64 {
        return Err("chameleon ELF parse: unexpected section header size".into());
    }
    if shnum == 0 || shoff == 0 || shstrndx >= shnum {
        return Err("chameleon ELF parse: invalid section table".into());
    }
    let shoff = usize::try_from(shoff).map_err(|_| "chameleon ELF parse: offset overflow")?;
    let table_end = shoff
        .checked_add(
            shnum
                .checked_mul(shentsize)
                .ok_or("chameleon ELF parse: section table overflow")?,
        )
        .ok_or("chameleon ELF parse: section table overflow")?;
    if table_end > bytes.len() {
        return Err("chameleon ELF parse: section table outside the file".into());
    }
    let mut sections = Vec::with_capacity(shnum);
    for index in 0..shnum {
        let offset = shoff + index * 64;
        let sh_type = read_u32(bytes, offset + 4)?;
        let file_offset = read_u64(bytes, offset + 24)?;
        let file_size = read_u64(bytes, offset + 32)?;
        let sh_link = read_u32(bytes, offset + 40)?;
        let sh_entsize = read_u64(bytes, offset + 56)?;
        let (file_start, file_end) = if sh_type == 8 {
            (0usize, 0usize)
        } else {
            checked_range(file_offset, file_size, bytes.len())?
        };
        sections.push(SectionInfo {
            index,
            name: String::new(),
            sh_type,
            sh_link,
            sh_entsize,
            file_start,
            file_size: file_end - file_start,
        });
    }
    // Section names live in the section named by e_shstrndx; its raw bytes are
    // re-read through the header table so a merged `.strtab`/`.shstrtab` (as
    // emitted by bpf-linker) works exactly like a conventional object.
    let (shstr_start, shstr_end) = {
        let header = shoff + shstrndx * 64;
        if read_u32(bytes, header + 4)? != 3 {
            return Err("chameleon ELF parse: section string table is not a string table".into());
        }
        let offset = read_u64(bytes, header + 24)?;
        let size = read_u64(bytes, header + 32)?;
        checked_range(offset, size, bytes.len())?
    };
    let shstr = &bytes[shstr_start..shstr_end];
    for index in 0..shnum {
        let offset = shoff + index * 64;
        let name_offset = read_u32(bytes, offset)? as usize;
        sections[index].name = if name_offset == 0 {
            String::new()
        } else {
            string_at(shstr, name_offset).ok_or("chameleon ELF parse: invalid section name")?
        };
    }
    Ok((shoff, shnum, shstrndx, sections))
}
