//! In-memory object neutraliser: appends the derived neutral names to the
//! symbol string table, repoints managed symbols and re-checks every
//! invariant (section names/instructions/relocations stay identical).

use super::*;
use std::collections::{BTreeMap, BTreeSet, HashMap};

/// A rebuilt, neutralised object.
#[derive(Debug)]
#[allow(dead_code)]
pub(super) struct PatchedObject {
    pub(super) bytes: Vec<u8>,
    pub(super) plan: HashMap<String, String>,
    pub(super) renamed_symbols: usize,
    pub(super) appended_bytes: usize,
}

/// Neutralises every managed program/map identifier of the object: appends the
/// neutral names to the symbol string table, repoints the managed symbol entries,
/// zeroes the now-unreferenced public bytes without touching any section name or
/// unmanaged symbol name, and shifts the trailing bytes by one constant delta.
/// Section names, program sections, instructions and relocations are unchanged.
pub(super) fn patch_object(bytes: &[u8], salt: &[u8; 32]) -> Result<PatchedObject, BoxError> {
    if bytes.len() < 64 || &bytes[0..4] != b"\x7fELF" || bytes[4] != 2 || bytes[5] != 1 {
        return Err("chameleon object patch requires an ELF64 little-endian object".into());
    }
    let (shoff, shnum, shstrndx, sections) = parse_elf_sections(bytes)?;
    if sections.iter().any(|section| section.name == ".BTF") {
        return Err(
            "chameleon object patch: objects with a .BTF section are not supported by this build (fail closed; build the shipped BTF-less object)"
                .into(),
        );
    }
    // Exactly one symbol string table: all SYMTAB sh_link values refer to the
    // same string table (the shipped object merges it with .shstrtab).
    let mut strtab_indices: BTreeSet<usize> = BTreeSet::new();
    for section in &sections {
        if section.name == ".strtab" && section.sh_type == 3 {
            strtab_indices.insert(section.index);
        }
        if section.sh_type == 2 {
            let linked = section.sh_link as usize;
            if linked >= sections.len() || sections[linked].sh_type != 3 {
                return Err("chameleon object patch: symbol table has no string table".into());
            }
            strtab_indices.insert(linked);
        }
    }
    if strtab_indices.len() != 1 {
        return Err(
            "chameleon object patch: exactly one symbol string table is supported".into(),
        );
    }
    let strtab_index = *strtab_indices.iter().next().expect("checked non-empty");
    let strtab = &sections[strtab_index];
    let strtab_start = strtab.file_start;
    let strtab_end = strtab.file_start + strtab.file_size;
    if strtab.file_size == 0 || strtab_start >= strtab_end {
        return Err("chameleon object patch: empty symbol string table".into());
    }
    if shoff < strtab_end {
        return Err(
            "chameleon object patch: section header table must follow the symbol string table"
                .into(),
        );
    }
    let table = &bytes[strtab_start..strtab_end];
    // Section-name views are protected: aya parses them to select program types.
    // A separate `.shstrtab` is never patched, so only a merged table can collide.
    let shstr_section = &sections[shstrndx];
    let mut protected: Vec<(usize, usize)> = Vec::new();
    if shstr_section.file_start == strtab_start && shstr_section.file_size == strtab.file_size {
        for index in 0..shnum {
            let name_offset = read_u32(bytes, shoff + index * 64)? as usize;
            if name_offset == 0 {
                continue;
            }
            let name =
                string_at(table, name_offset).ok_or("chameleon object patch: invalid section name")?;
            if name.is_empty() {
                continue;
            }
            if is_managed_identifier(&name) {
                return Err(format!(
                    "chameleon object patch: section name {name} collides with the managed namespace"
                )
                .into());
            }
            protected.push((name_offset, name_offset + name.len()));
        }
    }
    // Managed symbol entries plus every unmanaged symbol name (whose bytes stay
    // referenced and therefore must be preserved by the zeroing pass).
    let mut symbols: Vec<ManagedSymbol> = Vec::new();
    let mut managed_names: BTreeSet<String> = BTreeSet::new();
    for section in &sections {
        if section.sh_type != 2 {
            continue;
        }
        let entry_size = if section.sh_entsize == 0 {
            24usize
        } else {
            usize::try_from(section.sh_entsize)
                .map_err(|_| "chameleon object patch: symbol entry size overflow")?
        };
        if entry_size < 24 || section.file_size % entry_size != 0 {
            return Err("chameleon object patch: malformed symbol table".into());
        }
        let symbol_data = &bytes[section.file_start..section.file_start + section.file_size];
        for entry in (0..section.file_size).step_by(entry_size) {
            let name_offset = read_u32(symbol_data, entry)? as usize;
            if name_offset == 0 {
                continue;
            }
            let Some(name) = string_at(table, name_offset) else {
                continue;
            };
            if is_managed_identifier(&name) {
                managed_names.insert(name.clone());
                symbols.push(ManagedSymbol {
                    symtab_section: section.index,
                    entry_offset: entry,
                    public_name: name,
                });
            } else {
                protected.push((name_offset, name_offset + name.len()));
            }
        }
    }
    if symbols.is_empty() || managed_names.is_empty() {
        return Err(
            "chameleon object patch: no managed GeDefense identifiers found (refusing to load the public identity)"
                .into(),
        );
    }
    let plan = build_name_plan(&managed_names, salt)?;
    // Zero the public bytes that no symbol or section name references anymore.
    // The union of managed symbol name ranges and managed entry texts is reduced
    // by the protected ranges; e.g. the section name `xdp` is a suffix of
    // `gedefense_xdp`, so its three bytes are preserved while the rest of the
    // public spelling is erased.
    let mut erase: Vec<(usize, usize)> = Vec::new();
    // Recover each managed symbol's public byte range from the symbol entry.
    for symbol in &symbols {
        let section = &sections[symbol.symtab_section];
        let entry_offset = section.file_start + symbol.entry_offset;
        let name_offset = read_u32(bytes, entry_offset)? as usize;
        erase.push((name_offset, name_offset + symbol.public_name.len()));
    }
    // Managed entry texts that no symbol references are still public strings in
    // the table; include them so a hex dump cannot reveal them.
    let mut entry_offset = 0usize;
    while entry_offset < table.len() {
        let Some(relative_end) = table[entry_offset..].iter().position(|byte| *byte == 0) else {
            break;
        };
        let entry_end = entry_offset + relative_end;
        if let Ok(name) = std::str::from_utf8(&table[entry_offset..entry_end]) {
            if is_managed_identifier(name) {
                erase.push((entry_offset, entry_end));
            }
        }
        entry_offset = entry_end + 1;
    }
    protected.sort_unstable();
    let erased = subtract_ranges(&erase, &protected);
    // Append the neutral names to the string table.
    let mut appended: Vec<u8> = Vec::new();
    let mut appended_offset: BTreeMap<String, usize> = BTreeMap::new();
    for (public, neutral) in &plan {
        if neutral.len() != public.len() {
            return Err("chameleon object patch: neutral identifier length diverged".into());
        }
        appended_offset.insert(public.clone(), appended.len());
        appended.extend_from_slice(neutral.as_bytes());
        appended.push(0);
    }
    let appended_len = appended.len();
    let padded_len = appended_len.div_ceil(8) * 8;
    let delta = padded_len;
    let mut patched: Vec<u8> = Vec::with_capacity(bytes.len() + delta);
    patched.extend_from_slice(&bytes[..strtab_end]);
    for (start, end) in &erased {
        let absolute_start = strtab_start + start;
        let absolute_end = strtab_start + end;
        for byte in &mut patched[absolute_start..absolute_end] {
            *byte = 0;
        }
    }
    patched.extend_from_slice(&appended);
    patched.resize(strtab_end + padded_len, 0);
    patched.extend_from_slice(&bytes[strtab_end..]);
    // The section header table moved with the trailing bytes.
    let new_shoff = shoff + delta;
    write_u64(&mut patched, 0x28, new_shoff as u64);
    // Shift every section whose data started at/after the old table end and grow
    // the string table by the appended names.
    for index in 0..shnum {
        let header = new_shoff + index * 64;
        let sh_type = read_u32(&patched, header + 4)?;
        let old_offset = read_u64(&patched, header + 24)?;
        if index == strtab_index {
            let old_size = read_u64(&patched, header + 32)?;
            write_u64(&mut patched, header + 32, old_size + appended_len as u64);
        }
        if sh_type != 8 && old_offset >= strtab_end as u64 {
            write_u64(&mut patched, header + 24, old_offset + delta as u64);
        }
    }
    // Repoint exactly the managed symbol entries at their appended neutral name.
    let mut renamed = 0usize;
    for symbol in &symbols {
        let section = &sections[symbol.symtab_section];
        let new_section_start = if section.file_start >= strtab_end {
            section.file_start + delta
        } else {
            section.file_start
        };
        let entry_offset = new_section_start + symbol.entry_offset;
        let neutral_offset = appended_offset
            .get(&symbol.public_name)
            .ok_or_else(|| {
                format!(
                    "chameleon object patch: no neutral offset for {}",
                    symbol.public_name
                )
            })?;
        let new_name_offset = (strtab.file_size + neutral_offset) as u32;
        patched[entry_offset..entry_offset + 4].copy_from_slice(&new_name_offset.to_le_bytes());
        renamed += 1;
    }
    // Post-condition: every symbol resolves to a non-managed name and every
    // section name is still the original one.
    let (_, _, _, patched_sections) = parse_elf_sections(&patched)?;
    let patched_strtab = &patched[patched_sections[strtab_index].file_start
        ..patched_sections[strtab_index].file_start + patched_sections[strtab_index].file_size];
    for section in &patched_sections {
        if section.sh_type != 2 {
            continue;
        }
        let entry_size = if section.sh_entsize == 0 {
            24usize
        } else {
            section.sh_entsize as usize
        };
        let data = &patched[section.file_start..section.file_start + section.file_size];
        for entry in (0..section.file_size).step_by(entry_size) {
            let name_offset = read_u32(data, entry)? as usize;
            if name_offset == 0 {
                continue;
            }
            if let Some(name) = string_at(patched_strtab, name_offset) {
                if is_managed_identifier(&name) {
                    return Err(format!(
                        "chameleon object patch: public identifier {name} survived the patch"
                    )
                    .into());
                }
            }
        }
    }
    for original in &sections {
        if original.name.is_empty() {
            continue;
        }
        if !patched_sections.iter().any(|section| section.name == original.name) {
            return Err(format!(
                "chameleon object patch: section name {} was altered",
                original.name
            )
            .into());
        }
    }
    // The section header table itself is a fixed layout: type/link/flags must be
    // unchanged (only offsets shift by one delta and the string table grew).
    for index in 0..shnum {
        let old_header = shoff + index * 64;
        let new_header = new_shoff + index * 64;
        for field in [4usize, 8, 16, 40, 44, 48, 56] {
            let width = if field == 4 { 4 } else { 8 };
            if patched[new_header + field..new_header + field + width]
                != bytes[old_header + field..old_header + field + width]
            {
                return Err(
                    "chameleon object patch: section header invariant was altered".into(),
                );
            }
        }
    }
    Ok(PatchedObject {
        bytes: patched,
        plan,
        renamed_symbols: renamed,
        appended_bytes: appended_len,
    })
}

/// Returns `ranges` minus every range in `protected` (both as half-open byte
/// intervals), sorted and non-overlapping.
fn subtract_ranges(ranges: &[(usize, usize)], protected: &[(usize, usize)]) -> Vec<(usize, usize)> {
    let mut clipped: Vec<(usize, usize)> = Vec::new();
    for (start, end) in ranges {
        let mut pieces = vec![(*start, *end)];
        for (protected_start, protected_end) in protected {
            let mut next = Vec::new();
            for (piece_start, piece_end) in pieces {
                if *protected_end <= piece_start || *protected_start >= piece_end {
                    next.push((piece_start, piece_end));
                    continue;
                }
                if piece_start < *protected_start {
                    next.push((piece_start, *protected_start));
                }
                if *protected_end < piece_end {
                    next.push((*protected_end, piece_end));
                }
            }
            pieces = next;
        }
        clipped.extend(pieces);
    }
    clipped.sort_unstable();
    clipped.dedup();
    clipped
}
