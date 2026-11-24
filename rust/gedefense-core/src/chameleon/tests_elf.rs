//! Synthetic- and real-object neutralisation tests plus the audit-file
//! contract (the ELF/patcher half of the AP-8 test suite).

use super::*;
use super::tests::{TempDir, test_manifest};
use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::PermissionsExt;

// ------------------------------------------------------------- synthetic ELF

fn find_entry_offset(table: &[u8], entry: &[u8]) -> u32 {
    let mut offset = 0usize;
    while offset < table.len() {
        let Some(relative_end) = table[offset..].iter().position(|byte| *byte == 0) else {
            break;
        };
        let end = offset + relative_end;
        if &table[offset..end] == entry {
            return offset as u32;
        }
        offset = end + 1;
    }
    panic!("entry {entry:?} not found in string table");
}

/// Builds a minimal ELF64 LE relocatable object whose section-name table is the
/// merged `.strtab` (as the shipped bpf-linker object does). Sections:
/// 0 null, 1 .strtab, 2 .symtab, 3 `xdp` (program), 4 `maps` (map), then any
/// extra `(name, type, flags)` sections with 8 bytes of data.
fn build_synthetic_elf(
    strtab: &[u8],
    symbols: &[(u32, u16, u8)],
    extra_sections: &[(&str, u32, u64)],
) -> Vec<u8> {
    let section_count = 5 + extra_sections.len();
    let strtab_offset = 64usize;
    let symtab_offset = strtab_offset + strtab.len();
    let symtab_size = 24 * (1 + symbols.len());
    let xdp_offset = symtab_offset + symtab_size;
    let maps_offset = xdp_offset + 8;
    let mut data_end = maps_offset + 8;
    let mut extra_offsets = Vec::new();
    for _ in extra_sections {
        extra_offsets.push(data_end);
        data_end += 8;
    }
    let shoff = (data_end + 7) & !7usize;
    let total = shoff + section_count * 64;
    let mut elf = vec![0u8; total];
    elf[0..4].copy_from_slice(b"\x7fELF");
    elf[4] = 2;
    elf[5] = 1;
    elf[6] = 1;
    elf[16..18].copy_from_slice(&1u16.to_le_bytes()); // ET_REL
    elf[18..20].copy_from_slice(&0xf7u16.to_le_bytes()); // EM_BPF
    elf[20..24].copy_from_slice(&1u32.to_le_bytes());
    elf[40..48].copy_from_slice(&(shoff as u64).to_le_bytes());
    elf[52..54].copy_from_slice(&64u16.to_le_bytes());
    elf[58..60].copy_from_slice(&64u16.to_le_bytes());
    elf[60..62].copy_from_slice(&(section_count as u16).to_le_bytes());
    elf[62..64].copy_from_slice(&1u16.to_le_bytes()); // .strtab is the shstrtab
    elf[strtab_offset..strtab_offset + strtab.len()].copy_from_slice(strtab);
    {
        let mut position = symtab_offset + 24; // first entry stays null
        for (name_offset, section_index, info) in symbols {
            elf[position..position + 4].copy_from_slice(&name_offset.to_le_bytes());
            elf[position + 4] = *info;
            elf[position + 6..position + 8].copy_from_slice(&section_index.to_le_bytes());
            position += 24;
        }
    }
    let name_offset = |name: &str| -> u32 { find_entry_offset(strtab, name.as_bytes()) };
    let mut write_section = |index: usize,
                             name: &str,
                             sh_type: u32,
                             flags: u64,
                             offset: usize,
                             size: usize,
                             link: u32,
                             info: u32,
                             align: u64,
                             entsize: u64| {
        let base = shoff + index * 64;
        elf[base..base + 4].copy_from_slice(&name_offset(name).to_le_bytes());
        elf[base + 4..base + 8].copy_from_slice(&sh_type.to_le_bytes());
        elf[base + 8..base + 16].copy_from_slice(&flags.to_le_bytes());
        elf[base + 24..base + 32].copy_from_slice(&(offset as u64).to_le_bytes());
        elf[base + 32..base + 40].copy_from_slice(&(size as u64).to_le_bytes());
        elf[base + 40..base + 44].copy_from_slice(&link.to_le_bytes());
        elf[base + 44..base + 48].copy_from_slice(&info.to_le_bytes());
        elf[base + 48..base + 56].copy_from_slice(&align.to_le_bytes());
        elf[base + 56..base + 64].copy_from_slice(&entsize.to_le_bytes());
    };
    write_section(
        1,
        ".strtab",
        3,
        0,
        strtab_offset,
        strtab.len(),
        0,
        0,
        1,
        0,
    );
    write_section(
        2,
        ".symtab",
        2,
        0,
        symtab_offset,
        symtab_size,
        1,
        1,
        8,
        24,
    );
    write_section(3, "xdp", 1, 0x6, xdp_offset, 8, 0, 0, 8, 0);
    write_section(4, "maps", 1, 0x3, maps_offset, 8, 0, 0, 4, 0);
    for (extra_index, (name, sh_type, flags)) in extra_sections.iter().enumerate() {
        write_section(
            5 + extra_index,
            name,
            *sh_type,
            *flags,
            extra_offsets[extra_index],
            8,
            0,
            0,
            8,
            0,
        );
    }
    elf
}

fn section_names(elf: &[u8]) -> Vec<String> {
    let (_, _, _, sections) = parse_elf_sections(elf).expect("parse sections");
    sections.iter().map(|section| section.name.clone()).collect()
}

fn symbol_names(elf: &[u8]) -> Vec<String> {
    let (_, _, _, sections) = parse_elf_sections(elf).expect("parse sections");
    let strtab = sections
        .iter()
        .find(|section| section.name == ".strtab")
        .expect(".strtab");
    let table = &elf[strtab.file_start..strtab.file_start + strtab.file_size];
    let mut names = Vec::new();
    for section in &sections {
        if section.sh_type != 2 {
            continue;
        }
        let entry_size = if section.sh_entsize == 0 {
            24usize
        } else {
            section.sh_entsize as usize
        };
        let data = &elf[section.file_start..section.file_start + section.file_size];
        for entry in (0..section.file_size).step_by(entry_size) {
            let name_offset = read_u32(data, entry).expect("symbol name offset") as usize;
            if name_offset == 0 {
                continue;
            }
            if let Some(name) = string_at(table, name_offset) {
                names.push(name);
            }
        }
    }
    names
}

fn section_bytes(elf: &[u8], name: &str) -> Option<Vec<u8>> {
    let (_, _, _, sections) = parse_elf_sections(elf).expect("parse sections");
    sections
        .iter()
        .find(|section| section.name == name)
        .map(|section| elf[section.file_start..section.file_start + section.file_size].to_vec())
}

fn strtab_entries(elf: &[u8]) -> Vec<String> {
    let (_, _, _, sections) = parse_elf_sections(elf).expect("parse sections");
    let strtab = sections
        .iter()
        .find(|section| section.name == ".strtab")
        .expect(".strtab");
    let table = &elf[strtab.file_start..strtab.file_start + strtab.file_size];
    let mut entries = Vec::new();
    let mut offset = 0usize;
    while offset < table.len() {
        let Some(relative_end) = table[offset..].iter().position(|byte| *byte == 0) else {
            break;
        };
        let end = offset + relative_end;
        if let Ok(entry) = std::str::from_utf8(&table[offset..end]) {
            if !entry.is_empty() {
                entries.push(entry.to_owned());
            }
        }
        offset = end + 1;
    }
    entries
}

#[test]
fn synthetic_elf_patch_renames_managed_identifiers_only() {
    let strtab = b"\0gedefense_xdp\0TITAN_EXEC_EVENTS\0FLOW_EVENTS\0UNMANAGED\0.strtab\0.symtab\0xdp\0maps\0".to_vec();
    let xdp = find_entry_offset(&strtab, b"gedefense_xdp");
    let titan = find_entry_offset(&strtab, b"TITAN_EXEC_EVENTS");
    let flow = find_entry_offset(&strtab, b"FLOW_EVENTS");
    let unmanaged = find_entry_offset(&strtab, b"UNMANAGED");
    let exec = titan + "TITAN_".len() as u32;
    let symbols = vec![
        (xdp, 3u16, 0x12u8),
        (titan, 4, 0x11),
        (exec, 4, 0x11),
        (flow, 4, 0x11),
        (unmanaged, 4, 0x11),
    ];
    let original = build_synthetic_elf(&strtab, &symbols, &[]);
    let names_before = section_names(&original);
    let patched = patch_object(&original, &[0x42u8; 32]).expect("patch synthetic object");
    assert_eq!(patched.plan.len(), 4, "all managed spellings must be planned");
    assert_eq!(patched.renamed_symbols, 4);
    assert!(patched.appended_bytes > 0);
    for public in [
        "gedefense_xdp",
        "TITAN_EXEC_EVENTS",
        "EXEC_EVENTS",
        "FLOW_EVENTS",
    ] {
        let neutral = patched.plan.get(public).expect(public);
        assert_eq!(neutral.len(), public.len(), "same length for {public}");
        assert!(neutral_identifier_shape_is_valid(neutral), "{neutral}");
        assert!(!patched
            .bytes
            .windows(public.len())
            .any(|window| window == public.as_bytes()));
    }
    // Symbol names resolve to the neutral plan; unmanaged names are untouched.
    let resolved = symbol_names(&patched.bytes);
    for neutral in patched.plan.values() {
        assert!(resolved.iter().any(|name| name == neutral), "missing {neutral}");
    }
    assert!(resolved.iter().any(|name| name == "UNMANAGED"));
    for name in &resolved {
        assert!(!is_managed_identifier(name), "still managed: {name}");
    }
    // Section names are byte-identical and the program/map section data is
    // unchanged (only offsets shift by the appended table tail).
    assert_eq!(section_names(&patched.bytes), names_before);
    assert_eq!(section_bytes(&patched.bytes, "xdp"), section_bytes(&original, "xdp"));
    assert_eq!(
        section_bytes(&patched.bytes, "maps"),
        section_bytes(&original, "maps")
    );
    assert_eq!(
        section_bytes(&patched.bytes, ".text"),
        section_bytes(&original, ".text")
    );
    // The unmanaged string is still present in the string table.
    assert!(patched
        .bytes
        .windows(b"UNMANAGED".len())
        .any(|window| window == b"UNMANAGED"));
}

#[test]
fn synthetic_elf_patch_preserves_a_section_name_shared_with_a_symbol() {
    // Reproduce the shipped object's LLVM suffix sharing: the section name `xdp`
    // is the suffix of the program symbol `gedefense_xdp`. The symbol must be
    // renamed while the section name bytes stay intact.
    let strtab = b"\0gedefense_xdp\0.extra\0.strtab\0.symtab\0xdp\0maps\0".to_vec();
    let xdp_symbol = find_entry_offset(&strtab, b"gedefense_xdp");
    let symbols = vec![(xdp_symbol, 3u16, 0x12u8)];
    let extra = [(".extra", 1u32, 0u64)];
    let mut original = build_synthetic_elf(&strtab, &symbols, &extra);
    let (shoff, _, _, _) = parse_elf_sections(&original).expect("parse");
    // Point the `xdp` section name at the suffix inside the program symbol.
    let suffix = xdp_symbol + "gedefense_".len() as u32;
    original[shoff + 3 * 64..shoff + 3 * 64 + 4].copy_from_slice(&suffix.to_le_bytes());
    let patched = patch_object(&original, &[0x24u8; 32]).expect("patch shared-suffix object");
    let names = section_names(&patched.bytes);
    assert!(names.contains(&"xdp".to_owned()), "{names:?}");
    assert!(!patched
        .bytes
        .windows(b"gedefense_xdp".len())
        .any(|window| window == b"gedefense_xdp"));
    let resolved = symbol_names(&patched.bytes);
    assert!(resolved.iter().any(|name| name == &patched.plan["gedefense_xdp"]));
}

#[test]
fn synthetic_elf_patch_rejects_a_managed_section_name() {
    let strtab = b"\0FLOW_EVENTS\0gedefense_section\0.strtab\0.symtab\0xdp\0maps\0".to_vec();
    let flow = find_entry_offset(&strtab, b"FLOW_EVENTS");
    let extra = [("gedefense_section", 1u32, 0u64)];
    let elf = build_synthetic_elf(&strtab, &[(flow, 4u16, 0x11u8)], &extra);
    let error = patch_object(&elf, &[7u8; 32]).unwrap_err().to_string();
    assert!(error.contains("section name"), "{error}");
}

#[test]
fn synthetic_elf_patch_rejects_a_btf_bearing_object() {
    let strtab = b"\0FLOW_EVENTS\0.BTF\0.strtab\0.symtab\0xdp\0maps\0".to_vec();
    let flow = find_entry_offset(&strtab, b"FLOW_EVENTS");
    let extra = [(".BTF", 1u32, 0u64)];
    let elf = build_synthetic_elf(&strtab, &[(flow, 4u16, 0x11u8)], &extra);
    let error = patch_object(&elf, &[7u8; 32]).unwrap_err().to_string();
    assert!(error.contains(".BTF"), "{error}");
}

#[test]
fn synthetic_elf_patch_rejects_an_object_without_managed_identifiers() {
    let strtab = b"\0UNMANAGED_A\0UNMANAGED_B\0.strtab\0.symtab\0xdp\0maps\0".to_vec();
    let first = find_entry_offset(&strtab, b"UNMANAGED_A");
    let second = find_entry_offset(&strtab, b"UNMANAGED_B");
    let symbols = vec![(first, 4u16, 0x11u8), (second, 4, 0x11)];
    let elf = build_synthetic_elf(&strtab, &symbols, &[]);
    let error = patch_object(&elf, &[9u8; 32]).unwrap_err().to_string();
    assert!(
        error.contains("no managed GeDefense identifiers found"),
        "{error}"
    );
}

// ---------------------------------------------------------------- audit file

#[test]
fn audit_mapping_is_written_root_only_and_bounded() {
    let temp = TempDir::new("audit");
    let state_dir = temp.path.join("state");
    let config_dir = temp.path.join("etc");
    fs::create_dir_all(&state_dir).expect("state dir");
    fs::create_dir_all(&config_dir).expect("config dir");
    let manifest = test_manifest(&state_dir, &config_dir);
    let elf = build_synthetic_elf_for_maps();
    let patched = patch_object(&elf, &manifest.salt).expect("patch");
    write_audit_mapping(&manifest, &patched).expect("write audit");
    let audit_path = state_dir.join(CHAMELEON_AUDIT_FILE_NAME);
    let metadata = fs::symlink_metadata(&audit_path).expect("audit exists");
    assert!(metadata.is_file());
    assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
    let document = fs::read_to_string(&audit_path).expect("read audit");
    assert!(document.starts_with("# vgt-gedefense-chameleon-map-v1\n"));
    assert!(document.contains("# install_id=gd-ap8-test-install-0001\n"));
    assert!(document.contains("# salt_fingerprint="));
    assert!(document.contains("# mapping_sha256="));
    assert!(document.contains("# public=neutral\n"));
    for public in patched.plan.keys() {
        assert!(document.contains(&format!("{public}=")), "missing {public}");
    }
    // The raw salt must never be written to the audit document.
    let salt_hex = hex::encode(manifest.salt);
    assert!(!document.contains(&salt_hex));
    assert!(document.len() <= CHAMELEON_AUDIT_MAX_BYTES);
}

fn build_synthetic_elf_for_maps() -> Vec<u8> {
    let strtab = b"\0FLOW_EVENTS\0TITAN_EXEC_STATE\0.strtab\0.symtab\0xdp\0maps\0".to_vec();
    let flow = find_entry_offset(&strtab, b"FLOW_EVENTS");
    let titan = find_entry_offset(&strtab, b"TITAN_EXEC_STATE");
    build_synthetic_elf(&strtab, &[(flow, 4, 0x11), (titan, 4, 0x11)], &[])
}

// ------------------------------------------------------- real object smoke

/// Real-object neutralisation smoke: set `VGT_CHAMELEON_TEST_OBJECT` to a
/// freshly built eBPF object. The test proves that every managed symbol resolves
/// to a neutral identifier, that the public identifiers are gone from the string
/// table, and that every section name and every non-symbol section payload stays
/// byte-identical. When run as root it additionally asks aya to parse the
/// patched object (no programs are attached).
#[test]
#[ignore = "real eBPF object patcher smoke: set VGT_CHAMELEON_TEST_OBJECT=<object>"]
fn chameleon_real_object_patcher_removes_public_identifiers() {
    let Ok(object) = std::env::var("VGT_CHAMELEON_TEST_OBJECT") else {
        eprintln!("chameleon object smoke SKIP: VGT_CHAMELEON_TEST_OBJECT is not set");
        return;
    };
    let raw = fs::read(&object).expect("read test object");
    assert!(raw.len() > 64, "object is too small");
    let names_before = section_names(&raw);
    let payload_before: BTreeMap<String, Vec<u8>> = names_before
        .iter()
        .filter(|name| !matches!(name.as_str(), "" | ".strtab" | ".symtab"))
        .filter_map(|name| section_bytes(&raw, name).map(|bytes| (name.clone(), bytes)))
        .collect();
    let salt = [0x6du8; 32];
    let patched = patch_object(&raw, &salt).expect("patch real object");
    assert!(
        patched.plan.len() > 100,
        "shipped object must expose the full managed namespace (planned {})",
        patched.plan.len()
    );
    assert!(patched.renamed_symbols > 100);
    // Section names and every non-symbol section payload are unchanged.
    assert_eq!(section_names(&patched.bytes), names_before);
    for (name, before) in &payload_before {
        let after = section_bytes(&patched.bytes, name)
            .unwrap_or_else(|| panic!("section {name} disappeared"));
        assert_eq!(&after, before, "section payload {name} changed");
    }
    // Every managed symbol resolves to the neutral plan; no public identifier
    // survives in the string table.
    let resolved = symbol_names(&patched.bytes);
    for name in &resolved {
        assert!(!is_managed_identifier(name), "still managed: {name}");
    }
    for neutral in patched.plan.values() {
        assert!(
            resolved.iter().any(|name| name == neutral),
            "neutral symbol {neutral} missing"
        );
        assert!(neutral_identifier_shape_is_valid(neutral), "{neutral}");
    }
    // No managed identifier survives as a NUL-delimited string-table entry. A
    // *mangled* Rust helper symbol may still embed the vendor/module text as a
    // substring of its own (non-matching, never kernel-visible) name; those are
    // deliberately left untouched per the "never touch non-matching strings"
    // rule.
    for entry in strtab_entries(&patched.bytes) {
        assert!(
            !is_managed_identifier(&entry),
            "managed identifier survived as a string-table entry: {entry}"
        );
    }
    // Section-name spellings still resolve (aya needs them).
    for required in ["xdp", "maps", ".strtab", ".symtab"] {
        assert!(
            section_names(&patched.bytes)
                .iter()
                .any(|name| name == required),
            "section {required} disappeared"
        );
    }
    eprintln!(
        "chameleon object smoke: {} symbols renamed, {} neutral bytes appended",
        patched.renamed_symbols, patched.appended_bytes
    );
    if unsafe { libc::geteuid() } == 0 {
        let mut words = vec![0u64; patched.bytes.len().div_ceil(8)];
        // SAFETY: 8-byte aligned word buffer covering exactly bytes.len() bytes.
        let bytes: &mut [u8] = unsafe {
            std::slice::from_raw_parts_mut(words.as_mut_ptr().cast::<u8>(), patched.bytes.len())
        };
        bytes.copy_from_slice(&patched.bytes);
        // SAFETY: same live allocation, read-only view.
        let aligned: &[u8] =
            unsafe { std::slice::from_raw_parts(words.as_ptr().cast::<u8>(), patched.bytes.len()) };
        match aya::Ebpf::load(aligned) {
            Ok(ebpf) => {
                for public in ["gedefense_xdp", "gedefense_egress", "gedefense_exec"] {
                    assert!(
                        ebpf.program(public).is_none(),
                        "public program name {public} is still an aya key"
                    );
                }
                assert!(
                    ebpf.programs().count() > 0,
                    "patched object must still expose its programs"
                );
                for (name, _) in ebpf.programs() {
                    assert!(
                        !contains_forbidden_identifier(&name.to_ascii_lowercase()),
                        "kernel program name {name} still leaks a GeDefense marker"
                    );
                }
                for (name, _) in ebpf.maps() {
                    assert!(
                        !contains_forbidden_identifier(&name.to_ascii_lowercase()),
                        "kernel map name {name} still leaks a GeDefense marker"
                    );
                }
                eprintln!(
                    "chameleon object smoke: aya parsed the patched object ({} programs, {} maps)",
                    ebpf.programs().count(),
                    ebpf.maps().count()
                );
            }
            Err(error) => eprintln!(
                "chameleon object smoke: live aya load refused by this kernel/host ({error})"
            ),
        }
    } else {
        eprintln!("chameleon object smoke: euid={}", unsafe { libc::geteuid() });
    }
}
