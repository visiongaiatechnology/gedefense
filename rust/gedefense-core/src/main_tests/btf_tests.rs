#![cfg(test)]
//! Wave 5a: Titan BTF fixture and golden-offset tests moved verbatim from
//! `main_tests.rs` (structure-only split).

use super::*;

struct BtfFixture {
    strings: Vec<u8>,
    types: Vec<Vec<u8>>,
}

impl BtfFixture {
    fn new() -> Self {
        Self {
            strings: vec![0],
            types: Vec::new(),
        }
    }

    fn name(&mut self, name: &str) -> u32 {
        let offset = self.strings.len() as u32;
        self.strings.extend_from_slice(name.as_bytes());
        self.strings.push(0);
        offset
    }

    fn push(
        &mut self,
        name_off: u32,
        kind: u8,
        vlen: u16,
        flag: bool,
        value: u32,
        extra: &[u8],
    ) -> u32 {
        let mut info = (u32::from(kind) << 24) | u32::from(vlen);
        if flag {
            info |= 1 << 31;
        }
        let mut encoded = Vec::with_capacity(12 + extra.len());
        encoded.extend_from_slice(&name_off.to_le_bytes());
        encoded.extend_from_slice(&info.to_le_bytes());
        encoded.extend_from_slice(&value.to_le_bytes());
        encoded.extend_from_slice(extra);
        self.types.push(encoded);
        self.types.len() as u32
    }

    fn int(&mut self, name: &str, size: u32) -> u32 {
        let name_off = self.name(name);
        self.push(name_off, 1, 0, false, size, &size.to_le_bytes())
    }

    fn pointer(&mut self, pointee: u32) -> u32 {
        self.push(0, 2, 0, false, pointee, &[])
    }

    fn record(
        &mut self,
        name: &str,
        union: bool,
        flag: bool,
        size: u32,
        members: &[(u32, u32, u32)],
    ) -> u32 {
        let name_off = self.name(name);
        let mut extra = Vec::new();
        for (member_name, type_id, offset_bits) in members {
            extra.extend_from_slice(&member_name.to_le_bytes());
            extra.extend_from_slice(&type_id.to_le_bytes());
            extra.extend_from_slice(&offset_bits.to_le_bytes());
        }
        self.push(
            name_off,
            if union { 5 } else { 4 },
            members.len() as u16,
            flag,
            size,
            &extra,
        )
    }

    fn func_proto(&mut self, params: u16, param_type: u32) -> u32 {
        let mut extra = Vec::new();
        for _ in 0..params {
            extra.extend_from_slice(&0u32.to_le_bytes());
            extra.extend_from_slice(&param_type.to_le_bytes());
        }
        self.push(0, 13, params, false, 0, &extra)
    }

    fn func(&mut self, name: &str, proto: u32) -> u32 {
        let name_off = self.name(name);
        self.push(name_off, 12, 0, false, proto, &[])
    }

    fn finish(self) -> Vec<u8> {
        let type_len: u32 = self.types.iter().map(|encoded| encoded.len() as u32).sum();
        let mut data = Vec::new();
        data.extend_from_slice(&btf_offsets::BTF_MAGIC.to_le_bytes());
        data.push(btf_offsets::BTF_VERSION);
        data.push(0);
        data.extend_from_slice(&(btf_offsets::BTF_HEADER_BYTES as u32).to_le_bytes());
        data.extend_from_slice(&0u32.to_le_bytes());
        data.extend_from_slice(&type_len.to_le_bytes());
        data.extend_from_slice(&type_len.to_le_bytes());
        data.extend_from_slice(&(self.strings.len() as u32).to_le_bytes());
        for encoded in &self.types {
            data.extend_from_slice(encoded);
        }
        data.extend_from_slice(&self.strings);
        data
    }
}

#[derive(Clone, Copy, Debug)]
struct TitanBtfSpec {
    inode_size: u32,
    file_size: u32,
    bprm_size: u32,
    super_size: u32,
    bprm_nargs: u16,
    mmap_nargs: u16,
    i_ino_off: u32,
    drop_ino: bool,
    drop_super: bool,
    duplicate_inode: bool,
    // §4.1 ctime-Layout-Vertrag: `false` = legacy timespec64, `true` =
    // modern split `i_ctime_sec`/`i_ctime_nsec`; width 2 is the invalid probe.
    ctime_split: bool,
    split_nsec_width: u32,
    drop_ctime: bool,
}

impl Default for TitanBtfSpec {
    fn default() -> Self {
        Self {
            inode_size: 600,
            file_size: 256,
            bprm_size: 128,
            super_size: 256,
            bprm_nargs: 1,
            mmap_nargs: 4,
            i_ino_off: 64,
            drop_ino: false,
            drop_super: false,
            duplicate_inode: false,
            ctime_split: false,
            split_nsec_width: 4,
            drop_ctime: false,
        }
    }
}

/// Synthetic vmlinux-BTF with the §4.1 layout: anonymous union (`i_nlink`),
/// `kind_flag` bitfield (`i_opflags`), both ctime layouts and both LSM hooks.
fn titan_btf_fixture(spec: &TitanBtfSpec) -> Vec<u8> {
    let mut fixture = BtfFixture::new();
    let u16t = fixture.int("u16", 2);
    let u32t = fixture.int("u32", 4);
    let u64t = fixture.int("u64", 8);
    let i64t = fixture.int("i64", 8);
    let ulong = fixture.int("unsigned long", 8);
    let pointer = fixture.pointer(u32t);
    let tv_sec = fixture.name("tv_sec");
    let tv_nsec = fixture.name("tv_nsec");
    let timespec = fixture.record(
        "timespec64",
        false,
        false,
        16,
        &[(tv_sec, i64t, 0), (tv_nsec, i64t, 64)],
    );
    let i_nlink = fixture.name("i_nlink");
    let alternate = fixture.name("__i_nlink");
    let anonymous_union = fixture.record("", true, false, 4, &[(i_nlink, u32t, 0), (alternate, u32t, 0)]);
    let i_uid = fixture.name("i_uid");
    let d_parent = fixture.name("d_parent");
    let d_inode = fixture.name("d_inode");
    let path_mnt = fixture.name("mnt");
    let path_dentry = fixture.name("dentry");
    let f_path = fixture.name("f_path");
    let bprm_filename = fixture.name("filename");
    let i_mode = fixture.name("i_mode");
    let i_opflags = fixture.name("i_opflags");
    let i_ino = fixture.name("i_ino");
    let i_sb = fixture.name("i_sb");
    let i_generation = fixture.name("i_generation");
    let i_ctime = fixture.name("i_ctime");
    let i_ctime_sec = fixture.name("i_ctime_sec");
    let i_ctime_nsec = fixture.name("i_ctime_nsec");
    let split_nsec = match spec.split_nsec_width {
        8 => u64t,
        4 => u32t,
        _ => u16t,
    };
    let mut inode_members = vec![
        (i_mode, u16t, 0),
        (i_opflags, u16t, 16 | (4 << 24)),
        (i_uid, u32t, 8 * 8),
        (i_sb, pointer, 40 * 8),
        (0, anonymous_union, 72 * 8),
        (i_generation, u32t, 124 * 8),
    ];
    if spec.ctime_split {
        inode_members.push((i_ctime_sec, u64t, 104 * 8));
        inode_members.push((i_ctime_nsec, split_nsec, 120 * 8));
    } else if !spec.drop_ctime {
        inode_members.push((i_ctime, timespec, 128 * 8));
    }
    if !spec.drop_ino {
        inode_members.push((i_ino, u64t, spec.i_ino_off * 8));
    }
    fixture.record("inode", false, true, spec.inode_size, &inode_members);
    if spec.duplicate_inode {
        fixture.record("inode", false, false, spec.inode_size, &[(i_mode, u16t, 0)]);
    }
    let f_inode = fixture.name("f_inode");
    // §4.1 ABI 2: the bounded `file -> f_path.dentry -> d_parent` chain for
    // the UNTRUSTED world-writable ancestor check. The dentry walk below
    // reads the inode mode of each ancestor directory.
    let _dentry = fixture.record(
        "dentry",
        false,
        false,
        256,
        &[(d_parent, pointer, 16 * 8), (d_inode, pointer, 24 * 8)],
    );
    let path = fixture.record(
        "path",
        false,
        false,
        16,
        &[(path_mnt, pointer, 0), (path_dentry, pointer, 8 * 8)],
    );
    fixture.record(
        "file",
        false,
        false,
        spec.file_size,
        &[(f_inode, pointer, 32 * 8), (f_path, path, 96 * 8)],
    );
    let bprm_file = fixture.name("file");
    fixture.record(
        "linux_binprm",
        false,
        false,
        spec.bprm_size,
        &[(bprm_file, pointer, 64 * 8), (bprm_filename, pointer, 8 * 8)],
    );
    if !spec.drop_super {
        let s_dev = fixture.name("s_dev");
        let s_magic = fixture.name("s_magic");
        fixture.record(
            "super_block",
            false,
            false,
            spec.super_size,
            &[(s_dev, u32t, 16 * 8), (s_magic, ulong, 96 * 8)],
        );
    }
    let bprm_proto = fixture.func_proto(spec.bprm_nargs, pointer);
    fixture.func("bpf_lsm_bprm_check_security", bprm_proto);
    let mmap_proto = fixture.func_proto(spec.mmap_nargs, pointer);
    fixture.func("bpf_lsm_mmap_file", mmap_proto);
    fixture.finish()
}

/// Parses a synthetic BTF image and resolves the validated §4.1 offsets.
fn resolve_titan_btf(data: Vec<u8>) -> Result<btf_offsets::TitanExecOffsets, String> {
    btf_offsets::VmlinuxBtf::parse(data)?.resolve_titan_exec()
}

#[test]
fn titan_btf_golden_offsets_resolve_for_6_18_and_7_0() {
    // Golden values from §4.1 (x86_64, BTF-verified on 6.18/7.0); the 7.0
    // fixture only grows the inode struct, so the field offsets must stay.
    for (label, inode_size) in [("6.18", 600u32), ("7.0", 640)] {
        let spec = TitanBtfSpec {
            inode_size,
            ..Default::default()
        };
        let offsets =
            resolve_titan_btf(titan_btf_fixture(&spec)).expect(label);
        let resolved = [
            (offsets.bprm_file_off, 64),
            (offsets.file_f_inode_off, 32),
            (offsets.inode_i_ino_off, 64),
            (offsets.inode_i_sb_off, 40),
            (offsets.inode_i_nlink_off, 72),
            (offsets.inode_i_mode_off, 0),
            (offsets.inode_i_generation_off, 124),
            (offsets.super_s_dev_off, 16),
            (offsets.super_s_magic_off, 96),
            (offsets.inode_i_ctime_sec_off, 128),
            (offsets.inode_i_ctime_nsec_off, 136),
            (offsets.inode_i_ctime_nsec_width, 8),
            // §4.1 ABI 2: UNTRUSTED exec-mode facts of the golden layout.
            (offsets.bprm_filename_off, 8),
            (offsets.inode_i_uid_off, 8),
            (offsets.file_f_path_dentry_off, 104),
            (offsets.dentry_d_parent_off, 16),
            (offsets.dentry_d_inode_off, 24),
            (offsets.dentry_size, 256),
            (offsets.bprm_nargs, 1),
            (offsets.mmap_nargs, 4),
            (offsets.mmap_file_arg_idx, 0),
            (offsets.mmap_prot_arg_idx, 2),
            (offsets.mmap_flags_arg_idx, 3),
            (offsets.bprm_retval_slot, 1),
            (offsets.mmap_retval_slot, 4),
            (offsets.inode_size, inode_size),
            (offsets.file_size, 256),
            (offsets.bprm_size, 128),
        ];
        for (actual, expected) in resolved {
            assert_eq!(actual, expected, "{label}");
        }
        assert!(titan_exec_offsets_match_ebpf_slots(&offsets), "{label}");
        let table = encode_titan_exec_offsets_table(&offsets);
        assert_eq!(table.len(), btf_offsets::TITAN_EXEC_OFFSETS_TABLE_LEN);
        assert_eq!(table[btf_offsets::OFF_MAGIC], gedefense_common::TITAN_EXEC_OFFSETS_MAGIC);
        assert_eq!(table[btf_offsets::OFF_ABI], gedefense_common::TITAN_EXEC_OFFSETS_ABI);
        assert_eq!(table[btf_offsets::OFF_BPRM_FILE], 64);
        assert_eq!(table[btf_offsets::OFF_FILE_F_INODE], 32);
        assert_eq!(table[btf_offsets::OFF_TMPFS_MAGIC], btf_offsets::TMPFS_MAGIC);
        assert_eq!(table[btf_offsets::OFF_DEVTMPFS_MAGIC], btf_offsets::DEVTMPFS_MAGIC);
        assert_eq!(table[btf_offsets::OFF_PROC_MAGIC], btf_offsets::PROC_SUPER_MAGIC);
        assert_eq!(table[btf_offsets::OFF_SYSFS_MAGIC], btf_offsets::SYSFS_MAGIC);
        assert_eq!(table[btf_offsets::OFF_OVERLAY_MAGIC], btf_offsets::OVERLAYFS_SUPER_MAGIC);
        assert_eq!(table[btf_offsets::OFF_BPRM_NARGS], 1);
        assert_eq!(table[btf_offsets::OFF_MMAP_NARGS], 4);
        assert_eq!(table[btf_offsets::OFF_MMAP_PROT_ARG], 2);
        assert_eq!(table[btf_offsets::OFF_INODE_I_CTIME_SEC], 128);
        assert_eq!(table[btf_offsets::OFF_INODE_I_CTIME_NSEC], 136);
        assert_eq!(table[btf_offsets::OFF_INODE_I_CTIME_NSEC_WIDTH], 8);
        assert_eq!(table[btf_offsets::OFF_BPRM_FILENAME], 8);
        assert_eq!(table[btf_offsets::OFF_INODE_I_UID], 8);
        assert_eq!(table[btf_offsets::OFF_FILE_F_PATH_DENTRY], 104);
        assert_eq!(table[btf_offsets::OFF_DENTRY_D_PARENT], 16);
        assert_eq!(table[btf_offsets::OFF_DENTRY_D_INODE], 24);
        assert_eq!(table[btf_offsets::OFF_DENTRY_SIZE], 256);
        assert!(
            table[btf_offsets::OFF_RESERVED_FIRST..]
                .iter()
                .all(|value| *value == 0),
            "{label}"
        );
    }
}

#[test]
fn titan_btf_split_ctime_layout_publishes_the_nsec_width() {
    // §4.1 ctime-Layout-Vertrag: modern kernels have i_ctime_sec (8 B) +
    // i_ctime_nsec (4 B) instead of a timespec64; both must resolve and the
    // width index 28 must follow the real field width.
    let legacy = resolve_titan_btf(titan_btf_fixture(&TitanBtfSpec::default()))
        .expect("legacy timespec64 layout");
    assert_eq!(
        (
            legacy.inode_i_ctime_sec_off,
            legacy.inode_i_ctime_nsec_off,
            legacy.inode_i_ctime_nsec_width
        ),
        (128, 136, 8)
    );
    let split = resolve_titan_btf(titan_btf_fixture(&TitanBtfSpec {
        ctime_split: true,
        ..Default::default()
    }))
    .expect("split modern layout");
    assert_eq!(
        (
            split.inode_i_ctime_sec_off,
            split.inode_i_ctime_nsec_off,
            split.inode_i_ctime_nsec_width
        ),
        (104, 120, 4)
    );
    assert!(titan_exec_offsets_match_ebpf_slots(&split));
    let table = encode_titan_exec_offsets_table(&split);
    assert_eq!(table[btf_offsets::OFF_INODE_I_CTIME_NSEC_WIDTH], 4);
    // A split layout whose nsec field is 8 B is declared/reported as width 8
    // (eBPF reads u64 for 8, u32 for 4).
    let wide = resolve_titan_btf(titan_btf_fixture(&TitanBtfSpec {
        ctime_split: true,
        split_nsec_width: 8,
        ..Default::default()
    }))
    .expect("wide split layout");
    assert_eq!(wide.inode_i_ctime_nsec_width, 8);
    // Implausible width and a fully missing ctime pair are Err (fail-safe).
    for spec in [
        TitanBtfSpec {
            ctime_split: true,
            split_nsec_width: 2,
            ..Default::default()
        },
        TitanBtfSpec {
            drop_ctime: true,
            ..Default::default()
        },
    ] {
        assert!(resolve_titan_btf(titan_btf_fixture(&spec)).is_err(), "{spec:?}");
    }
}

#[test]
fn titan_btf_live_vmlinux_resolves_all_offsets() {
    // §4.1 Real-BTF-Gate: with a live /sys/kernel/btf/vmlinux every offset
    // (including the ctime variant) must resolve and validate. Without the
    // file this is a documented SKIP, never a silent pass.
    if !Path::new(btf_offsets::VMLINUX_BTF_PATH).is_file() {
        eprintln!(
            "SKIP titan_btf_live_vmlinux_resolves_all_offsets: {} is absent on this host",
            btf_offsets::VMLINUX_BTF_PATH
        );
        return;
    }
    let offsets = btf_offsets::resolve_vmlinux_offsets()
        .expect("live vmlinux BTF must resolve the §4.1 offsets");
    eprintln!("live BTF §4.1 offsets: {offsets:?}");
    assert!(titan_exec_offsets_match_ebpf_slots(&offsets));
    assert!(matches!(offsets.inode_i_ctime_nsec_width, 4 | 8));
    assert!(offsets.inode_i_ctime_nsec_off > offsets.inode_i_ctime_sec_off);
    assert!(offsets.inode_i_ctime_sec_off + 8 <= offsets.inode_size);
    assert!(
        offsets.inode_i_ctime_nsec_off + offsets.inode_i_ctime_nsec_width
            <= offsets.inode_size
    );
    // §4.1 ABI 2 (UNTRUSTED): every new field must fit its real struct.
    assert!(offsets.inode_i_uid_off + 4 <= offsets.inode_size);
    assert!(offsets.bprm_filename_off + 8 <= offsets.bprm_size);
    assert!(offsets.file_f_path_dentry_off + 8 <= offsets.file_size);
    assert!(offsets.dentry_d_parent_off + 8 <= offsets.dentry_size);
    assert!(offsets.dentry_d_inode_off + 8 <= offsets.dentry_size);
    assert!(offsets.dentry_size > 0);
    let table = encode_titan_exec_offsets_table(&offsets);
    assert_eq!(
        table[btf_offsets::OFF_INODE_I_CTIME_NSEC_WIDTH],
        offsets.inode_i_ctime_nsec_width
    );
    assert_eq!(
        table[btf_offsets::OFF_MAGIC],
        gedefense_common::TITAN_EXEC_OFFSETS_MAGIC
    );
}

#[test]
fn titan_btf_rejects_broken_headers_truncation_and_implausible_layouts() {
    let good = titan_btf_fixture(&TitanBtfSpec::default());
    let mut wrong_magic = good.clone();
    wrong_magic[0] ^= 0xff;
    let mut wrong_version = good.clone();
    wrong_version[2] = 2;
    let mut wrong_hdr_len = good.clone();
    wrong_hdr_len[4] = 23;
    let mut oversized_hdr_len = good.clone();
    oversized_hdr_len[4..8].copy_from_slice(&(good.len() as u32 + 1).to_le_bytes());
    let broken_bodies: Vec<(&str, Vec<u8>)> = vec![
        ("empty", Vec::new()),
        ("short header", good[..12].to_vec()),
        ("wrong magic", wrong_magic),
        ("wrong version", wrong_version),
        ("wrong hdr_len", wrong_hdr_len),
        ("hdr_len beyond image", oversized_hdr_len),
        ("truncated string table", good[..good.len() - 4].to_vec()),
    ];
    for (label, data) in broken_bodies {
        assert!(resolve_titan_btf(data).is_err(), "{label}");
    }
    let broken_layouts = [
        ("offset beyond inode", TitanBtfSpec { inode_size: 100, ..Default::default() }),
        ("missing i_ino", TitanBtfSpec { drop_ino: true, ..Default::default() }),
        ("missing super_block", TitanBtfSpec { drop_super: true, ..Default::default() }),
        ("ambiguous inode", TitanBtfSpec { duplicate_inode: true, ..Default::default() }),
        ("bprm arity 2", TitanBtfSpec { bprm_nargs: 2, ..Default::default() }),
        ("mmap arity 2", TitanBtfSpec { mmap_nargs: 2, ..Default::default() }),
        ("mmap arity 6", TitanBtfSpec { mmap_nargs: 6, ..Default::default() }),
    ];
    for (label, spec) in broken_layouts {
        assert!(
            resolve_titan_btf(titan_btf_fixture(&spec)).is_err(),
            "{label}"
        );
    }
    // §4.1 accepts mmap arities 3..=5 for index computation, but the eBPF
    // slots are fixed: only arity 4 may ever be attached.
    for arity in [3u16, 5] {
        let spec = TitanBtfSpec {
            mmap_nargs: arity,
            ..Default::default()
        };
        let offsets = resolve_titan_btf(titan_btf_fixture(&spec))
            .expect("arity is plausible");
        assert!(!titan_exec_offsets_match_ebpf_slots(&offsets), "arity {arity}");
    }
}

#[test]
fn titan_btf_accepts_extended_v1_header() {
    let baseline_data = titan_btf_fixture(&TitanBtfSpec::default());
    let baseline = resolve_titan_btf(baseline_data.clone()).expect("baseline BTF");
    // Kernel 7.3 grows the BTF v1 header to 32 bytes; the section offsets
    // stay relative to hdr_len, so an 8-byte extension must parse exactly
    // like the 24-byte header (and must not be mistaken for section data).
    let mut extended = baseline_data;
    extended.splice(24..24, [0u8; 8]);
    extended[4..8].copy_from_slice(&32u32.to_le_bytes());
    let offsets = resolve_titan_btf(extended).expect("32-byte BTF header");
    assert_eq!(offsets.file_f_inode_off, baseline.file_f_inode_off);
    assert_eq!(offsets.inode_i_ino_off, baseline.inode_i_ino_off);
    assert_eq!(offsets.inode_i_mode_off, baseline.inode_i_mode_off);
    assert_eq!(offsets.bprm_nargs, baseline.bprm_nargs);
    assert_eq!(offsets.mmap_nargs, baseline.mmap_nargs);
}

#[test]
fn titan_btf_from_path_is_bounded_and_strict() {
    let directory = test_titan_directory("btf");
    let path = directory.join("vmlinux.btf");
    fs::write(&path, titan_btf_fixture(&TitanBtfSpec::default())).expect("write fixture");
    let text = path.to_string_lossy().into_owned();
    let offsets = btf_offsets::VmlinuxBtf::from_path(&text)
        .expect("parse fixture file")
        .resolve_titan_exec()
        .expect("resolve fixture file");
    assert_eq!(offsets.inode_i_nlink_off, 72);
    assert!(btf_offsets::VmlinuxBtf::from_path(&directory.join("absent").to_string_lossy())
        .is_err());
    let oversized = directory.join("oversized.btf");
    fs::write(&oversized, vec![0u8; btf_offsets::MAX_VMLINUX_BTF_BYTES + 1])
        .expect("write oversized fixture");
    assert!(btf_offsets::VmlinuxBtf::from_path(&oversized.to_string_lossy()).is_err());
    fs::remove_dir_all(directory).expect("cleanup");
}

// ---- Point 1: pure Titan exec-gate helpers (§5/§6). ----
