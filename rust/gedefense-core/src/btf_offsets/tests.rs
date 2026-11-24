//! V6.3.0 AP-1: synthetic-BTF fixtures for the executable-inode identity
//! resolver (mirrors the fixture style used by the Titan tests in `main.rs`).

use super::*;

struct BtfFixture {
    strings: Vec<u8>,
    types: Vec<Vec<u8>>,
}

impl BtfFixture {
    fn new() -> Self {
        Self { strings: vec![0], types: Vec::new() }
    }

    fn name(&mut self, name: &str) -> u32 {
        let offset = self.strings.len() as u32;
        self.strings.extend_from_slice(name.as_bytes());
        self.strings.push(0);
        offset
    }

    fn push(&mut self, name_off: u32, kind: u8, vlen: u16, value: u32, extra: &[u8]) -> u32 {
        let info = (u32::from(kind) << 24) | u32::from(vlen);
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
        self.push(name_off, 1, 0, size, &size.to_le_bytes())
    }

    fn pointer(&mut self, pointee: u32) -> u32 {
        self.push(0, 2, 0, pointee, &[])
    }

    fn record(&mut self, name: &str, size: u32, members: &[(u32, u32, u32)]) -> u32 {
        let name_off = self.name(name);
        let mut extra = Vec::new();
        for (member_name, type_id, offset_bits) in members {
            extra.extend_from_slice(&member_name.to_le_bytes());
            extra.extend_from_slice(&type_id.to_le_bytes());
            extra.extend_from_slice(&offset_bits.to_le_bytes());
        }
        self.push(name_off, 4, members.len() as u16, size, &extra)
    }

    fn finish(self) -> Vec<u8> {
        let type_len: u32 = self.types.iter().map(|encoded| encoded.len() as u32).sum();
        let mut data = Vec::new();
        data.extend_from_slice(&BTF_MAGIC.to_le_bytes());
        data.push(BTF_VERSION);
        data.push(0);
        data.extend_from_slice(&(BTF_HEADER_BYTES as u32).to_le_bytes());
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
struct ExecBtfSpec {
    task_size: u32,
    mm_size: u32,
    file_size: u32,
    inode_size: u32,
    super_size: u32,
    task_mm_bit: u32,
    mm_exe_bit: u32,
    file_inode_bit: u32,
    inode_ino_bit: u32,
    inode_sb_bit: u32,
    sdev_bit: u32,
    drop_task_mm: bool,
    drop_mm_struct: bool,
    drop_exe_file: bool,
    duplicate_mm: bool,
}

impl Default for ExecBtfSpec {
    fn default() -> Self {
        Self {
            task_size: 8192,
            mm_size: 1024,
            file_size: 256,
            inode_size: 600,
            super_size: 256,
            task_mm_bit: 96 * 8,
            mm_exe_bit: 40 * 8,
            file_inode_bit: 24 * 8,
            inode_ino_bit: 64 * 8,
            inode_sb_bit: 40 * 8,
            sdev_bit: 16 * 8,
            drop_task_mm: false,
            drop_mm_struct: false,
            drop_exe_file: false,
            duplicate_mm: false,
        }
    }
}

/// Synthetic vmlinux-BTF with strictly the five structures the AP-1 gate
/// walks: `task_struct.mm`, `mm_struct.exe_file`, `file.f_inode`,
/// `inode.i_ino/i_sb` and `super_block.s_dev`.
fn exec_btf_fixture(spec: &ExecBtfSpec) -> Vec<u8> {
    let mut fixture = BtfFixture::new();
    let u32t = fixture.int("u32", 4);
    let u64t = fixture.int("u64", 8);
    let pointer = fixture.pointer(u32t);
    let task_mm = fixture.name("mm");
    let mut task_members = Vec::new();
    if !spec.drop_task_mm {
        task_members.push((task_mm, pointer, spec.task_mm_bit));
    }
    fixture.record("task_struct", spec.task_size, &task_members);
    if !spec.drop_mm_struct {
        let exe_file = fixture.name("exe_file");
        let mut mm_members = Vec::new();
        if !spec.drop_exe_file {
            mm_members.push((exe_file, pointer, spec.mm_exe_bit));
        }
        fixture.record("mm_struct", spec.mm_size, &mm_members);
        if spec.duplicate_mm {
            fixture.record("mm_struct", spec.mm_size, &[]);
        }
    }
    let f_inode = fixture.name("f_inode");
    fixture.record("file", spec.file_size, &[(f_inode, pointer, spec.file_inode_bit)]);
    let i_ino = fixture.name("i_ino");
    let i_sb = fixture.name("i_sb");
    fixture.record(
        "inode",
        spec.inode_size,
        &[(i_ino, u64t, spec.inode_ino_bit), (i_sb, pointer, spec.inode_sb_bit)],
    );
    let s_dev = fixture.name("s_dev");
    fixture.record("super_block", spec.super_size, &[(s_dev, u32t, spec.sdev_bit)]);
    fixture.finish()
}

fn resolve_exec_inode_btf(data: Vec<u8>) -> Result<ExecInodeOffsets, String> {
    VmlinuxBtf::parse(data)?.resolve_exec_inode()
}

#[test]
fn exec_inode_btf_golden_offsets_resolve() {
    let offsets = resolve_exec_inode_btf(exec_btf_fixture(&ExecBtfSpec::default()))
        .expect("golden AP-1 BTF fixture must resolve");
    assert_eq!(
        offsets,
        ExecInodeOffsets {
            task_mm_off: 96,
            task_size: 8192,
            mm_exe_file_off: 40,
            mm_size: 1024,
            file_f_inode_off: 24,
            inode_i_ino_off: 64,
            inode_i_sb_off: 40,
            super_s_dev_off: 16,
            file_size: 256,
            inode_size: 600,
            super_size: 256,
        }
    );
    // The 6.2 ABI table is independent: resolving AP-1 must not require the
    // Titan structures (linux_binprm/dentry/functions) at all.
    assert_eq!(offsets.task_mm_off % 8, 0);
}

#[test]
fn exec_inode_btf_rejects_missing_or_implausible_fields() {
    let cases = [
        ExecBtfSpec { drop_task_mm: true, ..ExecBtfSpec::default() },
        ExecBtfSpec { drop_exe_file: true, ..ExecBtfSpec::default() },
        ExecBtfSpec { drop_mm_struct: true, ..ExecBtfSpec::default() },
        ExecBtfSpec { duplicate_mm: true, ..ExecBtfSpec::default() },
        ExecBtfSpec { task_mm_bit: 0, ..ExecBtfSpec::default() },
        ExecBtfSpec { task_mm_bit: 101 * 8, ..ExecBtfSpec::default() },
        ExecBtfSpec { task_mm_bit: 8192 * 8, ..ExecBtfSpec::default() },
        ExecBtfSpec { mm_exe_bit: 4, ..ExecBtfSpec::default() },
        ExecBtfSpec { file_inode_bit: 33 * 8, ..ExecBtfSpec::default() },
        ExecBtfSpec { inode_ino_bit: 75 * 8, ..ExecBtfSpec::default() },
        ExecBtfSpec { inode_sb_bit: 0, ..ExecBtfSpec::default() },
        ExecBtfSpec { sdev_bit: 16 * 8 + 4, ..ExecBtfSpec::default() },
        ExecBtfSpec { task_size: 4, ..ExecBtfSpec::default() },
        ExecBtfSpec { mm_size: 0, ..ExecBtfSpec::default() },
        ExecBtfSpec { inode_size: 70 * 1024, ..ExecBtfSpec::default() },
    ];
    for spec in cases {
        assert!(
            resolve_exec_inode_btf(exec_btf_fixture(&spec)).is_err(),
            "{spec:?}"
        );
    }
}

#[test]
fn exec_inode_btf_accepts_the_live_vmlinux_when_readable() {
    if !std::path::Path::new(VMLINUX_BTF_PATH).exists() {
        // No vmlinux BTF on this host (Windows): the synthetic fixtures
        // above are the executable contract; the live path is NOT_TESTED.
        return;
    }
    let offsets = resolve_vmlinux_exec_inode_offsets()
        .expect("live vmlinux BTF must resolve the AP-1 offsets");
    // Evidence for the verification ledger: the live kernel BTF really
    // resolved the identity chain (not only a synthetic fixture).
    eprintln!("live exec-inode BTF offsets: {offsets:?}");
    assert!(offsets.task_size >= 8 && offsets.mm_size >= 8);
}
