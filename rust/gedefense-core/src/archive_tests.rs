//! M1.2 (6.2.0) archive-inspection fixtures and tests.
//!
//! The parser modules are capped at 500 lines, so the (large) builders and the
//! malicious/harmless recursion matrix live here, exactly like the BTF fixtures
//! of the Titan gate.

use crate::archive_scan::{inspect, Finding, MAX_DEPTH, MAX_ENTRIES};

fn hex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&text[index..index + 2], 16).expect("hex fixture"))
        .collect()
}

/// Minimal single-member ZIP (stored or deflate) with a valid central directory.
fn zip(method: u16, name: &[u8], payload: &[u8], declared: u32) -> Vec<u8> {
    let mut out = Vec::new();
    let crc = 0u32;
    // Local file header (30 bytes + name).
    out.extend_from_slice(b"PK\x03\x04");
    out.extend_from_slice(&20u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&method.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&crc.to_le_bytes());
    out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    out.extend_from_slice(&declared.to_le_bytes());
    out.extend_from_slice(&(name.len() as u16).to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(name);
    out.extend_from_slice(payload);
    let directory_offset = out.len() as u32;
    // Central directory entry (46 bytes + name); local header offset is 0.
    out.extend_from_slice(b"PK\x01\x02");
    out.extend_from_slice(&20u16.to_le_bytes());
    out.extend_from_slice(&20u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&method.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&crc.to_le_bytes());
    out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    out.extend_from_slice(&declared.to_le_bytes());
    out.extend_from_slice(&(name.len() as u16).to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(name);
    let directory_size = out.len() as u32 - directory_offset;
    // End of central directory.
    out.extend_from_slice(b"PK\x05\x06");
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&1u16.to_le_bytes());
    out.extend_from_slice(&1u16.to_le_bytes());
    out.extend_from_slice(&directory_size.to_le_bytes());
    out.extend_from_slice(&directory_offset.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out
}

/// One ustar regular-file member with a correct header checksum.
fn tar_member(name: &[u8], payload: &[u8]) -> Vec<u8> {
    let mut header = [0u8; 512];
    header[..name.len()].copy_from_slice(name);
    header[100..108].copy_from_slice(b"0000644\0");
    header[108..116].copy_from_slice(b"0000000\0");
    header[116..124].copy_from_slice(b"0000000\0");
    header[124..136].copy_from_slice(format!("{:011o}\0", payload.len()).as_bytes());
    header[136..148].copy_from_slice(b"00000000000\0");
    header[148..156].copy_from_slice(b"        ");
    header[156] = b'0';
    header[257..262].copy_from_slice(b"ustar");
    let mut sum = 0u64;
    for byte in header.iter() {
        sum += u64::from(*byte);
    }
    header[148..156].copy_from_slice(format!("{:06o}\0 ", sum).as_bytes());
    let mut out = Vec::new();
    out.extend_from_slice(&header);
    out.extend_from_slice(payload);
    let padding = (512 - payload.len() % 512) % 512;
    out.extend(std::iter::repeat(0u8).take(padding));
    out
}

/// One single-member GZIP wrapper (CRC intentionally zero; the inspector only
/// cross-checks ISIZE, the payload integrity is covered by the member SHA-256).
fn gzip(raw_deflate: &[u8], expanded: usize) -> Vec<u8> {
    let mut out = vec![0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 0xff];
    out.extend_from_slice(raw_deflate);
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&(expanded as u32).to_le_bytes());
    out
}

fn inspect_bytes(
    bytes: Vec<u8>,
    signature: &dyn Fn(&[u8; 32]) -> Option<String>,
) -> Option<Finding> {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    let path = std::env::temp_dir().join(format!(
        "gedefense-archive-{}-{nonce}",
        std::process::id()
    ));
    std::fs::write(&path, &bytes).expect("archive fixture");
    let mut file = std::fs::File::open(&path).expect("archive fixture open");
    let result = inspect(&mut file, bytes.len() as u64, b"EICAR", signature);
    std::fs::remove_file(&path).ok();
    result.expect("inspection")
}

fn no_signature(_digest: &[u8; 32]) -> Option<String> {
    None
}

#[test]
fn harmless_nested_archives_stay_clean() {
    let inner = tar_member(b"a.txt", b"harmless");
    let inner_zip = zip(0, b"docs/a.txt", b"harmless", 8);
    let outer = zip(0, b"payload.bin", &inner_zip, inner_zip.len() as u32);
    assert_eq!(inspect_bytes(outer, &no_signature), None);
    let gz = gzip(
        &hex("cb4b2d2e494dd14d2c4acec82c4bd5cd4dcd4d4a2d0200"),
        21,
    );
    assert_eq!(inspect_bytes(gz, &no_signature), None);
    let tar = {
        let mut bytes = tar_member(b"tool/run.sh", b"nested exec payload");
        bytes.extend(tar_member(b"tool/inner.tar", &inner));
        bytes.extend(std::iter::repeat(0u8).take(1024));
        bytes
    };
    assert_eq!(inspect_bytes(tar, &no_signature), None);
}

#[test]
fn eicar_inside_a_nested_member_is_malicious() {
    let inner_secret =
        b"XXX X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H* XXX";
    let payload = tar_member(b"eicar.com", inner_secret);
    let outer = zip(0, b"nested.zip", &payload, payload.len() as u32);
    let finding = inspect_bytes(outer, &no_signature).expect("finding");
    assert!(finding.malicious);
    assert_eq!(finding.reason, "nested-eicar-signature");
}

#[test]
fn nested_signature_match_is_malicious() {
    let payload = b"EICAR";
    let outer = zip(0, b"payload.bin", payload, payload.len() as u32);
    let hit = |_digest: &[u8; 32]| Some("NESTED.TEST.SIGNATURE".to_owned());
    let finding = inspect_bytes(outer, &hit).expect("finding");
    assert!(finding.malicious);
    assert_eq!(finding.reason, "NESTED.TEST.SIGNATURE");
}

#[test]
fn traversal_and_absolute_member_paths_are_rejected() {
    for name in [&b"../etc/passwd"[..], b"/etc/passwd", b"dir/../image", b"a\\b"] {
        let archive = zip(0, name, b"x", 1);
        let finding = inspect_bytes(archive, &no_signature).expect("finding");
        assert_eq!(
            finding.reason, "nested-archive-unsafe-path",
            "name {name:?}"
        );
    }
}

#[test]
fn expansion_bombs_are_bounded() {
    // Declared 256 MiB from a one-byte member: rejected before inflating.
    let bomb = zip(0, b"bomb", b"x", 256 * 1024 * 1024);
    assert_eq!(
        inspect_bytes(bomb, &no_signature).expect("finding").reason,
        "nested-archive-entry-size"
    );
    // 300 'A's in 7 compressed bytes: ratio 42 (<200) is legal and clean.
    let ratio_ok = zip(8, b"ok", &hex("73741c05c40200"), 300);
    assert_eq!(inspect_bytes(ratio_ok, &no_signature), None);
}

#[test]
fn depth_and_entry_budgets_are_enforced() {
    // MAX_DEPTH+1 nested zip layers: the recursion one level below the
    // documented depth is a bounded rejection, never a stack overflow.
    let mut archive = zip(0, b"leaf.txt", b"data", 4);
    for _ in 0..=MAX_DEPTH {
        archive = zip(0, b"layer.zip", &archive, archive.len() as u32);
    }
    assert_eq!(
        inspect_bytes(archive, &no_signature).expect("finding").reason,
        "nested-archive-depth"
    );
}

#[test]
fn entry_budget_is_enforced_before_the_directory_is_read() {
    // EOCD claims more entries than MAX_ENTRIES; the bounded parser rejects the
    // archive before allocating or reading any central directory.
    let mut archive = Vec::new();
    archive.extend_from_slice(b"PK\x03\x04");
    archive.resize(64, 0);
    archive.extend_from_slice(b"PK\x05\x06");
    archive.extend_from_slice(&0u16.to_le_bytes());
    archive.extend_from_slice(&0u16.to_le_bytes());
    archive.extend_from_slice(&(MAX_ENTRIES as u16 + 1).to_le_bytes());
    archive.extend_from_slice(&(MAX_ENTRIES as u16 + 1).to_le_bytes());
    archive.extend_from_slice(&0u32.to_le_bytes());
    archive.extend_from_slice(&0u32.to_le_bytes());
    archive.extend_from_slice(&0u16.to_le_bytes());
    assert_eq!(
        inspect_bytes(archive, &no_signature).expect("finding").reason,
        "nested-archive-entry-limit"
    );
}

#[test]
fn malformed_and_unsupported_archives_are_not_reported_clean() {
    let mut truncated = b"PK\x03\x04".to_vec();
    truncated.resize(64, 0);
    assert_eq!(
        inspect_bytes(truncated, &no_signature)
            .expect("finding")
            .reason,
        "archive-malformed"
    );
    let bz = {
        let mut bytes = b"BZh91AY&SY".to_vec();
        bytes.extend_from_slice(&[0u8; 32]);
        bytes
    };
    let wrapped = zip(0, b"nested.bz2", &bz, bz.len() as u32);
    assert_eq!(
        inspect_bytes(wrapped, &no_signature)
            .expect("finding")
            .reason,
        "nested-archive-uninspectable"
    );
}
