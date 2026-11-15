//! Config/profile loading and staging-path validation (POINT2 spec §4).
//!
//! Inputs are *never* free client paths: only `<staging_inputs>/<token>.bin`
//! and `<staging_exports>/<uuid>/export.bin` are addressable.  Every file is
//! opened with `O_NOFOLLOW` and validated on the same descriptor (`fstat`) to
//! avoid symlink/TOCTOU races. Profile file: `root:root 0640`, ≤256 KiB, ≤64
//! profiles; parser binaries absolute, root-owned, non-symlink, hash-pinned.
//!
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Component, Path, PathBuf};
use crate::types::{
    is_hex, ErrorCode, InputMeta, Profile, MAX_ACTIVE_CELLS, MAX_ARGV, HARD_MAX_INPUT_BYTES,
};
pub const MAX_PROFILE_FILE_BYTES: u64 = 256 * 1024;
pub const HASH_CHUNK: usize = 64 * 1024;
/// Key file requirement (spec §3): 32 bytes, `root:gedefense 0640`.
pub const KEY_FILE_LEN: u64 = 32;
/// Open a file read-only without following a final symlink (`O_CLOEXEC` too).
pub fn open_readonly_nofollow(path: &Path) -> Result<File, ErrorCode> {
    std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)
        .map_err(|_| ErrorCode::ProfileInvalid)
}
/// Validate the key file (32 bytes, root-owned `0640`) and return its bytes.
pub fn load_key(path: &Path) -> Result<[u8; 32], ErrorCode> {
    load_key_owned(path, 0)
}
/// Same as [`load_key`] but with an explicit expected owner (unit tests only;
/// production callers use the zero-argument wrapper).
pub fn load_key_owned(path: &Path, expected_uid: u32) -> Result<[u8; 32], ErrorCode> {
    let mut f = open_readonly_nofollow(path).map_err(|_| ErrorCode::Internal)?;
    let md = f.metadata().map_err(|_| ErrorCode::Internal)?;
    if !md.is_file() || md.len() != KEY_FILE_LEN || md.uid() != expected_uid || md.mode() & 0o777 != 0o640 {
        return Err(ErrorCode::Internal);
    }
    let mut key = [0u8; 32];
    f.read_exact(&mut key).map_err(|_| ErrorCode::Internal)?;
    Ok(key)
}
/// Parse the INI-style profile text into structurally validated profiles.
pub fn parse_profiles_text(text: &str) -> Result<Vec<Profile>, ErrorCode> {
    if text.len() as u64 > MAX_PROFILE_FILE_BYTES {
        return Err(ErrorCode::ProfileInvalid);
    }
    let mut profiles: Vec<Profile> = Vec::new();
    let mut block: Option<Profile> = None;
    let mut argv: Vec<(usize, String)> = Vec::new();
    let mut seen_keys: std::collections::HashSet<String> = std::collections::HashSet::new();
    for (lineno, raw) in text.lines().enumerate() {
        let line = raw.trim_end_matches('\r');
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if trimmed.starts_with('[') {
            if let Some(p) = block.take() {
                profiles.push(finish_block(p, &mut argv)?);
            }
            if profiles.len() >= MAX_ACTIVE_CELLS {
                return Err(ErrorCode::ProfileInvalid);
            }
            let inner = trimmed
                .strip_prefix("[profile ")
                .and_then(|s| s.strip_suffix(']'))
                .ok_or(ErrorCode::ProfileInvalid)?;
            if inner.is_empty() || inner.len() > crate::types::MAX_PROFILE_ID_LEN {
                return Err(ErrorCode::ProfileInvalid);
            }
            if profiles.iter().any(|p| p.id == inner) {
                return Err(ErrorCode::ProfileInvalid);
            }
            block = Some(Profile {
                id: inner.to_string(),
                binary: PathBuf::new(),
                sha256: String::new(),
                argv: Vec::new(),
                env_allow: Vec::new(),
                wayland: false,
                pipewire: false,
                max_input_bytes: 0,
                max_export_bytes: 0,
                ttl_max_seconds: 0,
            });
            argv.clear();
            seen_keys.clear();
            continue;
        }
        let (key, value) = trimmed.split_once('=').ok_or(ErrorCode::ProfileInvalid)?;
        let p = block.as_mut().ok_or(ErrorCode::ProfileInvalid)?;
        if value.bytes().any(|b| b == b' ' || b == b'\t' || b == 0x1f || b == 0) || value.is_empty() {
            return Err(ErrorCode::ProfileInvalid);
        }
        if !seen_keys.insert(key.to_string()) {
            return Err(ErrorCode::ProfileInvalid);
        }
        if let Some(idx) = key.strip_prefix("argv").and_then(|n| n.parse::<usize>().ok()).filter(|_| key.starts_with("argv")) {
            if idx >= MAX_ARGV || argv.len() >= MAX_ARGV {
                return Err(ErrorCode::ProfileInvalid);
            }
            argv.push((idx, value.to_string()));
            continue;
        }
        match key {
            "binary" => p.binary = PathBuf::from(value),
            "sha256" => p.sha256 = value.to_string(),
            "env_allow" => {
                p.env_allow = value.split(',').map(|s| s.to_string()).filter(|s| !s.is_empty()).collect();
            }
            "wayland" => p.wayland = parse_bool(value)?,
            "pipewire" => p.pipewire = parse_bool(value)?,
            "max_input_bytes" => p.max_input_bytes = parse_dec(value)?,
            "max_export_bytes" => p.max_export_bytes = parse_dec(value)?,
            "ttl_max_seconds" => p.ttl_max_seconds = parse_dec(value)?,
            _ => return Err(ErrorCode::ProfileInvalid),
        }
        let _ = lineno;
    }
    if let Some(p) = block.take() {
        profiles.push(finish_block(p, &mut argv)?);
    }
    if profiles.is_empty() {
        // Default packaging state: empty profile list is valid (spec §7).
        return Ok(profiles);
    }
    Ok(profiles)
}
fn finish_block(mut p: Profile, argv: &mut Vec<(usize, String)>) -> Result<Profile, ErrorCode> {
    if argv.is_empty() {
        return Err(ErrorCode::ProfileInvalid);
    }
    argv.sort_by_key(|(idx, _)| *idx);
    if argv.iter().enumerate().any(|(pos, (idx, _))| pos != *idx) {
        return Err(ErrorCode::ProfileInvalid);
    }
    p.argv = argv.iter().map(|(_, v)| v.clone()).collect();
    argv.clear();
    p.validate()?;
    Ok(p)
}
fn parse_bool(s: &str) -> Result<bool, ErrorCode> {
    match s {
        "true" => Ok(true),
        "false" => Ok(false),
        _ => Err(ErrorCode::ProfileInvalid),
    }
}
fn parse_dec(s: &str) -> Result<u64, ErrorCode> {
    if s.is_empty() || s.len() > 20 || !s.bytes().all(|b| b.is_ascii_digit()) {
        return Err(ErrorCode::ProfileInvalid);
    }
    s.parse::<u64>().map_err(|_| ErrorCode::ProfileInvalid)
}
/// Secure load: fstat-validated `root:root 0640` file (≤256 KiB), parsed and
/// with every referenced binary hash-verified (root-owned, non-symlink).
pub fn load_profiles(path: &Path) -> Result<Vec<Profile>, ErrorCode> {
    let mut f = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)
        .map_err(|_| ErrorCode::ProfileInvalid)?;
    let md = f.metadata().map_err(|_| ErrorCode::ProfileInvalid)?;
    if !md.is_file() || md.len() > MAX_PROFILE_FILE_BYTES || md.uid() != 0 || md.mode() & 0o777 != 0o640 {
        return Err(ErrorCode::ProfileInvalid);
    }
    let mut buf = Vec::with_capacity(md.len() as usize);
    (&mut f).take(MAX_PROFILE_FILE_BYTES + 1).read_to_end(&mut buf).map_err(|_| ErrorCode::ProfileInvalid)?;
    if buf.len() as u64 > MAX_PROFILE_FILE_BYTES {
        return Err(ErrorCode::ProfileInvalid);
    }
    let text = std::str::from_utf8(&buf).map_err(|_| ErrorCode::ProfileInvalid)?;
    let profiles = parse_profiles_text(text)?;
    for p in &profiles {
        validate_binary(p)?;
    }
    Ok(profiles)
}
/// Validate a parser binary: absolute, no `..`, root-owned, non-symlink,
/// regular, not group/world writable, SHA-256 matches the pinned profile hash.
pub fn validate_binary(profile: &Profile) -> Result<(), ErrorCode> {
    validate_binary_owned(profile, 0)
}
/// Same as [`validate_binary`] with explicit expected owner (unit tests only).
pub fn validate_binary_owned(profile: &Profile, expected_uid: u32) -> Result<(), ErrorCode> {
    if profile.binary.components().any(|c| !matches!(c, Component::RootDir | Component::Normal(_))) {
        return Err(ErrorCode::ProfileInvalid);
    }
    let mut f = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(&profile.binary)
        .map_err(|_| ErrorCode::ProfileInvalid)?;
    let md = f.metadata().map_err(|_| ErrorCode::ProfileInvalid)?;
    if !md.is_file() || md.uid() != expected_uid || md.mode() & 0o022 != 0 {
        return Err(ErrorCode::ProfileInvalid);
    }
    f.seek(SeekFrom::Start(0)).map_err(|_| ErrorCode::ProfileInvalid)?;
    let (_, sha) = sha256_reader(&mut f, None)?;
    if sha != profile.sha256 {
        return Err(ErrorCode::ProfileInvalid);
    }
    Ok(())
}
/// Streaming SHA-256 over a reader; optional hard byte cap (→ `InputInvalid`).
pub fn sha256_reader<R: Read>(reader: &mut R, max_bytes: Option<u64>) -> Result<(u64, String), ErrorCode> {
    let mut hasher = Sha256::new();
    let mut total: u64 = 0;
    let mut buf = vec![0u8; HASH_CHUNK];
    loop {
        let n = reader.read(&mut buf).map_err(|_| ErrorCode::Internal)?;
        if n == 0 {
            break;
        }
        total = total.saturating_add(n as u64);
        if let Some(max) = max_bytes {
            if total > max {
                return Err(ErrorCode::InputInvalid);
            }
        }
        hasher.update(&buf[..n]);
    }
    Ok((total, hex::encode(hasher.finalize())))
}
/// Validate `<staging_inputs>/<token>.bin` and return its path.
///
/// Checks (all on the opened descriptor): token is 32 lowercase hex chars,
/// file is a regular non-symlink, owned by `owner_uid` (the `gedefense`
/// account), mode 0640, size equals `meta.size`, size ≤ cap and SHA-256
/// matches.  The returned path is only used for the read-only cell bind.
pub fn validate_input(
    staging_inputs: &Path,
    meta: &InputMeta,
    owner_uid: u32,
    max_input_bytes: u64,
) -> Result<PathBuf, ErrorCode> {
    meta.validate(max_input_bytes.min(HARD_MAX_INPUT_BYTES))?;
    let path = staging_inputs.join(meta.file_name());
    if path.parent() != Some(staging_inputs) {
        return Err(ErrorCode::InputInvalid);
    }
    let mut f = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(&path)
        .map_err(|_| ErrorCode::InputMissing)?;
    let md = f.metadata().map_err(|_| ErrorCode::InputMissing)?;
    if !md.is_file()
        || md.uid() != owner_uid
        || md.mode() & 0o777 != 0o640
        || md.len() != meta.size
        || md.len() > max_input_bytes
        || md.nlink() != 1
    {
        return Err(ErrorCode::InputInvalid);
    }
    let (size, sha) = sha256_reader(&mut f, Some(max_input_bytes))?;
    if size != meta.size || sha != meta.sha256 {
        return Err(ErrorCode::InputInvalid);
    }
    Ok(path)
}
/// Validate an export destination directory `<staging_exports>/<uuid>`.
/// Returns the `export.bin` path (creation happens in `export.rs`).
#[allow(dead_code)]
pub fn validate_export_dir(staging_exports: &Path, uuid: &str) -> Result<PathBuf, ErrorCode> {
    if !is_hex(uuid, 32) || !staging_exports.is_absolute() {
        return Err(ErrorCode::ExportMissing);
    }
    let dir = staging_exports.join(uuid);
    if dir.parent() != Some(staging_exports) {
        return Err(ErrorCode::ExportMissing);
    }
    match std::fs::symlink_metadata(&dir) {
        Ok(md) => {
            if !md.is_dir() || md.file_type().is_symlink() || md.uid() != 0 || md.mode() & 0o022 != 0 {
                return Err(ErrorCode::ExportMissing);
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => return Err(ErrorCode::ExportMissing),
    }
    Ok(dir.join("export.bin"))
}
/// Startup/`--check` validation of the staging directories (no writes).
/// Startup/`--check` validation of the staging directories (no writes).
/// `parser-inputs` is `0730 gedefense:gedefense`, `parser-exports` `0750
/// root:gedefense` (spec §7); both absolute, real dirs, never world-accessible.
pub fn validate_staging_dirs(staging_inputs: &Path, staging_exports: &Path, gedefense_uid: u32) -> Result<(), ErrorCode> {
    for (dir, owner) in [(staging_inputs, gedefense_uid), (staging_exports, 0)] {
        if !dir.is_absolute() { return Err(ErrorCode::Internal); }
        let md = std::fs::symlink_metadata(dir).map_err(|_| ErrorCode::Internal)?;
        if !md.is_dir() || md.file_type().is_symlink() || md.uid() != owner || md.mode() & 0o007 != 0 {
            return Err(ErrorCode::Internal);
        }
    }
    Ok(())
}
/// Look up a profile by ID (closed set from the profile file).
pub fn find_profile<'a>(profiles: &'a [Profile], id: &str) -> Result<&'a Profile, ErrorCode> {
    profiles.iter().find(|p| p.id == id).ok_or(ErrorCode::ProfileUnknown)
}
/// True when the effective UID is root (privileged helper preconditions).
pub fn is_root() -> bool {
    // SAFETY: geteuid(2) has no preconditions and cannot fail.
    unsafe { libc::geteuid() == 0 }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::test_support::TempDir;
    const VALID: &str = "\
# parser profiles (test fixture)
[profile pdf-viewer]
binary=/usr/bin/pdftoppm
sha256=<SHA>
argv0=/usr/bin/pdftoppm
argv1={input}
argv2=/tmp/cell/out/
env_allow=LANG,LC_ALL,TZ
wayland=false
pipewire=false
max_input_bytes=8388608
max_export_bytes=2097152
ttl_max_seconds=300
";
    const SHA_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    fn valid_text() -> String { VALID.replace("<SHA>", SHA_A) }
    #[test]
    fn parses_spec_example_and_empty_default() {
        let profiles = parse_profiles_text(&valid_text()).unwrap();
        assert_eq!(profiles.len(), 1);
        let p = &profiles[0];
        assert_eq!((p.id.as_str(), p.binary.as_path()), ("pdf-viewer", Path::new("/usr/bin/pdftoppm")));
        assert_eq!(p.argv, vec!["/usr/bin/pdftoppm", "{input}", "/tmp/cell/out/"]);
        assert_eq!(p.env_allow, vec!["LANG", "LC_ALL", "TZ"]);
        assert!(!p.wayland && !p.pipewire && p.max_input_bytes == 8_388_608 && p.ttl_max_seconds == 300);
        assert_eq!((find_profile(&profiles, "pdf-viewer").unwrap().id.as_str(), find_profile(&profiles, "nope").err()), ("pdf-viewer", Some(ErrorCode::ProfileUnknown)));
        assert!(parse_profiles_text("").unwrap().is_empty());
        assert!(parse_profiles_text("# only comments\n\n").unwrap().is_empty());
    }
    #[test]
    fn rejects_unknown_keys_duplicates_bad_values_and_caps() {
        let cases = [
            valid_text().replace("wayland=false", "wayland=false\nevil=1"),
            valid_text().replace("wayland=false", "wayland=maybe"),
            valid_text().replace("wayland=false", "wayland=false\nwayland=true"),
            valid_text().replace("argv1={input}", "argv3={input}"),
            valid_text().replace("max_input_bytes=8388608", "max_input_bytes=99999999999"),
            valid_text().replace("ttl_max_seconds=300", "ttl_max_seconds=1"),
            valid_text().replace("sha256=", "sha256=0"),
            valid_text().replace("binary=/usr/bin/pdftoppm", "binary=relative/pdftoppm"),
            format!("{}\n[profile pdf-viewer]\n", valid_text()),
            valid_text().replace("max_export_bytes=2097152", "max_export_bytes=2097152\nenv_allow=A"),
            valid_text().replace("env_allow=LANG,LC_ALL,TZ", "env_allow=LD_PRELOAD"),
            valid_text().replace("binary=/usr/bin/pdftoppm\n", ""),
            valid_text().replace(&format!("sha256={}\n", SHA_A), ""),
            valid_text().replace("argv2=/tmp/cell/out/", "argv2=/tmp/cell/out/\nargv4=x"),
            valid_text().replace("argv2=/tmp/cell/out/", &format!("argv2=x\n{}", (3..=MAX_ARGV + 1)
                .map(|i| format!("argv{}={}", i, "x")).collect::<Vec<_>>().join("\n"))),
            "#".repeat(MAX_PROFILE_FILE_BYTES as usize + 1),
        ];
        for (i, text) in cases.iter().enumerate() {
            assert_eq!(parse_profiles_text(text), Err(ErrorCode::ProfileInvalid), "case {}", i);
        }
        assert_eq!((parse_bool("TRUE"), parse_dec("-1"), parse_dec("1x"), parse_dec("42").unwrap()),
            (Err(ErrorCode::ProfileInvalid), Err(ErrorCode::ProfileInvalid), Err(ErrorCode::ProfileInvalid), 42));
    }
    #[test]
    fn secure_profile_file_and_key_rules() {
        let td = TempDir::new("cfg-secure").unwrap();
        let real = td.write("profiles.conf", valid_text().as_bytes()).unwrap();
        let link = td.child("link.conf");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        assert_eq!(load_profiles(&link), Err(ErrorCode::ProfileInvalid));
        assert_eq!(load_profiles(&real), Err(ErrorCode::ProfileInvalid));
        use std::os::unix::fs::PermissionsExt;
        let euid = unsafe { libc::geteuid() };
        let good = td.write("cell-helper.key", &[7u8; 32]).unwrap();
        assert_eq!(load_key_owned(&good, euid), Err(ErrorCode::Internal)); // 0644 rejected
        std::fs::set_permissions(&good, std::fs::Permissions::from_mode(0o640)).unwrap();
        assert_eq!(load_key_owned(&good, euid).unwrap(), [7u8; 32]);
        if euid != 0 { assert_eq!(load_key(&good), Err(ErrorCode::Internal)); }
        let short = td.write("short.key", &[7u8; 31]).unwrap();
        std::fs::set_permissions(&short, std::fs::Permissions::from_mode(0o640)).unwrap();
        assert_eq!(load_key_owned(&short, euid), Err(ErrorCode::Internal));
        let key_link = td.child("key.link");
        std::os::unix::fs::symlink(&good, &key_link).unwrap();
        assert_eq!(load_key_owned(&key_link, euid), Err(ErrorCode::Internal));
    }
    #[test]
    fn binary_validation_hash_owner_symlink_traversal() {
        let td = TempDir::new("cfg-binary").unwrap();
        let bytes = b"#!/bin/fake-parser\n";
        let bin = td.write("fake-parser", bytes).unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
        let euid = unsafe { libc::geteuid() };
        let mut p = crate::types::Profile { id: "fake".into(), binary: bin.clone(),
            sha256: hex::encode(Sha256::digest(bytes)), argv: vec!["/fake-parser".into()],
            env_allow: vec![], wayland: false, pipewire: false,
            max_input_bytes: 1024, max_export_bytes: 1024, ttl_max_seconds: 30 };
        assert_eq!(validate_binary_owned(&p, euid), Ok(()));
        p.sha256 = "00".repeat(32);
        assert_eq!(validate_binary_owned(&p, euid), Err(ErrorCode::ProfileInvalid));
        p.sha256 = hex::encode(Sha256::digest(bytes));
        assert_eq!(validate_binary_owned(&p, euid ^ 1), Err(ErrorCode::ProfileInvalid));
        let link = td.child("fake-link");
        std::os::unix::fs::symlink(&bin, &link).unwrap();
        p.binary = link;
        assert_eq!(validate_binary_owned(&p, euid), Err(ErrorCode::ProfileInvalid));
        let ww = td.write("ww-parser", bytes).unwrap();
        std::fs::set_permissions(&ww, std::fs::Permissions::from_mode(0o666)).unwrap();
        p.binary = ww;
        assert_eq!(validate_binary_owned(&p, euid), Err(ErrorCode::ProfileInvalid));
        for bad in ["relative/parser", "/tmp/../etc/passwd"] {
            p.binary = PathBuf::from(bad);
            assert_eq!(validate_binary_owned(&p, euid), Err(ErrorCode::ProfileInvalid));
        }
    }
    #[test]
    fn input_validation_hash_size_owner_symlink_traversal() {
        let td = TempDir::new("cfg-input").unwrap();
        let data = b"hello parser input";
        let token = "ab".repeat(16);
        let path = td.child(&format!("{}.bin", token));
        std::fs::write(&path, data).unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();
        let uid = unsafe { libc::geteuid() };
        let meta = InputMeta { token: token.clone(), sha256: hex::encode(Sha256::digest(data)), size: data.len() as u64 };
        assert_eq!(validate_input(&td.path, &meta, uid, HARD_MAX_INPUT_BYTES).unwrap(), path);
        let bad_meta = [
            InputMeta { sha256: "00".repeat(32), ..meta.clone() },
            InputMeta { size: 1, ..meta.clone() },
            InputMeta { token: "../".to_string() + &"ab".repeat(14), ..meta.clone() },
            InputMeta { token: "zz".repeat(16), ..meta.clone() },
        ];
        for bad in bad_meta { assert!(validate_input(&td.path, &bad, uid, HARD_MAX_INPUT_BYTES).is_err()); }
        assert_eq!(validate_input(&td.path, &meta, uid ^ 1, HARD_MAX_INPUT_BYTES), Err(ErrorCode::InputInvalid));
        assert_eq!(validate_input(&td.path, &meta, uid, 8), Err(ErrorCode::InputInvalid));
        assert_eq!(validate_input(&TempDir::new("cfg-in-missing").unwrap().path, &meta, uid, HARD_MAX_INPUT_BYTES), Err(ErrorCode::InputMissing));
        let link = td.child(&format!("{}.bin", "cd".repeat(16)));
        std::os::unix::fs::symlink(&path, &link).unwrap();
        let linked = InputMeta { token: "cd".repeat(16), ..meta };
        assert_eq!(validate_input(&td.path, &linked, uid, HARD_MAX_INPUT_BYTES), Err(ErrorCode::InputMissing));
    }
    #[test]
    fn export_dir_and_streaming_sha256() {
        let td = TempDir::new("cfg-export").unwrap();
        let uuid = "ab".repeat(16);
        assert_eq!(validate_export_dir(&td.path, &uuid).unwrap(), td.path.join(&uuid).join("export.bin"));
        assert_eq!(validate_export_dir(Path::new("rel/exports"), &uuid), Err(ErrorCode::ExportMissing));
        assert_eq!(validate_export_dir(&td.path, "../escape"), Err(ErrorCode::ExportMissing));
        std::fs::create_dir(td.child(&uuid)).unwrap();
        if is_root() { assert!(validate_export_dir(&td.path, &uuid).is_ok()); }
        else { assert_eq!(validate_export_dir(&td.path, &uuid), Err(ErrorCode::ExportMissing)); }
        std::fs::remove_dir(td.child(&uuid)).unwrap();
        std::os::unix::fs::symlink(td.child("other"), td.child(&uuid)).unwrap();
        assert_eq!(validate_export_dir(&td.path, &uuid), Err(ErrorCode::ExportMissing));
        let data = vec![0x42u8; HASH_CHUNK * 2 + 7];
        let mut cur = std::io::Cursor::new(&data);
        let (n, sha) = sha256_reader(&mut cur, None).unwrap();
        assert_eq!((n, sha), (data.len() as u64, hex::encode(Sha256::digest(&data))));
        let mut cur = std::io::Cursor::new(&data);
        assert_eq!(sha256_reader(&mut cur, Some(10)), Err(ErrorCode::InputInvalid));
    }
    #[test]
    fn root_gated_profile_file_and_binary_validation() {
        if !is_root() {
            eprintln!("SKIP root_gated_profile_file_and_binary_validation: requires euid 0");
            return;
        }
        let binary = PathBuf::from("/usr/bin/true");
        if !binary.exists() {
            eprintln!("SKIP: /usr/bin/true missing");
            return;
        }
        let mut bf = File::open(&binary).unwrap();
        let (_, sha) = sha256_reader(&mut bf, None).unwrap();
        let text = valid_text().replace("binary=/usr/bin/pdftoppm", "binary=/usr/bin/true")
            .replace(SHA_A, &sha).replace("argv0=/usr/bin/pdftoppm", "argv0=/usr/bin/true");
        let td = TempDir::new("cfg-root").unwrap();
        use std::os::unix::fs::PermissionsExt;
        let path = td.write("profiles.conf", text.as_bytes()).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o640)).unwrap();
        assert_eq!(load_profiles(&path).unwrap().len(), 1);
        let bad = td.write("bad.conf", valid_text().replace("binary=/usr/bin/pdftoppm", "binary=/usr/bin/true").as_bytes()).unwrap();
        std::fs::set_permissions(&bad, std::fs::Permissions::from_mode(0o640)).unwrap();
        assert_eq!(load_profiles(&bad), Err(ErrorCode::ProfileInvalid));
    }
}
