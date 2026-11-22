//! M1.1 (6.2.0): on-write sensor policy tests.
//!
//! The sensor module keeps the thread/queue wiring; the pure policy surface
//! (candidate filter, root parser, path containment, token/object-id bounds) is
//! tested here so `on_write.rs` stays inside the module size cap.

use crate::malware::encode_path_token;
use crate::on_write::{close_quiet, event_file_path, random_object_id};
use crate::on_write_policy::*;
use std::fs::{self, File};
use std::os::fd::AsRawFd;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};


const MIB: u64 = 1024 * 1024;

#[test]
fn candidate_filter_scans_executables_and_data_regardless_of_uid() {
    assert_eq!(
        classify_write(0o100_755, 0, 4096, true),
        Some(Candidate::FullScan)
    );
    assert_eq!(
        classify_write(0o100_644, 0, 4096, true),
        Some(Candidate::SignatureProbe)
    );
    // A webserver (www-data) or benchmark user (1000) dropping an executable
    // or archive into a watched root must be scanned just like a root writer.
    assert_eq!(
        classify_write(0o100_755, 33, 4096, true),
        Some(Candidate::FullScan)
    );
    assert_eq!(
        classify_write(0o100_644, 1000, 4096, true),
        Some(Candidate::SignatureProbe)
    );
    // Directories, FIFOs and empty files are not scan candidates.
    assert_eq!(classify_write(0o040_755, 0, 4096, false), None);
    assert_eq!(classify_write(0o100_755, 0, 0, true), None);
    // Budget boundaries: 64 MiB for executables, 16 MiB for the data probe.
    assert_eq!(
        classify_write(0o100_755, 0, ON_WRITE_MAX_SCAN_BYTES, true),
        Some(Candidate::FullScan)
    );
    assert_eq!(
        classify_write(0o100_755, 0, ON_WRITE_MAX_SCAN_BYTES + 1, true),
        None
    );
    assert_eq!(
        classify_write(0o100_644, 0, ON_WRITE_SIGNATURE_PROBE_BYTES, true),
        Some(Candidate::SignatureProbe)
    );
    assert_eq!(
        classify_write(0o100_644, 0, ON_WRITE_SIGNATURE_PROBE_BYTES + 1, true),
        None
    );
    // A non-executable file above the 16 MiB probe budget is not scanned.
    assert_eq!(classify_write(0o100_644, 0, 128 * MIB, true), None);
}

#[test]
fn metadata_binding_reads_the_documented_fields() {
    let dir = std::env::temp_dir().join(format!(
        "gedefense-on-write-meta-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or(0)
    ));
    fs::create_dir_all(&dir).expect("fixture dir");
    let path = dir.join("fixture.bin");
    fs::write(&path, b"fixture").expect("fixture write");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).expect("fixture mode");
    let metadata = fs::metadata(&path).expect("fixture metadata");
    // The test runner is unprivileged, but ownership is no longer a filter:
    // an executable fixture is a FullScan candidate even when this uid owns it.
    assert_eq!(classify_candidate(&metadata), Some(Candidate::FullScan));
    assert!(metadata.len() > 0 && metadata.is_file());
    fs::remove_dir_all(&dir).ok();
}

#[test]
fn roots_are_strict_absolute_and_component_clean() {
    let parsed = parse_roots("/tmp,/var/tmp,/dev/shm").expect("valid roots");
    assert_eq!(
        parsed,
        vec![
            PathBuf::from("/tmp"),
            PathBuf::from("/var/tmp"),
            PathBuf::from("/dev/shm")
        ]
    );
    assert_eq!(parse_roots("").expect("empty"), Vec::<PathBuf>::new());
    for invalid in ["tmp", "/tmp/../etc", "/tmp//x", "/tmp/", "/", "/tmp\0"] {
        assert!(parse_roots(invalid).is_err(), "accepted {invalid:?}");
    }
    assert_eq!(parse_roots("/tmp,/tmp").expect("deduplicated").len(), 1);
    let many = (0..=MAX_ON_WRITE_ROOTS)
        .map(|index| format!("/tmp/root{index}"))
        .collect::<Vec<_>>()
        .join(",");
    assert!(parse_roots(&many).is_err(), "root cap not enforced");
}

#[test]
fn default_roots_and_configured_roots_are_separated() {
    let defaults = resolve_roots(&[]).expect("defaults");
    assert_eq!(defaults.len(), DEFAULT_ON_WRITE_ROOTS.len());
    assert_eq!(
        resolve_roots(&["/tmp,/srv/drop".to_owned()]).expect("configured"),
        vec![PathBuf::from("/tmp"), PathBuf::from("/srv/drop")]
    );
    assert!(resolve_roots(&["relative".to_owned()]).is_err());
    assert!(resolve_roots(&["/".to_owned()]).is_err());
}

#[test]
fn path_filter_is_component_exact() {
    let roots = vec![PathBuf::from("/tmp"), PathBuf::from("/var/www")];
    assert!(path_is_below_any(Path::new("/tmp"), &roots));
    assert!(path_is_below_any(Path::new("/tmp/payload"), &roots));
    assert!(path_is_below_any(Path::new("/var/www/uploads/a.php"), &roots));
    assert!(!path_is_below_any(Path::new("/tmp2/payload"), &roots));
    assert!(!path_is_below_any(Path::new("/var/www2/a"), &roots));
    assert!(!path_is_below_any(Path::new("/etc/passwd"), &roots));
}

#[test]
fn trusted_prefixes_cover_system_and_vault_trees() {
    for trusted in [
        "/usr/bin/ls",
        "/usr/lib/x86_64-linux-gnu/libc.so.6",
        "/bin/true",
        "/lib64/ld-linux-x86-64.so.2",
        "/opt/vgt/gedefense/current/libexec/gedefense-core",
        "/var/lib/vgt/gedefense/quarantine/objects/x",
        "/var/lib/dpkg/status",
        "/proc/self/status",
    ] {
        assert!(path_is_trusted(Path::new(trusted)), "not trusted: {trusted}");
    }
    for untrusted in [
        "/tmp/payload",
        "/var/tmp/x",
        "/dev/shm/y",
        "/var/www/uploads/shell.php",
        "/opt/other/app",
        "/home/alice/bin/tool",
    ] {
        assert!(
            !path_is_trusted(Path::new(untrusted)),
            "wrongly trusted: {untrusted}"
        );
    }
}

#[test]
fn path_tokens_are_bounded_and_absolute() {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    let short = encode_path_token(b"/tmp/a b");
    assert_eq!(
        URL_SAFE_NO_PAD.decode(short.as_bytes()).expect("decode"),
        b"/tmp/a b"
    );
    let long = b"/tmp/xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
    let hashed = encode_path_token(long);
    let decoded = URL_SAFE_NO_PAD.decode(hashed.as_bytes()).expect("decode");
    assert!(decoded.starts_with(b"/#path-sha256-"));
    assert!(hashed.len() < 192);
}

#[test]
fn object_ids_match_the_vault_format() {
    for _ in 0..8 {
        let id = random_object_id().expect("object id");
        assert_eq!(id.len(), 19);
        assert!(id.starts_with("QV-"));
        assert!(id[3..]
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()));
    }
}

#[test]
fn event_paths_are_only_stable_for_open_files() {
    let file = File::open("/dev/null").expect("dev null");
    let live = file.as_raw_fd();
    assert!(event_file_path(live).is_some());
    let closed = unsafe { libc::dup(live) };
    assert!(closed >= 0);
    close_quiet(closed);
    assert!(event_file_path(closed).is_none());
}
