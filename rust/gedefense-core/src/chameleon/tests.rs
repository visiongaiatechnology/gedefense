//! Unit tests for the AP-8 Chameleon profile: manifest rejecting parser, neutral
//! name derivation, in-memory object neutralisation and the default-off identity
//! proof.

use super::*;

use std::collections::{BTreeSet, HashSet};
use std::fs;
use std::os::unix::fs::PermissionsExt;

use std::sync::atomic::{AtomicU64, Ordering};

static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

pub(super) struct TempDir {
    pub(super) path: PathBuf,
}

impl TempDir {
    pub(super) fn new(label: &str) -> Self {
        let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "gd-chameleon-{}-{}-{sequence}-{label}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|duration| duration.as_nanos())
                .unwrap_or(0)
        ));
        fs::create_dir_all(&path).expect("create test directory");
        Self { path }
    }

    pub(super) fn file(&self, name: &str, contents: &[u8], mode: u32) -> PathBuf {
        let path = self.path.join(name);
        fs::write(&path, contents).expect("write test file");
        fs::set_permissions(&path, fs::Permissions::from_mode(mode)).expect("chmod test file");
        path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn valid_manifest_text() -> String {
    format!(
        "{schema}\n\
install_id=gd-ap8-test-install-0001\n\
bpf_name_salt={salt}\n\
core_socket=/run/chameleon/core.sock\n\
scan_socket=/run/chameleon/scan.sock\n\
bpf_pin_root=/sys/fs/bpf/chameleon\n\
state_dir=/var/lib/chameleon/state\n\
config_dir=/etc/chameleon\n\
public_port=39000\n\
backend_port=39001\n\
neutral_unit_prefix=cham\n",
        schema = CHAMELEON_MANIFEST_SCHEMA,
        salt = "0123456789abcdef".repeat(4),
    )
}

fn manifest_with(replacement: &str) -> String {
    let base = valid_manifest_text();
    let mut output = String::new();
    let mut replaced = false;
    for line in base.lines() {
        if let Some((key, _)) = line.split_once('=') {
            if replacement.starts_with(key) && replacement[key.len()..].starts_with('=') {
                output.push_str(replacement);
                output.push('\n');
                replaced = true;
                continue;
            }
        }
        output.push_str(line);
        output.push('\n');
    }
    if !replaced {
        output.push_str(replacement);
        output.push('\n');
    }
    output
}

fn manifest_without(key: &str) -> String {
    valid_manifest_text()
        .lines()
        .filter(|line| !line.starts_with(&format!("{key}=")))
        .map(|line| format!("{line}\n"))
        .collect()
}

pub(super) fn test_manifest(state_dir: &Path, config_dir: &Path) -> ChameleonManifest {
    let text = manifest_with(&format!("state_dir={}", state_dir.display())).replace(
        "config_dir=/etc/chameleon",
        &format!("config_dir={}", config_dir.display()),
    );
    parse_manifest(text.as_bytes()).expect("test manifest parses")
}

// ------------------------------------------------------------------ manifest

#[test]
fn manifest_accepts_a_strict_valid_document() {
    let temp = TempDir::new("manifest-ok");
    let path = temp.file("manifest.conf", valid_manifest_text().as_bytes(), 0o600);
    let profile = ChameleonProfile::from_manifest(path.to_str().unwrap()).expect("valid manifest");
    assert!(profile.active());
    let manifest = profile.manifest.as_ref().unwrap();
    assert_eq!(manifest.install_id, "gd-ap8-test-install-0001");
    assert_eq!(manifest.core_socket, "/run/chameleon/core.sock");
    assert_eq!(manifest.scan_socket, "/run/chameleon/scan.sock");
    assert_eq!(manifest.bpf_pin_root, "/sys/fs/bpf/chameleon");
    assert_eq!(manifest.state_dir, "/var/lib/chameleon/state");
    assert_eq!(manifest.config_dir, "/etc/chameleon");
    assert_eq!(manifest.public_port, 39000);
    assert_eq!(manifest.backend_port, 39001);
    assert_eq!(manifest.neutral_unit_prefix, "cham");
    assert!(manifest.admin_audit_path.is_none());
    assert_eq!(
        manifest.audit_path(),
        Path::new("/var/lib/chameleon/state/chameleon-map.audit")
    );
}

#[test]
fn manifest_accepts_optional_admin_audit_path() {
    let temp = TempDir::new("manifest-audit");
    let path = temp.file(
        "manifest.conf",
        manifest_with("admin_audit_path=/var/log/chameleon-map.audit").as_bytes(),
        0o600,
    );
    let profile = ChameleonProfile::from_manifest(path.to_str().unwrap()).expect("valid manifest");
    assert_eq!(
        profile.manifest.unwrap().audit_path(),
        Path::new("/var/log/chameleon-map.audit")
    );
}

#[test]
fn manifest_rejects_unknown_duplicate_and_missing_keys() {
    for document in [
        manifest_with("unexpected_key=value"),
        format!("{}public_port=39000\n", valid_manifest_text()),
        manifest_without("backend_port"),
    ] {
        assert!(
            parse_manifest(document.as_bytes()).is_err(),
            "document must be rejected: {document}"
        );
    }
    let error = parse_manifest(manifest_without("bpf_pin_root").as_bytes())
        .unwrap_err()
        .to_string();
    assert!(error.contains("missing required key bpf_pin_root"), "{error}");
    let error = parse_manifest(manifest_with("unexpected_key=value").as_bytes())
        .unwrap_err()
        .to_string();
    assert!(error.contains("unknown key unexpected_key"), "{error}");
    let error = parse_manifest(format!("{}public_port=39000\n", valid_manifest_text()).as_bytes())
        .unwrap_err()
        .to_string();
    assert!(error.contains("duplicate key public_port"), "{error}");
}

#[test]
fn manifest_rejects_invalid_values() {
    let mutations = [
        "install_id=short",
        "install_id=GD-AP8-TEST-INSTALL-0001",
        "install_id=-gd-ap8-test-install-0001-",
        "bpf_name_salt=zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
        "bpf_name_salt=0123456789ABCDEF0123456789abcdef0123456789abcdef0123456789abcdef",
        "core_socket=relative/core.sock",
        "core_socket=/run/../etc/core.sock",
        "core_socket=/run/chameleon//core.sock",
        "core_socket=/run/chameleon/core.sock/",
        "scan_socket=/run/chameleon/core.sock",
        "public_port=80",
        "public_port=65536",
        "public_port=notaport",
        "backend_port=39000",
        "neutral_unit_prefix=Cham",
        "neutral_unit_prefix=ch",
        "admin_audit_path=relative/audit.log",
    ];
    for mutation in mutations {
        let document = manifest_with(mutation);
        assert!(
            parse_manifest(document.as_bytes()).is_err(),
            "value must be rejected: {mutation}"
        );
    }
    // state_dir == config_dir must be rejected.
    let document = valid_manifest_text().replace(
        "state_dir=/var/lib/chameleon/state",
        "state_dir=/etc/chameleon",
    );
    assert!(parse_manifest(document.as_bytes()).is_err());
    // Control characters and CRLF are rejected before any value is used.
    assert!(parse_manifest(b"vgt-gedefense-chameleon-v1\nfoo\x01=bar\n").is_err());
    let crlf = valid_manifest_text().replace('\n', "\r\n");
    assert!(parse_manifest(crlf.as_bytes()).is_err());
    // Schema mismatch / BOM are rejected.
    assert!(parse_manifest(b"wrong-schema\n").is_err());
    let mut bom = Vec::from("\u{feff}".as_bytes());
    bom.extend_from_slice(valid_manifest_text().as_bytes());
    assert!(parse_manifest(&bom).is_err());
    // Oversized document.
    let oversized = format!("{}{}", valid_manifest_text(), " ".repeat(17 * 1024));
    assert!(parse_manifest(oversized.as_bytes()).is_err());
}

#[test]
fn manifest_file_policy_rejects_unsafe_files() {
    let temp = TempDir::new("manifest-policy");
    let valid = valid_manifest_text();
    // Group/world writable.
    let writable = temp.file("writable.conf", valid.as_bytes(), 0o666);
    let error = ChameleonProfile::from_manifest(writable.to_str().unwrap())
        .unwrap_err()
        .to_string();
    assert!(error.contains("group/world writable"), "{error}");
    // Symlinked manifest.
    let real = temp.file("real.conf", valid.as_bytes(), 0o600);
    let link = temp.path.join("link.conf");
    std::os::unix::fs::symlink(&real, &link).expect("symlink");
    let error = ChameleonProfile::from_manifest(link.to_str().unwrap())
        .unwrap_err()
        .to_string();
    assert!(error.contains("must not be a symlink"), "{error}");
    // Relative and empty paths.
    assert!(ChameleonProfile::from_manifest("relative.conf").is_err());
    assert!(!ChameleonProfile::from_manifest("").unwrap().active());
    assert!(!ChameleonProfile::from_manifest("   ").unwrap().active());
    // Missing manifest is an error, never a silent public identity.
    assert!(ChameleonProfile::from_manifest("/nonexistent/chameleon.conf").is_err());
}

// --------------------------------------------------------------- derivation

#[test]
fn derivation_is_deterministic_same_length_and_shaped() {
    let salt = [0x5au8; 32];
    for name in [
        "gedefense_xdp",
        "gedefense_lsm_uring_override_creds",
        "FLOW_EVENTS",
        "TITAN_EXEC_EVENTS",
        "EXEC_EVENTS",
        "INGRESS_FLOW_EVENTS_EMITTED",
    ] {
        let first = derive_neutral_identifier(&salt, identifier_domain(name), name, 0, name.len());
        let second = derive_neutral_identifier(&salt, identifier_domain(name), name, 0, name.len());
        assert_eq!(first, second, "derivation must be deterministic for {name}");
        assert_eq!(first.len(), name.len(), "same length for {name}");
        assert!(
            neutral_identifier_shape_is_valid(&first),
            "invalid neutral shape {first} for {name}"
        );
    }
    // The domain separator matters: the same public string in the map and the
    // program domain must not collide.
    let map_name = derive_neutral_identifier(&salt, b"map:", "same_name", 0, 9);
    let program_name = derive_neutral_identifier(&salt, b"prog:", "same_name", 0, 9);
    assert_ne!(map_name, program_name);
    // Different counters must produce different candidates for the same input.
    let counter_zero = derive_neutral_identifier(&salt, b"map:", "FLOW_EVENTS", 0, 11);
    let counter_one = derive_neutral_identifier(&salt, b"map:", "FLOW_EVENTS", 1, 11);
    assert_ne!(counter_zero, counter_one);
}

#[test]
fn derivation_is_unique_over_a_few_thousand_names() {
    let salt = [0x11u8; 32];
    let mut names = BTreeSet::new();
    for index in 0..3000usize {
        names.insert(format!("gedefense_test_program_{index:04}"));
    }
    let plan = build_name_plan(&names, &salt).expect("plan over many names");
    assert_eq!(plan.len(), names.len());
    let mut unique = HashSet::new();
    for (public, neutral) in &plan {
        assert_eq!(public.len(), neutral.len(), "length mismatch for {public}");
        assert!(neutral_identifier_shape_is_valid(neutral), "{neutral}");
        assert!(unique.insert(neutral.clone()), "duplicate neutral {neutral}");
    }
    assert!(
        !plan
            .values()
            .any(|neutral| contains_forbidden_identifier(neutral)),
        "neutral names must never contain a GeDefense marker"
    );
}

#[test]
fn derivation_retries_when_a_candidate_contains_a_forbidden_marker() {
    let public_name = "ABC";
    let mut found = None;
    for counter in 0..500_000u64 {
        let mut salt = [0u8; 32];
        salt[..8].copy_from_slice(&counter.to_le_bytes());
        salt[8..16].copy_from_slice(&counter.rotate_left(17).to_le_bytes());
        let candidate = derive_neutral_identifier(&salt, b"map:", public_name, 0, 3);
        if contains_forbidden_identifier(&candidate) {
            found = Some(salt);
            break;
        }
    }
    let salt = found.expect("a salt with a forbidden first candidate must exist");
    let mut names = BTreeSet::new();
    names.insert(public_name.to_owned());
    let plan = build_name_plan(&names, &salt).expect("plan");
    let neutral = &plan[public_name];
    assert_eq!(neutral.len(), 3);
    assert!(!contains_forbidden_identifier(neutral), "{neutral}");
}

// ------------------------------------------------------ default-off contract

#[test]
fn default_profile_is_inactive_and_identity() {
    let profile = ChameleonProfile::default();
    assert!(!profile.active());
    assert_eq!(profile.name("FLOW_EVENTS"), "FLOW_EVENTS");
    assert_eq!(profile.name("gedefense_xdp"), "gedefense_xdp");
    // The process-wide resolvers are identity while no profile is installed.
    // (No test in this module installs one; `install_active` is only called by
    // main() at startup.)
    assert_eq!(map_name("X"), "X");
    assert_eq!(map_name("FLOW_EVENTS"), "FLOW_EVENTS");
    assert_eq!(program_name("gedefense_xdp"), "gedefense_xdp");
    // A disabled profile loads the object through the plain aya path and does
    // not produce a chameleon-specific error.
    let error = ChameleonProfile::default()
        .load_object("/nonexistent/chameleon-test-object")
        .unwrap_err()
        .to_string();
    assert!(
        !error.starts_with("chameleon"),
        "disabled profile must use the plain load path: {error}"
    );
}

#[test]
fn active_profile_resolves_through_its_plan_and_keeps_unmanaged_names() {
    let temp = TempDir::new("active-name");
    let mut profile = ChameleonProfile::default();
    profile.enabled = true;
    profile.manifest = Some(test_manifest(&temp.path.join("state"), &temp.path.join("etc")));
    let salt = profile.manifest.as_ref().unwrap().salt;
    let neutral = derive_neutral_identifier(&salt, b"map:", "FLOW_EVENTS", 0, "FLOW_EVENTS".len());
    {
        let mut plan = profile.plan.lock().unwrap();
        plan.names.insert("FLOW_EVENTS".to_owned(), neutral.clone());
    }
    assert_eq!(profile.name("FLOW_EVENTS"), neutral);
    // Names outside the managed namespace are never renamed.
    assert_eq!(profile.name("UNMANAGED_NAME"), "UNMANAGED_NAME");
    // A managed name without a plan entry still derives a shaped neutral name
    // instead of silently returning the public identity.
    let fallback = profile.name("TITAN_EXEC_STATE");
    assert_ne!(fallback, "TITAN_EXEC_STATE");
    assert_eq!(fallback.len(), "TITAN_EXEC_STATE".len());
    assert!(neutral_identifier_shape_is_valid(&fallback));
}
