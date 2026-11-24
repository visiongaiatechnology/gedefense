//! Strict, bounded, rejecting parser/validator for the signed Chameleon
//! installation manifest (format: `vgt-gedefense-chameleon-v1`).

use super::*;
use std::path::Component;

/// Manifest keys every Chameleon installation must provide.
const REQUIRED_MANIFEST_KEYS: [&str; 10] = [
    "install_id",
    "bpf_name_salt",
    "core_socket",
    "scan_socket",
    "bpf_pin_root",
    "state_dir",
    "config_dir",
    "public_port",
    "backend_port",
    "neutral_unit_prefix",
];
/// Extra manifest key the parser accepts.
const OPTIONAL_MANIFEST_KEYS: [&str; 1] = ["admin_audit_path"];

// ----------------------------------------------------------------- manifest

/// Validates an absolute, normalized path as used by the manifest.
fn validate_absolute_path(key: &str, value: &str) -> Result<(), BoxError> {
    if value.is_empty() || value.len() > 200 {
        return Err(format!("chameleon manifest {key} has an invalid length").into());
    }
    if value.chars().any(char::is_control) {
        return Err(format!("chameleon manifest {key} contains control characters").into());
    }
    let path = Path::new(value);
    if !path.is_absolute() {
        return Err(format!("chameleon manifest {key} must be an absolute path").into());
    }
    if path == Path::new("/") {
        return Err(format!("chameleon manifest {key} must not be the filesystem root").into());
    }
    let mut components = path.components();
    if !matches!(components.next(), Some(Component::RootDir)) {
        return Err(format!("chameleon manifest {key} must be rooted").into());
    }
    if components.any(|component| !matches!(component, Component::Normal(_))) {
        return Err(format!(
            "chameleon manifest {key} must not contain '.', '..' or empty components"
        )
        .into());
    }
    // Path::components collapses repeated separators; the raw value must not
    // carry them, otherwise installer and core could disagree about the path.
    if value.contains("//") {
        return Err(format!("chameleon manifest {key} must not contain '//'").into());
    }
    if value.ends_with('/') {
        return Err(format!("chameleon manifest {key} must not end with '/'").into());
    }
    Ok(())
}

fn validate_install_id(value: &str) -> Result<(), BoxError> {
    let bytes = value.as_bytes();
    if bytes.len() < 16 || bytes.len() > 64 {
        return Err("chameleon manifest install_id must be 16..=64 characters".into());
    }
    if !bytes
        .iter()
        .all(|byte| matches!(byte, b'a'..=b'z' | b'0'..=b'9' | b'-'))
    {
        return Err("chameleon manifest install_id must match [a-z0-9-]".into());
    }
    if bytes.first() == Some(&b'-') || bytes.last() == Some(&b'-') {
        return Err("chameleon manifest install_id must not start or end with '-'".into());
    }
    Ok(())
}

fn validate_salt(value: &str) -> Result<[u8; 32], BoxError> {
    if value.len() != 64 {
        return Err("chameleon manifest bpf_name_salt must be exactly 64 hex characters".into());
    }
    if !value
        .bytes()
        .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err("chameleon manifest bpf_name_salt must be lowercase hex".into());
    }
    let mut salt = [0u8; 32];
    hex::decode_to_slice(value, &mut salt)
        .map_err(|_| "chameleon manifest bpf_name_salt is not valid hex")?;
    Ok(salt)
}

fn validate_port(key: &str, value: &str) -> Result<u16, BoxError> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(format!("chameleon manifest {key} must be a decimal port").into());
    }
    let port: u32 = value
        .parse()
        .map_err(|_| format!("chameleon manifest {key} is out of range"))?;
    if !(1024..=65535).contains(&port) {
        return Err(format!("chameleon manifest {key} must be 1024..=65535").into());
    }
    Ok(port as u16)
}

fn validate_unit_prefix(value: &str) -> Result<(), BoxError> {
    let bytes = value.as_bytes();
    if !(3..=21).contains(&bytes.len()) {
        return Err("chameleon manifest neutral_unit_prefix must be 3..=21 characters".into());
    }
    if !bytes[0].is_ascii_lowercase() {
        return Err("chameleon manifest neutral_unit_prefix must start with a letter".into());
    }
    if !bytes
        .iter()
        .all(|byte| matches!(byte, b'a'..=b'z' | b'0'..=b'9' | b'-'))
    {
        return Err("chameleon manifest neutral_unit_prefix must match [a-z0-9-]".into());
    }
    Ok(())
}

/// Strict, bounded, rejecting manifest parser. Every unknown/duplicate/missing
/// key, control character or invalid value is an error.
pub(super) fn parse_manifest(bytes: &[u8]) -> Result<ChameleonManifest, BoxError> {
    if bytes.is_empty() {
        return Err("chameleon manifest is empty".into());
    }
    if bytes.len() > CHAMELEON_MANIFEST_MAX_BYTES {
        return Err("chameleon manifest exceeds the size bound".into());
    }
    let text = std::str::from_utf8(bytes).map_err(|_| "chameleon manifest is not UTF-8")?;
    if text.starts_with('\u{feff}') {
        return Err("chameleon manifest must not start with a BOM".into());
    }
    if text.contains('\r') {
        return Err("chameleon manifest must use LF line endings".into());
    }
    if text
        .chars()
        .any(|character| character.is_control() && character != '\n')
    {
        return Err("chameleon manifest contains control characters".into());
    }
    let mut lines = text.split('\n');
    let schema = lines
        .next()
        .ok_or("chameleon manifest is missing the schema line")?;
    if schema != CHAMELEON_MANIFEST_SCHEMA {
        return Err(format!(
            "chameleon manifest schema mismatch (expected {CHAMELEON_MANIFEST_SCHEMA})"
        )
        .into());
    }
    let mut values: HashMap<String, String> = HashMap::new();
    let mut line_number = 1usize;
    for line in lines {
        line_number += 1;
        if line.is_empty() {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            return Err(format!("chameleon manifest line {line_number}: expected key=value").into());
        };
        if value.contains('=') {
            return Err(
                format!("chameleon manifest line {line_number}: unexpected second '='").into(),
            );
        }
        if key.is_empty()
            || value.is_empty()
            || !key
                .bytes()
                .all(|byte| matches!(byte, b'a'..=b'z' | b'0'..=b'9' | b'_'))
        {
            return Err(
                format!("chameleon manifest line {line_number}: invalid key or value").into(),
            );
        }
        let known = REQUIRED_MANIFEST_KEYS.contains(&key) || OPTIONAL_MANIFEST_KEYS.contains(&key);
        if !known {
            return Err(format!("chameleon manifest contains unknown key {key}").into());
        }
        if values.insert(key.to_owned(), value.to_owned()).is_some() {
            return Err(format!("chameleon manifest contains duplicate key {key}").into());
        }
    }
    for key in REQUIRED_MANIFEST_KEYS {
        if !values.contains_key(key) {
            return Err(format!("chameleon manifest is missing required key {key}").into());
        }
    }
    let required = |key: &str| -> Result<String, BoxError> {
        values
            .get(key)
            .cloned()
            .ok_or_else(|| format!("chameleon manifest is missing required key {key}").into())
    };
    let install_id = required("install_id")?;
    validate_install_id(&install_id)?;
    let salt = validate_salt(&required("bpf_name_salt")?)?;
    let core_socket = required("core_socket")?;
    validate_absolute_path("core_socket", &core_socket)?;
    let scan_socket = required("scan_socket")?;
    validate_absolute_path("scan_socket", &scan_socket)?;
    let bpf_pin_root = required("bpf_pin_root")?;
    validate_absolute_path("bpf_pin_root", &bpf_pin_root)?;
    let state_dir = required("state_dir")?;
    validate_absolute_path("state_dir", &state_dir)?;
    let config_dir = required("config_dir")?;
    validate_absolute_path("config_dir", &config_dir)?;
    if core_socket == scan_socket {
        return Err("chameleon manifest core_socket and scan_socket must differ".into());
    }
    if state_dir == config_dir {
        return Err("chameleon manifest state_dir and config_dir must differ".into());
    }
    let public_port = validate_port("public_port", &required("public_port")?)?;
    let backend_port = validate_port("backend_port", &required("backend_port")?)?;
    if public_port == backend_port {
        return Err("chameleon manifest public_port and backend_port must differ".into());
    }
    let neutral_unit_prefix = required("neutral_unit_prefix")?;
    validate_unit_prefix(&neutral_unit_prefix)?;
    let admin_audit_path = match values.get("admin_audit_path") {
        Some(path) => {
            validate_absolute_path("admin_audit_path", path)?;
            Some(path.clone())
        }
        None => None,
    };
    Ok(ChameleonManifest {
        install_id,
        salt,
        core_socket,
        scan_socket,
        bpf_pin_root,
        state_dir,
        config_dir,
        public_port,
        backend_port,
        neutral_unit_prefix,
        admin_audit_path,
    })
}
