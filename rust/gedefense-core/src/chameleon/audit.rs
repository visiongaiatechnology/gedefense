//! Admin-readable `public=neutral` audit document writer (root-owned,
//! 0600, atomically replaced, bounded; the salt itself is never written).

use super::*;
use std::fs::{self, OpenOptions};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

// ------------------------------------------------------------------- audit

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::Digest as _;
    let mut hasher = sha2::Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

/// Writes the admin-readable `public=neutral` mapping. The file is root-owned
/// 0600, atomically replaced, bounded, and contains no secret. The salt itself
/// is never written; only its SHA-256 fingerprint and a mapping digest are.
pub(super) fn write_audit_mapping(
    manifest: &ChameleonManifest,
    patched: &PatchedObject,
) -> Result<(), BoxError> {
    let path = manifest.audit_path();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| format!("chameleon audit directory cannot be created: {error}"))?;
        let metadata = fs::symlink_metadata(parent)
            .map_err(|error| format!("chameleon audit directory is unavailable: {error}"))?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err("chameleon audit directory must be a real directory".into());
        }
    }
    let mut sorted: Vec<(&String, &String)> = patched.plan.iter().collect();
    sorted.sort_by(|left, right| left.0.cmp(right.0));
    let mut mapping_lines = String::new();
    for (public, neutral) in &sorted {
        mapping_lines.push_str(public);
        mapping_lines.push('=');
        mapping_lines.push_str(neutral);
        mapping_lines.push('\n');
    }
    let salt_fingerprint = sha256_hex(&manifest.salt);
    let mapping_digest = sha256_hex(mapping_lines.as_bytes());
    let mut document = String::with_capacity(mapping_lines.len() + 512);
    document.push_str("# ");
    document.push_str(CHAMELEON_AUDIT_SCHEMA);
    document.push('\n');
    document.push_str("# install_id=");
    document.push_str(&manifest.install_id);
    document.push('\n');
    document.push_str("# salt_fingerprint=");
    document.push_str(&salt_fingerprint);
    document.push('\n');
    document.push_str("# mapping_sha256=");
    document.push_str(&mapping_digest);
    document.push('\n');
    document.push_str("# public=neutral\n");
    document.push_str(&mapping_lines);
    if document.len() > CHAMELEON_AUDIT_MAX_BYTES {
        return Err("chameleon audit mapping exceeds the size bound".into());
    }
    let file_name = path
        .file_name()
        .ok_or("chameleon audit path has no file name")?;
    let temp_name = format!(".{}.{}.tmp", file_name.to_string_lossy(), std::process::id());
    let temp_path = path.with_file_name(temp_name);
    let write_result = (|| -> Result<(), BoxError> {
        use std::io::Write as _;
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(&temp_path)
            .map_err(|error| format!("chameleon audit file cannot be created: {error}"))?;
        file.write_all(document.as_bytes())
            .map_err(|error| format!("chameleon audit file cannot be written: {error}"))?;
        file.sync_all()
            .map_err(|error| format!("chameleon audit file cannot be synced: {error}"))?;
        fs::set_permissions(&temp_path, fs::Permissions::from_mode(0o600))?;
        fs::rename(&temp_path, &path)
            .map_err(|error| format!("chameleon audit file cannot be published: {error}"))?;
        Ok(())
    })();
    if write_result.is_err() {
        let _ = fs::remove_file(&temp_path);
    }
    write_result?;
    let metadata = fs::symlink_metadata(&path)?;
    if !metadata.is_file() || metadata.permissions().mode() & 0o077 != 0 {
        return Err("chameleon audit mapping must stay root-owned and 0600".into());
    }
    Ok(())
}
