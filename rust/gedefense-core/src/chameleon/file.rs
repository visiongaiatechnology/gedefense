//! Bounded, symlink-refusing, owner/mode-checked file reader for the
//! manifest and the shipped eBPF object.

use super::*;
use std::{
    fs::{self, OpenOptions},
    io::Read,
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
};

// ---------------------------------------------------------------- file access

/// Reads a bounded regular file without following a final symlink and enforces
/// the documented owner/mode policy: the reader must be root or the file owner,
/// and the file may not be group/world writable.
pub(super) fn read_plain_file(path: &Path, max_bytes: usize, label: &str) -> Result<Vec<u8>, BoxError> {
    let metadata =
        fs::symlink_metadata(path).map_err(|error| format!("{label} is unavailable: {error}"))?;
    if metadata.file_type().is_symlink() {
        return Err(format!("{label} must not be a symlink").into());
    }
    if !metadata.is_file() {
        return Err(format!("{label} must be a regular file").into());
    }
    if metadata.len() > max_bytes as u64 {
        return Err(format!("{label} exceeds the {max_bytes} byte bound").into());
    }
    if metadata.permissions().mode() & 0o022 != 0 {
        return Err(format!("{label} must not be group/world writable").into());
    }
    let euid = unsafe { libc::geteuid() };
    // The installer provisions the manifest as root:root or root:<service
    // group>; the privileged core (root) and the unprivileged control plane
    // (reading a root-owned file through its group) must both accept it. A file
    // owned by some other account is never accepted.
    if metadata.uid() != 0 && metadata.uid() != euid {
        return Err(format!("{label} must belong to root or the effective user").into());
    }
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .map_err(|error| format!("{label} cannot be opened safely: {error}"))?;
    let opened = file
        .metadata()
        .map_err(|error| format!("{label} metadata is unavailable: {error}"))?;
    if opened.len() > max_bytes as u64 || !opened.is_file() {
        return Err(format!("{label} changed while it was opened").into());
    }
    let mut bytes = Vec::new();
    file.by_ref()
        .take(max_bytes as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("{label} cannot be read: {error}"))?;
    if bytes.len() > max_bytes {
        return Err(format!("{label} exceeds the {max_bytes} byte bound").into());
    }
    Ok(bytes)
}
