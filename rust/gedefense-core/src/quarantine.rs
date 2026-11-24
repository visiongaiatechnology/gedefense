// STATUS: DIAMANT VGT SUPREME

mod crypto;
mod path_guard;
mod store;
#[cfg(test)]
mod tests;

use self::crypto::*;
use self::path_guard::*;
use self::store::*;

use std::{
    error::Error,
    fs::{self, File},
    os::{
        fd::AsRawFd,
        unix::fs::{MetadataExt, PermissionsExt},
    },
    path::PathBuf,
};

type BoxError = Box<dyn Error + Send + Sync + 'static>;

const MAX_FILE_BYTES: u64 = 256 * 1024 * 1024;

// A quarantined file is restored as data, never as a privilege boundary: the
// captured SUID (04000) and SGID (02000) bits are dropped unconditionally even
// though the identity records them, so a restore can never reinstall a setuid
// payload. The temporary restore file is created 0600 and only reaches the final
// destination after verification.
const RESTORE_MODE_MASK: u32 = 0o777;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FileIdentity {
    pub size: u64,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub device: u64,
    pub inode: u64,
    pub modified_nanos: i64,
    pub sha256: [u8; 32],
}

impl FileIdentity {
    pub fn encode(&self) -> String {
        format!(
            "v1:{}:{}:{}:{}:{}:{}:{}:{}",
            self.size,
            self.mode,
            self.uid,
            self.gid,
            self.device,
            self.inode,
            self.modified_nanos,
            hex::encode(self.sha256)
        )
    }

    pub fn parse(fields: &[&str]) -> Result<Self, BoxError> {
        if fields.len() != 8 {
            return Err("quarantine identity field count is invalid".into());
        }
        let digest = hex::decode(fields[7])?;
        if digest.len() != 32 {
            return Err("quarantine identity digest is invalid".into());
        }
        let mut sha256 = [0u8; 32];
        sha256.copy_from_slice(&digest);
        let identity = Self {
            size: fields[0].parse()?,
            mode: fields[1].parse()?,
            uid: fields[2].parse()?,
            gid: fields[3].parse()?,
            device: fields[4].parse()?,
            inode: fields[5].parse()?,
            modified_nanos: fields[6].parse()?,
            sha256,
        };
        if identity.size > MAX_FILE_BYTES || identity.mode > 0o7777 {
            return Err("quarantine identity exceeds typed bounds".into());
        }
        Ok(identity)
    }

    /// Decodes the `v1:`-prefixed identity returned by [`QuarantineBroker`].
    /// Used by the M1.1 on-write sensor to compare the scanned SHA-256 with the
    /// identity the broker will capture; the version prefix is mandatory so a
    /// bare field list is never silently accepted as an identity.
    pub fn decode(encoded: &str) -> Result<Self, BoxError> {
        let fields: Vec<&str> = encoded
            .strip_prefix("v1:")
            .ok_or("quarantine identity version is invalid")?
            .split(':')
            .collect();
        Self::parse(&fields)
    }

    fn content_matches(&self, other: &Self) -> bool {
        self.size == other.size
            && self.mode == other.mode
            && self.uid == other.uid
            && self.gid == other.gid
            && self.sha256 == other.sha256
    }
}

pub struct QuarantineBroker {
    object_dir: PathBuf,
    storage_key: [u8; 32],
}

impl QuarantineBroker {
    pub fn new(object_dir: &str, storage_key: &[u8]) -> Result<Self, BoxError> {
        if storage_key.len() != 32 {
            return Err("quarantine storage key must contain exactly 32 bytes".into());
        }
        let object_dir = PathBuf::from(object_dir);
        if !object_dir.is_absolute() {
            return Err("quarantine object directory must be absolute".into());
        }
        fs::create_dir_all(&object_dir)?;
        let metadata = fs::symlink_metadata(&object_dir)?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err("quarantine object directory must be a non-symlink directory".into());
        }
        fs::set_permissions(&object_dir, fs::Permissions::from_mode(0o700))?;
        let mut key = [0u8; 32];
        key.copy_from_slice(storage_key);
        Ok(Self {
            object_dir,
            storage_key: key,
        })
    }

    pub fn inspect_token(&self, encoded_path: &str) -> Result<String, BoxError> {
        let path = decode_path(encoded_path)?;
        let (parent, basename) = open_parent_and_name(&path)?;
        let identity = inspect_at(parent.as_raw_fd(), &basename)?;
        Ok(identity.encode())
    }

    pub fn quarantine_token(
        &self,
        encoded_path: &str,
        object_id: &str,
        expected: &FileIdentity,
    ) -> Result<String, BoxError> {
        validate_object_id(object_id)?;
        let path = decode_path(encoded_path)?;
        let (parent, basename) = open_parent_and_name(&path)?;
        let staging_name = staging_name(object_id)?;
        match rename_noreplace(
            parent.as_raw_fd(),
            &basename,
            parent.as_raw_fd(),
            &staging_name,
        ) {
            Ok(()) => {
                sync_fd(parent.as_raw_fd())?;
                self.finish_staged_quarantine(
                    parent.as_raw_fd(),
                    &basename,
                    &staging_name,
                    object_id,
                    expected,
                )
            }
            Err(error) => {
                // F-HOTFIX-2: the service runs with ProtectSystem=strict, so an
                // in-place rename under /etc, /usr, /home or /var fails with EROFS
                // even though the source is readable - quarantine was therefore
                // unusable exactly where it matters most. Fall back to a verified
                // copy into the writable vault. The source is removed when the
                // sandbox permits it and reported as copy-only otherwise.
                if error
                    .raw_os_error()
                    .map(is_read_only_backing_errno)
                    .unwrap_or(false)
                {
                    return self.copy_quarantine(parent.as_raw_fd(), &basename, object_id, expected);
                }
                Err(error.into())
            }
        }
    }

    /// M1.1 on-write capture using the kernel-opened fanotify descriptor so
    /// non-world-readable files (e.g. `0600`/`0660` under CIS `UMASK 027`) in
    /// traversable drop roots like `/tmp` are quarantined without regaining
    /// `CAP_DAC_OVERRIDE` or `CAP_DAC_READ_SEARCH`.
    pub fn quarantine_open_file(
        &self,
        encoded_path: &str,
        source: &mut File,
        object_id: &str,
        expected_sha256: [u8; 32],
        expected_size: u64,
    ) -> Result<String, BoxError> {
        validate_object_id(object_id)?;
        let fd_meta = source.metadata()?;
        if !fd_meta.is_file() || fd_meta.len() > MAX_FILE_BYTES || fd_meta.len() != expected_size {
            return Err("quarantine source identity changed before capture".into());
        }
        let expected = file_identity_from_metadata(&fd_meta, expected_sha256)?;
        let path = decode_path(encoded_path)?;
        let (parent, basename) = open_parent_and_name(&path)?;
        let Some(before) = stat_at(parent.as_raw_fd(), &basename)? else {
            return Err(std::io::Error::from_raw_os_error(libc::ENOENT).into());
        };
        if !stat_matches_identity(&before, &expected) {
            return Err("quarantine source identity changed before capture".into());
        }
        let staging_name = staging_name(object_id)?;
        rename_noreplace(
            parent.as_raw_fd(),
            &basename,
            parent.as_raw_fd(),
            &staging_name,
        )?;
        sync_fd(parent.as_raw_fd())?;

        let mut object_committed = false;
        let result = (|| {
            let Some(staged) = stat_at(parent.as_raw_fd(), &staging_name)? else {
                return Err("quarantine staged file disappeared".into());
            };
            if !stat_matches_identity(&staged, &expected) {
                return Err("quarantine source identity changed after atomic capture".into());
            }
            self.encrypt_open_source(source, object_id, &expected)?;
            object_committed = true;
            unlink_at(parent.as_raw_fd(), &staging_name)?;
            sync_fd(parent.as_raw_fd())?;
            Ok(expected.encode())
        })();

        if result.is_err() {
            if object_committed {
                let _ = self.remove_object(object_id);
            }
            if matches!(stat_at(parent.as_raw_fd(), &staging_name), Ok(Some(_))) {
                let _ = rename_noreplace(parent.as_raw_fd(), &staging_name, parent.as_raw_fd(), &basename);
                let _ = sync_fd(parent.as_raw_fd());
            }
        }
        result
    }

    /// Captures an already-open malicious descriptor into the encrypted vault
    /// AFTER the caller has kernel-locked `(dev, ino)` in eBPF LSM (used strictly
    /// when a non-root `0755` drop directory refuses unlinking without `CAP_DAC_OVERRIDE`).
    pub fn capture_open_fd_only(
        &self,
        encoded_path: &str,
        source: &mut File,
        object_id: &str,
        expected_sha256: [u8; 32],
        expected_size: u64,
    ) -> Result<String, BoxError> {
        validate_object_id(object_id)?;
        let _ = decode_path(encoded_path)?;
        let fd_meta = source.metadata()?;
        if !fd_meta.is_file() || fd_meta.len() > MAX_FILE_BYTES || fd_meta.len() != expected_size {
            return Err("quarantine source identity changed before capture".into());
        }
        let expected = file_identity_from_metadata(&fd_meta, expected_sha256)?;
        self.encrypt_open_source(source, object_id, &expected)?;
        Ok(expected.encode())
    }

    pub fn verify_object(
        &self,
        object_id: &str,
        expected: &FileIdentity,
    ) -> Result<String, BoxError> {
        validate_object_id(object_id)?;
        let mut sink = std::io::sink();
        let restored = self.decrypt_object(object_id, expected, &mut sink)?;
        if restored != expected.size {
            return Err("quarantine object size verification failed".into());
        }
        Ok("verified".to_owned())
    }

    pub fn restore_token(
        &self,
        encoded_path: &str,
        object_id: &str,
        expected: &FileIdentity,
    ) -> Result<String, BoxError> {
        validate_object_id(object_id)?;
        let path = decode_path(encoded_path)?;
        let (parent, basename) = open_parent_and_name(&path)?;
        let staging_name = staging_name(object_id)?;

        if path_exists_at(parent.as_raw_fd(), &basename)? {
            let current = inspect_at(parent.as_raw_fd(), &basename)?;
            if !expected.content_matches(&current) {
                return Err("restore destination already exists with different identity".into());
            }
            if path_exists_at(parent.as_raw_fd(), &staging_name)? {
                let staged = inspect_at(parent.as_raw_fd(), &staging_name)?;
                if staged != *expected {
                    return Err("quarantine staging object identity mismatch".into());
                }
                unlink_at(parent.as_raw_fd(), &staging_name)?;
            }
            self.remove_object_if_present(object_id)?;
            sync_fd(parent.as_raw_fd())?;
            return Ok("restored".to_owned());
        }

        if path_exists_at(parent.as_raw_fd(), &staging_name)? {
            let staged = inspect_at(parent.as_raw_fd(), &staging_name)?;
            if staged != *expected {
                return Err("quarantine staging object identity mismatch".into());
            }
            rename_noreplace(
                parent.as_raw_fd(),
                &staging_name,
                parent.as_raw_fd(),
                &basename,
            )?;
            self.remove_object_if_present(object_id)?;
            sync_fd(parent.as_raw_fd())?;
            return Ok("restored".to_owned());
        }

        let temporary_name = temporary_restore_name(object_id)?;
        // F-15: the destination parent was already validated and opened with
        // openat2(RESOLVE_NO_SYMLINKS). The restore temporary file is therefore
        // created, renamed and (on the error path) unlinked strictly relative to
        // that descriptor - never by resolving the original path string again.
        let restore_result = (|| {
            {
                let mut output = create_restore_file_at(parent.as_raw_fd(), &temporary_name)?;
                let restored = self.decrypt_object(object_id, expected, &mut output)?;
                if restored != expected.size {
                    return Err("restored quarantine size mismatch".into());
                }
                let ownership = unsafe {
                    libc::fchown(
                        output.as_raw_fd(),
                        expected.uid as libc::uid_t,
                        expected.gid as libc::gid_t,
                    )
                };
                if ownership != 0 {
                    return Err(std::io::Error::last_os_error().into());
                }
                let restore_mode = restored_mode(expected.mode);
                let permissions =
                    unsafe { libc::fchmod(output.as_raw_fd(), restore_mode as libc::mode_t) };
                if permissions != 0 {
                    return Err(std::io::Error::last_os_error().into());
                }
                output.sync_all()?;
            }
            rename_noreplace(
                parent.as_raw_fd(),
                &temporary_name,
                parent.as_raw_fd(),
                &basename,
            )?;
            sync_fd(parent.as_raw_fd())?;
            self.remove_object(object_id)?;
            Ok("restored".to_owned())
        })();
        if restore_result.is_err() {
            let _ = unlink_at(parent.as_raw_fd(), &temporary_name);
        }
        restore_result
    }

    /// V6.3.0 AP-7: `QUARANTINE_PRUNE <object_id> <identity>` removes a
    /// verified false-positive vault object.
    ///
    /// The call is deliberately narrower than [`Self::restore_token`]: it takes
    /// no host path, so it can never resolve, recreate or delete a host file.
    /// The only mutation is the removal of the derived vault object
    /// `<object_dir>/<object_id>.qv`.
    ///
    /// Verification is two-stage and reuses the existing helpers:
    /// 1. the bounded vault header is decoded and compared with the caller's
    ///    identity in constant time ([`constant_time_identity_eq`]); a mismatch
    ///    is refused before any mutation;
    /// 2. [`Self::verify_object`] decrypts the object and checks the full
    ///    ciphertext digest against the identity, so a tampered or truncated
    ///    vault object can never be pruned as if it were the approved one.
    ///
    /// Explicit "not currently restored" check: a successful restore removes
    /// the vault object at its commit point in every restore branch
    /// (`remove_object`), therefore a present, verifiable vault object proves
    /// the object has not been restored. A missing object means it was already
    /// restored or already pruned; prune refuses instead of guessing so a
    /// retried or replayed IPC call cannot silently report success twice.
    pub fn prune_token(&self, object_id: &str, expected: &FileIdentity) -> Result<String, BoxError> {
        validate_object_id(object_id)?;
        let path = self.object_path(object_id)?;
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Err(
                    "quarantine object is not present in the vault (already pruned or restored)"
                        .into(),
                );
            }
            Err(error) => return Err(error.into()),
        };
        // The object path is derived from the validated object id, but a
        // symlink planted at that name would still redirect the removal (and
        // the verification read). Refuse anything that is not the expected
        // regular vault file.
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err("quarantine object must be a regular non-symlink file".into());
        }
        self.verify_prune_identity(object_id, expected)?;
        // Only the vault object is removed; no host path is ever decoded here.
        self.remove_object(object_id)?;
        Ok("pruned".to_owned())
    }
}

impl Drop for QuarantineBroker {
    fn drop(&mut self) {
        self.storage_key.fill(0);
    }
}

// FIND-035: a restore must never reproduce setuid/setgid (or sticky) bits from
// the stored identity. Only the ordinary permission bits are restored.
fn restored_mode(mode: u32) -> u32 {
    mode & RESTORE_MODE_MASK
}

fn file_identity_from_metadata(meta: &fs::Metadata, sha256: [u8; 32]) -> Result<FileIdentity, BoxError> {
    Ok(FileIdentity {
        size: meta.len(),
        mode: meta.mode() & 0o7777,
        uid: meta.uid(),
        gid: meta.gid(),
        device: meta.dev(),
        inode: meta.ino(),
        modified_nanos: meta
            .mtime()
            .checked_mul(1_000_000_000)
            .and_then(|seconds| seconds.checked_add(meta.mtime_nsec()))
            .ok_or("quarantine modification time overflow")?,
        sha256,
    })
}

fn is_read_only_backing_errno(errno: i32) -> bool {
    matches!(
        errno,
        libc::EROFS | libc::EXDEV | libc::EACCES | libc::EPERM | libc::ENOSYS | libc::EINVAL
    )
}

#[cfg(test)]
fn is_read_only_backing_error(error: &std::io::Error) -> bool {
    error
        .raw_os_error()
        .map(is_read_only_backing_errno)
        .unwrap_or(false)
}
