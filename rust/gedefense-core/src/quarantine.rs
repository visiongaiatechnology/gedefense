// STATUS: DIAMANT VGT SUPREME
use aes_gcm::{
    aead::{AeadInPlace, KeyInit},
    Aes256Gcm, Nonce,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use std::{
    error::Error,
    ffi::{CStr, CString, OsStr},
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd, RawFd},
        unix::{
            ffi::OsStrExt,
            fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
        },
    },
    path::{Path, PathBuf},
};

type BoxError = Box<dyn Error + Send + Sync + 'static>;
type HmacSha256 = Hmac<Sha256>;

const MAGIC: &[u8; 8] = b"VGTQV1\0\0";
const HEADER_BYTES: usize = 92;
const CHUNK_BYTES: usize = 1024 * 1024;
const MAX_FILE_BYTES: u64 = 256 * 1024 * 1024;
const RESOLVE_NO_MAGICLINKS: u64 = 0x02;
const RESOLVE_NO_SYMLINKS: u64 = 0x04;
const RENAME_NOREPLACE: u32 = 1;
// A quarantined file is restored as data, never as a privilege boundary: the
// captured SUID (04000) and SGID (02000) bits are dropped unconditionally even
// though the identity records them, so a restore can never reinstall a setuid
// payload. The temporary restore file is created 0600 and only reaches the final
// destination after verification.
const RESTORE_MODE_MASK: u32 = 0o777;

#[repr(C)]
struct OpenHow {
    flags: u64,
    mode: u64,
    resolve: u64,
}

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

    fn finish_staged_quarantine(
        &self,
        parent_fd: RawFd,
        basename: &CStr,
        staging_name: &CStr,
        object_id: &str,
        expected: &FileIdentity,
    ) -> Result<String, BoxError> {
        let mut object_committed = false;
        let result = (|| {
            let staged = inspect_at(parent_fd, staging_name)?;
            if &staged != expected {
                return Err("quarantine source identity changed after atomic capture".into());
            }
            self.encrypt_staged(parent_fd, staging_name, object_id, expected)?;
            object_committed = true;
            unlink_at(parent_fd, staging_name)?;
            sync_fd(parent_fd)?;
            Ok(expected.encode())
        })();

        if result.is_err() {
            if object_committed {
                let _ = self.remove_object(object_id);
            }
            if path_exists_at(parent_fd, staging_name)? {
                let _ = rename_noreplace(parent_fd, staging_name, parent_fd, basename);
                let _ = sync_fd(parent_fd);
            }
        }
        result
    }

    fn copy_quarantine(
        &self,
        parent_fd: RawFd,
        basename: &CStr,
        object_id: &str,
        expected: &FileIdentity,
    ) -> Result<String, BoxError> {
        let source_fd = open_regular_at(parent_fd, basename)?;
        let mut source = File::from(source_fd);
        let object_dir = File::open(&self.object_dir)?;
        let temporary_name = CString::new(format!(".{object_id}.copy.tmp"))?;
        let mut output = create_restore_file_at(object_dir.as_raw_fd(), &temporary_name)?;
        let result = (|| {
            let mut digest = Sha256::new();
            let mut remaining = expected.size;
            let mut buffer = vec![0u8; 64 * 1024];
            while remaining > 0 {
                let wanted = usize::try_from(remaining.min(buffer.len() as u64))?;
                let count = source.read(&mut buffer[..wanted])?;
                if count == 0 {
                    return Err("quarantine source ended before the captured size".into());
                }
                digest.update(&buffer[..count]);
                output.write_all(&buffer[..count])?;
                remaining -= count as u64;
            }
            let mut trailing = [0u8; 1];
            if source.read(&mut trailing)? != 0 {
                return Err("quarantine source grew during copy".into());
            }
            if digest.finalize().as_slice() != expected.sha256 {
                return Err("quarantine source changed during copy".into());
            }
            output.sync_all()?;
            drop(output);
            self.encrypt_staged(object_dir.as_raw_fd(), &temporary_name, object_id, expected)?;
            // FIND-035: the plaintext copy inside the vault must be gone before
            // the transaction may report success; a silent unlink failure would
            // leave an unmanaged cleartext duplicate behind.
            unlink_at(object_dir.as_raw_fd(), &temporary_name)?;
            let _ = sync_directory(&self.object_dir);
            // FIND-035: the encrypted vault object is only a quarantine when the
            // source is verifiably gone. The previous code logged an unlink
            // failure and still answered Ok, so the control plane believed the
            // malware had been removed while it still sat in place. Any failure
            // here aborts and rolls the vault object back.
            remove_source_after_verified_copy(parent_fd, basename)?;
            Ok(expected.encode())
        })();
        if result.is_err() {
            let _ = unlink_at(object_dir.as_raw_fd(), &temporary_name);
            let _ = self.remove_object_if_present(object_id);
        }
        result
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

    fn encrypt_staged(
        &self,
        parent_fd: RawFd,
        staging_name: &CStr,
        object_id: &str,
        expected: &FileIdentity,
    ) -> Result<(), BoxError> {
        let source_fd = open_regular_at(parent_fd, staging_name)?;
        let mut source = File::from(source_fd);
        self.encrypt_open_source(&mut source, object_id, expected)
    }

    fn encrypt_open_source(
        &self,
        source: &mut File,
        object_id: &str,
        expected: &FileIdentity,
    ) -> Result<(), BoxError> {
        source.seek(SeekFrom::Start(0))?;
        let temporary_path = self.object_dir.join(format!(".{object_id}.tmp"));
        let mut output = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(&temporary_path)?;
        let result = (|| {
            let nonce_prefix = random_nonce_prefix()?;
            let header = encode_header(expected, nonce_prefix);
            output.write_all(&header)?;
            let mut key = self.object_key(object_id)?;
            let encryption_result = (|| {
                let cipher = Aes256Gcm::new_from_slice(&key)
                    .map_err(|_| "quarantine cipher initialization failed")?;
                let mut remaining = expected.size;
                let mut index = 0u32;
                let mut digest = Sha256::new();
                loop {
                    let length = usize::try_from(remaining.min(CHUNK_BYTES as u64))?;
                    let mut chunk = vec![0u8; length];
                    if length > 0 {
                        source.read_exact(&mut chunk)?;
                        digest.update(&chunk);
                    }
                    let aad = chunk_aad(&header, index, length as u32);
                    let nonce_bytes = chunk_nonce(nonce_prefix, index);
                    let tag = cipher
                        .encrypt_in_place_detached(
                            Nonce::from_slice(&nonce_bytes),
                            &aad,
                            &mut chunk,
                        )
                        .map_err(|_| "quarantine chunk encryption failed")?;
                    output.write_all(&(length as u32).to_le_bytes())?;
                    output.write_all(&chunk)?;
                    output.write_all(tag.as_slice())?;
                    remaining = remaining.saturating_sub(length as u64);
                    index = index
                        .checked_add(1)
                        .ok_or("quarantine chunk counter exhausted")?;
                    if remaining == 0 {
                        break;
                    }
                }
                if digest.finalize().as_slice() != expected.sha256 {
                    return Err("quarantine source changed during encryption".into());
                }
                let mut extra = [0u8; 1];
                if source.read(&mut extra)? != 0 {
                    return Err("quarantine source grew during encryption".into());
                }
                Ok::<(), BoxError>(())
            })();
            key.fill(0);
            encryption_result?;
            output.sync_all()?;
            drop(output);
            let directory = File::open(&self.object_dir)?;
            let temporary_name = CString::new(format!(".{object_id}.tmp"))?;
            let object_name = CString::new(format!("{object_id}.qv"))?;
            rename_noreplace(
                directory.as_raw_fd(),
                &temporary_name,
                directory.as_raw_fd(),
                &object_name,
            )?;
            sync_directory(&self.object_dir)?;
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temporary_path);
        }
        result
    }

    fn decrypt_object<W: Write>(
        &self,
        object_id: &str,
        expected: &FileIdentity,
        output: &mut W,
    ) -> Result<u64, BoxError> {
        let path = self.object_path(object_id)?;
        let metadata = fs::symlink_metadata(&path)?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err("quarantine object must be a regular non-symlink file".into());
        }
        if metadata.len() > MAX_FILE_BYTES + (MAX_FILE_BYTES / CHUNK_BYTES as u64 + 1) * 24 + 4096 {
            return Err("quarantine object exceeds encrypted size boundary".into());
        }
        let mut input = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(&path)?;
        let mut header = [0u8; HEADER_BYTES];
        input.read_exact(&mut header)?;
        let (stored, nonce_prefix) = decode_header(&header)?;
        if expected != &stored {
            return Err("quarantine object header binding mismatch".into());
        }
        let mut key = self.object_key(object_id)?;
        let decryption_result = (|| {
            let cipher = Aes256Gcm::new_from_slice(&key)
                .map_err(|_| "quarantine cipher initialization failed")?;
            let mut remaining = stored.size;
            let mut index = 0u32;
            let mut digest = Sha256::new();
            loop {
                let mut length_bytes = [0u8; 4];
                input.read_exact(&mut length_bytes)?;
                let length = u32::from_le_bytes(length_bytes) as usize;
                let expected_length = usize::try_from(remaining.min(CHUNK_BYTES as u64))?;
                if length != expected_length {
                    return Err("quarantine chunk length mismatch".into());
                }
                let mut chunk = vec![0u8; length];
                input.read_exact(&mut chunk)?;
                let mut tag = [0u8; 16];
                input.read_exact(&mut tag)?;
                let aad = chunk_aad(&header, index, length as u32);
                let nonce_bytes = chunk_nonce(nonce_prefix, index);
                cipher
                    .decrypt_in_place_detached(
                        Nonce::from_slice(&nonce_bytes),
                        &aad,
                        &mut chunk,
                        aes_gcm::Tag::from_slice(&tag),
                    )
                    .map_err(|_| "quarantine chunk authentication failed")?;
                output.write_all(&chunk)?;
                digest.update(&chunk);
                remaining = remaining.saturating_sub(length as u64);
                index = index
                    .checked_add(1)
                    .ok_or("quarantine chunk counter exhausted")?;
                if remaining == 0 {
                    break;
                }
            }
            let mut trailing = [0u8; 1];
            if input.read(&mut trailing)? != 0 || digest.finalize().as_slice() != expected.sha256 {
                return Err("quarantine object digest or trailing-data verification failed".into());
            }
            Ok::<(), BoxError>(())
        })();
        key.fill(0);
        decryption_result?;
        Ok(stored.size)
    }

    fn object_key(&self, object_id: &str) -> Result<[u8; 32], BoxError> {
        let mut mac = <HmacSha256 as Mac>::new_from_slice(&self.storage_key)?;
        mac.update(b"VGT-GEDEFENSE-QUARANTINE-OBJECT-KEY-V1\0");
        mac.update(object_id.as_bytes());
        let bytes = mac.finalize().into_bytes();
        let mut key = [0u8; 32];
        key.copy_from_slice(&bytes);
        Ok(key)
    }

    fn object_path(&self, object_id: &str) -> Result<PathBuf, BoxError> {
        validate_object_id(object_id)?;
        Ok(self.object_dir.join(format!("{object_id}.qv")))
    }

    fn remove_object(&self, object_id: &str) -> Result<(), BoxError> {
        fs::remove_file(self.object_path(object_id)?)?;
        sync_directory(&self.object_dir)
    }

    fn remove_object_if_present(&self, object_id: &str) -> Result<(), BoxError> {
        let path = self.object_path(object_id)?;
        match fs::remove_file(path) {
            Ok(()) => sync_directory(&self.object_dir),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error.into()),
        }
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

    /// Re-validates the stored object binding before a prune may delete it.
    fn verify_prune_identity(
        &self,
        object_id: &str,
        expected: &FileIdentity,
    ) -> Result<(), BoxError> {
        let path = self.object_path(object_id)?;
        let mut input = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(&path)?;
        let mut header = [0u8; HEADER_BYTES];
        input.read_exact(&mut header)?;
        let (stored, _nonce_prefix) = decode_header(&header)?;
        // The header/stored identity comparison is constant time even though the
        // digest is not secret: the caller receives one indistinguishable refusal
        // for every mismatch position.
        if !constant_time_identity_eq(&stored, expected) {
            return Err("quarantine object identity mismatch".into());
        }
        // Full content verification reuses the existing verifier: decrypt every
        // chunk, authenticate the AEAD tags and compare the plaintext digest.
        self.verify_object(object_id, expected)?;
        Ok(())
    }
}

impl Drop for QuarantineBroker {
    fn drop(&mut self) {
        self.storage_key.fill(0);
    }
}

const CORE_QUARANTINE_FORBIDDEN_ROOTS: &[&str] = &[
    "/proc",
    "/sys",
    "/run",
    "/boot",
    "/bin",
    "/sbin",
    "/lib",
    "/lib64",
    "/lib32",
    "/libx32",
    "/usr",
    "/etc",
    "/var/lib/vgt",
    "/etc/vgt",
    "/opt/vgt",
];

const CORE_QUARANTINE_ALLOWED_ROOTS: &[&str] = &[
    "/tmp",
    "/var/tmp",
    "/dev/shm",
    "/var/www",
    "/home",
    "/root",
    "/srv",
    "/mnt",
    "/media",
    "/var/backups",
    "/var/spool",
    "/var/cache",
    "/var/opt",
    "/opt",
];

fn path_matches_root(path: &Path, root: &Path) -> bool {
    path == root || path.starts_with(root)
}

pub(crate) fn validate_core_quarantine_path(path: &Path) -> Result<(), BoxError> {
    if !path.is_absolute() || path == Path::new("/") {
        return Err("quarantine path must be absolute and non-root".into());
    }
    for component in path.components() {
        match component {
            std::path::Component::CurDir | std::path::Component::ParentDir => {
                return Err("quarantine path must be normalized without relative components".into());
            }
            _ => {}
        }
    }
    if path == Path::new("/dev")
        || (path.starts_with(Path::new("/dev")) && !path.starts_with(Path::new("/dev/shm")))
    {
        return Err("quarantine path is inside forbidden device root".into());
    }
    for forbidden in CORE_QUARANTINE_FORBIDDEN_ROOTS {
        if path_matches_root(path, Path::new(forbidden)) {
            return Err("quarantine path is inside forbidden system or control root".into());
        }
    }
    let allowed = CORE_QUARANTINE_ALLOWED_ROOTS
        .iter()
        .any(|root| path_matches_root(path, Path::new(root)));
    if !allowed {
        return Err("quarantine path is outside permitted core allowlist roots".into());
    }
    // Never allow quarantining one of the allowlist root directories themselves (must be a child).
    let is_bare_root = CORE_QUARANTINE_ALLOWED_ROOTS
        .iter()
        .any(|root| path == Path::new(root));
    if is_bare_root {
        return Err("quarantine target must be a file below an allowed root".into());
    }
    Ok(())
}

fn decode_path(encoded: &str) -> Result<PathBuf, BoxError> {
    if encoded.is_empty() || encoded.len() > 3072 {
        return Err("quarantine path token is outside bounds".into());
    }
    let raw = URL_SAFE_NO_PAD.decode(encoded)?;
    if raw.is_empty() || raw.len() > 2048 || raw.contains(&0) {
        return Err("quarantine path is outside bounds".into());
    }
    let path = PathBuf::from(OsStr::from_bytes(&raw));
    validate_core_quarantine_path(&path)?;
    Ok(path)
}

fn open_parent_and_name(path: &Path) -> Result<(OwnedFd, CString), BoxError> {
    let parent = path.parent().ok_or("quarantine path has no parent")?;
    let basename = path
        .file_name()
        .ok_or("quarantine path has no basename")?
        .as_bytes();
    if basename.is_empty() || basename == b"." || basename == b".." {
        return Err("quarantine basename is invalid".into());
    }
    let parent_c = CString::new(parent.as_os_str().as_bytes())?;
    let how = OpenHow {
        // A real readable directory descriptor is required: O_PATH accepts
        // openat/renameat operations but makes fsync(2) fail with EBADF,
        // breaking the durability boundary after atomic source capture.
        flags: (libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC) as u64,
        mode: 0,
        resolve: RESOLVE_NO_MAGICLINKS | RESOLVE_NO_SYMLINKS,
    };
    let descriptor = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            libc::AT_FDCWD,
            parent_c.as_ptr(),
            &how,
            std::mem::size_of::<OpenHow>(),
        )
    } as i32;
    if descriptor < 0 {
        let error = std::io::Error::last_os_error();
        // F-HOTFIX-4: under systemd's RestrictSUIDSGID=yes the kernel returns
        // ENOSYS for openat2 in this sandbox. Fall back to a component-wise
        // O_NOFOLLOW walk instead of failing the whole quarantine response.
        if matches!(error.raw_os_error(), Some(libc::ENOSYS) | Some(libc::EINVAL)) {
            let parent = crate::open_componentwise(
                parent,
                libc::O_RDONLY | libc::O_DIRECTORY,
            )?;
            return Ok((OwnedFd::from(parent), CString::new(basename)?));
        }
        return Err(error.into());
    }
    let parent_fd = unsafe { OwnedFd::from_raw_fd(descriptor) };
    Ok((parent_fd, CString::new(basename)?))
}

// FIND-035: a restore must never reproduce setuid/setgid (or sticky) bits from
// the stored identity. Only the ordinary permission bits are restored.
fn restored_mode(mode: u32) -> u32 {
    mode & RESTORE_MODE_MASK
}

fn open_regular_at(parent_fd: RawFd, name: &CStr) -> Result<OwnedFd, BoxError> {
    // O_NONBLOCK is the FIFO fix: a user-planted FIFO in the destination
    // directory made openat block forever on the single-threaded IPC loop. With
    // O_NONBLOCK the open returns at once and the type check below refuses it;
    // for a regular file O_NONBLOCK has no effect on reads.
    let descriptor = unsafe {
        libc::openat(
            parent_fd,
            name.as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK,
        )
    };
    if descriptor < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let fd = unsafe { OwnedFd::from_raw_fd(descriptor) };
    // fstat on the already opened descriptor: the target must be a regular file.
    // Symlinks are already refused by O_NOFOLLOW (ELOOP); FIFOs, sockets and
    // devices are refused here before any read can block.
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(fd.as_raw_fd(), &mut stat) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    if stat.st_mode & libc::S_IFMT != libc::S_IFREG
        || stat.st_size < 0
        || stat.st_size as u64 > MAX_FILE_BYTES
    {
        return Err("quarantine source must be a bounded regular file".into());
    }
    Ok(fd)
}

// F-15: creates the restore staging file relative to the already validated
// parent descriptor with O_EXCL|O_NOFOLLOW. Neither a symlink swap nor a second
// path resolution can redirect this privileged write.
fn create_restore_file_at(parent_fd: RawFd, name: &CStr) -> Result<File, BoxError> {
    let descriptor = unsafe {
        libc::openat(
            parent_fd,
            name.as_ptr(),
            libc::O_CREAT | libc::O_EXCL | libc::O_WRONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            0o600 as libc::mode_t,
        )
    };
    if descriptor < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(unsafe { File::from_raw_fd(descriptor) })
}

fn inspect_at(parent_fd: RawFd, name: &CStr) -> Result<FileIdentity, BoxError> {
    let fd = open_regular_at(parent_fd, name)?;
    let mut file = File::from(fd);
    let before = file.metadata()?;
    let mut digest = Sha256::new();
    let copied = std::io::copy(
        &mut std::io::Read::by_ref(&mut file).take(MAX_FILE_BYTES + 1),
        &mut digest,
    )?;
    if copied != before.len() {
        return Err("quarantine source changed while hashing".into());
    }
    let after = file.metadata()?;
    if before.dev() != after.dev()
        || before.ino() != after.ino()
        || before.len() != after.len()
        || before.mtime() != after.mtime()
        || before.mtime_nsec() != after.mtime_nsec()
    {
        return Err("quarantine source identity changed while hashing".into());
    }
    let bytes = digest.finalize();
    let mut sha256 = [0u8; 32];
    sha256.copy_from_slice(&bytes);
    file_identity_from_metadata(&after, sha256)
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

// Constant-time comparison of two file identities.
//
// The identity carries no secret, but a caller that can distinguish "first byte
// differs" from "last byte differs" gains a byte-at-a-time oracle for a digest
// comparison. The comparison therefore accumulates XOR differences over the
// canonical encoded identity and only inspects the accumulator once.
fn constant_time_identity_eq(left: &FileIdentity, right: &FileIdentity) -> bool {
    let left = left.encode();
    let right = right.encode();
    if left.len() != right.len() {
        return false;
    }
    let mut difference = 0u8;
    for (a, b) in left.bytes().zip(right.bytes()) {
        difference |= a ^ b;
    }
    difference == 0
}

fn stat_matches_identity(stat: &libc::stat, expected: &FileIdentity) -> bool {
    (stat.st_mode & libc::S_IFMT) == libc::S_IFREG
        && stat.st_size >= 0
        && stat.st_dev as u64 == expected.device
        && stat.st_ino as u64 == expected.inode
        && stat.st_size as u64 == expected.size
}

fn stat_at(parent_fd: RawFd, name: &CStr) -> Result<Option<libc::stat>, BoxError> {
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    let result = unsafe {
        libc::fstatat(
            parent_fd,
            name.as_ptr(),
            stat.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if result == 0 {
        // SAFETY: `fstatat` initialized `stat` on return 0.
        return Ok(Some(unsafe { stat.assume_init() }));
    }
    let error = std::io::Error::last_os_error();
    if error.raw_os_error() == Some(libc::ENOENT) {
        return Ok(None);
    }
    Err(error.into())
}

fn path_exists_at(parent_fd: RawFd, name: &CStr) -> Result<bool, BoxError> {
    Ok(stat_at(parent_fd, name)?.is_some())
}

fn rename_noreplace(
    from_fd: RawFd,
    from: &CStr,
    to_fd: RawFd,
    to: &CStr,
) -> std::io::Result<()> {
    let result = unsafe {
        libc::syscall(
            libc::SYS_renameat2,
            from_fd,
            from.as_ptr(),
            to_fd,
            to.as_ptr(),
            RENAME_NOREPLACE,
        )
    };
    if result != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

fn unlink_at(parent_fd: RawFd, name: &CStr) -> Result<(), BoxError> {
    let result = unsafe { libc::unlinkat(parent_fd, name.as_ptr(), 0) };
    if result != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}

// FIND-035: removal of the captured source is the commit point of a copy-only
// quarantine. Its failure is a failed quarantine, not a benign degradation: the
// caller aborts the transaction and the control plane must not record success
// while the malware is still at its original path.
fn remove_source_after_verified_copy(parent_fd: RawFd, basename: &CStr) -> Result<(), BoxError> {
    if let Err(error) = unlink_at(parent_fd, basename) {
        return Err(std::io::Error::other(format!(
            "quarantine source could not be removed after a verified copy: {error}"
        ))
        .into());
    }
    if let Err(error) = sync_fd(parent_fd) {
        // The source is already gone, so the quarantine itself is complete; only
        // the durability of the directory entry removal is degraded.
        eprintln!("GeDefense quarantine source removal was not durable: {error}");
    }
    Ok(())
}

fn sync_fd(descriptor: RawFd) -> Result<(), BoxError> {
    let result = unsafe { libc::fsync(descriptor) };
    if result != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}

fn sync_directory(path: &Path) -> Result<(), BoxError> {
    let directory = File::open(path)?;
    directory.sync_all()?;
    Ok(())
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

fn validate_object_id(object_id: &str) -> Result<(), BoxError> {
    if object_id.len() != 19
        || !object_id.starts_with("QV-")
        || !object_id[3..]
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err("quarantine object ID is invalid".into());
    }
    Ok(())
}

fn staging_name(object_id: &str) -> Result<CString, BoxError> {
    validate_object_id(object_id)?;
    Ok(CString::new(format!(".gedefense-q-{object_id}"))?)
}

fn temporary_restore_name(object_id: &str) -> Result<CString, BoxError> {
    validate_object_id(object_id)?;
    Ok(CString::new(format!(".gedefense-restore-{object_id}"))?)
}

fn random_nonce_prefix() -> Result<[u8; 8], BoxError> {
    let mut random = File::open("/dev/urandom")?;
    let mut prefix = [0u8; 8];
    random.read_exact(&mut prefix)?;
    Ok(prefix)
}

fn encode_header(identity: &FileIdentity, nonce_prefix: [u8; 8]) -> [u8; HEADER_BYTES] {
    let mut header = [0u8; HEADER_BYTES];
    header[0..8].copy_from_slice(MAGIC);
    header[8..16].copy_from_slice(&identity.size.to_le_bytes());
    header[16..20].copy_from_slice(&identity.mode.to_le_bytes());
    header[20..24].copy_from_slice(&identity.uid.to_le_bytes());
    header[24..28].copy_from_slice(&identity.gid.to_le_bytes());
    header[28..36].copy_from_slice(&identity.device.to_le_bytes());
    header[36..44].copy_from_slice(&identity.inode.to_le_bytes());
    header[44..52].copy_from_slice(&identity.modified_nanos.to_le_bytes());
    header[52..60].copy_from_slice(&nonce_prefix);
    header[60..92].copy_from_slice(&identity.sha256);
    header
}

fn decode_header(header: &[u8; HEADER_BYTES]) -> Result<(FileIdentity, [u8; 8]), BoxError> {
    if &header[0..8] != MAGIC {
        return Err("quarantine object magic is invalid".into());
    }
    let size = u64::from_le_bytes(header[8..16].try_into()?);
    let mode = u32::from_le_bytes(header[16..20].try_into()?);
    let uid = u32::from_le_bytes(header[20..24].try_into()?);
    let gid = u32::from_le_bytes(header[24..28].try_into()?);
    let device = u64::from_le_bytes(header[28..36].try_into()?);
    let inode = u64::from_le_bytes(header[36..44].try_into()?);
    let modified_nanos = i64::from_le_bytes(header[44..52].try_into()?);
    if size > MAX_FILE_BYTES || mode > 0o7777 {
        return Err("quarantine object header exceeds typed bounds".into());
    }
    let mut nonce_prefix = [0u8; 8];
    nonce_prefix.copy_from_slice(&header[52..60]);
    let mut sha256 = [0u8; 32];
    sha256.copy_from_slice(&header[60..92]);
    Ok((
        FileIdentity {
            size,
            mode,
            uid,
            gid,
            device,
            inode,
            modified_nanos,
            sha256,
        },
        nonce_prefix,
    ))
}

fn chunk_nonce(prefix: [u8; 8], index: u32) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[0..8].copy_from_slice(&prefix);
    nonce[8..12].copy_from_slice(&index.to_be_bytes());
    nonce
}

fn chunk_aad(header: &[u8; HEADER_BYTES], index: u32, length: u32) -> Vec<u8> {
    let mut aad = Vec::with_capacity(HEADER_BYTES + 48);
    aad.extend_from_slice(b"VGT-GEDEFENSE-QUARANTINE-CHUNK-V1\0");
    aad.extend_from_slice(header);
    aad.extend_from_slice(&index.to_be_bytes());
    aad.extend_from_slice(&length.to_be_bytes());
    aad
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn test_root(name: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("test clock")
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "gedefense-quarantine-{name}-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir_all(&root).expect("test root");
        root
    }

    fn path_token(path: &Path) -> String {
        URL_SAFE_NO_PAD.encode(path.as_os_str().as_bytes())
    }

    fn identity_from_token(token: &str) -> FileIdentity {
        let fields: Vec<&str> = token
            .strip_prefix("v1:")
            .expect("identity version")
            .split(':')
            .collect();
        FileIdentity::parse(&fields).expect("identity")
    }

    #[test]
    fn read_only_backing_errors_are_recoverable() {
        for errno in [
            libc::EROFS,
            libc::EXDEV,
            libc::EACCES,
            libc::EPERM,
            libc::ENOSYS,
            libc::EINVAL,
        ] {
            let error = std::io::Error::from_raw_os_error(errno);
            assert!(is_read_only_backing_error(&error), "errno {errno}");
        }
        for errno in [libc::ENOENT, libc::ENOTDIR, libc::EBADF] {
            let error = std::io::Error::from_raw_os_error(errno);
            assert!(!is_read_only_backing_error(&error), "errno {errno}");
        }
    }

    #[test]
    fn copy_quarantine_stores_a_verifiable_object() {
        let root = test_root("copy-fallback");
        let source_dir = root.join("source");
        let object_dir = root.join("vault");
        fs::create_dir_all(&source_dir).expect("source directory");
        fs::create_dir_all(&object_dir).expect("vault directory");
        let source = source_dir.join("threat.bin");
        fs::write(&source, b"copy-fallback-quarantine-payload").expect("source file");
        let broker = QuarantineBroker::new(
            object_dir.to_str().expect("utf8 vault"),
            &[3u8; 32],
        )
        .expect("broker");
        let (parent, basename) = open_parent_and_name(&source).expect("parent descriptor");
        let identity = inspect_at(parent.as_raw_fd(), &basename).expect("identity");
        let object_id = "QV-0123456789abcdef";
        broker
            .copy_quarantine(parent.as_raw_fd(), &basename, object_id, &identity)
            .expect("copy quarantine");
        assert!(
            !source.exists(),
            "source must be removed when the directory is writable"
        );
        assert!(
            object_dir.join(format!("{object_id}.qv")).exists(),
            "vault object missing"
        );
        broker
            .verify_object(object_id, &identity)
            .expect("object verifies");
    }

    #[test]
    fn object_ids_and_identity_encoding_are_strict() {
        assert!(validate_object_id("QV-0123456789abcdef").is_ok());
        assert!(validate_object_id("QV-0123456789ABCDEf").is_err());
        assert!(validate_object_id("../0123456789abcdef").is_err());
        let identity = FileIdentity {
            size: 12,
            mode: 0o640,
            uid: 1000,
            gid: 1000,
            device: 8,
            inode: 99,
            modified_nanos: 123,
            sha256: [7u8; 32],
        };
        let encoded = identity.encode();
        let fields: Vec<&str> = encoded
            .strip_prefix("v1:")
            .expect("identity prefix")
            .split(':')
            .collect();
        assert_eq!(FileIdentity::parse(&fields).expect("identity"), identity);
    }

    #[test]
    fn chunk_nonce_is_unique_per_index() {
        let prefix = [9u8; 8];
        assert_ne!(chunk_nonce(prefix, 0), chunk_nonce(prefix, 1));
    }

    #[test]
    fn encrypted_object_round_trip_is_atomic_and_verified() {
        let root = test_root("round-trip");
        let source_dir = root.join("source");
        let object_dir = root.join("vault");
        fs::create_dir_all(&source_dir).expect("source directory");
        let source = source_dir.join("threat.bin");
        let payload = vec![0x5au8; CHUNK_BYTES + 37];
        fs::write(&source, &payload).expect("source write");
        fs::set_permissions(&source, fs::Permissions::from_mode(0o640)).expect("source mode");

        let broker =
            QuarantineBroker::new(object_dir.to_str().expect("object directory"), &[0x33; 32])
                .expect("broker");
        let encoded_path = path_token(&source);
        let identity =
            identity_from_token(&broker.inspect_token(&encoded_path).expect("inspect source"));
        let object_id = "QV-0123456789abcdef";

        broker
            .quarantine_token(&encoded_path, object_id, &identity)
            .expect("quarantine");
        assert!(!source.exists());
        broker
            .verify_object(object_id, &identity)
            .expect("verify object");
        broker
            .restore_token(&encoded_path, object_id, &identity)
            .expect("restore");
        assert_eq!(fs::read(&source).expect("restored payload"), payload);
        assert!(!object_dir.join(format!("{object_id}.qv")).exists());

        fs::remove_dir_all(&root).expect("test cleanup");
    }

    #[test]
    fn encrypted_object_tamper_and_symlink_parent_are_rejected() {
        let root = test_root("tamper");
        let source_dir = root.join("source");
        let object_dir = root.join("vault");
        fs::create_dir_all(&source_dir).expect("source directory");
        let source = source_dir.join("threat.bin");
        fs::write(&source, b"hostile payload").expect("source write");
        let broker =
            QuarantineBroker::new(object_dir.to_str().expect("object directory"), &[0x44; 32])
                .expect("broker");
        let encoded_path = path_token(&source);
        let identity =
            identity_from_token(&broker.inspect_token(&encoded_path).expect("inspect source"));
        let object_id = "QV-fedcba9876543210";
        broker
            .quarantine_token(&encoded_path, object_id, &identity)
            .expect("quarantine");

        let object = object_dir.join(format!("{object_id}.qv"));
        let mut bytes = fs::read(&object).expect("object read");
        let last = bytes.len() - 1;
        bytes[last] ^= 0x80;
        fs::write(&object, bytes).expect("object tamper");
        assert!(broker.verify_object(object_id, &identity).is_err());

        let real_parent = root.join("real-parent");
        let linked_parent = root.join("linked-parent");
        fs::create_dir_all(&real_parent).expect("real parent");
        std::os::unix::fs::symlink(&real_parent, &linked_parent).expect("parent symlink");
        let linked_source = linked_parent.join("target.bin");
        fs::write(real_parent.join("target.bin"), b"target").expect("linked source");
        assert!(broker.inspect_token(&path_token(&linked_source)).is_err());

        fs::remove_dir_all(&root).expect("test cleanup");
    }

    // F-15: the restore staging file is created relative to the validated parent
    // descriptor, exclusively, without following symlinks and with mode 0600.
    #[test]
    fn restore_staging_file_is_fd_relative_exclusive_and_private() {
        let root = test_root("restore-fd");
        let parent = root.join("parent");
        fs::create_dir_all(&parent).expect("parent directory");
        let directory = File::open(&parent).expect("open parent");
        let name = CString::new(".gedefense-restore-QV-0123456789abcdef").expect("staging name");

        {
            let file =
                create_restore_file_at(directory.as_raw_fd(), &name).expect("create staging");
            let metadata = file.metadata().expect("staging metadata");
            assert!(metadata.is_file());
            assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
        }
        assert!(
            create_restore_file_at(directory.as_raw_fd(), &name).is_err(),
            "staging file must be exclusive"
        );

        let symlink_name = CString::new(".gedefense-restore-QV-fedcba9876543210").expect("name");
        let outside = root.join("outside");
        fs::write(&outside, b"outside").expect("outside file");
        std::os::unix::fs::symlink(&outside, parent.join(symlink_name.to_str().unwrap()))
            .expect("symlink staging name");
        assert!(
            create_restore_file_at(directory.as_raw_fd(), &symlink_name).is_err(),
            "symlink staging target must be refused"
        );
        unlink_at(directory.as_raw_fd(), &name).expect("fd-relative unlink");
        assert!(!parent.join(name.to_str().unwrap()).exists());

        fs::remove_dir_all(&root).expect("test cleanup");
    }

    // F-15: a failed restore must clean up its staging file through the parent
    // descriptor and must not leave attacker-influenced destinations behind.
    #[test]
    fn failed_restore_removes_fd_relative_staging_file() {
        let root = test_root("restore-failure");
        let source_dir = root.join("source");
        let object_dir = root.join("vault");
        fs::create_dir_all(&source_dir).expect("source directory");
        let source = source_dir.join("threat.bin");
        fs::write(&source, b"restore failure payload").expect("source write");
        let broker =
            QuarantineBroker::new(object_dir.to_str().expect("object directory"), &[0x55; 32])
                .expect("broker");
        let encoded_path = path_token(&source);
        let identity =
            identity_from_token(&broker.inspect_token(&encoded_path).expect("inspect source"));
        let object_id = "QV-0011223344556677";
        broker
            .quarantine_token(&encoded_path, object_id, &identity)
            .expect("quarantine");

        let object = object_dir.join(format!("{object_id}.qv"));
        let mut bytes = fs::read(&object).expect("object read");
        let last = bytes.len() - 1;
        bytes[last] ^= 0x40;
        fs::write(&object, bytes).expect("object tamper");
        assert!(broker
            .restore_token(&encoded_path, object_id, &identity)
            .is_err());
        assert!(
            !source.exists(),
            "failed restore must not install a destination"
        );
        let leftovers: Vec<String> = fs::read_dir(&source_dir)
            .expect("source directory listing")
            .map(|entry| {
                entry
                    .expect("source entry")
                    .file_name()
                    .to_string_lossy()
                    .into_owned()
            })
            .filter(|name| name.starts_with(".gedefense-restore-"))
            .collect();
        assert!(
            leftovers.is_empty(),
            "failed restore left staging files: {leftovers:?}"
        );

        fs::remove_dir_all(&root).expect("test cleanup");
    }

    // FIND-035: captured SUID/SGID bits are never restored.
    #[test]
    fn restored_mode_masks_suid_sgid_and_sticky() {
        assert_eq!(restored_mode(0o4755), 0o755);
        assert_eq!(restored_mode(0o2755), 0o755);
        assert_eq!(restored_mode(0o6755), 0o755);
        assert_eq!(restored_mode(0o1655), 0o655);
        assert_eq!(restored_mode(0o640), 0o640);
        assert_eq!(restored_mode(0o7777), 0o777);
    }

    #[test]
    fn restore_drops_the_suid_bit_of_a_quarantined_file() {
        let root = test_root("restore-suid");
        let source_dir = root.join("source");
        let object_dir = root.join("vault");
        fs::create_dir_all(&source_dir).expect("source directory");
        let source = source_dir.join("setuid.bin");
        fs::write(&source, b"setuid payload").expect("source write");
        fs::set_permissions(&source, fs::Permissions::from_mode(0o4755)).expect("source mode");
        let broker =
            QuarantineBroker::new(object_dir.to_str().expect("object directory"), &[0x77; 32])
                .expect("broker");
        let encoded_path = path_token(&source);
        let identity =
            identity_from_token(&broker.inspect_token(&encoded_path).expect("inspect source"));
        assert_eq!(
            identity.mode & 0o7777,
            0o4755,
            "the identity records the captured SUID bit"
        );
        let object_id = "QV-0011223344556677";
        broker
            .quarantine_token(&encoded_path, object_id, &identity)
            .expect("quarantine");
        assert!(!source.exists());
        broker
            .restore_token(&encoded_path, object_id, &identity)
            .expect("restore");
        let mode = fs::metadata(&source).expect("restored metadata").mode() & 0o7777;
        assert_eq!(mode, 0o755, "restore must drop SUID/SGID bits");
        assert_eq!(mode & 0o7000, 0, "no privilege bits may survive a restore");

        fs::remove_dir_all(&root).expect("test cleanup");
    }

    // FIND-035: a FIFO planted at the quarantine source name must be refused
    // immediately instead of blocking the single-threaded IPC loop forever.
    #[test]
    fn open_regular_at_returns_immediately_for_a_fifo() {
        let root = test_root("fifo-open");
        let parent = File::open(&root).expect("parent directory");
        let fifo = root.join("threat.fifo");
        let fifo_c = CString::new(fifo.as_os_str().as_bytes()).expect("fifo path");
        assert_eq!(unsafe { libc::mkfifo(fifo_c.as_ptr(), 0o600) }, 0, "mkfifo");
        let name = CString::new("threat.fifo").expect("fifo name");
        let started = std::time::Instant::now();
        let result = open_regular_at(parent.as_raw_fd(), &name);
        assert!(result.is_err(), "a FIFO must not be accepted as a source");
        assert!(
            started.elapsed() < std::time::Duration::from_secs(2),
            "open_regular_at blocked on a FIFO"
        );

        // A directory and a symlink are not regular files either.
        fs::create_dir(root.join("directory")).expect("directory fixture");
        let directory = CString::new("directory").expect("directory name");
        assert!(open_regular_at(parent.as_raw_fd(), &directory).is_err());
        let target = root.join("target.bin");
        fs::write(&target, b"target").expect("symlink target");
        std::os::unix::fs::symlink(&target, root.join("linked.bin")).expect("symlink fixture");
        let link = CString::new("linked.bin").expect("symlink name");
        assert!(open_regular_at(parent.as_raw_fd(), &link).is_err());

        fs::remove_dir_all(&root).expect("test cleanup");
    }

    #[test]
    fn unlink_at_propagates_missing_and_directory_failures() {
        let root = test_root("unlink-errors");
        let parent = File::open(&root).expect("parent directory");
        let missing = CString::new("missing.bin").expect("missing name");
        assert!(unlink_at(parent.as_raw_fd(), &missing).is_err());
        fs::create_dir(root.join("subdir")).expect("directory fixture");
        let directory = CString::new("subdir").expect("directory name");
        let error: BoxError = unlink_at(parent.as_raw_fd(), &directory)
            .expect_err("unlinkat on a directory must not report success");
        assert!(!error.to_string().is_empty(), "{error}");
        assert!(root.join("subdir").exists());
        fs::remove_dir_all(&root).expect("test cleanup");
    }

    // FIND-035: the source removal is the commit point of the copy fallback.
    // This test runs in an unprivileged child process when the harness is root,
    // because root's CAP_DAC_OVERRIDE would unlink inside a read-only directory
    // and hide the defect.
    #[test]
    fn copy_quarantine_aborts_when_the_source_cannot_be_removed() {
        if std::env::var_os("GEDEFENSE_QUARANTINE_READONLY_CHILD").is_some() {
            copy_quarantine_aborts_when_the_source_cannot_be_removed_inner();
            return;
        }
        if unsafe { libc::geteuid() } == 0 {
            use std::ffi::CString;
            use std::os::unix::process::CommandExt;
            let child_tmp = PathBuf::from(format!("/tmp/gedefense-qchild-{}", std::process::id()));
            let _ = fs::remove_dir_all(&child_tmp);
            fs::create_dir_all(&child_tmp).expect("child tmp dir");
            fs::set_permissions(&child_tmp, fs::Permissions::from_mode(0o700))
                .expect("child tmp permissions");
            let c_tmp = CString::new(child_tmp.as_os_str().as_bytes()).expect("cstr child_tmp");
            if unsafe { libc::chown(c_tmp.as_ptr(), 65534, 65534) } != 0 {
                let _ = fs::remove_dir_all(&child_tmp);
                panic!("chown child_tmp failed: {}", std::io::Error::last_os_error());
            }
            let run_as_nobody = |bin: &Path| -> std::io::Result<std::process::ExitStatus> {
                let mut command = std::process::Command::new(bin);
                command.args([
                    "--exact",
                    "quarantine::tests::copy_quarantine_aborts_when_the_source_cannot_be_removed",
                    "--nocapture",
                ]);
                command.env("GEDEFENSE_QUARANTINE_READONLY_CHILD", "1");
                // Override root's inherited TMPDIR (e.g. pam_tmpdir /tmp/user/0 mode 0700)
                // because std::env::temp_dir() does not fall back when TMPDIR is unwritable.
                command.env("TMPDIR", &child_tmp);
                unsafe {
                    command.pre_exec(|| {
                        if libc::setgid(65534) != 0 || libc::setuid(65534) != 0 {
                            return Err(std::io::Error::last_os_error());
                        }
                        Ok(())
                    });
                }
                command.status()
            };
            let exe = std::env::current_exe().expect("test binary");
            let status_res = match run_as_nobody(&exe) {
                Ok(status) => Ok(status),
                Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => {
                    // When invoked inside an installer's 0700 WORK directory, uid 65534
                    // cannot traverse parent directories to exec `exe`; stage a transient
                    // 0755 copy inside a 0711 directory under /tmp or /var/tmp.
                    let mut result = Err(err);
                    for base in [PathBuf::from("/tmp"), PathBuf::from("/var/tmp")] {
                        let stage_dir = base.join(format!("gedefense-qtest-{}", std::process::id()));
                        let _ = fs::remove_dir_all(&stage_dir);
                        if fs::create_dir_all(&stage_dir).is_ok()
                            && fs::set_permissions(&stage_dir, fs::Permissions::from_mode(0o711)).is_ok()
                        {
                            let staged_bin = stage_dir.join("test-runner");
                            if fs::copy(&exe, &staged_bin).is_ok()
                                && fs::set_permissions(&staged_bin, fs::Permissions::from_mode(0o755)).is_ok()
                            {
                                result = run_as_nobody(&staged_bin);
                            }
                            let _ = fs::remove_dir_all(&stage_dir);
                            if let Ok(ref st) = result {
                                if st.success() {
                                    break;
                                }
                            }
                        }
                    }
                    result
                }
                Err(err) => Err(err),
            };
            let _ = fs::remove_dir_all(&child_tmp);
            let status = status_res.expect("unprivileged staged child test process");
            assert!(status.success(), "unprivileged child test failed: {status}");
            return;
        }
        copy_quarantine_aborts_when_the_source_cannot_be_removed_inner();
    }

    fn copy_quarantine_aborts_when_the_source_cannot_be_removed_inner() {
        let root = test_root("copy-abort");
        let source_dir = root.join("source");
        let object_dir = root.join("vault");
        fs::create_dir_all(&source_dir).expect("source directory");
        let source = source_dir.join("threat.bin");
        fs::write(&source, b"copy-abort payload").expect("source write");
        let broker =
            QuarantineBroker::new(object_dir.to_str().expect("object directory"), &[0x66; 32])
                .expect("broker");
        let (parent, basename) = open_parent_and_name(&source).expect("parent descriptor");
        let identity = inspect_at(parent.as_raw_fd(), &basename).expect("identity");
        // Readable but not writable: the vault copy succeeds, unlink of the
        // source fails with EACCES.
        fs::set_permissions(&source_dir, fs::Permissions::from_mode(0o555))
            .expect("read-only source directory");
        let object_id = "QV-0123456789abcdef";
        let error = broker
            .copy_quarantine(parent.as_raw_fd(), &basename, object_id, &identity)
            .expect_err("an unremovable source must fail the quarantine");
        assert!(
            error.to_string().contains("could not be removed"),
            "{error}"
        );
        assert!(source.exists(), "the source must remain at its path");
        assert!(
            !object_dir.join(format!("{object_id}.qv")).exists(),
            "the vault object must be rolled back"
        );
        let leftovers: Vec<String> = fs::read_dir(&object_dir)
            .expect("vault listing")
            .map(|entry| {
                entry
                    .expect("vault entry")
                    .file_name()
                    .to_string_lossy()
                    .into_owned()
            })
            .collect();
        assert!(leftovers.is_empty(), "vault leftovers: {leftovers:?}");
        fs::set_permissions(&source_dir, fs::Permissions::from_mode(0o755))
            .expect("restore directory mode");
        fs::remove_dir_all(&root).expect("test cleanup");
    }

    #[test]
    fn quarantine_open_file_captures_already_open_descriptor_without_reopen() {
        let root = test_root("open-fd-quarantine");
        let source_dir = root.join("source");
        let object_dir = root.join("vault");
        fs::create_dir_all(&source_dir).expect("source directory");
        let source_path = source_dir.join("secret_payload.txt");
        let payload = b"open-fd-quarantine-payload";
        fs::write(&source_path, payload).expect("write source");
        let mut handle = File::open(&source_path).expect("open source");
        // Tighten permissions before capture; open_regular_at would require read
        // bits (or DAC bypass) when reopening by path, whereas the kernel-held
        // fanotify descriptor captures via the open fd + fstatat.
        fs::set_permissions(&source_path, fs::Permissions::from_mode(0o000))
            .expect("strip read bits");
        let digest: [u8; 32] = Sha256::digest(payload).into();
        let broker =
            QuarantineBroker::new(object_dir.to_str().expect("object directory"), &[0x77; 32])
                .expect("broker");
        let encoded_path = path_token(&source_path);
        let object_id = "QV-abcdef0123456789";
        let encoded_identity = broker
            .quarantine_open_file(&encoded_path, &mut handle, object_id, digest, payload.len() as u64)
            .expect("open-fd quarantine succeeds");
        let identity = FileIdentity::decode(&encoded_identity).expect("decode identity");
        assert_eq!(identity.sha256, digest);
        assert!(!source_path.exists(), "source must be unlinked after capture");
        assert_eq!(
            broker
                .verify_object(object_id, &identity)
                .expect("verify vault object"),
            "verified"
        );
        fs::remove_dir_all(&root).expect("test cleanup");
    }

    #[test]
    fn find_g_001_decode_path_enforces_core_allowlist_and_denylist() {
        for blocked in [
            "/etc/sysctl.d/99-gedefense.conf",
            "/etc/shadow",
            "/etc/vgt/gedefense/secrets/core-ipc.key",
            "/var/lib/vgt/gedefense/quarantine/objects/x.qv",
            "/opt/vgt/gedefense/current/bin/gedefense-control",
            "/proc/self/environ",
            "/sys/kernel/security/lsm",
            "/dev/sda1",
            "/usr/bin/bash",
            "/tmp/../etc/shadow",
            "/tmp",
            "relative/path.bin",
            "/",
        ] {
            let token = URL_SAFE_NO_PAD.encode(blocked.as_bytes());
            assert!(
                decode_path(&token).is_err(),
                "expected core path policy to reject {blocked}"
            );
        }
        for allowed in [
            "/tmp/drop.bin",
            "/var/tmp/payload.elf",
            "/dev/shm/stage.sh",
            "/var/www/html/shell.php",
            "/home/pentest/download.bin",
        ] {
            let token = URL_SAFE_NO_PAD.encode(allowed.as_bytes());
            assert_eq!(
                decode_path(&token).expect("allowed path"),
                PathBuf::from(allowed)
            );
        }
    }

    // -------------------------------------------------------------------
    // V6.3.0 AP-7: QUARANTINE_PRUNE
    // -------------------------------------------------------------------

    /// Creates one vaulted object from a temporary source file and returns the
    /// fixture alongside the broker, the encoded host path and the captured
    /// identity the prune must match.
    fn prune_fixture(
        name: &str,
        object_id: &str,
    ) -> (PathBuf, PathBuf, QuarantineBroker, String, FileIdentity) {
        let root = test_root(name);
        let source_dir = root.join("source");
        let object_dir = root.join("vault");
        fs::create_dir_all(&source_dir).expect("source directory");
        let source = source_dir.join("false-positive.bin");
        fs::write(&source, b"prune-false-positive-payload").expect("source write");
        let broker = QuarantineBroker::new(
            object_dir.to_str().expect("object directory"),
            &[0x5a; 32],
        )
        .expect("broker");
        let encoded_path = path_token(&source);
        let identity =
            identity_from_token(&broker.inspect_token(&encoded_path).expect("inspect source"));
        broker
            .quarantine_token(&encoded_path, object_id, &identity)
            .expect("quarantine");
        (root, object_dir, broker, encoded_path, identity)
    }

    #[test]
    fn prune_removes_verified_vault_object_and_refuses_a_second_prune() {
        let object_id = "QV-0123456789abcdef";
        let (root, object_dir, broker, _encoded_path, identity) =
            prune_fixture("prune-success", object_id);
        let object = object_dir.join(format!("{object_id}.qv"));
        assert!(object.exists(), "fixture object missing before prune");

        assert_eq!(
            broker
                .prune_token(object_id, &identity)
                .expect("verified false-positive must prune"),
            "pruned"
        );
        assert!(!object.exists(), "the vault object must be removed");
        assert!(
            !object_dir.join(format!(".{object_id}.tmp")).exists(),
            "prune must not leave temporary objects behind"
        );

        // The object is gone (already pruned or restored); a replay must be
        // refused instead of reporting a second successful prune.
        let error = broker
            .prune_token(object_id, &identity)
            .expect_err("double prune must fail closed");
        assert!(error.to_string().contains("not present"), "{error}");
        fs::remove_dir_all(&root).expect("test cleanup");
    }

    #[test]
    fn prune_refuses_identity_mismatch_without_removing_the_object() {
        let object_id = "QV-0011223344556677";
        let (root, object_dir, broker, _encoded_path, identity) =
            prune_fixture("prune-mismatch", object_id);
        let object = object_dir.join(format!("{object_id}.qv"));
        let mut wrong = identity.clone();
        wrong.sha256[0] ^= 0x01;

        let error = broker
            .prune_token(object_id, &wrong)
            .expect_err("a mismatched identity must never prune");
        assert!(
            error.to_string().contains("identity mismatch"),
            "unexpected refusal: {error}"
        );
        assert!(object.exists(), "a refused prune must not remove the object");
        // The object stays verifiable with its real identity.
        assert_eq!(
            broker
                .verify_object(object_id, &identity)
                .expect("object still verifies"),
            "verified"
        );
        fs::remove_dir_all(&root).expect("test cleanup");
    }

    #[test]
    fn prune_refuses_an_object_that_was_already_restored() {
        let object_id = "QV-fedcba9876543210";
        let (root, object_dir, broker, encoded_path, identity) =
            prune_fixture("prune-restored", object_id);
        broker
            .restore_token(&encoded_path, object_id, &identity)
            .expect("restore");
        // A successful restore removes the vault object in every branch; the
        // explicit "not currently restored" check is exactly this absence.
        assert!(!object_dir.join(format!("{object_id}.qv")).exists());
        let error = broker
            .prune_token(object_id, &identity)
            .expect_err("a restored object cannot be pruned");
        assert!(error.to_string().contains("not present"), "{error}");
        fs::remove_dir_all(&root).expect("test cleanup");
    }

    #[test]
    fn prune_rejects_invalid_object_ids() {
        let object_id = "QV-0123456789abcdef";
        let (root, _object_dir, broker, _encoded_path, identity) =
            prune_fixture("prune-invalid-id", object_id);
        for invalid in [
            "",
            "QV-0123",
            "QV-0123456789ABCDEF",
            "../0123456789abcdef",
            "QV-0123456789abcdeg",
        ] {
            assert!(
                broker.prune_token(invalid, &identity).is_err(),
                "invalid object id accepted for prune: {invalid:?}"
            );
        }
        // The valid object is untouched by the rejected calls.
        assert_eq!(
            broker
                .verify_object(object_id, &identity)
                .expect("object still verifies"),
            "verified"
        );
        fs::remove_dir_all(&root).expect("test cleanup");
    }

    #[test]
    fn prune_refuses_a_symlink_planted_in_the_vault() {
        let object_id = "QV-abcdef0123456789";
        let (root, object_dir, broker, _encoded_path, identity) =
            prune_fixture("prune-symlink", object_id);
        let object = object_dir.join(format!("{object_id}.qv"));
        let outside = root.join("outside.bin");
        fs::write(&outside, b"outside").expect("outside file");
        fs::remove_file(&object).expect("remove fixture object");
        std::os::unix::fs::symlink(&outside, &object).expect("vault symlink fixture");
        assert!(
            broker.prune_token(object_id, &identity).is_err(),
            "a symlink planted in the vault must not be pruned"
        );
        assert!(outside.exists(), "the symlink target must stay untouched");
        fs::remove_dir_all(&root).expect("test cleanup");
    }
}
