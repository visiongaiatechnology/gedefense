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
    io::{Read, Write},
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
        rename_noreplace(
            parent.as_raw_fd(),
            &basename,
            parent.as_raw_fd(),
            &staging_name,
        )?;
        sync_fd(parent.as_raw_fd())?;

        let mut object_committed = false;
        let result = (|| {
            let staged = inspect_at(parent.as_raw_fd(), &staging_name)?;
            if &staged != expected {
                return Err("quarantine source identity changed after atomic capture".into());
            }
            self.encrypt_staged(parent.as_raw_fd(), &staging_name, object_id, expected)?;
            object_committed = true;
            unlink_at(parent.as_raw_fd(), &staging_name)?;
            sync_fd(parent.as_raw_fd())?;
            Ok(expected.encode())
        })();

        if result.is_err() {
            if object_committed {
                let _ = self.remove_object(object_id);
            }
            if path_exists_at(parent.as_raw_fd(), &staging_name)? {
                let _ = rename_noreplace(
                    parent.as_raw_fd(),
                    &staging_name,
                    parent.as_raw_fd(),
                    &basename,
                );
                let _ = sync_fd(parent.as_raw_fd());
            }
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
        let temporary_path = path
            .parent()
            .ok_or("quarantine restore parent is missing")?
            .join(OsStr::from_bytes(temporary_name.as_bytes()));
        let restore_result = (|| {
            {
                let mut output = OpenOptions::new()
                    .create_new(true)
                    .write(true)
                    .mode(0o600)
                    .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
                    .open(&temporary_path)?;
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
                let permissions =
                    unsafe { libc::fchmod(output.as_raw_fd(), expected.mode as libc::mode_t) };
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
            let _ = fs::remove_file(&temporary_path);
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
        if metadata.len() > MAX_FILE_BYTES + (MAX_FILE_BYTES / CHUNK_BYTES as u64 + 1) * 24 + 4096
        {
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
}

impl Drop for QuarantineBroker {
    fn drop(&mut self) {
        self.storage_key.fill(0);
    }
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
    if !path.is_absolute() || path == Path::new("/") {
        return Err("quarantine path must be absolute and non-root".into());
    }
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
        return Err(std::io::Error::last_os_error().into());
    }
    let parent_fd = unsafe { OwnedFd::from_raw_fd(descriptor) };
    Ok((parent_fd, CString::new(basename)?))
}

fn open_regular_at(parent_fd: RawFd, name: &CStr) -> Result<OwnedFd, BoxError> {
    let descriptor = unsafe {
        libc::openat(
            parent_fd,
            name.as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if descriptor < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let fd = unsafe { OwnedFd::from_raw_fd(descriptor) };
    let metadata = File::from(fd.try_clone()?).metadata()?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > MAX_FILE_BYTES {
        return Err("quarantine source must be a bounded regular file".into());
    }
    Ok(fd)
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
    Ok(FileIdentity {
        size: after.len(),
        mode: after.mode() & 0o7777,
        uid: after.uid(),
        gid: after.gid(),
        device: after.dev(),
        inode: after.ino(),
        modified_nanos: after
            .mtime()
            .checked_mul(1_000_000_000)
            .and_then(|seconds| seconds.checked_add(after.mtime_nsec()))
            .ok_or("quarantine modification time overflow")?,
        sha256,
    })
}

fn path_exists_at(parent_fd: RawFd, name: &CStr) -> Result<bool, BoxError> {
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
        return Ok(true);
    }
    let error = std::io::Error::last_os_error();
    if error.raw_os_error() == Some(libc::ENOENT) {
        return Ok(false);
    }
    Err(error.into())
}

fn rename_noreplace(
    from_fd: RawFd,
    from: &CStr,
    to_fd: RawFd,
    to: &CStr,
) -> Result<(), BoxError> {
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
        return Err(std::io::Error::last_os_error().into());
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

        let broker = QuarantineBroker::new(
            object_dir.to_str().expect("object directory"),
            &[0x33; 32],
        )
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
        let broker = QuarantineBroker::new(
            object_dir.to_str().expect("object directory"),
            &[0x44; 32],
        )
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
}
