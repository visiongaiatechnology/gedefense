use super::*;

use sha2::{Digest, Sha256};
use std::{
    ffi::{CStr, CString},
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd, RawFd},
        unix::fs::{MetadataExt, OpenOptionsExt},
    },
    path::{Path, PathBuf},
};

const RENAME_NOREPLACE: u32 = 1;

impl QuarantineBroker {
    pub(super) fn finish_staged_quarantine(
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

    pub(super) fn copy_quarantine(
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

    pub(super) fn object_path(&self, object_id: &str) -> Result<PathBuf, BoxError> {
        validate_object_id(object_id)?;
        Ok(self.object_dir.join(format!("{object_id}.qv")))
    }

    pub(super) fn remove_object(&self, object_id: &str) -> Result<(), BoxError> {
        fs::remove_file(self.object_path(object_id)?)?;
        sync_directory(&self.object_dir)
    }

    pub(super) fn remove_object_if_present(&self, object_id: &str) -> Result<(), BoxError> {
        let path = self.object_path(object_id)?;
        match fs::remove_file(path) {
            Ok(()) => sync_directory(&self.object_dir),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error.into()),
        }
    }

    /// Re-validates the stored object binding before a prune may delete it.
    pub(super) fn verify_prune_identity(
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

pub(super) fn open_regular_at(parent_fd: RawFd, name: &CStr) -> Result<OwnedFd, BoxError> {
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
pub(super) fn create_restore_file_at(parent_fd: RawFd, name: &CStr) -> Result<File, BoxError> {
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

pub(super) fn inspect_at(parent_fd: RawFd, name: &CStr) -> Result<FileIdentity, BoxError> {
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

pub(super) fn stat_matches_identity(stat: &libc::stat, expected: &FileIdentity) -> bool {
    (stat.st_mode & libc::S_IFMT) == libc::S_IFREG
        && stat.st_size >= 0
        && stat.st_dev as u64 == expected.device
        && stat.st_ino as u64 == expected.inode
        && stat.st_size as u64 == expected.size
}

pub(super) fn stat_at(parent_fd: RawFd, name: &CStr) -> Result<Option<libc::stat>, BoxError> {
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

pub(super) fn path_exists_at(parent_fd: RawFd, name: &CStr) -> Result<bool, BoxError> {
    Ok(stat_at(parent_fd, name)?.is_some())
}

pub(super) fn rename_noreplace(
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

pub(super) fn unlink_at(parent_fd: RawFd, name: &CStr) -> Result<(), BoxError> {
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

pub(super) fn sync_fd(descriptor: RawFd) -> Result<(), BoxError> {
    let result = unsafe { libc::fsync(descriptor) };
    if result != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}

pub(super) fn sync_directory(path: &Path) -> Result<(), BoxError> {
    let directory = File::open(path)?;
    directory.sync_all()?;
    Ok(())
}

pub(super) fn validate_object_id(object_id: &str) -> Result<(), BoxError> {
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

pub(super) fn staging_name(object_id: &str) -> Result<CString, BoxError> {
    validate_object_id(object_id)?;
    Ok(CString::new(format!(".gedefense-q-{object_id}"))?)
}

pub(super) fn temporary_restore_name(object_id: &str) -> Result<CString, BoxError> {
    validate_object_id(object_id)?;
    Ok(CString::new(format!(".gedefense-restore-{object_id}"))?)
}
