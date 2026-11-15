//! Bounded export channel (POINT2 spec §4.7).
//!
//! The child receives exactly one pre-opened write FD for
//! `<staging_exports>/<uuid>/export.bin`; there is never a writable path inside
//! the cell.  The parent keeps its own descriptor, polls the size via `fstat`
//! (overflow ⇒ kill/burn with `export-overflow`) and, after the burn, copies
//! the file into a sealed memfd (`F_SEAL_WRITE|F_SEAL_GROW|F_SEAL_SHRINK`) and
//! hands that FD to Go-Control via `SCM_RIGHTS`.  Export content is evidence
//! only: it is bounded, hashed and never executed/rendered by the helper.
//! `read_bounded`/`sha256_of` are broker-tooling helpers covered by tests.
#![allow(dead_code)]

use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::Write;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use crate::config::sha256_reader;
use crate::types::{is_hex, ErrorCode};

pub const EXPORT_FILE_NAME: &str = "export.bin";
pub const EXPORT_MODE: u32 = 0o640;
pub const EXPORT_DIR_MODE: u32 = 0o750;
const MEMFD_NAME: &[u8] = b"gedefense-parser-export\0";
/// Maximum single bounded read served from a sealed export.
pub const MAX_READ_CHUNK: usize = 64 * 1024;

/// Pre-opened, inheritable write-only export file.
pub struct ExportTarget {
    file: File,
    path: PathBuf,
    ino: u64,
    dev: u64,
}

impl ExportTarget {
    /// Create `<staging_exports>/<uuid>/export.bin`.
    ///
    /// `owner` = `Some((0, gedefense_gid))` in production (root:gedefense);
    /// `None` is only used by non-root tests.  The FD is deliberately created
    /// without `CLOEXEC` so the sandbox child inherits it as its only write
    /// channel; the parent keeps it open for size policing.
    pub fn open(staging_exports: &Path, uuid: &str, owner: Option<(u32, u32)>) -> Result<ExportTarget, ErrorCode> {
        if !is_hex(uuid, 32) {
            return Err(ErrorCode::ExportMissing);
        }
        let dir = staging_exports.join(uuid);
        if dir.parent() != Some(staging_exports) {
            return Err(ErrorCode::ExportMissing);
        }
        match std::fs::symlink_metadata(&dir) {
            Ok(md) if md.is_dir() && !md.file_type().is_symlink() => {}
            Ok(_) => return Err(ErrorCode::ExportMissing),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let mut b = std::fs::DirBuilder::new();
                use std::os::unix::fs::DirBuilderExt;
                b.mode(EXPORT_DIR_MODE);
                b.create(&dir).map_err(|_| ErrorCode::ExportMissing)?;
                if let Some((uid, gid)) = owner {
                    let rc = unsafe { libc::chown(cstr(&dir)?.as_ptr(), uid, gid) };
                    if rc != 0 {
                        return Err(ErrorCode::ExportMissing);
                    }
                }
            }
            Err(_) => return Err(ErrorCode::ExportMissing),
        }
        let path = dir.join(EXPORT_FILE_NAME);
        let file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(EXPORT_MODE)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&path)
            .map_err(|_| ErrorCode::ExportMissing)?;
        let md = file.metadata().map_err(|_| ErrorCode::ExportMissing)?;
        if !md.is_file() || md.len() != 0 {
            return Err(ErrorCode::ExportMissing);
        }
        if let Some((uid, gid)) = owner {
            if unsafe { libc::fchown(file.as_raw_fd(), uid, gid) } != 0 {
                return Err(ErrorCode::ExportMissing);
            }
        }
        // The child must inherit this FD: clear FD_CLOEXEC (std sets it always).
        if unsafe { libc::fcntl(file.as_raw_fd(), libc::F_SETFD, 0) } != 0 {
            return Err(ErrorCode::Internal);
        }
        Ok(ExportTarget { file, path, ino: md.ino(), dev: md.dev() })
    }

    pub fn fd(&self) -> RawFd {
        self.file.as_raw_fd()
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// `fstat`-based size check; verifies device/inode did not change.
    pub fn size(&self) -> Result<u64, ErrorCode> {
        let md = self.file.metadata().map_err(|_| ErrorCode::Internal)?;
        if md.ino() != self.ino || md.dev() != self.dev || !md.is_file() {
            return Err(ErrorCode::ExportMissing);
        }
        Ok(md.len())
    }

    /// Returns current size or `export-overflow` once the cap is exceeded.
    pub fn check_limit(&self, max_export_bytes: u64) -> Result<u64, ErrorCode> {
        let size = self.size()?;
        if size > max_export_bytes {
            return Err(ErrorCode::ExportOverflow);
        }
        Ok(size)
    }

    /// `fsync` after burn, then a final bounded size check.
    pub fn flush_sync(&self, max_export_bytes: u64) -> Result<u64, ErrorCode> {
        self.file.sync_all().map_err(|_| ErrorCode::ExportMissing)?;
        self.check_limit(max_export_bytes)
    }
}

impl std::os::unix::io::AsRawFd for ExportTarget {
    fn as_raw_fd(&self) -> RawFd {
        self.file.as_raw_fd()
    }
}

fn cstr(p: &Path) -> Result<std::ffi::CString, ErrorCode> {
    use std::os::unix::ffi::OsStrExt;
    std::ffi::CString::new(p.as_os_str().as_bytes()).map_err(|_| ErrorCode::Internal)
}

/// Sealed, immutable export snapshot served to Go-Control (`CELL_EXPORT_READ`).
pub struct SealedExport {
    fd: OwnedFd,
    pub size: u64,
    pub sha256: String,
}

impl SealedExport {
    pub fn fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }

    /// Bounded `pread` from the sealed FD.
    pub fn read_bounded(&self, offset: u64, len: usize) -> Result<Vec<u8>, ErrorCode> {
        if len > MAX_READ_CHUNK {
            return Err(ErrorCode::BadRequest);
        }
        if offset > self.size || (offset as usize).saturating_add(len) > self.size as usize {
            return Err(ErrorCode::ExportMissing);
        }
        let mut buf = vec![0u8; len];
        // SAFETY: buf is valid for len bytes, offset fits the sealed file size.
        let n = unsafe {
            libc::pread(self.fd.as_raw_fd(), buf.as_mut_ptr() as *mut libc::c_void, len, offset as libc::off_t)
        };
        if n < 0 || n as usize != len {
            return Err(ErrorCode::ExportMissing);
        }
        Ok(buf)
    }
}

/// Hash the burned export file, copy it (bounded) into a sealed memfd.
///
/// `max_export_bytes` enforces the per-profile cap a second time; the memfd is
/// sealed against write/grow/shrink before the FD is exposed.
pub fn seal_export_file(
    path: &Path,
    max_export_bytes: u64,
    expected_owner_uid: Option<u32>,
) -> Result<SealedExport, ErrorCode> {
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| ErrorCode::ExportMissing)?;
    let md = file.metadata().map_err(|_| ErrorCode::ExportMissing)?;
    if !md.is_file() || md.len() > max_export_bytes {
        return Err(if md.is_file() { ErrorCode::ExportOverflow } else { ErrorCode::ExportMissing });
    }
    if let Some(uid) = expected_owner_uid {
        if md.uid() != uid {
            return Err(ErrorCode::ExportMissing);
        }
    }
    let (size, sha256) = sha256_reader(&mut file, Some(max_export_bytes))?;
    if size != md.len() {
        return Err(ErrorCode::ExportMissing);
    }
    // Fresh, sealed memfd for the evidence broker. MFD_ALLOW_SEALING is
    // required for F_ADD_SEALS (otherwise EPERM); MFD_CLOEXEC keeps the FD out
    // of any future exec (SCM_RIGHTS transfer ignores CLOEXEC on the wire).
    // SAFETY: memfd_create(2) with a static, NUL-terminated name and plain flags.
    let raw = unsafe {
        libc::syscall(libc::SYS_memfd_create, MEMFD_NAME.as_ptr(), libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING)
    } as RawFd;
    if raw < 0 {
        return Err(ErrorCode::Internal);
    }
    // SAFETY: `raw` is a freshly created, exclusively owned descriptor.
    let memfd = unsafe { OwnedFd::from_raw_fd(raw) };
    copy_bounded(&mut file, &memfd, size)?;
    apply_seals(&memfd, size)?;
    Ok(SealedExport { fd: memfd, size, sha256 })
}

fn copy_bounded(file: &mut File, memfd: &OwnedFd, size: u64) -> Result<(), ErrorCode> {
    use std::io::{Read, Seek, SeekFrom};
    file.seek(SeekFrom::Start(0)).map_err(|_| ErrorCode::Internal)?;
    let mut out = std::fs::File::from(memfd.try_clone().map_err(|_| ErrorCode::Internal)?);
    let mut total: u64 = 0;
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = file.read(&mut buf).map_err(|_| ErrorCode::Internal)?;
        if n == 0 {
            break;
        }
        total = total.saturating_add(n as u64);
        if total > size {
            return Err(ErrorCode::ExportOverflow);
        }
        out.write_all(&buf[..n]).map_err(|_| ErrorCode::Internal)?;
    }
    if total != size {
        return Err(ErrorCode::ExportMissing);
    }
    out.flush().map_err(|_| ErrorCode::Internal)?;
    Ok(())
}

fn apply_seals(fd: &OwnedFd, size: u64) -> Result<(), ErrorCode> {
    let seals = libc::F_SEAL_WRITE | libc::F_SEAL_GROW | libc::F_SEAL_SHRINK;
    // SAFETY: fcntl on our own memfd; size is bounded and validated above.
    if unsafe { libc::ftruncate(fd.as_raw_fd(), size as libc::off_t) } != 0 {
        return Err(ErrorCode::Internal);
    }
    if unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_ADD_SEALS, seals) } != 0 {
        return Err(ErrorCode::Internal);
    }
    // SAFETY: F_GET_SEALS states that all requested seals are active; a
    // missing seal means the evidence FD is NOT exposed (fail-closed).
    let got = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GET_SEALS) };
    if got < 0 || (got as i32 & seals) != seals {
        return Err(ErrorCode::Internal);
    }
    // Rewind: the FD is transferred via SCM_RIGHTS, so the receiver shares this
    // file offset.  Bounded readers expect to start at 0.
    // SAFETY: lseek on our own sealed memfd cannot fail for a seekable file.
    if unsafe { libc::lseek(fd.as_raw_fd(), 0, libc::SEEK_SET) } != 0 {
        return Err(ErrorCode::Internal);
    }
    Ok(())
}

/// Hash helper used by tests and diagnostics (bounded via [`sha256_reader`]).
pub fn sha256_of(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::test_support::TempDir;
    use std::io::Read;

    fn uuid() -> String {
        "ab".repeat(16)
    }

    fn target(td: &TempDir) -> ExportTarget {
        ExportTarget::open(&td.path, &uuid(), None).expect("export target")
    }

    #[test]
    fn target_is_created_0640_and_inheritable() {
        let td = TempDir::new("exp-open").unwrap();
        let t = target(&td);
        assert_eq!(t.size().unwrap(), 0);
        assert!(t.path().ends_with("export.bin"));
        let md = std::fs::metadata(t.path()).unwrap();
        assert_eq!(md.mode() & 0o777, EXPORT_MODE);
        // FD_CLOEXEC must be clear so the cell child inherits the only write FD
        let flags = unsafe { libc::fcntl(t.fd(), libc::F_GETFD) };
        assert!(flags >= 0 && flags & libc::FD_CLOEXEC == 0);
        // exact duplicate creation is rejected (O_EXCL)
        assert_eq!(ExportTarget::open(&td.path, &uuid(), None).err(), Some(ErrorCode::ExportMissing));
        // traversal/hex validation
        assert_eq!(ExportTarget::open(&td.path, "../escape", None).err(), Some(ErrorCode::ExportMissing));
        assert_eq!(ExportTarget::open(Path::new("rel"), &uuid(), None).err(), Some(ErrorCode::ExportMissing));
    }

    #[test]
    fn size_limit_and_sync() {
        let td = TempDir::new("exp-size").unwrap();
        let t = target(&td);
        {
            let mut f = &t.file;
            f.write_all(b"0123456789").unwrap();
        }
        assert_eq!(t.size().unwrap(), 10);
        assert_eq!(t.check_limit(10).unwrap(), 10);
        assert_eq!(t.check_limit(9), Err(ErrorCode::ExportOverflow));
        assert_eq!(t.flush_sync(10).unwrap(), 10);
        assert_eq!(std::fs::read(t.path()).unwrap(), b"0123456789");
    }

    #[test]
    fn seal_export_roundtrip_and_bounded_reads() {
        let td = TempDir::new("exp-seal").unwrap();
        let t = target(&td);
        let data = vec![0x5au8; 100_000];
        let mut f = &t.file;
        f.write_all(&data).unwrap();
        drop(t);
        let path = td.path.join(uuid()).join("export.bin");
        let sealed = seal_export_file(&path, 2 * 1024 * 1024, Some(unsafe { libc::geteuid() })).unwrap();
        assert_eq!(sealed.size, data.len() as u64);
        assert_eq!(sealed.sha256, sha256_of(&data));
        let got = sealed.read_bounded(0, 10).unwrap();
        assert_eq!(got, data[..10]);
        assert_eq!(sealed.read_bounded(99_990, 10).unwrap(), data[99_990..100_000]);
        assert_eq!(sealed.read_bounded(0, 1).unwrap(), vec![0x5a]);
        assert_eq!(sealed.read_bounded(100_000, 1), Err(ErrorCode::ExportMissing));
        assert_eq!(sealed.read_bounded(0, MAX_READ_CHUNK + 1), Err(ErrorCode::BadRequest));
        // seals are active: write/grow/shrink must fail with EPERM
        let rc = unsafe { libc::write(sealed.fd(), b"x".as_ptr() as *const libc::c_void, 1) };
        assert!(rc < 0);
        let seals = unsafe { libc::fcntl(sealed.fd(), libc::F_GET_SEALS) };
        assert_eq!(seals as i32 & (libc::F_SEAL_WRITE | libc::F_SEAL_GROW | libc::F_SEAL_SHRINK), libc::F_SEAL_WRITE | libc::F_SEAL_GROW | libc::F_SEAL_SHRINK);
    }

    #[test]
    fn seal_rejects_oversize_symlink_and_missing() {
        let td = TempDir::new("exp-seal-bad").unwrap();
        let dir = td.child(&uuid());
        std::fs::create_dir(&dir).unwrap();
        let path = dir.join("export.bin");
        std::fs::write(&path, vec![0u8; 64]).unwrap();
        assert_eq!(seal_export_file(&path, 32, None).err(), Some(ErrorCode::ExportOverflow));
        let link = dir.join("link.bin");
        std::os::unix::fs::symlink(&path, &link).unwrap();
        assert_eq!(seal_export_file(&link, 1024, None).err(), Some(ErrorCode::ExportMissing));
        assert_eq!(seal_export_file(&dir.join("nope.bin"), 1024, None).err(), Some(ErrorCode::ExportMissing));
        // wrong expected owner is rejected
        assert_eq!(seal_export_file(&path, 1024, Some(0)).err(), if unsafe { libc::geteuid() } == 0 { None } else { Some(ErrorCode::ExportMissing) });
    }

    #[test]
    fn empty_export_seals_ok() {
        let td = TempDir::new("exp-empty").unwrap();
        let t = target(&td);
        drop(t);
        let path = td.path.join(uuid()).join("export.bin");
        let sealed = seal_export_file(&path, 1024, None).unwrap();
        assert_eq!(sealed.size, 0);
        assert_eq!(sealed.sha256, sha256_of(b""));
        assert_eq!(sealed.read_bounded(0, 0).unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn owner_chown_requires_privilege() {
        let td = TempDir::new("exp-owner").unwrap();
        let res = ExportTarget::open(&td.path, &uuid(), Some((0, 0)));
        if unsafe { libc::geteuid() } == 0 {
            let t = res.unwrap();
            let md = std::fs::metadata(t.path()).unwrap();
            use std::os::unix::fs::MetadataExt;
            assert_eq!(md.uid(), 0);
        } else {
            assert_eq!(res.err(), Some(ErrorCode::ExportMissing));
        }
    }

    #[test]
    fn sealed_export_is_readable_as_file() {
        let td = TempDir::new("exp-read").unwrap();
        let t = target(&td);
        let mut f = &t.file;
        f.write_all(b"evidence-bytes").unwrap();
        drop(t);
        let path = td.path.join(uuid()).join("export.bin");
        let sealed = seal_export_file(&path, 1024, None).unwrap();
        let mut reader = std::fs::File::from(sealed.fd().try_clone_owned().unwrap());
        let mut all = Vec::new();
        reader.read_to_end(&mut all).unwrap();
        assert_eq!(all, b"evidence-bytes");
    }

    trait TryCloneOwned {
        fn try_clone_owned(&self) -> Result<OwnedFd, ErrorCode>;
    }

    impl TryCloneOwned for RawFd {
        fn try_clone_owned(&self) -> Result<OwnedFd, ErrorCode> {
            let rc = unsafe { libc::fcntl(*self, libc::F_DUPFD_CLOEXEC, 3) };
            if rc < 0 {
                return Err(ErrorCode::Internal);
            }
            Ok(unsafe { OwnedFd::from_raw_fd(rc) })
        }
    }
}
