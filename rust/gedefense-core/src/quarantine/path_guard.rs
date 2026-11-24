use super::*;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use std::{
    ffi::{CString, OsStr},
    os::{
        fd::{FromRawFd, OwnedFd},
        unix::ffi::OsStrExt,
    },
    path::{Path, PathBuf},
};

const RESOLVE_NO_MAGICLINKS: u64 = 0x02;
const RESOLVE_NO_SYMLINKS: u64 = 0x04;

#[repr(C)]
struct OpenHow {
    flags: u64,
    mode: u64,
    resolve: u64,
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

pub(super) fn decode_path(encoded: &str) -> Result<PathBuf, BoxError> {
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

pub(super) fn open_parent_and_name(path: &Path) -> Result<(OwnedFd, CString), BoxError> {
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
