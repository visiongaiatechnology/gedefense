//! Wave 3a extraction: the malware/quarantine/canary command surface
//! (`MALWARE_*`, `QUARANTINE_*`, `CANARY_*`) and the component-wise path opener
//! formerly inline in `main.rs`.

use crate::*;

pub(crate) fn parse_quarantine_identity(token: &str) -> Result<FileIdentity, BoxError> {
    FileIdentity::decode(token)
}

// F-HOTFIX-4: systemd's RestrictSUIDSGID=yes makes the kernel return ENOSYS
// for openat2 on this sandbox (observed on Ubuntu 24.04/systemd 255 with
// RestrictSUIDSGID enabled), which broke quarantine and user-scan path
// resolution even though openat() is fully permitted. Resolve a path
// component-wise with openat(O_NOFOLLOW) as a safe fallback: every component
// is opened relative to the already validated parent descriptor and symbolic
// links are refused at every step.
pub(crate) fn open_componentwise(path: &std::path::Path, final_flags: i32) -> Result<std::fs::File, BoxError> {
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    let mut components = path.components();
    let anchor = match components.next() {
        Some(std::path::Component::RootDir) => {
            let fd = unsafe {
                libc::open(
                    c"/".as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
                )
            };
            if fd < 0 {
                return Err(std::io::Error::last_os_error().into());
            }
            unsafe { OwnedFd::from_raw_fd(fd) }
        }
        _ => return Err("component-wise open requires an absolute path".into()),
    };
    let remaining: std::path::PathBuf = components.collect();
    open_componentwise_from(anchor.as_raw_fd(), &remaining, final_flags)
}

// Resolve an already validated relative path one component at a time from an
// open anchor directory descriptor. The anchor descriptor is the trust boundary:
// no component can leave it (`..` and root components are rejected), and
// O_NOFOLLOW refuses a symlink at every step. Used as the openat2 fallback for
// both the absolute-path scan open and the home-anchored quarantine open.
pub(crate) fn open_componentwise_from(
    anchor: std::os::fd::RawFd,
    relative: &std::path::Path,
    final_flags: i32,
) -> Result<std::fs::File, BoxError> {
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    if relative.is_absolute() || relative.as_os_str().is_empty() {
        return Err("component-wise open requires a relative file path".into());
    }
    let duplicate = unsafe { libc::fcntl(anchor, libc::F_DUPFD_CLOEXEC, 3) };
    if duplicate < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let mut current: OwnedFd = unsafe { OwnedFd::from_raw_fd(duplicate) };
    let components: Vec<_> = relative.components().collect();
    let mut opened = false;
    for (index, component) in components.iter().enumerate() {
        match component {
            std::path::Component::Normal(name) => {
                let name_c = std::ffi::CString::new(name.as_encoded_bytes())?;
                let is_last = index + 1 == components.len();
                let flags = if is_last {
                    final_flags | libc::O_CLOEXEC | libc::O_NOFOLLOW
                } else {
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW
                };
                let fd = unsafe { libc::openat(current.as_raw_fd(), name_c.as_ptr(), flags) };
                if fd < 0 {
                    return Err(std::io::Error::last_os_error().into());
                }
                current = unsafe { OwnedFd::from_raw_fd(fd) };
                opened = true;
            }
            std::path::Component::CurDir => continue,
            _ => return Err("component-wise open rejects parent or root components".into()),
        }
    }
    if !opened {
        return Err("component-wise open requires a file component".into());
    }
    Ok(std::fs::File::from(current))
}

pub(crate) fn dispatch(
    core: &mut KernelCore,
    quarantine: &QuarantineBroker,
    scanner: &MalwareScanner,
    canary: &CanaryBroker,
    parts: &[&str],
) -> Result<Option<String>, BoxError> {
    let result = match parts {
        ["MALWARE_EVENTS"] => scanner.take_events(),
        ["MALWARE_STATUS"] => Ok(scanner.status()),
        ["MALWARE_SCAN", path] => scanner.inspect_token(path),
        ["QUARANTINE_INSPECT", path] => quarantine.inspect_token(path),
        ["QUARANTINE_APPLY", path, object_id, identity] => {
            quarantine.quarantine_token(path, object_id, &parse_quarantine_identity(identity)?)
        }
        ["QUARANTINE_VERIFY", object_id, identity] => {
            quarantine.verify_object(object_id, &parse_quarantine_identity(identity)?)
        }
        ["QUARANTINE_RESTORE", path, object_id, identity] => {
            quarantine.restore_token(path, object_id, &parse_quarantine_identity(identity)?)
        }
        // V6.3.0 AP-7: signed false-positive vault prune after a verified restore.
        ["QUARANTINE_PRUNE", object_id, identity] => {
            quarantine.prune_token(object_id, &parse_quarantine_identity(identity)?)
        }
        ["CANARY_DEPLOY", path, canary_type, mode, content] => {
            canary.deploy_token(path, canary_type, mode, content)
        }
        ["CANARY_REMOVE", path] => canary.remove_token(path),
        ["CANARY_EVENTS"] => canary.take_events(),
        ["CANARY_STATUS"] => Ok(canary.status()),
        ["MALWARE_INODE_LOCK", dev, ino, ttl] => {
            core.exec_inode.lock_malware_inode(dev, ino, ttl)
        }
        ["MALWARE_INODE_UNLOCK", dev, ino] => core.exec_inode.unlock_malware_inode(dev, ino),
        ["MALWARE_INODE_STATUS"] => Ok(core.exec_inode.malware_lock_status()),
        _ => return Ok(None),
    };
    Ok(Some(result?))
}
