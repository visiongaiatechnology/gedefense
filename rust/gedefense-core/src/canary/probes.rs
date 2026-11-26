use super::*;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use sha2::{Digest, Sha256};
use std::{
    ffi::{CString, OsString},
    fs::File,
    io::Write,
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd},
        unix::ffi::{OsStrExt, OsStringExt},
    },
    path::{Component, Path, PathBuf},
};

impl CanaryBroker {
    pub(super) fn deploy_token_inner(
        &self,
        path_token: &str,
        canary_type: &str,
        mode_token: &str,
        content_token: &str,
        require_watch: bool,
    ) -> Result<String, BoxError> {
        if !VALID_TYPES.contains(&canary_type) {
            return Err("canary type is not one of SSH_KEY, CLOUD_CRED, SHADOW_BAK, DOTENV".into());
        }
        let mode = parse_mode_token(mode_token)?;
        let content = decode_content_token(content_token)?;
        let path = decode_path_token(path_token)?;
        let (root, relative) = self.resolve_in_roots(&path)?;
        let (parent_components, basename) = split_relative(&relative)?;
        if basename.as_bytes() == MANIFEST_NAME.as_bytes() {
            return Err("canary path collides with the broker manifest".into());
        }
        let digest: [u8; 32] = Sha256::digest(&content).into();
        {
            let records = self
                .records
                .lock()
                .map_err(|_| "canary registry integrity failure")?;
            if !records.contains_key(&path) && records.len() >= MAX_REGISTERED_CANARIES {
                return Err("canary registration capacity reached".into());
            }
        }
        let parent = open_canary_parent(&root, &parent_components, true)?;
        let base_name = CString::new(basename.as_bytes())?;

        // 1. Atomic staging file inside the already validated parent directory.
        let staging_name = staging_name(basename.as_bytes())?;
        let fd = unsafe {
            libc::openat(
                parent.as_raw_fd(),
                staging_name.as_ptr(),
                libc::O_CREAT | libc::O_EXCL | libc::O_WRONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
                0o600 as libc::mode_t,
            )
        };
        if fd < 0 {
            return Err(std::io::Error::other(format!(
                "canary staging file: {}",
                std::io::Error::last_os_error()
            ))
            .into());
        }
        let mut staging = unsafe { File::from_raw_fd(fd) };
        let staging_path = root.join(render_relative(&parent_components, &staging_name));
        let result = (|| -> Result<String, BoxError> {
            staging.write_all(&content)?;
            staging.sync_all()?;
            if unsafe { libc::fchmod(staging.as_raw_fd(), mode as libc::mode_t) } != 0 {
                return Err(std::io::Error::last_os_error().into());
            }
            drop(staging);
            let rename = unsafe {
                libc::syscall(
                    libc::SYS_renameat2,
                    parent.as_raw_fd(),
                    staging_name.as_ptr(),
                    parent.as_raw_fd(),
                    base_name.as_ptr(),
                    RENAME_NOREPLACE,
                )
            };
            if rename != 0 {
                let error = std::io::Error::last_os_error();
                if error.raw_os_error() != Some(libc::EEXIST) {
                    return Err(error.into());
                }
                // A decoy already exists. The identity must match exactly
                // (regular file, root-owned by this process, expected mode and
                // digest) or the deployment fails closed instead of overwriting
                // evidence.
                let existing = open_regular_at(parent.as_raw_fd(), &base_name)?;
                let metadata = existing.metadata()?;
                if !metadata.is_file()
                    || metadata.uid() != unsafe { libc::geteuid() }
                    || (metadata.mode() & 0o7777) != mode
                {
                    return Err("canary already exists with a different identity".into());
                }
                let mut file = existing;
                let mut digest_now = Sha256::new();
                let copied = std::io::copy(&mut file, &mut digest_now)?;
                if copied > MAX_CANARY_CONTENT_BYTES as u64
                    || digest_now.finalize().as_slice() != digest
                {
                    return Err("canary already exists with a different identity".into());
                }
                self.remember_record(CanaryRecord {
                    path: path.clone(),
                    canary_type: canary_type.to_owned(),
                    mode,
                    sha256: digest,
                })?;
                if require_watch {
                    self.wait_for_mark(&path)?;
                }
                return Ok("exists".to_owned());
            }
            unsafe { libc::fsync(parent.as_raw_fd()) };
            self.remember_record(CanaryRecord {
                path: path.clone(),
                canary_type: canary_type.to_owned(),
                mode,
                sha256: digest,
            })?;
            if require_watch {
                self.wait_for_mark(&path)?;
            }
            Ok("deployed".to_owned())
        })();
        // Remove the staging file whether the rename succeeded (then it no longer
        // exists), failed, or the decoy already existed with identical identity.
        // The "exists" path returns before the rename and used to leave hidden
        // staging files in the canary directory.
        let _ = unsafe { libc::unlinkat(parent.as_raw_fd(), staging_name.as_ptr(), 0) };
        let _ = staging_path;
        result
    }

    fn remember_record(&self, record: CanaryRecord) -> Result<(), BoxError> {
        {
            let mut records = self
                .records
                .lock()
                .map_err(|_| "canary registry integrity failure")?;
            records.insert(record.path.clone(), record);
        }
        self.persist_manifest()
    }

    pub(super) fn forget_record(&self, path: &Path) {
        if let Ok(mut records) = self.records.lock() {
            records.remove(path);
        }
        self.unmark_path(path);
        let _ = self.persist_manifest();
    }

    pub(super) fn resolve_in_roots(&self, path: &Path) -> Result<(PathBuf, Vec<OsString>), BoxError> {
        let mut best: Option<(usize, PathBuf, Vec<OsString>)> = None;
        for root in self.roots.iter() {
            if !path.starts_with(root) || path == root {
                continue;
            }
            let relative: Vec<OsString> = path
                .strip_prefix(root)
                .map_err(|_| "canary path is outside every configured canary root")?
                .components()
                .map(|component| match component {
                    Component::Normal(name) => Ok(name.to_os_string()),
                    _ => Err("canary relative path contains a non-normal component"),
                })
                .collect::<Result<Vec<_>, _>>()?;
            if relative.is_empty() {
                continue;
            }
            let root_components = root.components().count();
            if best
                .as_ref()
                .map(|(depth, _, _)| root_components > *depth)
                .unwrap_or(true)
            {
                best = Some((root_components, root.clone(), relative));
            }
        }
        match best {
            Some((_, root, relative)) => Ok((root, relative)),
            None => Err("canary path is outside every configured canary root".into()),
        }
    }
}

// ------------------------------------------------------------------ helpers

pub(super) fn validate_absolute_clean(path: &Path, label: &str) -> Result<(), BoxError> {
    if !path.is_absolute() || path == Path::new("/") {
        return Err(format!("{label} must be absolute and non-root").into());
    }
    let mut components = path.components();
    if !matches!(components.next(), Some(Component::RootDir)) {
        return Err(format!("{label} must start at the filesystem root").into());
    }
    for component in components {
        match component {
            Component::Normal(_) => {}
            _ => return Err(format!("{label} contains a non-normal component").into()),
        }
    }
    Ok(())
}

pub(super) fn decode_path_token(token: &str) -> Result<PathBuf, BoxError> {
    if token.is_empty() || token.len() > 4096 {
        return Err("canary path token is outside bounds".into());
    }
    let raw = URL_SAFE_NO_PAD.decode(token)?;
    if raw.is_empty() || raw.len() > MAX_CANARY_PATH_BYTES || raw.contains(&0) {
        return Err("canary path is outside bounds".into());
    }
    let path = PathBuf::from(OsString::from_vec(raw));
    validate_absolute_clean(&path, "canary path")?;
    Ok(path)
}

fn decode_content_token(token: &str) -> Result<Vec<u8>, BoxError> {
    if token.is_empty() || token.len() > ((MAX_CANARY_CONTENT_BYTES + 2) / 3) * 4 + 4 {
        return Err("canary content token is outside bounds".into());
    }
    let raw = URL_SAFE_NO_PAD.decode(token)?;
    if raw.is_empty() || raw.len() > MAX_CANARY_CONTENT_BYTES || raw.contains(&0) {
        return Err("canary content is outside bounds".into());
    }
    Ok(raw)
}

fn parse_mode_token(token: &str) -> Result<u32, BoxError> {
    if token.is_empty() || token.len() > 4 {
        return Err("canary mode token is outside bounds".into());
    }
    let mode = u32::from_str_radix(token, 8)?;
    if !VALID_MODES.contains(&mode) {
        return Err("canary mode must be 0600 or 0640".into());
    }
    Ok(mode)
}

pub(super) fn split_relative(relative: &[OsString]) -> Result<(Vec<OsString>, OsString), BoxError> {
    let (basename, parent) = relative
        .split_last()
        .ok_or("canary relative path is empty")?;
    if basename.is_empty() || basename.as_bytes() == b"." || basename.as_bytes() == b".." {
        return Err("canary basename is invalid".into());
    }
    Ok((parent.to_vec(), basename.clone()))
}

pub(super) fn open_canary_parent(
    root: &Path,
    parent_components: &[OsString],
    create: bool,
) -> Result<OwnedFd, BoxError> {
    let root_c = CString::new(root.as_os_str().as_bytes())?;
    let root_fd = unsafe {
        libc::open(
            root_c.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if root_fd < 0 {
        return Err(std::io::Error::other(format!(
            "canary root open {}: {}",
            root.display(),
            std::io::Error::last_os_error()
        ))
        .into());
    }
    let mut current = unsafe { OwnedFd::from_raw_fd(root_fd) };
    for component in parent_components {
        let name = CString::new(component.as_bytes())?;
        if create {
            let mkdir =
                unsafe { libc::mkdirat(current.as_raw_fd(), name.as_ptr(), 0o750 as libc::mode_t) };
            if mkdir != 0 {
                let error = std::io::Error::last_os_error();
                if error.raw_os_error() != Some(libc::EEXIST) {
                    return Err(
                        std::io::Error::other(format!("canary parent directory: {error}")).into(),
                    );
                }
            }
        }
        let fd = unsafe {
            libc::openat(
                current.as_raw_fd(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            )
        };
        if fd < 0 {
            return Err(std::io::Error::other(format!(
                "canary parent component rejected (symlink or non-directory): {}",
                std::io::Error::last_os_error()
            ))
            .into());
        }
        current = unsafe { OwnedFd::from_raw_fd(fd) };
    }
    Ok(current)
}

pub(super) fn open_regular_at(parent_fd: i32, name: &CString) -> Result<File, BoxError> {
    let fd = unsafe {
        libc::openat(
            parent_fd,
            name.as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let file = unsafe { File::from_raw_fd(fd) };
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err("canary target must be a regular non-symlink file".into());
    }
    Ok(file)
}

fn render_relative(parent: &[OsString], name: &CString) -> PathBuf {
    let mut path = PathBuf::new();
    for component in parent {
        path.push(component);
    }
    path.push(std::ffi::OsStr::from_bytes(name.as_bytes()));
    path
}

fn staging_name(basename: &[u8]) -> Result<CString, BoxError> {
    if basename.is_empty() || basename.len() > 128 {
        return Err("canary basename is outside bounds".into());
    }
    let token = random_hex(8)?;
    let mut name = Vec::with_capacity(basename.len() + 32);
    name.push(b'.');
    name.extend_from_slice(basename);
    name.extend_from_slice(b".canary.");
    name.extend_from_slice(token.as_bytes());
    name.extend_from_slice(b".tmp");
    Ok(CString::new(name)?)
}

pub(super) fn random_hex(bytes: usize) -> Result<String, BoxError> {
    if bytes == 0 || bytes > 32 {
        return Err("random token size is outside bounds".into());
    }
    let mut buffer = vec![0u8; bytes];
    let filled = unsafe {
        libc::syscall(
            libc::SYS_getrandom,
            buffer.as_mut_ptr().cast::<libc::c_void>(),
            buffer.len(),
            0u32,
        )
    };
    if filled == bytes as libc::c_long {
        return Ok(hex::encode(buffer));
    }
    // The sandbox has never been observed to block getrandom; a fallback keeps
    // deployments working if a kernel policy ever does. Uniqueness only needs
    // to survive a concurrent writer, so monotonic time plus pid is sufficient.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|value| value.as_nanos())
        .unwrap_or(0);
    let seed = format!("{}-{}-{now}", std::process::id(), bytes);
    let digest = Sha256::digest(seed.as_bytes());
    let mut fallback = digest.to_vec();
    fallback.truncate(bytes);
    Ok(hex::encode(fallback))
}
