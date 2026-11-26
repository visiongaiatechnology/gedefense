use super::*;

impl ExecInodeCore {
    pub(super) fn enabled(&self) -> bool {
        self.armed && self.offsets_ok
    }
}

impl ExecInodeCore {
    /// Resolves the default trusted path contract into `(s_dev, i_ino)` identity
    /// keys. Missing paths are skipped and counted; nothing is guessed.
    pub(super) fn populate_default_trust(&mut self) {
        for path in AUTH_EXEC_PATHS {
            let flags = EXEC_INODE_ALLOW_CRED_READ | EXEC_INODE_ALLOW_RANSOM_FULL;
            self.insert_default_path(path, flags);
        }
        // V6.3.0 AP-1 fix: `/opt/vgt/gedefense/current` is an upgrade symlink, so
        // `openat2(RESOLVE_NO_SYMLINKS)` intentionally rejects it. Derive the
        // concrete release root from the kernel-resolved `/proc/self/exe` target
        // so packaged `gedefense-control`, `gedefense-core`, and `gedefense-cell-helper`
        // binaries resolve without following symlinks and are never locked out of
        // `/etc/vgt/gedefense/secrets/*`.
        for path in Self::sibling_release_binaries() {
            if let Some(s) = path.to_str() {
                let flags = EXEC_INODE_ALLOW_CRED_READ | EXEC_INODE_ALLOW_RANSOM_FULL;
                self.insert_default_path(s, flags);
            }
        }
        for path in SYSTEM_RANSOM_PATHS {
            self.insert_default_path(path, EXEC_INODE_ALLOW_RANSOM_FULL);
        }
        for path in POOL_SERVICE_PATHS {
            self.insert_default_path(path, EXEC_INODE_ALLOW_RANSOM_POOL_META);
        }
    }

    fn sibling_release_binaries() -> Vec<PathBuf> {
        let mut out = Vec::new();
        if let Ok(self_exe) = fs::read_link("/proc/self/exe") {
            if let Some(release_root) = self_exe.parent().and_then(|p| p.parent()) {
                out.push(release_root.join("bin/gedefense-control"));
                out.push(release_root.join("libexec/gedefense-core"));
                out.push(release_root.join("libexec/gedefense-cell-helper"));
            }
        }
        out
    }

    /// Registers GeDefense's own executables in `SELF_DAEMON_INODES` so they can
    /// quarantine malware-locked inodes without any spoofable `comm` allowlist.
    pub(super) fn populate_self_daemon_inodes(&mut self) {
        let Some(ref mut map) = self.self_daemons else {
            return;
        };
        let mut candidates: Vec<PathBuf> = Self::sibling_release_binaries();
        candidates.push(PathBuf::from("/usr/bin/gedefense-control"));
        if let Ok(self_exe) = fs::read_link("/proc/self/exe") {
            candidates.push(self_exe);
        }
        for path in candidates {
            if let Ok((dev, ino)) = resolve_executable_identity(&path) {
                let key = exec_inode_key(dev, ino);
                if let Err(error) = map.insert(&key, 1u8, 0) {
                    eprintln!(
                        "exec-inode gate: self-daemon insert for {} failed: {error}",
                        path.display()
                    );
                }
            }
        }
    }
}

impl ExecInodeCore {
    pub(super) fn insert_default_path(&mut self, label: &str, flags: u32) {
        match resolve_executable_identity(Path::new(label)) {
            Ok((dev, ino)) => {
                let key = exec_inode_key(dev, ino);
                if self.trusted_entries.len() >= EXEC_INODE_TRUSTED_CAPACITY {
                    eprintln!("exec-inode gate: trusted inode capacity reached; {label} skipped");
                    return;
                }
                match self.trusted.insert(&key, flags, 0) {
                    Ok(()) => {
                        self.trusted_entries.insert(key, flags);
                    }
                    Err(error) => {
                        eprintln!(
                            "exec-inode gate: trusted map insert for {label} failed: {error}"
                        );
                    }
                }
            }
            Err(error) => {
                self.missing_paths = self.missing_paths.saturating_add(1);
                eprintln!("exec-inode gate: {label} skipped ({error})");
            }
        }
    }
}

impl ExecInodeCore {
    /// `EXEC_INODE_ALLOW_ADD <path_b64?> <flags>` (path protocol token).
    pub(crate) fn allow_add(&mut self, path: &str, flags: &str) -> Result<String, BoxError> {
        let flags = parse_flags_token(flags)?;
        let path = decode_path_token(path)?;
        validate_trust_path(&path)?;
        let (dev, ino) = resolve_executable_identity(&path)?;
        let key = exec_inode_key(dev, ino);
        if !self.trusted_entries.contains_key(&key)
            && self.trusted_entries.len() >= EXEC_INODE_TRUSTED_CAPACITY
        {
            return Err("exec-inode trusted map capacity exhausted".into());
        }
        self.trusted.insert(&key, flags, 0)?;
        self.trusted_entries.insert(key, flags);
        Ok("applied".to_owned())
    }
}

impl ExecInodeCore {
    /// `EXEC_INODE_ALLOW_DEL <dev> <ino>`.
    pub(crate) fn allow_del(&mut self, dev: &str, ino: &str) -> Result<String, BoxError> {
        let dev = parse_dev_token(dev)?;
        let ino = parse_ino_token(ino)?;
        let key = exec_inode_key(dev, ino);
        if self.trusted_entries.remove(&key).is_none() {
            return Err("trusted exec inode not present".into());
        }
        match self.trusted.remove(&key) {
            Ok(()) | Err(aya::maps::MapError::KeyNotFound) => Ok("deleted".to_owned()),
            Err(error) => Err(error.into()),
        }
    }
}

impl ExecInodeCore {
    /// `EXEC_INODE_CLEAR`.
    pub(crate) fn clear(&mut self) -> Result<String, BoxError> {
        let keys: Vec<[u8; 16]> = self.trusted_entries.keys().copied().collect();
        for key in &keys {
            match self.trusted.remove(key) {
                Ok(()) | Err(aya::maps::MapError::KeyNotFound) => {}
                Err(error) => {
                    return Err(format!("exec-inode CLEAR failed: {error}").into());
                }
            }
        }
        self.trusted_entries.clear();
        Ok("cleared".to_owned())
    }
}

/// Capacity mirror of the BPF map (`EXEC_INODE_TRUST_MAP_ENTRIES`).
pub(super) const EXEC_INODE_TRUSTED_CAPACITY: usize = 2048;

/// One 16-byte identity key -> `(dev, ino)` decode failure message.
pub(super) fn decimal_digits_only(token: &str) -> bool {
    !token.is_empty() && token.bytes().all(|byte| byte.is_ascii_digit())
}

pub(super) fn parse_dev_token(token: &str) -> Result<u32, BoxError> {
    if token.len() > 10 || !decimal_digits_only(token) {
        return Err("exec-inode dev token is not a bounded decimal u32".into());
    }
    let dev: u32 = token
        .parse()
        .map_err(|_| -> BoxError { "exec-inode dev token is not a decimal u32".into() })?;
    if dev == 0 {
        return Err("exec-inode dev must not be zero".into());
    }
    Ok(dev)
}

pub(super) fn parse_ino_token(token: &str) -> Result<u64, BoxError> {
    if token.len() > 20 || !decimal_digits_only(token) {
        return Err("exec-inode ino token is not a bounded decimal u64".into());
    }
    let ino: u64 = token
        .parse()
        .map_err(|_| -> BoxError { "exec-inode ino token is not a decimal u64".into() })?;
    if ino == 0 {
        return Err("exec-inode ino must not be zero".into());
    }
    Ok(ino)
}

pub(super) fn parse_flags_token(token: &str) -> Result<u32, BoxError> {
    if token.len() > 10 || !decimal_digits_only(token) {
        return Err("exec-inode flag token is not a bounded decimal u32".into());
    }
    let flags: u32 = token
        .parse()
        .map_err(|_| -> BoxError { "exec-inode flag token is not a decimal u32".into() })?;
    if !exec_inode_flags_valid(flags) {
        return Err("exec-inode flags must be a non-zero subset of ALLOW_CRED_READ|ALLOW_RANSOM_FULL|ALLOW_RANSOM_POOL_META".into());
    }
    Ok(flags)
}

/// Decodes `EXEC_INODE_ALLOW_ADD`'s path token: either a plain absolute path or
/// a base64url(path) token (the VGT3 field cannot carry spaces otherwise).
pub(super) fn decode_path_token(token: &str) -> Result<PathBuf, BoxError> {
    if token.is_empty() || token.len() > MAX_EXEC_INODE_PATH_BYTES {
        return Err("exec-inode path token is outside bounds".into());
    }
    let raw = if token.starts_with('/') {
        token.as_bytes().to_vec()
    } else {
        let decoded = URL_SAFE_NO_PAD
            .decode(token)
            .map_err(|_| -> BoxError { "exec-inode path token is not valid base64url".into() })?;
        if decoded.is_empty() || decoded.len() > MAX_EXEC_INODE_PATH_BYTES {
            return Err("exec-inode decoded path is outside bounds".into());
        }
        decoded
    };
    if raw.contains(&0) {
        return Err("exec-inode path token contains a NUL byte".into());
    }
    let path = PathBuf::from(OsStr::from_bytes(&raw));
    validate_trust_path(&path)?;
    Ok(path)
}

/// Sanitisation of a trusted-path token: absolute, bounded, component-clean
/// (no `..`, no interior root), regular-file resolution is checked later.
pub(super) fn validate_trust_path(path: &Path) -> Result<(), BoxError> {
    if !path.is_absolute() {
        return Err("exec-inode trusted path must be absolute".into());
    }
    if path.as_os_str().as_bytes().len() > MAX_EXEC_INODE_PATH_BYTES {
        return Err("exec-inode trusted path exceeds the path bound".into());
    }
    let mut components = path.components();
    match components.next() {
        Some(Component::RootDir) => {}
        _ => return Err("exec-inode trusted path must start at the root".into()),
    }
    let mut basename_seen = false;
    for component in components {
        match component {
            Component::Normal(_) => basename_seen = true,
            Component::CurDir => {}
            _ => return Err("exec-inode trusted path rejects parent/root components".into()),
        }
    }
    if !basename_seen {
        return Err("exec-inode trusted path has no basename".into());
    }
    Ok(())
}
