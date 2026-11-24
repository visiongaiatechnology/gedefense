use super::*;

/// `openat2(2)` argument structure (linux/openat2.h, stable UAPI).
#[repr(C)]
pub(super) struct OpenHow {
    pub(super) flags: u64,
    pub(super) mode: u64,
    pub(super) resolve: u64,
}

/// One symlink-safe resolved watched object.
#[derive(Clone, Debug)]
pub(super) struct ResolvedIdentity {
    /// Canonical path of the opened object (from the descriptor, never a
    /// path re-resolution after the identity was read).
    pub(super) canonical: PathBuf,
    pub(super) dev: u32,
    pub(super) ino: u64,
    pub(super) uid: u32,
    pub(super) is_dir: bool,
    pub(super) is_file: bool,
}

// ---------------------------------------------------------------------------
// Symlink-safe path resolution (same contract as AP-1 `exec_inode.rs`)
// ---------------------------------------------------------------------------

/// Resolves one watch path to its real `(st_dev, st_ino)` identity without
/// following a final-component symlink and without trusting a path string.
///
/// The strict `openat2(RESOLVE_NO_SYMLINKS|NO_MAGICLINKS)` probe is the primary
/// resolver (see the AP-1 pattern in `exec_inode.rs`). Vendor-managed prefix
/// symlinks (`/lib -> usr/lib`, a symlinked home directory) are not an attack
/// signal, so on such a failure the path is canonicalised once and the
/// canonicalised path is re-opened with the same no-symlink resolve flags. On
/// kernels/sandboxes that answer `ENOSYS`/`EINVAL` the component-wise
/// `O_NOFOLLOW` walk is used. The identity always comes from `fstat` on the
/// descriptor; the canonical path is read from `/proc/self/fd/<fd>`, so a
/// rename between resolution and use cannot redirect a later hash/scan.
pub(super) fn resolve_identity(path: &Path, want_dir: bool) -> Result<ResolvedIdentity, String> {
    let mut flags = libc::O_PATH | libc::O_CLOEXEC;
    if want_dir {
        flags |= libc::O_DIRECTORY;
    }
    let file = match openat2_no_symlinks(path, flags) {
        Ok(file) => file,
        Err(error) => match error.raw_os_error() {
            Some(libc::ENOSYS) | Some(libc::EINVAL) => crate::open_componentwise(path, flags)
                .map_err(|error| format!("open {} failed: {error}", path.display()))?,
            _ => {
                let canonical = fs::canonicalize(path)
                    .map_err(|error| format!("resolve {} failed: {error}", path.display()))?;
                openat2_no_symlinks(&canonical, flags).map_err(|error| {
                    format!("open resolved {} failed: {error}", canonical.display())
                })?
            }
        },
    };
    let metadata = file
        .metadata()
        .map_err(|error| format!("fstat {} failed: {error}", path.display()))?;
    // The descriptor path is the race-free canonical name. A hardened/container
    // host without a readable `/proc/self/fd` falls back to `canonicalize`; the
    // identity above still comes from `fstat` on the descriptor, never from the
    // path string.
    let canonical = match fs::read_link(format!("/proc/self/fd/{}", file.as_raw_fd())) {
        Ok(descriptor_path) => {
            if descriptor_path
                .as_os_str()
                .as_bytes()
                .ends_with(b" (deleted)")
            {
                return Err(format!("{} was unlinked while resolving", path.display()));
            }
            if descriptor_path.is_absolute() {
                descriptor_path
            } else {
                fs::canonicalize(path)
                    .map_err(|error| format!("canonical path {} failed: {error}", path.display()))?
            }
        }
        Err(_) => fs::canonicalize(path)
            .map_err(|error| format!("canonical path {} failed: {error}", path.display()))?,
    };
    if want_dir && !metadata.is_dir() {
        return Err(format!("{} is not a directory", path.display()));
    }
    let dev = u32::try_from(metadata.dev())
        .map_err(|_| format!("{} device id does not fit u32", path.display()))?;
    let ino = metadata.ino();
    if dev == 0 || ino == 0 {
        return Err(format!("{} resolved a zero identity", path.display()));
    }
    Ok(ResolvedIdentity {
        canonical,
        dev,
        ino,
        uid: metadata.uid(),
        is_dir: metadata.is_dir(),
        is_file: metadata.is_file(),
    })
}

/// Opens one resolved path for reading with the same no-follow discipline.
pub(super) fn open_watch_read(path: &Path) -> Result<File, BoxError> {
    let flags = libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK;
    match openat2_no_symlinks(path, flags) {
        Ok(file) => Ok(file),
        Err(error) => match error.raw_os_error() {
            Some(libc::ENOSYS) | Some(libc::EINVAL) => {
                crate::open_componentwise(path, flags).map_err(|error| error.into())
            }
            _ => Err(format!("open {} failed: {error}", path.display()).into()),
        },
    }
}

/// Bounded, regular-file-only SHA-256 of one path. The descriptor is opened
/// before the size is read, so a rename/symlink race cannot redirect the hash to
/// another object between check and read.
pub(super) fn hash_watch_file(path: &Path, remaining_budget: &mut u64) -> Result<[u8; 32], String> {
    let mut file = open_watch_read(path).map_err(|error| format!("{error}"))?;
    let metadata = file
        .metadata()
        .map_err(|error| format!("fstat failed: {error}"))?;
    if !metadata.is_file() {
        return Err("not a regular file".to_owned());
    }
    let limit = MAX_BASELINE_FILE_BYTES.min(*remaining_budget);
    if limit == 0 {
        return Err("baseline byte budget exhausted".to_owned());
    }
    if metadata.len() > MAX_BASELINE_FILE_BYTES {
        return Err("file exceeds the 16 MiB baseline bound".to_owned());
    }
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    let mut total = 0u64;
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|error| format!("read failed: {error}"))?;
        if read == 0 {
            break;
        }
        total = total.saturating_add(read as u64);
        if total > limit {
            return Err("file grew beyond the baseline byte budget".to_owned());
        }
        hasher.update(&buffer[..read]);
    }
    *remaining_budget = remaining_budget.saturating_sub(total);
    let digest = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&digest);
    Ok(hash)
}

/// Bounded file read (used for BTF and tracefs format files).
pub(super) fn read_bounded_file(path: &Path, limit: u64) -> Result<Vec<u8>, String> {
    let file =
        fs::File::open(path).map_err(|error| format!("open {} failed: {error}", path.display()))?;
    let length = file
        .metadata()
        .map_err(|error| format!("stat {} failed: {error}", path.display()))?
        .len();
    if length > limit {
        return Err(format!("{} exceeds the {limit} byte bound", path.display()));
    }
    let mut data = Vec::with_capacity(length as usize + 1);
    file.take(limit + 1)
        .read_to_end(&mut data)
        .map_err(|error| format!("read {} failed: {error}", path.display()))?;
    if data.len() as u64 > limit {
        return Err(format!(
            "{} grew beyond the {limit} byte bound",
            path.display()
        ));
    }
    Ok(data)
}

pub(super) fn unix_millis_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0)
}

/// Effective uid of the core process (used as the producer identity of the
/// userspace drift/baseline records; the kernel records always carry the real
/// opener identity).
pub(super) fn current_euid() -> u32 {
    // SAFETY: geteuid has no preconditions and cannot fail.
    unsafe { libc::geteuid() }
}

// ---------------------------------------------------------------------------
// Minimal, bounded vmlinux BTF field/arity resolver
// ---------------------------------------------------------------------------

impl PersistenceCore {
    pub(super) fn populate_path_contract(&mut self) {
        self.clear_path_maps();
        self.baseline_candidates.clear();
        self.baseline_skips = 0;
        self.skipped_paths = 0;
        self.capacity_skips = 0;
        let mut candidates: Vec<(PathBuf, u8)> = Vec::new();

        // Linker (`L5`): preload/configuration/TLS/loader binaries.
        self.watch_exact_file(
            Path::new("/etc/ld.so.preload"),
            PERSIST_CLASS_LD_PRELOAD,
            true,
            &mut candidates,
        );
        self.watch_exact_file(
            Path::new("/etc/ld.so.conf"),
            PERSIST_CLASS_LD_CONF,
            true,
            &mut candidates,
        );
        self.watch_directory(
            Path::new("/etc/ld.so.conf.d"),
            PERSIST_CLASS_LD_CONF,
            true,
            |name| name.ends_with(".conf"),
            256,
            true,
            &mut candidates,
        );
        for directory in [
            "/lib/tls",
            "/lib64/tls",
            "/usr/lib/tls",
            "/usr/lib64/tls",
            "/lib/x86_64-linux-gnu/tls",
            "/usr/lib/x86_64-linux-gnu/tls",
        ] {
            self.watch_directory(
                Path::new(directory),
                PERSIST_CLASS_TLS,
                true,
                |_| true,
                64,
                true,
                &mut candidates,
            );
        }
        for loader in [
            "/lib64/ld-linux-x86-64.so.2",
            "/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2",
            "/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2",
            "/lib/ld-linux.so.2",
        ] {
            self.watch_exact_file(
                Path::new(loader),
                PERSIST_CLASS_LD_SO,
                true,
                &mut candidates,
            );
        }

        // PAM (`L5`): module libraries and the service configuration directory.
        for directory in [
            "/lib/security",
            "/lib64/security",
            "/usr/lib/security",
            "/usr/lib64/security",
            "/lib/x86_64-linux-gnu/security",
            "/usr/lib/x86_64-linux-gnu/security",
            "/usr/local/lib/security",
        ] {
            self.watch_directory(
                Path::new(directory),
                PERSIST_CLASS_PAM,
                true,
                |name| name.starts_with("pam_") && name.contains(".so"),
                256,
                true,
                &mut candidates,
            );
        }
        self.watch_directory(
            Path::new("/etc/pam.d"),
            PERSIST_CLASS_PAM,
            true,
            |name| !name.starts_with('.'),
            256,
            true,
            &mut candidates,
        );

        // systemd generators and unit drop-ins (`L5`).
        for directory in [
            "/etc/systemd/system-generators",
            "/lib/systemd/system-generators",
            "/usr/local/lib/systemd/system-generators",
            "/usr/lib/systemd/system-generators",
        ] {
            self.watch_directory(
                Path::new(directory),
                PERSIST_CLASS_SYSTEMD_GENERATOR,
                true,
                |name| !name.starts_with('.'),
                128,
                true,
                &mut candidates,
            );
        }
        for base in [
            "/etc/systemd/system",
            "/lib/systemd/system",
            "/usr/lib/systemd/system",
        ] {
            self.watch_systemd_base(Path::new(base), &mut candidates);
        }

        // udev (`L5`): rule directories and the main configuration file.
        for directory in [
            "/etc/udev/rules.d",
            "/lib/udev/rules.d",
            "/usr/lib/udev/rules.d",
            "/run/udev/rules.d",
        ] {
            self.watch_directory(
                Path::new(directory),
                PERSIST_CLASS_UDEV,
                true,
                |name| name.ends_with(".rules"),
                256,
                true,
                &mut candidates,
            );
        }
        self.watch_exact_file(
            Path::new("/etc/udev/udev.conf"),
            PERSIST_CLASS_UDEV,
            true,
            &mut candidates,
        );
        self.watch_exact_file(
            Path::new("/etc/ssh/sshrc"),
            PERSIST_CLASS_SSHRC,
            true,
            &mut candidates,
        );

        // System shell/profile hooks.
        for profile in [
            "/etc/profile",
            "/etc/bash.bashrc",
            "/etc/bashrc",
            "/etc/zsh/zshrc",
            "/etc/zshrc",
            "/etc/csh.cshrc",
            "/etc/csh.login",
            "/etc/environment",
        ] {
            self.watch_exact_file(
                Path::new(profile),
                PERSIST_CLASS_SHELL_PROFILE,
                true,
                &mut candidates,
            );
        }
        self.watch_directory(
            Path::new("/etc/profile.d"),
            PERSIST_CLASS_SHELL_PROFILE,
            true,
            |name| !name.starts_with('.'),
            256,
            true,
            &mut candidates,
        );

        // Per-user persistence and secret-store roots (bounded user list).
        let homes = enumerate_home_directories();
        for home in &homes {
            self.watch_exact_file(
                &home.join(".ssh/authorized_keys"),
                PERSIST_CLASS_AUTHORIZED_KEYS,
                true,
                &mut candidates,
            );
            for profile in [
                ".bashrc",
                ".bash_profile",
                ".bash_login",
                ".profile",
                ".zshrc",
                ".zshenv",
                ".config/fish/config.fish",
            ] {
                self.watch_exact_file(
                    &home.join(profile),
                    PERSIST_CLASS_SHELL_PROFILE,
                    true,
                    &mut candidates,
                );
            }
            for (relative, class) in [
                (".ssh", PERSIST_CLASS_SECRET_SSH),
                (".gnupg", PERSIST_CLASS_SECRET_GNUPG),
                (".gnupg/private-keys-v1.d", PERSIST_CLASS_SECRET_GNUPG),
                (".aws", PERSIST_CLASS_SECRET_CLOUD),
                (".local/share/keyrings", PERSIST_CLASS_SECRET_KEYRING),
                (".gnome2/keyrings", PERSIST_CLASS_SECRET_KEYRING),
            ] {
                self.watch_directory_only(&home.join(relative), class);
            }
            for browser in [
                ".config/google-chrome",
                ".config/chromium",
                ".config/BraveSoftware",
                ".config/microsoft-edge",
                ".mozilla/firefox",
            ] {
                let root = home.join(browser);
                // The browser root covers `Local State` and the profile
                // directories themselves; known profiles are additionally
                // watched so `Login Data`/`Cookies`/`logins.json` are direct
                // children of a watched directory.
                self.watch_directory_only(&root, PERSIST_CLASS_SECRET_BROWSER);
                self.watch_browser_profiles(&root);
            }
        }

        // Desktop peripherals (`L6`): devices plus Wayland/PipeWire/Pulse roots.
        self.watch_peripheral_devices();
        self.watch_capture_sockets();

        self.baseline_candidates = candidates;
        eprintln!(
            "GeDefense persistence path contract: paths={} devices={} secrets={} baseline_candidates={} skipped={} capacity={}",
            self.paths.len(),
            self.device_entries,
            self.secret_entries,
            self.baseline_candidates.len(),
            self.skipped_paths,
            self.capacity_skips
        );
    }
}

impl PersistenceCore {
    pub(super) fn clear_path_maps(&mut self) {
        let keys: Vec<[u8; 16]> = self.paths.keys().copied().collect();
        let mut failures = 0u32;
        for key in keys {
            if self.paths_map.remove(&key).is_err() {
                failures = failures.saturating_add(1);
            }
        }
        if failures > 0 {
            eprintln!("persistence guard: {failures} stale path map entries could not be removed");
        }
        self.paths.clear();
        self.device_entries = 0;
        self.secret_entries = 0;
    }
}

impl PersistenceCore {
    pub(super) fn clear_exec_maps(&mut self) {
        let keys: Vec<[u8; 16]> = self.execs.keys().copied().collect();
        for key in keys {
            let _ = self.execs_map.remove(&key);
        }
        self.execs.clear();
    }
}
