use super::*;

/// Bounded users/directories/package-database scans.
pub(super) const MAX_USERS: usize = 64;
pub(super) const MAX_DIR_CHILDREN: usize = 512;
pub(super) const MAX_SYSTEMD_UNIT_CHILDREN: usize = 1_024;

impl PersistenceCore {
    /// Resolves and inserts one exact watched file. Missing/non-regular paths are
    /// skipped and counted; the path is still retained as a baseline candidate
    /// so an appearing file (the classic `ld.so.preload` attack) is detected.
    pub(super) fn watch_exact_file(
        &mut self,
        path: &Path,
        class: u8,
        baseline: bool,
        candidates: &mut Vec<(PathBuf, u8)>,
    ) {
        if baseline {
            self.push_baseline_candidate(candidates, path.to_path_buf(), class);
        }
        match resolve_identity(path, false) {
            Ok(identity) if identity.is_file => {
                let owner = if gedefense_common::persistence_class_is_secret(class) {
                    identity.uid
                } else {
                    0
                };
                self.insert_path_identity(identity.dev, identity.ino, class, owner, false);
            }
            Ok(_) => self.skipped_paths = self.skipped_paths.saturating_add(1),
            Err(_) => self.skipped_paths = self.skipped_paths.saturating_add(1),
        }
    }
}

impl PersistenceCore {
    /// Inserts one watched directory identity (direct children are matched
    /// through the eBPF parent-dentry step) and, when `scan` is set, bounded
    /// scans the current regular-file children matching `filter`.
    pub(super) fn watch_directory<F>(
        &mut self,
        path: &Path,
        class: u8,
        scan: bool,
        filter: F,
        max_children: usize,
        baseline: bool,
        candidates: &mut Vec<(PathBuf, u8)>,
    ) where
        F: Fn(&str) -> bool,
    {
        let identity = match resolve_identity(path, true) {
            Ok(identity) if identity.is_dir => identity,
            _ => {
                self.skipped_paths = self.skipped_paths.saturating_add(1);
                return;
            }
        };
        let owner = if gedefense_common::persistence_class_is_secret(class) {
            identity.uid
        } else {
            0
        };
        self.insert_path_identity(identity.dev, identity.ino, class, owner, true);
        if !scan || max_children == 0 {
            return;
        }
        let Ok(entries) = fs::read_dir(&identity.canonical) else {
            return;
        };
        let mut children: Vec<String> = Vec::new();
        for entry in entries.flatten().take(max_children) {
            let name = entry.file_name().to_string_lossy().into_owned();
            if filter(&name) {
                children.push(name);
            }
        }
        children.sort();
        for name in children {
            let child = identity.canonical.join(&name);
            self.watch_exact_file(&child, class, baseline, candidates);
        }
    }
}

impl PersistenceCore {
    /// Inserts one watched directory identity only (no child scan; the path map
    /// directory flag covers dynamically created children).
    pub(super) fn watch_directory_only(&mut self, path: &Path, class: u8) {
        let mut ignored = Vec::new();
        self.watch_directory(path, class, false, |_| false, 0, false, &mut ignored);
    }
}

impl PersistenceCore {
    /// systemd unit roots: `<base>/*.d/*.conf` drop-ins and `<base>/*.conf`
    /// additions are watched; the base directory itself is watched so new
    /// drop-in directories are covered through the parent step.
    pub(super) fn watch_systemd_base(&mut self, base: &Path, candidates: &mut Vec<(PathBuf, u8)>) {
        let identity = match resolve_identity(base, true) {
            Ok(identity) if identity.is_dir => identity,
            _ => {
                self.skipped_paths = self.skipped_paths.saturating_add(1);
                return;
            }
        };
        self.insert_path_identity(
            identity.dev,
            identity.ino,
            PERSIST_CLASS_SYSTEMD_DROPIN,
            0,
            true,
        );
        let Ok(entries) = fs::read_dir(&identity.canonical) else {
            return;
        };
        let mut directories: Vec<PathBuf> = Vec::new();
        let mut files: Vec<PathBuf> = Vec::new();
        for entry in entries.flatten().take(MAX_SYSTEMD_UNIT_CHILDREN) {
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.ends_with(".d") && entry.file_type().map(|kind| kind.is_dir()).unwrap_or(false)
            {
                directories.push(identity.canonical.join(name));
            } else if name.ends_with(".conf")
                && entry
                    .file_type()
                    .map(|kind| kind.is_file())
                    .unwrap_or(false)
            {
                files.push(identity.canonical.join(name));
            }
        }
        directories.sort();
        directories.truncate(256);
        for directory in directories {
            self.watch_directory(
                &directory,
                PERSIST_CLASS_SYSTEMD_DROPIN,
                true,
                |name| name.ends_with(".conf"),
                128,
                true,
                candidates,
            );
        }
        files.sort();
        files.truncate(256);
        for file in files {
            self.watch_exact_file(&file, PERSIST_CLASS_SYSTEMD_DROPIN, true, candidates);
        }
    }
}

impl PersistenceCore {
    pub(super) fn watch_browser_profiles(&mut self, root: &Path) {
        let identity = match resolve_identity(root, true) {
            Ok(identity) if identity.is_dir => identity,
            _ => return,
        };
        let Ok(entries) = fs::read_dir(&identity.canonical) else {
            return;
        };
        let mut profiles: Vec<PathBuf> = Vec::new();
        for entry in entries.flatten().take(MAX_DIR_CHILDREN) {
            let name = entry.file_name().to_string_lossy().into_owned();
            let profile_like = name == "Default"
                || name.starts_with("Profile ")
                || name == "Guest Profile"
                || name.contains("default");
            if profile_like && entry.file_type().map(|kind| kind.is_dir()).unwrap_or(false) {
                profiles.push(identity.canonical.join(name));
            }
        }
        profiles.sort();
        profiles.truncate(8);
        for profile in profiles {
            self.watch_directory_only(&profile, PERSIST_CLASS_SECRET_BROWSER);
        }
    }
}

impl PersistenceCore {
    pub(super) fn watch_peripheral_devices(&mut self) {
        let mut ignored = Vec::new();
        if let Ok(entries) = fs::read_dir("/sys/class/video4linux") {
            for entry in entries.flatten().take(MAX_DIR_CHILDREN) {
                let name = entry.file_name().to_string_lossy().into_owned();
                if name.starts_with("video") {
                    self.watch_exact_file(
                        &PathBuf::from(format!("/dev/{name}")),
                        PERSIST_CLASS_DEVICE_CAMERA,
                        false,
                        &mut ignored,
                    );
                }
            }
        }
        if let Ok(entries) = fs::read_dir("/dev/snd") {
            for entry in entries.flatten().take(MAX_DIR_CHILDREN) {
                let name = entry.file_name().to_string_lossy().into_owned();
                if name.starts_with("pcm") || name.starts_with("control") {
                    self.watch_exact_file(
                        &PathBuf::from(format!("/dev/snd/{name}")),
                        PERSIST_CLASS_DEVICE_MIC,
                        false,
                        &mut ignored,
                    );
                }
            }
        }
        if let Ok(entries) = fs::read_dir("/dev/input") {
            for entry in entries.flatten().take(MAX_DIR_CHILDREN) {
                let name = entry.file_name().to_string_lossy().into_owned();
                if name.starts_with("event") {
                    self.watch_exact_file(
                        &PathBuf::from(format!("/dev/input/{name}")),
                        PERSIST_CLASS_DEVICE_EVDEV,
                        false,
                        &mut ignored,
                    );
                }
            }
        }
    }
}

impl PersistenceCore {
    pub(super) fn watch_capture_sockets(&mut self) {
        let mut ignored = Vec::new();
        let Ok(entries) = fs::read_dir("/run/user") else {
            return;
        };
        let mut directories: Vec<PathBuf> = Vec::new();
        for entry in entries.flatten().take(MAX_USERS) {
            let name = entry.file_name().to_string_lossy().into_owned();
            if !name.is_empty() && name.bytes().all(|byte| byte.is_ascii_digit()) {
                directories.push(entry.path());
            }
        }
        directories.sort();
        for directory in directories {
            for socket in [
                "wayland-0",
                "wayland-1",
                "pipewire-0",
                "pipewire-1",
                "pulse/native",
            ] {
                self.watch_exact_file(
                    &directory.join(socket),
                    PERSIST_CLASS_DEVICE_CAPTURE_SOCKET,
                    false,
                    &mut ignored,
                );
            }
            self.watch_directory_only(
                &directory.join("pulse"),
                PERSIST_CLASS_DEVICE_CAPTURE_SOCKET,
            );
        }
    }

    // -- protected executables ---------------------------------------------
}

impl PersistenceCore {
    pub(super) fn populate_executables(&mut self) {
        self.clear_exec_maps();
        let executables: [(&str, u8); 14] = [
            ("/usr/sbin/sshd", gedefense_common::PERSIST_EXEC_CLASS_SSHD),
            ("/usr/bin/sshd", gedefense_common::PERSIST_EXEC_CLASS_SSHD),
            (
                "/usr/sbin/sshd-session",
                gedefense_common::PERSIST_EXEC_CLASS_SSHD_SESSION,
            ),
            (
                "/usr/lib/openssh/sshd-session",
                gedefense_common::PERSIST_EXEC_CLASS_SSHD_SESSION,
            ),
            ("/usr/sbin/sudo", gedefense_common::PERSIST_EXEC_CLASS_SUDO),
            ("/usr/bin/sudo", gedefense_common::PERSIST_EXEC_CLASS_SUDO),
            ("/usr/bin/su", gedefense_common::PERSIST_EXEC_CLASS_SU),
            ("/bin/su", gedefense_common::PERSIST_EXEC_CLASS_SU),
            ("/usr/bin/login", gedefense_common::PERSIST_EXEC_CLASS_LOGIN),
            ("/bin/login", gedefense_common::PERSIST_EXEC_CLASS_LOGIN),
            ("/usr/bin/curl", gedefense_common::PERSIST_EXEC_CLASS_CURL),
            (
                "/usr/local/bin/curl",
                gedefense_common::PERSIST_EXEC_CLASS_CURL,
            ),
            (
                "/usr/bin/git-remote-https",
                gedefense_common::PERSIST_EXEC_CLASS_CURL,
            ),
            (
                "/usr/lib/git-core/git-remote-https",
                gedefense_common::PERSIST_EXEC_CLASS_CURL,
            ),
        ];
        for (path, class) in executables {
            let Ok(identity) = resolve_identity(Path::new(path), false) else {
                self.skipped_paths = self.skipped_paths.saturating_add(1);
                continue;
            };
            if !identity.is_file {
                continue;
            }
            let key = persistence_identity_key(identity.dev, identity.ino);
            if self.execs.contains_key(&key) {
                continue;
            }
            if self.execs.len() >= PERSIST_EXEC_MAP_ENTRIES as usize {
                self.capacity_skips = self.capacity_skips.saturating_add(1);
                continue;
            }
            match self.execs_map.insert(&key, class, 0) {
                Ok(()) => {
                    self.execs.insert(key, class);
                }
                Err(error) => {
                    eprintln!("persistence guard: executable map insert for {path} failed: {error}")
                }
            }
        }
    }

    // -- baseline -----------------------------------------------------------
}

impl PersistenceCore {
    pub(super) fn insert_path_identity(
        &mut self,
        dev: u32,
        ino: u64,
        class: u8,
        owner_uid: u32,
        directory: bool,
    ) -> bool {
        if dev == 0 || ino == 0 {
            return false;
        }
        let key = persistence_identity_key(dev, ino);
        if self.paths.contains_key(&key) {
            return true;
        }
        if self.paths.len() >= PERSIST_PATH_MAP_ENTRIES as usize {
            self.capacity_skips = self.capacity_skips.saturating_add(1);
            return false;
        }
        let Some(value) = persistence_path_value(class, owner_uid, directory) else {
            return false;
        };
        match self.paths_map.insert(&key, value, 0) {
            Ok(()) => {
                self.paths.insert(key, value);
                if gedefense_common::persistence_class_is_device(class) {
                    self.device_entries = self.device_entries.saturating_add(1);
                }
                if gedefense_common::persistence_class_is_secret(class) {
                    self.secret_entries = self.secret_entries.saturating_add(1);
                }
                true
            }
            Err(error) => {
                eprintln!("persistence guard: path map insert for class {class} failed: {error}");
                false
            }
        }
    }
}

impl PersistenceCore {
    pub(super) fn push_baseline_candidate(
        &mut self,
        candidates: &mut Vec<(PathBuf, u8)>,
        path: PathBuf,
        class: u8,
    ) {
        if candidates.len() >= MAX_BASELINE_FILES {
            self.baseline_skips = self.baseline_skips.saturating_add(1);
            return;
        }
        if candidates.iter().any(|(existing, _)| *existing == path) {
            return;
        }
        candidates.push((path, class));
    }
}
