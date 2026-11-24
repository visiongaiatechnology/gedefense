use super::*;

/// Package-database ownership index refresh cadence (a package upgrade must not
/// leave the mapped-library ownership snapshot stale forever).
pub(super) const PKGDB_REFRESH_MS: u64 = 900_000;

pub(super) const MAX_PKGDB_FILES: usize = 8_192;
pub(super) const MAX_PKGDB_TOTAL_BYTES: u64 = 64 * 1024 * 1024;
pub(super) const MAX_PKGDB_PATHS: usize = 200_000;
pub(super) const MAX_PKGDB_INODE_STATS: usize = 24_000;

#[derive(Default)]
pub(super) struct PackageIndex {
    /// `dpkg`, `pacman`, `both` or `unsupported`.
    pub(super) format: String,
    /// Retained package-owned paths (only `.so*`, `/etc/ld.so.*` and `/etc/pam.d/`
    /// entries to bound memory) -> package name.
    pub(super) owned_paths: BTreeMap<String, String>,
    /// Reverse index `(st_dev, st_ino)` -> package name for mapped libraries.
    pub(super) inode_owners: BTreeMap<(u32, u64), String>,
    pub(super) parsed_paths: u64,
    pub(super) stat_failures: u64,
    pub(super) ready: bool,
}

impl PackageIndex {
    pub(super) fn unsupported() -> Self {
        Self {
            format: "unsupported".to_owned(),
            ..Self::default()
        }
    }

    pub(super) fn load() -> Self {
        Self::load_from(
            Path::new("/var/lib/dpkg/info"),
            Path::new("/var/lib/pacman/local"),
        )
    }

    pub(super) fn load_from(dpkg_dir: &Path, pacman_dir: &Path) -> Self {
        let mut index = Self::default();
        let mut dpkg_seen = false;
        let mut pacman_seen = false;
        let mut total_bytes = 0u64;
        let mut dpkg_files = 0usize;
        if let Ok(entries) = fs::read_dir(dpkg_dir) {
            let mut paths: Vec<PathBuf> = Vec::new();
            for entry in entries.flatten().take(MAX_PKGDB_FILES) {
                let name = entry.file_name();
                let name = name.to_string_lossy();
                if name.ends_with(".list") {
                    paths.push(entry.path());
                }
            }
            paths.sort();
            for path in paths {
                if dpkg_files >= MAX_PKGDB_FILES || index.owned_paths.len() >= MAX_PKGDB_PATHS {
                    break;
                }
                let Some(stem) = path
                    .file_name()
                    .map(|name| name.to_string_lossy().into_owned())
                else {
                    continue;
                };
                let package = stem
                    .strip_suffix(".list")
                    .unwrap_or(&stem)
                    .trim()
                    .to_owned();
                if package.is_empty() || package.len() > 128 {
                    continue;
                }
                let Some(contents) = read_package_listing(&path, &mut total_bytes) else {
                    continue;
                };
                dpkg_files = dpkg_files.saturating_add(1);
                dpkg_seen = true;
                for line in contents.split(|byte| *byte == b'\n') {
                    let Ok(path) = std::str::from_utf8(line) else {
                        continue;
                    };
                    let path = path.trim_end_matches('\r').trim();
                    if !retain_package_path(path) {
                        continue;
                    }
                    index
                        .owned_paths
                        .entry(path.to_owned())
                        .or_insert_with(|| package.clone());
                    index.parsed_paths = index.parsed_paths.saturating_add(1);
                    if index.owned_paths.len() >= MAX_PKGDB_PATHS {
                        break;
                    }
                }
            }
        }
        if let Ok(entries) = fs::read_dir(pacman_dir) {
            let mut entries: Vec<PathBuf> = entries
                .flatten()
                .take(MAX_PKGDB_FILES)
                .map(|entry| entry.path())
                .collect();
            entries.sort();
            for package_dir in entries {
                if index.owned_paths.len() >= MAX_PKGDB_PATHS {
                    break;
                }
                let Some(directory_name) = package_dir
                    .file_name()
                    .map(|name| name.to_string_lossy().into_owned())
                else {
                    continue;
                };
                let files_path = package_dir.join("files");
                if !files_path.is_file() {
                    continue;
                }
                let package = pacman_package_name(&directory_name);
                if package.is_empty() || package.len() > 128 {
                    continue;
                }
                let Some(contents) = read_package_listing(&files_path, &mut total_bytes) else {
                    continue;
                };
                pacman_seen = true;
                for line in contents.split(|byte| *byte == b'\n') {
                    let Ok(relative) = std::str::from_utf8(line) else {
                        continue;
                    };
                    let relative = relative.trim_end_matches('\r').trim();
                    if relative.is_empty() || relative.ends_with('/') || relative.starts_with('/') {
                        continue;
                    }
                    let absolute = format!("/{relative}");
                    if !retain_package_path(&absolute) {
                        continue;
                    }
                    index
                        .owned_paths
                        .entry(absolute)
                        .or_insert_with(|| package.clone());
                    index.parsed_paths = index.parsed_paths.saturating_add(1);
                    if index.owned_paths.len() >= MAX_PKGDB_PATHS {
                        break;
                    }
                }
            }
        }
        // Reverse inode index: only the retained `.so*`/linker paths are stat'ed.
        let mut stats = 0usize;
        for (path, package) in &index.owned_paths {
            if stats >= MAX_PKGDB_INODE_STATS {
                break;
            }
            stats += 1;
            match fs::metadata(path) {
                Ok(metadata) if metadata.is_file() => {
                    let Ok(dev) = u32::try_from(metadata.dev()) else {
                        continue;
                    };
                    let ino = metadata.ino();
                    if dev == 0 || ino == 0 {
                        continue;
                    }
                    index
                        .inode_owners
                        .entry((dev, ino))
                        .or_insert_with(|| package.clone());
                }
                _ => index.stat_failures = index.stat_failures.saturating_add(1),
            }
        }
        index.format = match (dpkg_seen, pacman_seen) {
            (true, true) => "both",
            (true, false) => "dpkg",
            (false, true) => "pacman",
            (false, false) => "unsupported",
        }
        .to_owned();
        index.ready = !index.inode_owners.is_empty();
        index
    }

    pub(super) fn package_of(&self, dev: u32, ino: u64) -> Option<&str> {
        self.inode_owners.get(&(dev, ino)).map(String::as_str)
    }
}

/// True when a package listing entry is retained: `.so*` files (libraries and
/// linker binaries) plus the linker/PAM configuration files. Everything else is
/// dropped so a full dpkg database cannot exhaust memory.
pub(super) fn retain_package_path(path: &str) -> bool {
    if path.is_empty() || path.len() > 4_096 || !path.starts_with('/') {
        return false;
    }
    let name = path.rsplit('/').next().unwrap_or("");
    name.contains(".so") || path.starts_with("/etc/ld.so.") || path.starts_with("/etc/pam.d/")
}

pub(super) fn read_package_listing(path: &Path, total_bytes: &mut u64) -> Option<Vec<u8>> {
    if *total_bytes >= MAX_PKGDB_TOTAL_BYTES {
        return None;
    }
    let remaining = MAX_PKGDB_TOTAL_BYTES.saturating_sub(*total_bytes);
    let data = read_bounded_file(path, remaining).ok()?;
    *total_bytes = total_bytes.saturating_add(data.len() as u64);
    Some(data)
}

/// Arch package directory name `name-version-release` -> package name.
pub(super) fn pacman_package_name(directory: &str) -> String {
    let mut parts = directory.rsplitn(3, '-');
    let _release = parts.next();
    let _version = parts.next();
    parts.next().unwrap_or(directory).to_owned()
}

// ---------------------------------------------------------------------------
// Honest systemd session sampling (no D-Bus, no IdleHint claim)
// ---------------------------------------------------------------------------
