use super::*;

pub(super) const LIBRARY_MAPS_MAX_BYTES: u64 = 4 * 1024 * 1024;
pub(super) const LIBRARY_MAX_TARGET_PIDS: usize = 32;
pub(super) const LIBRARY_MAX_FINDINGS_PER_SCAN: usize = 16;
pub(super) const LIBRARY_TARGET_COMMS: [&str; 6] =
    ["sshd", "sshd-session", "sudo", "su", "login", "curl"];
/// System library roots whose `.so` must be package-owned; writable user paths
/// are deliberately excluded to keep the rule false-positive free.
pub(super) const SYSTEM_LIB_ROOTS: [&str; 8] = [
    "/lib/",
    "/lib64/",
    "/lib32/",
    "/usr/lib/",
    "/usr/lib64/",
    "/usr/lib32/",
    "/usr/libexec/",
    "/usr/local/lib/",
];
/// Paths under writable/admin roots are checked against the package DB but a
/// miss there is expected (locally built libraries), so they are not reported.
pub(super) const PKGDB_EXEMPT_ROOTS: [&str; 4] = ["/usr/local/", "/opt/", "/snap/", "/srv/"];
pub(super) const DPKG_INFO_DIR: &str = "/var/lib/dpkg/info";
pub(super) const PACMAN_LOCAL_DIR: &str = "/var/lib/pacman/local";
pub(super) const PKGDB_FILE_MAX_BYTES: u64 = 2 * 1024 * 1024;
pub(super) const PKGDB_TOTAL_BYTES: u64 = 64 * 1024 * 1024;

// ------------------------------------------------------------------- pins

pub(super) const PIN_MAX_BYTES: u64 = 4096;
pub(super) const PIN_RESOLVE_LIMIT: usize = 256;

// --------------------------------------------------------- tap/path heuristics

impl CrossViewCore {
    pub(super) fn scan_libraries(
        &mut self,
        now_ms: u64,
        deadline: Instant,
        outcome: &mut ScanOutcome,
    ) {
        if matches!(self.pkgdb, PkgDbState::Unbuilt) {
            self.pkgdb = build_pkgdb(deadline);
        }
        let incomplete = match &self.pkgdb {
            PkgDbState::Indexed {
                complete,
                libraries,
                ..
            } => {
                let _ = libraries;
                !*complete
            }
            PkgDbState::Unsupported => {
                outcome.reason("pkgdb_unsupported");
                return;
            }
            PkgDbState::Unbuilt => return,
        };
        if incomplete {
            outcome.reason("pkgdb_incomplete");
        }
        outcome.domains += 1;

        let pids = match read_proc_pids() {
            Ok(pids) => pids,
            Err(error) => {
                eprintln!("cross-view library view: {PROCFS_PATH} listing unavailable ({error})");
                outcome.degrade("proc_unreadable");
                return;
            }
        };
        let mut targets: Vec<u32> = Vec::new();
        for pid in pids.iter() {
            if targets.len() >= LIBRARY_MAX_TARGET_PIDS || Instant::now() >= deadline {
                break;
            }
            let Some(comm) = read_proc_comm(*pid) else {
                continue;
            };
            if LIBRARY_TARGET_COMMS.contains(&comm.as_str()) {
                targets.push(*pid);
            }
        }
        let own = std::process::id();
        if !targets.contains(&own) {
            targets.push(own);
        }

        let mut findings = 0usize;
        for pid in targets {
            if findings >= LIBRARY_MAX_FINDINGS_PER_SCAN || Instant::now() >= deadline {
                break;
            }
            let maps = match read_bounded_string(
                &format!("{PROCFS_PATH}/{pid}/maps"),
                LIBRARY_MAPS_MAX_BYTES,
            ) {
                Ok((text, _)) => text,
                Err(error) => {
                    eprintln!("cross-view library view: maps of a target pid unreadable ({error})");
                    outcome.degrade("maps_unreadable");
                    continue;
                }
            };
            let uid = proc_uid(pid).unwrap_or(0);
            let mut seen: HashSet<u64> = HashSet::new();
            for (path, deleted) in library_mappings(&maps) {
                if findings >= LIBRARY_MAX_FINDINGS_PER_SCAN {
                    break;
                }
                let hash = fnv64(path.as_bytes());
                if !seen.insert(hash) {
                    continue;
                }
                let (detail, suspicious) = match &self.pkgdb {
                    PkgDbState::Indexed {
                        complete,
                        libraries,
                        ..
                    } => {
                        if deleted {
                            (CROSS_VIEW_DETAIL_LIB_DELETED, true)
                        } else if *complete
                            && system_library_path(&path)
                            && !libraries.contains(&hash)
                        {
                            (CROSS_VIEW_DETAIL_LIB_FOREIGN, true)
                        } else {
                            (0, false)
                        }
                    }
                    _ => (0, false),
                };
                if !suspicious || detail == 0 {
                    continue;
                }
                findings += 1;
                let label = path.rsplit('/').next().unwrap_or("lib");
                self.enqueue(CrossViewEvent {
                    ts_ns: now_ms.saturating_mul(1_000_000),
                    ino: hash,
                    pid,
                    uid,
                    dev: 0,
                    detail_code: detail,
                    domain: CROSS_VIEW_DOMAIN_LIBRARY_VIEW,
                    kind: CROSS_VIEW_KIND_LIBRARY_MISMATCH,
                    severity: CROSS_VIEW_SEVERITY_HIGH,
                    action: CROSS_VIEW_ACTION_AUDIT,
                    comm: bounded_comm(label),
                    reserved: [0u8; 12],
                });
            }
        }
    }
}

/// Builds the bounded package-ownership index. Only `.so` paths are indexed; a
/// cap/deadline hit marks the index incomplete so a missing entry can never be
/// reported as a foreign library (reject-not-guess).
pub(super) fn build_pkgdb(deadline: Instant) -> PkgDbState {
    if Path::new(DPKG_INFO_DIR).is_dir() {
        return build_debian_pkgdb(deadline);
    }
    if Path::new(PACMAN_LOCAL_DIR).is_dir() {
        return build_arch_pkgdb(deadline);
    }
    PkgDbState::Unsupported
}

pub(super) fn build_debian_pkgdb(deadline: Instant) -> PkgDbState {
    let mut libraries: HashSet<u64> = HashSet::new();
    let mut complete = true;
    let mut files = 0usize;
    let mut total_bytes = 0u64;
    let entries = match fs::read_dir(DPKG_INFO_DIR) {
        Ok(entries) => entries,
        Err(error) => {
            eprintln!("cross-view pkgdb: {DPKG_INFO_DIR} unreadable ({error})");
            return PkgDbState::Unsupported;
        }
    };
    for entry in entries.flatten() {
        if files >= CROSS_VIEW_MAX_PKGDB_FILES
            || total_bytes >= PKGDB_TOTAL_BYTES
            || Instant::now() >= deadline
            || libraries.len() >= CROSS_VIEW_MAX_PKGDB_ENTRIES
        {
            complete = false;
            break;
        }
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if !name.ends_with(".list") {
            continue;
        }
        files += 1;
        let list_path = entry.path().to_string_lossy().into_owned();
        let Ok((text, read_bytes)) = read_bounded_string(&list_path, PKGDB_FILE_MAX_BYTES) else {
            complete = false;
            continue;
        };
        total_bytes = total_bytes.saturating_add(read_bytes);
        for line in text.lines() {
            if !line.starts_with('/') || !line.contains(".so") {
                continue;
            }
            if libraries.len() >= CROSS_VIEW_MAX_PKGDB_ENTRIES {
                complete = false;
                break;
            }
            libraries.insert(fnv64(line.as_bytes()));
        }
    }
    PkgDbState::Indexed {
        token: CROSS_VIEW_PKGDB_DEBIAN,
        complete,
        libraries,
    }
}

pub(super) fn build_arch_pkgdb(deadline: Instant) -> PkgDbState {
    let mut libraries: HashSet<u64> = HashSet::new();
    let mut complete = true;
    let mut files = 0usize;
    let mut total_bytes = 0u64;
    let packages = match fs::read_dir(PACMAN_LOCAL_DIR) {
        Ok(entries) => entries,
        Err(error) => {
            eprintln!("cross-view pkgdb: {PACMAN_LOCAL_DIR} unreadable ({error})");
            return PkgDbState::Unsupported;
        }
    };
    for package in packages.flatten() {
        if files >= CROSS_VIEW_MAX_PKGDB_FILES
            || total_bytes >= PKGDB_TOTAL_BYTES
            || Instant::now() >= deadline
            || libraries.len() >= CROSS_VIEW_MAX_PKGDB_ENTRIES
        {
            complete = false;
            break;
        }
        let files_path = package.path().join("files");
        let files_path = files_path.to_string_lossy().into_owned();
        let Ok((text, read_bytes)) = read_bounded_string(&files_path, PKGDB_FILE_MAX_BYTES) else {
            continue;
        };
        files += 1;
        total_bytes = total_bytes.saturating_add(read_bytes);
        for line in text.lines() {
            if !line.contains(".so") || line.ends_with('/') {
                continue;
            }
            let mut path = String::with_capacity(line.len() + 1);
            path.push('/');
            path.push_str(line);
            if libraries.len() >= CROSS_VIEW_MAX_PKGDB_ENTRIES {
                complete = false;
                break;
            }
            libraries.insert(fnv64(path.as_bytes()));
        }
    }
    PkgDbState::Indexed {
        token: CROSS_VIEW_PKGDB_ARCH,
        complete,
        libraries,
    }
}

// ===========================================================================
// Raw bpf() syscall layer
// ===========================================================================

/// Parses `/proc/<pid>/maps` and yields the mapped shared-library paths with
/// their "(deleted)" marker. Every line is validated; malformed lines are
/// skipped (a racing unmap must never invalidate the whole view).
pub(super) fn library_mappings(text: &str) -> Vec<(String, bool)> {
    let mut out = Vec::new();
    if out.capacity() < 64 {
        out.reserve(64);
    }
    for line in text.lines() {
        let Some(path) = maps_line_path(line) else {
            continue;
        };
        if !path.starts_with('/') || !path.contains(".so") {
            continue;
        }
        let deleted = path.ends_with(" (deleted)");
        let path = path.trim_end_matches(" (deleted)");
        if path.is_empty() || path.len() > 4096 {
            continue;
        }
        out.push((path.to_owned(), deleted));
    }
    out
}

/// Returns the pathname field of one maps line (5 fixed columns, then the path
/// remainder which may contain spaces).
pub(super) fn maps_line_path(line: &str) -> Option<&str> {
    let bytes = line.as_bytes();
    let mut index = 0usize;
    while index < bytes.len() && (bytes[index] == b' ' || bytes[index] == b'\t') {
        index += 1;
    }
    for _ in 0..5 {
        while index < bytes.len() && bytes[index] != b' ' && bytes[index] != b'\t' {
            index += 1;
        }
        while index < bytes.len() && (bytes[index] == b' ' || bytes[index] == b'\t') {
            index += 1;
        }
    }
    if index >= bytes.len() {
        return None;
    }
    let path = line.get(index..)?.trim();
    if path.is_empty() {
        None
    } else {
        Some(path)
    }
}

pub(super) fn system_library_path(path: &str) -> bool {
    if PKGDB_EXEMPT_ROOTS.iter().any(|root| path.starts_with(root)) {
        return false;
    }
    SYSTEM_LIB_ROOTS.iter().any(|root| path.starts_with(root))
}

// ===========================================================================
// pins / cmdline / misc helpers
// ===========================================================================
