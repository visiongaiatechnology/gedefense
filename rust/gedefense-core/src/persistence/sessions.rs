use super::*;

/// Session sample cadence (logind session files, inherited from systemd).
pub(super) const SESSIONS_REFRESH_MS: u64 = 5_000;

pub(super) const MAX_SESSIONS_FILES: usize = 256;
pub(super) const MAX_SESSION_FILE_BYTES: u64 = 16 * 1024;
pub(super) const MAX_SEATS: usize = 64;

#[derive(Default, Clone)]
pub(super) struct SessionSnapshot {
    /// True when the session directory could be read and at least sampled.
    pub(super) parsed: bool,
    pub(super) total: u32,
    pub(super) active: u32,
    pub(super) inactive: u32,
    pub(super) seats: u32,
    pub(super) active_uids: BTreeSet<u32>,
}

impl SessionSnapshot {
    pub(super) fn to_status_value(&self) -> String {
        format!("{}/{}/{}", self.total, self.active, self.inactive)
    }
}

pub(super) fn read_session_snapshot(sessions_dir: &Path, seats_dir: &Path) -> SessionSnapshot {
    let mut snapshot = SessionSnapshot::default();
    if let Ok(entries) = fs::read_dir(sessions_dir) {
        snapshot.parsed = true;
        let mut files: Vec<PathBuf> = Vec::new();
        for entry in entries.flatten().take(MAX_SESSIONS_FILES) {
            let name = entry.file_name().to_string_lossy().into_owned();
            // `.ref` files are inverse indexes maintained by logind; the plain
            // session files carry the fields this contract uses.
            if name.starts_with('.') || name.ends_with(".ref") {
                continue;
            }
            files.push(entry.path());
        }
        files.sort();
        for path in files.into_iter().take(MAX_SESSIONS_FILES) {
            let Ok(data) = read_bounded_file(&path, MAX_SESSION_FILE_BYTES) else {
                continue;
            };
            let text = String::from_utf8_lossy(&data);
            let mut uid: Option<u32> = None;
            let mut active = false;
            let mut state_active = false;
            let mut class_user = false;
            let mut seat_present = false;
            let mut local_type = false;
            for line in text.lines().take(64) {
                if let Some(value) = line.strip_prefix("UID=") {
                    uid = value.trim().parse().ok();
                } else if let Some(value) = line.strip_prefix("ACTIVE=") {
                    // systemd-logind writes the boolean as `1`/`0`; older
                    // documentation examples use `yes`/`no`. Both are accepted.
                    let value = value.trim();
                    active = value == "1"
                        || value.eq_ignore_ascii_case("yes")
                        || value.eq_ignore_ascii_case("true");
                } else if let Some(value) = line.strip_prefix("STATE=") {
                    state_active = value.trim().eq_ignore_ascii_case("active");
                } else if let Some(value) = line.strip_prefix("CLASS=") {
                    class_user = value.trim().eq_ignore_ascii_case("user");
                } else if let Some(value) = line.strip_prefix("SEAT=") {
                    seat_present = !value.trim().is_empty();
                } else if let Some(value) = line.strip_prefix("TYPE=") {
                    // Local seat session types. A bare TTY session may carry no
                    // SEAT line (observed on WSL/Ubuntu 24.04), so the session
                    // type is the second local-session indicator.
                    let value = value.trim();
                    local_type = value.eq_ignore_ascii_case("tty")
                        || value.eq_ignore_ascii_case("x11")
                        || value.eq_ignore_ascii_case("wayland")
                        || value.eq_ignore_ascii_case("mir");
                }
            }
            let Some(uid) = uid else {
                continue;
            };
            snapshot.total = snapshot.total.saturating_add(1);
            // A remote/manager session is not a desktop session; only a `user`
            // class session on a seat or a local session type in the active
            // state can plausibly own a camera/microphone.
            if class_user && (seat_present || local_type) && active && state_active {
                snapshot.active = snapshot.active.saturating_add(1);
                snapshot.active_uids.insert(uid);
            }
        }
    }
    if let Ok(entries) = fs::read_dir(seats_dir) {
        snapshot.seats = u32::try_from(entries.flatten().take(MAX_SEATS).count()).unwrap_or(0);
    }
    snapshot.inactive = snapshot.total.saturating_sub(snapshot.active);
    snapshot
}

// ---------------------------------------------------------------------------
// Baseline hashing (in memory only; nothing persisted outside the unit grants)
// ---------------------------------------------------------------------------

/// Bounded user home enumeration: `/root` plus at most [`MAX_USERS`] `/home/*`
/// directories, sorted for determinism. A missing `/home` is not an error.
pub(super) fn enumerate_home_directories() -> Vec<PathBuf> {
    let mut homes = vec![PathBuf::from("/root")];
    let Ok(entries) = fs::read_dir("/home") else {
        return homes;
    };
    let mut names: Vec<String> = Vec::new();
    for entry in entries.flatten().take(MAX_USERS * 4) {
        if entry.file_type().map(|kind| kind.is_dir()).unwrap_or(false) {
            names.push(entry.file_name().to_string_lossy().into_owned());
        }
    }
    names.sort();
    for name in names.into_iter().take(MAX_USERS.saturating_sub(1)) {
        homes.push(PathBuf::from("/home").join(name));
    }
    homes
}
