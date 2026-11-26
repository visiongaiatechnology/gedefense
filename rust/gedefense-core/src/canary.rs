// STATUS: DIAMANT VGT SUPREME
//! Kernel-backed deception canary broker.
//!
//! The unprivileged control plane cannot create decoys outside its sandbox
//! (ProtectSystem=strict, PrivateTmp) and cannot observe host file accesses.
//! This module gives the privileged Rust core both capabilities:
//!
//! * `CANARY_DEPLOY` creates a bounded decoy file strictly inside one of the
//!   configured canary roots, atomically and without following a symbolic link
//!   in any path component (`openat(O_NOFOLLOW)` walk, `O_CREAT|O_EXCL`
//!   staging file, `fsync`, `renameat2`).
//! * `CANARY_REMOVE` removes one registered decoy inside the same jail.
//! * A dedicated fanotify instance watches every registered decoy and reports
//!   open/execute events (`CANARY_EVENTS`). The core never denies the access:
//!   the decoy is an alerting sensor, containment belongs to the control
//!   plane's response engine. (A notification-class fanotify event carries no
//!   file descriptor, so a path can only be resolved from a permission-class
//!   event's fd; the handler therefore answers FAN_ALLOW immediately.)
//! * `CANARY_STATUS` publishes bounded sensor health.
//!
//! A restart loses the in-memory registry, not the evidence: the broker writes
//! a small root-owned manifest inside the first canary root and re-registers
//! and re-marks every verified decoy on startup. A decoy whose content, mode or
//! owner changed is *not* silently accepted.

mod manifest;
mod probes;
mod watcher;
#[cfg(test)]
mod tests;

use self::probes::*;
use self::watcher::*;

use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, VecDeque},
    error::Error,
    ffi::CString,
    fs,
    os::{
        fd::{AsRawFd, OwnedFd},
        unix::{
            ffi::OsStrExt,
            fs::{MetadataExt, PermissionsExt},
        },
    },
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex,
    },
    thread,
    time::Duration,
};

type BoxError = Box<dyn Error + Send + Sync + 'static>;

pub const DEFAULT_CANARY_ROOT: &str = "/var/lib/vgt/gedefense/canaries";
pub(crate) const SELF_TEST_DECOY_NAME: &str = ".vgt-self-test";
const MAX_SELF_TEST_HITS: usize = 16;
const MAX_CANARY_ROOTS: usize = 8;
const MAX_REGISTERED_CANARIES: usize = 512;
const MAX_PENDING_EVENTS: usize = 512;
const MAX_EVENTS_PER_RESPONSE: usize = 4;
const MAX_CANARY_PATH_BYTES: usize = 256;
const MAX_CANARY_CONTENT_BYTES: usize = 1024;
const MAX_MANIFEST_BYTES: u64 = 64 * 1024;
const MAX_EVENT_PATH_BYTES: usize = 256;
const WATCH_BUFFER_BYTES: usize = 64 * 1024;
const WATCH_BACKOFF_MAX_SECONDS: u64 = 30;
// Waiting for the fanotify mark stays below the control plane's IPC request
// timeout (`core.request_timeout_millis`, shipped as 1500 ms): a watcher that
// is not armed must fail the deployment visibly instead of turning it into a
// timeout whose outcome the caller cannot read.
const MARK_WAIT_ATTEMPTS: usize = 20;
const MARK_WAIT_MILLIS: u64 = 50;
const MANIFEST_NAME: &str = ".canary-manifest";
const RENAME_NOREPLACE: u32 = 1;
// FIND-036a: the wire field for the accessor UID is a uint32, so an attribution
// that could not be resolved must not be encoded as 0 - the control plane treats
// UID 0 as root/system and downgrades the incident. The all-ones value is not a
// valid Linux UID and is documented as "unknown accessor"; downstream escalation
// stays fail-closed (an unknown accessor is never treated as a system scanner).
const CANARY_UID_UNKNOWN: u32 = u32::MAX;
const VALID_TYPES: [&str; 4] = ["SSH_KEY", "CLOUD_CRED", "SHADOW_BAK", "DOTENV"];
const VALID_MODES: [u32; 2] = [0o600, 0o640];

#[derive(Clone, Debug, Eq, PartialEq)]
struct CanaryRecord {
    path: PathBuf,
    canary_type: String,
    mode: u32,
    sha256: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CanaryEvent {
    pub(crate) pid: i32,
    pub(crate) uid: u32,
    pub(crate) path: PathBuf,
    pub(crate) canary_type: String,
    pub(crate) exec: bool,
}

struct WatchState {
    fd: Option<OwnedFd>,
    degraded: bool,
    last_error: String,
}

impl WatchState {
    fn new() -> Self {
        Self {
            fd: None,
            degraded: true,
            last_error: "canary watcher not started".to_owned(),
        }
    }
}

/// Privileged deception broker shared between the IPC dispatcher and the
/// fanotify worker thread.
#[derive(Clone)]
pub struct CanaryBroker {
    roots: Arc<Vec<PathBuf>>,
    records: Arc<Mutex<BTreeMap<PathBuf, CanaryRecord>>>,
    events: Arc<Mutex<VecDeque<CanaryEvent>>>,
    self_test_hits: Arc<Mutex<VecDeque<(i32, PathBuf)>>>,
    dropped: Arc<AtomicU64>,
    mark_failures: Arc<AtomicU64>,
    watch: Arc<Mutex<WatchState>>,
}

impl CanaryBroker {
    /// Validates and (if needed) creates the configured canary roots.
    ///
    /// A root must be absolute, canonical, a real directory owned by the
    /// effective uid (root in production) and not group/world writable. The
    /// package contract creates `/var/lib/vgt/gedefense/canaries` as
    /// `0750 root:gedefense`; the broker only repairs the mode of a root it
    /// already owns.
    pub fn new(roots: &[PathBuf]) -> Result<Self, BoxError> {
        if roots.is_empty() || roots.len() > MAX_CANARY_ROOTS {
            return Err("canary root count is outside the accepted range".into());
        }
        let effective_uid = unsafe { libc::geteuid() };
        let mut normalized: Vec<PathBuf> = Vec::with_capacity(roots.len());
        for root in roots {
            validate_absolute_clean(root, "canary root")?;
            if normalized.iter().any(|existing| existing == root) {
                return Err("duplicate canary root rejected".into());
            }
            fs::create_dir_all(root).map_err(|error| {
                std::io::Error::other(format!("canary root creation {}: {error}", root.display()))
            })?;
            let metadata = fs::symlink_metadata(root).map_err(|error| {
                std::io::Error::other(format!("canary root metadata {}: {error}", root.display()))
            })?;
            if !metadata.is_dir() || metadata.file_type().is_symlink() {
                return Err("canary root must be a real directory".into());
            }
            if metadata.uid() != effective_uid {
                return Err("canary root ownership does not match the core identity".into());
            }
            if metadata.mode() & 0o022 != 0 {
                return Err("canary root must not be group or world writable".into());
            }
            let mode = metadata.mode() & 0o7777;
            if mode != 0o750 && mode != 0o700 {
                fs::set_permissions(root, fs::Permissions::from_mode(0o750))?;
            }
            normalized.push(root.clone());
        }
        let broker = Self {
            roots: Arc::new(normalized),
            records: Arc::new(Mutex::new(BTreeMap::new())),
            events: Arc::new(Mutex::new(VecDeque::with_capacity(MAX_PENDING_EVENTS))),
            self_test_hits: Arc::new(Mutex::new(VecDeque::with_capacity(MAX_SELF_TEST_HITS))),
            dropped: Arc::new(AtomicU64::new(0)),
            mark_failures: Arc::new(AtomicU64::new(0)),
            watch: Arc::new(Mutex::new(WatchState::new())),
        };
        broker.load_manifest();
        Ok(broker)
    }

    /// Returns the configured primary canary root used for self-defense decoys.
    pub(crate) fn primary_root(&self) -> &Path {
        &self.roots[0]
    }

    /// Consumes a recorded self-test fanotify hit matching `(probe_pid, path)`
    /// from the dedicated channel so concurrent `CANARY_EVENTS` IPC polls cannot
    /// starve self-defense verification.
    pub(crate) fn consume_self_test_hit(&self, path: &Path, probe_pid: i32) -> bool {
        let Ok(mut hits) = self.self_test_hits.lock() else {
            return false;
        };
        let Some(pos) = hits
            .iter()
            .position(|(pid, hit_path)| *pid == probe_pid && hit_path == path)
        else {
            return false;
        };
        hits.remove(pos);
        true
    }

    /// Parses one `--canary-root=<absolute path>` occurrence. Repeated flags
    /// are supported by [`collect_canary_roots`].
    pub fn parse_root(value: &str) -> Result<PathBuf, BoxError> {
        let root = PathBuf::from(value);
        validate_absolute_clean(&root, "canary root")?;
        if root == Path::new("/") {
            return Err("canary root must not be the filesystem root".into());
        }
        Ok(root)
    }

    /// Spawns the fanotify worker. A sensor fault never aborts the privileged
    /// core: the session is retried with bounded backoff and the rest of the
    /// fabric (XDP, pidfd broker, IPC) stays online.
    pub fn start_watch(&self) -> Result<(), BoxError> {
        let broker = self.clone();
        thread::Builder::new()
            .name("gedefense-canary-watch".to_owned())
            .spawn(move || {
                let mut backoff = Duration::from_secs(1);
                loop {
                    match broker.run_watch_session() {
                        Ok(()) => {
                            eprintln!("GeDefense canary watch session ended; restarting sensor")
                        }
                        Err(error) => {
                            broker.set_watch_degraded(&error.to_string());
                            eprintln!(
                                "GeDefense canary sensor degraded: {error}; retrying in {backoff:?}"
                            );
                        }
                    }
                    thread::sleep(backoff);
                    backoff = std::cmp::min(
                        backoff.saturating_mul(2),
                        Duration::from_secs(WATCH_BACKOFF_MAX_SECONDS),
                    );
                }
            })?;
        Ok(())
    }

    /// IPC `CANARY_DEPLOY <path_b64> <type> <mode_octal> <content_b64>`.
    pub fn deploy_token(
        &self,
        path_token: &str,
        canary_type: &str,
        mode_token: &str,
        content_token: &str,
    ) -> Result<String, BoxError> {
        self.deploy_token_inner(path_token, canary_type, mode_token, content_token, true)
    }

    /// IPC `CANARY_REMOVE <path_b64>`.
    pub fn remove_token(&self, path_token: &str) -> Result<String, BoxError> {
        let path = decode_path_token(path_token)?;
        let (root, relative) = self.resolve_in_roots(&path)?;
        let (parent_components, basename) = split_relative(&relative)?;
        let parent = open_canary_parent(&root, &parent_components, false)?;
        let name = CString::new(basename.as_bytes())?;
        let mut stat: libc::stat = unsafe { std::mem::zeroed() };
        let stat_result = unsafe {
            libc::fstatat(
                parent.as_raw_fd(),
                name.as_ptr(),
                &mut stat,
                libc::AT_SYMLINK_NOFOLLOW,
            )
        };
        if stat_result != 0 {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::ENOENT) {
                self.forget_record(&path);
                return Ok("absent".to_owned());
            }
            return Err(std::io::Error::other(format!(
                "canary removal inspection failed: {error}"
            ))
            .into());
        }
        if stat.st_mode & libc::S_IFMT != libc::S_IFREG {
            return Err("canary removal target is not a regular file".into());
        }
        let unlink_result = unsafe { libc::unlinkat(parent.as_raw_fd(), name.as_ptr(), 0) };
        if unlink_result != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        unsafe { libc::fsync(parent.as_raw_fd()) };
        self.forget_record(&path);
        Ok("removed".to_owned())
    }

    /// IPC `CANARY_EVENTS` → `"<dropped>|<pid>:<uid>:<path_b64>:<type>:<exec>,"`
    pub fn take_events(&self) -> Result<String, BoxError> {
        let dropped = self.dropped.swap(0, Ordering::AcqRel);
        let mut queue = self
            .events
            .lock()
            .map_err(|_| "canary event queue integrity failure")?;
        let mut encoded = Vec::with_capacity(MAX_EVENTS_PER_RESPONSE);
        while encoded.len() < MAX_EVENTS_PER_RESPONSE {
            let Some(event) = queue.pop_front() else {
                break;
            };
            encoded.push(encode_event(&event));
        }
        if dropped == 0 && encoded.is_empty() {
            return Ok("empty".to_owned());
        }
        Ok(format!("{dropped}|{}", encoded.join(",")))
    }

    /// IPC `CANARY_STATUS` — bounded sensor health, no paths or content.
    pub fn status(&self) -> String {
        let registered = self.records.lock().map(|map| map.len()).unwrap_or(0);
        let queued = self.events.lock().map(|queue| queue.len()).unwrap_or(0);
        let (watcher, last_error) = match self.watch.lock() {
            Ok(state) => (
                if state.fd.is_some() && !state.degraded {
                    "active"
                } else {
                    "degraded"
                },
                state.last_error.clone(),
            ),
            Err(_) => ("degraded", "watch state poisoned".to_owned()),
        };
        let error_fingerprint = hex::encode(&Sha256::digest(last_error.as_bytes())[..4]);
        format!(
            "roots={}:registered={}:queued={}:dropped={}:mark_failures={}:watcher={}:last_error={}",
            self.roots.len(),
            registered,
            queued,
            self.dropped.load(Ordering::Relaxed),
            self.mark_failures.load(Ordering::Relaxed),
            watcher,
            error_fingerprint
        )
    }
}

/// Collects repeated `--canary-root=<path>` values. The shipped default is a
/// root-owned directory under the state tree, never a world-writable `/tmp`
/// path: a decoy in `/tmp` would be written by the private-tmp namespace of a
/// sandboxed service and could never be observed by another host process.
pub fn collect_canary_roots(values: &[String]) -> Result<Vec<PathBuf>, BoxError> {
    if values.is_empty() {
        return Ok(vec![PathBuf::from(DEFAULT_CANARY_ROOT)]);
    }
    if values.len() > MAX_CANARY_ROOTS {
        return Err("canary root count is outside the accepted range".into());
    }
    let mut roots: Vec<PathBuf> = Vec::with_capacity(values.len());
    for value in values {
        let root = CanaryBroker::parse_root(value)?;
        if !roots.contains(&root) {
            roots.push(root);
        }
    }
    Ok(roots)
}
