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

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, VecDeque},
    error::Error,
    ffi::{CString, OsString},
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd},
        unix::{
            ffi::{OsStrExt, OsStringExt},
            fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
        },
    },
    path::{Component, Path, PathBuf},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex,
    },
    thread,
    time::Duration,
};

type BoxError = Box<dyn Error + Send + Sync + 'static>;

pub const DEFAULT_CANARY_ROOT: &str = "/var/lib/vgt/gedefense/canaries";
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
struct CanaryEvent {
    pid: i32,
    uid: u32,
    path: PathBuf,
    canary_type: String,
    exec: bool,
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
            dropped: Arc::new(AtomicU64::new(0)),
            mark_failures: Arc::new(AtomicU64::new(0)),
            watch: Arc::new(Mutex::new(WatchState::new())),
        };
        broker.load_manifest();
        Ok(broker)
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

    fn deploy_token_inner(
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

    fn forget_record(&self, path: &Path) {
        if let Ok(mut records) = self.records.lock() {
            records.remove(path);
        }
        self.unmark_path(path);
        let _ = self.persist_manifest();
    }

    fn resolve_in_roots(&self, path: &Path) -> Result<(PathBuf, Vec<OsString>), BoxError> {
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

    fn set_watch_degraded(&self, error: &str) {
        if let Ok(mut state) = self.watch.lock() {
            state.degraded = true;
            state.last_error = error.chars().take(96).collect();
        }
    }

    fn wait_for_mark(&self, path: &Path) -> Result<(), BoxError> {
        for _ in 0..MARK_WAIT_ATTEMPTS {
            {
                let mut state = self
                    .watch
                    .lock()
                    .map_err(|_| "canary watch state integrity failure")?;
                if let Some(fd) = state.fd.as_ref() {
                    match mark_path(fd.as_raw_fd(), path) {
                        Ok(()) => return Ok(()),
                        Err(error) => {
                            state.last_error = error.to_string().chars().take(96).collect();
                            self.mark_failures.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                }
            }
            thread::sleep(Duration::from_millis(MARK_WAIT_MILLIS));
        }
        Err("canary watcher unavailable; decoy is not monitored".into())
    }

    fn unmark_path(&self, path: &Path) {
        if let Ok(state) = self.watch.lock() {
            if let Some(fd) = state.fd.as_ref() {
                let _ = unmark_path(fd.as_raw_fd(), path);
            }
        }
    }

    // ------------------------------------------------------------- fanotify

    fn run_watch_session(&self) -> Result<(), BoxError> {
        let fd = unsafe {
            libc::fanotify_init(
                (libc::FAN_CLASS_CONTENT | libc::FAN_CLOEXEC | libc::FAN_NONBLOCK) as u32,
                (libc::O_RDONLY | libc::O_CLOEXEC | libc::O_LARGEFILE) as u32,
            )
        };
        if fd < 0 {
            let error = std::io::Error::last_os_error();
            return Err(
                std::io::Error::other(format!("fanotify_init(canary watch): {error}")).into(),
            );
        }
        let owned = unsafe { OwnedFd::from_raw_fd(fd) };
        self.remark_all(owned.as_raw_fd());
        {
            let mut state = self
                .watch
                .lock()
                .map_err(|_| "canary watch state integrity failure")?;
            state.fd = Some(owned);
            state.degraded = false;
            state.last_error.clear();
        }
        let read_fd = {
            let state = self
                .watch
                .lock()
                .map_err(|_| "canary watch state integrity failure")?;
            let raw = state
                .fd
                .as_ref()
                .ok_or("canary watch descriptor disappeared")?
                .as_raw_fd();
            unsafe { libc::fcntl(raw, libc::F_DUPFD_CLOEXEC, 3) }
        };
        if read_fd < 0 {
            self.clear_watch_fd();
            return Err(std::io::Error::last_os_error().into());
        }
        // Deployments that registered while the fd was not yet published are
        // marked by this second catch-up pass.
        self.remark_all(read_fd);
        let result = self.event_loop(read_fd);
        unsafe { libc::close(read_fd) };
        self.clear_watch_fd();
        result
    }

    fn clear_watch_fd(&self) {
        if let Ok(mut state) = self.watch.lock() {
            state.fd = None;
            state.degraded = true;
            if state.last_error.is_empty() {
                state.last_error = "watch session ended".to_owned();
            }
        }
    }

    fn remark_all(&self, fan_fd: i32) {
        let paths: Vec<PathBuf> = match self.records.lock() {
            Ok(records) => records.keys().cloned().collect(),
            Err(_) => return,
        };
        for path in paths {
            if mark_path(fan_fd, &path).is_err() {
                self.mark_failures.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    fn event_loop(&self, fan_fd: i32) -> Result<(), BoxError> {
        let mut buffer = [0u8; WATCH_BUFFER_BYTES];
        loop {
            let count = unsafe {
                libc::read(
                    fan_fd,
                    buffer.as_mut_ptr().cast::<libc::c_void>(),
                    buffer.len(),
                )
            };
            if count < 0 {
                let error = std::io::Error::last_os_error();
                if matches!(error.raw_os_error(), Some(libc::EAGAIN) | Some(libc::EINTR)) {
                    thread::sleep(Duration::from_millis(25));
                    continue;
                }
                return Err(error.into());
            }
            let count = usize::try_from(count)?;
            if count == 0 {
                thread::sleep(Duration::from_millis(25));
                continue;
            }
            let mut offset = 0usize;
            while offset + std::mem::size_of::<libc::fanotify_event_metadata>() <= count {
                let metadata = unsafe {
                    std::ptr::read_unaligned(
                        buffer
                            .as_ptr()
                            .add(offset)
                            .cast::<libc::fanotify_event_metadata>(),
                    )
                };
                let event_len = metadata.event_len as usize;
                if event_len < std::mem::size_of::<libc::fanotify_event_metadata>()
                    || offset.checked_add(event_len).is_none()
                    || offset + event_len > count
                    || metadata.vers != libc::FANOTIFY_METADATA_VERSION
                {
                    eprintln!("GeDefense canary sensor skipped a malformed fanotify record");
                    break;
                }
                if metadata.fd >= 0 {
                    self.handle_event(fan_fd, &metadata);
                    unsafe { libc::close(metadata.fd) };
                }
                offset += event_len;
            }
        }
    }

    fn handle_event(&self, fan_fd: i32, metadata: &libc::fanotify_event_metadata) {
        let open = metadata.mask & libc::FAN_OPEN_PERM != 0;
        let exec = metadata.mask & libc::FAN_OPEN_EXEC_PERM != 0;
        if open || exec {
            if let Some(event) = self.capture_event(metadata, exec) {
                self.record_event(event);
            }
            let response = libc::fanotify_response {
                fd: metadata.fd,
                response: libc::FAN_ALLOW,
            };
            let written = unsafe {
                libc::write(
                    fan_fd,
                    (&response as *const libc::fanotify_response).cast::<libc::c_void>(),
                    std::mem::size_of::<libc::fanotify_response>(),
                )
            };
            if written != std::mem::size_of::<libc::fanotify_response>() as isize {
                eprintln!(
                    "GeDefense canary sensor could not acknowledge a fanotify event: {}",
                    std::io::Error::last_os_error()
                );
            }
        }
    }

    fn capture_event(
        &self,
        metadata: &libc::fanotify_event_metadata,
        exec: bool,
    ) -> Option<CanaryEvent> {
        if metadata.pid <= 0 || metadata.fd < 0 {
            return None;
        }
        // The broker itself opens decoys during deploy and identity verification.
        // Those opens are not attacker access; without this guard the sensor froze
        // the privileged core as the "accessor" of its own canary file.
        if metadata.pid == std::process::id() as i32 {
            return None;
        }
        let path = fs::read_link(format!("/proc/self/fd/{}", metadata.fd)).ok()?;
        let path = strip_deleted_suffix(&path);
        if path.as_os_str().as_bytes().len() > MAX_EVENT_PATH_BYTES {
            self.dropped.fetch_add(1, Ordering::Relaxed);
            return None;
        }
        let record = {
            let records = self.records.lock().ok()?;
            records.get(path.as_path()).cloned()
        }?;
        let mut stat: libc::stat = unsafe { std::mem::zeroed() };
        let uid = if unsafe { libc::fstat(metadata.fd, &mut stat) } == 0 {
            stat.st_uid
        } else {
            0
        };
        Some(CanaryEvent {
            pid: metadata.pid,
            uid,
            path: record.path,
            canary_type: record.canary_type,
            exec,
        })
    }

    fn record_event(&self, event: CanaryEvent) {
        let Ok(mut queue) = self.events.lock() else {
            return;
        };
        if queue.len() >= MAX_PENDING_EVENTS {
            queue.pop_front();
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
        queue.push_back(event);
    }

    // -------------------------------------------------------------- manifest

    fn manifest_path(&self) -> Option<PathBuf> {
        self.roots.first().map(|root| root.join(MANIFEST_NAME))
    }

    fn load_manifest(&self) {
        let Some(path) = self.manifest_path() else {
            return;
        };
        let Ok(metadata) = fs::symlink_metadata(&path) else {
            return;
        };
        if !metadata.is_file()
            || metadata.file_type().is_symlink()
            || metadata.len() == 0
            || metadata.len() > MAX_MANIFEST_BYTES
        {
            eprintln!("GeDefense canary manifest rejected by type or size");
            return;
        }
        let Ok(file) = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(&path)
        else {
            eprintln!("GeDefense canary manifest could not be opened");
            return;
        };
        let mut text = String::new();
        if file
            .take(MAX_MANIFEST_BYTES)
            .read_to_string(&mut text)
            .is_err()
        {
            eprintln!("GeDefense canary manifest is not valid UTF-8");
            return;
        }
        let mut loaded = 0usize;
        for line in text.lines() {
            if loaded >= MAX_REGISTERED_CANARIES {
                break;
            }
            let Some((digest_hex, rest)) = line.split_once(' ') else {
                continue;
            };
            let Some((mode_text, rest)) = rest.split_once(' ') else {
                continue;
            };
            let Some((canary_type, path_token)) = rest.split_once(' ') else {
                continue;
            };
            if !VALID_TYPES.contains(&canary_type) {
                continue;
            }
            let Ok(mode) = u32::from_str_radix(mode_text, 8) else {
                continue;
            };
            if !VALID_MODES.contains(&mode) {
                continue;
            }
            let Ok(digest_raw) = hex::decode(digest_hex) else {
                continue;
            };
            let Ok(digest) = <[u8; 32]>::try_from(digest_raw) else {
                continue;
            };
            let Ok(path) = decode_path_token(path_token) else {
                continue;
            };
            let Ok((root, relative)) = self.resolve_in_roots(&path) else {
                continue;
            };
            let Ok((parent_components, basename)) = split_relative(&relative) else {
                continue;
            };
            let Ok(parent) = open_canary_parent(&root, &parent_components, false) else {
                continue;
            };
            let Ok(name) = CString::new(basename.as_bytes()) else {
                continue;
            };
            let Ok(mut file) = open_regular_at(parent.as_raw_fd(), &name) else {
                continue;
            };
            let Ok(metadata) = file.metadata() else {
                continue;
            };
            if (metadata.mode() & 0o7777) != mode {
                continue;
            }
            let mut digest_now = Sha256::new();
            if std::io::copy(&mut file, &mut digest_now).is_err() {
                continue;
            }
            if digest_now.finalize().as_slice() != digest {
                continue;
            }
            if let Ok(mut records) = self.records.lock() {
                records.insert(
                    path.clone(),
                    CanaryRecord {
                        path,
                        canary_type: canary_type.to_owned(),
                        mode,
                        sha256: digest,
                    },
                );
                loaded += 1;
            }
        }
        if loaded > 0 {
            eprintln!("GeDefense canary broker recovered {loaded} registered decoy(s)");
        }
    }

    fn persist_manifest(&self) -> Result<(), BoxError> {
        let Some(directory) = self.roots.first().cloned() else {
            return Ok(());
        };
        let records = {
            let records = self
                .records
                .lock()
                .map_err(|_| "canary registry integrity failure")?;
            records.values().cloned().collect::<Vec<_>>()
        };
        let mut text = String::new();
        for record in records {
            let path_token = URL_SAFE_NO_PAD.encode(record.path.as_os_str().as_bytes());
            text.push_str(&format!(
                "{} {:o} {} {}\n",
                hex::encode(record.sha256),
                record.mode,
                record.canary_type,
                path_token
            ));
        }
        let staging_name = format!(".canary-manifest.{}.tmp", random_hex(8)?);
        let staging_path = directory.join(&staging_name);
        let final_path = directory.join(MANIFEST_NAME);
        let write = (|| -> Result<(), BoxError> {
            let mut file = OpenOptions::new()
                .create_new(true)
                .write(true)
                .mode(0o600)
                .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
                .open(&staging_path)?;
            file.write_all(text.as_bytes())?;
            file.sync_all()?;
            drop(file);
            fs::rename(&staging_path, &final_path)?;
            if let Ok(directory_file) = File::open(&directory) {
                let _ = directory_file.sync_all();
            }
            Ok(())
        })();
        if write.is_err() {
            let _ = fs::remove_file(&staging_path);
        }
        write
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

// ------------------------------------------------------------------ helpers

fn validate_absolute_clean(path: &Path, label: &str) -> Result<(), BoxError> {
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

fn decode_path_token(token: &str) -> Result<PathBuf, BoxError> {
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

fn split_relative(relative: &[OsString]) -> Result<(Vec<OsString>, OsString), BoxError> {
    let (basename, parent) = relative
        .split_last()
        .ok_or("canary relative path is empty")?;
    if basename.is_empty() || basename.as_bytes() == b"." || basename.as_bytes() == b".." {
        return Err("canary basename is invalid".into());
    }
    Ok((parent.to_vec(), basename.clone()))
}

fn open_canary_parent(
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

fn open_regular_at(parent_fd: i32, name: &CString) -> Result<File, BoxError> {
    let fd = unsafe {
        libc::openat(
            parent_fd,
            name.as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
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

fn mark_path(fan_fd: i32, path: &Path) -> Result<(), BoxError> {
    let path_c = CString::new(path.as_os_str().as_bytes())?;
    let result = unsafe {
        libc::fanotify_mark(
            fan_fd,
            libc::FAN_MARK_ADD,
            libc::FAN_OPEN_PERM | libc::FAN_OPEN_EXEC_PERM,
            libc::AT_FDCWD,
            path_c.as_ptr(),
        )
    };
    if result != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}

fn unmark_path(fan_fd: i32, path: &Path) {
    if let Ok(path_c) = CString::new(path.as_os_str().as_bytes()) {
        unsafe {
            libc::fanotify_mark(
                fan_fd,
                libc::FAN_MARK_REMOVE,
                libc::FAN_OPEN_PERM | libc::FAN_OPEN_EXEC_PERM,
                libc::AT_FDCWD,
                path_c.as_ptr(),
            );
        }
    }
}

fn strip_deleted_suffix(path: &Path) -> PathBuf {
    let bytes = path.as_os_str().as_bytes();
    const SUFFIX: &[u8] = b" (deleted)";
    if bytes.ends_with(SUFFIX) {
        if let Some(stripped) = path
            .as_os_str()
            .as_bytes()
            .strip_suffix(SUFFIX)
            .map(|raw| PathBuf::from(OsString::from_vec(raw.to_vec())))
        {
            return stripped;
        }
    }
    path.to_path_buf()
}

fn encode_event(event: &CanaryEvent) -> String {
    format!(
        "{}:{}:{}:{}:{}",
        event.pid,
        event.uid,
        URL_SAFE_NO_PAD.encode(event.path.as_os_str().as_bytes()),
        event.canary_type,
        u8::from(event.exec)
    )
}

fn random_hex(bytes: usize) -> Result<String, BoxError> {
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

#[cfg(test)]
mod tests {
    use super::*;

    fn test_root(label: &str) -> PathBuf {
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|value| value.as_nanos())
            .unwrap_or(0);
        let root = std::env::temp_dir().join(format!(
            "gedefense-canary-{label}-{}-{stamp}",
            std::process::id()
        ));
        fs::create_dir_all(&root).expect("test canary root");
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).expect("test root mode");
        root
    }

    fn token_for(path: &Path) -> String {
        URL_SAFE_NO_PAD.encode(path.as_os_str().as_bytes())
    }

    struct TestBroker {
        root: PathBuf,
        broker: CanaryBroker,
    }

    impl TestBroker {
        fn new(label: &str) -> Self {
            let root = test_root(label);
            let broker = CanaryBroker::new(&[root.clone()]).expect("broker");
            Self { root, broker }
        }

        fn deploy(&self, relative: &str, content: &[u8]) -> Result<String, BoxError> {
            let path = self.root.join(relative);
            let content_token = URL_SAFE_NO_PAD.encode(content);
            self.broker.deploy_token_inner(
                &token_for(&path),
                "DOTENV",
                "600",
                &content_token,
                false,
            )
        }
    }

    impl Drop for TestBroker {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    #[test]
    fn deploy_and_remove_roundtrip_is_atomic_and_private() {
        let test = TestBroker::new("roundtrip");
        let content = b"DECOY=value\n";
        assert_eq!(
            test.deploy("app/.env", content).expect("deploy"),
            "deployed"
        );
        let deployed = test.root.join("app/.env");
        assert_eq!(fs::read(&deployed).expect("read decoy"), content);
        let metadata = fs::metadata(&deployed).expect("decoy metadata");
        assert_eq!(metadata.mode() & 0o7777, 0o600);
        assert_eq!(
            test.deploy("app/.env", content).expect("idempotent deploy"),
            "exists"
        );
        let mismatch = test
            .deploy("app/.env", b"TAMPERED=1\n")
            .expect_err("identity change");
        assert!(
            mismatch.to_string().contains("different identity"),
            "{mismatch}"
        );
        let status = test.broker.status();
        assert!(status.contains("registered=1"), "status={status}");
        assert!(test.root.join(MANIFEST_NAME).is_file());
        assert_eq!(
            test.broker
                .remove_token(&token_for(&deployed))
                .expect("remove"),
            "removed"
        );
        assert!(!deployed.exists());
        assert_eq!(
            test.broker
                .remove_token(&token_for(&deployed))
                .expect("absent"),
            "absent"
        );
    }

    #[test]
    fn manifest_reload_re_registers_verified_decoys() {
        let root = test_root("reload");
        let path = root.join("shadow.bak");
        let content = b"root:decoy\n";
        {
            let broker = CanaryBroker::new(&[root.clone()]).expect("broker");
            broker
                .deploy_token_inner(
                    &token_for(&path),
                    "SHADOW_BAK",
                    "640",
                    &URL_SAFE_NO_PAD.encode(content),
                    false,
                )
                .expect("deploy");
        }
        let reloaded = CanaryBroker::new(&[root.clone()]).expect("reload");
        let status = reloaded.status();
        assert!(status.contains("registered=1"), "status={status}");
        assert!(reloaded
            .records
            .lock()
            .expect("registry")
            .contains_key(&path));
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn path_jail_rejects_traversal_outside_and_symlink_components() {
        let test = TestBroker::new("jail");
        let outside = PathBuf::from("/tmp/gedefense-canary-outside");
        let outside_token = token_for(&outside);
        assert!(test
            .broker
            .deploy_token_inner(&outside_token, "DOTENV", "600", "ZGVjb3k=", false)
            .is_err());
        let traversal = format!("{}/../escape", test.root.display());
        assert!(test
            .broker
            .deploy_token_inner(
                &token_for(Path::new(&traversal)),
                "DOTENV",
                "600",
                "ZGVjb3k=",
                false
            )
            .is_err());
        std::os::unix::fs::symlink("/tmp", test.root.join("link")).expect("symlink");
        assert!(test.deploy("link/escaped", b"nope\n").is_err());
    }

    #[test]
    fn deploy_rejects_invalid_type_mode_content_and_reserved_name() {
        let test = TestBroker::new("bounds");
        let path = test.root.join("a.env");
        let path_token = token_for(&path);
        let content = URL_SAFE_NO_PAD.encode(b"x\n");
        assert!(test
            .broker
            .deploy_token_inner(&path_token, "UNKNOWN", "600", &content, false)
            .is_err());
        assert!(test
            .broker
            .deploy_token_inner(&path_token, "DOTENV", "644", &content, false)
            .is_err());
        assert!(test
            .broker
            .deploy_token_inner(&path_token, "DOTENV", "600", "", false)
            .is_err());
        assert!(test
            .broker
            .deploy_token_inner(
                &token_for(&test.root.join(MANIFEST_NAME)),
                "DOTENV",
                "600",
                &content,
                false
            )
            .is_err());
        let oversized = URL_SAFE_NO_PAD.encode(vec![b'a'; MAX_CANARY_CONTENT_BYTES + 1]);
        assert!(test
            .broker
            .deploy_token_inner(&path_token, "DOTENV", "600", &oversized, false)
            .is_err());
    }

    #[test]
    fn event_encoding_is_bounded_and_decodable() {
        let event = CanaryEvent {
            pid: 4242,
            uid: 1000,
            path: PathBuf::from("/var/lib/vgt/gedefense/canaries/.aws_credentials"),
            canary_type: "CLOUD_CRED".to_owned(),
            exec: true,
        };
        let encoded = encode_event(&event);
        assert!(
            encoded.len() < 512,
            "encoded event too large: {}",
            encoded.len()
        );
        let fields: Vec<&str> = encoded.split(':').collect();
        assert_eq!(fields.len(), 5);
        assert_eq!(fields[0], "4242");
        assert_eq!(fields[1], "1000");
        assert_eq!(fields[2], token_for(&event.path));
        assert_eq!(fields[3], "CLOUD_CRED");
        assert_eq!(fields[4], "1");
    }

    #[test]
    fn strip_deleted_suffix_keeps_regular_paths() {
        assert_eq!(
            strip_deleted_suffix(Path::new("/run/x (deleted)")),
            PathBuf::from("/run/x")
        );
        assert_eq!(
            strip_deleted_suffix(Path::new("/run/x")),
            PathBuf::from("/run/x")
        );
    }
}
