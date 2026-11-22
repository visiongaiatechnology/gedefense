//! M1.1 (6.2.0): asynchronous on-write malware sensor for untrusted drop roots.
//!
//! A second, independent fanotify group watches the configured drop roots with
//! `FAN_CLOSE_WRITE` only. It never registers a `FAN_*_PERM` event and never
//! answers the kernel, so a writer is never blocked, held or slowed down by the
//! sensor; the initial open/exec protection stays with the pre-existing
//! `FAN_OPEN_EXEC_PERM` group in `malware.rs`.
//!
//! Architecture (bounded, fail-safe):
//! - one kernel-reader thread per sensor session; it only claims the event fd
//!   into a *bounded* channel and closes it again when the channel is full
//!   (counted through the pre-existing malware event drop counter),
//! - one scanner worker that classifies and scans, so a slow hash never stalls
//!   the kernel read loop,
//! - candidate filter (see [`Candidate`]) keeps the scan budget small:
//!   executables outside the trusted system trees are fully inspected and
//!   non-executable files up to 16 MiB get the bounded signature/archive
//!   probe, independent of the writer's uid. A webserver or pentest user
//!   writing into `/tmp`, `/var/tmp`, `/dev/shm` or `/var/www` is therefore
//!   visible instead of being discarded by an ownership filter.
//!
//! A malicious verdict is handed to the pre-existing [`QuarantineBroker`]
//! *after* re-reading the current file identity and comparing its SHA-256 with
//! the scanned digest, so a rename/replace race between scan and capture can
//! never quarantine a clean file (the broker repeats the identity check under
//! its own rename lock anyway). No verdict ever deletes a file directly.
//!
//! Root selection: the drop roots must be writable by the core for a *move*
//! quarantine, otherwise the broker's copy fallback correctly refuses to report
//! success while the source remains (FIND-035). The shipped systemd unit
//! therefore grants exactly `/tmp`, `/var/tmp`, `/dev/shm` and `/var/www`; `/opt`
//! and `/home` are deliberately not on-write roots because the unit keeps them
//! read-only (exec protection for `/home` remains in place).

use crate::{
    malware::{encode_path_token, MalwareScanner, ScanVerdict},
    on_write_policy::{
        classify_candidate, path_is_below_any, path_is_trusted, Candidate, MAX_ON_WRITE_ROOTS,
    },
    quarantine::QuarantineBroker,
};
use std::{
    fs::{self, File},
    io::Read,
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd, RawFd},
        unix::fs::MetadataExt,
    },
    path::PathBuf,
    sync::{
        atomic::{AtomicU64, Ordering},
        mpsc::{sync_channel, Receiver, SyncSender, TrySendError},
        Arc,
    },
    thread,
    time::Duration,
};

type BoxError = Box<dyn std::error::Error + Send + Sync + 'static>;

/// Default on-write roots (re-exported from the policy module for `main.rs`).
pub(crate) use crate::on_write_policy::resolve_roots;

/// Bounded queue between the kernel reader and the scanner worker.
const ON_WRITE_QUEUE_DEPTH: usize = 1024;
/// How often a full queue is summarised on stderr (drop counting stays exact).
const DROP_LOG_EVERY: u64 = 4096;
/// Read buffer for one `read(2)` on the fanotify group.
const EVENT_BUFFER_BYTES: usize = 64 * 1024;
/// The configured on-write sensor of one core instance.
pub(crate) struct OnWriteSensor {
    roots: Vec<PathBuf>,
    scanner: MalwareScanner,
    quarantine: Arc<QuarantineBroker>,
    dropped: Arc<AtomicU64>,
}

impl OnWriteSensor {
    /// Validates the root set and starts both threads. Only a thread-spawn
    /// failure is fatal; every later sensor error is retried with backoff and
    /// never aborts the privileged core (same F-HOTFIX-1 doctrine as the
    /// pre-existing on-access sensor).
    pub(crate) fn start(
        scanner: MalwareScanner,
        quarantine: Arc<QuarantineBroker>,
        roots: &[PathBuf],
    ) -> Result<(), BoxError> {
        if roots.is_empty() || roots.len() > MAX_ON_WRITE_ROOTS {
            return Err("on-write root boundary rejected".into());
        }
        let mut unique = Vec::with_capacity(roots.len());
        for root in roots {
            if !unique.iter().any(|known: &PathBuf| known == root) {
                unique.push(root.clone());
            }
        }
        let sensor = Self {
            roots: unique,
            scanner,
            quarantine,
            dropped: Arc::new(AtomicU64::new(0)),
        };
        let (tx, rx) = sync_channel::<QueuedWrite>(ON_WRITE_QUEUE_DEPTH);
        let worker = sensor.clone_shared();
        thread::Builder::new()
            .name("gedefense-on-write-scan".to_owned())
            .spawn(move || worker.scan_worker(rx))?;
        let reader = sensor.clone_shared();
        thread::Builder::new()
            .name("gedefense-on-write".to_owned())
            .spawn(move || reader.reader_loop(tx))?;
        Ok(())
    }

    fn clone_shared(&self) -> Self {
        Self {
            roots: self.roots.clone(),
            scanner: self.scanner.clone(),
            quarantine: Arc::clone(&self.quarantine),
            dropped: Arc::clone(&self.dropped),
        }
    }

    /// Kernel reader: never scans, never blocks on the worker.
    fn reader_loop(&self, tx: SyncSender<QueuedWrite>) {
        let mut backoff = Duration::from_secs(1);
        loop {
            match self.run_reader_session(&tx) {
                Ok(()) => eprintln!("GeDefense on-write session ended; restarting sensor"),
                Err(error) => eprintln!(
                    "GeDefense on-write sensor degraded: {error}; retrying in {backoff:?}"
                ),
            }
            thread::sleep(backoff);
            backoff = std::cmp::min(backoff.saturating_mul(2), Duration::from_secs(30));
        }
    }

    fn run_reader_session(&self, tx: &SyncSender<QueuedWrite>) -> Result<(), BoxError> {
        let fan_fd = unsafe {
            libc::fanotify_init(
                libc::FAN_CLASS_NOTIF | libc::FAN_CLOEXEC | libc::FAN_NONBLOCK,
                (libc::O_RDONLY | libc::O_CLOEXEC | libc::O_LARGEFILE) as u32,
            )
        };
        if fan_fd < 0 {
            return Err(std::io::Error::other(format!(
                "fanotify_init(FAN_CLASS_NOTIF): {}",
                std::io::Error::last_os_error()
            ))
            .into());
        }
        let marked = match self.mark_roots(fan_fd) {
            Ok(marked) => marked,
            Err(error) => {
                close_quiet(fan_fd);
                return Err(error);
            }
        };
        if marked == 0 {
            close_quiet(fan_fd);
            return Err("none of the on-write watch roots exists".into());
        }
        let result = self.read_events(fan_fd, tx);
        close_quiet(fan_fd);
        result
    }

    /// Marks each distinct superblock backing the watch roots with
    /// `FAN_MARK_FILESYSTEM` + `FAN_CLOSE_WRITE`. Using filesystem marks
    /// instead of `FAN_MARK_MOUNT` is required when `gedefense-core` runs
    /// under systemd `ProtectSystem=strict` + `ReadWritePaths=-/tmp ...`,
    /// where private bind mounts otherwise isolate the service from writes in
    /// the host mount namespace. The candidate filter still checks exact root
    /// prefixes before scanning.
    fn mark_roots(&self, fan_fd: i32) -> Result<usize, BoxError> {
        let mut marked = 0usize;
        let mut seen_devs: Vec<u64> = Vec::with_capacity(self.roots.len());
        for root in &self.roots {
            let metadata = match fs::symlink_metadata(root) {
                Ok(metadata) => metadata,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    eprintln!(
                        "GeDefense on-write watch root missing, skipped: {}",
                        root.display()
                    );
                    continue;
                }
                Err(error) => {
                    return Err(std::io::Error::other(format!(
                        "on-write watch-root metadata path={} error={error}",
                        root.display()
                    ))
                    .into())
                }
            };
            if !metadata.is_dir() || metadata.file_type().is_symlink() {
                return Err("on-write watch root type rejected".into());
            }
            if seen_devs.contains(&metadata.dev()) {
                marked += 1;
                continue;
            }
            let path_c = std::ffi::CString::new(root.as_os_str().as_encoded_bytes())?;
            let rc = unsafe {
                libc::fanotify_mark(
                    fan_fd,
                    libc::FAN_MARK_ADD | libc::FAN_MARK_FILESYSTEM,
                    libc::FAN_CLOSE_WRITE,
                    libc::AT_FDCWD,
                    path_c.as_ptr(),
                )
            };
            if rc != 0 {
                return Err(std::io::Error::other(format!(
                    "fanotify_mark(FAN_CLOSE_WRITE) path={} error={}",
                    root.display(),
                    std::io::Error::last_os_error()
                ))
                .into());
            }
            seen_devs.push(metadata.dev());
            marked += 1;
        }
        Ok(marked)
    }

    fn read_events(&self, fan_fd: i32, tx: &SyncSender<QueuedWrite>) -> Result<(), BoxError> {
        let mut buffer = [0u8; EVENT_BUFFER_BYTES];
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
                    thread::sleep(Duration::from_millis(20));
                    continue;
                }
                return Err(error.into());
            }
            let count = usize::try_from(count)?;
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
                    eprintln!("GeDefense on-write skipped a malformed fanotify record");
                    break;
                }
                if metadata.mask & libc::FAN_Q_OVERFLOW != 0 {
                    self.note_dropped();
                } else if metadata.fd >= 0 && metadata.mask & libc::FAN_CLOSE_WRITE != 0 {
                    match tx.try_send(QueuedWrite {
                        fd: metadata.fd,
                        pid: metadata.pid,
                    }) {
                        Ok(()) => {}
                        Err(TrySendError::Full(queued)) => {
                            close_quiet(queued.fd);
                            self.note_dropped();
                        }
                        Err(TrySendError::Disconnected(queued)) => {
                            close_quiet(queued.fd);
                            return Err("on-write scan worker is gone".into());
                        }
                    }
                } else if metadata.fd >= 0 {
                    close_quiet(metadata.fd);
                }
                offset += event_len;
            }
        }
    }

    fn note_dropped(&self) {
        let dropped = self.dropped.fetch_add(1, Ordering::Relaxed) + 1;
        if dropped % DROP_LOG_EVERY == 1 {
            eprintln!("GeDefense on-write scan queue full; {dropped} events dropped so far");
        }
    }

    fn scan_worker(&self, rx: Receiver<QueuedWrite>) {
        while let Ok(queued) = rx.recv() {
            let owned = unsafe { OwnedFd::from_raw_fd(queued.fd) };
            if let Err(error) = self.handle_write(queued.pid, owned) {
                eprintln!("GeDefense on-write scan failed: {error}");
            }
        }
    }

    fn handle_write(&self, pid: i32, owned: OwnedFd) -> Result<(), BoxError> {
        if pid <= 0 {
            return Ok(());
        }
        let Some(path) = event_file_path(owned.as_raw_fd()) else {
            return Ok(());
        };
        if !path_is_below_any(&path, &self.roots) || path_is_trusted(&path) {
            return Ok(());
        }
        let file = File::from(owned);
        let metadata = file.metadata()?;
        let Some(candidate) = classify_candidate(&metadata) else {
            return Ok(());
        };
        let mut capture_file = file.try_clone()?;
        // Hash the same descriptor the kernel handed us, so the scan cannot be
        // redirected by a path swap; the broker re-checks the path identity.
        let verdict = match candidate {
            Candidate::FullScan | Candidate::SignatureProbe => self.scanner.scan_on_write(file),
        };
        let token = encode_path_token(path.as_os_str().as_encoded_bytes());
        match verdict {
            Ok(verdict) if verdict.state == "malicious" => {
                self.quarantine_hit(pid, metadata.uid(), &token, &mut capture_file, verdict);
                Ok(())
            }
            Ok(verdict) if verdict.state == "suspicious" => self.scanner.record_on_write_event(
                pid,
                metadata.uid(),
                token,
                "suspicious",
                verdict.reason,
                verdict.sha256,
                verdict.size,
                verdict.classification,
            ),
            Ok(_) => Ok(()),
            Err(error) => {
                self.scanner.record_on_write_event(
                    pid,
                    metadata.uid(),
                    token,
                    "suspicious",
                    "on-write-scan-error".to_owned(),
                    [0u8; 32],
                    0,
                    "unknown",
                )?;
                Err(format!("on-write scan error: {error}").into())
            }
        }
    }

    /// Moves an already re-verified malicious file into the encrypted vault.
    /// Never reports success without the broker's own identity check.
    fn quarantine_hit(
        &self,
        pid: i32,
        file_uid: u32,
        token: &str,
        capture_file: &mut File,
        verdict: ScanVerdict,
    ) {
        let reason = if token == "-" {
            eprintln!(
                "GeDefense on-write malicious file has no stable path; not quarantined sha256={}",
                hex::encode(verdict.sha256)
            );
            "on-write-quarantine-unavailable"
        } else {
            match self.try_quarantine(token, capture_file, &verdict) {
                Ok(()) => "on-write-quarantined",
                Err(error) => {
                    eprintln!(
                        "GeDefense on-write quarantine failed sha256={} error={error}",
                        hex::encode(verdict.sha256)
                    );
                    "on-write-quarantine-failed"
                }
            }
        };
        if let Err(error) = self.scanner.record_on_write_event(
            pid,
            file_uid,
            token.to_owned(),
            "malicious",
            reason.to_owned(),
            verdict.sha256,
            verdict.size,
            verdict.classification,
        ) {
            eprintln!("GeDefense on-write event queue failed: {error}");
        }
    }

    /// Captures the scanned malicious payload using the already-open kernel
    /// descriptor so `0600`/`0660` non-root files in drop roots are quarantined
    /// without widening DAC capabilities.
    fn try_quarantine(
        &self,
        token: &str,
        capture_file: &mut File,
        verdict: &ScanVerdict,
    ) -> Result<(), BoxError> {
        let object_id = random_object_id()?;
        self.quarantine.quarantine_open_file(
            token,
            capture_file,
            &object_id,
            verdict.sha256,
            verdict.size,
        )?;
        Ok(())
    }
}

/// Event fd + writer pid handed from the kernel reader to the scanner worker.
struct QueuedWrite {
    fd: RawFd,
    pid: i32,
}

pub(crate) fn close_quiet(fd: RawFd) {
    unsafe { libc::close(fd) };
}

/// Current path of an event descriptor. A file unlinked after the write cannot
/// be captured by path; it is already gone, so there is nothing left to move.
pub(crate) fn event_file_path(fd: RawFd) -> Option<PathBuf> {
    let path = fs::read_link(format!("/proc/self/fd/{fd}")).ok()?;
    let text = path.to_str()?;
    if text.ends_with(" (deleted)") {
        return None;
    }
    Some(path)
}

/// `QV-` plus 16 lowercase hex characters: the pre-existing quarantine object id
/// format. The id is random, never derived from content, so two identical
/// payloads cannot collide in the vault.
pub(crate) fn random_object_id() -> Result<String, BoxError> {
    let mut bytes = [0u8; 8];
    File::open("/dev/urandom")?.read_exact(&mut bytes)?;
    Ok(format!("QV-{}", hex::encode(bytes)))
}
