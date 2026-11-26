use super::*;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use std::{
    ffi::{CString, OsString},
    fs::{self, File},
    io::Read,
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd},
        unix::ffi::{OsStrExt, OsStringExt},
    },
    path::{Path, PathBuf},
    sync::atomic::Ordering,
    thread,
    time::Duration,
};

impl CanaryBroker {
    pub(super) fn set_watch_degraded(&self, error: &str) {
        if let Ok(mut state) = self.watch.lock() {
            state.degraded = true;
            state.last_error = error.chars().take(96).collect();
        }
    }

    pub(super) fn wait_for_mark(&self, path: &Path) -> Result<(), BoxError> {
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

    pub(super) fn unmark_path(&self, path: &Path) {
        if let Ok(state) = self.watch.lock() {
            if let Some(fd) = state.fd.as_ref() {
                let _ = unmark_path(fd.as_raw_fd(), path);
            }
        }
    }

    // ------------------------------------------------------------- fanotify

    pub(super) fn run_watch_session(&self) -> Result<(), BoxError> {
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
        // FIND-036a: the fanotify event only names the accessing pid. A fstat on
        // metadata.fd reports the UID of the decoy file itself (root), never the
        // UID of the accessor, so every canary hit used to be attributed to UID 0
        // and the control plane downgraded it to "system access". The accessor
        // identity is read from /proc/<pid>/status instead.
        let uid = accessor_uid(metadata.pid).unwrap_or(CANARY_UID_UNKNOWN);
        Some(CanaryEvent {
            pid: metadata.pid,
            uid,
            path: record.path,
            canary_type: record.canary_type,
            exec,
        })
    }

    pub(crate) fn record_event(&self, event: CanaryEvent) {
        if event
            .path
            .file_name()
            .and_then(|name| name.to_str())
            == Some(SELF_TEST_DECOY_NAME)
        {
            if let Ok(mut hits) = self.self_test_hits.lock() {
                if hits.len() >= MAX_SELF_TEST_HITS {
                    hits.pop_front();
                }
                hits.push_back((event.pid, event.path));
            }
            return;
        }
        let Ok(mut queue) = self.events.lock() else {
            return;
        };
        if queue.len() >= MAX_PENDING_EVENTS {
            queue.pop_front();
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
        queue.push_back(event);
    }
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

pub(super) fn strip_deleted_suffix(path: &Path) -> PathBuf {
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

// FIND-036a: resolve the UID of the process the kernel named in the fanotify
// event. /proc/<pid>/status carries the Uid: line as
// "Uid: <real> <effective> <saved> <fs>"; the effective UID is the identity the
// process acted with. Any unreadable or malformed status yields None so the
// caller can attribute the event as unknown instead of guessing root.
pub(super) fn parse_uid_from_status(status: &str) -> Option<u32> {
    let line = status.lines().find(|line| line.starts_with("Uid:"))?;
    let fields: Vec<&str> = line.split_whitespace().collect();
    if fields.len() != 5 || fields[0] != "Uid:" {
        return None;
    }
    // Validate the whole line so a partially fabricated status is never trusted.
    for field in &fields[1..5] {
        field.parse::<u32>().ok()?;
    }
    fields[2].parse::<u32>().ok()
}

pub(super) fn accessor_uid(pid: i32) -> Option<u32> {
    if pid <= 0 {
        return None;
    }
    let file = File::open(format!("/proc/{pid}/status")).ok()?;
    let mut status = String::with_capacity(1024);
    file.take(8192).read_to_string(&mut status).ok()?;
    parse_uid_from_status(&status)
}

pub(super) fn encode_event(event: &CanaryEvent) -> String {
    format!(
        "{}:{}:{}:{}:{}",
        event.pid,
        event.uid,
        URL_SAFE_NO_PAD.encode(event.path.as_os_str().as_bytes()),
        event.canary_type,
        u8::from(event.exec)
    )
}
