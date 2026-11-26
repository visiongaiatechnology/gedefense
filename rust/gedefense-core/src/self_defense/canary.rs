use super::*;

/// Canary sensor state exposed through `SELF_GUARD_STATUS`.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum CanaryState {
    Unknown,
    Active,
    Degraded,
}

impl CanaryState {
    pub(super) fn token(self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::Active => "active",
            Self::Degraded => "degraded",
        }
    }
}

/// Result of one synthetic canary cycle, produced off the IPC path.
pub(super) enum CanaryOutcome {
    /// The decoy was deployed, a real access was observed and the decoy removed.
    Success,
    /// The canary chain expected to fire did not: self-tamper evidence.
    SensorFailure { code: u32 },
    /// The broker cannot run the self-test on this host (e.g. the operator
    /// configured a canary root the self-test cannot resolve to). This degrades
    /// the canary status honestly without inventing an attack.
    Unavailable { code: u32 },
}

impl SelfDefenseCore {
    /// Attaches the already-started canary broker for the synthetic self-test.
    pub(crate) fn attach_canary(&mut self, canary: crate::canary::CanaryBroker) {
        self.canary = Some(canary);
        if self.enabled {
            self.canary_due_ms = unix_millis();
        }
    }
}

impl SelfDefenseCore {
    pub(super) fn reap_canary_worker(&mut self, now_ms: u64) {
        let Some(handle) = self.canary_worker.take() else {
            return;
        };
        if !handle.is_finished() {
            self.canary_worker = Some(handle);
            return;
        }
        match handle.join() {
            Ok(outcome) => self.apply_canary_outcome(outcome, now_ms),
            Err(_) => self.apply_canary_outcome(
                CanaryOutcome::SensorFailure {
                    code: CODE_CANARY_PANIC,
                },
                now_ms,
            ),
        }
    }

    pub(super) fn start_canary_worker(&mut self, now_ms: u64) {
        let Some(broker) = self.canary.clone() else {
            self.canary_due_ms = now_ms.saturating_add(CANARY_TEST_INTERVAL_MS);
            return;
        };
        let path = broker.primary_root().join(SELF_TEST_DECOY_NAME);
        let path_token = URL_SAFE_NO_PAD.encode(path.as_os_str().as_bytes());
        let content_token = URL_SAFE_NO_PAD.encode(DECOY_CONTENT);
        let spawn = thread::Builder::new()
            .name("gedefense-canary-selftest".to_owned())
            .stack_size(CANARY_WORKER_STACK_BYTES)
            .spawn(move || run_canary_self_test(broker, path, path_token, content_token));
        match spawn {
            Ok(handle) => self.canary_worker = Some(handle),
            Err(_) => self.apply_canary_outcome(
                CanaryOutcome::SensorFailure {
                    code: CODE_CANARY_SPAWN,
                },
                now_ms,
            ),
        }
    }

    pub(super) fn apply_canary_outcome(&mut self, outcome: CanaryOutcome, now_ms: u64) {
        match outcome {
            CanaryOutcome::Success => {
                self.canary_runs = self.canary_runs.saturating_add(1);
                self.canary_state = CanaryState::Active;
                if self.canary_dead_reported {
                    self.canary_dead_reported = false;
                    self.push_event(now_ms, KIND_CANARY_RECOVERED, 0, b"selftest");
                }
            }
            CanaryOutcome::SensorFailure { code } => {
                self.canary_failures = self.canary_failures.saturating_add(1);
                self.canary_state = CanaryState::Degraded;
                if !self.canary_dead_reported {
                    self.canary_dead_reported = true;
                    self.push_event(now_ms, KIND_CANARY_DEAD, code, b"selftest");
                }
            }
            CanaryOutcome::Unavailable { code } => {
                self.canary_failures = self.canary_failures.saturating_add(1);
                self.canary_state = CanaryState::Degraded;
                // A configuration mismatch is a capability fact, not an attack:
                // it degrades the canary status and lets the retry cadence
                // re-evaluate it. The code is intentionally not put on the wire
                // because it is not a tamper record.
                let _ = code;
            }
        }
        self.canary_due_ms = now_ms.saturating_add(CANARY_TEST_INTERVAL_MS);
    }
}

/// Runs one full canary cycle on the worker thread. Every blocking operation is
/// bounded by the constants above; the caller only ever joins a finished thread.
pub(super) fn run_canary_self_test(
    broker: crate::canary::CanaryBroker,
    path: PathBuf,
    path_token: String,
    content_token: String,
) -> CanaryOutcome {
    let queued_before = match parse_canary_status(&broker.status()) {
        Some((true, queued)) => queued,
        _ => {
            return CanaryOutcome::SensorFailure {
                code: CODE_CANARY_WATCHER,
            }
        }
    };
    // A decoy left behind by an interrupted cycle is removed first, so the
    // deployment itself is always a fresh, observed event.
    let _ = broker.remove_token(&path_token);
    match broker.deploy_token(
        &path_token,
        DECOY_CANARY_TYPE,
        DECOY_MODE_TOKEN,
        &content_token,
    ) {
        Ok(state) if state == "deployed" || state == "exists" => {}
        Ok(_) => {
            return CanaryOutcome::SensorFailure {
                code: CODE_CANARY_DEPLOY,
            }
        }
        Err(error) => {
            let message = error.to_string();
            if message.contains("outside every configured canary root") {
                return CanaryOutcome::Unavailable {
                    code: CODE_CANARY_SCOPE,
                };
            }
            return CanaryOutcome::SensorFailure {
                code: if message.contains("canary watcher unavailable") {
                    CODE_CANARY_WATCHER
                } else {
                    CODE_CANARY_DEPLOY
                },
            };
        }
    }
    let probe_pid = match probe_decoy_open(&path) {
        Ok(pid) => pid,
        Err(_) => {
            let _ = broker.remove_token(&path_token);
            return CanaryOutcome::SensorFailure {
                code: CODE_CANARY_PROBE,
            };
        }
    };
    // The decoy access is recorded before fanotify returns FAN_ALLOW to the probe
    // child. Check the dedicated self-test channel first so concurrent Go
    // CANARY_EVENTS IPC polling cannot race with self-defense verification.
    let mut observed = broker.consume_self_test_hit(&path, probe_pid);
    if !observed {
        let queued_after = parse_canary_status(&broker.status())
            .map(|(_, queued)| queued)
            .unwrap_or(queued_before);
        for _ in 0..CANARY_DRAIN_ATTEMPTS {
            match broker.take_events() {
                Ok(batch) => {
                    if canary_batch_observed(&batch, &path, probe_pid) {
                        observed = true;
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        if !observed && queued_after > queued_before {
            observed = true;
        }
    }
    let _ = broker.remove_token(&path_token);
    if observed {
        CanaryOutcome::Success
    } else {
        CanaryOutcome::SensorFailure {
            code: CODE_CANARY_NO_EVENT,
        }
    }
}

/// Parses `CANARY_STATUS` (bounded `key=value:...`) for the watcher state and
/// the queued-event count. Returns `None` for a shape this module does not
/// recognize, so an unknown answer is never silently treated as healthy.
pub(super) fn parse_canary_status(status: &str) -> Option<(bool, u64)> {
    if status.is_empty() || status.len() > 512 || status.contains('\0') {
        return None;
    }
    let mut watcher = None;
    let mut queued = None;
    for field in status.split(':') {
        let (key, value) = field.split_once('=')?;
        match key {
            "watcher" => {
                if value != "active" && value != "degraded" {
                    return None;
                }
                watcher = Some(value == "active");
            }
            "queued" => {
                if value.is_empty()
                    || value.len() > 20
                    || !value.bytes().all(|b| b.is_ascii_digit())
                {
                    return None;
                }
                queued = value.parse::<u64>().ok();
            }
            _ => {}
        }
    }
    Some((watcher?, queued?))
}

/// True when one drained `CANARY_EVENTS` batch carries the decoy access of the
/// probe child. The batch shape is `empty` or `<dropped>|<record>[,...]` with the
/// record `pid:uid:path_b64:type:exec` (canary.rs `encode_event`).
pub(super) fn canary_batch_observed(batch: &str, path: &Path, probe_pid: i32) -> bool {
    if batch == "empty" || batch.is_empty() || batch.len() > 4 * 1024 || batch.contains('\0') {
        return false;
    }
    let Some((_, records)) = batch.split_once('|') else {
        return false;
    };
    if records.is_empty() {
        return false;
    }
    let expected_path = path.as_os_str().as_bytes();
    for record in records.split(',').take(4) {
        let fields: Vec<&str> = record.split(':').collect();
        if fields.len() != 5 {
            continue;
        }
        let Ok(pid) = fields[0].parse::<i32>() else {
            continue;
        };
        if pid != probe_pid || fields[3] != DECOY_CANARY_TYPE {
            continue;
        }
        let Ok(decoded) = URL_SAFE_NO_PAD.decode(fields[2]) else {
            continue;
        };
        if decoded == expected_path {
            return true;
        }
    }
    false
}

/// Opens the decoy in a short-lived child process and waits for it with a
/// bounded number of microseconds. The fanotify permission event is answered by
/// the broker's watcher thread before the `open` returns, so a successful probe
/// means the event is already queued for the drain.
pub(super) fn probe_decoy_open(path: &Path) -> Result<i32, BoxError> {
    let path_c = CString::new(path.as_os_str().as_bytes())?;
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    if pid == 0 {
        // Child: only async-signal-safe libc calls, then `_exit`; no Rust
        // destructors, allocator or locks touched after fork.
        let fd = unsafe {
            libc::open(
                path_c.as_ptr(),
                libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            )
        };
        if fd >= 0 {
            unsafe { libc::close(fd) };
            unsafe { libc::_exit(0) };
        }
        unsafe { libc::_exit(2) };
    }
    let mut status: libc::c_int = 0;
    for _ in 0..PROBE_WAIT_STEPS {
        let waited = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
        if waited == pid {
            let opened = libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0;
            return if opened {
                Ok(pid)
            } else {
                Err("canary probe open failed".into())
            };
        }
        if waited < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        thread::sleep(Duration::from_micros(PROBE_STEP_MICROS));
    }
    // The probe is stuck in a permission event the sensor never answered.
    // Killing it is the only way to keep the worker bounded.
    unsafe { libc::kill(pid, libc::SIGKILL) };
    let _ = unsafe { libc::waitpid(pid, &mut status, 0) };
    Err("canary probe timed out".into())
}
