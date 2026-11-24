use super::*;

impl SelfDefenseCore {
    /// Pins the critical kernel maps under `pin_root` (best-effort; a host
    /// without bpffs degrades honestly instead of failing the core) and records
    /// the expected pin manifest.
    pub(crate) fn load(ebpf: &mut Ebpf, pin_root: &str) -> Self {
        let root = validate_pin_root(pin_root);
        let mut core = Self::empty();
        let Some(root) = root else {
            core.push_event(
                unix_millis(),
                KIND_BPFFS_UNAVAILABLE,
                CODE_PIN_ROOT_INVALID,
                b"pin-root",
            );
            return core;
        };
        match prepare_pin_root(&root) {
            Ok(()) => {
                let (pinned, failed) = core.install_pins(ebpf, &root);
                if pinned == 0 {
                    // The bpffs is usable but no critical map could be pinned:
                    // the manifest cannot guard anything, so do not claim it can.
                    core.push_event(
                        unix_millis(),
                        KIND_BPFFS_UNAVAILABLE,
                        CODE_PIN_FAILED,
                        b"pin-none",
                    );
                } else {
                    core.pins_usable = true;
                    if failed > 0 {
                        core.push_event(
                            unix_millis(),
                            KIND_BPFFS_UNAVAILABLE,
                            CODE_PIN_PARTIAL,
                            b"pin-partial",
                        );
                    }
                }
            }
            Err(code) => {
                core.push_event(unix_millis(), KIND_BPFFS_UNAVAILABLE, code, b"bpffs");
            }
        }
        core
    }
}

impl SelfDefenseCore {
    /// Runs the pin-manifest verification and the canary self-test when due.
    /// Bounded, allocation-light and never blocking on the IPC path: the canary
    /// cycle runs on a worker thread and the pin check is a bounded set of
    /// `statx`/`symlink_metadata` calls.
    pub(crate) fn poll(&mut self, now_ms: u64) {
        if !self.enabled {
            return;
        }
        self.reap_canary_worker(now_ms);
        if self.canary_worker.is_none() && self.canary.is_some() && now_ms >= self.canary_due_ms {
            self.start_canary_worker(now_ms);
        }
        if now_ms >= self.pin_verify_due_ms {
            if self.pins_usable {
                self.verify_pins(now_ms);
            }
            self.pin_verify_due_ms = now_ms.saturating_add(PIN_VERIFY_INTERVAL_MS);
        }
    }
}

impl SelfDefenseCore {
    /// `SELF_GUARD_SET <0|1>` -> `armed` / `disarmed`.
    pub(crate) fn set_enabled_token(&mut self, token: &str) -> Result<String, BoxError> {
        match token {
            "0" => {
                self.enabled = false;
                Ok("disarmed".to_owned())
            }
            "1" => {
                self.enabled = true;
                // Verify the manifest and run one canary cycle immediately:
                // arming must not leave a stale status behind.
                self.pin_verify_due_ms = 0;
                self.canary_due_ms = unix_millis();
                Ok("armed".to_owned())
            }
            _ => Err("SELF_GUARD_SET accepts 0 or 1".into()),
        }
    }
}

impl SelfDefenseCore {
    pub(super) fn empty() -> Self {
        Self {
            enabled: false,
            pins_usable: false,
            manifest: Vec::with_capacity(CRITICAL_MAPS.len()),
            pins_missing: 0,
            pins_replaced: 0,
            pin_verify_due_ms: 0,
            canary: None,
            canary_state: CanaryState::Unknown,
            canary_due_ms: 0,
            canary_runs: 0,
            canary_failures: 0,
            canary_dead_reported: false,
            canary_worker: None,
            queue: VecDeque::with_capacity(TAMPER_QUEUE_CAPACITY),
            events_total: 0,
            dropped_total: 0,
            dropped_pending: 0,
        }
    }
}
