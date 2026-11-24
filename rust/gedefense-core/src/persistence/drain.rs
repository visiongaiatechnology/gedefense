use super::*;

/// Bounded userspace queue for drift/baseline records injected by the core.
pub(super) const MAX_PENDING_RECORDS: usize = 256;

impl PersistenceCore {
    pub(super) fn counter_snapshot(&self) -> [u64; 6] {
        [
            Self::per_cpu_sum_or_zero(&self.emitted),
            Self::per_cpu_sum_or_zero(&self.ring_drops),
            Self::per_cpu_sum_or_zero(&self.read_failures),
            Self::per_cpu_sum_or_zero(&self.device_events),
            Self::per_cpu_sum_or_zero(&self.secret_events),
            Self::per_cpu_sum_or_zero(&self.mmap_events),
        ]
    }
}

impl PersistenceCore {
    pub(super) fn can_arm(&self) -> bool {
        self.identity_offsets_ok
            || self.hook_ptrace
            || self.hook_readv
            || self.hook_writev
            || self.hook_mmap
            || self.hook_file_open
    }
}

impl PersistenceCore {
    pub(super) fn attached_mask(&self) -> u64 {
        let mut mask = 0u64;
        if self.hook_file_open {
            mask |= PERSIST_HOOK_FILE_OPEN;
        }
        if self.hook_mmap {
            mask |= PERSIST_HOOK_MMAP;
        }
        if self.hook_ptrace {
            mask |= PERSIST_HOOK_PTRACE;
        }
        if self.hook_readv {
            mask |= PERSIST_HOOK_READV;
        }
        if self.hook_writev {
            mask |= PERSIST_HOOK_WRITEV;
        }
        if self.identity_offsets_ok {
            mask |= PERSIST_STATUS_IDENTITY_OFFSETS;
        }
        if self.pkgdb.ready {
            mask |= PERSIST_STATUS_PKGDB_READY;
        }
        if self.readv_offsets_ok {
            mask |= PERSIST_STATUS_READV_OFFSETS;
        }
        if self.writev_offsets_ok {
            mask |= PERSIST_STATUS_WRITEV_OFFSETS;
        }
        if Self::per_cpu_sum_or_zero(&self.read_failures) > 0 {
            mask |= PERSIST_STATUS_READ_FAILURES;
        }
        if self.sessions.parsed {
            mask |= PERSIST_STATUS_SESSIONS_KNOWN;
        }
        mask
    }

    // -- offsets ------------------------------------------------------------
}

impl PersistenceCore {
    pub(super) fn push_userspace_event(&mut self, event: &PersistenceEvent) {
        if self.pending.len() >= MAX_PENDING_RECORDS {
            // Bounded queue: the oldest pending record is dropped and counted,
            // exactly like the kernel ring's drop counter.
            self.pending.pop_front();
            self.pending_dropped = self.pending_dropped.saturating_add(1);
        }
        self.pending.push_back(encode_persistence_event(event));
    }
}

impl PersistenceCore {
    /// Periodic bounded work on the IPC poll cadence: session sample every 5 s,
    /// baseline re-verification every 120 s. Never blocks the IPC response for
    /// more than the bounded hash pass.
    pub(crate) fn poll(&mut self, now_ms: u64) {
        if now_ms.saturating_sub(self.last_sessions_ms) >= SESSIONS_REFRESH_MS {
            self.sessions = read_session_snapshot(
                Path::new("/run/systemd/sessions"),
                Path::new("/run/systemd/seats"),
            );
            self.last_sessions_ms = now_ms;
        }
        if now_ms.saturating_sub(self.last_pkgdb_ms) >= PKGDB_REFRESH_MS {
            // Bounded re-parse of the package database: an upgrade must not leave
            // the mapped-library ownership snapshot stale forever. `PERSIST_BASELINE`
            // forces the same refresh out of band.
            self.pkgdb = PackageIndex::load();
            self.last_pkgdb_ms = now_ms;
        }
        if self.baseline.roots.is_empty() {
            return;
        }
        if now_ms.saturating_sub(self.last_verify_ms) >= BASELINE_REVERIFY_MS {
            self.verify_baseline(now_ms);
        }
    }
}

impl PersistenceCore {
    pub(super) fn write_state(&mut self, armed: bool) -> Result<(), BoxError> {
        let word = persistence_state_word(self.epoch as u32, armed);
        self.state.set(PERSIST_STATE_INDEX, word, 0)?;
        self.armed = armed;
        Ok(())
    }
}

impl PersistenceCore {
    /// `PERSIST_GUARD_SET <0|1>` -> `armed` / `disarmed`.
    ///
    /// Refusing to arm a guard whose identity offsets are unavailable is the
    /// honest answer: an armed-but-blind guard would let the operator believe
    /// the sensor works. The status keeps showing `attached` for whatever did
    /// attach.
    pub(crate) fn set_enabled_token(&mut self, token: &str) -> Result<String, BoxError> {
        match token {
            "0" => {
                self.write_state(false)?;
                Ok("disarmed".to_owned())
            }
            "1" => {
                if !self.can_arm() {
                    return Err(
                        "persistence guard has no usable sensor offsets/hooks; refusing to arm an armed-but-blind guard"
                            .into(),
                    );
                }
                self.write_state(true)?;
                Ok("armed".to_owned())
            }
            _ => Err("PERSIST_GUARD_SET accepts 0 or 1".into()),
        }
    }
}

impl PersistenceCore {
    pub(super) fn push_text_record(
        records: &mut Vec<String>,
        payload_bytes: &mut usize,
        event: &PersistenceEvent,
    ) -> bool {
        let record = encode_event_text(event);
        let separator = usize::from(!records.is_empty());
        if payload_bytes
            .saturating_add(separator)
            .saturating_add(record.len())
            .saturating_add(24)
            > PERSIST_MAX_DRAIN_PAYLOAD_BYTES
        {
            return false;
        }
        *payload_bytes = payload_bytes
            .saturating_add(separator)
            .saturating_add(record.len());
        records.push(record);
        true
    }
}

impl PersistenceCore {
    /// Kernel-record enrichment/filtering:
    /// - a mapped library that belongs to a package-owned inode is dropped (the
    ///   package database is the ownership authority; without it the event stays
    ///   evidence and the status says `pkgdb=unsupported`),
    /// - peripheral records get the honest session-correlation bits. `KNOWN`
    ///   clear means "no session view": the control plane must report `NONE`,
    ///   never invent an idle state.
    pub(super) fn accept_kernel_event(&mut self, event: &mut PersistenceEvent) -> bool {
        match event.kind {
            PERSIST_KIND_LIBRARY_MMAP => {
                if self.pkgdb.ready && self.pkgdb.package_of(event.dev, event.ino).is_some() {
                    self.tolerated_library_mmaps = self.tolerated_library_mmaps.saturating_add(1);
                    return false;
                }
                true
            }
            PERSIST_KIND_PERIPHERAL_OPEN => {
                if self.sessions.parsed {
                    event.detail_code |= PERSIST_DETAIL_SESSION_KNOWN;
                    if self.sessions.active_uids.contains(&event.uid) {
                        event.detail_code |= PERSIST_DETAIL_SESSION_ACTIVE;
                    }
                }
                true
            }
            _ => true,
        }
    }
}

impl PersistenceCore {
    /// `PERSIST_GUARD_STATUS`: the fourteen documented `key=value` fields.
    /// `attached` is a documented bitmask (hook bits, offsets/pkgdb readiness and
    /// a read-failure indicator) so an operator can tell a fully working sensor
    /// from a partially attached one; `idlehint=unavailable` is the honest answer
    /// (logind `IdleHint` is not a file, the core does not speak D-Bus).
    pub(crate) fn status(&self) -> String {
        let emitted = Self::per_cpu_sum_or_zero(&self.emitted);
        let drops = Self::per_cpu_sum_or_zero(&self.ring_drops);
        format!(
            "enabled={}:attached={}:paths={}:execs={}:devices={}:secrets={}:pkgdb={}:roots={}:drifted={}:baseline_at_ms={}:events={}:drops={}:sessions={}:idlehint={}",
            u8::from(self.armed),
            self.attached_mask(),
            self.paths.len(),
            self.execs.len(),
            self.device_entries,
            self.secret_entries,
            self.pkgdb.format,
            self.baseline.roots.len(),
            self.drifted_total,
            self.baseline_at_ms,
            emitted,
            drops,
            self.sessions.to_status_value(),
            PERSIST_IDLEHINT_UNAVAILABLE
        )
    }
}

impl PersistenceCore {
    pub(super) fn per_cpu_sum(counter: &PerCpuArray<MapData, u64>) -> Result<u64, BoxError> {
        let values = counter.get(&0, 0)?;
        Ok(values
            .iter()
            .copied()
            .fold(0u64, |sum, value| sum.saturating_add(value)))
    }
}

impl PersistenceCore {
    pub(super) fn per_cpu_sum_or_zero(counter: &PerCpuArray<MapData, u64>) -> u64 {
        match Self::per_cpu_sum(counter) {
            Ok(value) => value,
            Err(error) => {
                eprintln!("persistence guard counter read failed ({error}); reporting 0");
                0
            }
        }
    }
}

/// Encodes the twelve-field control-plane text record
/// (`ts:pid:tgid:uid:class:kind:action:detail_code:dev:ino:comm_hex:detail_hex`).
pub(super) fn encode_event_text(event: &PersistenceEvent) -> String {
    format!(
        "{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}",
        event.ts_ns,
        event.pid,
        event.tgid,
        event.uid,
        event.class,
        event.kind,
        event.action,
        event.detail_code,
        event.dev,
        event.ino,
        hex::encode(event.comm_bytes()),
        hex::encode(event.detail_bytes())
    )
}

/// Random per-boot epoch (a freshness marker, not key material).
pub(super) fn random_epoch() -> u64 {
    let mut bytes = [0u8; 8];
    if let Ok(mut file) = fs::File::open("/dev/urandom") {
        if file.read_exact(&mut bytes).is_ok() {
            let value = u64::from_ne_bytes(bytes);
            if value != 0 {
                return value;
            }
        }
    }
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos() as u64)
        .unwrap_or(0);
    (nanos ^ 0x9e37_79b9_7f4a_7c15) | 1
}
