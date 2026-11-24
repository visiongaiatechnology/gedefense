use super::*;

impl ExecInodeCore {
    /// Expires TTL-bounded malware inode locks (called on the IPC poll cadence).
    pub(crate) fn poll(&mut self) {
        if self.ttl_locks.is_empty() {
            return;
        }
        let now = Instant::now();
        let expired: Vec<[u8; 16]> = self
            .ttl_locks
            .iter()
            .filter(|(_, deadline)| **deadline <= now)
            .map(|(key, _)| *key)
            .collect();
        for key in expired {
            match self.ttl.remove(&key) {
                Ok(()) | Err(aya::maps::MapError::KeyNotFound) => {
                    self.ttl_locks.remove(&key);
                    self.expired_locks = self.expired_locks.saturating_add(1);
                }
                Err(error) => {
                    // The kernel-side lock is still in place; keep tracking it
                    // and retry on the next poll instead of claiming an expiry
                    // that did not happen.
                    eprintln!("exec-inode gate: TTL lock expiry failed, will retry: {error}");
                }
            }
        }
    }
}

impl ExecInodeCore {
    /// `EXEC_INODE_STATUS` -> bounded `key:value` status (no paths).
    pub(crate) fn status(&self) -> String {
        let allowed = per_cpu_sum(&self.allowed);
        let denied = per_cpu_sum(&self.denied);
        let emitted = per_cpu_sum(&self.emitted);
        let drops = per_cpu_sum(&self.ring_drops);
        let fallbacks = per_cpu_sum(&self.fallbacks);
        format!(
            "enabled={}:offsets={}:trusted={}:missing={}:allowed={}:denied={}:events={}:drops={}:fallbacks={}:locks={}:expired={}",
            u8::from(self.enabled()),
            u8::from(self.offsets_ok),
            self.trusted_entries.len(),
            self.missing_paths,
            allowed,
            denied,
            emitted,
            drops,
            fallbacks,
            self.ttl_locks.len(),
            self.expired_locks
        )
    }
}

impl ExecInodeCore {
    /// `EXEC_INODE_EVENTS` -> `empty` or `<dropped>|<record>[,<record>...]`.
    pub(crate) fn take_events(&mut self) -> Result<String, BoxError> {
        let mut records = Vec::with_capacity(MAX_EXEC_INODE_EVENTS_PER_RESPONSE);
        while records.len() < MAX_EXEC_INODE_EVENTS_PER_RESPONSE {
            let Some(item) = self.events.next() else {
                break;
            };
            let Some(event) = decode_exec_inode_event(&item) else {
                self.rejected = self.rejected.saturating_add(1);
                continue;
            };
            records.push(encode_event_text(&event));
        }
        let ring_drops = per_cpu_sum(&self.ring_drops);
        let dropped = ring_drops.saturating_sub(self.last_ring_drops);
        self.last_ring_drops = ring_drops;
        let rejected = std::mem::take(&mut self.rejected);
        if records.is_empty() {
            if dropped == 0 && rejected == 0 {
                return Ok("empty".to_owned());
            }
            return Ok(format!("{dropped}|"));
        }
        let payload = format!("{dropped}|{}", records.join(","));
        if payload.len() > MAX_EXEC_INODE_PAYLOAD_BYTES {
            return Err("exec-inode event batch exceeds the response payload budget".into());
        }
        Ok(payload)
    }
}

/// Encodes the 9-field control-plane text record
/// (`ts_ns:pid:tgid:uid:exe_dev:exe_ino:trust_flags:action:comm_hex`).
pub(crate) fn encode_event_text(event: &ExecInodeEvent) -> String {
    let comm = event.comm_bytes();
    format!(
        "{}:{}:{}:{}:{}:{}:{}:{}:{}",
        event.ts_ns,
        event.pid,
        event.tgid,
        event.uid,
        event.exe_dev,
        event.exe_ino,
        event.trust_flags,
        event.action,
        hex::encode(comm)
    )
}

pub(super) fn per_cpu_sum(counter: &PerCpuArray<MapData, u64>) -> u64 {
    match counter.get(&0, 0) {
        Ok(values) => values
            .iter()
            .copied()
            .fold(0u64, |sum, value| sum.saturating_add(value)),
        Err(error) => {
            eprintln!("exec-inode gate: per-CPU counter read failed: {error}");
            0
        }
    }
}
