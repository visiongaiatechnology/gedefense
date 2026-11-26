use super::*;

/// One bounded scan result (used for the report/status projection).
pub(super) struct ScanOutcome {
    pub(super) bounds_ok: bool,
    pub(super) domains: u8,
    pub(super) reasons: Vec<&'static str>,
}

impl ScanOutcome {
    pub(super) fn new() -> Self {
        Self {
            bounds_ok: true,
            domains: 0,
            reasons: Vec::new(),
        }
    }

    pub(super) fn reason(&mut self, token: &'static str) {
        if self.reasons.len() < 8 && !self.reasons.contains(&token) {
            self.reasons.push(token);
        }
    }

    pub(super) fn degrade(&mut self, token: &'static str) {
        self.bounds_ok = false;
        if self.reasons.contains(&token) {
            return;
        }
        if self.reasons.len() >= 8 {
            // Keep the degradation visible in the bounded report even when the
            // reason budget is already full.
            if let Some(last) = self.reasons.last_mut() {
                *last = token;
            }
            return;
        }
        self.reasons.push(token);
    }
}

impl CrossViewCore {
    /// Runs a scheduled scan when due and drains the eBPF tap ring. A tap event
    /// triggers an early scan (rate-limited) because the raw-socket evidence is
    /// only usable while it is fresh.
    pub(crate) fn poll(&mut self, now_ms: u64) {
        if !self.enabled {
            return;
        }
        let had_tap = self.drain_ring(now_ms);
        let since_scan = now_ms.saturating_sub(self.last_scan_ms);
        let scheduled = self.last_scan_ms == 0 || since_scan >= CROSS_VIEW_SCAN_INTERVAL_MS;
        let event_triggered =
            had_tap && (self.last_scan_ms == 0 || since_scan >= CROSS_VIEW_EVENT_SCAN_MIN_GAP_MS);
        if scheduled || event_triggered {
            self.run_scan(now_ms);
        }
    }
}

impl CrossViewCore {
    /// Drains the bounded tap ring; returns true when at least one record was
    /// accepted (and therefore an early scan is worth running).
    pub(super) fn drain_ring(&mut self, now_ms: u64) -> bool {
        let mut accepted = false;
        let mut processed = 0usize;
        let mut batch: Vec<CrossViewEvent> = Vec::with_capacity(RING_DRAIN_PER_POLL);
        while processed < RING_DRAIN_PER_POLL {
            let Some(item) = self.events.next() else {
                break;
            };
            processed += 1;
            match decode_cross_view_event(&item) {
                Some(event) => batch.push(event),
                None => self.rejected = self.rejected.saturating_add(1),
            }
        }
        for event in batch {
            accepted = true;
            let Some(record) = classify_tap_event(&event, now_ms) else {
                continue;
            };
            let key = (record.pid, record.detail_code & 0xff);
            let until = now_ms.saturating_add(TAP_DEDUPE_TTL_MS);
            let duplicate = self
                .tap_dedupe
                .get(&key)
                .is_some_and(|seen_until| *seen_until > now_ms);
            if duplicate {
                continue;
            }
            self.tap_dedupe.insert(key, until);
            if self.tap_dedupe.len() > TAP_DEDUPE_LIMIT {
                self.tap_dedupe.retain(|_, seen| *seen > now_ms);
            }
            if record.pid != 0 {
                self.evidence_pids.insert(record.pid, now_ms);
                if self.evidence_pids.len() > CROSS_VIEW_MAX_EVIDENCE_PIDS {
                    self.evidence_pids.retain(|_, seen| {
                        now_ms.saturating_sub(*seen) <= CROSS_VIEW_EVIDENCE_TTL_MS
                    });
                }
            }
            self.enqueue(record);
        }
        accepted
    }
}

impl CrossViewCore {
    /// Appends one record to the bounded queue and updates the counters.
    pub(super) fn enqueue(&mut self, event: CrossViewEvent) {
        self.events_total = self.events_total.saturating_add(1);
        if event.severity >= CROSS_VIEW_SEVERITY_HIGH {
            self.contradictions = self.contradictions.saturating_add(1);
        }
        if self.queue.len() >= CROSS_VIEW_MAX_QUEUED_EVENTS {
            self.queue_drops = self.queue_drops.saturating_add(1);
            return;
        }
        self.queue.push_back(event);
    }
}

impl CrossViewCore {
    /// One bounded scan over every readable domain.
    pub(super) fn run_scan(&mut self, now_ms: u64) {
        let started = Instant::now();
        let deadline = started + Duration::from_millis(CROSS_VIEW_SCAN_BUDGET_MS);
        let mut outcome = ScanOutcome::new();
        self.scans = self.scans.saturating_add(1);

        // Domain 7 (netlink-filter/tap ring) is readable whenever any socket-tap
        // hook is attached; the ring is drained by poll() independently of the
        // scan. An inactive hook set names the capability gap honestly.
        if self.lsm_create_attached || self.lsm_setsockopt_attached || self.kprobe_attached {
            outcome.domains += 1;
        } else {
            outcome.reason("tap_hooks_absent");
        }

        // Cheapest independent views first; the expensive map/pid enumeration
        // comes last so a hostile huge view cannot starve the others.
        self.scan_module_trace(now_ms, deadline, &mut outcome);
        self.scan_pins(now_ms, &mut outcome);
        self.scan_processes(now_ms, deadline, &mut outcome);
        self.scan_bpf_id_gap(now_ms, deadline, &mut outcome);
        self.scan_sockets(now_ms, deadline, &mut outcome);
        self.scan_libraries(now_ms, deadline, &mut outcome);

        if Instant::now() >= deadline {
            outcome.degrade("budget_exhausted");
        }
        self.last_scan_ms = now_ms;
        self.last_bounds_ok = outcome.bounds_ok;
        self.last_domains = outcome.domains;
        self.last_reasons = outcome.reasons;
    }
}

impl CrossViewCore {
    /// `CROSS_VIEW_STATUS`: bounded `key=value` health (no paths). The 13 fields
    /// are the documented Go parser contract.
    pub(crate) fn status(&self) -> String {
        let now_ms = unix_millis();
        let age_ms = if self.last_scan_ms == 0 {
            0
        } else {
            now_ms.saturating_sub(self.last_scan_ms)
        };
        format!(
            "enabled={}:scans={}:contradictions={}:events={}:drops={}:domains={}:age_ms={}:tap={}:mods={}:procs={}:bpf={}:pkgdb={}:trace={}",
            u8::from(self.enabled),
            self.scans,
            self.contradictions,
            self.events_total,
            self.total_drops(),
            self.last_domains,
            age_ms,
            u8::from(self.lsm_create_attached || self.lsm_setsockopt_attached || self.kprobe_attached),
            u8::from(self.module_available),
            u8::from(self.proc_available),
            u8::from(self.bpf_available),
            self.pkgdb_token(),
            u8::from(self.trace_available)
        )
    }
}

impl CrossViewCore {
    pub(super) fn total_drops(&self) -> u64 {
        self.counter_sum(COUNTER_DROPS)
            .saturating_add(self.queue_drops)
            .saturating_add(self.rejected)
    }
}

impl CrossViewCore {
    pub(super) fn counter_sum(&self, index: u32) -> u64 {
        match self.counters.get(&index, 0) {
            Ok(values) => values
                .iter()
                .copied()
                .fold(0u64, |sum, value| sum.saturating_add(value)),
            Err(error) => {
                eprintln!("cross-view counter {index} read failed ({error}); reporting 0");
                0
            }
        }
    }
}

impl CrossViewCore {
    pub(super) fn pkgdb_token(&self) -> &'static str {
        match &self.pkgdb {
            PkgDbState::Indexed {
                token,
                complete: true,
                ..
            } => token,
            PkgDbState::Indexed {
                complete: false, ..
            } => CROSS_VIEW_PKGDB_DEGRADED,
            PkgDbState::Unsupported => CROSS_VIEW_PKGDB_UNSUPPORTED,
            PkgDbState::Unbuilt => "unknown",
        }
    }
}

impl CrossViewCore {
    pub(super) fn scan_processes(
        &mut self,
        now_ms: u64,
        deadline: Instant,
        outcome: &mut ScanOutcome,
    ) {
        let first = match read_proc_pids() {
            Ok(pids) => pids,
            Err(error) => {
                eprintln!("cross-view process view: {PROCFS_PATH} listing unavailable ({error})");
                outcome.degrade("proc_unreadable");
                self.proc_available = false;
                return;
            }
        };
        self.proc_available = true;
        outcome.domains += 1;
        let mut listing: HashSet<u32> = first.iter().copied().collect();
        let mut findings = 0usize;

        // `stat` verification for the pids the listing reported. A pid that
        // vanished between the two calls is a normal exit, not evidence; any
        // other failure while the directory entry exists is.
        for pid in first.iter().take(CROSS_VIEW_MAX_PIDS) {
            if Instant::now() >= deadline || findings >= 8 {
                break;
            }
            match read_proc_stat(*pid) {
                Ok(_) => {}
                Err(StatRead::Gone) => {}
                Err(StatRead::Refused) => {
                    findings += 1;
                    self.enqueue(hidden_process_event(
                        now_ms,
                        *pid,
                        0,
                        CROSS_VIEW_DETAIL_STAT_FAILED,
                        CROSS_VIEW_SEVERITY_MEDIUM,
                    ));
                }
            }
        }

        // Pids claimed by kernel evidence (tap ring) but missing from two
        // consecutive listings: a `getdents64`-hook signature. A process that
        // merely exited is dropped instead of reported.
        let mut evidence: Vec<(u32, u64)> = self
            .evidence_pids
            .iter()
            .map(|(pid, seen)| (*pid, *seen))
            .collect();
        evidence.sort_unstable();
        let mut second: Option<HashSet<u32>> = None;
        for (pid, seen) in evidence {
            if now_ms.saturating_sub(seen) > CROSS_VIEW_EVIDENCE_TTL_MS {
                self.evidence_pids.remove(&pid);
                continue;
            }
            if listing.contains(&pid) || findings >= 8 {
                continue;
            }
            if second.is_none() {
                second = read_proc_pids().ok().map(|pids| pids.into_iter().collect());
            }
            let still_missing = second
                .as_ref()
                .map(|pids| !pids.contains(&pid))
                .unwrap_or(true);
            if !still_missing {
                continue;
            }
            match read_proc_stat(pid) {
                Ok(_) => {
                    if let Some(tgid) = read_proc_tgid(pid) {
                        if tgid != pid
                            && second
                                .as_ref()
                                .is_some_and(|pids| pids.contains(&tgid))
                        {
                            self.evidence_pids.remove(&pid);
                            continue;
                        }
                    }
                    findings += 1;
                    self.enqueue(hidden_process_event(
                        now_ms,
                        pid,
                        0,
                        CROSS_VIEW_DETAIL_LISTING_MISS,
                        CROSS_VIEW_SEVERITY_HIGH,
                    ));
                }
                Err(StatRead::Gone) => {
                    self.evidence_pids.remove(&pid);
                }
                Err(StatRead::Refused) => {
                    findings += 1;
                    self.enqueue(hidden_process_event(
                        now_ms,
                        pid,
                        0,
                        CROSS_VIEW_DETAIL_STAT_FAILED,
                        CROSS_VIEW_SEVERITY_MEDIUM,
                    ));
                }
            }
        }

        // Bounded pid memory refresh.
        for pid in &first {
            self.known_pids.insert(*pid, now_ms);
        }
        if self.known_pids.len() > CROSS_VIEW_MAX_PIDS {
            self.known_pids
                .retain(|_, seen| now_ms.saturating_sub(*seen) <= CROSS_VIEW_EVIDENCE_TTL_MS);
        }
        listing.clear();
    }
}
