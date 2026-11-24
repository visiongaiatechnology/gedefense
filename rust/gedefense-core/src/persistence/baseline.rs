use super::*;

/// Baseline bounds: at most 256 exact files, 16 MiB each, 96 MiB total per pass.
pub(super) const MAX_BASELINE_FILES: usize = 256;
pub(super) const MAX_BASELINE_FILE_BYTES: u64 = 16 * 1024 * 1024;
pub(super) const MAX_BASELINE_TOTAL_BYTES: u64 = 96 * 1024 * 1024;
/// Baseline re-verification cadence and drift-evidence dedupe window.
pub(super) const BASELINE_REVERIFY_MS: u64 = 120_000;
pub(super) const DRIFT_DEDUP_MS: u64 = 600_000;
pub(super) const MAX_DRIFT_DEDUP: usize = 4_096;

#[derive(Clone)]
pub(super) struct BaselineRoot {
    pub(super) path: PathBuf,
    pub(super) class: u8,
    pub(super) dev: u32,
    pub(super) ino: u64,
    pub(super) hash: Option<[u8; 32]>,
}

#[derive(Default)]
pub(super) struct BaselineCounters {
    pub(super) checked: u64,
    pub(super) drifted: u64,
    pub(super) read_failures: u64,
    pub(super) budget_skips: u64,
}

pub(super) struct DriftNotice {
    pub(super) class: u8,
    pub(super) dev: u32,
    pub(super) ino: u64,
    pub(super) reason: u32,
    /// Owner uid of the observed object (0 when the file is missing).
    pub(super) uid: u32,
}

#[derive(Default)]
pub(super) struct BaselineSet {
    pub(super) roots: Vec<BaselineRoot>,
    pub(super) captured_ms: u64,
}

impl BaselineSet {
    pub(super) fn capture(candidates: &[(PathBuf, u8)], now_ms: u64) -> Self {
        let mut set = Self {
            roots: Vec::with_capacity(candidates.len().min(MAX_BASELINE_FILES)),
            captured_ms: now_ms,
        };
        let mut remaining = MAX_BASELINE_TOTAL_BYTES;
        for (path, class) in candidates.iter().take(MAX_BASELINE_FILES) {
            let mut root = BaselineRoot {
                path: path.clone(),
                class: *class,
                dev: 0,
                ino: 0,
                hash: None,
            };
            if let Ok(identity) = resolve_identity(path, false) {
                if identity.is_file {
                    root.dev = identity.dev;
                    root.ino = identity.ino;
                    match hash_watch_file(&identity.canonical, &mut remaining) {
                        Ok(hash) => root.hash = Some(hash),
                        // An unreadable/oversized watched file stays a watched
                        // path without a content reference; the operator-visible
                        // reason is the bounded read-failure counter on verify.
                        Err(_) => {}
                    }
                }
            }
            set.roots.push(root);
        }
        set
    }

    /// Re-resolves and re-hashes every root. Returns the drift notices and the
    /// verification counters; a reference hash is only updated when a content/
    /// identity change was actually observed.
    pub(super) fn verify(&mut self) -> (Vec<DriftNotice>, BaselineCounters) {
        let mut notices: Vec<DriftNotice> = Vec::new();
        let mut counters = BaselineCounters::default();
        let mut remaining = MAX_BASELINE_TOTAL_BYTES;
        for root in &mut self.roots {
            counters.checked = counters.checked.saturating_add(1);
            let identity = match resolve_identity(&root.path, false) {
                Ok(identity) if identity.is_file => identity,
                _ => {
                    if root.hash.is_some() {
                        notices.push(DriftNotice {
                            class: root.class,
                            dev: root.dev,
                            ino: root.ino,
                            reason: PERSIST_DRIFT_MISSING,
                            uid: 0,
                        });
                        counters.drifted = counters.drifted.saturating_add(1);
                        root.hash = None;
                        root.dev = 0;
                        root.ino = 0;
                    }
                    continue;
                }
            };
            if root.hash.is_none() {
                // Appeared after being absent at baseline: this is the classic
                // "create /etc/ld.so.preload" persistence move.
                notices.push(DriftNotice {
                    class: root.class,
                    dev: identity.dev,
                    ino: identity.ino,
                    reason: PERSIST_DRIFT_APPEARED,
                    uid: identity.uid,
                });
                counters.drifted = counters.drifted.saturating_add(1);
            } else if identity.dev != root.dev || identity.ino != root.ino {
                notices.push(DriftNotice {
                    class: root.class,
                    dev: identity.dev,
                    ino: identity.ino,
                    reason: PERSIST_DRIFT_REPLACED,
                    uid: identity.uid,
                });
                counters.drifted = counters.drifted.saturating_add(1);
            }
            match hash_watch_file(&identity.canonical, &mut remaining) {
                Ok(hash) => {
                    if let Some(previous) = root.hash {
                        if previous != hash {
                            if identity.dev == root.dev && identity.ino == root.ino {
                                notices.push(DriftNotice {
                                    class: root.class,
                                    dev: identity.dev,
                                    ino: identity.ino,
                                    reason: PERSIST_DRIFT_CONTENT,
                                    uid: identity.uid,
                                });
                                counters.drifted = counters.drifted.saturating_add(1);
                            }
                        }
                    }
                    root.hash = Some(hash);
                    root.dev = identity.dev;
                    root.ino = identity.ino;
                }
                Err(_) => {
                    counters.read_failures = counters.read_failures.saturating_add(1);
                    if remaining == 0 {
                        counters.budget_skips = counters.budget_skips.saturating_add(1);
                    }
                }
            }
        }
        // Keep the lifetime of the drift list bounded.
        notices.truncate(MAX_BASELINE_FILES);
        (notices, counters)
    }
}

impl PersistenceCore {
    pub(super) fn capture_initial_baseline(&mut self) {
        let now = unix_millis_now();
        let candidates = std::mem::take(&mut self.baseline_candidates);
        self.baseline = BaselineSet::capture(&candidates, now);
        self.baseline_candidates = candidates;
        self.baseline_at_ms = now;
        self.last_verify_ms = now;
        eprintln!(
            "GeDefense persistence baseline: roots={} at_ms={} (in-memory only; no file outside /var/lib/vgt/gedefense)",
            self.baseline.roots.len(),
            self.baseline.captured_ms
        );
    }
}

impl PersistenceCore {
    pub(super) fn verify_baseline(&mut self, now_ms: u64) {
        let (notices, counters) = self.baseline.verify();
        self.last_verify_ms = now_ms;
        self.verify_errors = self.verify_errors.saturating_add(counters.read_failures);
        for notice in notices {
            self.process_drift_notice(notice, now_ms);
        }
    }
}

impl PersistenceCore {
    /// Queues one drift notice and heals the kernel map so a file that
    /// appeared/changed is watched by the `file_open` ladder from now on (not
    /// only by the 120 s userspace hash pass).
    pub(super) fn process_drift_notice(&mut self, notice: DriftNotice, now_ms: u64) {
        if !self.queue_drift(notice.class, notice.dev, notice.ino, notice.reason, now_ms) {
            return;
        }
        self.drifted_total = self.drifted_total.saturating_add(1);
        if matches!(
            notice.reason,
            PERSIST_DRIFT_APPEARED | PERSIST_DRIFT_REPLACED
        ) {
            let owner = if gedefense_common::persistence_class_is_secret(notice.class) {
                notice.uid
            } else {
                0
            };
            self.insert_path_identity(notice.dev, notice.ino, notice.class, owner, false);
        }
    }
}

impl PersistenceCore {
    pub(super) fn queue_drift(
        &mut self,
        class: u8,
        dev: u32,
        ino: u64,
        reason: u32,
        now_ms: u64,
    ) -> bool {
        let key = (class, dev, ino);
        if let Some(until) = self.drift_dedup.get(&key) {
            if now_ms < *until {
                return false;
            }
        }
        if self.drift_dedup.len() >= MAX_DRIFT_DEDUP {
            let expired: Vec<(u8, u32, u64)> = self
                .drift_dedup
                .iter()
                .filter(|(_, until)| **until <= now_ms)
                .map(|(key, _)| *key)
                .collect();
            for key in expired {
                self.drift_dedup.remove(&key);
            }
        }
        self.drift_dedup
            .insert(key, now_ms.saturating_add(DRIFT_DEDUP_MS));
        let event = PersistenceEvent {
            ts_ns: now_ms.saturating_mul(1_000_000),
            ino,
            dev,
            pid: std::process::id(),
            tgid: std::process::id(),
            uid: current_euid(),
            detail_code: reason,
            class,
            kind: PERSIST_KIND_DRIFT,
            action: PERSIST_ACTION_AUDIT,
            reserved: 0,
            comm: *b"gedefense-core\0\0",
            detail: [0u8; 8],
        };
        self.push_userspace_event(&event);
        true
    }
}

impl PersistenceCore {
    pub(super) fn queue_baseline_marker(&mut self, roots: usize, now_ms: u64) {
        let event = PersistenceEvent {
            ts_ns: now_ms.saturating_mul(1_000_000),
            ino: 0,
            dev: 0,
            pid: std::process::id(),
            tgid: std::process::id(),
            uid: current_euid(),
            detail_code: u32::try_from(roots).unwrap_or(u32::MAX),
            class: gedefense_common::PERSIST_CLASS_UNSPECIFIED,
            kind: PERSIST_KIND_BASELINE,
            action: PERSIST_ACTION_AUDIT,
            reserved: 0,
            comm: *b"gedefense-core\0\0",
            detail: [0u8; 8],
        };
        self.push_userspace_event(&event);
    }

    // -- poll / commands ----------------------------------------------------
}
