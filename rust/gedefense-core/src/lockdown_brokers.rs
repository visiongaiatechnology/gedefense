//! Point 5 (§6.4): reversible key-broker freeze.
//!
//! Only `SIGSTOP`/`SIGCONT` through an identity-checked pidfd: never a kill, no
//! paths or command lines are read or reported. The fixed name list is bounded,
//! the `/proc` walk is capped, the own PID and PID<=4 are excluded, and frozen
//! PIDs are remembered by PID plus start time so a recycled PID is never
//! signalled. Records older than the 300 s TTL are not resumed (bounded action
//! window, documented limitation) and the status is `frozen-not-locked`: a
//! reversible freeze, not a zeroized key store.

use gedefense_common::{
    LOCKDOWN_OUTCOME_APPLIED as APPLIED, LOCKDOWN_OUTCOME_FAILED as FAILED,
    LOCKDOWN_OUTCOME_PARTIAL as PARTIAL, LOCKDOWN_OUTCOME_SKIPPED as SKIPPED,
};
use std::{
    fs,
    path::PathBuf,
    time::{Duration, Instant},
};

/// Fixed broker name list (§6.4); no operator-supplied names, no path matching.
pub(crate) const BROKER_NAMES: &[&str] =
    &["ssh-agent", "gpg-agent", "gnome-keyring-d", "keepassxc", "vault", "astraea-key-bro", "astraea-key-broker"];
/// Upper bound on remembered frozen PIDs.
pub(crate) const MAX_BROKERS: usize = 256;
/// Upper bound on one `/proc` scan.
pub(crate) const MAX_PROC_SCAN: usize = 512;
/// Maximum record age that is still resumed on Clear (§6.4 TTL cap).
pub(crate) const BROKER_TTL: Duration = Duration::from_secs(300);
/// The honest §6.4 status: frozen, not locked/zeroized.
pub(crate) const BROKER_STATUS: &str = "frozen-not-locked";

/// PID plus kernel start time: the identity pair every signal is checked against.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct BrokerProcess {
    pub(crate) pid: i32,
    pub(crate) start: u64,
}

/// Injectable process interface: production `/proc` + pidfd, tests a fake.
pub(crate) trait BrokerOps {
    fn scan(&self) -> Result<Vec<BrokerProcess>, String>;
    fn signal(&mut self, pid: i32, start: u64, stop: bool) -> Result<(), String>;
    fn now(&self) -> Instant;
}

/// Production implementation: bounded `/proc` name match and pidfd signals.
#[derive(Clone, Debug)]
pub(crate) struct SystemBrokerOps {
    proc_root: PathBuf,
}

impl SystemBrokerOps {
    #[allow(dead_code)] // production path: the real /proc
    pub(crate) fn system() -> Self {
        Self { proc_root: PathBuf::from("/proc") }
    }
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn for_root(proc_root: impl Into<PathBuf>) -> Self {
        Self { proc_root: proc_root.into() }
    }
}

fn proc_start_ticks(stat: &str) -> Option<u64> {
    let close = stat.rfind(')')?;
    let fields: Vec<&str> = stat.get(close + 2..)?.split_whitespace().collect();
    fields.get(19)?.parse::<u64>().ok()
}

fn proc_comm(proc_root: &PathBuf, pid: i32) -> Option<String> {
    let value = fs::read_to_string(proc_root.join(pid.to_string()).join("comm")).ok()?;
    (value.len() <= 64).then(|| value.trim().to_owned())
}

impl BrokerOps for SystemBrokerOps {
    fn scan(&self) -> Result<Vec<BrokerProcess>, String> {
        let entries = fs::read_dir(&self.proc_root).map_err(|_| "proc-scan-failed".to_owned())?;
        let mut found = Vec::new();
        let mut examined = 0usize;
        for entry in entries.flatten() {
            if examined >= MAX_PROC_SCAN || found.len() >= MAX_BROKERS {
                break;
            }
            let name = entry.file_name();
            let Some(name) = name.to_str() else { continue };
            let Ok(pid) = name.parse::<i32>() else { continue };
            examined += 1;
            if pid <= 4 || pid == std::process::id() as i32 {
                continue;
            }
            let Some(comm) = proc_comm(&self.proc_root, pid) else { continue };
            if !BROKER_NAMES.contains(&comm.as_str()) {
                continue;
            }
            let Ok(stat) = fs::read_to_string(self.proc_root.join(name).join("stat")) else {
                continue;
            };
            if let Some(start) = proc_start_ticks(&stat) {
                found.push(BrokerProcess { pid, start });
            }
        }
        Ok(found)
    }

    fn signal(&mut self, pid: i32, start: u64, stop: bool) -> Result<(), String> {
        let signal = if stop { libc::SIGSTOP } else { libc::SIGCONT };
        // Identity (PID + starttime) is re-checked before and after pidfd_open
        // inside this helper; only STOP/CONT are reachable from this module.
        crate::process_control::pidfd_signal(pid, start, signal, "LOCKDOWN.BROKER")
            .map_err(|error| error.to_string())
    }

    fn now(&self) -> Instant {
        Instant::now()
    }
}

#[derive(Clone, Copy, Debug)]
struct FrozenBroker {
    pid: i32,
    start: u64,
    frozen_at: Instant,
}

/// Result of one broker phase or clear.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct BrokerReport {
    pub(crate) outcome: u8,
    pub(crate) reason: &'static str,
    pub(crate) frozen: u32,
    pub(crate) resumed: u32,
    pub(crate) failed: u32,
    pub(crate) expired: u32,
}

impl BrokerReport {
    fn new(outcome: u8, reason: &'static str) -> Self {
        Self { outcome, reason, frozen: 0, resumed: 0, failed: 0, expired: 0 }
    }
}

/// Remembers which broker PIDs were stopped so Clear can release exactly those.
pub(crate) struct BrokerFreezer {
    frozen: Vec<FrozenBroker>,
}

impl BrokerFreezer {
    pub(crate) fn new() -> Self {
        Self { frozen: Vec::new() }
    }

    pub(crate) fn frozen_count(&self) -> u64 {
        self.frozen.len() as u64
    }

    /// Stops every named broker that is not stopped yet (idempotent per identity).
    pub(crate) fn freeze(&mut self, ops: &mut dyn BrokerOps) -> BrokerReport {
        let processes = match ops.scan() {
            Ok(processes) => processes,
            Err(_) => return BrokerReport::new(FAILED, "proc-scan-failed"),
        };
        let now = ops.now();
        let mut report = BrokerReport::new(APPLIED, "no-brokers");
        for process in processes {
            if self
                .frozen
                .iter()
                .any(|entry| entry.pid == process.pid && entry.start == process.start)
            {
                continue;
            }
            if self.frozen.len() >= MAX_BROKERS || ops.signal(process.pid, process.start, true).is_err() {
                report.failed = report.failed.saturating_add(1);
                continue;
            }
            self.frozen.push(FrozenBroker {
                pid: process.pid,
                start: process.start,
                frozen_at: now,
            });
            report.frozen = report.frozen.saturating_add(1);
        }
        report.outcome = if report.failed > 0 {
            if report.frozen > 0 { PARTIAL } else { FAILED }
        } else {
            APPLIED
        };
        if report.frozen > 0 {
            report.reason = BROKER_STATUS;
        }
        report
    }

    /// Sends `SIGCONT` to the remembered PIDs; expired records are dropped
    /// without a signal because the bounded TTL window has passed.
    pub(crate) fn resume(&mut self, ops: &mut dyn BrokerOps) -> BrokerReport {
        let now = ops.now();
        let records = std::mem::take(&mut self.frozen);
        let mut report = BrokerReport::new(APPLIED, "no-brokers");
        for record in records {
            if now.saturating_duration_since(record.frozen_at) > BROKER_TTL {
                report.expired = report.expired.saturating_add(1);
                continue;
            }
            match ops.signal(record.pid, record.start, false) {
                Ok(()) => report.resumed = report.resumed.saturating_add(1),
                Err(_) => report.failed = report.failed.saturating_add(1),
            }
        }
        report.outcome = if report.failed > 0 {
            if report.resumed > 0 { PARTIAL } else { FAILED }
        } else if report.resumed > 0 {
            APPLIED
        } else if report.expired > 0 {
            SKIPPED
        } else {
            APPLIED
        };
        report.reason = if report.expired > 0 && report.resumed == 0 {
            "identity-ttl-expired"
        } else if report.failed > 0 {
            "signal-failed"
        } else if report.resumed > 0 {
            "resumed"
        } else {
            "no-brokers"
        };
        report
    }
}

impl crate::lockdown::LockdownCore {
    /// §6.4 phase: freezes the fixed broker set and records identities.
    pub(crate) fn broker_phase(&mut self) -> (u8, &'static str) {
        let mut ops = SystemBrokerOps::for_root(&self.config.proc_root);
        let report = self.brokers.freeze(&mut ops);
        (report.outcome, report.reason)
    }
    /// §6.4 Clear: SIGCONT to the remembered PIDs (never a kill).
    pub(crate) fn broker_release(&mut self) -> (u8, &'static str) {
        let mut ops = SystemBrokerOps::for_root(&self.config.proc_root);
        let report = self.brokers.resume(&mut ops);
        (report.outcome, report.reason)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::{
        cell::Cell,
        path::Path,
        time::{SystemTime, UNIX_EPOCH},
    };

    #[derive(Default)]
    pub(crate) struct FakeOps {
        pub(crate) processes: Vec<BrokerProcess>,
        pub(crate) fail: bool,
        pub(crate) signals: Vec<(i32, u64, bool)>,
        pub(crate) clock: Cell<Option<Instant>>,
    }

    impl FakeOps {
        pub(crate) fn at(now: Instant) -> Self {
            Self { clock: Cell::new(Some(now)), ..Self::default() }
        }
    }

    impl BrokerOps for FakeOps {
        fn scan(&self) -> Result<Vec<BrokerProcess>, String> {
            Ok(self.processes.clone())
        }
        fn signal(&mut self, pid: i32, start: u64, stop: bool) -> Result<(), String> {
            self.signals.push((pid, start, stop));
            if self.fail {
                return Err("signal-failed".to_owned());
            }
            Ok(())
        }
        fn now(&self) -> Instant {
            self.clock.get().unwrap_or_else(Instant::now)
        }
    }

    fn process(pid: i32, start: u64) -> BrokerProcess {
        BrokerProcess { pid, start }
    }

    fn fixture(label: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|value| value.as_nanos())
            .unwrap_or(0);
        let root = std::env::temp_dir().join(format!(
            "vgt-lockdown-brokers-{label}-{}-{nanos}",
            std::process::id()
        ));
        fs::create_dir_all(&root).expect("proc fixture");
        root
    }

    fn proc_entry(root: &Path, pid: i32, comm: &str, start: u64) {
        let dir = root.join(pid.to_string());
        fs::create_dir_all(&dir).expect("pid dir");
        fs::write(dir.join("comm"), format!("{comm}\n")).expect("comm");
        // Field 22 of /proc/<pid>/stat is starttime; after `)` it is index 19.
        let mut stat = format!("{pid} ({comm}) S");
        for _ in 0..18 {
            stat.push_str(" 0");
        }
        stat.push_str(&format!(" {start}"));
        fs::write(dir.join("stat"), stat).expect("stat");
    }

    #[test]
    fn freeze_and_resume_touch_only_the_remembered_identities() {
        let now = Instant::now();
        let mut ops = FakeOps::at(now);
        ops.processes = vec![process(101, 7), process(202, 9)];
        let mut freezer = BrokerFreezer::new();
        let report = freezer.freeze(&mut ops);
        assert_eq!((report.outcome, report.frozen, report.reason), (APPLIED, 2, BROKER_STATUS));
        assert_eq!(freezer.frozen_count(), 2);
        assert_eq!(ops.signals, vec![(101, 7, true), (202, 9, true)]);
        // Idempotent: a second freeze performs no signal for known identities.
        assert_eq!(freezer.freeze(&mut ops).frozen, 0);
        assert_eq!(ops.signals.len(), 2);

        let report = freezer.resume(&mut ops);
        assert_eq!((report.outcome, report.resumed), (APPLIED, 2));
        assert_eq!(freezer.frozen_count(), 0);
        assert_eq!(ops.signals, vec![(101, 7, true), (202, 9, true), (101, 7, false), (202, 9, false)]);
    }

    #[test]
    fn records_past_the_ttl_are_not_resumed() {
        let start = Instant::now();
        let mut ops = FakeOps::at(start);
        ops.processes = vec![process(303, 11)];
        let mut freezer = BrokerFreezer::new();
        assert_eq!(freezer.freeze(&mut ops).frozen, 1);
        ops.clock.set(Some(start + BROKER_TTL + Duration::from_secs(1)));
        let report = freezer.resume(&mut ops);
        assert_eq!((report.outcome, report.expired, report.resumed), (SKIPPED, 1, 0));
        assert_eq!(ops.signals, vec![(303, 11, true)]);
        assert_eq!(freezer.frozen_count(), 0);
    }

    #[test]
    fn signal_failures_are_partial_never_killed() {
        let mut ops = FakeOps::at(Instant::now());
        ops.processes = vec![process(404, 12), process(505, 13)];
        let mut freezer = BrokerFreezer::new();
        let report = freezer.freeze(&mut ops);
        assert_eq!((report.outcome, report.frozen), (APPLIED, 2));
        // Any recorded freeze is only ever SIGSTOP/SIGCONT, never a kill: the
        // fake records the boolean `stop` flag and nothing else.
        assert!(ops.signals.iter().all(|(_, _, stop)| *stop));
        ops.fail = true;
        let report = freezer.resume(&mut ops);
        assert_eq!((report.outcome, report.failed), (FAILED, 2));
    }

    #[test]
    fn proc_scan_is_bounded_name_matched_and_protects_low_and_own_pids() {
        let root = fixture("procscan");
        proc_entry(&root, 1, "systemd", 5);
        proc_entry(&root, 4, "kworker", 6);
        proc_entry(&root, 9001, "ssh-agent", 41);
        proc_entry(&root, 9002, "gnome-keyring-d", 42);
        proc_entry(&root, 9003, "bash", 43);
        proc_entry(&root, 9004, "astraea-key-bro", 45);
        proc_entry(&root, std::process::id() as i32, "ssh-agent", 44);
        let mut ops = SystemBrokerOps::for_root(&root);
        let scanned = ops.scan().expect("scan");
        let mut got: Vec<_> = scanned.iter().map(|entry| (entry.pid, entry.start)).collect();
        got.sort_unstable();
        assert_eq!(got, vec![(9001, 41), (9002, 42), (9004, 45)]);
        let mut freezer = BrokerFreezer::new();
        let report = freezer.freeze(&mut ops);
        // The fake /proc has no pidfd-visible processes: the signals fail
        // honestly instead of being claimed as frozen.
        assert!(matches!(report.outcome, FAILED | PARTIAL), "{report:?}");
        assert_eq!(report.failed, 3);
    }
}
