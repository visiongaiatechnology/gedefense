//! Point 5 (§6.3): hardening sysctl observation and opt-in writes.
//!
//! Observation is always on. Writes only happen when the caller asks for them:
//! automatic lockdown may set `kexec_load_disabled=1` and `sysrq=0`; it must
//! never touch `modules_disabled` (irreversible, breaks container hosts). Only
//! the explicit operator single-phase command passes `explicit=true`, which then
//! also sets `modules_disabled=1` when the kernel exposes it. Kernel-lockdown is
//! an immutable boot parameter and is observed only.

use gedefense_common::{
    LOCKDOWN_OUTCOME_APPLIED as APPLIED, LOCKDOWN_OUTCOME_FAILED as FAILED,
    LOCKDOWN_OUTCOME_PARTIAL as PARTIAL,
    LOCKDOWN_OUTCOME_UNSUPPORTED as UNSUPPORTED,
};
use std::{fs, path::PathBuf};

/// Injectable roots: production `/proc` + `/sys`, tests a temp-dir fake.
#[derive(Clone, Debug)]
pub(crate) struct HardeningPaths {
    proc_root: PathBuf,
    sys_root: PathBuf,
}

impl HardeningPaths {
    #[allow(dead_code)] // production path: real /proc and /sys
    pub(crate) fn system() -> Self {
        Self { proc_root: PathBuf::from("/proc"), sys_root: PathBuf::from("/sys") }
    }
    /// Fake layout: `<root>/proc/sys/...` and `<root>/sys/kernel/security/lockdown`.
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn for_root(root: impl Into<PathBuf>) -> Self {
        let root = root.into();
        Self { proc_root: root.join("proc"), sys_root: root.join("sys") }
    }
    pub(crate) fn kexec(&self) -> PathBuf {
        self.proc_root.join("sys/kernel/kexec_load_disabled")
    }
    pub(crate) fn sysrq(&self) -> PathBuf {
        self.proc_root.join("sys/kernel/sysrq")
    }
    pub(crate) fn modules(&self) -> PathBuf {
        self.proc_root.join("sys/kernel/modules_disabled")
    }
    pub(crate) fn unprivileged_bpf(&self) -> PathBuf {
        self.proc_root.join("sys/kernel/unprivileged_bpf_disabled")
    }
    pub(crate) fn kernel_lockdown(&self) -> PathBuf {
        self.sys_root.join("kernel/security/lockdown")
    }
}

impl Default for HardeningPaths {
    fn default() -> Self {
        Self::system()
    }
}

/// One observed sysctl value (already trimmed, bounded); `None` = not present.
pub(crate) type Observed = Option<String>;

/// Read-only observation of the §6.3 knobs (§9: never a claim without a read).
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct Observation {
    pub(crate) kexec_load_disabled: Observed,
    pub(crate) sysrq: Observed,
    pub(crate) modules_disabled: Observed,
    pub(crate) unprivileged_bpf_disabled: Observed,
    pub(crate) kernel_lockdown: Observed,
}

fn read(path: &PathBuf) -> Observed {
    let value = fs::read_to_string(path).ok()?;
    (value.len() <= 64).then(|| value.trim().to_owned()).filter(|value| !value.is_empty())
}

/// Parses e.g. `none [integrity] confidentiality` into the selected mode token.
fn selected_lockdown(value: &str) -> String {
    value
        .split_whitespace()
        .find(|token| token.starts_with('[') && token.ends_with(']'))
        .map(|token| token.trim_matches(|c| c == '[' || c == ']').to_owned())
        .unwrap_or_else(|| value.split_whitespace().next().unwrap_or_default().to_owned())
}

pub(crate) fn observe(paths: &HardeningPaths) -> Observation {
    Observation {
        kexec_load_disabled: read(&paths.kexec()),
        sysrq: read(&paths.sysrq()),
        modules_disabled: read(&paths.modules()),
        unprivileged_bpf_disabled: read(&paths.unprivileged_bpf()),
        kernel_lockdown: read(&paths.kernel_lockdown()).map(|value| selected_lockdown(&value)),
    }
}

/// One write attempt; `Blocked` is the honest "never auto" state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Write {
    Applied,
    AlreadySet,
    Missing,
    Failed,
    Blocked,
}

/// Writes `desired` and verifies it. The first attempt is a plain sysctl-style
/// write (the kernel replaces the value atomically); only a regular-file fake
/// that kept residual bytes is retried once with truncation, so a shorter value
/// such as `sysrq=0` over a bitmask pre-state works in tests without ever
/// truncating a real `/proc/sys` file.
fn write_then_verify(path: &PathBuf, desired: &str) -> Write {
    use std::io::Write as _;
    for truncate in [false, true] {
        let Ok(mut file) = fs::OpenOptions::new().write(true).truncate(truncate).open(path) else {
            return Write::Failed;
        };
        if file.write_all(desired.as_bytes()).is_err() || file.write_all(b"\n").is_err() {
            return Write::Failed;
        }
        drop(file);
        if read(path).as_deref() == Some(desired) {
            return Write::Applied;
        }
    }
    Write::Failed
}

/// Writes `desired` only if `current != desired`, then verifies by read-back.
fn set(path: &PathBuf, desired: &str, domain: &[&str]) -> Write {
    let Some(current) = read(path) else {
        return Write::Missing;
    };
    if !domain.contains(&current.as_str()) {
        return Write::Failed;
    }
    if current == desired {
        return Write::AlreadySet;
    }
    write_then_verify(path, desired)
}

/// `kernel.sysrq` is a bitmask on many hosts (e.g. 438). Any numeric pre-state
/// is tolerated; the typed opt-out `0` may always be written. A non-numeric
/// pre-state is a write failure (fail-safe, no fake success).
fn set_sysrq(path: &PathBuf) -> Write {
    let Some(current) = read(path) else {
        return Write::Missing;
    };
    if current == "0" {
        return Write::AlreadySet;
    }
    if current.parse::<u64>().is_err() {
        return Write::Failed;
    }
    write_then_verify(path, "0")
}

/// Result of §6.3 hardening apply, including the observation it was based on.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct HardeningReport {
    pub(crate) outcome: u8,
    pub(crate) reason: &'static str,
    pub(crate) kexec_load_disabled: Write,
    pub(crate) sysrq: Write,
    pub(crate) modules_disabled: Write,
    pub(crate) observation: Observation,
}

fn settle(writes: &[Write]) -> u8 {
    if writes.contains(&Write::Failed) {
        if writes.iter().any(|write| matches!(write, Write::Applied | Write::AlreadySet)) {
            PARTIAL
        } else {
            FAILED
        }
    } else if writes.iter().any(|write| matches!(write, Write::Applied | Write::AlreadySet)) {
        APPLIED
    } else {
        UNSUPPORTED
    }
}

/// Applies the hardening phase. `explicit=true` is the operator single-phase
/// command that additionally attempts `modules_disabled=1` (irreversible) and
/// folds its result into the reported outcome; automatic lockdown never writes
/// it (`modules-disabled-auto-forbidden`).
pub(crate) fn apply(paths: &HardeningPaths, explicit: bool) -> HardeningReport {
    let kexec = set(&paths.kexec(), "1", &["0", "1"]);
    let sysrq = set_sysrq(&paths.sysrq());
    let modules = if explicit {
        set(&paths.modules(), "1", &["0", "1"])
    } else {
        Write::Blocked
    };
    // The auto path aggregates exactly kexec+sysrq; the explicit operator
    // command must surface a failed/partial modules_disabled write.
    let outcome = if explicit { settle(&[kexec, sysrq, modules]) } else { settle(&[kexec, sysrq]) };
    let reason = match outcome {
        APPLIED => "applied",
        FAILED => "write-or-verify-failed",
        PARTIAL => "partial",
        _ => "not-present",
    };
    HardeningReport {
        outcome,
        reason,
        kexec_load_disabled: kexec,
        sysrq,
        modules_disabled: modules,
        observation: observe(paths),
    }
}

/// The auto path never claims `modules_disabled`; exposed for status/events.
#[allow(dead_code)] // ABI documentation string: auto path never sets it
pub(crate) fn modules_disabled_auto_state() -> &'static str {
    "skipped:modules-disabled-auto-forbidden"
}

impl crate::lockdown::LockdownCore {
    /// §6.3 phase wrapper; `explicit` is the operator single-phase command.
    pub(crate) fn hardening_phase(&mut self, explicit: bool) -> (u8, &'static str) {
        let report = apply(&self.config.hardening, explicit);
        (report.outcome, report.reason)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        os::unix::fs::PermissionsExt,
        path::Path,
        time::{SystemTime, UNIX_EPOCH},
    };

    fn fixture(label: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|value| value.as_nanos())
            .unwrap_or(0);
        let root = std::env::temp_dir().join(format!(
            "vgt-lockdown-hardening-{label}-{}-{nanos}",
            std::process::id()
        ));
        fs::create_dir_all(root.join("proc/sys/kernel")).expect("proc fixture");
        fs::create_dir_all(root.join("sys/kernel/security")).expect("sys fixture");
        root
    }

    fn write(root: &Path, path: &str, value: &str) {
        fs::write(root.join(path), format!("{value}\n")).expect("attr");
    }

    fn full_fixture(label: &str) -> PathBuf {
        let root = fixture(label);
        write(&root, "proc/sys/kernel/kexec_load_disabled", "0");
        write(&root, "proc/sys/kernel/sysrq", "1");
        write(&root, "proc/sys/kernel/modules_disabled", "0");
        write(&root, "proc/sys/kernel/unprivileged_bpf_disabled", "2");
        write(&root, "sys/kernel/security/lockdown", "none [integrity] confidentiality");
        root
    }

    fn value(root: &Path, path: &str) -> String {
        fs::read_to_string(root.join(path)).expect("attr").trim().to_owned()
    }

    #[test]
    fn observation_is_read_only_and_complete() {
        let root = full_fixture("observe");
        let paths = HardeningPaths::for_root(&root);
        let observation = observe(&paths);
        assert_eq!(observation.kexec_load_disabled.as_deref(), Some("0"));
        assert_eq!(observation.sysrq.as_deref(), Some("1"));
        assert_eq!(observation.modules_disabled.as_deref(), Some("0"));
        assert_eq!(observation.unprivileged_bpf_disabled.as_deref(), Some("2"));
        assert_eq!(observation.kernel_lockdown.as_deref(), Some("integrity"));
        // Observation must not mutate anything.
        assert_eq!(value(&root, "proc/sys/kernel/sysrq"), "1");
    }

    #[test]
    fn automatic_apply_writes_only_kexec_and_sysrq() {
        let root = full_fixture("auto");
        let paths = HardeningPaths::for_root(&root);
        let report = apply(&paths, false);
        assert_eq!(report.outcome, APPLIED, "{report:?}");
        assert_eq!(report.kexec_load_disabled, Write::Applied);
        assert_eq!(report.sysrq, Write::Applied);
        assert_eq!(report.modules_disabled, Write::Blocked);
        assert_eq!(value(&root, "proc/sys/kernel/kexec_load_disabled"), "1");
        assert_eq!(value(&root, "proc/sys/kernel/sysrq"), "0");
        assert_eq!(value(&root, "proc/sys/kernel/modules_disabled"), "0");
        assert_eq!(report.observation.modules_disabled.as_deref(), Some("0"));
        assert_eq!(modules_disabled_auto_state(), "skipped:modules-disabled-auto-forbidden");
    }

    #[test]
    fn explicit_apply_may_set_modules_disabled_but_missing_knobs_are_honest() {
        let root = full_fixture("explicit");
        let paths = HardeningPaths::for_root(&root);
        assert_eq!(apply(&paths, true).modules_disabled, Write::Applied);
        assert_eq!(value(&root, "proc/sys/kernel/modules_disabled"), "1");

        // A kernel without the knobs exposes nothing; no write is invented.
        let bare = fixture("bare");
        let paths = HardeningPaths::for_root(&bare);
        let report = apply(&paths, false);
        assert_eq!(report.outcome, UNSUPPORTED, "{report:?}");
        assert_eq!(report.kexec_load_disabled, Write::Missing);
        assert_eq!(report.sysrq, Write::Missing);
        assert_eq!(report.modules_disabled, Write::Blocked);
        assert_eq!(observe(&paths), Observation::default());
    }

    #[test]
    fn already_satisfied_knobs_are_not_rewritten() {
        let root = full_fixture("idempotent");
        let paths = HardeningPaths::for_root(&root);
        assert_eq!(apply(&paths, false).outcome, APPLIED);
        for file in [paths.kexec(), paths.sysrq()] {
            fs::set_permissions(&file, fs::Permissions::from_mode(0o444)).expect("read-only");
        }
        let report = apply(&paths, false);
        assert_eq!(report.outcome, APPLIED, "{report:?}");
        assert_eq!(report.kexec_load_disabled, Write::AlreadySet);
        assert_eq!(report.sysrq, Write::AlreadySet);
    }

    #[test]
    fn untyped_values_are_never_claimed() {
        let root = fixture("bad-domain");
        write(&root, "proc/sys/kernel/kexec_load_disabled", "7");
        write(&root, "proc/sys/kernel/sysrq", "1");
        let paths = HardeningPaths::for_root(&root);
        let report = apply(&paths, false);
        assert_eq!(report.kexec_load_disabled, Write::Failed);
        assert_eq!(report.sysrq, Write::Applied);
        assert_eq!(report.outcome, PARTIAL, "{report:?}");
        // A read-only knob is only a write failure for an unprivileged test
        // process; root can still write, so the outcome is checked honestly.
        fs::write(root.join("proc/sys/kernel/kexec_load_disabled"), "0\n").expect("knob");
        fs::set_permissions(
            root.join("proc/sys/kernel/kexec_load_disabled"),
            fs::Permissions::from_mode(0o444),
        )
        .expect("read-only");
        let report = apply(&paths, false);
        if unsafe { libc::geteuid() } != 0 {
            assert_eq!(report.kexec_load_disabled, Write::Failed);
            assert!(matches!(report.outcome, FAILED | PARTIAL), "{report:?}");
        } else {
            assert_eq!(report.outcome, APPLIED, "{report:?}");
        }
    }

    #[test]
    fn sysrq_bitmask_is_tolerated_and_explicit_modules_disabled_is_visible() {
        let root = full_fixture("sysrq-bitmask");
        let paths = HardeningPaths::for_root(&root);
        // A bitmask pre-state (e.g. kernel.sysrq=438) is a valid observation and
        // the typed opt-out to 0 is a valid write.
        write(&root, "proc/sys/kernel/sysrq", "438");
        assert_eq!(observe(&paths).sysrq.as_deref(), Some("438"));
        let report = apply(&paths, false);
        assert_eq!(report.sysrq, Write::Applied, "{report:?}");
        assert_eq!(value(&root, "proc/sys/kernel/sysrq"), "0");
        // A non-numeric value is a fail-safe failure, never a fake success.
        write(&root, "proc/sys/kernel/sysrq", "not-a-number");
        let report = apply(&paths, false);
        assert_eq!(report.sysrq, Write::Failed);
        assert_eq!(report.outcome, PARTIAL, "{report:?}");

        // Explicit single-phase command: a modules_disabled write failure is
        // part of the reported outcome (out-of-domain value => deterministic).
        write(&root, "proc/sys/kernel/sysrq", "1");
        write(&root, "proc/sys/kernel/modules_disabled", "7");
        let report = apply(&paths, true);
        assert_eq!(report.modules_disabled, Write::Failed, "{report:?}");
        assert_eq!(report.outcome, PARTIAL, "modules failure must be visible");
        // Auto path never writes modules_disabled even when it is writable.
        write(&root, "proc/sys/kernel/modules_disabled", "0");
        let report = apply(&paths, false);
        assert_eq!(report.modules_disabled, Write::Blocked);
        assert_eq!(value(&root, "proc/sys/kernel/modules_disabled"), "0");
        // Explicit path applies modules_disabled=1 once the knob is writable.
        let report = apply(&paths, true);
        assert_eq!(report.modules_disabled, Write::Applied, "{report:?}");
        assert_eq!(value(&root, "proc/sys/kernel/modules_disabled"), "1");
        assert_eq!(report.outcome, APPLIED, "{report:?}");
    }
}
