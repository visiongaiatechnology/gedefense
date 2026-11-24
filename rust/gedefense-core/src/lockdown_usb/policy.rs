//! §6.2 USB/Thunderbolt policy phase: injectable sysfs paths, the per-phase
//! report, read-before-write attribute application and the locked arm.

use gedefense_common::{
    LOCKDOWN_OUTCOME_APPLIED as APPLIED, LOCKDOWN_OUTCOME_FAILED as FAILED,
    LOCKDOWN_OUTCOME_PARTIAL as PARTIAL, LOCKDOWN_OUTCOME_UNSUPPORTED as UNSUPPORTED,
};
use std::{
    fs,
    path::{Path, PathBuf},
};

use super::classify::{classify, valid_name, DevicePolicy, MAX_NAME_BYTES, MAX_USB_ENTRIES};

/// Injectable sysfs root: production `/sys`, tests a temp-dir fake.
#[derive(Clone, Debug)]
pub(crate) struct UsbPaths {
    sys_root: PathBuf,
}

impl UsbPaths {
    pub(crate) fn new(sys_root: impl Into<PathBuf>) -> Self {
        Self { sys_root: sys_root.into() }
    }
    pub(crate) fn system() -> Self {
        Self::new("/sys")
    }
    pub(crate) fn usb_root(&self) -> PathBuf {
        self.sys_root.join("bus/usb")
    }
    pub(crate) fn autoprobe(&self) -> PathBuf {
        self.sys_root.join("bus/usb/drivers_autoprobe")
    }
    pub(crate) fn usb_devices(&self) -> PathBuf {
        self.sys_root.join("bus/usb/devices")
    }
    pub(crate) fn tb_devices(&self) -> PathBuf {
        self.sys_root.join("bus/thunderbolt/devices")
    }

    /// Maps a kernel uevent `DEVPATH` (`/devices/...`) onto the injected sysfs
    /// root; only conservative, traversal-free paths are accepted.
    pub(crate) fn device_dir(&self, devpath: &str) -> Option<PathBuf> {
        if !devpath.starts_with('/')
            || devpath.len() > MAX_NAME_BYTES * 4
            || devpath.contains("..")
            || !devpath.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'.' | b'_' | b'-' | b':')
            })
        {
            return None;
        }
        Some(self.sys_root.join(devpath.trim_start_matches('/')))
    }
}

impl Default for UsbPaths {
    fn default() -> Self {
        Self::system()
    }
}

/// Aggregate per-phase result plus the counters the §5 health line reports.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PolicyReport {
    pub(crate) outcome: u8,
    pub(crate) scanned: u32,
    pub(crate) blocked: u32,
    pub(crate) allowed: u32,
    pub(crate) unsupported: u32,
    pub(crate) failed: u32,
    pub(crate) reason: &'static str,
}

impl PolicyReport {
    fn new(reason: &'static str) -> Self {
        Self { outcome: UNSUPPORTED, scanned: 0, blocked: 0, allowed: 0, unsupported: 0, failed: 0, reason }
    }

    fn settle(mut self, enforcement: bool) -> Self {
        self.outcome = if self.failed > 0 {
            if self.blocked > 0 || enforcement { PARTIAL } else { FAILED }
        } else if self.unsupported >= self.scanned && !enforcement {
            UNSUPPORTED
        } else {
            APPLIED
        };
        self
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum WriteOutcome {
    Applied,
    AlreadySet,
    Missing,
    Failed,
}

/// Read-before-write + read-back verify for one plain sysfs value.
pub(crate) fn set_attr(path: &Path, desired: &str) -> WriteOutcome {
    use std::io::Write as _;
    let Ok(current) = fs::read_to_string(path) else {
        return WriteOutcome::Missing;
    };
    if current.trim() == desired {
        return WriteOutcome::AlreadySet;
    }
    if current.len() > 32 {
        return WriteOutcome::Failed;
    }
    let Ok(mut file) = fs::OpenOptions::new().write(true).open(path) else {
        return WriteOutcome::Failed;
    };
    if file.write_all(desired.as_bytes()).is_err() || file.write_all(b"\n").is_err() {
        return WriteOutcome::Failed;
    }
    drop(file);
    match fs::read_to_string(path) {
        Ok(verified) if verified.trim() == desired => WriteOutcome::Applied,
        _ => WriteOutcome::Failed,
    }
}

fn account(report: &mut PolicyReport, outcome: WriteOutcome, blocked: bool) {
    match outcome {
        WriteOutcome::Applied | WriteOutcome::AlreadySet if blocked => report.blocked += 1,
        WriteOutcome::Applied | WriteOutcome::AlreadySet => report.allowed += 1,
        WriteOutcome::Missing => report.unsupported += 1,
        WriteOutcome::Failed => report.failed += 1,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Scope {
    UsbLock,
    UsbRelease,
    TbLock,
    TbRelease,
}

fn locked(scope: Scope) -> bool {
    matches!(scope, Scope::UsbLock | Scope::TbLock)
}

/// Applies or releases the USB/TB policy (§6.2). UsbLock walks every device,
/// skips power-only and console classes, and blocks the rest; TbLock blocks all
/// Thunderbolt devices (DMA). Release re-authorizes what the policy manages.
pub(crate) fn run(paths: &UsbPaths, scope: Scope) -> PolicyReport {
    let usb = scope == Scope::UsbLock || scope == Scope::UsbRelease;
    let root = if usb { paths.usb_devices() } else { paths.tb_devices() };
    let present = if usb { paths.usb_root().is_dir() && root.is_dir() } else { root.is_dir() };
    if !present {
        return PolicyReport::new("not-present");
    }
    let mut report = PolicyReport::new(if locked(scope) { "applied" } else { "released" });
    if usb {
        let desired = if locked(scope) { "0" } else { "1" };
        match set_attr(&paths.autoprobe(), desired) {
            WriteOutcome::Missing => report.unsupported += 1,
            WriteOutcome::Failed => report.failed += 1,
            _ => {}
        }
    }
    let Ok(entries) = fs::read_dir(&root) else {
        return PolicyReport::new("scan-failed");
    };
    let mut enforcement = true;
    for entry in entries.flatten() {
        if report.scanned as usize >= MAX_USB_ENTRIES {
            break;
        }
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        let dir = entry.path();
        if !valid_name(name) || !dir.is_dir() {
            continue;
        }
        if usb && !dir.join("bDeviceClass").is_file() {
            continue;
        }
        if scope == Scope::UsbLock {
            match classify(&dir) {
                DevicePolicy::PowerOnly | DevicePolicy::Console => {
                    report.scanned += 1;
                    report.allowed += 1;
                    continue;
                }
                DevicePolicy::Block => {}
            }
        }
        report.scanned += 1;
        let authorized = dir.join("authorized");
        if !authorized.is_file() {
            report.unsupported += 1;
            enforcement = false;
            continue;
        }
        let desired = if locked(scope) { "0" } else { "1" };
        account(&mut report, set_attr(&authorized, desired), locked(scope));
        if usb {
            account(&mut report, set_attr(&dir.join("authorized_default"), desired), false);
        }
    }
    if usb && locked(scope) {
        if let Ok(entries) = fs::read_dir(&root) {
            for entry in entries.flatten() {
                let name = entry.file_name();
                let Some(name) = name.to_str() else { continue };
                if name.starts_with("usb") && valid_name(name) {
                    account(&mut report, set_attr(&entry.path().join("authorized_default"), "0"), false);
                }
            }
        }
    }
    report.settle(enforcement)
}

pub(crate) fn apply_usb(paths: &UsbPaths) -> PolicyReport {
    run(paths, Scope::UsbLock)
}

pub(crate) fn apply_tb(paths: &UsbPaths) -> PolicyReport {
    run(paths, Scope::TbLock)
}

impl crate::lockdown::LockdownCore {
    /// §6.2 USB/TB phase: applies the fixed sysfs policy, counts blocked devices.
    pub(crate) fn usb_phase(&mut self, thunderbolt: bool) -> (u8, &'static str) {
        let report = if thunderbolt { apply_tb(&self.config.usb) } else { apply_usb(&self.config.usb) };
        if thunderbolt {
            self.shared.add_tb_blocks(report.blocked);
        } else {
            self.shared.add_usb_blocks(report.blocked);
        }
        (report.outcome, report.reason)
    }
}
