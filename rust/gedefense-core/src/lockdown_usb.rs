//! Point 5 (§6.2): USB/Thunderbolt sysfs hotplug policy.
//!
//! Every knob is a plain sysfs attribute (never a shell). Each write is preceded
//! by a read (already-correct values are never rewritten) and followed by a
//! read-back that must match; a missing tree/attribute is `unsupported`, never a
//! fake success. Paths are injectable and unit-tested against a temp-dir fake.

use gedefense_common::{
    LOCKDOWN_OUTCOME_APPLIED as APPLIED, LOCKDOWN_OUTCOME_FAILED as FAILED,
    LOCKDOWN_OUTCOME_PARTIAL as PARTIAL, LOCKDOWN_OUTCOME_UNSUPPORTED as UNSUPPORTED,
};
use std::{
    fs,
    path::{Path, PathBuf},
};

/// Upper bound on devices/entries examined per phase (§6 bounded scan).
pub(crate) const MAX_USB_ENTRIES: usize = 256;
const MAX_NAME_BYTES: usize = 64;
const CLASS_HID: u8 = 0x03;
const CLASS_HUB: u8 = 0x09;

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

/// Policy verdict for one device (§9 fail-safe matrix).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DevicePolicy {
    /// Charger/cable: no block, no trigger (Lade-Kabel-DoS-Schutz).
    PowerOnly,
    /// HID/Hub: default-allow so the local console stays usable.
    Console,
    /// Everything else in `locked`: `authorized=0`.
    Block,
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
fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_NAME_BYTES
        && name.bytes().all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b':'))
}

fn read_trimmed(dir: &Path, name: &str) -> Option<String> {
    let value = fs::read_to_string(dir.join(name)).ok()?;
    (value.len() <= 32).then(|| value.trim().to_owned()).filter(|value| !value.is_empty())
}
fn parse_class(value: &str) -> Option<u8> {
    u8::from_str_radix(value.trim_start_matches("0x"), 16).ok()
}
fn parse_u32(value: &str) -> Option<u32> {
    value.parse::<u32>().ok()
}

/// Subdirectories of a USB device that expose `bInterfaceClass` (bounded).
fn interfaces(dir: &Path) -> Vec<PathBuf> {
    let Ok(entries) = fs::read_dir(dir) else { return Vec::new() };
    let mut found = Vec::new();
    for entry in entries.flatten() {
        if found.len() >= MAX_USB_ENTRIES {
            break;
        }
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        let path = entry.path();
        if valid_name(name) && path.is_dir() && path.join("bInterfaceClass").is_file() {
            found.push(path);
        }
    }
    found
}

/// Power-only heuristic (§6): class-0, at most one interface and one
/// configuration, no interface class and no bound driver = charger/port.  The
/// interface count must match `bNumInterfaces` too: an empty/partial sysfs
/// interface list must never be read as "zero classes, therefore a charger".
fn is_power_only(
    dir: &Path,
    device_class: Option<u8>,
    num_interfaces: Option<u32>,
    ifaces: &[PathBuf],
) -> bool {
    let Some(count) = num_interfaces else { return false };
    let configurations = read_trimmed(dir, "bNumConfigurations").and_then(|value| parse_u32(&value));
    if !matches!(configurations, Some(0) | Some(1))
        || device_class != Some(0)
        || count > 1
        || count as usize != ifaces.len()
    {
        return false;
    }
    ifaces.iter().all(|interface| {
        read_trimmed(interface, "bInterfaceClass").and_then(|value| parse_class(&value)) == Some(0)
            && !interface.join("driver").exists()
    })
}

fn interface_class(interface: &Path) -> Option<u8> {
    read_trimmed(interface, "bInterfaceClass").and_then(|value| parse_class(&value))
}

/// Classifies one device directory according to the §9 policy matrix.
///
/// A console/hub claim is only trusted when the interface list is complete:
/// an empty list (pre-enumeration or a uevent race) or `bNumInterfaces` that
/// does not match the discovered interface count is a spoofed/partial
/// descriptor and therefore `Block`, never `Console`.  HID may also be declared
/// on the interface (`bDeviceClass=0`), in which case every interface must be
/// HID and the count must match so composite BadUSB devices are blocked.
pub(crate) fn classify(dir: &Path) -> DevicePolicy {
    let device_class = read_trimmed(dir, "bDeviceClass").and_then(|value| parse_class(&value));
    let num_interfaces = read_trimmed(dir, "bNumInterfaces").and_then(|value| parse_u32(&value));
    let ifaces = interfaces(dir);
    let interfaces_complete =
        !ifaces.is_empty() && num_interfaces.is_some_and(|count| count as usize == ifaces.len());
    let hid_only_interfaces = interfaces_complete
        && device_class == Some(0)
        && ifaces.iter().all(|interface| interface_class(interface) == Some(CLASS_HID));
    let pure_device_console = interfaces_complete
        && match device_class {
            Some(CLASS_HID) => ifaces.iter().all(|interface| interface_class(interface) == Some(CLASS_HID)),
            Some(CLASS_HUB) => ifaces.iter().all(|interface| interface_class(interface) == Some(CLASS_HUB)),
            _ => false,
        };
    if pure_device_console || hid_only_interfaces {
        return DevicePolicy::Console;
    }
    if is_power_only(dir, device_class, num_interfaces, &ifaces) {
        return DevicePolicy::PowerOnly;
    }
    DevicePolicy::Block
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WriteOutcome {
    Applied,
    AlreadySet,
    Missing,
    Failed,
}

/// Read-before-write + read-back verify for one plain sysfs value.
fn set_attr(path: &Path, desired: &str) -> WriteOutcome {
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
enum Scope {
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
fn run(paths: &UsbPaths, scope: Scope) -> PolicyReport {
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

pub(crate) fn release_usb(paths: &UsbPaths) -> PolicyReport {
    run(paths, Scope::UsbRelease)
}

pub(crate) fn apply_tb(paths: &UsbPaths) -> PolicyReport {
    run(paths, Scope::TbLock)
}

pub(crate) fn release_tb(paths: &UsbPaths) -> PolicyReport {
    run(paths, Scope::TbRelease)
}

/// Resolves the parent device path of a USB interface uevent: the last path
/// component must be an interface name (`1-1:1.0`), the returned parent
/// (`.../1-1`) still has to pass `UsbPaths::device_dir` validation.
pub(crate) fn parent_device_devpath(devpath: &str) -> Option<&str> {
    let (parent, last) = devpath.rsplit_once('/')?;
    if parent.len() <= 1
        || parent.len() > MAX_NAME_BYTES * 4
        || !last.contains(':')
        || last.len() > MAX_NAME_BYTES
        || devpath.contains("..")
    {
        return None;
    }
    Some(parent)
}

/// Uevent path: classify one newly added USB device and block it in `locked`.
/// `Err` names why no device action was taken; it is not a fake success.
pub(crate) fn apply_device(paths: &UsbPaths, devpath: &str) -> Result<DevicePolicy, &'static str> {
    let dir = paths.device_dir(devpath).ok_or("invalid-devpath")?;
    if !dir.is_dir() || !dir.join("bDeviceClass").is_file() {
        return Err("not-present");
    }
    let policy = classify(&dir);
    if policy != DevicePolicy::Block {
        return Ok(policy);
    }
    let authorized = dir.join("authorized");
    match set_attr(&authorized, "0") {
        WriteOutcome::Applied | WriteOutcome::AlreadySet => Ok(DevicePolicy::Block),
        WriteOutcome::Missing => Err("no-authorized-attribute"),
        WriteOutcome::Failed => Err("authorized-write-failed"),
    }
}

/// Uevent path for Thunderbolt: every added device is unauthorized (DMA).
pub(crate) fn apply_tb_device(paths: &UsbPaths, devpath: &str) -> Result<(), &'static str> {
    let dir = paths.device_dir(devpath).ok_or("invalid-devpath")?;
    match set_attr(&dir.join("authorized"), "0") {
        WriteOutcome::Applied | WriteOutcome::AlreadySet => Ok(()),
        WriteOutcome::Missing => Err("no-authorized-attribute"),
        WriteOutcome::Failed => Err("authorized-write-failed"),
    }
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
    /// §6.2 reversible release used by Clear and `LOCKDOWN_PHASE ... off`.
    pub(crate) fn usb_release(&mut self, thunderbolt: bool) -> (u8, &'static str) {
        let report = if thunderbolt { release_tb(&self.config.usb) } else { release_usb(&self.config.usb) };
        (report.outcome, report.reason)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::{
        os::unix::fs::PermissionsExt,
        time::{SystemTime, UNIX_EPOCH},
    };

    pub(crate) fn fixture(label: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|value| value.as_nanos())
            .unwrap_or(0);
        let root = std::env::temp_dir().join(format!(
            "vgt-lockdown-usb-{label}-{}-{nanos}",
            std::process::id()
        ));
        fs::create_dir_all(root.join("sys/bus/usb/devices")).expect("usb fixture");
        fs::create_dir_all(root.join("sys/bus/thunderbolt/devices")).expect("tb fixture");
        fs::write(root.join("sys/bus/usb/drivers_autoprobe"), "1\n").expect("autoprobe fixture");
        root
    }

    pub(crate) fn usb_device(
        root: &Path,
        name: &str,
        class: &str,
        interfaces: &str,
        configurations: &str,
        authorized: Option<&str>,
    ) -> PathBuf {
        let dir = root.join("sys/bus/usb/devices").join(name);
        fs::create_dir_all(&dir).expect("device dir");
        fs::write(dir.join("bDeviceClass"), format!("{class}\n")).expect("class");
        fs::write(dir.join("bNumInterfaces"), format!("{interfaces}\n")).expect("interfaces");
        fs::write(dir.join("bNumConfigurations"), format!("{configurations}\n")).expect("configs");
        if let Some(value) = authorized {
            fs::write(dir.join("authorized"), format!("{value}\n")).expect("authorized");
        }
        dir
    }

    pub(crate) fn interface(dir: &Path, name: &str, class: &str, driver: bool) {
        let iface = dir.join(name);
        fs::create_dir_all(&iface).expect("interface dir");
        fs::write(iface.join("bInterfaceClass"), format!("{class}\n")).expect("iface class");
        if driver {
            let target = dir.join("driver-target");
            fs::create_dir_all(&target).expect("driver target");
            std::os::unix::fs::symlink(&target, iface.join("driver")).expect("driver link");
        }
    }

    fn tb_device(root: &Path, name: &str, authorized: &str) {
        let dir = root.join("sys/bus/thunderbolt/devices").join(name);
        fs::create_dir_all(&dir).expect("tb dir");
        fs::write(dir.join("authorized"), format!("{authorized}\n")).expect("tb authorized");
    }

    fn value(path: &Path) -> String {
        fs::read_to_string(path).expect("attribute").trim().to_owned()
    }

    #[test]
    fn classifier_matches_the_fail_safe_matrix() {
        let root = fixture("classify");
        let charger = usb_device(&root, "1-1", "00", "00", "01", None);
        assert_eq!(classify(&charger), DevicePolicy::PowerOnly);
        let keyboard = usb_device(&root, "1-2", "00", "01", "01", Some("1"));
        interface(&keyboard, "1-2:1.0", "03", true);
        assert_eq!(classify(&keyboard), DevicePolicy::Console);
        // A device-level HID/hub console is only trusted with a complete
        // interface list: non-empty and matching bNumInterfaces.
        let hid = usb_device(&root, "1-3", "03", "01", "01", Some("1"));
        interface(&hid, "1-3:1.0", "03", true);
        assert_eq!(classify(&hid), DevicePolicy::Console);
        let hub = usb_device(&root, "usb1", "09", "01", "01", Some("1"));
        interface(&hub, "usb1:1.0", "09", true);
        assert_eq!(classify(&hub), DevicePolicy::Console);
        let storage = usb_device(&root, "1-4", "00", "01", "01", Some("1"));
        interface(&storage, "1-4:1.0", "08", true);
        assert_eq!(classify(&storage), DevicePolicy::Block);
        let class_zero = usb_device(&root, "1-7", "00", "01", "01", Some("1"));
        interface(&class_zero, "1-7:1.0", "00", true);
        assert_eq!(classify(&class_zero), DevicePolicy::Block);
        for name in ["1-5", "1-6"] {
            let class = if name == "1-5" { "ff" } else { "02" };
            assert_eq!(classify(&usb_device(&root, name, class, "01", "01", Some("1"))), DevicePolicy::Block);
        }
        // Composite BadUSB: HID + Mass Storage / CDC under bDeviceClass=00 must block.
        let badusb = usb_device(&root, "1-8", "00", "02", "01", Some("1"));
        interface(&badusb, "1-8:1.0", "03", true);
        interface(&badusb, "1-8:1.1", "08", true);
        assert_eq!(classify(&badusb), DevicePolicy::Block);
        // Spoofed device-level HID with a non-HID interface or partial enumeration must block.
        let spoof_hid = usb_device(&root, "1-9", "03", "02", "01", Some("1"));
        interface(&spoof_hid, "1-9:1.0", "03", true);
        interface(&spoof_hid, "1-9:1.1", "02", true);
        assert_eq!(classify(&spoof_hid), DevicePolicy::Block);
        let partial_enum = usb_device(&root, "1-10", "00", "02", "01", Some("1"));
        interface(&partial_enum, "1-10:1.0", "03", true);
        assert_eq!(classify(&partial_enum), DevicePolicy::Block);
        // FIND-004 regression: an empty or count-mismatched interface list is
        // never a console and never a power-only charger.
        let lazy_hid = usb_device(&root, "1-11", "03", "00", "01", Some("1"));
        assert_eq!(classify(&lazy_hid), DevicePolicy::Block, "HID class 3 without enumerated interfaces");
        let hid_mismatch = usb_device(&root, "1-12", "03", "02", "01", Some("1"));
        interface(&hid_mismatch, "1-12:1.0", "03", true);
        assert_eq!(classify(&hid_mismatch), DevicePolicy::Block, "HID bNumInterfaces=2 with one interface");
        let hub_mismatch = usb_device(&root, "1-13", "09", "02", "01", Some("1"));
        interface(&hub_mismatch, "1-13:1.0", "09", true);
        assert_eq!(classify(&hub_mismatch), DevicePolicy::Block, "hub bNumInterfaces=2 with one interface");
        let spoof_hub_hid = usb_device(&root, "1-14", "09", "01", "01", Some("1"));
        interface(&spoof_hub_hid, "1-14:1.0", "03", true);
        assert_eq!(classify(&spoof_hub_hid), DevicePolicy::Block, "hub class with HID interface");
        let lazy_charger = usb_device(&root, "1-15", "00", "01", "01", Some("1"));
        assert_eq!(classify(&lazy_charger), DevicePolicy::Block, "power-only with missing interface dir");
    }

    #[test]
    fn locked_policy_blocks_data_devices_but_never_chargers_or_console() {
        let root = fixture("locked");
        let paths = UsbPaths::new(root.join("sys"));
        let storage = usb_device(&root, "1-3", "08", "01", "01", Some("1"));
        let keyboard = usb_device(&root, "1-2", "03", "01", "01", Some("1"));
        interface(&keyboard, "1-2:1.0", "03", true);
        let hub = usb_device(&root, "usb1", "09", "01", "01", Some("1"));
        interface(&hub, "usb1:1.0", "09", true);
        let report = apply_usb(&paths);
        assert_eq!((report.outcome, report.blocked), (APPLIED, 1), "{report:?}");
        assert_eq!((value(&paths.autoprobe()), value(&storage.join("authorized"))), ("0".into(), "0".into()));
        assert_eq!(value(&keyboard.join("authorized")), "1");
        assert_eq!(value(&hub.join("authorized")), "1");
        // Idempotent: read-only attributes force a read-only second pass.
        for file in [paths.autoprobe(), storage.join("authorized")] {
            fs::set_permissions(&file, fs::Permissions::from_mode(0o444)).expect("read-only");
        }
        let second = apply_usb(&paths);
        assert_eq!((second.outcome, second.blocked), (APPLIED, 1), "{second:?}");
    }

    #[test]
    fn incomplete_console_claims_are_blocked_and_written_as_authorized_zero() {
        // The same devices classify() rejects must be enforced by run(): a
        // zero-interface HID claim and a mismatched hub claim end up with
        // authorized=0 while a genuine console keeps authorized=1.
        let root = fixture("write-zero");
        let paths = UsbPaths::new(root.join("sys"));
        let lazy_hid = usb_device(&root, "1-2", "03", "00", "01", Some("1"));
        let hub_mismatch = usb_device(&root, "usb1", "09", "02", "01", Some("1"));
        interface(&hub_mismatch, "usb1:1.0", "09", true);
        let console = usb_device(&root, "1-3", "03", "01", "01", Some("1"));
        interface(&console, "1-3:1.0", "03", true);
        let report = apply_usb(&paths);
        assert_eq!((report.outcome, report.blocked), (APPLIED, 2), "{report:?}");
        assert_eq!(value(&lazy_hid.join("authorized")), "0");
        assert_eq!(value(&hub_mismatch.join("authorized")), "0");
        assert_eq!(value(&console.join("authorized")), "1");
    }

    #[test]
    fn interface_uevent_parent_resolution_is_bounded_and_applies_parent_policy() {
        let root = fixture("iface-parent");
        let paths = UsbPaths::new(root.join("sys"));
        let dir = root.join("sys/devices/pci0000:00/usb1/1-9");
        fs::create_dir_all(&dir).expect("parent device dir");
        fs::write(dir.join("bDeviceClass"), "00\n").expect("class");
        fs::write(dir.join("bNumInterfaces"), "01\n").expect("interfaces");
        fs::write(dir.join("bNumConfigurations"), "01\n").expect("configs");
        fs::write(dir.join("authorized"), "1\n").expect("authorized");
        interface(&dir, "1-9:1.0", "08", true);
        let iface = "/devices/pci0000:00/usb1/1-9/1-9:1.0";
        let parent = parent_device_devpath(iface).expect("interface parent");
        assert_eq!(parent, "/devices/pci0000:00/usb1/1-9");
        assert_eq!(apply_device(&paths, parent), Ok(DevicePolicy::Block));
        assert_eq!(value(&dir.join("authorized")), "0", "late storage interface deauthorizes the parent");
        // Not an interface path / traversal / too-short paths never resolve.
        assert_eq!(parent_device_devpath("/devices/pci0000:00/usb1/1-9"), None);
        assert_eq!(parent_device_devpath("/devices/../etc/passwd:1.0"), None);
        assert_eq!(parent_device_devpath("/1-1:1.0"), None);
        let relative = parent_device_devpath("relative/1-1:1.0").expect("split succeeds");
        assert_eq!(relative, "relative");
        assert!(paths.device_dir(relative).is_none(), "device_dir rejects relative parents");
        // A genuine console parent stays authorized when its interface uevent
        // is resolved and the parent policy is applied.
        let console = root.join("sys/devices/pci0000:00/usb1/1-10");
        fs::create_dir_all(&console).expect("console dir");
        fs::write(console.join("bDeviceClass"), "03\n").expect("class");
        fs::write(console.join("bNumInterfaces"), "01\n").expect("interfaces");
        fs::write(console.join("bNumConfigurations"), "01\n").expect("configs");
        fs::write(console.join("authorized"), "1\n").expect("authorized");
        interface(&console, "1-10:1.0", "03", true);
        let console_iface = "/devices/pci0000:00/usb1/1-10/1-10:1.0";
        assert_eq!(apply_device(&paths, parent_device_devpath(console_iface).unwrap()), Ok(DevicePolicy::Console));
        assert_eq!(value(&console.join("authorized")), "1");
    }

    #[test]
    fn release_reauthorizes_and_missing_tree_is_unsupported() {
        let root = fixture("release");
        let paths = UsbPaths::new(root.join("sys"));
        let storage = usb_device(&root, "1-3", "08", "01", "01", Some("0"));
        assert_eq!(apply_usb(&paths).outcome, APPLIED);
        assert_eq!(value(&storage.join("authorized")), "0");
        assert_eq!(release_usb(&paths).outcome, APPLIED);
        assert_eq!((value(&storage.join("authorized")).as_str(), value(&paths.autoprobe()).as_str()), ("1", "1"));
        let missing = UsbPaths::new(root.join("absent"));
        let report = apply_usb(&missing);
        assert_eq!((report.outcome, report.reason), (UNSUPPORTED, "not-present"));
        assert_eq!(apply_tb(&missing).outcome, UNSUPPORTED);
    }

    #[test]
    fn thunderbolt_is_always_blocked_while_locked() {
        let root = fixture("tb");
        let paths = UsbPaths::new(root.join("sys"));
        tb_device(&root, "0-1", "1");
        tb_device(&root, "0-2", "0");
        let report = apply_tb(&paths);
        assert_eq!(report.outcome, APPLIED, "{report:?}");
        assert_eq!(report.blocked, 2);
        assert_eq!(release_tb(&paths).outcome, APPLIED);
    }
}
