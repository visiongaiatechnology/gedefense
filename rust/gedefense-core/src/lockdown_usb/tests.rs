use gedefense_common::{
    LOCKDOWN_OUTCOME_APPLIED as APPLIED, LOCKDOWN_OUTCOME_UNSUPPORTED as UNSUPPORTED,
};
use std::fs;
use std::path::{Path, PathBuf};

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
