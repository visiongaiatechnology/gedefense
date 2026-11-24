//! §6.2/§9 USB device classification: the fail-safe policy matrix (charger,
//! console/HID/hub, block) over the injectable sysfs tree.

use std::{
    fs,
    path::{Path, PathBuf},
};

/// Upper bound on devices/entries examined per phase (§6 bounded scan).
pub(crate) const MAX_USB_ENTRIES: usize = 256;
pub(crate) const MAX_NAME_BYTES: usize = 64;
const CLASS_HID: u8 = 0x03;
const CLASS_HUB: u8 = 0x09;

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

pub(crate) fn valid_name(name: &str) -> bool {
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
