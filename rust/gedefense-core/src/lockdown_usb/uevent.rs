//! §6.2 hotplug path: bounded parent-device resolution and per-device
//! classification/authorization for USB interface and Thunderbolt uevents.

use super::classify::{classify, DevicePolicy, MAX_NAME_BYTES};
use super::policy::{set_attr, UsbPaths, WriteOutcome};

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
