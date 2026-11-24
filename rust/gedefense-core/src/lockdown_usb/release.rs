//! §6.2 reversible release: re-authorizes what the USB/Thunderbolt policy
//! manages (Clear and `LOCKDOWN_PHASE ... off`).

use super::policy::{run, PolicyReport, Scope, UsbPaths};

pub(crate) fn release_usb(paths: &UsbPaths) -> PolicyReport {
    run(paths, Scope::UsbRelease)
}

pub(crate) fn release_tb(paths: &UsbPaths) -> PolicyReport {
    run(paths, Scope::TbRelease)
}

impl crate::lockdown::LockdownCore {
    /// §6.2 reversible release used by Clear and `LOCKDOWN_PHASE ... off`.
    pub(crate) fn usb_release(&mut self, thunderbolt: bool) -> (u8, &'static str) {
        let report = if thunderbolt { release_tb(&self.config.usb) } else { release_usb(&self.config.usb) };
        (report.outcome, report.reason)
    }
}
