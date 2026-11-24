//! Point 5 (§6.2): USB/Thunderbolt sysfs hotplug policy.
//!
//! Every knob is a plain sysfs attribute (never a shell). Each write is preceded
//! by a read (already-correct values are never rewritten) and followed by a
//! read-back that must match; a missing tree/attribute is `unsupported`, never a
//! fake success. Paths are injectable and unit-tested against a temp-dir fake.
//!
//! Wave 3c (structure-only) split: this parent keeps the public API and
//! re-exports the children — `classify` (device policy matrix), `policy`
//! (sysfs path injection, report, application/lock phase), `release` (the
//! reversible release phase) and `uevent` (hotplug parent/device handling).
//! The temp-dir sysfs fixture tests live in `tests`.

mod classify;
mod policy;
mod release;
mod uevent;
#[cfg(test)]
pub(crate) mod tests;

pub(crate) use self::classify::*;
pub(crate) use self::policy::*;
pub(crate) use self::uevent::*;
// The free release functions are called through this path by the tests.
#[cfg(test)]
pub(crate) use self::release::*;
