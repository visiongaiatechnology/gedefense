//! M2.2 (6.2.0): userspace half of the eBPF ransomware/rename-storm sensor.
//!
//! Owns the `RANSOM_*` maps of `rust/gedefense-ebpf/src/ransom.rs`: the event
//! ring, the armed state word, the trusted-comm exemption map and the health
//! counters. The kernel emits at most one 64-byte `RansomEvent` per window; this
//! module decodes it with the shared rejecting decoder, resolves the *real*
//! process group from `/proc/<tgid>/stat`, freezes the whole group with
//! `SIGSTOP` (bounded, reversible through `XDR_GROUP_CONT`) and forwards the
//! 8-field text record to the control plane:
//!
//! ```text
//! <tgid>:<pgid>:<uid>:<signal>:<reason>:<ts_ns>:<count>:<comm_hex>
//! ```
//!
//! `signal` is 1 (entropy burst) or 2 (rename storm); the wire `reason` is
//! `entropy_burst`/`rename_storm` (matching `control/coreipc_ransom.go`), while
//! the freeze/kill rule token is `XDR.RANSOM_ENTROPY_BURST`/`XDR.RANSOM_RENAME_STORM`;
//! `count` is the distinct-inode or operation count of the kernel window.
//! `RANSOM_EVENTS` answers `empty` or `<dropped>|<record>[,<record>…]`;
//! `RANSOM_STATUS` answers eight decimal health fields; `RANSOM_SET <0|1>` arms
//! or disarms the sensor.
//!
//! When at least one kprobe attaches, a dedicated low-latency watcher thread
//! (`gedefense-ransom-watch`) polls `RANSOM_EVENTS` directly via `poll(2)` (with
//! a 10 ms safety timeout) so non-trusted process groups are frozen with
//! `SIGSTOP` within <= 10 ms instead of waiting for the 100 ms control-plane
//! IPC drain tick.
//!
//! Attach is optional (a kernel without kprobe support still runs the rest of
//! the core); the map lookups are mandatory, so a stale eBPF object fails
//! loudly at startup instead of silently disabling the endpoint sensor. The
//! trusted-comm list is a *heuristic* exemption for package managers, compilers
//! and backup tools: `comm` is spoofable by a local attacker, so the control
//! plane correlates `RANSOM.*` with the XDR exec sensor instead of trusting the
//! name alone.
//!
//! Wave 3c (structure-only) split: this parent keeps the public API and the
//! shared `BoxError` alias and re-exports the children — `policy` (limits and
//! trusted-comm policy), `queue` (bounded record FIFO), `signals` (wire tokens
//! and ABI encoders), `watcher` (low-latency freeze broker) and `core`
//! (`RANSOM_*` map owner). The wire/status tests stay in `ransom_tests.rs`.

use std::error::Error;

mod core;
mod policy;
mod queue;
mod signals;
mod watcher;

pub(crate) use self::core::*;
pub(crate) use self::policy::*;
// The queue and signal helpers are consumed directly by `ransom_tests`.
#[cfg(test)]
pub(crate) use self::queue::*;
#[cfg(test)]
pub(crate) use self::signals::*;

type BoxError = Box<dyn Error + Send + Sync + 'static>;
