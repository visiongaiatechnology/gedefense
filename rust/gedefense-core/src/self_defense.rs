//! V6.3.0 AP-0 — sensor self-protection: eBPF pin manifest, synthetic canary
//! self-test and the bounded self-tamper evidence queue.
//!
//! STATUS: V6.3.0 AP-0 implemented (observe-only; the control plane owns the
//! XDR semantics). Fixed public contract from `main.rs`:
//! `load(ebpf, pin_root)`, `attach_canary(broker)`, `poll(now_ms)`,
//! `set_enabled_token(token)`, `take_events()`, `status()`, `unix_millis()`.
//!
//! What this module does — and deliberately does not do:
//!
//! * **Pin manifest.** At load it pins the critical kernel maps under
//!   `--bpf-pin-root` (default `/sys/fs/bpf/gedefense`) and records
//!   `(path, dev, ino)` for every expected pin. A host without a real BPF
//!   filesystem degrades honestly (`pins=unavailable`) instead of failing the
//!   core. On `poll` the manifest is re-verified on a <=5 s cadence: an unlinked
//!   pin (`ENOENT`) or a replaced inode becomes one bounded self-tamper record.
//! * **Synthetic canary self-test.** `attach_canary` stores the shared
//!   [`crate::canary::CanaryBroker`]. Every ~30 s a reserved, content-free decoy
//!   is deployed through the broker's public API inside the canary root, opened
//!   by a short-lived forked probe (the broker ignores opens by its own PID, so
//!   a child process is required to exercise a real access), the broker's event
//!   queue is drained and the decoy event is verified, then the decoy is
//!   removed. A sensor that produces no event within the bounded retry is
//!   self-tamper evidence — never silence. The whole cycle runs on a bounded
//!   worker thread so the authenticated IPC path never blocks on fanotify.
//! * **Bounded queue.** Capacity 64 records, each `ts_ms`, `kind`,
//!   `detail_code` and at most 32 bytes of hex-encodable detail. One drain
//!   returns at most 8 records and fits below 2 KiB.
//!
//! Nothing here blocks, kills or changes kernel policy. It observes and
//! reports; control-plane response semantics stay out of the privileged core.

mod pins;
mod queue;
mod canary;
mod core;

use self::pins::*;
use self::queue::*;
use self::canary::*;
use aya::{maps::Map, Ebpf};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use std::{
    collections::VecDeque,
    error::Error,
    ffi::CString,
    fs,
    os::unix::{ffi::OsStrExt, fs::MetadataExt},
    path::{Component, Path, PathBuf},
    thread,
    time::Duration,
};

type BoxError = Box<dyn Error + Send + Sync + 'static>;

/// Linux BPF filesystem magic (`include/uapi/linux/magic.h`).
const BPF_FS_MAGIC: u64 = 0xcafe_4a11;
/// Bounded self-tamper queue capacity (AP-0 contract).
const TAMPER_QUEUE_CAPACITY: usize = 64;
/// Maximum records returned by one `SELF_TAMPER_EVENTS` drain.
const MAX_EVENTS_PER_REPLY: usize = 8;
/// Hard ceiling for one encoded drain payload (AP-0 contract: <= 2 KiB).
const MAX_EVENTS_PAYLOAD_BYTES: usize = 2 * 1024;
/// Maximum detail bytes per record (hex-encoded on the wire).
const MAX_DETAIL_BYTES: usize = 32;
/// Pin verification cadence; the AP-0 acceptance window is <= 5 s.
const PIN_VERIFY_INTERVAL_MS: u64 = 5_000;
/// Synthetic canary self-test cadence.
const CANARY_TEST_INTERVAL_MS: u64 = 30_000;
/// Maximum non-destructive `CANARY_EVENTS` batches one self-test drains while
/// looking for its own decoy (each batch is at most four records).
const CANARY_DRAIN_ATTEMPTS: usize = 3;
/// The canary sensor owner (fanotify) ignores accesses by its own PID; the
/// probe therefore runs in a short-lived forked child and waits for it in a
/// bounded loop. The fanotify permission event is recorded before the access is
/// allowed, so a returned probe means the event is already queued.
const PROBE_WAIT_STEPS: usize = 500;
const PROBE_STEP_MICROS: u64 = 1_000;
/// Reserved decoy name; operators never create this one and the broker treats
/// it as an ordinary bounded decoy inside the configured canary root.
const SELF_TEST_DECOY_NAME: &str = ".vgt-self-test";
const DECOY_CANARY_TYPE: &str = "DOTENV";
const DECOY_MODE_TOKEN: &str = "600";
const DECOY_CONTENT: &[u8] = b"VGT-GEDEFENSE-SELF-TEST\n";
/// Worker stack bound: the cycle only performs file/fanotify calls plus small
/// bounded string parsing.
const CANARY_WORKER_STACK_BYTES: usize = 256 * 1024;

// Self-tamper record kinds (wire contract, AP-0).
const KIND_PIN_MISSING: u8 = 1;
const KIND_PIN_REPLACED: u8 = 2;
const KIND_CANARY_DEAD: u8 = 3;
const KIND_BPFFS_UNAVAILABLE: u8 = 4;
const KIND_PIN_RESTORED: u8 = 5;
const KIND_CANARY_RECOVERED: u8 = 6;

// Machine-readable detail codes. The human meaning is documented here only; the
// wire never carries free text from the kernel or a path.
const CODE_PIN_ROOT_INVALID: u32 = 1;
const CODE_PIN_ROOT_CREATE: u32 = 2;
const CODE_PIN_ROOT_NOT_BPFFS: u32 = 3;
const CODE_PIN_FAILED: u32 = 4;
const CODE_PIN_PARTIAL: u32 = 5;
const CODE_PIN_MISSING: u32 = 1;
const CODE_PIN_STAT_FAILED: u32 = 2;
const CODE_PIN_REPLACED_INODE: u32 = 1;
const CODE_PIN_REPLACED_TYPE: u32 = 2;
const CODE_CANARY_WATCHER: u32 = 1;
const CODE_CANARY_SCOPE: u32 = 2;
const CODE_CANARY_DEPLOY: u32 = 3;
const CODE_CANARY_PROBE: u32 = 4;
const CODE_CANARY_NO_EVENT: u32 = 5;
const CODE_CANARY_SPAWN: u32 = 6;
const CODE_CANARY_PANIC: u32 = 7;

/// Critical kernel maps whose pins are part of the AP-0 self-protection contract.
///
/// Names are the eBPF object symbol names. A name that the loaded object does
/// not carry (a pre-AP feature set) is not treated as an expected pin: the
/// manifest is the set that was actually pinned, so a missing pin can never be
/// confused with a feature that was never compiled in.
const CRITICAL_MAPS: [&str; 23] = [
    "EXEC_EVENTS",
    "EGRESS_EVENTS",
    "INGRESS_EVENTS",
    "FLOW_EVENTS",
    "CRED_GUARD_EVENTS",
    "RANSOM_EVENTS",
    "TITAN_EXEC_EVENTS",
    "CELL_LSM_EVENTS",
    "KERNEL_PROBE_EVENTS",
    "EXEC_ARGV_EVENTS",
    "WORKER_CRASH_EVENTS",
    "MALWARE_DENIED_INODES",
    "CRED_GUARD_FILES",
    "CRED_GUARD_DIRS",
    "TITAN_EXEC_POLICY",
    "TITAN_EXEC_MODE",
    "CELL_LSM_POLICIES",
    "CELL_EGRESS_MODE",
    "STYX_GLOBAL",
    "LOCKDOWN_STATE",
    "CRED_GUARD_STATE",
    "RANSOM_STATE",
    "WORKER_GUARD_STATE",
];

/// Monotonic-enough wall-clock milliseconds for the self-defence cadence.
pub(crate) fn unix_millis() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0)
}

/// Core-side self-protection state (AP-0).
pub(crate) struct SelfDefenseCore {
    enabled: bool,
    pins_usable: bool,
    manifest: Vec<PinEntry>,
    pins_missing: u64,
    pins_replaced: u64,
    pin_verify_due_ms: u64,
    canary: Option<crate::canary::CanaryBroker>,
    canary_state: CanaryState,
    canary_due_ms: u64,
    canary_runs: u64,
    canary_failures: u64,
    /// A `canary_dead` record has been emitted and no success has cleared it;
    /// this keeps one failure episode to exactly one record and makes the
    /// matching `canary_recovered` record unambiguous.
    canary_dead_reported: bool,
    canary_worker: Option<thread::JoinHandle<CanaryOutcome>>,
    queue: VecDeque<TamperRecord>,
    events_total: u64,
    dropped_total: u64,
    /// Overflow count not yet reported by `take_events`.
    dropped_pending: u64,
}

impl SelfDefenseCore {
    /// `SELF_TAMPER_EVENTS` -> `empty` or
    /// `<dropped>|<ts_ms>:<kind>:<detail_code>:<detail_hex>[,<record>...]`
    /// (at most 8 records, below 2 KiB).
    pub(crate) fn take_events(&mut self) -> Result<String, BoxError> {
        let dropped = std::mem::take(&mut self.dropped_pending);
        if dropped == 0 && self.queue.is_empty() {
            return Ok("empty".to_owned());
        }
        let count = self.queue.len().min(MAX_EVENTS_PER_REPLY);
        let mut encoded = String::with_capacity(512);
        let mut records = 0usize;
        let mut first = true;
        while records < count {
            let Some(record) = self.queue.pop_front() else {
                break;
            };
            let rendered = record.encode();
            if encoded
                .len()
                .saturating_add(rendered.len())
                .saturating_add(1)
                > MAX_EVENTS_PAYLOAD_BYTES
            {
                // Cannot happen with the fixed record caps, but never emit an
                // oversized response: keep the record for the next drain.
                self.queue.push_front(record);
                break;
            }
            if !first {
                encoded.push(',');
            }
            first = false;
            encoded.push_str(&rendered);
            records += 1;
        }
        Ok(format!("{dropped}|{encoded}"))
    }

    /// Pins every critical map the loaded object still carries and records the
    /// resulting file identity. Stale pins from a previous core instance are
    /// replaced; a non-regular node at an expected pin path is never deleted
    /// silently. Returns `(pinned, failed)` so the caller can report aggregate
    /// coverage without turning one bad boot into dozens of records.
    ///
    /// V6.3.0 AP-8: the map is resolved through the Chameleon profile (identity
    /// when the profile is off) and the pin **file name** uses the resolved name
    /// as well, so an opted-in installation does not publish the public map
    /// identifiers through the bpffs directory listing. The human-readable event
    /// detail keeps the public name; the signed admin mapping owns the relation.
    fn install_pins(&mut self, ebpf: &Ebpf, root: &Path) -> (usize, usize) {
        let mut failed = 0usize;
        for name in CRITICAL_MAPS {
            let resolved = crate::chameleon::map_name(name);
            let Some(map) = ebpf.map(&resolved) else {
                // Not part of this eBPF build: nothing to guard, nothing lost.
                continue;
            };
            let path = root.join(&resolved);
            match pin_one(map, &path) {
                Ok((dev, ino)) => self.manifest.push(PinEntry {
                    name,
                    path,
                    dev,
                    ino,
                    state: PinState::Healthy,
                }),
                Err(_) => failed += 1,
            }
        }
        (self.manifest.len(), failed)
    }

    /// Re-verifies the whole manifest. Each entry transitions at most once per
    /// observation, so a persistent condition produces one record, not one per
    /// poll. The manifest is temporarily moved out so enqueueing can borrow the
    /// rest of the state without allocation.
    fn verify_pins(&mut self, now_ms: u64) {
        let mut manifest = std::mem::take(&mut self.manifest);
        for entry in manifest.iter_mut() {
            let (state, code) = inspect_pin(entry);
            if state == entry.state {
                continue;
            }
            entry.state = state;
            match state {
                PinState::Healthy => {
                    self.push_event(now_ms, KIND_PIN_RESTORED, 0, entry.name.as_bytes());
                }
                PinState::Missing => {
                    self.pins_missing = self.pins_missing.saturating_add(1);
                    self.push_event(now_ms, KIND_PIN_MISSING, code, entry.name.as_bytes());
                }
                PinState::Replaced => {
                    self.pins_replaced = self.pins_replaced.saturating_add(1);
                    self.push_event(now_ms, KIND_PIN_REPLACED, code, entry.name.as_bytes());
                }
            }
        }
        self.manifest = manifest;
    }

    // ---------------------------------------------------------- canary probe

}

/// Pins one map and returns the identity of the resulting bpffs node.
fn pin_one(map: &Map, path: &Path) -> Result<(u64, u64), u32> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                // Never resolve or follow an unexpected node at a pin path.
                return Err(CODE_PIN_REPLACED_TYPE);
            }
            // A stale pin from a previous core instance (or a node that is not
            // our map) would make BPF_OBJ_PIN fail with EEXIST; replace the
            // installation-owned file so this boot's manifest is complete.
            fs::remove_file(path).map_err(|_| CODE_PIN_FAILED)?;
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => return Err(CODE_PIN_FAILED),
    }
    map.pin(path).map_err(|_| CODE_PIN_FAILED)?;
    let metadata = fs::symlink_metadata(path).map_err(|_| CODE_PIN_STAT_FAILED)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(CODE_PIN_REPLACED_TYPE);
    }
    Ok((metadata.dev(), metadata.ino()))
}

/// Classifies the current on-disk state of one expected pin.
fn inspect_pin(entry: &PinEntry) -> (PinState, u32) {
    match fs::symlink_metadata(&entry.path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                return (PinState::Replaced, CODE_PIN_REPLACED_TYPE);
            }
            if metadata.dev() == entry.dev && metadata.ino() == entry.ino {
                (PinState::Healthy, 0)
            } else {
                (PinState::Replaced, CODE_PIN_REPLACED_INODE)
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            (PinState::Missing, CODE_PIN_MISSING)
        }
        Err(_) => (PinState::Replaced, CODE_PIN_STAT_FAILED),
    }
}

#[cfg(test)]
mod tests;
