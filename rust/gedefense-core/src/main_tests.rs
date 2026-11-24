#![cfg(test)]
//! Wave 3a extraction: the crate-root test suite moved verbatim from the inline
//! `#[cfg(test)] mod tests` of `main.rs` (module name and `crate::tests` path
//! are preserved via `#[path]` in the crate root).
//!
//! Wave 5a: split into thematic child modules under `main_tests/` (structure-only;
//! every test body/name moved verbatim, only the module path gained one segment).
//!
//! The child modules are declared with explicit `#[path]` attributes: a module
//! loaded via `#[path]` resolves its children in the containing `src/` directory,
//! so the explicit paths pin the required `src/main_tests/<group>.rs` layout.

use super::*;
// 6.1.0 policy-bit expectations are test-only: the production path only
// needs the aggregate mask, so these stay out of the shipped import set.
use gedefense_common::{
    CELL_LSM_DENY_AF_PACKET, CELL_LSM_DENY_NON_UNIX_SOCKET, CELL_LSM_DENY_RDS,
};

use crate::ebpf_loader::*;
use crate::ipc::dispatch_lockdown::*;
use crate::ipc::dispatch_net::*;
use crate::ipc::dispatch_titan::*;
use crate::ipc::server::*;
use crate::poller::*;
use crate::sysctl_broker::*;

// Shared fixtures: `MemoryWordStore` is referenced by the `crate::lockdown_uevent`
// tests and the lockdown child module; `test_titan_directory` is shared by the
// `btf_tests` and `exec_tests` child modules.

/// Fake `LOCKDOWN_STATE` array map; `ignore_writes` simulates a write that
/// the kernel does not persist, so a read-back mismatch must be visible.
pub(crate) struct MemoryWordStore {
    word: std::sync::Mutex<u64>,
    ignore_write: std::sync::atomic::AtomicBool,
    writes: std::sync::atomic::AtomicU64,
}

impl MemoryWordStore {
    pub(crate) fn new() -> Self {
        Self {
            word: std::sync::Mutex::new(0),
            ignore_write: std::sync::atomic::AtomicBool::new(false),
            writes: std::sync::atomic::AtomicU64::new(0),
        }
    }
    pub(crate) fn word(&self) -> u64 {
        *self.word.lock().expect("fake word")
    }
    pub(crate) fn ignore_writes(&self) {
        self.ignore_write.store(true, std::sync::atomic::Ordering::Relaxed);
    }
    pub(crate) fn writes(&self) -> u64 {
        self.writes.load(std::sync::atomic::Ordering::Relaxed)
    }
}

impl lockdown::LockdownWordStore for MemoryWordStore {
    fn write(&self, word: u64) -> Result<(), String> {
        self.writes.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if self.ignore_write.load(std::sync::atomic::Ordering::Relaxed) {
            return Ok(());
        }
        *self.word.lock().map_err(|_| "fake word".to_owned())? = word;
        Ok(())
    }
    fn read(&self) -> Result<u64, String> {
        Ok(*self.word.lock().map_err(|_| "fake word".to_owned())?)
    }
}

fn test_titan_directory(label: &str) -> std::path::PathBuf {
    let mut path = std::env::temp_dir();
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or(0);
    path.push(format!("vgt-titan-{label}-{}-{nanos}", std::process::id()));
    fs::create_dir_all(&path).expect("create titan fixture directory");
    path
}

#[cfg(test)]
#[path = "main_tests/ipc_tests.rs"]
mod ipc_tests;
#[cfg(test)]
#[path = "main_tests/flow_tests.rs"]
mod flow_tests;
#[cfg(test)]
#[path = "main_tests/btf_tests.rs"]
mod btf_tests;
#[cfg(test)]
#[path = "main_tests/exec_tests.rs"]
mod exec_tests;
#[cfg(test)]
#[path = "main_tests/lockdown_group.rs"]
mod lockdown_group;
