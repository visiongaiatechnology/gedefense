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

use crate::process_tree;
use aya::{
    maps::{Array as AyaArray, HashMap as AyaHashMap, MapData, PerCpuArray, RingBuf},
    programs::{KProbe, ProgramError},
    Ebpf,
};
use gedefense_common::{
    decode_ransom_event, RansomEvent, RANSOM_SIGNAL_RENAME_STORM, RANSOM_STATE_ABI,
    RANSOM_STATE_ABI_SHIFT, RANSOM_STATE_ARMED_SHIFT, RANSOM_STATE_MAGIC,
    RANSOM_STATE_MAGIC_SHIFT, RANSOM_TRUST_FULL, RANSOM_TRUST_POOL_METADATA,
};
use std::{
    collections::VecDeque,
    error::Error,
    os::fd::AsRawFd,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    thread::{self, JoinHandle},
    time::Duration,
};

type BoxError = Box<dyn Error + Send + Sync + 'static>;

/// Pre-existing event batch bound (same shape as the malware/exec drains).
pub(crate) const MAX_RANSOM_EVENTS_PER_RESPONSE: usize = 8;
pub(crate) const MAX_RANSOM_PAYLOAD_BYTES: usize = 2048;
/// Bounded FIFO buffer between the <10 ms watcher thread and `RANSOM_EVENTS` IPC.
pub(crate) const MAX_PENDING_RANSOM_RECORDS: usize = 256;
/// Maximum sleep between ringbuf checks when no kernel wakeup fires.
const RANSOM_POLL_TIMEOUT_MS: i32 = 10;
/// Kernel-side kprobe symbols (see `rust/gedefense-ebpf/src/ransom.rs`).
const RANSOM_KPROBES: &[(&str, &str)] = &[
    ("gedefense_ransom_vfs_write", "vfs_write"),
    ("gedefense_ransom_vfs_rename", "vfs_rename"),
    ("gedefense_ransom_vfs_unlink", "vfs_unlink"),
];
/// Built-in trusted-comm exemptions (package managers, compilers, backup/sync
/// tools, container runtimes). Each entry is a Linux task name (≤15 bytes).
pub(crate) const TRUSTED_COMMS: &[&str] = &[
    "apt",
    "apt-get",
    "dpkg",
    "dpkg-deb",
    "apt-helper",
    "tar",
    "gzip",
    "gunzip",
    "bzip2",
    "xz",
    "zstd",
    "rsync",
    "git",
    "cargo",
    "rustc",
    "cc1",
    "cc1plus",
    "gcc",
    "clang",
    "ld",
    "ld.bfd",
    "ld.gold",
    "lld",
    "make",
    "cmake",
    "ninja",
    "python3",
    "python",
    "node",
    "npm",
    "systemd",
    "systemd-journal",
    "systemd-udevd",
    "udevadm",
    "systemd-tmpfile",
    "systemd-user-ru",
    "systemd-logind",
    "systemd-resolve",
    "systemd-timesyn",
    "systemd-network",
    "gedefense-core",
    "gedefense-contr",
    "snapd",
    "dockerd",
    "containerd",
    "runc",
];

/// Pooled web/PHP/DB service workers routinely perform rapid atomic cache
/// writes (`tempnam -> rename -> unlink`); skip `rename_storm` heuristics
/// while keeping high-entropy encryption detection (`entropy_burst`) active
/// and isolating any triggered worker without crashing its pool siblings.
pub(crate) const POOL_SERVICE_COMMS: &[&str] = &[
    "php-fpm",
    "php-fpm8.0",
    "php-fpm8.1",
    "php-fpm8.2",
    "php-fpm8.3",
    "php-fpm8.4",
    "php-fpm8.5",
    "php-fpm8.6",
    "lsphp",
    "lsphp81",
    "lsphp82",
    "lsphp83",
    "lsphp84",
    "httpd",
    "apache2",
    "nginx",
    "openlitespeed",
    "lshttpd",
    "mariadbd",
    "mysqld",
    "postgres",
    "redis-server",
    "memcached",
    "gitea",
];

#[derive(Default)]
pub(crate) struct RansomQueue {
    records: VecDeque<String>,
    dropped_local: u64,
    pub(crate) rejected: u64,
    pub(crate) stops_ok: u64,
    pub(crate) stops_failed: u64,
    pub(crate) stops_skipped: u64,
    pub(crate) last_event_ts: u64,
}

impl RansomQueue {
    pub(crate) fn push_record(&mut self, record: String) {
        if self.records.len() >= MAX_PENDING_RANSOM_RECORDS {
            self.records.pop_front();
            self.dropped_local = self.dropped_local.saturating_add(1);
        }
        self.records.push_back(record);
    }

    pub(crate) fn pop_batch(&mut self) -> (Vec<String>, u64) {
        let mut records = Vec::with_capacity(MAX_RANSOM_EVENTS_PER_RESPONSE);
        let mut total_bytes = 0usize;
        while records.len() < MAX_RANSOM_EVENTS_PER_RESPONSE {
            let Some(front) = self.records.front() else {
                break;
            };
            // Reserve room for "<dropped>|" prefix and comma separator inside 2048 B.
            let separator = usize::from(!records.is_empty());
            if total_bytes.saturating_add(separator).saturating_add(front.len())
                > MAX_RANSOM_PAYLOAD_BYTES.saturating_sub(32)
            {
                break;
            }
            if let Some(record) = self.records.pop_front() {
                total_bytes = total_bytes.saturating_add(separator).saturating_add(record.len());
                records.push(record);
            }
        }
        let dropped_local = self.dropped_local;
        self.dropped_local = 0;
        (records, dropped_local)
    }

    #[cfg(test)]
    pub(crate) fn pending_len(&self) -> usize {
        self.records.len()
    }
}

/// Ransomware sensor state owned by the core.
pub(crate) struct RansomCore {
    _events: Option<RingBuf<MapData>>,
    state: AyaArray<MapData, u64>,
    trusted_comm: AyaHashMap<MapData, [u8; 16], u8>,
    emitted: PerCpuArray<MapData, u64>,
    ring_drops: PerCpuArray<MapData, u64>,
    track_failures: PerCpuArray<MapData, u64>,
    queue: Arc<Mutex<RansomQueue>>,
    stop_watcher: Arc<AtomicBool>,
    watcher: Option<JoinHandle<()>>,
    epoch: u64,
    attached: bool,
    armed: bool,
    last_ring_drops: u64,
}

impl Drop for RansomCore {
    fn drop(&mut self) {
        self.stop_watcher.store(true, Ordering::Release);
        if let Some(handle) = self.watcher.take() {
            let _ = handle.join();
        }
    }
}

impl RansomCore {
    /// Takes the mandatory maps, populates the trusted-comm exemptions and
    /// attaches the three optional kprobes. Errors only for a missing/
    /// incompatible object, never for an unavailable kprobe.
    pub(crate) fn load(ebpf: &mut Ebpf) -> Result<Self, BoxError> {
        let events = RingBuf::try_from(
            ebpf.take_map("RANSOM_EVENTS").ok_or("RANSOM_EVENTS missing")?,
        )?;
        let state = AyaArray::try_from(
            ebpf.take_map("RANSOM_STATE").ok_or("RANSOM_STATE missing")?,
        )?;
        let trusted_comm = AyaHashMap::try_from(
            ebpf.take_map("RANSOM_TRUSTED_COMM")
                .ok_or("RANSOM_TRUSTED_COMM missing")?,
        )?;
        let emitted = PerCpuArray::try_from(
            ebpf.take_map("RANSOM_EVENTS_EMITTED")
                .ok_or("RANSOM_EVENTS_EMITTED missing")?,
        )?;
        let ring_drops = PerCpuArray::try_from(
            ebpf.take_map("RANSOM_RING_DROPS").ok_or("RANSOM_RING_DROPS missing")?,
        )?;
        let track_failures = PerCpuArray::try_from(
            ebpf.take_map("RANSOM_TRACK_FAILURES")
                .ok_or("RANSOM_TRACK_FAILURES missing")?,
        )?;
        let queue = Arc::new(Mutex::new(RansomQueue::default()));
        let stop_watcher = Arc::new(AtomicBool::new(false));
        let mut core = Self {
            _events: Some(events),
            state,
            trusted_comm,
            emitted,
            ring_drops,
            track_failures,
            queue,
            stop_watcher,
            watcher: None,
            epoch: random_epoch(),
            attached: false,
            armed: false,
            last_ring_drops: 0,
        };
        core.populate_trusted_comm()?;
        core.attach_kprobes(ebpf);
        // Fail-safe default for the endpoint P1 mitigation: arm as soon as at
        // least one kprobe is attached and launch the <= 10 ms ringbuf watcher
        // so non-trusted groups are frozen immediately via SIGSTOP without
        // waiting for the control plane's 100 ms IPC drain tick.
        let armed_at_load = core.attached;
        core.set_armed(armed_at_load)?;
        if core.attached {
            if let Some(ring) = core._events.take() {
                core.watcher = Some(spawn_watcher(
                    ring,
                    Arc::clone(&core.queue),
                    Arc::clone(&core.stop_watcher),
                )?);
            }
        }
        eprintln!(
            "GeDefense ransomware sensor: armed={} attached={} watcher={} trusted_comms={}",
            u8::from(armed_at_load),
            core.attached,
            u8::from(core.watcher.is_some()),
            TRUSTED_COMMS.len()
        );
        Ok(core)
    }

    fn insert_comm_tier(&mut self, comms: &[&str], tier: u8) -> Result<(), BoxError> {
        for name in comms {
            let bytes = name.as_bytes();
            if bytes.is_empty() || bytes.len() >= 16 {
                return Err("trusted comm entry exceeds the task-name ABI".into());
            }
            let mut key = [0u8; 16];
            key[..bytes.len()].copy_from_slice(bytes);
            self.trusted_comm.insert(&key, tier, 0)?;
        }
        Ok(())
    }

    fn populate_trusted_comm(&mut self) -> Result<(), BoxError> {
        self.insert_comm_tier(TRUSTED_COMMS, RANSOM_TRUST_FULL)?;
        self.insert_comm_tier(POOL_SERVICE_COMMS, RANSOM_TRUST_POOL_METADATA)?;
        Ok(())
    }

    /// Best-effort attach: a kernel without kprobe support keeps the rest of
    /// the core alive, and `RANSOM_STATUS` reports `attached=0` honestly.
    fn attach_kprobes(&mut self, ebpf: &mut Ebpf) {
        for (program_name, symbol) in RANSOM_KPROBES {
            let Some(program) = ebpf.program_mut(program_name) else {
                eprintln!("ransomware kprobe program {program_name} missing; sensor stays audit-only");
                continue;
            };
            let result = (|| -> Result<(), ProgramError> {
                let kprobe: &mut KProbe = program.try_into()?;
                kprobe.load()?;
                kprobe.attach(*symbol, 0)?;
                Ok(())
            })();
            match result {
                Ok(()) => self.attached = true,
                Err(error) => eprintln!(
                    "ransomware kprobe {symbol} unavailable ({error}); continuing without it"
                ),
            }
        }
    }

    /// Writes the armed state word (`epoch | armed | magic | abi`).
    fn set_armed(&mut self, armed: bool) -> Result<String, BoxError> {
        let word = encode_state_word(self.epoch, armed);
        self.state.set(0, word, 0)?;
        self.armed = armed;
        Ok(if armed { "armed" } else { "disarmed" }.to_owned())
    }

    /// §M2.2 IPC: `RANSOM_SET <0|1>`.
    pub(crate) fn set_armed_token(&mut self, token: &str) -> Result<String, BoxError> {
        match token {
            "0" => self.set_armed(false),
            "1" => self.set_armed(true),
            _ => Err("RANSOM_SET accepts 0 or 1".into()),
        }
    }

    /// Pops up to 8 pre-frozen 8-field records drained by the watcher thread.
    pub(crate) fn take_events(&mut self) -> Result<String, BoxError> {
        let (records, dropped_local, rejected) = {
            let mut queue = lock_queue(&self.queue);
            let (records, dropped_local) = queue.pop_batch();
            let rejected = std::mem::take(&mut queue.rejected);
            (records, dropped_local, rejected)
        };
        let ring_drops = Self::per_cpu_sum(&self.ring_drops)?;
        let dropped_kernel = ring_drops.saturating_sub(self.last_ring_drops);
        self.last_ring_drops = ring_drops;
        let dropped = dropped_kernel.saturating_add(dropped_local);
        if records.is_empty() {
            if dropped == 0 && rejected == 0 {
                return Ok("empty".to_owned());
            }
            return Ok(format!("{dropped}|"));
        }
        let payload = format!("{dropped}|{}", records.join(","));
        if payload.len() > MAX_RANSOM_PAYLOAD_BYTES {
            return Err("ransomware event batch exceeds the response payload budget".into());
        }
        Ok(payload)
    }

    /// Eight decimal health fields:
    /// `armed:attached:emitted:drops:stops_ok:stops_failed:stops_skipped:track_failures`.
    pub(crate) fn status(&self) -> Result<String, BoxError> {
        let emitted = Self::per_cpu_sum(&self.emitted)?;
        let drops = Self::per_cpu_sum(&self.ring_drops)?;
        let track_failures = Self::per_cpu_sum(&self.track_failures)?;
        let (stops_ok, stops_failed, stops_skipped) = {
            let queue = lock_queue(&self.queue);
            (queue.stops_ok, queue.stops_failed, queue.stops_skipped)
        };
        Ok(format!(
            "{}:{}:{}:{}:{}:{}:{}:{}",
            u8::from(self.armed),
            u8::from(self.attached),
            emitted,
            drops,
            stops_ok,
            stops_failed,
            stops_skipped,
            track_failures
        ))
    }

    fn per_cpu_sum(counter: &PerCpuArray<MapData, u64>) -> Result<u64, BoxError> {
        let values = counter.get(&0, 0)?;
        Ok(values
            .iter()
            .copied()
            .fold(0u64, |sum, value| sum.saturating_add(value)))
    }
}

fn lock_queue(queue: &Mutex<RansomQueue>) -> std::sync::MutexGuard<'_, RansomQueue> {
    queue.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn spawn_watcher(
    mut events: RingBuf<MapData>,
    queue: Arc<Mutex<RansomQueue>>,
    stop: Arc<AtomicBool>,
) -> Result<JoinHandle<()>, BoxError> {
    let handle = thread::Builder::new()
        .name("gedefense-ransom-watch".to_owned())
        .spawn(move || {
            let ring_fd = events.as_raw_fd();
            while !stop.load(Ordering::Acquire) {
                while let Some(item) = events.next() {
                    process_ring_item(&item, &queue);
                }
                if stop.load(Ordering::Acquire) {
                    break;
                }
                let mut pfd = libc::pollfd {
                    fd: ring_fd,
                    events: libc::POLLIN,
                    revents: 0,
                };
                // SAFETY: `pfd` points to a single initialized `pollfd` on the stack with `nfds = 1`.
                let ready = unsafe { libc::poll(&mut pfd, 1, RANSOM_POLL_TIMEOUT_MS) };
                if ready < 0
                    && std::io::Error::last_os_error().raw_os_error() != Some(libc::EINTR)
                {
                    thread::sleep(Duration::from_millis(RANSOM_POLL_TIMEOUT_MS as u64));
                }
            }
        })?;
    Ok(handle)
}

fn process_ring_item(raw: &[u8], queue: &Mutex<RansomQueue>) {
    let Some(event) = decode_ransom_event(raw) else {
        let mut guard = lock_queue(queue);
        guard.rejected = guard.rejected.saturating_add(1);
        return;
    };
    let rule = reason_token(event.signal);
    // Resolve the real PGID: the kernel event names the TGID only.
    let pgid = process_tree::process_group_of(event.tgid as i32).unwrap_or(0);
    if pgid <= 0 {
        let mut guard = lock_queue(queue);
        guard.stops_failed = guard.stops_failed.saturating_add(1);
        guard.last_event_ts = event.ts_ns;
        eprintln!(
            "GeDefense ransomware freeze skipped tgid={} (process vanished before PGID lookup)",
            event.tgid
        );
        return;
    }
    if pgid == 1 {
        let mut guard = lock_queue(queue);
        guard.stops_failed = guard.stops_failed.saturating_add(1);
        guard.last_event_ts = event.ts_ns;
        guard.push_record(encode_event_text(&event, pgid));
        eprintln!(
            "GeDefense ransomware freeze skipped tgid={} pgid=1 (init group protected)",
            event.tgid
        );
        return;
    }
    let pooled_worker = process_tree::is_service_pool_worker(event.tgid as i32)
        .unwrap_or(false);
    if pooled_worker && event.signal == RANSOM_SIGNAL_RENAME_STORM {
        let mut guard = lock_queue(queue);
        guard.stops_skipped = guard.stops_skipped.saturating_add(1);
        guard.last_event_ts = event.ts_ns;
        return;
    }
    // FP guard: never freeze or queue for tree-kill a group that contains a
    // trusted package/build/service comm or a protected core/init/systemd task.
    let exempt = match process_tree::process_group_has_trusted_comm(pgid, TRUSTED_COMMS) {
        Ok(true) => Ok(true),
        Ok(false) => process_tree::process_group_has_protected_target(pgid),
        Err(error) => Err(error),
    };
    match exempt {
        Ok(true) => {
            let mut guard = lock_queue(queue);
            guard.stops_skipped = guard.stops_skipped.saturating_add(1);
            guard.last_event_ts = event.ts_ns;
            eprintln!(
                "GeDefense ransomware freeze skipped exempt/protected group tgid={} pgid={pgid}",
                event.tgid
            );
            return;
        }
        Ok(false) => {
            // A pooled worker (e.g. compromised php-fpm child sharing the master PGID)
            // is frozen by PID/descendants alone so healthy pool siblings keep serving.
            let stop_result = if pooled_worker {
                process_tree::stop_process_descendants(event.tgid as i32, rule)
            } else {
                process_tree::stop_process_group(pgid, rule)
            };
            let mut guard = lock_queue(queue);
            match stop_result {
                Ok(()) => guard.stops_ok = guard.stops_ok.saturating_add(1),
                Err(error) => {
                    guard.stops_failed = guard.stops_failed.saturating_add(1);
                    eprintln!(
                        "GeDefense ransomware freeze failed tgid={} pgid={pgid} error={error}",
                        event.tgid
                    );
                }
            }
            guard.last_event_ts = event.ts_ns;
            guard.push_record(encode_event_text(&event, pgid));
        }
        Err(error) => {
            let mut guard = lock_queue(queue);
            guard.stops_failed = guard.stops_failed.saturating_add(1);
            guard.last_event_ts = event.ts_ns;
            guard.push_record(encode_event_text(&event, pgid));
            eprintln!(
                "GeDefense ransomware freeze skipped tgid={} pgid={pgid}: exemption check failed: {error}",
                event.tgid
            );
        }
    }
}

/// Packs the `RANSOM_STATE` word (32-bit epoch | armed | magic | abi).
pub(crate) fn encode_state_word(epoch: u64, armed: bool) -> u64 {
    (epoch & u64::from(u32::MAX))
        | (u64::from(armed) << RANSOM_STATE_ARMED_SHIFT)
        | (u64::from(RANSOM_STATE_MAGIC) << RANSOM_STATE_MAGIC_SHIFT)
        | (u64::from(RANSOM_STATE_ABI) << RANSOM_STATE_ABI_SHIFT)
}

fn random_epoch() -> u64 {
    use std::io::Read as _;
    let mut bytes = [0u8; 8];
    match std::fs::File::open("/dev/urandom") {
        Ok(mut file) => {
            let _ = file.read_exact(&mut bytes);
            u64::from_ne_bytes(bytes) & u64::from(u32::MAX)
        }
        Err(_) => 0,
    }
}

/// Control-plane closed wire vocabulary (`control/coreipc_ransom.go`).
pub(crate) fn wire_reason(signal: u8) -> &'static str {
    match signal {
        RANSOM_SIGNAL_RENAME_STORM => "rename_storm",
        _ => "entropy_burst",
    }
}

/// `XDR.RANSOM_*` rule token for the freeze/kill evidence contract.
pub(crate) fn reason_token(signal: u8) -> &'static str {
    match signal {
        RANSOM_SIGNAL_RENAME_STORM => "XDR.RANSOM_RENAME_STORM",
        _ => "XDR.RANSOM_ENTROPY_BURST",
    }
}

/// Encodes the 8-field control-plane text record
/// (`tgid:pgid:uid:signal:reason:ts_ns:count:comm_hex`).
pub(crate) fn encode_event_text(event: &RansomEvent, pgid: i32) -> String {
    let comm_end = event.comm.iter().position(|byte| *byte == 0).unwrap_or(15);
    format!(
        "{}:{}:{}:{}:{}:{}:{}:{}",
        event.tgid,
        pgid,
        event.uid,
        event.signal,
        wire_reason(event.signal),
        event.ts_ns,
        event.count,
        hex::encode(&event.comm[..comm_end]),
    )
}
