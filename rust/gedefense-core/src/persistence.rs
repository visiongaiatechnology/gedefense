//! V6.3.0 AP-5 — linker/PAM/sshd/systemd persistence integrity and desktop
//! peripheral/credential sensors (`PERSIST_GUARD_*`).
//!
//! The privileged core owns the userspace half of the AP-5 observer:
//!
//! - it takes the mandatory `PERSIST_GUARD_*` maps, publishes the BTF/tracefs
//!   resolved `PERSIST_GUARD_OFFSETS` table, populates the watched path and
//!   protected-executable inode maps, attaches the LSM/tracepoint hook ladder
//!   and arms the state word,
//! - it resolves the **path contract** at load and on `PERSIST_BASELINE`:
//!   linker (`/etc/ld.so.preload`, `/etc/ld.so.conf*`, `/lib*/tls`,
//!   `ld-linux*.so*`), PAM (`/etc/pam.d`, `/lib*/security/pam_*.so`), systemd
//!   generators/drop-ins, udev rules, `authorized_keys`, `/etc/ssh/sshrc`,
//!   shell profiles, user secret stores and desktop peripherals,
//! - it builds a **package-database ownership index** (Debian/Ubuntu
//!   `/var/lib/dpkg/info/*.list`, Arch `/var/lib/pacman/local/*/files`) without
//!   ever executing `dpkg`/`rpm`/`ldd` and uses it to drop package-owned
//!   libraries from the `mmap_file` evidence,
//! - it captures and re-verifies SHA-256 content baselines of the watched exact
//!   files (bounded; in memory only) and injects `KIND_DRIFT` records into the
//!   same bounded queue as the kernel records,
//! - it samples `/run/systemd/sessions`/`/run/systemd/seats` for an honest
//!   session correlation and reports `idlehint=unavailable` (logind IdleHint is
//!   a D-Bus property, not a file; the control plane must label the correlation
//!   `TEMPORAL` at best, never `OBSERVED`),
//! - it drains `PERSIST_GUARD_EVENTS` in bounded batches.
//!
//! Everything here is Observe-only: no response action, no kill, no change to
//! the existing kill gate. A missing hook or BTF table is reported honestly in
//! the status mask, never as enforcement.
//!
//! Public signatures are fixed by `main.rs`:
//! `load(ebpf, btf, bpf_lsm_active)`, `poll(now_ms)`,
//! `set_enabled_token(token)`, `take_events()`, `baseline()`, `status()`.

mod paths;
mod watch;
mod attach;
mod btf;
mod tracefs;
mod pkgdb;
mod sessions;
mod baseline;
mod drain;

use self::paths::*;
use self::watch::*;
use self::attach::*;
use self::btf::*;
use self::tracefs::*;
use self::pkgdb::*;
use self::sessions::*;
use self::baseline::*;
use self::drain::*;
use aya::{
    maps::{Array as AyaArray, HashMap as AyaHashMap, MapData, PerCpuArray, RingBuf},
    programs::{Lsm, TracePoint},
    Btf, Ebpf,
};
use gedefense_common::{
    decode_persistence_event, encode_persistence_event, persistence_identity_key,
    persistence_path_value, persistence_state_word, PersistenceEvent, PERSIST_ACTION_AUDIT,
    PERSIST_CLASS_AUTHORIZED_KEYS, PERSIST_CLASS_DEVICE_CAMERA, PERSIST_CLASS_DEVICE_CAPTURE_SOCKET,
    PERSIST_CLASS_DEVICE_EVDEV, PERSIST_CLASS_DEVICE_MIC, PERSIST_CLASS_LD_CONF,
    PERSIST_CLASS_LD_PRELOAD, PERSIST_CLASS_LD_SO, PERSIST_CLASS_PAM,
    PERSIST_CLASS_SECRET_BROWSER, PERSIST_CLASS_SECRET_CLOUD, PERSIST_CLASS_SECRET_GNUPG,
    PERSIST_CLASS_SECRET_KEYRING, PERSIST_CLASS_SECRET_SSH, PERSIST_CLASS_SHELL_PROFILE,
    PERSIST_CLASS_SSHRC, PERSIST_CLASS_SYSTEMD_DROPIN, PERSIST_CLASS_SYSTEMD_GENERATOR,
    PERSIST_CLASS_TLS, PERSIST_CLASS_UDEV, PERSIST_DETAIL_SESSION_ACTIVE,
    PERSIST_DETAIL_SESSION_KNOWN, PERSIST_DRIFT_APPEARED, PERSIST_DRIFT_CONTENT,
    PERSIST_DRIFT_MISSING, PERSIST_DRIFT_REPLACED, PERSIST_EVENT_WIRE_BYTES,
    PERSIST_EXEC_MAP_ENTRIES, PERSIST_KIND_BASELINE, PERSIST_KIND_DRIFT,
    PERSIST_KIND_LIBRARY_MMAP, PERSIST_KIND_PERIPHERAL_OPEN, PERSIST_MAX_DRAIN_PAYLOAD_BYTES,
    PERSIST_MAX_EVENTS_PER_DRAIN, PERSIST_MAX_STRUCT_SIZE, PERSIST_MAX_TRACEPOINT_BYTES,
    PERSIST_OFF_ABI, PERSIST_OFF_DENTRY_D_INODE, PERSIST_OFF_DENTRY_D_PARENT, PERSIST_OFF_DENTRY_SIZE,
    PERSIST_OFF_FILE_F_FLAGS, PERSIST_OFF_FILE_F_INODE, PERSIST_OFF_FILE_F_PATH_DENTRY,
    PERSIST_OFF_FILE_OPEN_NARGS, PERSIST_OFF_FILE_OPEN_PREV, PERSIST_FILE_OPEN_NARGS_EXPECTED, PERSIST_OFF_FILE_SIZE,
    PERSIST_OFF_INODE_I_INO, PERSIST_OFF_INODE_I_MODE, PERSIST_OFF_INODE_I_SB,
    PERSIST_OFF_INODE_SIZE, PERSIST_OFF_MAGIC, PERSIST_OFF_MM_EXE_FILE, PERSIST_OFF_MM_SIZE,
    PERSIST_OFF_MMAP_FILE_ARG, PERSIST_OFF_MMAP_NARGS, PERSIST_OFF_MMAP_PREV,
    PERSIST_OFF_MMAP_PROT_ARG, PERSIST_OFF_PTRACE_CHILD_ARG, PERSIST_OFF_PTRACE_MODE_ARG,
    PERSIST_OFF_PTRACE_NARGS, PERSIST_OFF_PTRACE_PREV, PERSIST_OFF_READV_PID,
    PERSIST_OFF_READV_SIZE, PERSIST_OFF_READV_TARGET, PERSIST_OFF_SUPER_S_DEV,
    PERSIST_OFF_SUPER_SIZE, PERSIST_OFF_TASK_MM, PERSIST_OFF_TASK_PID, PERSIST_OFF_TASK_SIZE,
    PERSIST_OFF_TASK_TGID, PERSIST_OFF_WRITEV_PID, PERSIST_OFF_WRITEV_SIZE,
    PERSIST_OFF_WRITEV_TARGET, PERSIST_OFFSETS_ABI, PERSIST_OFFSETS_MAGIC,
    PERSIST_OFFSETS_TABLE_LEN, PERSIST_PATH_MAP_ENTRIES, PERSIST_PTRACE_CHILD_ARG,
    PERSIST_PTRACE_MODE_ARG, PERSIST_PTRACE_NARGS_EXPECTED,
};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    error::Error,
    ffi::CString,
    fs::{self, File},
    io::Read as _,
    os::{
        fd::{AsRawFd as _, FromRawFd, RawFd},
        unix::{ffi::OsStrExt, fs::MetadataExt},
    },
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

type BoxError = Box<dyn Error + Send + Sync + 'static>;

/// Index of the single armed state word in `PERSIST_GUARD_STATE`.
const PERSIST_STATE_INDEX: u32 = 0;
/// `openat2(2)` resolve flags: never follow a symlink or magic link.
const RESOLVE_NO_MAGICLINKS: u64 = 0x02;
const RESOLVE_NO_SYMLINKS: u64 = 0x04;
const _: () = assert!(PERSIST_EVENT_WIRE_BYTES == 64);
const _: () = assert!(PERSIST_MAX_EVENTS_PER_DRAIN >= 1);
const _: () = assert!(PERSIST_MAX_DRAIN_PAYLOAD_BYTES > 320);

/// The one documented "no real source" answer for `idlehint=` in the status:
/// logind's `IdleHint` is a D-Bus property, not a file, and the core does not
/// speak D-Bus. The control plane must label peripheral findings `TEMPORAL`
/// (session inactive observed) or `NONE`, never `OBSERVED`.
pub(crate) const PERSIST_IDLEHINT_UNAVAILABLE: &str = "unavailable";

fn openat2_no_symlinks(path: &Path, flags: i32) -> std::io::Result<File> {
    let path_c = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| std::io::Error::from_raw_os_error(libc::EINVAL))?;
    let how = OpenHow {
        flags: flags as u64,
        mode: 0,
        resolve: RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS,
    };
    // SAFETY: `path_c` and `how` are valid for the duration of the syscall and
    // `size_of::<OpenHow>()` is the kernel-documented structure length.
    let descriptor = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            libc::AT_FDCWD,
            path_c.as_ptr(),
            &how,
            std::mem::size_of::<OpenHow>(),
        )
    } as RawFd;
    if descriptor < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: the syscall returned a fresh owned descriptor.
    Ok(unsafe { File::from_raw_fd(descriptor) })
}





// ---------------------------------------------------------------------------
// Core-side owner of the persistence/peripheral maps
// ---------------------------------------------------------------------------

pub(crate) struct PersistenceCore {
    events: RingBuf<MapData>,
    state: AyaArray<MapData, u64>,
    paths_map: AyaHashMap<MapData, [u8; 16], u64>,
    execs_map: AyaHashMap<MapData, [u8; 16], u8>,
    offsets_map: AyaArray<MapData, u32>,
    emitted: PerCpuArray<MapData, u64>,
    ring_drops: PerCpuArray<MapData, u64>,
    read_failures: PerCpuArray<MapData, u64>,
    device_events: PerCpuArray<MapData, u64>,
    secret_events: PerCpuArray<MapData, u64>,
    mmap_events: PerCpuArray<MapData, u64>,
    epoch: u64,
    armed: bool,
    hook_file_open: bool,
    hook_mmap: bool,
    hook_ptrace: bool,
    hook_readv: bool,
    hook_writev: bool,
    identity_offsets_ok: bool,
    readv_offsets_ok: bool,
    writev_offsets_ok: bool,
    paths: BTreeMap<[u8; 16], u64>,
    execs: BTreeMap<[u8; 16], u8>,
    device_entries: u32,
    secret_entries: u32,
    skipped_paths: u32,
    capacity_skips: u32,
    baseline_candidates: Vec<(PathBuf, u8)>,
    baseline_skips: u32,
    pkgdb: PackageIndex,
    baseline: BaselineSet,
    baseline_at_ms: u64,
    last_verify_ms: u64,
    drifted_total: u64,
    drift_dedup: BTreeMap<(u8, u32, u64), u64>,
    verify_errors: u64,
    pending: VecDeque<[u8; 64]>,
    pending_dropped: u64,
    last_ring_drops: u64,
    rejected: u64,
    sessions: SessionSnapshot,
    last_sessions_ms: u64,
    last_pkgdb_ms: u64,
    tolerated_library_mmaps: u64,
}

impl PersistenceCore {
    /// Takes the mandatory `PERSIST_GUARD_*` maps, resolves and publishes the
    /// BTF/tracefs offsets, populates the path/executable contracts, attaches
    /// the hook ladder, captures the initial content baseline and arms the
    /// guard. A stale object (missing map) fails loudly; an unsupported hook or
    /// unavailable BTF traceable degrades the status instead of claiming
    /// enforcement.
    pub(crate) fn load(
        ebpf: &mut Ebpf,
        btf: Option<&Btf>,
        bpf_lsm_active: bool,
    ) -> Result<Self, BoxError> {
        let events = RingBuf::try_from(
            ebpf.take_map(&crate::chameleon::map_name("PERSIST_GUARD_EVENTS"))
                .ok_or("PERSIST_GUARD_EVENTS missing")?,
        )?;
        let state = AyaArray::try_from(
            ebpf.take_map(&crate::chameleon::map_name("PERSIST_GUARD_STATE"))
                .ok_or("PERSIST_GUARD_STATE missing")?,
        )?;
        let paths_map = AyaHashMap::try_from(
            ebpf.take_map(&crate::chameleon::map_name("PERSIST_GUARD_PATHS"))
                .ok_or("PERSIST_GUARD_PATHS missing")?,
        )?;
        let execs_map = AyaHashMap::try_from(
            ebpf.take_map(&crate::chameleon::map_name("PERSIST_GUARD_EXECS"))
                .ok_or("PERSIST_GUARD_EXECS missing")?,
        )?;
        let offsets_map = AyaArray::try_from(
            ebpf.take_map(&crate::chameleon::map_name("PERSIST_GUARD_OFFSETS"))
                .ok_or("PERSIST_GUARD_OFFSETS missing")?,
        )?;
        let emitted = PerCpuArray::try_from(
            ebpf.take_map(&crate::chameleon::map_name("PERSIST_GUARD_EVENTS_EMITTED"))
                .ok_or("PERSIST_GUARD_EVENTS_EMITTED missing")?,
        )?;
        let ring_drops = PerCpuArray::try_from(
            ebpf.take_map(&crate::chameleon::map_name("PERSIST_GUARD_RING_DROPS"))
                .ok_or("PERSIST_GUARD_RING_DROPS missing")?,
        )?;
        let read_failures = PerCpuArray::try_from(
            ebpf.take_map(&crate::chameleon::map_name("PERSIST_GUARD_READ_FAILURES"))
                .ok_or("PERSIST_GUARD_READ_FAILURES missing")?,
        )?;
        let device_events = PerCpuArray::try_from(
            ebpf.take_map(&crate::chameleon::map_name("PERSIST_GUARD_DEVICE_EVENTS"))
                .ok_or("PERSIST_GUARD_DEVICE_EVENTS missing")?,
        )?;
        let secret_events = PerCpuArray::try_from(
            ebpf.take_map(&crate::chameleon::map_name("PERSIST_GUARD_SECRET_EVENTS"))
                .ok_or("PERSIST_GUARD_SECRET_EVENTS missing")?,
        )?;
        let mmap_events = PerCpuArray::try_from(
            ebpf.take_map(&crate::chameleon::map_name("PERSIST_GUARD_MMAP_EVENTS"))
                .ok_or("PERSIST_GUARD_MMAP_EVENTS missing")?,
        )?;
        let mut core = Self {
            events,
            state,
            paths_map,
            execs_map,
            offsets_map,
            emitted,
            ring_drops,
            read_failures,
            device_events,
            secret_events,
            mmap_events,
            epoch: random_epoch(),
            armed: false,
            hook_file_open: false,
            hook_mmap: false,
            hook_ptrace: false,
            hook_readv: false,
            hook_writev: false,
            identity_offsets_ok: false,
            readv_offsets_ok: false,
            writev_offsets_ok: false,
            paths: BTreeMap::new(),
            execs: BTreeMap::new(),
            device_entries: 0,
            secret_entries: 0,
            skipped_paths: 0,
            capacity_skips: 0,
            baseline_candidates: Vec::new(),
            baseline_skips: 0,
            pkgdb: PackageIndex::unsupported(),
            baseline: BaselineSet::default(),
            baseline_at_ms: 0,
            last_verify_ms: 0,
            drifted_total: 0,
            drift_dedup: BTreeMap::new(),
            verify_errors: 0,
            pending: VecDeque::new(),
            pending_dropped: 0,
            last_ring_drops: 0,
            rejected: 0,
            sessions: SessionSnapshot::default(),
            last_sessions_ms: 0,
            last_pkgdb_ms: 0,
            tolerated_library_mmaps: 0,
        };
        core.resolve_and_publish_offsets();
        core.populate_path_contract();
        core.populate_executables();
        core.pkgdb = PackageIndex::load();
        core.last_pkgdb_ms = unix_millis_now();
        core.sessions = read_session_snapshot(Path::new("/run/systemd/sessions"), Path::new("/run/systemd/seats"));
        core.attach_hooks(ebpf, btf, bpf_lsm_active);
        core.capture_initial_baseline();
        if core.can_arm() {
            core.write_state(true)?;
            core.armed = true;
        } else {
            eprintln!(
                "GeDefense persistence guard not armed: no usable sensor offsets/hooks (btf={} lsm={}); staying fail-open with no enforcement claim",
                u8::from(core.identity_offsets_ok),
                u8::from(bpf_lsm_active)
            );
        }
        eprintln!(
            "GeDefense persistence guard: enabled={} attached={:#x} paths={} execs={} devices={} secrets={} pkgdb={} roots={} sessions={} drift={} verify_errors={} tolerated_mmap={} counters={:?}",
            u8::from(core.armed),
            core.attached_mask(),
            core.paths.len(),
            core.execs.len(),
            core.device_entries,
            core.secret_entries,
            core.pkgdb.format,
            core.baseline.roots.len(),
            core.sessions.to_status_value(),
            core.drifted_total,
            core.verify_errors,
            core.tolerated_library_mmaps,
            core.counter_snapshot()
        );
        Ok(core)
    }

    /// `PERSIST_GUARD_EVENTS`: `empty` or `<dropped>|<record>[,<record>...]`.
    /// Drains the bounded userspace drift queue first, then the kernel ring.
    pub(crate) fn take_events(&mut self) -> Result<String, BoxError> {
        let mut records: Vec<String> = Vec::with_capacity(PERSIST_MAX_EVENTS_PER_DRAIN);
        let mut payload_bytes = 0usize;
        let rejected_before = self.rejected;

        while records.len() < PERSIST_MAX_EVENTS_PER_DRAIN {
            let Some(raw) = self.pending.pop_front() else {
                break;
            };
            let Some(event) = decode_persistence_event(&raw) else {
                self.rejected = self.rejected.saturating_add(1);
                continue;
            };
            if !Self::push_text_record(&mut records, &mut payload_bytes, &event) {
                self.pending.push_front(raw);
                break;
            }
        }
        while records.len() < PERSIST_MAX_EVENTS_PER_DRAIN {
            // Scope the ring item: the decoded record is owned, so the mutable
            // borrow of `self.events` ends before `self.accept_kernel_event`.
            let decoded = {
                let Some(item) = self.events.next() else {
                    break;
                };
                decode_persistence_event(&item)
            };
            let Some(mut event) = decoded else {
                self.rejected = self.rejected.saturating_add(1);
                continue;
            };
            if !self.accept_kernel_event(&mut event) {
                continue;
            }
            if !Self::push_text_record(&mut records, &mut payload_bytes, &event) {
                break;
            }
        }
        if self.rejected > rejected_before {
            eprintln!(
                "persistence guard rejected {} malformed record(s) in this drain (total {})",
                self.rejected.saturating_sub(rejected_before),
                self.rejected
            );
        }
        let ring_drops = Self::per_cpu_sum(&self.ring_drops)?;
        let kernel_dropped = ring_drops.saturating_sub(self.last_ring_drops);
        self.last_ring_drops = ring_drops;
        let queue_dropped = std::mem::take(&mut self.pending_dropped);
        let dropped = kernel_dropped.saturating_add(queue_dropped);
        if records.is_empty() {
            if dropped == 0 && self.rejected == 0 {
                return Ok("empty".to_owned());
            }
            return Ok(format!("{dropped}|"));
        }
        let payload = format!("{dropped}|{}", records.join(","));
        if payload.len() > PERSIST_MAX_DRAIN_PAYLOAD_BYTES {
            return Err("persistence event batch exceeds the response payload budget".into());
        }
        Ok(payload)
    }

    /// `PERSIST_BASELINE`: re-resolve the contract, reload the package index,
    /// re-verify the previous content baseline (emitting drift evidence) and
    /// capture a fresh baseline. Response:
    /// `roots=..:verified=..:drifted=..:at_ms=..`.
    pub(crate) fn baseline(&mut self) -> Result<String, BoxError> {
        let now_ms = unix_millis_now();
        let was_armed = self.armed;
        if was_armed {
            // Re-populating the maps is a short, explicit maintenance window:
            // disarm so no kernel event is matched against a half-built map.
            self.write_state(false)?;
        }
        self.populate_path_contract();
        self.populate_executables();
        self.pkgdb = PackageIndex::load();
        self.last_pkgdb_ms = now_ms;
        self.sessions = read_session_snapshot(Path::new("/run/systemd/sessions"), Path::new("/run/systemd/seats"));
        let (notices, counters) = self.baseline.verify();
        let drifted = counters.drifted;
        for notice in notices {
            self.process_drift_notice(notice, now_ms);
        }
        let candidates = std::mem::take(&mut self.baseline_candidates);
        self.baseline = BaselineSet::capture(&candidates, now_ms);
        self.baseline_candidates = candidates;
        self.baseline_at_ms = now_ms;
        self.last_verify_ms = now_ms;
        self.verify_errors = self.verify_errors.saturating_add(counters.read_failures);
        self.queue_baseline_marker(self.baseline.roots.len(), now_ms);
        if was_armed && self.can_arm() {
            self.write_state(true)?;
        }
        Ok(format!(
            "roots={}:verified={}:drifted={}:at_ms={}",
            self.baseline.roots.len(),
            counters.checked,
            drifted,
            now_ms
        ))
    }

}

#[cfg(test)]
mod tests;
