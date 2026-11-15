//! Cell registry, state machine, cgroup-v2 control, TTL timer and burn ledger
//! (POINT2 spec §4.5/§4.6/§6). The helper owns all cgroups; Go never writes
//! cgroupfs. Burn is idempotent and generation/UUID-bound; the ledger is
//! append-only (`0x1f`-separated `k=v`, fsync, 1 MiB rotation).
use std::collections::BTreeMap;
use std::fs;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use crate::config;
use crate::export::{self, ExportTarget, SealedExport};
use crate::types::*;
pub const CGROUP_PREFIX: &str = "parser-";
pub const LEDGER_MAX_BYTES: u64 = 1024 * 1024;
const BURN_RETAINED: usize = 8;
/// Wall + monotonic sample (fake-clock friendly; TTL is monotonic-authoritative).
#[derive(Clone, Copy, Debug, Default)]
pub struct TimeSample { pub mono_ms: u64, pub wall_s: u64 }
impl TimeSample {
    pub fn now() -> TimeSample { TimeSample { mono_ms: mono_ms().unwrap_or(0), wall_s: wall_s() } }
    pub fn at(mono_ms: u64, wall_s: u64) -> TimeSample { TimeSample { mono_ms, wall_s } }
}
/// Monotonic milliseconds since boot (`CLOCK_MONOTONIC`).
pub fn mono_ms() -> Result<u64, ErrorCode> {
    let mut ts: libc::timespec = unsafe { std::mem::zeroed() };
    if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts) } != 0 { return Err(ErrorCode::Internal); }
    Ok((ts.tv_sec as u64) * 1000 + (ts.tv_nsec as u64) / 1_000_000)
}
/// Unix seconds (`CLOCK_REALTIME`), saturating to 0 on pre-epoch clocks.
pub fn wall_s() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}
/// Single timerfd wakeup source with absolute monotonic deadlines.
pub struct MonotonicTimer { fd: OwnedFd }
impl MonotonicTimer {
    pub fn new() -> Result<Self, ErrorCode> {
        // SAFETY: timerfd_create(2) returns a new, exclusively owned descriptor.
        let raw = unsafe { libc::timerfd_create(libc::CLOCK_MONOTONIC, libc::TFD_NONBLOCK | libc::TFD_CLOEXEC) };
        if raw < 0 { return Err(ErrorCode::Internal); }
        Ok(MonotonicTimer { fd: unsafe { OwnedFd::from_raw_fd(raw) } })
    }
    pub fn as_raw_fd(&self) -> RawFd { self.fd.as_raw_fd() }
    pub fn arm(&self, deadline_mono_ms: u64) -> Result<(), ErrorCode> {
        let mut spec: libc::itimerspec = unsafe { std::mem::zeroed() };
        spec.it_value.tv_sec = (deadline_mono_ms / 1000) as libc::time_t;
        spec.it_value.tv_nsec = ((deadline_mono_ms % 1000) * 1_000_000) as libc::c_long;
        // SAFETY: valid itimerspec for our own timerfd.
        let rc = unsafe { libc::timerfd_settime(self.fd.as_raw_fd(), libc::TFD_TIMER_ABSTIME, &spec, std::ptr::null_mut()) };
        if rc != 0 { Err(ErrorCode::Internal) } else { Ok(()) }
    }
    pub fn disarm(&self) -> Result<(), ErrorCode> { self.arm(0) }
    pub fn consume(&self) -> u64 {
        let mut count: u64 = 0;
        // SAFETY: 8-byte read into a local from our own timerfd; EAGAIN = not ready.
        let n = unsafe { libc::read(self.fd.as_raw_fd(), &mut count as *mut u64 as *mut libc::c_void, 8) };
        if n == 8 { count } else { 0 }
    }
}
fn cg_write(dir: &Path, file: &str, value: &str) -> Result<(), ErrorCode> {
    fs::write(dir.join(file), value).map_err(|_| ErrorCode::Internal)
}
fn cg_read(dir: &Path, file: &str) -> Result<String, ErrorCode> {
    fs::read_to_string(dir.join(file)).map(|s| s.trim().to_string()).map_err(|_| ErrorCode::Internal)
}
fn cg_id(dir: &Path) -> Result<u64, ErrorCode> { Ok(fs::symlink_metadata(dir).map_err(|_| ErrorCode::Internal)?.ino()) }
/// Append-only burn ledger (own bounded text format, one line per event).
pub struct BurnLedger { path: PathBuf }
impl BurnLedger {
    pub fn open(path: PathBuf) -> Result<Self, ErrorCode> {
        if let Some(parent) = path.parent() { fs::create_dir_all(parent).map_err(|_| ErrorCode::Internal)?; }
        let ledger = BurnLedger { path };
        if let Ok(md) = fs::metadata(&ledger.path) {
            if !md.is_file() { return Err(ErrorCode::Internal); }
        }
        Ok(ledger)
    }
    pub fn append(&mut self, entry: &BurnLedgerEntry) -> Result<(), ErrorCode> {
        use std::io::Write;
        let line = entry.to_line();
        let len = fs::metadata(&self.path).map(|m| m.len()).unwrap_or(0);
        if len + line.len() as u64 > LEDGER_MAX_BYTES {
            let name = self.path.file_name().and_then(|n| n.to_str()).ok_or(ErrorCode::Internal)?;
            let rotated = self.path.with_file_name(format!("{}.1", name));
            let _ = fs::remove_file(&rotated);
            if self.path.exists() { fs::rename(&self.path, &rotated).map_err(|_| ErrorCode::Internal)?; }
        }
        let mut f = fs::OpenOptions::new().create(true).append(true).mode(0o640).open(&self.path).map_err(|_| ErrorCode::Internal)?;
        f.write_all(line.as_bytes()).map_err(|_| ErrorCode::Internal)?;
        f.sync_all().map_err(|_| ErrorCode::Internal)
    }
}
pub struct CellEntry {
    pub record: CellRecord,
    pub handle: CellHandle,
    pub input_path: PathBuf,
    pub export: Option<ExportTarget>,
    pub sealed: Option<SealedExport>,
    pub deadline_mono_ms: u64,
    pub frozen: bool,
    pub max_export_bytes: u64,
    pub sealed_seq: u64,
}
/// `CELL_CREATE` request values (syntax-checked by `protocol`).
#[derive(Clone, Debug)]
pub struct CreateRequest {
    pub profile_id: String,
    pub input_token: String,
    pub input_sha256: String,
    pub input_size: u64,
    pub ttl_seconds: u64,
    pub max_rss_bytes: u64,
    pub max_pids: u64,
}
pub struct CellRegistry {
    entries: BTreeMap<String, CellEntry>,
    max_cells: usize,
    cgroup_root: PathBuf,
    cell_root: PathBuf,
    ledger: BurnLedger,
    started_at: u64,
    burned_total: u64,
    last_error: Option<String>,
    generation: u64,
    next_sealed_seq: u64,
    gedefense_gid: Option<u32>,
    fake_cgroup: bool,
}
impl CellRegistry {
    pub fn new(cgroup_root: PathBuf, cell_root: PathBuf, ledger_path: PathBuf, max_cells: usize,
        gedefense_gid: Option<u32>) -> Result<Self, ErrorCode> {
        let md = fs::symlink_metadata(&cgroup_root).map_err(|_| ErrorCode::SandboxUnavailable)?;
        if !md.is_dir() || md.file_type().is_symlink() { return Err(ErrorCode::SandboxUnavailable); }
        fs::create_dir_all(&cell_root).map_err(|_| ErrorCode::Internal)?;
        Ok(CellRegistry { entries: BTreeMap::new(), max_cells: max_cells.clamp(1, MAX_ACTIVE_CELLS),
            cgroup_root, cell_root, ledger: BurnLedger::open(ledger_path)?, started_at: wall_s(),
            burned_total: 0, last_error: None, generation: 1, next_sealed_seq: 1,
            gedefense_gid, fake_cgroup: false })
    }
    pub fn active_count(&self) -> usize { self.entries.values().filter(|e| !e.record.state.is_terminal()).count() }
    pub fn max_cells(&self) -> usize { self.max_cells }
    pub fn list(&self) -> Vec<CellRecord> {
        let mut rows: Vec<CellRecord> = self.entries.values().map(|e| e.record.clone()).collect();
        rows.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        rows.truncate(self.max_cells + BURN_RETAINED);
        rows
    }
    pub fn health(&self) -> Health {
        match &self.last_error {
            Some(err) => Health::degraded(err, self.burned_total, self.started_at),
            None => Health::healthy(self.active_count(), self.burned_total, self.started_at),
        }
    }
    pub fn next_deadline_mono(&self) -> Option<u64> {
        self.entries.values().filter(|e| !e.record.state.is_terminal()).map(|e| e.deadline_mono_ms).min()
    }
    /// Create + spawn one cell: requested → spawned → isolated (isolation is
    /// only attributed when `sandbox::spawn` succeeded; no blind claim).
    pub fn create(&mut self, profiles: &[Profile], req: &CreateRequest, staging_inputs: &Path,
        staging_exports: &Path, gedefense_uid: u32, now: TimeSample) -> Result<CellRecord, ErrorCode> {
        if self.active_count() >= self.max_cells { return Err(ErrorCode::CellLimit); }
        let profile = config::find_profile(profiles, &req.profile_id)?.clone();
        let input = InputMeta { token: req.input_token.clone(), sha256: req.input_sha256.clone(), size: req.input_size };
        let input_path = config::validate_input(staging_inputs, &input, gedefense_uid, profile.max_input_bytes)?;
        let limits = Limits::clamp_for(&profile, req.ttl_seconds, req.max_rss_bytes, req.max_pids);
        let uuid = self.new_uuid()?;
        let generation = self.next_generation();
        let cgroup_path = self.cgroup_root.join(format!("{}{}", CGROUP_PREFIX, uuid));
        self.cg_create(&cgroup_path, &limits)?;
        let export_target = match export::ExportTarget::open(staging_exports, &uuid, self.gedefense_gid.map(|gid| (0, gid))) {
            Ok(t) => t,
            Err(code) => { self.cg_remove(&cgroup_path); return Err(code); }
        };
        let root_dir = self.cell_root.join(&uuid);
        fs::create_dir_all(&root_dir).map_err(|_| ErrorCode::Internal)?;
        let spec = CellSpec {
            uuid: uuid.clone(), generation, profile_id: profile.id.clone(), binary: profile.binary.clone(),
            binary_sha256: profile.sha256.clone(), argv: profile.argv.clone(), env_allow: profile.env_allow.clone(),
            wayland: profile.wayland, pipewire: profile.pipewire, input_path: input_path.clone(),
            input_size: req.input_size, input_sha256: req.input_sha256.clone(), input_token: req.input_token.clone(),
            export_fd: export_target.fd(), export_path: export_target.path().to_path_buf(), limits,
            uid: DEFAULT_CELL_UID, gid: DEFAULT_CELL_GID, root_dir: root_dir.clone(),
        };
        let handle = match crate::sandbox::spawn(&spec) {
            Ok(h) => h,
            Err(code) => { self.cg_remove(&cgroup_path); let _ = fs::remove_file(export_target.path()); let _ = fs::remove_dir_all(&root_dir); return Err(code); }
        };
        let cgroup_id = match self.cg_attach(&cgroup_path, handle.pid) {
            Ok(id) => id,
            Err(code) => { let _ = crate::sandbox::kill(&handle); self.cg_remove(&cgroup_path); let _ = fs::remove_file(export_target.path()); return Err(code); }
        };
        let expires_at = now.wall_s.saturating_add(limits.ttl_seconds);
        let mut handle = handle;
        handle.cgroup_id = cgroup_id; handle.cgroup_path = cgroup_path.clone(); handle.export_fd = export_target.fd();
        handle.export_path = export_target.path().to_path_buf(); handle.started_at = now.wall_s; handle.expires_at = expires_at;
        let record = CellRecord { uuid: uuid.clone(), generation, profile: profile.id.clone(),
            state: CellState::Isolated, pid: handle.pid, cgroup_id, cgroup_path, created_at: now.wall_s,
            expires_at, export_size: 0, export_sha256: String::new(), burn_reason: String::new(),
            evidence_id: String::new() };
        let deadline_mono_ms = now.mono_ms.saturating_add(limits.ttl_seconds.saturating_mul(1000));
        self.entries.insert(uuid, CellEntry { record: record.clone(), handle, input_path,
            export: Some(export_target), sealed: None, deadline_mono_ms, frozen: false,
            max_export_bytes: limits.max_export_bytes, sealed_seq: 0 });
        Ok(record)
    }
    /// Freeze one cell (idempotent, `cgroup.freeze=1` + read-back verify).
    pub fn freeze(&mut self, uuid: &str, generation: u64, cgroup_id: u64) -> Result<(), ErrorCode> {
        self.set_frozen(uuid, generation, cgroup_id, true)
    }
    /// Unfreeze one cell (idempotent, `cgroup.freeze=0` + read-back verify).
    pub fn unfreeze(&mut self, uuid: &str, generation: u64, cgroup_id: u64) -> Result<(), ErrorCode> {
        self.set_frozen(uuid, generation, cgroup_id, false)
    }
    fn set_frozen(&mut self, uuid: &str, generation: u64, cgroup_id: u64, freeze: bool) -> Result<(), ErrorCode> {
        let entry = self.checked_entry_mut(uuid, generation, cgroup_id)?;
        if entry.frozen == freeze { return Ok(()); }
        let path = entry.record.cgroup_path.clone();
        let value = if freeze { "1" } else { "0" };
        cg_write(&path, "cgroup.freeze", value)?;
        if cg_read(&path, "cgroup.freeze")? != value { return Err(ErrorCode::Internal); }
        entry.frozen = freeze; Ok(())
    }
    /// Idempotent burn: cgroup.kill, seal + hash export, ledger, cleanup.
    pub fn burn(&mut self, uuid: &str, generation: u64, cgroup_id: u64, evidence_id: &str,
        reason: &str, now: TimeSample) -> Result<ExportMeta, ErrorCode> {
        let (cgroup_path, pid, export_path, max_export) = {
            let entry = self.checked_entry_mut(uuid, generation, cgroup_id)?;
            if entry.record.state == CellState::Burned {
                return Ok(ExportMeta { size: entry.record.export_size, sha256: entry.record.export_sha256.clone(), kind: "file".into() });
            }
            if entry.record.state.is_terminal() { return Err(ErrorCode::BurnFailed); }
            entry.record.state = CellState::Burning;
            entry.record.burn_reason = token_or_dash(reason);
            entry.record.evidence_id = token_or_dash(evidence_id);
            (entry.record.cgroup_path.clone(), entry.handle.pid, entry.handle.export_path.clone(), entry.max_export_bytes)
        };
        self.cg_kill(&cgroup_path, pid);
        let target = self.entries.get_mut(uuid).expect("burn entry").export.take();
        if let Some(target) = target.as_ref() {
            if let Err(code) = target.flush_sync(max_export) {
                self.fail_burn(uuid, &cgroup_path, now, "overflow");
                return Err(code);
            }
        }
        drop(target);
        let sealed = match export::seal_export_file(&export_path, max_export, self.gedefense_gid.map(|_| 0)) {
            Ok(s) => s,
            Err(code) => { self.fail_burn(uuid, &cgroup_path, now, "seal-failed"); return Err(code); }
        };
        let meta = ExportMeta { size: sealed.size, sha256: sealed.sha256.clone(), kind: "file".into() };
        let seq = self.next_sealed_seq;
        self.next_sealed_seq = self.next_sealed_seq.wrapping_add(1).max(1);
        let entry = self.entries.get_mut(uuid).expect("burn entry");
        entry.record.export_size = sealed.size;
        entry.record.export_sha256 = sealed.sha256.clone();
        entry.record.state = CellState::Burned;
        entry.sealed = Some(sealed);
        entry.sealed_seq = seq;
        self.burned_total += 1;
        self.record_burn(uuid, now, "burn");
        if let Some(input_path) = self.entries.get(uuid).map(|e| e.input_path.clone()) { let _ = fs::remove_file(input_path); }
        let _ = fs::remove_file(&export_path);
        self.cg_remove(&cgroup_path);
        self.enforce_retention();
        Ok(meta)
    }
    /// `CELL_EXPORT_READ`: sealed FD + metadata (bounded retention).
    pub fn export_read(&self, uuid: &str, generation: u64) -> Result<(RawFd, ExportMeta), ErrorCode> {
        let entry = self.entries.get(uuid).ok_or(ErrorCode::UnknownCell)?;
        if entry.record.generation != generation { return Err(ErrorCode::StaleGeneration); }
        if entry.record.state != CellState::Burned { return Err(ErrorCode::ExportMissing); }
        let sealed = entry.sealed.as_ref().ok_or(ErrorCode::ExportMissing)?;
        Ok((sealed.fd(), ExportMeta { size: sealed.size, sha256: sealed.sha256.clone(), kind: "file".into() }))
    }
    /// TTL: mark due cells `expiring`, then burn them with `ttl-expired`.
    pub fn expire_due(&mut self, now: TimeSample) -> usize {
        let due: Vec<(String, u64, u64)> = self.entries.values().filter(|e| !e.record.state.is_terminal() && e.deadline_mono_ms <= now.mono_ms)
            .map(|e| (e.record.uuid.clone(), e.record.generation, e.record.cgroup_id)).collect();
        let mut burned = 0;
        for (uuid, generation, cgroup_id) in due {
            if let Some(e) = self.entries.get_mut(&uuid) { e.record.state = CellState::Expiring; }
            if self.burn(&uuid, generation, cgroup_id, "none", "ttl-expired", now).is_ok() { burned += 1; }
        }
        burned
    }
    /// Startup orphan sweep: `parser-*` cgroups without live registry state.
    pub fn sweep_orphans(&mut self, now: TimeSample) -> Result<usize, ErrorCode> {
        let mut dirs: Vec<PathBuf> = fs::read_dir(&self.cgroup_root).map_err(|_| ErrorCode::Internal)?
            .filter_map(|e| e.ok().map(|e| e.path())).filter(|p| p.file_name().and_then(|n| n.to_str()).map(|n| n.starts_with(CGROUP_PREFIX)).unwrap_or(false)).collect();
        dirs.sort();
        let mut swept = 0;
        for dir in dirs {
            let Some(name) = dir.file_name().and_then(|n| n.to_str()) else { continue };
            let uuid = name.trim_start_matches(CGROUP_PREFIX).to_string();
            if self.entries.get(&uuid).map(|e| !e.record.state.is_terminal()).unwrap_or(false) { continue; }
            let cgroup_id = cg_id(&dir).unwrap_or(0);
            self.cg_kill(&dir, 0);
            self.cg_remove(&dir);
            let profile = self.entries.get(&uuid).map(|e| e.record.profile.clone()).unwrap_or_default();
            let entry = BurnLedgerEntry { ts: now.wall_s, uuid: uuid.clone(), generation: 0, cgroup_id, profile,
                reason: "orphan-sweep".into(), export_size: 0, export_sha256: String::new(), evidence_id: String::new(), kind: "orphan".into() };
            if self.ledger.append(&entry).is_err() { self.last_error = Some("ledger-write-failed".into()); }
            self.entries.remove(&uuid);
            swept += 1;
        }
        Ok(swept)
    }
    // ---- internals -------------------------------------------------------
    fn checked_entry_mut(&mut self, uuid: &str, generation: u64, cgroup_id: u64) -> Result<&mut CellEntry, ErrorCode> {
        let entry = self.entries.get_mut(uuid).ok_or(ErrorCode::UnknownCell)?;
        if entry.record.generation != generation || entry.record.cgroup_id != cgroup_id { return Err(ErrorCode::StaleGeneration); }
        Ok(entry)
    }
    fn next_generation(&mut self) -> u64 {
        let g = self.generation;
        self.generation = self.generation.wrapping_add(1).max(1);
        g
    }
    fn new_uuid(&mut self) -> Result<String, ErrorCode> {
        for _ in 0..8 {
            let mut buf = [0u8; 16];
            // SAFETY: getrandom(2) writes at most buf.len() bytes into buf.
            if unsafe { libc::syscall(libc::SYS_getrandom, buf.as_mut_ptr(), buf.len(), 0u32) } == 16 { return Ok(hex::encode(buf)); }
        }
        use std::io::Read;
        let mut buf = [0u8; 16];
        fs::File::open("/dev/urandom").and_then(|mut f| f.read_exact(&mut buf)).map_err(|_| ErrorCode::Internal)?;
        Ok(hex::encode(buf))
    }
    fn cg_create(&self, path: &Path, limits: &Limits) -> Result<(), ErrorCode> {
        if path.parent() != Some(self.cgroup_root.as_path()) { return Err(ErrorCode::Internal); }
        if path.exists() { return Err(ErrorCode::CellLimit); }
        fs::create_dir(path).map_err(|_| ErrorCode::SandboxUnavailable)?;
        cg_write(path, "memory.max", &limits.max_rss_bytes.to_string())?;
        cg_write(path, "pids.max", &limits.max_pids.to_string())?;
        cg_write(path, "cpu.max", "max 100000")?;
        cg_write(path, "memory.swap.max", "0")
    }
    fn cg_attach(&self, path: &Path, pid: i32) -> Result<u64, ErrorCode> {
        if pid <= 0 { return Err(ErrorCode::Internal); }
        cg_write(path, "cgroup.procs", &pid.to_string())?;
        cg_id(path)
    }
    fn cg_kill(&mut self, path: &Path, pid: i32) {
        let _ = cg_write(path, "cgroup.kill", "1");
        // SAFETY: SIGKILL to the cell PID; ESRCH/EPERM ignored (cgroup.kill is
        // authoritative, this is belt-and-braces).
        if pid > 0 { unsafe { libc::kill(pid, libc::SIGKILL) }; }
        for _ in 0..50 {
            if fs::read_to_string(path.join("cgroup.procs")).map(|s| s.trim().is_empty()).unwrap_or(true) { break; }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
    }
    fn cg_remove(&mut self, path: &Path) {
        if self.fake_cgroup { let _ = fs::remove_dir_all(path); return; }
        for _ in 0..20 {
            match fs::remove_dir(path) {
                Ok(()) => return,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => return,
                Err(_) => std::thread::sleep(std::time::Duration::from_millis(20)),
            }
        }
        self.last_error = Some("cgroup-rmdir-failed".into());
    }
    fn fail_burn(&mut self, uuid: &str, cgroup_path: &Path, now: TimeSample, kind: &str) {
        if let Some(entry) = self.entries.get_mut(uuid) { entry.record.state = CellState::Failed; }
        self.record_burn(uuid, now, kind);
        self.cg_remove(cgroup_path);
    }
    fn record_burn(&mut self, uuid: &str, now: TimeSample, kind: &str) {
        let Some(entry) = self.entries.get(uuid) else { return };
        let ledger_entry = BurnLedgerEntry { ts: now.wall_s, uuid: uuid.to_string(),
            generation: entry.record.generation, cgroup_id: entry.record.cgroup_id,
            profile: entry.record.profile.clone(), reason: entry.record.burn_reason.clone(),
            export_size: entry.record.export_size, export_sha256: entry.record.export_sha256.clone(),
            evidence_id: entry.record.evidence_id.clone(), kind: kind.to_string() };
        if self.ledger.append(&ledger_entry).is_err() { self.last_error = Some("ledger-write-failed".into()); }
    }
    fn enforce_retention(&mut self) {
        let mut sealed: Vec<(u64, String)> = self.entries.iter().filter(|(_, e)| e.sealed.is_some()).map(|(k, e)| (e.sealed_seq, k.clone())).collect();
        if sealed.len() > MAX_RETAINED_EXPORTS {
            sealed.sort();
            let excess = sealed.len() - MAX_RETAINED_EXPORTS;
            for (_, uuid) in sealed.into_iter().take(excess) { if let Some(e) = self.entries.get_mut(&uuid) { e.sealed = None; } }
        }
        let mut terminal: Vec<(u64, String)> = self.entries.iter().filter(|(_, e)| e.record.state.is_terminal()).map(|(k, e)| (e.record.created_at, k.clone())).collect();
        if terminal.len() > BURN_RETAINED {
            terminal.sort();
            let excess = terminal.len() - BURN_RETAINED;
            for (_, uuid) in terminal.into_iter().take(excess) { self.entries.remove(&uuid); }
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::test_support::TempDir;
    fn uuid(seed: u8) -> String { hex::encode([seed; 16]) }
    fn registry(tag: &str) -> (TempDir, CellRegistry) {
        let td = TempDir::new(tag).unwrap();
        std::fs::create_dir(td.child("cgroup")).unwrap();
        let mut reg = CellRegistry::new(td.child("cgroup"), td.child("cells"), td.child("ledger.jsonl"), 4, None).unwrap();
        reg.fake_cgroup = true;
        (td, reg)
    }
    /// Synthetic cell (fake cgroup dir + export file) without spawning.
    fn test_entry(td: &TempDir, reg: &mut CellRegistry, seed: u8, data: &[u8], now: TimeSample) -> String {
        std::fs::create_dir_all(td.child("exports")).unwrap();
        let uuid = hex::encode([seed; 16]);
        let cgroup_path = reg.cgroup_root.join(format!("{}{}", CGROUP_PREFIX, uuid));
        reg.cg_create(&cgroup_path, &Limits::new(60, 1024, 8, 4096)).unwrap();
        for (name, value) in [("cgroup.freeze", "0"), ("cgroup.kill", "0"), ("cgroup.procs", ""), ("cgroup.events", "populated 0\n")] {
            std::fs::write(cgroup_path.join(name), value).unwrap();
        }
        let export = ExportTarget::open(&td.child("exports"), &uuid, None).unwrap();
        let mut f = std::fs::File::from(unsafe { <std::os::fd::OwnedFd as std::os::fd::FromRawFd>::from_raw_fd(libc::dup(export.fd())) });
        std::io::Write::write_all(&mut f, data).unwrap();
        let cgroup_id = cg_id(&cgroup_path).unwrap();
        let handle = CellHandle { pid: -1, uuid: uuid.clone(), generation: 1, cgroup_id,
            cgroup_path: cgroup_path.clone(), root_dir: td.child("cells").join(&uuid),
            export_fd: export.fd(), export_path: export.path().to_path_buf(),
            started_at: now.wall_s, expires_at: now.wall_s + 60 };
        let record = CellRecord { uuid: uuid.clone(), generation: 1, profile: "pdf-viewer".into(), state: CellState::Isolated, pid: -1, cgroup_id, cgroup_path,
            created_at: now.wall_s, expires_at: now.wall_s + 60, export_size: 0, export_sha256: String::new(), burn_reason: String::new(), evidence_id: String::new() };
        reg.entries.insert(uuid.clone(), CellEntry { record, handle, input_path: td.write(&format!("{}.bin", "aa".repeat(16)), b"input").unwrap(),
            export: Some(export), sealed: None, deadline_mono_ms: now.mono_ms + 60_000,
            frozen: false, max_export_bytes: HARD_MAX_EXPORT_BYTES, sealed_seq: 0 });
        uuid
    }
    #[test]
    fn ledger_rotates_timer_fires() {
        let td = TempDir::new("lc-ledger").unwrap();
        let mut ledger = BurnLedger::open(td.child("burn_ledger.jsonl")).unwrap();
        let entry = BurnLedgerEntry { ts: 5, uuid: uuid(1), generation: 1, cgroup_id: 7, profile: "p".into(),
            reason: "ttl-expired".into(), export_size: 3, export_sha256: "ab".repeat(32),
            evidence_id: "ev".into(), kind: "burn".into() };
        ledger.append(&entry).unwrap();
        assert_eq!(BurnLedgerEntry::from_line(&std::fs::read_to_string(td.child("burn_ledger.jsonl")).unwrap()), Some(entry));
        std::fs::write(td.child("burn_ledger.jsonl"), "x".repeat(LEDGER_MAX_BYTES as usize - 50)).unwrap();
        ledger.append(&BurnLedgerEntry { ts: 1, reason: "rotate".into(), ..BurnLedgerEntry {
            ts: 0, uuid: uuid(2), generation: 1, cgroup_id: 7, profile: "p".into(), reason: String::new(),
            export_size: 0, export_sha256: String::new(), evidence_id: String::new(), kind: "burn".into() } }).unwrap();
        assert!(td.child("burn_ledger.jsonl.1").exists());
        let t = MonotonicTimer::new().unwrap();
        t.arm(mono_ms().unwrap() + 20).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(80));
        assert!(t.consume() >= 1);
        t.disarm().unwrap();
        std::thread::sleep(std::time::Duration::from_millis(20));
        assert_eq!(t.consume(), 0);
    }
    #[test]
    fn burn_idempotent_overflow_and_fake_cgroup() {
        let (td, mut reg) = registry("lc-burn");
        let now = TimeSample::at(1000, 1_700_000_000);
        let u = test_entry(&td, &mut reg, 3, b"evidence-bytes", now);
        let (gen, cgid) = (reg.entries[&u].record.generation, reg.entries[&u].record.cgroup_id);
        let path = reg.entries[&u].record.cgroup_path.clone();
        assert_eq!(std::fs::read_to_string(path.join("memory.max")).unwrap(), "1024");
        assert_eq!(reg.cg_attach(&path, -1).err(), Some(ErrorCode::Internal));
        assert_eq!(reg.freeze(&u, 99, 0).err(), Some(ErrorCode::StaleGeneration));
        reg.freeze(&u, 1, cgid).unwrap();
        reg.unfreeze(&u, 1, cgid).unwrap();
        let meta = reg.burn(&u, gen, cgid, "ev-1", "operator-burn", now).unwrap();
        assert_eq!((meta.size, meta.sha256.as_str()), (14, export::sha256_of(b"evidence-bytes").as_str()));
        assert_eq!(reg.export_read(&u, gen).unwrap().1, meta);
        assert_eq!(reg.entries[&u].record.state, CellState::Burned);
        assert_eq!(reg.export_read(&u, gen + 100).err(), Some(ErrorCode::StaleGeneration));
        assert_eq!(reg.burn(&u, gen + 100, cgid, "x", "x", now).err(), Some(ErrorCode::StaleGeneration));
        assert_eq!(reg.export_read(&"ff".repeat(16), gen).err(), Some(ErrorCode::UnknownCell));
        assert_eq!(reg.burn(&u, gen, cgid, "ev-1", "operator-burn", now).unwrap(), meta);
        assert!(std::fs::read_to_string(td.child("ledger.jsonl")).unwrap().contains("kind=burn"));
        let v = test_entry(&td, &mut reg, 4, b"x", now);
        reg.entries.get_mut(&v).unwrap().max_export_bytes = 0;
        let (g2, c2) = (reg.entries[&v].record.generation, reg.entries[&v].record.cgroup_id);
        assert_eq!(reg.burn(&v, g2, c2, "e", "r", now).err(), Some(ErrorCode::ExportOverflow));
        assert_eq!(reg.entries[&v].record.state, CellState::Failed);
        assert!(std::fs::read_to_string(td.child("ledger.jsonl")).unwrap().contains("kind=overflow"));
    }
    #[test]
    fn ttl_expiry_sweep_health_and_bad_root() {
        let (td, mut reg) = registry("lc-ttl");
        let now = TimeSample::at(5000, 1_700_000_000);
        let v = test_entry(&td, &mut reg, 5, b"ttl", now);
        assert_eq!(reg.next_deadline_mono(), Some(65_000));
        assert_eq!(reg.expire_due(TimeSample::at(1_000, 1_700_000_001)), 0);
        assert_eq!(reg.expire_due(TimeSample::at(70_000, 1_700_000_002)), 1);
        assert_eq!(reg.entries[&v].record.state, CellState::Burned);
        assert_eq!((reg.next_deadline_mono(), reg.health().burned_total), (None, 1));
        let orphan = td.child("cgroup").join(format!("{}{}", CGROUP_PREFIX, uuid(6)));
        std::fs::create_dir(&orphan).unwrap();
        std::fs::write(orphan.join("cgroup.kill"), "0").unwrap();
        std::fs::write(orphan.join("cgroup.procs"), "").unwrap();
        assert_eq!(reg.sweep_orphans(TimeSample::at(1000, 1_700_000_000)).unwrap(), 1);
        assert!(!orphan.exists() && std::fs::read_to_string(td.child("ledger.jsonl")).unwrap().contains("kind=orphan"));
        reg.last_error = Some("x".into()); assert_eq!(reg.health().state, "degraded");
        assert_eq!(CellRegistry::new(td.child("missing"), td.child("c"), td.child("l"), 4, None).err(), Some(ErrorCode::SandboxUnavailable));
        assert_eq!(CellRegistry::new(td.write("file", b"x").unwrap(), td.child("c"), td.child("l"), 4, None).err(), Some(ErrorCode::SandboxUnavailable));
    }
}