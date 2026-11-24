//! Wave 3a extraction: the Emergency-Lockdown ABI glue (token parsing, status
//! formatting, shared telemetry bridge, persisted state and the `LOCKDOWN_*`
//! catch-all dispatch arm) formerly inline in `main.rs`.

use crate::ipc::server::MAX_RESPONSE_BYTES;
use crate::*;

// ---------------------------------------------------------------------------
// Point 5 (§5/§6/§9): Emergency-Lockdown ABI glue.
//
// The §5 tokens are parsed and the answers formatted here, next to the existing
// VGT3 command surface; the typed state machine lives in `lockdown`. The shared
// telemetry bridge (event queue, counters, arm policy) also lives at the crate
// root because both the command surface and the uevent monitor thread use it.
// ---------------------------------------------------------------------------

use gedefense_common::{
    decode_lockdown_word, encode_lockdown_word, LockdownEvent, LOCKDOWN_FLAG_ALLOW_LOOPBACK,
    LOCKDOWN_FLAG_DROP_ALL, LOCKDOWN_MODE_ARMED, LOCKDOWN_OUTCOME_APPLIED, LOCKDOWN_OUTCOME_UNSUPPORTED,
    LOCKDOWN_PHASE_BROKERS, LOCKDOWN_PHASE_CELLS, LOCKDOWN_PHASE_DM, LOCKDOWN_PHASE_HARDENING,
    LOCKDOWN_PHASE_INTENT, LOCKDOWN_PHASE_NET, LOCKDOWN_PHASE_SESSIONS, LOCKDOWN_PHASE_TB,
    LOCKDOWN_PHASE_USB, LOCKDOWN_REASON_BOOT_TRUST_DRIFT, LOCKDOWN_REASON_MANUAL,
    LOCKDOWN_REASON_POLICY, LOCKDOWN_REASON_SCREEN_LOCK, LOCKDOWN_REASON_TAMPER,
    LOCKDOWN_REASON_TB_UNKNOWN, LOCKDOWN_REASON_USB_UNKNOWN, LOCKDOWN_REASON_XDR_CRITICAL,
    LOCKDOWN_SOURCE_MANUAL, LOCKDOWN_SOURCE_POLICY, LOCKDOWN_SOURCE_TIMER, LOCKDOWN_SOURCE_UEVENT,
};

/// Arm mode (§5 `mode=locked|unlocked`): kernel enforcement and uevent blocking
/// only exist in `locked`; `unlocked` is audit-only (Lade-Kabel-DoS-Schutz).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ArmMode {
    Unlocked,
    Locked,
}

impl ArmMode {
    pub(crate) fn token(self) -> &'static str {
        match self {
            Self::Unlocked => "unlocked",
            Self::Locked => "locked",
        }
    }
    pub(crate) fn from_token(token: &str) -> Option<Self> {
        match token {
            "unlocked" => Some(Self::Unlocked),
            "locked" => Some(Self::Locked),
            _ => None,
        }
    }
}

/// Snapshot the uevent monitor acts on; kept in sync by ARM/TRIGGER/SET_MODE.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct UeventPolicy {
    pub(crate) arm: ArmMode,
    pub(crate) auto_network_drop: bool,
    pub(crate) allow_loopback: bool,
    pub(crate) epoch: u32,
}

impl Default for UeventPolicy {
    fn default() -> Self {
        Self { arm: ArmMode::Unlocked, auto_network_drop: false, allow_loopback: true, epoch: 0 }
    }
}

/// Bounded, monotonically sequenced lifecycle event queue (§5 `LOCKDOWN_EVENTS`).
#[derive(Default)]
pub(crate) struct LockdownEventQueue {
    pub(crate) records: VecDeque<LockdownEvent>,
    pub(crate) seq: u64,
    pub(crate) dropped: u64,
    pub(crate) reported: u64,
}

impl LockdownEventQueue {
    pub(crate) fn push(&mut self, epoch: u32, source: u8, reason: u8, phase: u8, outcome: u8, detail: u64) {
        if self.records.len() >= LOCKDOWN_EVENT_QUEUE_CAPACITY {
            self.dropped = self.dropped.saturating_add(1);
            return;
        }
        let ts_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|value| value.as_millis().min(u128::from(u64::MAX)) as u64)
            .unwrap_or(0)
            .max(1);
        self.seq = self.seq.saturating_add(1);
        self.records.push_back(LockdownEvent {
            seq: self.seq,
            ts_ms,
            epoch,
            source,
            reason,
            phase,
            outcome,
            cgroup_id: 0,
            detail_u64: detail,
            reserved: [0u8; 24],
        });
    }

    /// Drains up to `max` records; `dropped` is the delta since the last drain.
    pub(crate) fn take(&mut self, max: usize) -> (u64, Vec<LockdownEvent>) {
        let mut records = Vec::with_capacity(max.min(self.records.len()));
        while records.len() < max {
            match self.records.pop_front() {
                Some(record) => records.push(record),
                None => break,
            }
        }
        let dropped = self.dropped.saturating_sub(self.reported);
        self.reported = self.dropped;
        (dropped, records)
    }
}

pub(crate) const LOCKDOWN_EVENT_QUEUE_CAPACITY: usize = 64;

/// State shared between the command surface and the uevent monitor thread.
pub(crate) struct LockdownShared {
    pub(crate) word: Arc<dyn lockdown::LockdownWordStore>,
    pub(crate) events: Mutex<LockdownEventQueue>,
    pub(crate) policy: Mutex<UeventPolicy>,
    /// Set once a hotplug auto-drop wrote `LOCKDOWN_FLAG_DROP_ALL`; keeps the
    /// flag owned by the shared state instead of only by the kernel word, so a
    /// later phase refresh cannot silently clear the drop.
    pub(crate) auto_drop: AtomicBool,
    pub(crate) uevent_events: AtomicU64,
    pub(crate) usb_blocks: AtomicU64,
    pub(crate) tb_blocks: AtomicU64,
}

impl LockdownShared {
    pub(crate) fn new(word: Arc<dyn lockdown::LockdownWordStore>, policy: UeventPolicy) -> Self {
        Self {
            word,
            events: Mutex::new(LockdownEventQueue::default()),
            policy: Mutex::new(policy),
            auto_drop: AtomicBool::new(false),
            uevent_events: AtomicU64::new(0),
            usb_blocks: AtomicU64::new(0),
            tb_blocks: AtomicU64::new(0),
        }
    }
    pub(crate) fn set_policy(&self, policy: UeventPolicy) {
        if let Ok(mut guard) = self.policy.lock() {
            *guard = policy;
        }
    }
    pub(crate) fn policy(&self) -> UeventPolicy {
        self.policy.lock().map(|guard| *guard).unwrap_or_default()
    }
    pub(crate) fn emit(&self, epoch: u32, source: u8, reason: u8, phase: u8, outcome: u8, detail: u64) {
        if let Ok(mut guard) = self.events.lock() {
            guard.push(epoch, source, reason, phase, outcome, detail);
        }
    }
    pub(crate) fn take_events(&self, max: usize) -> (u64, Vec<LockdownEvent>) {
        self.events.lock().map(|mut guard| guard.take(max)).unwrap_or((0, Vec::new()))
    }
    pub(crate) fn inc_uevent(&self) {
        self.uevent_events.fetch_add(1, Ordering::Relaxed);
    }
    pub(crate) fn add_usb_blocks(&self, count: u32) {
        self.usb_blocks.fetch_add(u64::from(count), Ordering::Relaxed);
    }
    pub(crate) fn add_tb_blocks(&self, count: u32) {
        self.tb_blocks.fetch_add(u64::from(count), Ordering::Relaxed);
    }
    pub(crate) fn uevent_counters(&self) -> (u64, u64, u64) {
        (
            self.uevent_events.load(Ordering::Relaxed),
            self.usb_blocks.load(Ordering::Relaxed),
            self.tb_blocks.load(Ordering::Relaxed),
        )
    }
    /// §5 STATUS `flags`: verified kernel state word of `epoch`, 0 if absent.
    pub(crate) fn word_flags(&self, epoch: u32) -> u8 {
        self.word
            .read()
            .ok()
            .and_then(decode_lockdown_word)
            .filter(|word| word.epoch == epoch)
            .map(|word| word.flags)
            .unwrap_or(0)
    }
    /// Immediate kernel network drop after a blocked hotplug (§2 auto flag).
    ///
    /// The drop is tracked in `auto_drop` and merged into the flags already
    /// persisted for the current epoch: an operator phase refresh (or another
    /// concurrent writer) no longer erases `DROP_ALL`, and this write no longer
    /// erases `USB_LOCKED`/`HARDENING_APPLIED`.
    pub(crate) fn auto_network_drop(&self) -> Result<(), &'static str> {
        let policy = self.policy();
        if !policy.auto_network_drop {
            return Ok(());
        }
        let mut flags = self
            .word
            .read()
            .ok()
            .and_then(decode_lockdown_word)
            .filter(|word| word.epoch == policy.epoch)
            .map(|word| word.flags)
            .unwrap_or(0);
        flags |= LOCKDOWN_FLAG_DROP_ALL;
        if policy.allow_loopback {
            flags |= LOCKDOWN_FLAG_ALLOW_LOOPBACK;
        }
        // Fail-secure: the drop is claimed before the write, so a failed or
        // unverified write is re-applied by the next `refresh_word()` instead
        // of being forgotten.  The caller still observes the error.
        self.auto_drop.store(true, Ordering::SeqCst);
        let word = encode_lockdown_word(policy.epoch, LOCKDOWN_MODE_ARMED, flags);
        self.word.write(word).map_err(|_| "state-map-write-failed")?;
        match decode_lockdown_word(self.word.read().map_err(|_| "state-map-read-failed")?) {
            Some(decoded)
                if decoded.epoch == policy.epoch && decoded.flags & LOCKDOWN_FLAG_DROP_ALL != 0 =>
            {
                Ok(())
            }
            _ => Err("state-map-readback-mismatch"),
        }
    }
    /// `true` while a hotplug auto-drop owns `LOCKDOWN_FLAG_DROP_ALL`.
    pub(crate) fn auto_drop(&self) -> bool {
        self.auto_drop.load(Ordering::SeqCst)
    }
    /// Releases the auto-drop ownership (CLEAR, a new epoch, explicit NET off).
    pub(crate) fn clear_auto_drop(&self) {
        self.auto_drop.store(false, Ordering::SeqCst);
    }
    /// Marks an already verified word drop as auto-drop ownership discovered
    /// during startup re-arm, so the next refresh does not clear it.
    pub(crate) fn mark_auto_drop(&self) {
        self.auto_drop.store(true, Ordering::SeqCst);
    }
}

// --- §5 token tables (closed sets; unknown tokens are always ERR) -----------

pub(crate) const LOCKDOWN_PHASE_TOKENS: &[(u8, &str)] = &[
    (LOCKDOWN_PHASE_INTENT, "intent"),
    (LOCKDOWN_PHASE_NET, "net"),
    (LOCKDOWN_PHASE_USB, "usb"),
    (LOCKDOWN_PHASE_TB, "tb"),
    (LOCKDOWN_PHASE_HARDENING, "hardening"),
    (LOCKDOWN_PHASE_BROKERS, "brokers"),
    (LOCKDOWN_PHASE_CELLS, "cells"),
    (LOCKDOWN_PHASE_SESSIONS, "sessions"),
    (LOCKDOWN_PHASE_DM, "dm"),
];

pub(crate) const LOCKDOWN_REASON_TOKENS: &[(&str, u8)] = &[
    ("manual", LOCKDOWN_REASON_MANUAL),
    ("usb-unknown", LOCKDOWN_REASON_USB_UNKNOWN),
    ("tb-unknown", LOCKDOWN_REASON_TB_UNKNOWN),
    ("screen-lock", LOCKDOWN_REASON_SCREEN_LOCK),
    ("tamper", LOCKDOWN_REASON_TAMPER),
    ("xdr-critical", LOCKDOWN_REASON_XDR_CRITICAL),
    ("boot-trust-drift", LOCKDOWN_REASON_BOOT_TRUST_DRIFT),
    ("policy", LOCKDOWN_REASON_POLICY),
];

pub(crate) const LOCKDOWN_SOURCE_TOKENS: &[(&str, u8)] = &[
    ("manual", LOCKDOWN_SOURCE_MANUAL),
    ("uevent", LOCKDOWN_SOURCE_UEVENT),
    ("policy", LOCKDOWN_SOURCE_POLICY),
    ("timer", LOCKDOWN_SOURCE_TIMER),
];

pub(crate) fn lockdown_phase_token(phase: u8) -> Option<&'static str> {
    LOCKDOWN_PHASE_TOKENS.iter().find(|(value, _)| *value == phase).map(|(_, token)| *token)
}

pub(crate) fn parse_lockdown_phase(token: &str) -> Option<u8> {
    LOCKDOWN_PHASE_TOKENS.iter().find(|(_, name)| *name == token).map(|(value, _)| *value)
}

pub(crate) fn parse_lockdown_reason(token: &str) -> Result<u8, BoxError> {
    LOCKDOWN_REASON_TOKENS
        .iter()
        .find(|(name, _)| *name == token)
        .map(|(_, value)| *value)
        .ok_or_else(|| "unknown lockdown reason token".into())
}

pub(crate) fn parse_lockdown_source(token: &str) -> Result<u8, BoxError> {
    LOCKDOWN_SOURCE_TOKENS
        .iter()
        .find(|(name, _)| *name == token)
        .map(|(_, value)| *value)
        .ok_or_else(|| "unknown lockdown source token".into())
}

pub(crate) fn parse_lockdown_flags(token: &str) -> Result<u8, BoxError> {
    let flags = token.parse::<u8>().map_err(|_| "invalid lockdown policy flags")?;
    if flags & !lockdown::POLICY_FLAGS_KNOWN != 0 {
        return Err("unknown lockdown policy flag".into());
    }
    Ok(flags)
}

pub(crate) fn parse_lockdown_epoch(token: &str) -> Result<u32, BoxError> {
    if token.len() != 8 || !token.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("invalid lockdown epoch".into());
    }
    u32::from_str_radix(token, 16).map_err(|_| "invalid lockdown epoch".into())
}

// --- §5 ABI answers ---------------------------------------------------------

/// §5 `LOCKDOWN_STATUS` exact wire format.
pub(crate) fn lockdown_status(core: &lockdown::LockdownCore) -> String {
    format!(
        "state={};epoch={:08x};mode={};flags={};phases={};unsupported={}",
        core.state_text(),
        core.epoch(),
        core.arm_mode().token(),
        core.word_flags(),
        lockdown_applied_csv(core),
        lockdown_unsupported_csv(core),
    )
}

/// Applied phases in contract order, plus the honest `cells=delegated` marker.
pub(crate) fn lockdown_applied_csv(core: &lockdown::LockdownCore) -> String {
    let mut entries: Vec<String> = [LOCKDOWN_PHASE_NET, LOCKDOWN_PHASE_USB, LOCKDOWN_PHASE_TB, LOCKDOWN_PHASE_HARDENING, LOCKDOWN_PHASE_BROKERS]
        .into_iter()
        .filter(|phase| core.phase_outcome(*phase) == LOCKDOWN_OUTCOME_APPLIED)
        .filter_map(|phase| lockdown_phase_token(phase).map(str::to_owned))
        .collect();
    if core.phase_outcome(LOCKDOWN_PHASE_CELLS) == lockdown::DELEGATED {
        entries.push("cells=delegated".to_owned());
    }
    if entries.is_empty() {
        "-".to_owned()
    } else {
        entries.join(",")
    }
}

/// Unsupported phases: the permanent Phase-1 limits plus attempted ones.
pub(crate) fn lockdown_unsupported_csv(core: &lockdown::LockdownCore) -> String {
    let mut entries: Vec<String> = [LOCKDOWN_PHASE_SESSIONS, LOCKDOWN_PHASE_DM]
        .into_iter()
        .filter_map(|phase| lockdown_phase_token(phase).map(str::to_owned))
        .collect();
    for phase in 0..lockdown::PHASE_COUNT as u8 {
        if core.phase_outcome(phase) == LOCKDOWN_OUTCOME_UNSUPPORTED
            && phase != LOCKDOWN_PHASE_SESSIONS
            && phase != LOCKDOWN_PHASE_DM
        {
            if let Some(token) = lockdown_phase_token(phase) {
                entries.push(token.to_owned());
            }
        }
    }
    entries.join(",")
}

/// §5 `LOCKDOWN_EVENTS`: ≤16 records as `<dropped>|<seq:ts:source:reason:
/// phase:outcome>,…`; the batch is either complete or an error (never a
/// silent truncation), and the queue keeps the remaining records.
pub(crate) fn lockdown_events(core: &mut lockdown::LockdownCore) -> Result<String, BoxError> {
    let max = lockdown_uevent::EVENTS_PER_RESPONSE;
    let (dropped, records) = core.take_events(max);
    if records.is_empty() {
        return if dropped == 0 { Ok("empty".to_owned()) } else { Ok(format!("{dropped}|")) };
    }
    let mut items = Vec::with_capacity(records.len());
    for event in &records {
        items.push(format!(
            "{}:{}:{}:{}:{}:{}",
            event.seq, event.ts_ms, event.source, event.reason, event.phase, event.outcome
        ));
    }
    let payload = format!("{dropped}|{}", items.join(","));
    if payload.len() > MAX_RESPONSE_BYTES {
        return Err("lockdown event batch exceeds the response budget".into());
    }
    Ok(payload)
}

/// §5 `LOCKDOWN_HEALTH`: 6 decimal per-CPU sums / counters.
pub(crate) fn lockdown_health(core: &lockdown::LockdownCore) -> Result<String, BoxError> {
    let (net_drops, witness_passes) =
        core.net_counters().map_err(|error| -> BoxError { error.into() })?;
    let (uevent_events, usb_blocks, tb_blocks) = core.uevent_counters();
    Ok(format!(
        "{net_drops}:{witness_passes}:{uevent_events}:{usb_blocks}:{tb_blocks}:{}",
        core.broker_frozen()
    ))
}

/// §5 dispatch for every `LOCKDOWN_*` command; unknown names stay ERR.
pub(crate) const LOCKDOWN_KERNEL_LOCKDOWN_REASON: &str = "boot-parameter-immutable";
pub(crate) fn lockdown_command(core: &mut lockdown::LockdownCore, parts: &[&str]) -> Result<String, BoxError> {
    match parts {
        ["LOCKDOWN_VERSION"] => Ok(core.version().to_owned()),
        ["LOCKDOWN_EPOCH"] => Ok(format!("{:08x}", core.epoch())),
        ["LOCKDOWN_STATUS"] => Ok(lockdown_status(core)),
        ["LOCKDOWN_ARM", mode, reason, flags] => {
            let mode = ArmMode::from_token(mode).ok_or("unknown lockdown mode token")?;
            let reason = parse_lockdown_reason(reason)?;
            let flags = parse_lockdown_flags(flags)?;
            Ok(match core.arm(mode, reason, flags)? {
                lockdown::ArmOutcome::Armed(epoch) => format!("armed:{epoch:08x}"),
                lockdown::ArmOutcome::Unchanged(epoch) => format!("armed-unchanged:{epoch:08x}"),
            })
        }
        ["LOCKDOWN_TRIGGER", source, reason, flags] => {
            let source = parse_lockdown_source(source)?;
            let reason = parse_lockdown_reason(reason)?;
            let flags = parse_lockdown_flags(flags)?;
            let epoch = core.trigger(source, reason, flags)?;
            Ok(format!(
                "triggered:{epoch:08x};phases={};unsupported={}",
                lockdown_applied_csv(core),
                lockdown_unsupported_csv(core)
            ))
        }
        ["LOCKDOWN_CLEAR", expected_epoch, reason] => {
            let expected_epoch = parse_lockdown_epoch(expected_epoch)?;
            let reason = parse_lockdown_reason(reason)?;
            Ok(match core.clear(expected_epoch, reason)? {
                lockdown::ClearOutcome::Cleared => "cleared".to_owned(),
                lockdown::ClearOutcome::AlreadyOff => "already-off".to_owned(),
            })
        }
        ["LOCKDOWN_SET_MODE", mode] => {
            core.set_mode(ArmMode::from_token(mode).ok_or("unknown lockdown mode token")?)?;
            Ok("applied".to_owned())
        }
        ["LOCKDOWN_EVENTS"] => lockdown_events(core),
        ["LOCKDOWN_HEALTH"] => lockdown_health(core),
        // Kernel-lockdown is an immutable boot parameter (Phase 1 honest limit).
        ["LOCKDOWN_PHASE", "kernel-lockdown", "on" | "off"] => {
            Ok(format!("unsupported:kernel-lockdown:{LOCKDOWN_KERNEL_LOCKDOWN_REASON}"))
        }
        ["LOCKDOWN_PHASE", phase, state] => {
            let phase = parse_lockdown_phase(phase).ok_or("unknown lockdown phase token")?;
            let on = match *state {
                "on" => true,
                "off" => false,
                _ => return Err("unknown lockdown phase state".into()),
            };
            let name = lockdown_phase_token(phase).ok_or("unknown lockdown phase token")?;
            Ok(match core.phase(phase, on)? {
                lockdown::PhaseOutcome::Applied => format!("applied:{name}"),
                lockdown::PhaseOutcome::Unsupported(reason) => {
                    format!("unsupported:{name}:{reason}")
                }
                lockdown::PhaseOutcome::Failed(reason) => format!("failed:{name}:{reason}"),
            })
        }
        _ => Err("unknown command".into()),
    }
}

// --- §5 state file `epoch|mode|flags|phases|ts` (§5 Core-Zustand) ------------

/// One persisted applied phase (read back by startup re-arm).
pub(crate) struct LoadedPhase {
    pub(crate) phase: u8,
}

pub(crate) enum LockdownStateLoad {
    Absent,
    Corrupt,
    Valid(LockdownPersisted),
}

pub(crate) struct LockdownPersisted {
    pub(crate) epoch: u32,
    pub(crate) mode: ArmMode,
    pub(crate) flags: u8,
    pub(crate) phases: Vec<LoadedPhase>,
}

pub(crate) fn unix_seconds_now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|value| value.as_secs()).unwrap_or(0)
}

pub(crate) fn lockdown_state_content(core: &lockdown::LockdownCore) -> String {
    let phases: Vec<&str> = core
        .applied_phases()
        .iter()
        .filter_map(|entry| lockdown_phase_token(entry.phase))
        .collect();
    format!(
        "{:08x}|{}|{:02x}|{}|{}",
        core.epoch(),
        core.arm_mode().token(),
        core.policy_flags(),
        if phases.is_empty() { "-".to_owned() } else { phases.join(",") },
        unix_seconds_now()
    )
}

/// Atomic 0640 write of the §5 state file (same-directory temp + rename).
pub(crate) fn write_lockdown_state_atomic(path: &Path, content: &str) -> Result<(), String> {
    let directory = path.parent().ok_or("state file directory missing")?;
    fs::create_dir_all(directory).map_err(|_| "state directory create failed".to_owned())?;
    let temporary = directory.join(format!(".LOCKDOWN.state.{}.tmp", std::process::id()));
    let _ = fs::remove_file(&temporary);
    let write = || -> Result<(), String> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o640)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(&temporary)
            .map_err(|_| "state file create failed".to_owned())?;
        fs::set_permissions(&temporary, fs::Permissions::from_mode(0o640))
            .map_err(|_| "state file permissions failed".to_owned())?;
        file.write_all(content.as_bytes()).map_err(|_| "state file write failed".to_owned())?;
        file.write_all(b"\n").map_err(|_| "state file write failed".to_owned())?;
        file.sync_all().map_err(|_| "state file sync failed".to_owned())?;
        drop(file);
        fs::rename(&temporary, path).map_err(|_| "state file rename failed".to_owned())?;
        if let Ok(directory) = File::open(directory) {
            let _ = directory.sync_all();
        }
        Ok(())
    };
    let result = write();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

pub(crate) fn persist_lockdown_state(core: &lockdown::LockdownCore) -> Result<(), String> {
    write_lockdown_state_atomic(core.state_file(), &lockdown_state_content(core))
}

/// Strict state-file parse: any unreadable/foreign content is `Corrupt`
/// (fail-closed latch), never a silent `off`.
pub(crate) fn load_lockdown_state(path: &Path) -> LockdownStateLoad {
    let bytes = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return LockdownStateLoad::Absent,
        Err(_) => return LockdownStateLoad::Corrupt,
    };
    if bytes.len() > 256 {
        return LockdownStateLoad::Corrupt;
    }
    let Ok(text) = std::str::from_utf8(&bytes) else { return LockdownStateLoad::Corrupt };
    let fields: Vec<&str> = text.trim_end().split('|').collect();
    if fields.len() != 5 {
        return LockdownStateLoad::Corrupt;
    }
    let Ok(epoch) = parse_lockdown_epoch(fields[0]) else { return LockdownStateLoad::Corrupt };
    let Some(mode) = ArmMode::from_token(fields[1]) else { return LockdownStateLoad::Corrupt };
    if fields[2].len() != 2 {
        return LockdownStateLoad::Corrupt;
    }
    let Ok(flags) = u8::from_str_radix(fields[2], 16) else { return LockdownStateLoad::Corrupt };
    if flags & !lockdown::POLICY_FLAGS_KNOWN != 0 || fields[4].parse::<u64>().is_err() {
        return LockdownStateLoad::Corrupt;
    }
    let mut phases = Vec::new();
    let mut seen = [0u8; lockdown::PHASE_COUNT];
    if fields[3] != "-" {
        for token in fields[3].split(',') {
            let Some(phase) = parse_lockdown_phase(token) else {
                return LockdownStateLoad::Corrupt;
            };
            if seen[phase as usize] != 0 {
                return LockdownStateLoad::Corrupt;
            }
            seen[phase as usize] = 1;
            phases.push(LoadedPhase { phase });
        }
    }
    LockdownStateLoad::Valid(LockdownPersisted { epoch, mode, flags, phases })
}

// --- eBPF adapters for the lockdown core ------------------------------------

/// `LOCKDOWN_STATE` array-map handle: interior mutability because the command
/// surface and the uevent monitor thread both need verified writes.
pub(crate) struct AyaLockdownWordStore {
    pub(crate) map: Mutex<AyaArray<MapData, u64>>,
}

impl lockdown::LockdownWordStore for AyaLockdownWordStore {
    fn write(&self, word: u64) -> Result<(), String> {
        let mut map = self.map.lock().map_err(|_| "LOCKDOWN_STATE lock".to_owned())?;
        map.set(0, word, 0).map_err(|error| error.to_string())
    }
    fn read(&self) -> Result<u64, String> {
        let map = self.map.lock().map_err(|_| "LOCKDOWN_STATE lock".to_owned())?;
        map.get(&0, 0).map_err(|error| error.to_string())
    }
}

/// §5 health: saturating per-CPU sums of the two lockdown counters.
pub(crate) struct LiveLockdownCounters {
    pub(crate) drops: PerCpuArray<MapData, u64>,
    pub(crate) witness_passes: PerCpuArray<MapData, u64>,
}

impl LiveLockdownCounters {
    pub(crate) fn sum(counter: &PerCpuArray<MapData, u64>) -> Result<u64, String> {
        let values = counter.get(&0, 0).map_err(|error| error.to_string())?;
        Ok(values.iter().copied().fold(0u64, |sum, value| sum.saturating_add(value)))
    }
}

impl lockdown::NetCounters for LiveLockdownCounters {
    fn net_counters(&self) -> Result<(u64, u64), String> {
        Ok((Self::sum(&self.drops)?, Self::sum(&self.witness_passes)?))
    }
}

pub(crate) fn dispatch(
    core: &mut KernelCore,
    parts: &[&str],
) -> Result<Option<String>, BoxError> {
    let result = match parts {
        // Point 5 (§5): the lock-down command surface is dispatched by the
        // crate-root ABI layer; unknown LOCKDOWN_* names stay ERR.
        [command, ..] if command.starts_with("LOCKDOWN_") => {
            lockdown_command(&mut core.lockdown, parts)
        }
        _ => return Ok(None),
    };
    Ok(Some(result?))
}
