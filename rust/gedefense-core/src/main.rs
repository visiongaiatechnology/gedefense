use aya::{
    maps::{
        lpm_trie::{Key, LpmTrie},
        Array as AyaArray, HashMap as AyaHashMap, Map, MapData, MapError, PerCpuArray, RingBuf,
    },
    programs::{
        tc, CgroupAttachMode, CgroupSkb, CgroupSkbAttachType, Lsm, SchedClassifier, TcAttachType,
        TracePoint, Xdp, XdpMode,
    },
    Btf, Ebpf,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use gedefense_common::{
    decode_ingress_event, decode_styx_flow_event, decode_titan_exec_event, CellLsmDenyEvent,
    EgressDropEvent, ExecEvent, ACTION_DROP, CELL_LSM_DENY_ALL_KNOWN,
    EXEC_COMM_BYTES, NETWORK_ADDRESS_BYTES, NETWORK_FAMILY_V4, NETWORK_FAMILY_V6,
    STYX_FLOW_EVENT_WIRE_BYTES, STYX_MODE_OFF, TITAN_EXEC_EVENT_WIRE_BYTES,
    TITAN_EXEC_MODE_OFF, TITAN_EXEC_OFFSETS_ABI, TITAN_EXEC_OFFSETS_MAGIC, TITAN_EXEC_SCOPE_FLAG_JIT_ALLOW,
    TITAN_EXEC_STATE_ABI, TITAN_EXEC_STATE_MAGIC,
};
use hmac::{Hmac, Mac};
use sha2::Sha256;
mod archive_deflate;
mod archive_gzip;
mod archive_scan;
mod archive_tar;
mod archive_zip;
#[cfg(test)]
mod archive_tests;
mod btf_offsets;
mod btf_validate;
mod canary;
mod lockdown;
mod lockdown_brokers;
mod lockdown_hardening;
mod lockdown_uevent;
mod lockdown_usb;
mod malware;
mod on_write;
mod on_write_policy;
#[cfg(test)]
mod on_write_tests;
mod process_control;
mod process_tree;
#[cfg(test)]
mod process_tree_tests;
mod quarantine;
mod credential_guard;
#[cfg(test)]
mod credential_guard_tests;
mod ransom;
#[cfg(test)]
mod ransom_tests;
mod styx_flow;
mod titan_exec;
mod titan_status;
mod worker_guard;
mod xdr_kernel;
use canary::{collect_canary_roots, CanaryBroker};
use malware::{handle_user_scan, MalwareScanner};
#[cfg(test)]
use process_control::valid_rule_token;
use process_control::{lookup_identity, peer_uid, pidfd_signal};
use quarantine::{FileIdentity, QuarantineBroker};
use std::{
    collections::{HashSet, VecDeque},
    env,
    error::Error,
    ffi::CString,
    fs::{self, File, OpenOptions},
    io::{BufRead, BufReader, Read, Write},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    os::unix::{
        ffi::OsStrExt,
        fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
        net::{UnixListener, UnixStream},
    },
    path::Path,
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc, Mutex,
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

type BoxError = Box<dyn Error + Send + Sync + 'static>;
type HmacSha256 = Hmac<Sha256>;

const PROTOCOL: &str = "VGT3";
const MAX_REQUEST_BYTES: u64 = 4096;
// Response ceiling for the authenticated IPC wire (busybox-sized multi-record
// batches such as the 64-record StyX flow drain are the reason this is not
// 2048 anymore). The bound is enforced before the base64 URL encoding, so the
// control-plane reader limit (`maxCoreResponseBytes` in control/coreipc.go)
// must cover base64url(MAX_RESPONSE_BYTES) plus the protocol line overhead;
// the Go side is updated with the same StyX batch/payload limits.
const MAX_RESPONSE_BYTES: usize = 24 * 1024;
const CLOCK_WINDOW_SECS: u64 = 30;
// A request timestamp may lead the local clock by at most this much.
//
// The previous `|now - stamp| <= CLOCK_WINDOW_SECS` check accepted timestamps up
// to a full window in the future. The nonce was cached against the arrival time
// and evicted one window later, while such a future timestamp stayed valid for
// another window after that: a captured request could be replayed in
// [t + window + 1, t + 2 * window]. The tolerated future skew is therefore tiny
// (the control plane and the core share one host clock), and the nonce entry is
// keyed to the later of arrival and request time.
const CLOCK_FUTURE_TOLERANCE_SECS: u64 = 5;
const REPLAY_CACHE_CAPACITY: usize = 4096;
const MAX_EXEC_EVENTS_PER_RESPONSE: usize = 24;
const MAX_EGRESS_EVENTS_PER_RESPONSE: usize = 24;
const MAX_INGRESS_EVENTS_PER_RESPONSE: usize = 12;
// How many undecodable ingress samples in a single drain mean the wire format itself is wrong.
//
// One such sample is a loss of fidelity and is skipped; a batch full of them is a real fault, and
// the control plane has to be told so the operator sees a sensor that receives nothing instead of
// a sensor that looks healthy. The threshold is far above the sporadic rate a busy host produces,
// so it cannot be tripped by ordinary mixed-protocol aggregates.
const INGRESS_REJECTED_ALARM_THRESHOLD: u64 = 16;
const MAX_CELL_LSM_EVENTS_PER_RESPONSE: usize = 24;
// §4 mandatory-veto seed: metadata/link-local/multicast/unspecified ranges that
// must be blocked from the moment the core is online (127/8 and ::1 stay out so
// loopback keeps working; the IPv6 ND exception is implemented in the kernel
// program and applies on top of this list).
const STYX_MANDATORY_VETO_V4: &[(u32, [u8; 4])] = &[
    (16, [169, 254, 0, 0]),
    (32, [100, 100, 100, 200]),
    (32, [168, 63, 129, 16]),
    (32, [192, 0, 0, 192]),
    (8, [0, 0, 0, 0]),
    (4, [224, 0, 0, 0]),
];
const STYX_MANDATORY_VETO_V6: &[(u32, [u8; 16])] = &[
    (128, [0xfd, 0x00, 0x0e, 0xc2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02, 0x54]),
    (10, [0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
    (8, [0xff, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
];
// F-04: one canonical persistence path. The product contract (BETA-TEST-PLAN,
// READMEs) names 90-vgt-gedefense.conf; read, create, replace, rollback and
// migration all derive from these constants so they can never diverge again.
const HARDENING_DIRECTORY: &str = "/etc/sysctl.d";
const HARDENING_FILE_NAME: &str = "90-vgt-gedefense.conf";
const HARDENING_TEMPORARY_PREFIX: &str = ".90-vgt-gedefense.conf.";
// Files written by earlier builds/attempts. They sort after the canonical file
// and would win at boot, so they are migrated or reconciled, never ignored.
const LEGACY_HARDENING_FILE_NAMES: &[&str] =
    &["99-zzz-vgt-gedefense.conf", "99-vgt-gedefense.conf"];
const RENAME_NOREPLACE: u32 = 1;
const RENAME_EXCHANGE: u32 = 2;

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
struct LockdownEventQueue {
    records: VecDeque<LockdownEvent>,
    seq: u64,
    dropped: u64,
    reported: u64,
}

impl LockdownEventQueue {
    fn push(&mut self, epoch: u32, source: u8, reason: u8, phase: u8, outcome: u8, detail: u64) {
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
    fn take(&mut self, max: usize) -> (u64, Vec<LockdownEvent>) {
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

const LOCKDOWN_EVENT_QUEUE_CAPACITY: usize = 64;

/// State shared between the command surface and the uevent monitor thread.
pub(crate) struct LockdownShared {
    pub(crate) word: Arc<dyn lockdown::LockdownWordStore>,
    events: Mutex<LockdownEventQueue>,
    policy: Mutex<UeventPolicy>,
    /// Set once a hotplug auto-drop wrote `LOCKDOWN_FLAG_DROP_ALL`; keeps the
    /// flag owned by the shared state instead of only by the kernel word, so a
    /// later phase refresh cannot silently clear the drop.
    auto_drop: AtomicBool,
    uevent_events: AtomicU64,
    usb_blocks: AtomicU64,
    tb_blocks: AtomicU64,
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

const LOCKDOWN_PHASE_TOKENS: &[(u8, &str)] = &[
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

const LOCKDOWN_REASON_TOKENS: &[(&str, u8)] = &[
    ("manual", LOCKDOWN_REASON_MANUAL),
    ("usb-unknown", LOCKDOWN_REASON_USB_UNKNOWN),
    ("tb-unknown", LOCKDOWN_REASON_TB_UNKNOWN),
    ("screen-lock", LOCKDOWN_REASON_SCREEN_LOCK),
    ("tamper", LOCKDOWN_REASON_TAMPER),
    ("xdr-critical", LOCKDOWN_REASON_XDR_CRITICAL),
    ("boot-trust-drift", LOCKDOWN_REASON_BOOT_TRUST_DRIFT),
    ("policy", LOCKDOWN_REASON_POLICY),
];

const LOCKDOWN_SOURCE_TOKENS: &[(&str, u8)] = &[
    ("manual", LOCKDOWN_SOURCE_MANUAL),
    ("uevent", LOCKDOWN_SOURCE_UEVENT),
    ("policy", LOCKDOWN_SOURCE_POLICY),
    ("timer", LOCKDOWN_SOURCE_TIMER),
];

fn lockdown_phase_token(phase: u8) -> Option<&'static str> {
    LOCKDOWN_PHASE_TOKENS.iter().find(|(value, _)| *value == phase).map(|(_, token)| *token)
}

fn parse_lockdown_phase(token: &str) -> Option<u8> {
    LOCKDOWN_PHASE_TOKENS.iter().find(|(_, name)| *name == token).map(|(value, _)| *value)
}

fn parse_lockdown_reason(token: &str) -> Result<u8, BoxError> {
    LOCKDOWN_REASON_TOKENS
        .iter()
        .find(|(name, _)| *name == token)
        .map(|(_, value)| *value)
        .ok_or_else(|| "unknown lockdown reason token".into())
}

fn parse_lockdown_source(token: &str) -> Result<u8, BoxError> {
    LOCKDOWN_SOURCE_TOKENS
        .iter()
        .find(|(name, _)| *name == token)
        .map(|(_, value)| *value)
        .ok_or_else(|| "unknown lockdown source token".into())
}

fn parse_lockdown_flags(token: &str) -> Result<u8, BoxError> {
    let flags = token.parse::<u8>().map_err(|_| "invalid lockdown policy flags")?;
    if flags & !lockdown::POLICY_FLAGS_KNOWN != 0 {
        return Err("unknown lockdown policy flag".into());
    }
    Ok(flags)
}

fn parse_lockdown_epoch(token: &str) -> Result<u32, BoxError> {
    if token.len() != 8 || !token.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("invalid lockdown epoch".into());
    }
    u32::from_str_radix(token, 16).map_err(|_| "invalid lockdown epoch".into())
}

// --- §5 ABI answers ---------------------------------------------------------

/// §5 `LOCKDOWN_STATUS` exact wire format.
fn lockdown_status(core: &lockdown::LockdownCore) -> String {
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
fn lockdown_applied_csv(core: &lockdown::LockdownCore) -> String {
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
fn lockdown_unsupported_csv(core: &lockdown::LockdownCore) -> String {
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
fn lockdown_events(core: &mut lockdown::LockdownCore) -> Result<String, BoxError> {
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
fn lockdown_health(core: &lockdown::LockdownCore) -> Result<String, BoxError> {
    let (net_drops, witness_passes) =
        core.net_counters().map_err(|error| -> BoxError { error.into() })?;
    let (uevent_events, usb_blocks, tb_blocks) = core.uevent_counters();
    Ok(format!(
        "{net_drops}:{witness_passes}:{uevent_events}:{usb_blocks}:{tb_blocks}:{}",
        core.broker_frozen()
    ))
}

/// §5 dispatch for every `LOCKDOWN_*` command; unknown names stay ERR.
const LOCKDOWN_KERNEL_LOCKDOWN_REASON: &str = "boot-parameter-immutable";
fn lockdown_command(core: &mut lockdown::LockdownCore, parts: &[&str]) -> Result<String, BoxError> {
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

fn unix_seconds_now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|value| value.as_secs()).unwrap_or(0)
}

fn lockdown_state_content(core: &lockdown::LockdownCore) -> String {
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
fn write_lockdown_state_atomic(path: &Path, content: &str) -> Result<(), String> {
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
struct AyaLockdownWordStore {
    map: Mutex<AyaArray<MapData, u64>>,
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
struct LiveLockdownCounters {
    drops: PerCpuArray<MapData, u64>,
    witness_passes: PerCpuArray<MapData, u64>,
}

impl LiveLockdownCounters {
    fn sum(counter: &PerCpuArray<MapData, u64>) -> Result<u64, String> {
        let values = counter.get(&0, 0).map_err(|error| error.to_string())?;
        Ok(values.iter().copied().fold(0u64, |sum, value| sum.saturating_add(value)))
    }
}

impl lockdown::NetCounters for LiveLockdownCounters {
    fn net_counters(&self) -> Result<(u64, u64), String> {
        Ok((Self::sum(&self.drops)?, Self::sum(&self.witness_passes)?))
    }
}

const HARDENING_SERVER: &str =
    "# Managed atomically by VGT GeDefense. Manual edits are rejected.\n\
fs.protected_fifos = 2\n\
fs.protected_regular = 2\n\
fs.suid_dumpable = 0\n\
kernel.dmesg_restrict = 1\n\
kernel.kptr_restrict = 2\n\
kernel.randomize_va_space = 2\n\
net.ipv4.conf.all.accept_redirects = 0\n\
net.ipv4.conf.all.log_martians = 1\n\
net.ipv4.conf.all.rp_filter = 1\n\
net.ipv4.conf.all.send_redirects = 0\n\
net.ipv4.conf.default.accept_redirects = 0\n\
net.ipv4.conf.default.log_martians = 1\n\
net.ipv4.conf.default.rp_filter = 1\n\
net.ipv4.conf.default.send_redirects = 0\n\
net.ipv4.icmp_echo_ignore_broadcasts = 1\n\
net.ipv4.icmp_ignore_bogus_error_responses = 1\n\
net.ipv4.tcp_syncookies = 1\n\
net.ipv6.conf.all.accept_redirects = 0\n\
net.ipv6.conf.default.accept_redirects = 0\n";

const HARDENING_ASTRAEAOS: &str =
    "# Managed atomically by VGT GeDefense. Manual edits are rejected.\n\
fs.protected_fifos = 2\n\
fs.protected_regular = 2\n\
fs.suid_dumpable = 0\n\
kernel.dmesg_restrict = 1\n\
kernel.kptr_restrict = 2\n\
kernel.randomize_va_space = 2\n\
kernel.unprivileged_bpf_disabled = 1\n\
kernel.yama.ptrace_scope = 2\n\
net.ipv4.conf.all.accept_redirects = 0\n\
net.ipv4.conf.all.log_martians = 1\n\
net.ipv4.conf.all.rp_filter = 1\n\
net.ipv4.conf.all.send_redirects = 0\n\
net.ipv4.conf.default.accept_redirects = 0\n\
net.ipv4.conf.default.log_martians = 1\n\
net.ipv4.conf.default.rp_filter = 1\n\
net.ipv4.conf.default.send_redirects = 0\n\
net.ipv4.icmp_echo_ignore_broadcasts = 1\n\
net.ipv4.icmp_ignore_bogus_error_responses = 1\n\
net.ipv4.tcp_syncookies = 1\n\
net.ipv6.conf.all.accept_redirects = 0\n\
net.ipv6.conf.default.accept_redirects = 0\n\
dev.tty.ldisc_autoload = 0\n\
vm.swappiness = 10\n";

// 6.1.x persisted-profile compatibility. Upgrades must keep recognizing the
// file written by the previous release so the first 6.2.0 HARDENING_GET does
// not fail closed; the next apply rewrites the canonical 6.2 content above.
const LEGACY_HARDENING_SERVER: &str =
    "# Managed atomically by VGT GeDefense. Manual edits are rejected.\n\
fs.protected_fifos = 2\n\
fs.protected_regular = 2\n\
fs.suid_dumpable = 0\n\
kernel.dmesg_restrict = 1\n\
kernel.kptr_restrict = 2\n\
kernel.randomize_va_space = 2\n\
net.ipv4.conf.all.accept_redirects = 0\n\
net.ipv4.conf.all.send_redirects = 0\n\
net.ipv4.conf.default.accept_redirects = 0\n\
net.ipv4.conf.default.send_redirects = 0\n\
net.ipv4.tcp_syncookies = 1\n\
net.ipv6.conf.all.accept_redirects = 0\n\
net.ipv6.conf.default.accept_redirects = 0\n";
const LEGACY_HARDENING_ASTRAEAOS: &str =
    "# Managed atomically by VGT GeDefense. Manual edits are rejected.\n\
fs.protected_fifos = 2\n\
fs.protected_regular = 2\n\
fs.suid_dumpable = 0\n\
kernel.dmesg_restrict = 1\n\
kernel.kptr_restrict = 2\n\
kernel.randomize_va_space = 2\n\
kernel.unprivileged_bpf_disabled = 1\n\
kernel.yama.ptrace_scope = 2\n\
net.ipv4.conf.all.accept_redirects = 0\n\
net.ipv4.conf.all.send_redirects = 0\n\
net.ipv4.conf.default.accept_redirects = 0\n\
net.ipv4.conf.default.send_redirects = 0\n\
net.ipv4.tcp_syncookies = 1\n\
net.ipv6.conf.all.accept_redirects = 0\n\
net.ipv6.conf.default.accept_redirects = 0\n";

/// Complete CIS/Lynis Level-1 profile (M5.1, 6.2.0). It is intentionally
/// opt-in and matches the control set of `astraeaos-cis-l1` in the Go
/// `hardening_sysctl.go` catalogue, including the new CIS keys.
const HARDENING_CIS_L1: &str =
    "# Managed atomically by VGT GeDefense. Manual edits are rejected.\n\
dev.tty.ldisc_autoload = 0\n\
fs.protected_fifos = 2\n\
fs.protected_hardlinks = 1\n\
fs.protected_regular = 2\n\
fs.protected_symlinks = 1\n\
fs.suid_dumpable = 0\n\
kernel.dmesg_restrict = 1\n\
kernel.kptr_restrict = 2\n\
kernel.perf_event_paranoid = 3\n\
kernel.randomize_va_space = 2\n\
kernel.sysrq = 0\n\
kernel.unprivileged_bpf_disabled = 1\n\
kernel.yama.ptrace_scope = 2\n\
net.ipv4.conf.all.accept_redirects = 0\n\
net.ipv4.conf.all.log_martians = 1\n\
net.ipv4.conf.all.rp_filter = 1\n\
net.ipv4.conf.all.send_redirects = 0\n\
net.ipv4.conf.default.accept_redirects = 0\n\
net.ipv4.conf.default.log_martians = 1\n\
net.ipv4.conf.default.rp_filter = 1\n\
net.ipv4.conf.default.send_redirects = 0\n\
net.ipv4.icmp_echo_ignore_broadcasts = 1\n\
net.ipv4.icmp_ignore_bogus_error_responses = 1\n\
net.ipv4.tcp_syncookies = 1\n\
net.ipv6.conf.all.accept_redirects = 0\n\
net.ipv6.conf.default.accept_redirects = 0\n";

/// M5.1 grows the custom identity space from 10 to 21 control bits. The Go
/// catalogue uses the same maximum (`0x1f_ffff`); an unknown high bit must be
/// rejected rather than silently ignored.
const HARDENING_CUSTOM_MASK: u32 = 0x001f_ffff;

fn hardening_content(profile: &str) -> Option<String> {
    match profile {
        "linux-server-balanced" => Some(HARDENING_SERVER.to_owned()),
        "astraeaos-workstation-strict" => Some(HARDENING_ASTRAEAOS.to_owned()),
        "astraeaos-cis-l1" => Some(HARDENING_CIS_L1.to_owned()),
        _ => custom_hardening_content(profile),
    }
}

fn custom_hardening_content(profile: &str) -> Option<String> {
    let encoded = profile.strip_prefix("astraeaos-custom-")?;
    // Go emits `%04x`, therefore a 21-bit mask has four to six hex digits
    // (`0001` … `1fffff`). Anything shorter/longer is not a Go-produced
    // profile and must not reach a persistent sysctl file.
    if !(4..=6).contains(&encoded.len()) || !encoded.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    let mask = u32::from_str_radix(encoded, 16).ok()?;
    if mask == 0 || mask & !HARDENING_CUSTOM_MASK != 0 {
        return None;
    }
    let mut content = format!(
        "# Managed atomically by VGT GeDefense. Manual edits are rejected.\n# Profile: {profile}\n"
    );
    let controls: &[(u32, &[(&str, &str)])] = &[
        (1 << 0, &[("kernel.randomize_va_space", "2")]),
        (1 << 1, &[("kernel.kptr_restrict", "2")]),
        (1 << 2, &[("kernel.dmesg_restrict", "1")]),
        (1 << 3, &[("kernel.yama.ptrace_scope", "2")]),
        (1 << 4, &[("kernel.unprivileged_bpf_disabled", "1")]),
        (
            1 << 5,
            &[("fs.protected_fifos", "2"), ("fs.protected_regular", "2")],
        ),
        (1 << 6, &[("fs.suid_dumpable", "0")]),
        (1 << 7, &[("net.ipv4.tcp_syncookies", "1")]),
        (
            1 << 8,
            &[
                ("net.ipv4.conf.all.accept_redirects", "0"),
                ("net.ipv4.conf.all.send_redirects", "0"),
                ("net.ipv4.conf.default.accept_redirects", "0"),
                ("net.ipv4.conf.default.send_redirects", "0"),
            ],
        ),
        (
            1 << 9,
            &[
                ("net.ipv6.conf.all.accept_redirects", "0"),
                ("net.ipv6.conf.default.accept_redirects", "0"),
            ],
        ),
        (1 << 10, &[("kernel.unprivileged_userns_clone", "0")]),
        (
            1 << 11,
            &[
                ("net.ipv4.conf.all.rp_filter", "1"),
                ("net.ipv4.conf.default.rp_filter", "1"),
            ],
        ),
        (
            1 << 12,
            &[
                ("net.ipv4.conf.all.log_martians", "1"),
                ("net.ipv4.conf.default.log_martians", "1"),
            ],
        ),
        (
            1 << 13,
            &[
                ("net.ipv4.icmp_echo_ignore_broadcasts", "1"),
                ("net.ipv4.icmp_ignore_bogus_error_responses", "1"),
            ],
        ),
        (1 << 14, &[("fs.protected_hardlinks", "1")]),
        (1 << 15, &[("fs.protected_symlinks", "1")]),
        (1 << 16, &[("kernel.sysrq", "0")]),
        (1 << 17, &[("kernel.perf_event_paranoid", "3")]),
        (1 << 18, &[("dev.tty.ldisc_autoload", "0")]),
        (1 << 19, &[("vm.swappiness", "10")]),
        (
            1 << 20,
            &[
                ("net.ipv6.conf.all.disable_ipv6", "1"),
                ("net.ipv6.conf.default.disable_ipv6", "1"),
            ],
        ),
    ];
    let mut values = Vec::new();
    for (bit, entries) in controls {
        if mask & bit != 0 {
            values.extend_from_slice(entries);
        }
    }
    values.sort_unstable_by_key(|(key, _)| *key);
    for (key, value) in values {
        content.push_str(key);
        content.push_str(" = ");
        content.push_str(value);
        content.push('\n');
    }
    Some(content)
}

fn recognized_hardening_state(content: &str) -> Option<String> {
    // 6.1.x files stay recognized for upgrade; the next apply writes the new
    // canonical content and extends the persistent policy with M5.1 controls.
    if content == LEGACY_HARDENING_SERVER {
        return Some("linux-server-balanced".to_owned());
    }
    if content == LEGACY_HARDENING_ASTRAEAOS {
        return Some("astraeaos-workstation-strict".to_owned());
    }
    for profile in [
        "linux-server-balanced",
        "astraeaos-workstation-strict",
        "astraeaos-cis-l1",
    ] {
        if hardening_content(profile).as_deref() == Some(content) {
            return Some(profile.to_owned());
        }
    }
    let profile = content
        .lines()
        .find_map(|line| line.strip_prefix("# Profile: "))?;
    if hardening_content(profile).as_deref() == Some(content) {
        return Some(profile.to_owned());
    }
    None
}

// Reads a GeDefense-managed hardening file through an O_NOFOLLOW descriptor.
// Ok(None) means the file does not exist; an existing file that is unreadable,
// oversized or not managed by GeDefense is an error and never treated as state.
fn read_managed_hardening_file(path: &Path) -> Result<Option<String>, BoxError> {
    let mut file = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) if error.raw_os_error() == Some(libc::ELOOP) => {
            return Err(format!(
                "persistent hardening state {} must not be a symlink",
                path.display()
            )
            .into())
        }
        Err(error) => return Err(error.into()),
    };
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() > 4096 {
        return Err("persistent hardening state is not a bounded regular file".into());
    }
    let mut content = String::with_capacity(metadata.len() as usize);
    file.read_to_string(&mut content)?;
    recognized_hardening_state(&content)
        .map(Some)
        .ok_or_else(|| {
            format!(
                "persistent hardening state {} is not managed by GeDefense",
                path.display()
            )
            .into()
        })
}

fn hardening_directory() -> std::path::PathBuf {
    std::path::PathBuf::from(HARDENING_DIRECTORY)
}

fn hardening_canonical_path(directory: &Path) -> std::path::PathBuf {
    directory.join(HARDENING_FILE_NAME)
}

// Removes temporary files left behind by an interrupted compare-set. This is
// what prevents a crashed writer from accumulating unmanaged .90-* strays.
fn cleanup_hardening_temporary_files(directory: &Path) -> Result<(), BoxError> {
    let entries = match fs::read_dir(directory) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    for entry in entries {
        let entry = entry?;
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        if name.starts_with(HARDENING_TEMPORARY_PREFIX) {
            match fs::remove_file(entry.path()) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
        }
    }
    Ok(())
}

fn remove_managed_legacy_file(directory: &Path, name: &str) -> Result<(), BoxError> {
    let path = directory.join(name);
    match fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

// F-04 state machine: the canonical file is authoritative. A legacy file is
// migrated when the canonical file is absent, accepted-and-removed when the
// canonical file already carries the same managed state, and any unmanaged or
// ambiguous stray fails closed instead of silently overriding the profile.
fn hardening_file_state_in(directory: &Path) -> Result<String, BoxError> {
    let canonical = hardening_canonical_path(directory);
    let canonical_state = read_managed_hardening_file(&canonical)?;
    let mut legacy: Vec<(&'static str, String)> = Vec::new();
    for name in LEGACY_HARDENING_FILE_NAMES {
        if let Some(state) = read_managed_hardening_file(&directory.join(name))? {
            legacy.push((name, state));
        }
    }

    if let Some(state) = canonical_state {
        // Canonical state exists: reconcile every managed legacy stray so it can
        // never sort after (and override) the canonical file at boot.
        for (name, _) in &legacy {
            remove_managed_legacy_file(directory, name)?;
        }
        return Ok(state);
    }

    match legacy.len() {
        0 => Ok("absent".to_owned()),
        1 => {
            let (name, state) = &legacy[0];
            let name = *name;
            let state = state.clone();
            let directory_file = File::open(directory)?;
            let directory_fd = std::os::fd::AsRawFd::as_raw_fd(&directory_file);
            let from = CString::new(name)?;
            let to = CString::new(HARDENING_FILE_NAME)?;
            match renameat2_names(directory_fd, &from, &to, RENAME_NOREPLACE) {
                Ok(()) => {
                    directory_file.sync_all()?;
                    Ok(state)
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    // A concurrent writer created the canonical file between the
                    // two reads. Re-read it and reconcile the now-stale legacy file.
                    let state = read_managed_hardening_file(&hardening_canonical_path(directory))?
                        .ok_or(
                            "persistent hardening canonical state disappeared during migration",
                        )?;
                    remove_managed_legacy_file(directory, name)?;
                    Ok(state)
                }
                Err(error) => Err(format!(
                    "persistent hardening legacy migration failed for {}: {error}",
                    name
                )
                .into()),
            }
        }
        _ => Err("multiple legacy persistent hardening files present; refusing to guess".into()),
    }
}

fn hardening_file_state() -> Result<String, BoxError> {
    let directory = hardening_directory();
    let state = hardening_file_state_in(&directory)?;
    cleanup_hardening_temporary_files(&directory)?;
    Ok(state)
}

fn hardening_temp_name() -> Result<CString, BoxError> {
    let mut random = [0u8; 8];
    File::open("/dev/urandom")?.read_exact(&mut random)?;
    Ok(CString::new(format!(
        "{HARDENING_TEMPORARY_PREFIX}{}.{}",
        std::process::id(),
        hex::encode(random)
    ))?)
}

fn renameat2_names(
    directory_fd: i32,
    from: &CString,
    to: &CString,
    flags: u32,
) -> Result<(), std::io::Error> {
    let result = unsafe {
        libc::syscall(
            libc::SYS_renameat2,
            directory_fd,
            from.as_ptr(),
            directory_fd,
            to.as_ptr(),
            flags,
        )
    };
    if result != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

fn compare_set_hardening_file(expected: &str, desired: &str) -> Result<String, BoxError> {
    compare_set_hardening_file_in(&hardening_directory(), expected, desired)
}

// Single canonical compare-set implementation for GET/SET/rollback. Tests run it
// against a temporary directory; production always uses /etc/sysctl.d.
fn compare_set_hardening_file_in(
    directory: &Path,
    expected: &str,
    desired: &str,
) -> Result<String, BoxError> {
    if expected != "absent" && hardening_content(expected).is_none() {
        return Err("persistent hardening expected state is invalid".into());
    }
    if desired != "absent" && hardening_content(desired).is_none() {
        return Err("persistent hardening desired state is invalid".into());
    }
    // Migration/reconciliation happens before the compare so a stale legacy file
    // and its canonical successor are never observed as two different states.
    cleanup_hardening_temporary_files(directory)?;
    if hardening_file_state_in(directory)? != expected {
        return Err("persistent hardening compare-set precondition failed".into());
    }
    if expected == desired {
        return Ok(desired.to_owned());
    }
    let directory_file = File::open(directory)?;
    let directory_fd = std::os::fd::AsRawFd::as_raw_fd(&directory_file);
    let target_name = CString::new(HARDENING_FILE_NAME)?;
    let temporary_name = hardening_temp_name()?;
    let temporary_path = directory.join(std::ffi::OsStr::from_bytes(temporary_name.as_bytes()));

    if desired == "absent" {
        renameat2_names(
            directory_fd,
            &target_name,
            &temporary_name,
            RENAME_NOREPLACE,
        )?;
        let captured = hardening_file_state_at(&temporary_path)?;
        if captured != expected {
            let _ = renameat2_names(
                directory_fd,
                &temporary_name,
                &target_name,
                RENAME_NOREPLACE,
            );
            return Err("persistent hardening source changed during removal".into());
        }
        fs::remove_file(&temporary_path)?;
        directory_file.sync_all()?;
        cleanup_hardening_temporary_files(directory)?;
        return Ok("absent".to_owned());
    }

    let content = hardening_content(desired).ok_or("hardening profile is invalid")?;
    {
        let mut temporary = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o644)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(&temporary_path)?;
        temporary.write_all(content.as_bytes())?;
        temporary.sync_all()?;
    }
    let result = (|| {
        if expected == "absent" {
            renameat2_names(
                directory_fd,
                &temporary_name,
                &target_name,
                RENAME_NOREPLACE,
            )?;
            let observed = hardening_file_state_in(directory);
            if observed.ok().as_deref() != Some(desired) {
                // Undo the rename only if it is provably still our temporary file.
                if hardening_file_state_at(&hardening_canonical_path(directory))
                    .ok()
                    .as_deref()
                    == Some(desired)
                {
                    let _ = renameat2_names(
                        directory_fd,
                        &target_name,
                        &temporary_name,
                        RENAME_NOREPLACE,
                    );
                }
                return Err("persistent hardening post-state verification failed".into());
            }
        } else {
            renameat2_names(directory_fd, &temporary_name, &target_name, RENAME_EXCHANGE)?;
            let captured = hardening_file_state_at(&temporary_path)?;
            if captured != expected {
                let _ =
                    renameat2_names(directory_fd, &temporary_name, &target_name, RENAME_EXCHANGE);
                return Err("persistent hardening source changed during replacement".into());
            }
            if hardening_file_state_in(directory).ok().as_deref() != Some(desired) {
                let _ =
                    renameat2_names(directory_fd, &temporary_name, &target_name, RENAME_EXCHANGE);
                return Err("persistent hardening post-state verification failed".into());
            }
            fs::remove_file(&temporary_path)?;
        }
        directory_file.sync_all()?;
        cleanup_hardening_temporary_files(directory)?;
        Ok::<(), BoxError>(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary_path);
    }
    result?;
    Ok(desired.to_owned())
}

// Parses a recognized persistent profile into (allowlisted sysctl key, value)
// assignments. Used by the boot-time self-healing pass, which re-asserts the
// persisted intent after systemd-sysctl so later-sorting 99-* files cannot
// silently override GeDefense values.
fn parse_hardening_assignments(content: &str) -> Result<Vec<(String, String)>, BoxError> {
    let mut assignments: Vec<(String, String)> = Vec::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (key, value) = line
            .split_once('=')
            .ok_or("persistent hardening line is malformed")?;
        let key = key.trim();
        let value = value.trim();
        let (_, allowed) = sysctl_spec(key).ok_or_else(|| {
            format!("persistent hardening key {key} is not an allowlisted sysctl")
        })?;
        if !allowed.contains(&value) {
            return Err(format!(
                "persistent hardening value for {key} is outside its typed domain"
            )
            .into());
        }
        if assignments.iter().any(|(existing, _)| existing == key) {
            return Err(format!("persistent hardening profile repeats {key}").into());
        }
        assignments.push((key.to_owned(), value.to_owned()));
    }
    if assignments.is_empty() {
        return Err("persistent hardening profile has no assignments".into());
    }
    Ok(assignments)
}

// Best-effort boot-time re-assertion: the persisted profile is applied via the
// same allowlisted compare-set primitive the control plane uses. Failures are
// logged and never prevent the core from starting (availability), but they are
// visible instead of silently leaving the host on distribution defaults.
fn reassert_persisted_hardening() {
    let state = match hardening_file_state() {
        Ok(state) => state,
        Err(error) => {
            eprintln!("persistent hardening state unavailable at startup: {error}");
            return;
        }
    };
    if state == "absent" {
        return;
    }
    let content = match hardening_content(&state) {
        Some(content) => content,
        None => {
            eprintln!("persistent hardening profile {state} is not recognized");
            return;
        }
    };
    let assignments = match parse_hardening_assignments(&content) {
        Ok(assignments) => assignments,
        Err(error) => {
            eprintln!("persistent hardening profile {state} rejected at startup: {error}");
            return;
        }
    };
    let mut reasserted = 0usize;
    for (key, desired) in assignments {
        match read_sysctl_value(&key) {
            Ok(current) if current == desired => {}
            Ok(current) => match compare_set_sysctl(&key, &current, &desired) {
                Ok(_) => {
                    reasserted += 1;
                    eprintln!("persistent hardening re-asserted {key}={desired} (was {current})");
                }
                Err(error) => {
                    eprintln!("persistent hardening re-assertion failed for {key}: {error}")
                }
            },
            Err(error) => eprintln!("persistent hardening live read failed for {key}: {error}"),
        }
    }
    eprintln!(
        "persistent hardening profile {state} held at startup: {reasserted} value(s) re-asserted"
    );
}

fn hardening_file_state_at(path: &Path) -> Result<String, BoxError> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() > 4096 {
        return Err("captured hardening state is invalid".into());
    }
    let mut content = String::new();
    file.read_to_string(&mut content)?;
    recognized_hardening_state(&content)
        .ok_or_else(|| "captured hardening state is unmanaged".into())
}

// F-18: sockets created by the root core are pinned to the control-plane group
// and never left world-accessible. A symlinked socket path is rejected before
// permissions are touched, and ownership is corrected only when the service
// manager did not already apply Group=gedefense.
fn secure_runtime_socket(path: &Path, group: u32, mode: u32) -> Result<(), BoxError> {
    let metadata = fs::symlink_metadata(path)?;
    let effective_uid = unsafe { libc::geteuid() };
    if metadata.file_type().is_symlink() || metadata.uid() != effective_uid {
        return Err("runtime socket ownership rejected".into());
    }
    fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    if metadata.gid() != group {
        let socket_c = CString::new(path.as_os_str().as_bytes())?;
        // SAFETY: socket_c is a valid NUL-terminated path. u32::MAX as uid leaves
        // the owner untouched and only changes the owning group.
        let rc = unsafe { libc::chown(socket_c.as_ptr(), libc::uid_t::MAX, group) };
        if rc != 0 {
            return Err(std::io::Error::last_os_error().into());
        }
    }
    let secured = fs::symlink_metadata(path)?;
    if secured.permissions().mode() & 0o007 != 0 {
        return Err("runtime socket must not be accessible to other".into());
    }
    Ok(())
}

// Every privileged runtime socket is bound through this one path, so no caller
// can accidentally create a world-accessible or group-mismatched socket that
// escapes the F-18 hardening above.
fn bind_secure_runtime_socket(
    path: &Path,
    group: u32,
    mode: u32,
) -> Result<UnixListener, BoxError> {
    let _ = fs::remove_file(path);
    let listener = UnixListener::bind(path)?;
    secure_runtime_socket(path, group, mode)?;
    Ok(listener)
}

fn sysctl_spec(key: &str) -> Option<(&'static str, &'static [&'static str])> {
    match key {
        "kernel.kptr_restrict" => Some(("/proc/sys/kernel/kptr_restrict", &["0", "1", "2"])),
        "kernel.dmesg_restrict" => Some(("/proc/sys/kernel/dmesg_restrict", &["0", "1"])),
        "kernel.randomize_va_space" => {
            Some(("/proc/sys/kernel/randomize_va_space", &["0", "1", "2"]))
        }
        "kernel.yama.ptrace_scope" => {
            Some(("/proc/sys/kernel/yama/ptrace_scope", &["0", "1", "2", "3"]))
        }
        "kernel.unprivileged_bpf_disabled" => Some((
            "/proc/sys/kernel/unprivileged_bpf_disabled",
            &["0", "1", "2"],
        )),
        // The entry point of a local metadata-trust exploit is often an unprivileged user namespace:
        // without it a process cannot hold CAP_NET_RAW in a namespace it owns, which several kernel
        // packet-socket and netfilter classes need before they are reachable at all. The kernel
        // exposes exactly 0 or 1 here, so the domain is a typed binary.
        "kernel.unprivileged_userns_clone" => {
            Some(("/proc/sys/kernel/unprivileged_userns_clone", &["0", "1"]))
        }
        // CVE-2026-98432 reaches the IPv4 request-socket UAF through MPTCP. The mitigation
        // guard must be able to read and compare-set this knob through the privileged core,
        // exactly like the user-namespace boundary above. The kernel exposes 0 or 1.
        "net.mptcp.enabled" => Some(("/proc/sys/net/mptcp/enabled", &["0", "1"])),
        "fs.protected_fifos" => Some(("/proc/sys/fs/protected_fifos", &["0", "1", "2"])),
        "fs.protected_regular" => Some(("/proc/sys/fs/protected_regular", &["0", "1", "2"])),
        "fs.suid_dumpable" => Some(("/proc/sys/fs/suid_dumpable", &["0", "1", "2"])),
        "net.ipv4.tcp_syncookies" => Some(("/proc/sys/net/ipv4/tcp_syncookies", &["0", "1", "2"])),
        "net.ipv4.conf.all.accept_redirects" => {
            Some(("/proc/sys/net/ipv4/conf/all/accept_redirects", &["0", "1"]))
        }
        "net.ipv4.conf.default.accept_redirects" => Some((
            "/proc/sys/net/ipv4/conf/default/accept_redirects",
            &["0", "1"],
        )),
        "net.ipv4.conf.all.send_redirects" => {
            Some(("/proc/sys/net/ipv4/conf/all/send_redirects", &["0", "1"]))
        }
        "net.ipv4.conf.default.send_redirects" => Some((
            "/proc/sys/net/ipv4/conf/default/send_redirects",
            &["0", "1"],
        )),
        "net.ipv6.conf.all.accept_redirects" => {
            Some(("/proc/sys/net/ipv6/conf/all/accept_redirects", &["0", "1"]))
        }
        "net.ipv6.conf.default.accept_redirects" => Some((
            "/proc/sys/net/ipv6/conf/default/accept_redirects",
            &["0", "1"],
        )),
        // V6.2 CIS/Lynis M5.1 controls. The Go control plane ships these in its
        // hardening catalogue only after this typed core allowlist accepts the
        // exact key/path/value domain; an unlisted key must never reach a
        // privileged `/proc/sys` write.
        "net.ipv4.conf.all.rp_filter" => {
            Some(("/proc/sys/net/ipv4/conf/all/rp_filter", &["0", "1", "2"]))
        }
        "net.ipv4.conf.default.rp_filter" => Some((
            "/proc/sys/net/ipv4/conf/default/rp_filter",
            &["0", "1", "2"],
        )),
        "net.ipv4.conf.all.log_martians" => {
            Some(("/proc/sys/net/ipv4/conf/all/log_martians", &["0", "1"]))
        }
        "net.ipv4.conf.default.log_martians" => Some((
            "/proc/sys/net/ipv4/conf/default/log_martians",
            &["0", "1"],
        )),
        "net.ipv4.icmp_echo_ignore_broadcasts" => Some((
            "/proc/sys/net/ipv4/icmp_echo_ignore_broadcasts",
            &["0", "1"],
        )),
        "net.ipv4.icmp_ignore_bogus_error_responses" => Some((
            "/proc/sys/net/ipv4/icmp_ignore_bogus_error_responses",
            &["0", "1"],
        )),
        "fs.protected_hardlinks" => Some(("/proc/sys/fs/protected_hardlinks", &["0", "1"])),
        "fs.protected_symlinks" => Some(("/proc/sys/fs/protected_symlinks", &["0", "1"])),
        // sysrq is a bitmask, not a boolean. Keep the documented safe masks the
        // provisioning profiles may compare-set and the distribution defaults
        // that can be read back before the first apply.
        "kernel.sysrq" => Some((
            "/proc/sys/kernel/sysrq",
            &["0", "1", "2", "4", "8", "16", "32", "64", "128", "176", "244", "438"],
        )),
        "kernel.perf_event_paranoid" => Some((
            "/proc/sys/kernel/perf_event_paranoid",
            // Debian/Ubuntu may expose the hardening value 4 in addition to
            // the upstream -1..=3 range; the read-back must accept what the
            // distribution actually reports before compare-set runs.
            &["-1", "0", "1", "2", "3", "4"],
        )),
        "dev.tty.ldisc_autoload" => {
            Some(("/proc/sys/dev/tty/ldisc_autoload", &["0", "1"]))
        }
        "vm.swappiness" => Some((
            "/proc/sys/vm/swappiness",
            &["0", "1", "10", "20", "30", "40", "50", "60", "70", "80", "90", "100"],
        )),
        "net.ipv6.conf.all.disable_ipv6" => {
            Some(("/proc/sys/net/ipv6/conf/all/disable_ipv6", &["0", "1"]))
        }
        "net.ipv6.conf.default.disable_ipv6" => {
            Some(("/proc/sys/net/ipv6/conf/default/disable_ipv6", &["0", "1"]))
        }
        _ => None,
    }
}

fn read_sysctl_value(key: &str) -> Result<String, BoxError> {
    let (path, allowed) = sysctl_spec(key).ok_or("sysctl key is not allowlisted")?;
    let value = fs::read_to_string(path)?;
    if value.len() > 32 {
        return Err("sysctl value exceeds response boundary".into());
    }
    let value = value.trim();
    if !allowed.contains(&value) {
        return Err("sysctl contains a value outside its typed domain".into());
    }
    Ok(value.to_owned())
}

fn compare_set_sysctl(key: &str, expected: &str, desired: &str) -> Result<String, BoxError> {
    let (path, allowed) = sysctl_spec(key).ok_or("sysctl key is not allowlisted")?;
    if !allowed.contains(&expected) || !allowed.contains(&desired) {
        return Err("sysctl value is outside its typed domain".into());
    }
    let current = read_sysctl_value(key)?;
    if current != expected {
        return Err("sysctl compare-set precondition failed".into());
    }
    let mut file = OpenOptions::new()
        .write(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)?;
    file.write_all(desired.as_bytes())?;
    file.write_all(b"\n")?;
    file.flush()?;
    drop(file);
    let verified = read_sysctl_value(key)?;
    if verified != desired {
        return Err("sysctl post-state verification failed".into());
    }
    Ok(verified)
}

// Point 1 (§4/§5): one Titan exec-gate state object.
//
// The maps are taken even when BPF LSM is inactive so a stale eBPF object fails
// loudly at startup instead of running blind (§8). `attached` becomes true only
// after both LSM hooks attached on an active kernel, so no command can claim
// enforcement the kernel does not deliver; the default mode stays OFF.
struct TitanExecGate {
    state: AyaArray<MapData, u64>,
    offsets: AyaArray<MapData, u32>,
    modes: AyaHashMap<MapData, u64, u8>,
    policy: AyaHashMap<MapData, [u8; 16], [u8; 16]>,
    events: RingBuf<MapData>,
    emitted: PerCpuArray<MapData, u64>,
    ring_drops: PerCpuArray<MapData, u64>,
    read_failures: PerCpuArray<MapData, u64>,
    denies: PerCpuArray<MapData, u64>,
    audits: PerCpuArray<MapData, u64>,
    ctime_rejects: PerCpuArray<MapData, u64>,
    store: titan_exec::TitanExecPolicy,
    epoch: u32,
    epoch_hex: String,
    mode: u8,
    flags: u8,
    lsm_active: bool,
    offsets_valid: bool,
    attached: bool,
    last_ring_drops: u64,
    rejected_events: u64,
}

/// §4 `TITAN_EXEC_STATE` word: epoch | mode | flags | abi=1 | magic='T'.
fn encode_titan_exec_state(epoch: u32, mode: u8, flags: u8) -> u64 {
    u64::from(epoch)
        | (u64::from(mode) << 32)
        | (u64::from(flags) << 40)
        | (u64::from(TITAN_EXEC_STATE_ABI) << 48)
        | (u64::from(TITAN_EXEC_STATE_MAGIC) << 56)
}

/// §4 `TITAN_EXEC_POLICY` key: `dev u32 LE @0 | ino u64 LE @4 | pad`.
fn encode_titan_exec_policy_key(dev: u32, ino: u64) -> [u8; 16] {
    let mut key = [0u8; 16];
    key[0..4].copy_from_slice(&dev.to_le_bytes());
    key[4..12].copy_from_slice(&ino.to_le_bytes());
    key
}

/// §4 `TITAN_EXEC_POLICY` value: `action @0 | flags @1 | reserved @2 | ctime_ns LE @4`.
fn encode_titan_exec_policy_value(entry: &titan_exec::PolicyEntry) -> [u8; 16] {
    let mut value = [0u8; 16];
    value[0] = entry.action;
    value[1] = entry.flags;
    value[4..12].copy_from_slice(&entry.ctime_ns.to_le_bytes());
    value
}

/// §4 `TITAN_EXEC_MODE` value: `(mode << 2) | (scope flags & 1)`, validated.
fn encode_titan_exec_scope_value(mode: u8, flags: u8) -> Result<u8, BoxError> {
    if mode > gedefense_common::TITAN_EXEC_MODE_STRICT {
        return Err("titan-exec scope mode is not 0..3".into());
    }
    if flags & !TITAN_EXEC_SCOPE_FLAG_JIT_ALLOW != 0 {
        return Err("titan-exec scope flags contain unknown bits".into());
    }
    Ok((mode << titan_exec::TITAN_EXEC_SCOPE_MODE_SHIFT) | flags)
}

/// §4.1 `TITAN_EXEC_OFFSETS` table (48 words, reserved indices stay 0).
fn encode_titan_exec_offsets_table(
    offsets: &btf_offsets::TitanExecOffsets,
) -> [u32; btf_offsets::TITAN_EXEC_OFFSETS_TABLE_LEN] {
    let mut table = [0u32; btf_offsets::TITAN_EXEC_OFFSETS_TABLE_LEN];
    table[btf_offsets::OFF_MAGIC] = TITAN_EXEC_OFFSETS_MAGIC;
    table[btf_offsets::OFF_ABI] = TITAN_EXEC_OFFSETS_ABI;
    table[btf_offsets::OFF_BPRM_FILE] = offsets.bprm_file_off;
    table[btf_offsets::OFF_FILE_F_INODE] = offsets.file_f_inode_off;
    table[btf_offsets::OFF_INODE_I_INO] = offsets.inode_i_ino_off;
    table[btf_offsets::OFF_INODE_I_SB] = offsets.inode_i_sb_off;
    table[btf_offsets::OFF_INODE_I_NLINK] = offsets.inode_i_nlink_off;
    table[btf_offsets::OFF_INODE_I_MODE] = offsets.inode_i_mode_off;
    table[btf_offsets::OFF_INODE_I_GEN] = offsets.inode_i_generation_off;
    table[btf_offsets::OFF_SUPER_S_DEV] = offsets.super_s_dev_off;
    table[btf_offsets::OFF_SUPER_S_MAGIC] = offsets.super_s_magic_off;
    table[btf_offsets::OFF_INODE_I_CTIME_SEC] = offsets.inode_i_ctime_sec_off;
    table[btf_offsets::OFF_INODE_I_CTIME_NSEC] = offsets.inode_i_ctime_nsec_off;
    table[btf_offsets::OFF_INODE_I_CTIME_NSEC_WIDTH] = offsets.inode_i_ctime_nsec_width;
    // §4.1 ABI 2 (6.2.0): UNTRUSTED exec-mode facts.
    table[btf_offsets::OFF_BPRM_FILENAME] = offsets.bprm_filename_off;
    table[btf_offsets::OFF_INODE_I_UID] = offsets.inode_i_uid_off;
    table[btf_offsets::OFF_FILE_F_PATH_DENTRY] = offsets.file_f_path_dentry_off;
    table[btf_offsets::OFF_DENTRY_D_PARENT] = offsets.dentry_d_parent_off;
    table[btf_offsets::OFF_DENTRY_D_INODE] = offsets.dentry_d_inode_off;
    table[btf_offsets::OFF_DENTRY_SIZE] = offsets.dentry_size;
    table[btf_offsets::OFF_BPRM_NARGS] = offsets.bprm_nargs;
    table[btf_offsets::OFF_MMAP_NARGS] = offsets.mmap_nargs;
    table[btf_offsets::OFF_MMAP_FILE_ARG] = offsets.mmap_file_arg_idx;
    table[btf_offsets::OFF_MMAP_PROT_ARG] = offsets.mmap_prot_arg_idx;
    table[btf_offsets::OFF_MMAP_FLAGS_ARG] = offsets.mmap_flags_arg_idx;
    table[btf_offsets::OFF_TMPFS_MAGIC] = btf_offsets::TMPFS_MAGIC;
    table[btf_offsets::OFF_DEVTMPFS_MAGIC] = btf_offsets::DEVTMPFS_MAGIC;
    table[btf_offsets::OFF_PROC_MAGIC] = btf_offsets::PROC_SUPER_MAGIC;
    table[btf_offsets::OFF_SYSFS_MAGIC] = btf_offsets::SYSFS_MAGIC;
    table[btf_offsets::OFF_OVERLAY_MAGIC] = btf_offsets::OVERLAYFS_SUPER_MAGIC;
    table[btf_offsets::OFF_BPRM_RETVAL_SLOT] = offsets.bprm_retval_slot;
    table[btf_offsets::OFF_MMAP_RETVAL_SLOT] = offsets.mmap_retval_slot;
    table[btf_offsets::OFF_INODE_SIZE] = offsets.inode_size;
    table[btf_offsets::OFF_FILE_SIZE] = offsets.file_size;
    table[btf_offsets::OFF_BPRM_SIZE] = offsets.bprm_size;
    table
}

/// §4.1: the eBPF programs hard-code `bprm file=0/previous=1` and
/// `mmap file=0/prot=2/previous=4`; only this hook shape may be attached.
fn titan_exec_offsets_match_ebpf_slots(offsets: &btf_offsets::TitanExecOffsets) -> bool {
    offsets.bprm_nargs == 1
        && offsets.mmap_nargs == 4
        && offsets.mmap_file_arg_idx == 0
        && offsets.mmap_prot_arg_idx == 2
        && offsets.mmap_flags_arg_idx == 3
        && offsets.bprm_retval_slot == 1
        && offsets.mmap_retval_slot == 4
}

/// §4 STATE flag byte bits 40..47: offsets_valid, lsm_active (only when both
/// hooks are attached) and ctime_check_enabled (SET_GLOBAL REQUIRE_CTIME).
fn encode_titan_exec_state_flags(offsets_valid: bool, attached: bool, ctime_check: bool) -> u8 {
    (if offsets_valid { titan_exec::TITAN_EXEC_STATE_FLAG_OFFSETS_VALID } else { 0 })
        | (if attached { titan_exec::TITAN_EXEC_STATE_FLAG_LSM_ACTIVE } else { 0 })
        | (if ctime_check { titan_exec::TITAN_EXEC_STATE_FLAG_CTIME_CHECK } else { 0 })
}

impl TitanExecGate {
    /// §6: only an active LSM list, validated offsets and both attached hooks
    /// may ever be reported or acted upon as enforcement.
    fn enforcement_available(&self) -> bool {
        self.lsm_active && self.offsets_valid && self.attached
    }

    fn state_text(&self) -> &'static str {
        titan_exec::exec_state(
            self.enforcement_available(),
            self.lsm_active,
            self.offsets_valid,
        )
        .text()
    }

    /// Rewrites the §4 STATE word from the current truthful gate state.
    fn write_state(&mut self) -> Result<(), BoxError> {
        let ctime_check = self.flags & titan_exec::TITAN_EXEC_GLOBAL_FLAG_REQUIRE_CTIME != 0;
        let flags = encode_titan_exec_state_flags(self.offsets_valid, self.attached, ctime_check);
        self.state
            .set(0, encode_titan_exec_state(self.epoch, self.mode, flags), 0)?;
        Ok(())
    }

    fn version(&self) -> Result<String, BoxError> {
        Ok(titan_exec::TITAN_EXEC_VERSION.to_owned())
    }

    fn epoch(&self) -> Result<String, BoxError> {
        Ok(self.epoch_hex.clone())
    }

    fn status(&self) -> Result<String, BoxError> {
        Ok(titan_exec::encode_exec_status(&titan_exec::StatusView {
            state: titan_exec::exec_state(
                self.enforcement_available(),
                self.lsm_active,
                self.offsets_valid,
            ),
            mode: self.mode,
            flags: self.flags,
            path_bpf_lsm: self.attached,
            lsm_active: self.lsm_active,
            offsets_valid: self.offsets_valid,
            entries: self.store.entry_count(),
            scopes: self.store.scope_count(),
            epoch: &self.epoch_hex,
        }))
    }

    fn health(&self) -> Result<String, BoxError> {
        let counters = [
            KernelCore::per_cpu_counter_sum(&self.emitted)?,
            KernelCore::per_cpu_counter_sum(&self.ring_drops)?,
            KernelCore::per_cpu_counter_sum(&self.read_failures)?,
            KernelCore::per_cpu_counter_sum(&self.denies)?,
            KernelCore::per_cpu_counter_sum(&self.audits)?,
            KernelCore::per_cpu_counter_sum(&self.ctime_rejects)?,
        ];
        Ok(titan_exec::encode_exec_health(&counters))
    }

    /// §5 `SET_GLOBAL`: mode>0 only when the gate can really enforce; the
    /// REQUIRE_CTIME flag is mirrored into STATE bit2 and every policy value.
    fn set_global(&mut self, mode: &str, flags: &str) -> Result<String, BoxError> {
        let mode = titan_exec::parse_mode(mode).map_err(|message| -> BoxError { message.into() })?;
        let flags =
            titan_exec::parse_global_flags(flags).map_err(|message| -> BoxError { message.into() })?;
        if mode != TITAN_EXEC_MODE_OFF && !self.enforcement_available() {
            return Err(titan_exec::ENFORCEMENT_UNAVAILABLE.into());
        }
        let require_ctime = flags & titan_exec::TITAN_EXEC_GLOBAL_FLAG_REQUIRE_CTIME != 0;
        let mut updates = Vec::new();
        for (dev, ino) in self.store.keys() {
            let Some(mut entry) = self.store.entry(dev, ino) else {
                continue;
            };
            let wanted = if require_ctime {
                entry.flags | titan_exec::TITAN_EXEC_POLICY_FLAG_REQUIRE_CTIME
            } else {
                entry.flags & !titan_exec::TITAN_EXEC_POLICY_FLAG_REQUIRE_CTIME
            };
            if wanted != entry.flags {
                entry.flags = wanted;
                updates.push(((dev, ino), entry));
            }
        }
        for ((dev, ino), entry) in &updates {
            self.policy.insert(
                encode_titan_exec_policy_key(*dev, *ino),
                encode_titan_exec_policy_value(entry),
                0,
            )?;
        }
        for ((dev, ino), entry) in updates {
            self.store.insert(dev, ino, entry)?;
        }
        self.mode = mode;
        self.flags = flags;
        self.write_state()?;
        Ok("applied".to_owned())
    }

    /// §5 `ALLOW_ADD`/`ALLOW_ADD_BATCH` per-path step: validate fully, then the
    /// single map write, then the RAM mirror. `Ok(false)` means "already there".
    fn insert_resolved(&mut self, path: &str) -> Result<(u32, u64, bool), &'static str> {
        let identity = titan_exec::resolve_exec_path(path).map_err(|reject| reject.token())?;
        if self.store.entry(identity.dev, identity.ino).is_some() {
            return Ok((identity.dev, identity.ino, false));
        }
        if self.store.entry_count() >= titan_exec::TITAN_EXEC_MAX_POLICY_ENTRIES {
            return Err("cap-reached");
        }
        let entry = titan_exec::PolicyEntry {
            action: titan_exec::TITAN_EXEC_ALLOW_ACTION,
            flags: if self.flags & titan_exec::TITAN_EXEC_GLOBAL_FLAG_REQUIRE_CTIME != 0 {
                titan_exec::TITAN_EXEC_POLICY_FLAG_REQUIRE_CTIME
            } else {
                0
            },
            ctime_ns: identity.ctime_ns,
        };
        self.policy
            .insert(
                encode_titan_exec_policy_key(identity.dev, identity.ino),
                encode_titan_exec_policy_value(&entry),
                0,
            )
            .map_err(|_| "map-write-failed")?;
        self.store
            .insert(identity.dev, identity.ino, entry)
            .map_err(|_| "store-write-failed")?;
        Ok((identity.dev, identity.ino, true))
    }

    fn allow_add(&mut self, path: &str) -> Result<String, BoxError> {
        match self.insert_resolved(path) {
            Ok((dev, ino, true)) => Ok(format!("added:{dev}:{ino}")),
            Ok((dev, ino, false)) => Ok(format!("exists:{dev}:{ino}")),
            Err(token) => Err(format!("titan-exec path rejected: {token}").into()),
        }
    }

    fn allow_add_batch(&mut self, token: &str) -> Result<String, BoxError> {
        let paths = titan_exec::decode_allow_batch(token).map_err(|message| -> BoxError { message.into() })?;
        let (mut added, mut rejected) = (0usize, 0usize);
        let mut error = titan_exec::BATCH_ERROR_NONE;
        for path in paths {
            match self.insert_resolved(&path) {
                Ok(_) => added = added.saturating_add(1),
                Err(reason) => {
                    rejected = rejected.saturating_add(1);
                    if error == titan_exec::BATCH_ERROR_NONE {
                        error = reason;
                    }
                }
            }
        }
        Ok(titan_exec::encode_allow_batch_response(added, rejected, error))
    }

    /// §5 `ALLOW_DEL`: validate, drop from the eBPF map (KeyNotFound is fine),
    /// then from the mirror; DELETE is idempotent.
    fn allow_del(&mut self, dev: &str, ino: &str) -> Result<String, BoxError> {
        let dev = titan_exec::parse_policy_dev(dev).map_err(|message| -> BoxError { message.into() })?;
        let ino = titan_exec::parse_policy_ino(ino).map_err(|message| -> BoxError { message.into() })?;
        match self.policy.remove(&encode_titan_exec_policy_key(dev, ino)) {
            Ok(()) | Err(MapError::KeyNotFound) => {}
            Err(error) => return Err(error.into()),
        }
        self.store.remove(dev, ino);
        Ok("deleted".to_owned())
    }

    fn clear(&mut self) -> Result<String, BoxError> {
        for (dev, ino) in self.store.keys() {
            match self.policy.remove(&encode_titan_exec_policy_key(dev, ino)) {
                Ok(()) | Err(MapError::KeyNotFound) => {}
                Err(error) => return Err(error.into()),
            }
        }
        self.store.clear();
        Ok("cleared".to_owned())
    }

    /// §5 `SCOPE_SET`: mode>0 only on the enforcing gate; a failed mirror insert
    /// rolls the eBPF map write back so store and map never disagree.
    fn scope_set(&mut self, cgroup: &str, mode: &str, flags: &str) -> Result<String, BoxError> {
        let cgroup =
            titan_exec::parse_scope_cgroup(cgroup).map_err(|message| -> BoxError { message.into() })?;
        // §4: the per-cgroup scope value has only two mode bits, so UNTRUSTED
        // (4) stays a global mode and is rejected here instead of truncating.
        let mode = titan_exec::parse_scope_mode(mode).map_err(|message| -> BoxError { message.into() })?;
        let flags = titan_exec::parse_scope_flags(flags).map_err(|message| -> BoxError { message.into() })?;
        if mode != TITAN_EXEC_MODE_OFF && !self.enforcement_available() {
            return Err(titan_exec::ENFORCEMENT_UNAVAILABLE.into());
        }
        let value = encode_titan_exec_scope_value(mode, flags)?;
        self.modes.insert(cgroup, value, 0)?;
        if let Err(error) = self.store.scope_set(cgroup, value) {
            let _ = self.modes.remove(&cgroup);
            return Err(error.into());
        }
        Ok("applied".to_owned())
    }

    fn scope_del(&mut self, cgroup: &str) -> Result<String, BoxError> {
        let cgroup =
            titan_exec::parse_scope_cgroup(cgroup).map_err(|message| -> BoxError { message.into() })?;
        match self.modes.remove(&cgroup) {
            Ok(()) | Err(MapError::KeyNotFound) => {}
            Err(error) => return Err(error.into()),
        }
        self.store.scope_remove(cgroup);
        Ok("deleted".to_owned())
    }

    /// §3.3/§6 event drain: ≤8 records, 88-byte and decoder check, undecodable
    /// records are skipped and counted (never an abort), `dropped` is the ring
    /// drop delta since the previous drain.
    fn take_events(&mut self) -> Result<String, BoxError> {
        let mut records = Vec::with_capacity(titan_exec::TITAN_EXEC_MAX_EVENTS_PER_RESPONSE);
        while records.len() < titan_exec::TITAN_EXEC_MAX_EVENTS_PER_RESPONSE {
            let Some(item) = self.events.next() else {
                break;
            };
            if item.len() != TITAN_EXEC_EVENT_WIRE_BYTES {
                self.rejected_events = self.rejected_events.saturating_add(1);
                continue;
            }
            let Some(event) = decode_titan_exec_event(&item) else {
                self.rejected_events = self.rejected_events.saturating_add(1);
                continue;
            };
            records.push(titan_exec::encode_exec_event_text(&event));
        }
        if self.rejected_events > 0 && self.rejected_events <= 4 {
            eprintln!(
                "Titan exec ring record rejected: {} records so far fit no TitanExecEvent; the drain continues",
                self.rejected_events
            );
        }
        let ring_drops = KernelCore::per_cpu_counter_sum(&self.ring_drops)?;
        let dropped = ring_drops.saturating_sub(self.last_ring_drops);
        self.last_ring_drops = ring_drops;
        titan_exec::encode_exec_events_batch(&records, dropped).map_err(Into::into)
    }
}

struct KernelCore {
    _ebpf: Ebpf,
    exec_events: RingBuf<MapData>,
    egress_events: RingBuf<MapData>,
    ingress_events: RingBuf<MapData>,
    ingress_events_emitted: PerCpuArray<MapData, u64>,
    ingress_ring_drops: PerCpuArray<MapData, u64>,
    ingress_track_insert_failures: PerCpuArray<MapData, u64>,
    cell_lsm_events: RingBuf<MapData>,
    cell_lsm_policies: AyaHashMap<MapData, u64, u8>,
    allow_v4: LpmTrie<MapData, [u8; 4], u8>,
    allow_v6: LpmTrie<MapData, [u8; 16], u8>,
    v4: LpmTrie<MapData, [u8; 4], u8>,
    v6: LpmTrie<MapData, [u8; 16], u8>,
    blocked: HashSet<Target>,
    mode: String,
    // Which hook is actually enforcing ingress, decided at attach time and reported
    // through INGRESS_HEALTH. The attach ladder degrades native XDP -> generic XDP -> TC
    // ingress, and until now the outcome was only written to stderr at start: an operator
    // had no way to tell which of the three was live on their hardware.
    ingress_mode: &'static str,
    cell_lsm_attached: bool,
    cell_policy_epoch: String,
    // Point 3 ABI-2 (§4): policy maps, flow ring/counters and the global word.
    styx_global: AyaArray<MapData, u64>,
    styx_mode: AyaHashMap<MapData, u64, u8>,
    styx_cell_allow_v4: LpmTrie<MapData, [u8; 16], u8>,
    styx_cell_allow_v6: LpmTrie<MapData, [u8; 24], u8>,
    styx_allow_global_v4: LpmTrie<MapData, [u8; 8], u8>,
    styx_allow_global_v6: LpmTrie<MapData, [u8; 20], u8>,
    styx_block_v4: LpmTrie<MapData, [u8; 4], u8>,
    styx_block_v6: LpmTrie<MapData, [u8; 16], u8>,
    styx_resolver_v4: LpmTrie<MapData, [u8; 4], u8>,
    styx_resolver_v6: LpmTrie<MapData, [u8; 16], u8>,
    styx_flow_events: RingBuf<MapData>,
    styx_flow_emitted: PerCpuArray<MapData, u64>,
    styx_ring_drops: PerCpuArray<MapData, u64>,
    styx_agg_insert_failures: PerCpuArray<MapData, u64>,
    styx_egress_parse_errors: PerCpuArray<MapData, u64>,
    styx_egress_drops_total: PerCpuArray<MapData, u64>,
    styx_egress_policy_drops: PerCpuArray<MapData, u64>,
    // Opaque handles for maps only the kernel reads/writes. Taking them makes the
    // startup ABI gate complete: an object missing any §4 map fails loudly here
    // instead of running with silently absent telemetry/caching.
    _styx_resolved: Map,
    _flow_agg_v4: Map,
    _flow_agg_v6: Map,
    styx_epoch: u64,
    styx_epoch_hex: String,
    styx_last_ring_drops: u64,
    styx_flow_rejected: u64,
    // Point 1 (§4/§5): Titan exec-gate maps, RAM policy mirror and honest state.
    titan_exec: TitanExecGate,
    // Point 5 (§5/§6): lockdown state machine (word store + net counters are
    // owned by it; the maps are mandatory above so it can always verify).
    lockdown: lockdown::LockdownCore,
    // 6.1.0 Module B: worker crash-storm sensor (mandatory maps, optional
    // tracepoint attach reported honestly through WORKER_GUARD_STATUS).
    worker_guard: worker_guard::WorkerGuardCore,
    // 6.2.0 M2.2: ransomware/rename-storm sensor (mandatory maps, optional
    // kprobe attach reported through RANSOM_STATUS; the kernel only audits and
    // the core freezes the resolved process group with SIGSTOP).
    ransom: ransom::RansomCore,
    // 6.2.0 M2.4: file_open LSM credential guard (mandatory maps, optional
    // LSM attach reported through CRED_GUARD_STATUS; the kernel denies with -EACCES).
    credential_guard: credential_guard::CredentialGuardCore,
    // Kernel XDR behavioral tracepoints & probe emitters.
    xdr_kernel: xdr_kernel::XdrKernelCore,
}

impl KernelCore {
    fn load(
        object: &str,
        iface: &str,
        require_cell_lsm: bool,
        lockdown_state_path: &str,
    ) -> Result<Self, BoxError> {
        let mut ebpf = Ebpf::load_file(object)?;
        let xdp_mode = {
            let program: &mut Xdp = ebpf
                .program_mut("gedefense_xdp")
                .ok_or("XDP program missing")?
                .try_into()?;
            program.load()?;
            match program.attach(iface, XdpMode::Driver) {
                Ok(_) => Some("native"),
                Err(native) => {
                    eprintln!("native XDP unavailable ({native}); using generic mode");
                    match program.attach(iface, XdpMode::Skb) {
                        Ok(_) => Some("generic"),
                        Err(generic) => {
                            eprintln!(
                                "generic XDP unavailable ({generic}); using TC ingress kernel enforcement"
                            );
                            None
                        }
                    }
                }
            }
        };
        let ingress_mode: &'static str = match xdp_mode {
            Some(mode) => mode,
            None => {
                if let Err(error) = tc::qdisc_add_clsact(iface) {
                    if !matches!(error, tc::TcError::AlreadyAttached) {
                        return Err(error.into());
                    }
                }
                let program: &mut SchedClassifier = ebpf
                    .program_mut("gedefense_tc_ingress")
                    .ok_or("TC ingress program missing")?
                    .try_into()?;
                program.load()?;
                program.attach_with_options(
                    iface,
                    TcAttachType::Ingress,
                    tc::TcAttachOptions::Netlink(tc::NlOptions::default()),
                )?;
                "tc-ingress"
            }
        };
        let exec_program: &mut TracePoint = ebpf
            .program_mut("gedefense_exec")
            .ok_or("process exec tracepoint program missing")?
            .try_into()?;
        exec_program.load()?;
        if let Err(error) = exec_program.attach("sched", "sched_process_exec") {
            eprintln!("Process exec tracepoint unavailable ({error}); falling back to fanotify and procfs monitoring");
        }
        let cgroup = File::open("/sys/fs/cgroup")?;
        let egress_program: &mut CgroupSkb = ebpf
            .program_mut("gedefense_egress")
            .ok_or("cgroup egress program missing")?
            .try_into()?;
        egress_program.load()?;
        // AllowOverride, not AllowMultiple.
        //
        // The two differ in whether an attach replaces or appends, and nothing here ever
        // detaches - the core has no shutdown path, and a cgroup program outlives the
        // process that attached it. With AllowMultiple every restart appended another
        // gedefense_egress to the root cgroup's egress hook and left it there, holding
        // its maps: eleven stale programs and roughly 110 MB of kernel memory had
        // accumulated on a host that had been restarted a handful of times.
        //
        // AllowOverride replaces the previous attachment instead, so a restart leaves one
        // program rather than one more. It is preferred over Single because it still
        // permits a child cgroup to install its own program over this one, which is what
        // a container runtime expects to be able to do.
        egress_program.attach(
            cgroup,
            CgroupSkbAttachType::Egress,
            CgroupAttachMode::AllowOverride,
        )?;
        // §0/§6/P3-Fix: an active BPF LSM is a hard precondition for any attach
        // claim. On a kernel whose `/sys/kernel/security/lsm` list lacks `bpf`,
        // `Lsm::attach` succeeds but the stubs are never called - the old code
        // still reported `bpf-lsm-cell` for that silent no-op.
        let bpf_lsm_active = match titan_exec::bpf_lsm_active_from_sys_fs() {
            Ok(active) => active,
            Err(error) => {
                eprintln!("BPF LSM activation probe failed ({error}); treating BPF LSM as inactive");
                false
            }
        };
        if !bpf_lsm_active && require_cell_lsm {
            return Err(
                "--require-bpf-lsm: /sys/kernel/security/lsm does not list the `bpf` token".into(),
            );
        }
        let lsm_btf = if bpf_lsm_active {
            match Btf::from_sys_fs() {
                Ok(btf) => Some(btf),
                Err(error) if !require_cell_lsm => {
                    eprintln!("BPF LSM BTF unavailable ({error}); LSM attach disabled");
                    None
                }
                Err(error) => return Err(format!("required BPF LSM BTF unavailable: {error}").into()),
            }
        } else {
            None
        };
        let cell_lsm_attached = match &lsm_btf {
            Some(btf) => match attach_cell_socket_lsm(&mut ebpf, btf) {
                Ok(()) => true,
                Err(error) if !require_cell_lsm => {
                    eprintln!(
                        "BPF LSM unavailable ({error}); Gaia Cell host socket reinforcement disabled"
                    );
                    false
                }
                Err(error) => {
                    return Err(format!("required Gaia Cell BPF LSM attach failed: {error}").into())
                }
            },
            None => {
                eprintln!(
                    "BPF LSM is not active (or its BTF is missing); Gaia Cell host socket reinforcement optional-unavailable, bpf-lsm-cell not claimed"
                );
                false
            }
        };
        let exec_events =
            RingBuf::try_from(ebpf.take_map("EXEC_EVENTS").ok_or("EXEC_EVENTS missing")?)?;
        let egress_events = RingBuf::try_from(
            ebpf.take_map("EGRESS_EVENTS")
                .ok_or("EGRESS_EVENTS missing")?,
        )?;
        let ingress_events = RingBuf::try_from(
            ebpf.take_map("INGRESS_EVENTS")
                .ok_or("INGRESS_EVENTS missing")?,
        )?;
        let ingress_events_emitted = PerCpuArray::try_from(
            ebpf.take_map("INGRESS_EVENTS_EMITTED")
                .ok_or("INGRESS_EVENTS_EMITTED missing")?,
        )?;
        let ingress_ring_drops = PerCpuArray::try_from(
            ebpf.take_map("INGRESS_RING_DROPS")
                .ok_or("INGRESS_RING_DROPS missing")?,
        )?;
        let ingress_track_insert_failures = PerCpuArray::try_from(
            ebpf.take_map("INGRESS_TRACK_INSERT_FAILURES")
                .ok_or("INGRESS_TRACK_INSERT_FAILURES missing")?,
        )?;
        let cell_lsm_events = RingBuf::try_from(
            ebpf.take_map("CELL_LSM_EVENTS")
                .ok_or("CELL_LSM_EVENTS missing")?,
        )?;
        let cell_lsm_policies = AyaHashMap::try_from(
            ebpf.take_map("CELL_LSM_POLICIES")
                .ok_or("CELL_LSM_POLICIES missing")?,
        )?;
        let allow_v4 = LpmTrie::try_from(
            ebpf.take_map("ALLOWLIST_V4")
                .ok_or("ALLOWLIST_V4 missing")?,
        )?;
        let allow_v6 = LpmTrie::try_from(
            ebpf.take_map("ALLOWLIST_V6")
                .ok_or("ALLOWLIST_V6 missing")?,
        )?;
        let v4 = LpmTrie::try_from(
            ebpf.take_map("BLOCKLIST_V4")
                .ok_or("BLOCKLIST_V4 missing")?,
        )?;
        let v6 = LpmTrie::try_from(
            ebpf.take_map("BLOCKLIST_V6")
                .ok_or("BLOCKLIST_V6 missing")?,
        )?;
        // Point 3: all §4 maps are taken here so a mismatched eBPF object fails
        // at startup (no silent "sensor online but blind" state).
        let mut styx_global = AyaArray::try_from(
            ebpf.take_map("STYX_GLOBAL").ok_or("STYX_GLOBAL missing")?,
        )?;
        let styx_mode = AyaHashMap::try_from(
            ebpf.take_map("CELL_EGRESS_MODE")
                .ok_or("CELL_EGRESS_MODE missing")?,
        )?;
        let styx_cell_allow_v4 = LpmTrie::try_from(
            ebpf.take_map("CELL_EGRESS_ALLOW_V4")
                .ok_or("CELL_EGRESS_ALLOW_V4 missing")?,
        )?;
        let styx_cell_allow_v6 = LpmTrie::try_from(
            ebpf.take_map("CELL_EGRESS_ALLOW_V6")
                .ok_or("CELL_EGRESS_ALLOW_V6 missing")?,
        )?;
        let styx_allow_global_v4 = LpmTrie::try_from(
            ebpf.take_map("STYX_ALLOW_GLOBAL_V4")
                .ok_or("STYX_ALLOW_GLOBAL_V4 missing")?,
        )?;
        let styx_allow_global_v6 = LpmTrie::try_from(
            ebpf.take_map("STYX_ALLOW_GLOBAL_V6")
                .ok_or("STYX_ALLOW_GLOBAL_V6 missing")?,
        )?;
        let mut styx_block_v4 = LpmTrie::try_from(
            ebpf.take_map("STYX_BLOCK_V4")
                .ok_or("STYX_BLOCK_V4 missing")?,
        )?;
        let mut styx_block_v6 = LpmTrie::try_from(
            ebpf.take_map("STYX_BLOCK_V6")
                .ok_or("STYX_BLOCK_V6 missing")?,
        )?;
        let styx_resolver_v4 = LpmTrie::try_from(
            ebpf.take_map("STYX_RESOLVER_V4")
                .ok_or("STYX_RESOLVER_V4 missing")?,
        )?;
        let styx_resolver_v6 = LpmTrie::try_from(
            ebpf.take_map("STYX_RESOLVER_V6")
                .ok_or("STYX_RESOLVER_V6 missing")?,
        )?;
        seed_styx_mandatory_veto(&mut styx_block_v4, &mut styx_block_v6)?;
        // One random epoch per core process: the Go control plane full-resyncs
        // its policy whenever this value changes (§5 resync contract). The global
        // word starts with OFF/0 so an upgraded host behaves like 5.2.0.
        let (styx_epoch, styx_epoch_hex) = random_styx_epoch()?;
        styx_global.set(
            0,
            styx_flow::encode_styx_global(styx_epoch as u32, STYX_MODE_OFF, 0),
            0,
        )?;
        let styx_flow_events = RingBuf::try_from(
            ebpf.take_map("FLOW_EVENTS").ok_or("FLOW_EVENTS missing")?,
        )?;
        let styx_flow_emitted = PerCpuArray::try_from(
            ebpf.take_map("FLOW_EVENTS_EMITTED")
                .ok_or("FLOW_EVENTS_EMITTED missing")?,
        )?;
        let styx_ring_drops = PerCpuArray::try_from(
            ebpf.take_map("FLOW_RING_DROPS")
                .ok_or("FLOW_RING_DROPS missing")?,
        )?;
        let styx_agg_insert_failures = PerCpuArray::try_from(
            ebpf.take_map("FLOW_AGG_INSERT_FAILURES")
                .ok_or("FLOW_AGG_INSERT_FAILURES missing")?,
        )?;
        let styx_egress_parse_errors = PerCpuArray::try_from(
            ebpf.take_map("EGRESS_PARSE_ERRORS")
                .ok_or("EGRESS_PARSE_ERRORS missing")?,
        )?;
        let styx_egress_drops_total = PerCpuArray::try_from(
            ebpf.take_map("EGRESS_DROPS_TOTAL")
                .ok_or("EGRESS_DROPS_TOTAL missing")?,
        )?;
        let styx_egress_policy_drops = PerCpuArray::try_from(
            ebpf.take_map("EGRESS_POLICY_DROPS")
                .ok_or("EGRESS_POLICY_DROPS missing")?,
        )?;
        let styx_resolved = ebpf.take_map("STYX_RESOLVED").ok_or("STYX_RESOLVED missing")?;
        let flow_agg_v4 = ebpf.take_map("FLOW_AGG_V4").ok_or("FLOW_AGG_V4 missing")?;
        let flow_agg_v6 = ebpf.take_map("FLOW_AGG_V6").ok_or("FLOW_AGG_V6 missing")?;
        // Point 1 (§4): Titan exec-gate maps are always taken, even while BPF
        // LSM is inactive, so a stale eBPF object fails loudly at startup.
        let titan_exec_state = AyaArray::try_from(
            ebpf.take_map("TITAN_EXEC_STATE").ok_or("TITAN_EXEC_STATE missing")?,
        )?;
        let titan_exec_offsets = AyaArray::try_from(
            ebpf.take_map("TITAN_EXEC_OFFSETS").ok_or("TITAN_EXEC_OFFSETS missing")?,
        )?;
        let titan_exec_modes = AyaHashMap::try_from(
            ebpf.take_map("TITAN_EXEC_MODE").ok_or("TITAN_EXEC_MODE missing")?,
        )?;
        let titan_exec_policy = AyaHashMap::try_from(
            ebpf.take_map("TITAN_EXEC_POLICY").ok_or("TITAN_EXEC_POLICY missing")?,
        )?;
        let titan_exec_events = RingBuf::try_from(
            ebpf.take_map("TITAN_EXEC_EVENTS").ok_or("TITAN_EXEC_EVENTS missing")?,
        )?;
        let titan_exec_emitted = PerCpuArray::try_from(
            ebpf.take_map("TITAN_EXEC_EVENTS_EMITTED")
                .ok_or("TITAN_EXEC_EVENTS_EMITTED missing")?,
        )?;
        let titan_exec_ring_drops = PerCpuArray::try_from(
            ebpf.take_map("TITAN_EXEC_RING_DROPS").ok_or("TITAN_EXEC_RING_DROPS missing")?,
        )?;
        let titan_exec_read_failures = PerCpuArray::try_from(
            ebpf.take_map("TITAN_EXEC_READ_FAILURES").ok_or("TITAN_EXEC_READ_FAILURES missing")?,
        )?;
        let titan_exec_denies = PerCpuArray::try_from(
            ebpf.take_map("TITAN_EXEC_POLICY_DENIES").ok_or("TITAN_EXEC_POLICY_DENIES missing")?,
        )?;
        let titan_exec_audits = PerCpuArray::try_from(
            ebpf.take_map("TITAN_EXEC_POLICY_AUDITS").ok_or("TITAN_EXEC_POLICY_AUDITS missing")?,
        )?;
        let titan_exec_ctime_rejects = PerCpuArray::try_from(
            ebpf.take_map("TITAN_EXEC_CTIME_REJECTS").ok_or("TITAN_EXEC_CTIME_REJECTS missing")?,
        )?;
        // Point 5 (§5/§8): the lockdown maps are mandatory like every other §4
        // map. A stale eBPF object must fail startup instead of running the
        // command surface without a kernel word to verify against.
        let lockdown_state = AyaArray::try_from(
            ebpf.take_map("LOCKDOWN_STATE").ok_or("LOCKDOWN_STATE missing")?,
        )?;
        let lockdown_drops = PerCpuArray::try_from(
            ebpf.take_map("LOCKDOWN_DROPS").ok_or("LOCKDOWN_DROPS missing")?,
        )?;
        let lockdown_witness = PerCpuArray::try_from(
            ebpf.take_map("LOCKDOWN_WITNESS_PASSES").ok_or("LOCKDOWN_WITNESS_PASSES missing")?,
        )?;
        let (titan_epoch, titan_epoch_hex) = random_epoch_word()?;
        let mut titan_exec = TitanExecGate {
            state: titan_exec_state,
            offsets: titan_exec_offsets,
            modes: titan_exec_modes,
            policy: titan_exec_policy,
            events: titan_exec_events,
            emitted: titan_exec_emitted,
            ring_drops: titan_exec_ring_drops,
            read_failures: titan_exec_read_failures,
            denies: titan_exec_denies,
            audits: titan_exec_audits,
            ctime_rejects: titan_exec_ctime_rejects,
            store: titan_exec::TitanExecPolicy::new(),
            epoch: titan_epoch as u32,
            epoch_hex: titan_epoch_hex,
            mode: TITAN_EXEC_MODE_OFF,
            flags: 0,
            lsm_active: bpf_lsm_active,
            offsets_valid: false,
            attached: false,
            last_ring_drops: 0,
            rejected_events: 0,
        };
        // §6: BTF offsets are validated before any attach; invalid offsets leave
        // STATE/OFFSETS at their fail-safe zero words and no hook is attached.
        // Valid offsets are published even when this eBPF build cannot attach
        // them (hook arity outside the hard-coded slots): the status then names
        // `offsets=valid` and `unavailable`, never a silent enforcement claim.
        let mut titan_slots_supported = false;
        match btf_offsets::resolve_vmlinux_offsets() {
            Ok(offsets) => {
                titan_exec.offsets_valid = true;
                titan_slots_supported = titan_exec_offsets_match_ebpf_slots(&offsets);
                for (index, value) in encode_titan_exec_offsets_table(&offsets).iter().enumerate() {
                    titan_exec.offsets.set(index as u32, *value, 0)?;
                }
                if !titan_slots_supported {
                    eprintln!(
                        "Titan exec gate unavailable: hook arity bprm={} mmap={} is not supported by this eBPF build; attaching nothing",
                        offsets.bprm_nargs, offsets.mmap_nargs
                    );
                }
            }
            Err(error) => eprintln!(
                "Titan exec gate unavailable: BTF offsets are invalid ({error}); attaching nothing"
            ),
        }
        if titan_exec.offsets_valid && titan_slots_supported && bpf_lsm_active {
            match &lsm_btf {
                Some(btf) => match attach_titan_exec_lsm(&mut ebpf, btf) {
                    Ok(()) => titan_exec.attached = true,
                    Err(error) if !require_cell_lsm => eprintln!(
                        "Titan exec gate attach failed ({error}); enforcement unavailable"
                    ),
                    Err(error) => {
                        return Err(format!("required Titan exec BPF LSM attach failed: {error}").into())
                    }
                },
                None => eprintln!("Titan exec gate not attached: BPF LSM BTF unavailable"),
            }
        } else if !bpf_lsm_active {
            eprintln!(
                "Titan exec gate inactive: BPF LSM is not active; no attach and no enforcement claim (activation requires `lsm=...,bpf` + reboot)"
            );
        } else if !titan_exec.offsets_valid {
            eprintln!("Titan exec gate unavailable: runtime offsets are invalid; no attach");
        }
        if titan_exec.offsets_valid {
            titan_exec.write_state()?;
        } else {
            eprintln!("Titan exec STATE/OFFSETS left at fail-safe zero words (offsets invalid)");
        }
        let mut mode = String::from(ingress_mode);
        if cell_lsm_attached {
            mode.push_str("+bpf-lsm-cell");
        }
        mode.push_str("+titan-exec:");
        mode.push_str(titan_exec::ping_titan_exec_token(
            titan_exec.enforcement_available(),
            titan_exec.mode,
        ));
        let mut lockdown_config = lockdown::LockdownConfig::default();
        lockdown_config.state_file = Path::new(lockdown_state_path).to_path_buf();
        let lockdown = lockdown::LockdownCore::new(
            lockdown_config,
            Arc::new(AyaLockdownWordStore { map: Mutex::new(lockdown_state) }),
            Arc::new(LiveLockdownCounters {
                drops: lockdown_drops,
                witness_passes: lockdown_witness,
            }),
        )?;
        // 6.1.0 Module B: takes its mandatory maps and attaches the signal
        // tracepoint when the kernel permits it. An unavailable tracepoint is
        // reported as `attached=0`, never as enforcement.
        let worker_guard = worker_guard::WorkerGuardCore::load(&mut ebpf)?;
        // M2.2: mandatory RANSOM_* maps, optional kprobe attach, armed state.
        let ransom = ransom::RansomCore::load(&mut ebpf)?;
        // M2.4: mandatory CRED_GUARD_* maps, protected-inode policy, optional
        // file_open LSM attach (active=0 when BPF-LSM/BTF/policy are unavailable).
        let credential_guard =
            credential_guard::CredentialGuardCore::load(&mut ebpf, lsm_btf.as_ref(), bpf_lsm_active)?;
        let xdr_kernel = xdr_kernel::XdrKernelCore::load(&mut ebpf)?;
        Ok(Self {
            _ebpf: ebpf,
            exec_events,
            egress_events,
            ingress_events,
            ingress_events_emitted,
            ingress_ring_drops,
            ingress_track_insert_failures,
            cell_lsm_events,
            cell_lsm_policies,
            allow_v4,
            allow_v6,
            v4,
            v6,
            blocked: HashSet::new(),
            mode,
            ingress_mode,
            cell_lsm_attached,
            cell_policy_epoch: random_epoch()?,
            styx_global,
            styx_mode,
            styx_cell_allow_v4,
            styx_cell_allow_v6,
            styx_allow_global_v4,
            styx_allow_global_v6,
            styx_block_v4,
            styx_block_v6,
            styx_resolver_v4,
            styx_resolver_v6,
            styx_flow_events,
            styx_flow_emitted,
            styx_ring_drops,
            styx_agg_insert_failures,
            styx_egress_parse_errors,
            styx_egress_drops_total,
            styx_egress_policy_drops,
            _styx_resolved: styx_resolved,
            _flow_agg_v4: flow_agg_v4,
            _flow_agg_v6: flow_agg_v6,
            styx_epoch,
            styx_epoch_hex,
            styx_last_ring_drops: 0,
            styx_flow_rejected: 0,
            titan_exec,
            lockdown,
            worker_guard,
            ransom,
            credential_guard,
            xdr_kernel,
        })
    }

    fn cell_policy_epoch(&self) -> Result<String, BoxError> {
        self.require_cell_lsm()?;
        Ok(self.cell_policy_epoch.clone())
    }

    fn set_cell_policy(&mut self, cgroup_id: &str, flags: &str) -> Result<String, BoxError> {
        self.require_cell_lsm()?;
        let cgroup_id = parse_cell_cgroup_id(cgroup_id)?;
        let flags = parse_cell_policy_flags(flags)?;
        self.cell_lsm_policies.insert(cgroup_id, flags, 0)?;
        Ok("applied".to_owned())
    }

    fn delete_cell_policy(&mut self, cgroup_id: &str) -> Result<String, BoxError> {
        self.require_cell_lsm()?;
        let cgroup_id = parse_cell_cgroup_id(cgroup_id)?;
        match self.cell_lsm_policies.remove(&cgroup_id) {
            Ok(()) | Err(MapError::KeyNotFound) => Ok("deleted".to_owned()),
            Err(error) => Err(error.into()),
        }
    }

    fn take_cell_lsm_events(&mut self) -> Result<String, BoxError> {
        self.require_cell_lsm()?;
        let mut encoded = Vec::with_capacity(MAX_CELL_LSM_EVENTS_PER_RESPONSE);
        let mut skipped = 0u64;
        while encoded.len() < MAX_CELL_LSM_EVENTS_PER_RESPONSE {
            let Some(item) = self.cell_lsm_events.next() else {
                break;
            };
            match decode_cell_lsm_deny_event(&item)? {
                Some(record) => encoded.push(record),
                None => {
                    skipped = skipped.saturating_add(1);
                    if skipped == 1 {
                        eprintln!(
                            "kernel Gaia Cell LSM denied an AF_UNSPEC socket; the denial is enforced but the record is not representable on the typed control-plane wire"
                        );
                    }
                }
            }
        }
        if encoded.is_empty() {
            Ok("empty".to_owned())
        } else {
            Ok(encoded.join(","))
        }
    }

    fn require_cell_lsm(&self) -> Result<(), BoxError> {
        if self.cell_lsm_attached {
            Ok(())
        } else {
            Err("Gaia Cell BPF LSM is unavailable".into())
        }
    }

    fn take_exec_events(&mut self) -> Result<String, BoxError> {
        let mut encoded = Vec::with_capacity(MAX_EXEC_EVENTS_PER_RESPONSE);
        while encoded.len() < MAX_EXEC_EVENTS_PER_RESPONSE {
            let Some(item) = self.exec_events.next() else {
                break;
            };
            if item.len() != std::mem::size_of::<ExecEvent>() {
                return Err("kernel exec event has invalid size".into());
            }
            let pid = u32::from_ne_bytes(item[0..4].try_into()?);
            let uid = u32::from_ne_bytes(item[4..8].try_into()?);
            let gid = u32::from_ne_bytes(item[8..12].try_into()?);
            let comm: [u8; EXEC_COMM_BYTES] = item[12..12 + EXEC_COMM_BYTES].try_into()?;
            let comm_len = comm
                .iter()
                .position(|value| *value == 0)
                .unwrap_or(EXEC_COMM_BYTES);
            encoded.push(format!(
                "{pid}:{uid}:{gid}:{}",
                hex::encode(&comm[..comm_len])
            ));
        }
        if encoded.is_empty() {
            Ok("empty".to_owned())
        } else {
            Ok(encoded.join(","))
        }
    }

    fn per_cpu_counter_sum(counter: &PerCpuArray<MapData, u64>) -> Result<u64, BoxError> {
        let values = counter.get(&0, 0)?;
        Ok(values
            .iter()
            .copied()
            .fold(0u64, |sum, value| sum.saturating_add(value)))
    }

    /// §5 PING: the existing mode token plus the additive lockdown state.
    fn ping_mode(&self) -> String {
        format!("{}{}", self.mode, self.lockdown.ping_suffix())
    }

    fn ingress_health(&self) -> Result<String, BoxError> {
        let emitted = Self::per_cpu_counter_sum(&self.ingress_events_emitted)?;
        let ring_drops = Self::per_cpu_counter_sum(&self.ingress_ring_drops)?;
        let track_insert_failures = Self::per_cpu_counter_sum(&self.ingress_track_insert_failures)?;
        // A fourth field, appended rather than inserted so a control plane from before
        // this change still parses the response. The mode is what an operator needs in
        // order to know whether the kernel enforces in the driver path, in the generic
        // path, or only at the traffic-control layer.
        Ok(format!(
            "{emitted}:{ring_drops}:{track_insert_failures}:{}",
            self.ingress_mode
        ))
    }

    fn take_ingress_events(&mut self) -> Result<String, BoxError> {
        let mut encoded = Vec::with_capacity(MAX_INGRESS_EVENTS_PER_RESPONSE);
        let mut rejected = 0u64;
        while encoded.len() < MAX_INGRESS_EVENTS_PER_RESPONSE {
            let Some(item) = self.ingress_events.next() else {
                break;
            };
            // One undecodable sample is skipped and named, not fatal.
            //
            // Returning an error here failed the entire drain, and the control plane reads a
            // failed drain as a lost kernel hook: the mandatory ingress sensor was declared
            // degraded, every automatic decision paused, and before the fail-closed change the
            // release gate emptied the kernel blocklist outright - a production host was found
            // unprotected twenty hours later. A record this process cannot interpret is a loss
            // of fidelity; it must not cost the protection.
            let Some(event) = decode_ingress_event(&item) else {
                if rejected < 4 {
                    eprintln!(
                        "kernel ingress sample rejected: {} bytes; size, family or counters are not consistent",
                        item.len()
                    );
                }
                rejected = rejected.saturating_add(1);
                continue;
            };
            let address_len = if event.family == NETWORK_FAMILY_V4 {
                4
            } else {
                NETWORK_ADDRESS_BYTES
            };
            encoded.push(format!(
                "{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}",
                event.family,
                event.protocol,
                event.tcp_flags,
                event.attempt_count,
                event.src_port,
                event.dst_port,
                event.packets,
                event.bytes,
                event.syn_count,
                event.ack_count,
                event.window_epoch_sec,
                hex::encode(&event.source[..address_len]),
                hex::encode(&event.destination[..address_len])
            ));
        }
        // A batch in which many samples cannot be decoded states something else: the wire format
        // itself does not match what this core expects. That is a real fault and the operator has
        // to hear about it, rather than being left with a sensor that silently receives nothing.
        if rejected >= INGRESS_REJECTED_ALARM_THRESHOLD {
            return Err(format!(
                "kernel ingress event format is inconsistent: {rejected} samples rejected in one drain"
            )
            .into());
        }
        if encoded.is_empty() {
            Ok("empty".to_owned())
        } else {
            Ok(encoded.join(","))
        }
    }

    fn take_egress_events(&mut self) -> Result<String, BoxError> {
        let mut encoded = Vec::with_capacity(MAX_EGRESS_EVENTS_PER_RESPONSE);
        while encoded.len() < MAX_EGRESS_EVENTS_PER_RESPONSE {
            let Some(item) = self.egress_events.next() else {
                break;
            };
            if item.len() != std::mem::size_of::<EgressDropEvent>() {
                return Err("kernel egress event has invalid size".into());
            }
            let pid = u32::from_ne_bytes(item[0..4].try_into()?);
            let uid = u32::from_ne_bytes(item[4..8].try_into()?);
            let family = item[8];
            let protocol = item[9];
            let action = item[10];
            if action != ACTION_DROP || !matches!(family, NETWORK_FAMILY_V4 | NETWORK_FAMILY_V6) {
                return Err("kernel egress event has invalid metadata".into());
            }
            let address_len = if family == NETWORK_FAMILY_V4 {
                4
            } else {
                NETWORK_ADDRESS_BYTES
            };
            let destination = &item[12..12 + address_len];
            let comm_start = 12 + NETWORK_ADDRESS_BYTES;
            let comm: [u8; EXEC_COMM_BYTES] =
                item[comm_start..comm_start + EXEC_COMM_BYTES].try_into()?;
            let comm_len = comm
                .iter()
                .position(|value| *value == 0)
                .unwrap_or(EXEC_COMM_BYTES);
            encoded.push(format!(
                "{pid}:{uid}:{family}:{protocol}:{}:{}",
                hex::encode(destination),
                hex::encode(&comm[..comm_len])
            ));
        }
        if encoded.is_empty() {
            Ok("empty".to_owned())
        } else {
            Ok(encoded.join(","))
        }
    }

    fn add(&mut self, target: &str) -> Result<(), BoxError> {
        let target = parse_target(target)?;
        match target {
            Target::V4(ip, prefix) => {
                self.v4
                    .insert(&Key::new(prefix, ip.octets()), ACTION_DROP, 0)?;
            }
            Target::V6(ip, prefix) => {
                self.v6
                    .insert(&Key::new(prefix, ip.octets()), ACTION_DROP, 0)?;
            }
        }
        self.blocked.insert(target);
        Ok(())
    }

    fn del(&mut self, target: &str) -> Result<(), BoxError> {
        let target = parse_target(target)?;
        match target {
            Target::V4(ip, prefix) => self.v4.remove(&Key::new(prefix, ip.octets()))?,
            Target::V6(ip, prefix) => self.v6.remove(&Key::new(prefix, ip.octets()))?,
        }
        self.blocked.remove(&target);
        Ok(())
    }

    fn clear_blocklist(&mut self) -> Result<(), BoxError> {
        let targets: Vec<Target> = self.blocked.iter().copied().collect();
        let mut failures = 0usize;
        for target in targets {
            let result = match target {
                Target::V4(ip, prefix) => self.v4.remove(&Key::new(prefix, ip.octets())),
                Target::V6(ip, prefix) => self.v6.remove(&Key::new(prefix, ip.octets())),
            };
            match result {
                Ok(()) => {
                    self.blocked.remove(&target);
                }
                Err(error) => {
                    failures += 1;
                    eprintln!("kernel blocklist clear failed for {target:?}: {error}");
                }
            }
        }
        if failures == 0 {
            Ok(())
        } else {
            Err(format!("kernel blocklist clear retained {failures} entries").into())
        }
    }

    fn allow_add(&mut self, target: &str) -> Result<(), BoxError> {
        match parse_target(target)? {
            Target::V4(ip, prefix) => {
                self.allow_v4.insert(&Key::new(prefix, ip.octets()), 1, 0)?;
            }
            Target::V6(ip, prefix) => {
                self.allow_v6.insert(&Key::new(prefix, ip.octets()), 1, 0)?;
            }
        }
        Ok(())
    }

    fn allow_del(&mut self, target: &str) -> Result<(), BoxError> {
        match parse_target(target)? {
            Target::V4(ip, prefix) => self.allow_v4.remove(&Key::new(prefix, ip.octets()))?,
            Target::V6(ip, prefix) => self.allow_v6.remove(&Key::new(prefix, ip.octets()))?,
        }
        Ok(())
    }

    // ------------------------------------------------------------------
    // Point 3 (Phase 1) STYX command surface (§5/§7).
    //
    // Every method parses and validates the complete argument list first and
    // only then performs its single map operation, so a rejected command can
    // never leave a partial policy change behind. Deletes are idempotent.
    // ------------------------------------------------------------------

    fn styx_version(&self) -> Result<String, BoxError> {
        Ok(styx_flow::STYX_WIRE_VERSION.to_owned())
    }

    fn styx_epoch(&self) -> Result<String, BoxError> {
        Ok(self.styx_epoch_hex.clone())
    }

    fn styx_set_global(&mut self, args: &[&str]) -> Result<String, BoxError> {
        let request = styx_flow::parse_global_request(args)?;
        // The epoch is fixed for the process lifetime, so a global update only
        // rewrites mode/flags and keeps the kernel cache epoch valid.
        let word =
            styx_flow::encode_styx_global(self.styx_epoch as u32, request.mode, request.flags);
        self.styx_global.set(0, word, 0)?;
        Ok("applied".to_owned())
    }

    fn styx_mode_set(&mut self, args: &[&str]) -> Result<String, BoxError> {
        let (cgroup_id, mode, flags) = styx_flow::parse_mode_set_request(args)?;
        self.styx_mode.insert(cgroup_id, mode | flags, 0)?;
        Ok("applied".to_owned())
    }

    fn styx_mode_delete(&mut self, args: &[&str]) -> Result<String, BoxError> {
        let cgroup_id = styx_flow::parse_mode_del_request(args)?;
        styx_map_result(self.styx_mode.remove(&cgroup_id), false)
    }

    fn styx_allow(&mut self, args: &[&str], add: bool) -> Result<String, BoxError> {
        let key = styx_flow::parse_allow_request(args)?.allow_key()?;
        let result = match key {
            styx_flow::StyxAllowKey::CellV4(key, prefix) => {
                if add {
                    self.styx_cell_allow_v4.insert(&Key::new(prefix, key), 1, 0)
                } else {
                    self.styx_cell_allow_v4.remove(&Key::new(prefix, key))
                }
            }
            styx_flow::StyxAllowKey::CellV6(key, prefix) => {
                if add {
                    self.styx_cell_allow_v6.insert(&Key::new(prefix, key), 1, 0)
                } else {
                    self.styx_cell_allow_v6.remove(&Key::new(prefix, key))
                }
            }
            styx_flow::StyxAllowKey::GlobalV4(key, prefix) => {
                if add {
                    self.styx_allow_global_v4.insert(&Key::new(prefix, key), 1, 0)
                } else {
                    self.styx_allow_global_v4.remove(&Key::new(prefix, key))
                }
            }
            styx_flow::StyxAllowKey::GlobalV6(key, prefix) => {
                if add {
                    self.styx_allow_global_v6.insert(&Key::new(prefix, key), 1, 0)
                } else {
                    self.styx_allow_global_v6.remove(&Key::new(prefix, key))
                }
            }
        };
        styx_map_result(result, add)
    }

    fn styx_block(&mut self, args: &[&str], add: bool) -> Result<String, BoxError> {
        self.styx_prefix_change(args, add, false)
    }

    fn styx_resolver(&mut self, args: &[&str], add: bool) -> Result<String, BoxError> {
        self.styx_prefix_change(args, add, true)
    }

    fn styx_prefix_change(
        &mut self,
        args: &[&str],
        add: bool,
        resolver: bool,
    ) -> Result<String, BoxError> {
        let key = styx_flow::parse_prefix_request(args)?.prefix_key()?;
        let result = match (resolver, key) {
            (false, styx_flow::StyxPrefixKey::V4(key, prefix)) => {
                if add {
                    self.styx_block_v4.insert(&Key::new(prefix, key), 1, 0)
                } else {
                    self.styx_block_v4.remove(&Key::new(prefix, key))
                }
            }
            (false, styx_flow::StyxPrefixKey::V6(key, prefix)) => {
                if add {
                    self.styx_block_v6.insert(&Key::new(prefix, key), 1, 0)
                } else {
                    self.styx_block_v6.remove(&Key::new(prefix, key))
                }
            }
            (true, styx_flow::StyxPrefixKey::V4(key, prefix)) => {
                if add {
                    self.styx_resolver_v4.insert(&Key::new(prefix, key), 1, 0)
                } else {
                    self.styx_resolver_v4.remove(&Key::new(prefix, key))
                }
            }
            (true, styx_flow::StyxPrefixKey::V6(key, prefix)) => {
                if add {
                    self.styx_resolver_v6.insert(&Key::new(prefix, key), 1, 0)
                } else {
                    self.styx_resolver_v6.remove(&Key::new(prefix, key))
                }
            }
        };
        styx_map_result(result, add)
    }

    fn styx_take_flow_events(&mut self) -> Result<String, BoxError> {
        let mut records = Vec::with_capacity(styx_flow::MAX_STYX_FLOW_EVENTS_PER_RESPONSE);
        while records.len() < styx_flow::MAX_STYX_FLOW_EVENTS_PER_RESPONSE {
            let Some(item) = self.styx_flow_events.next() else {
                break;
            };
            if item.len() != STYX_FLOW_EVENT_WIRE_BYTES {
                self.styx_flow_rejected = self.styx_flow_rejected.saturating_add(1);
                continue;
            }
            // A record this core cannot decode is skipped and counted, never a
            // reason to abort the drain (§3.2: no degradation on first miss).
            let Some(event) = decode_styx_flow_event(&item) else {
                self.styx_flow_rejected = self.styx_flow_rejected.saturating_add(1);
                continue;
            };
            let Some(encoded) = styx_flow::encode_styx_flow_event_text(&event) else {
                self.styx_flow_rejected = self.styx_flow_rejected.saturating_add(1);
                continue;
            };
            records.push(encoded);
        }
        let ring_drops = Self::per_cpu_counter_sum(&self.styx_ring_drops)?;
        let dropped = ring_drops.saturating_sub(self.styx_last_ring_drops);
        self.styx_last_ring_drops = ring_drops;
        let response = styx_flow_batch_response(&records, dropped);
        if response.len() > styx_flow::MAX_STYX_FLOW_PAYLOAD_BYTES {
            return Err("styx flow batch exceeds the response payload budget".into());
        }
        Ok(response)
    }

    fn styx_flow_health(&self) -> Result<String, BoxError> {
        let counters = [
            Self::per_cpu_counter_sum(&self.styx_flow_emitted)?,
            Self::per_cpu_counter_sum(&self.styx_ring_drops)?,
            Self::per_cpu_counter_sum(&self.styx_agg_insert_failures)?,
            Self::per_cpu_counter_sum(&self.styx_egress_parse_errors)?,
            Self::per_cpu_counter_sum(&self.styx_egress_drops_total)?,
            Self::per_cpu_counter_sum(&self.styx_egress_policy_drops)?,
        ];
        Ok(styx_flow::encode_styx_flow_health(&counters))
    }
}

/// Maps one STYX map write to the §5 `added`/`deleted` payload. A missing key on
/// DELETE is a success: the delete commands are idempotent by contract.
fn styx_map_result(result: Result<(), MapError>, add: bool) -> Result<String, BoxError> {
    match result {
        Ok(()) => Ok(if add { "added" } else { "deleted" }.to_owned()),
        Err(MapError::KeyNotFound) if !add => Ok("deleted".to_owned()),
        Err(error) => Err(error.into()),
    }
}

/// §3.3 response shape: `empty` only for a truly idle poll. A drop-only poll
/// still reports the FLOW_RING_DROPS delta (`<dropped>|`) so the control plane
/// can see the visibility loss instead of a silent "no events".
fn styx_flow_batch_response(records: &[String], dropped: u64) -> String {
    if records.is_empty() {
        if dropped == 0 {
            "empty".to_owned()
        } else {
            format!("{dropped}|")
        }
    } else {
        format!("{dropped}|{}", records.join(","))
    }
}

/// Seeds the §4 mandatory veto. Failure is fatal at startup: the core must not
/// claim enforcement without the metadata/link-local/multicast guard.
fn seed_styx_mandatory_veto(
    block_v4: &mut LpmTrie<MapData, [u8; 4], u8>,
    block_v6: &mut LpmTrie<MapData, [u8; 16], u8>,
) -> Result<(), BoxError> {
    for (prefix, address) in STYX_MANDATORY_VETO_V4 {
        block_v4.insert(&Key::new(*prefix, *address), 1, 0)?;
    }
    for (prefix, address) in STYX_MANDATORY_VETO_V6 {
        block_v6.insert(&Key::new(*prefix, *address), 1, 0)?;
    }
    Ok(())
}

/// Random per-start epoch word plus its 16 lowercase hex characters; the low
/// 32 bits are what `STYX_GLOBAL`/`TITAN_EXEC_STATE` can carry.
fn random_epoch_word() -> Result<(u64, String), BoxError> {
    let mut bytes = [0u8; 8];
    File::open("/dev/urandom")?.read_exact(&mut bytes)?;
    let epoch = u64::from_ne_bytes(bytes);
    Ok((epoch, format!("{epoch:016x}")))
}

/// §5 `STYX_EPOCH`: random per core start.
fn random_styx_epoch() -> Result<(u64, String), BoxError> {
    random_epoch_word()
}

/// §0/§6: the Cell socket LSM program is only loaded with an active LSM list
/// (the caller checked `/sys/kernel/security/lsm`); BTF is parsed once per start.
fn attach_cell_socket_lsm(ebpf: &mut Ebpf, btf: &Btf) -> Result<(), BoxError> {
    let program: &mut Lsm = ebpf
        .program_mut("gedefense_cell_socket_create")
        .ok_or("Gaia Cell socket LSM program missing")?
        .try_into()?;
    program.load("socket_create", btf)?;
    program.attach()?;
    Ok(())
}

/// §6: load and attach both Titan exec-gate hooks; only called when BPF LSM is
/// active and the BTF offsets were validated. Both attaches share one BTF.
fn attach_titan_exec_lsm(ebpf: &mut Ebpf, btf: &Btf) -> Result<(), BoxError> {
    for (symbol, hook) in [
        ("gedefense_titan_exec_bprm", "bprm_check_security"),
        ("gedefense_titan_exec_mmap", "mmap_file"),
    ] {
        let program: &mut Lsm = ebpf
            .program_mut(symbol)
            .ok_or_else(|| format!("Titan exec LSM program {symbol} missing"))?
            .try_into()?;
        program.load(hook, btf)?;
        program.attach()?;
    }
    Ok(())
}

fn random_epoch() -> Result<String, BoxError> {
    let mut bytes = [0u8; 16];
    File::open("/dev/urandom")?.read_exact(&mut bytes)?;
    Ok(hex::encode(bytes))
}

fn parse_cell_cgroup_id(value: &str) -> Result<u64, BoxError> {
    let parsed = value.parse::<u64>()?;
    if parsed == 0 {
        return Err("Gaia Cell cgroup ID must be non-zero".into());
    }
    Ok(parsed)
}

fn parse_cell_policy_flags(value: &str) -> Result<u8, BoxError> {
    let parsed = value.parse::<u8>()?;
    // 6.1.0 Module D widens the policy word with the LPE deny bits. Zero and
    // unknown bits stay rejected; every pre-6.1.0 value (1) keeps its exact
    // meaning.
    if parsed == 0 || parsed & !CELL_LSM_DENY_ALL_KNOWN != 0 {
        return Err("Gaia Cell LSM policy flags are invalid".into());
    }
    Ok(parsed)
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
enum Target {
    V4(Ipv4Addr, u32),
    V6(Ipv6Addr, u32),
}

fn parse_target(value: &str) -> Result<Target, BoxError> {
    let (ip, prefix) = match value.split_once('/') {
        Some((address, raw_prefix)) => (address, Some(raw_prefix.parse::<u32>()?)),
        None => (value, None),
    };
    match ip.parse::<IpAddr>()? {
        IpAddr::V4(address) => {
            let prefix = prefix.unwrap_or(32);
            if prefix > 32 {
                return Err("invalid IPv4 prefix".into());
            }
            let bits = u32::from(address);
            let mask = if prefix == 0 {
                0
            } else {
                u32::MAX << (32 - prefix)
            };
            let network = Ipv4Addr::from(bits & mask);
            if network.is_unspecified() {
                return Err("unspecified IPv4 network is forbidden".into());
            }
            Ok(Target::V4(network, prefix))
        }
        IpAddr::V6(address) => {
            let prefix = prefix.unwrap_or(128);
            if prefix > 128 {
                return Err("invalid IPv6 prefix".into());
            }
            let bits = u128::from(address);
            let mask = if prefix == 0 {
                0
            } else {
                u128::MAX << (128 - prefix)
            };
            let network = Ipv6Addr::from(bits & mask);
            if network.is_unspecified() {
                return Err("unspecified IPv6 network is forbidden".into());
            }
            Ok(Target::V6(network, prefix))
        }
    }
}

fn valid_nonce(nonce: &str) -> bool {
    nonce.len() == 32 && nonce.bytes().all(|byte| byte.is_ascii_hexdigit())
}

// F-20: the key is opened exactly once with O_NOFOLLOW and every property
// (type, mode, owner, size) is verified on that same file descriptor before the
// descriptor is read. The former symlink_metadata + path-based fs::read pair
// resolved the path twice and could be swapped between check and read.
fn load_secret_key(path: &str, control_gid: u32, label: &str) -> Result<Vec<u8>, BoxError> {
    let file = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
    {
        Ok(file) => file,
        Err(error) if error.raw_os_error() == Some(libc::ELOOP) => {
            return Err(format!("{label} must be a regular non-symlink file").into())
        }
        Err(error) => return Err(error.into()),
    };
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(format!("{label} must be a regular non-symlink file").into());
    }
    let mode = metadata.permissions().mode() & 0o777;
    let production_profile = metadata.uid() == 0 && metadata.gid() == control_gid && mode == 0o640;
    let local_profile = metadata.uid() == 0 && mode == 0o600;
    if !production_profile && !local_profile {
        return Err(format!(
            "{label} ownership/mode invalid: uid={} gid={} mode={mode:#o}",
            metadata.uid(),
            metadata.gid()
        )
        .into());
    }
    if metadata.len() != 32 {
        return Err(format!("{label} must contain exactly 32 bytes").into());
    }
    let mut key = Vec::with_capacity(32);
    (&file).take(33).read_to_end(&mut key)?;
    if key.len() != 32 {
        return Err(format!("{label} must contain exactly 32 bytes").into());
    }
    Ok(key)
}

fn load_auth_key(path: &str, control_gid: u32) -> Result<Vec<u8>, BoxError> {
    load_secret_key(path, control_gid, "IPC authentication key")
}

fn parse_quarantine_identity(token: &str) -> Result<FileIdentity, BoxError> {
    FileIdentity::decode(token)
}

fn unix_seconds() -> Result<u64, BoxError> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}

// F-20: the IPC MAC covers length-less fields joined by a 0x1f delimiter. That
// encoding is only unambiguous when no field itself contains the delimiter.
// Fields are therefore rejected when they do, which keeps the on-wire format
// compatible with the control plane and makes ("ab","c") and ("a","bc") - or
// any field split that smuggles the separator - impossible to conflate.
const MAC_FIELD_SEPARATOR: u8 = 0x1f;

fn pack_mac_fields(fields: &[&str]) -> Result<Vec<u8>, BoxError> {
    let mut packed = Vec::with_capacity(64);
    for (index, field) in fields.iter().enumerate() {
        if field.as_bytes().contains(&MAC_FIELD_SEPARATOR) {
            return Err("IPC field contains the MAC field separator".into());
        }
        if index > 0 {
            packed.push(MAC_FIELD_SEPARATOR);
        }
        packed.extend_from_slice(field.as_bytes());
    }
    Ok(packed)
}

fn authenticated_mac(key: &[u8], fields: &[&str]) -> Result<Vec<u8>, BoxError> {
    let packed = pack_mac_fields(fields)?;
    let mut mac = HmacSha256::new_from_slice(key)?;
    mac.update(&packed);
    Ok(mac.finalize().into_bytes().to_vec())
}

fn verify_mac(key: &[u8], fields: &[&str], encoded_mac: &str) -> Result<(), BoxError> {
    let supplied = hex::decode(encoded_mac)?;
    if supplied.len() != 32 {
        return Err("request authentication failed".into());
    }
    let packed = pack_mac_fields(fields)?;
    let mut mac = HmacSha256::new_from_slice(key)?;
    mac.update(&packed);
    mac.verify_slice(&supplied)
        .map_err(|_| "request authentication failed".into())
}

// The one timestamp policy for authenticated IPC. A timestamp may be at most
// CLOCK_WINDOW_SECS old and CLOCK_FUTURE_TOLERANCE_SECS ahead of the local
// clock. This function is used both before the MAC check (cheap filter) and as
// part of the replay decision, so the two can never drift apart.
fn request_timestamp_error(now: u64, stamp: u64) -> Option<&'static str> {
    if stamp > now.saturating_add(CLOCK_FUTURE_TOLERANCE_SECS) {
        return Some("future");
    }
    if now.saturating_sub(stamp) > CLOCK_WINDOW_SECS {
        return Some("stale");
    }
    None
}

struct ReplayGuard {
    set: HashSet<String>,
    // (nonce, expires_at). The expiry is derived from the later of arrival time
    // and request timestamp plus one full clock window, so a nonce is never
    // evicted while its own timestamp could still pass the window check.
    order: VecDeque<(String, u64)>,
}

impl ReplayGuard {
    fn new() -> Self {
        Self {
            set: HashSet::with_capacity(REPLAY_CACHE_CAPACITY),
            order: VecDeque::with_capacity(REPLAY_CACHE_CAPACITY),
        }
    }

    fn accept(&mut self, nonce: &str, now: u64, stamp: u64) -> bool {
        // A request outside its own validity window is never accepted, no matter
        // whether its nonce is still cached.
        if request_timestamp_error(now, stamp).is_some() {
            return false;
        }

        while self
            .order
            .front()
            .is_some_and(|(_, expires_at)| *expires_at < now)
        {
            let Some((old_nonce, _)) = self.order.pop_front() else {
                break;
            };
            self.set.remove(&old_nonce);
        }

        // A nonce already in the window is a replay. Nothing else is.
        if self.set.contains(nonce) {
            return false;
        }

        // At capacity, evict the oldest entry instead of refusing the request.
        //
        // The guard exists to reject duplicates, and a full cache is not evidence of one.
        // Treating it as though it were turned a burst of legitimate commands into a
        // lockout: the control plane applies its blocklist one entry at a time, so a list
        // larger than the capacity could never be applied at all. Every command past the
        // 4096th was refused as a replay, including the health checks that decide whether
        // the core is considered connected - so the platform reported its own kernel
        // channel offline while the kernel was answering it perfectly well, and the
        // entries it had already added stayed in the map.
        //
        // Eviction is safe because the nonce cache is the second line of defence, not the
        // first: every request also carries a timestamp that is rejected outright when it
        // falls outside CLOCK_WINDOW_SECS, and nonce entries outlive that window because
        // they are keyed to max(arrival, request time) + CLOCK_WINDOW_SECS.
        while self.order.len() >= REPLAY_CACHE_CAPACITY {
            match self.order.pop_front() {
                Some((old_nonce, _)) => {
                    self.set.remove(&old_nonce);
                }
                None => break,
            }
        }

        let expires_at = now.max(stamp).saturating_add(CLOCK_WINDOW_SECS);
        self.set.insert(nonce.to_owned());
        self.order.push_back((nonce.to_owned(), expires_at));
        true
    }
}

// GAIA-CELL LSM DENY EVENT DECODING
//
// One malformed record must not be able to wedge the whole enforcement-event
// drain: the control plane reads a failed CELL_LSM_EVENTS call as a lost kernel
// hook, pauses automatic decisions and raises a critical alert, so a single
// undecodable record is a cheap denial of service against event correlation.
//
// AF_UNSPEC (0) is a legal socket(2) family: the LSM hook in the kernel denies
// it like every other non-AF_UNIX family and emits it verbatim. The IPC wire
// record carries only a typed, non-zero, non-AF_UNIX family (the control plane
// rejects anything else and would then discard the entire batch), so that one
// denial cannot be represented. It is skipped explicitly, which keeps the rest
// of the batch intact; the kernel denial itself has already been enforced.
fn decode_cell_lsm_deny_event(item: &[u8]) -> Result<Option<String>, BoxError> {
    if item.len() != std::mem::size_of::<CellLsmDenyEvent>() {
        return Err("kernel Gaia Cell LSM event has invalid size".into());
    }
    let cgroup_id = u64::from_ne_bytes(item[0..8].try_into()?);
    let pid = u32::from_ne_bytes(item[8..12].try_into()?);
    let uid = u32::from_ne_bytes(item[12..16].try_into()?);
    let family = i32::from_ne_bytes(item[16..20].try_into()?);
    let action = item[20];
    if cgroup_id == 0 || pid == 0 || action != ACTION_DROP {
        return Err("kernel Gaia Cell LSM event has invalid metadata".into());
    }
    if family == libc::AF_UNSPEC {
        return Ok(None);
    }
    if family <= 0 || family > i32::from(u8::MAX) || family == libc::AF_UNIX {
        return Err("kernel Gaia Cell LSM event has invalid metadata".into());
    }
    Ok(Some(format!("{cgroup_id}:{pid}:{uid}:{family}")))
}

fn write_response(
    stream: &mut UnixStream,
    key: &[u8],
    nonce: &str,
    status: &str,
    message: &str,
) -> Result<(), BoxError> {
    let bounded = if message.len() > MAX_RESPONSE_BYTES {
        "response truncated"
    } else {
        message
    };
    let encoded = URL_SAFE_NO_PAD.encode(bounded.as_bytes());
    let response_tag = format!("{PROTOCOL}R");
    let mac = authenticated_mac(key, &[&response_tag, nonce, status, &encoded])?;
    writeln!(
        stream,
        "{} {} {} {} {}",
        response_tag,
        nonce,
        status,
        encoded,
        hex::encode(mac)
    )?;
    Ok(())
}

// F-HOTFIX-4: systemd's RestrictSUIDSGID=yes makes the kernel return ENOSYS
// for openat2 on this sandbox (observed on Ubuntu 24.04/systemd 255 with
// RestrictSUIDSGID enabled), which broke quarantine and user-scan path
// resolution even though openat() is fully permitted. Resolve a path
// component-wise with openat(O_NOFOLLOW) as a safe fallback: every component
// is opened relative to the already validated parent descriptor and symbolic
// links are refused at every step.
fn open_componentwise(path: &std::path::Path, final_flags: i32) -> Result<std::fs::File, BoxError> {
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    let mut components = path.components();
    let anchor = match components.next() {
        Some(std::path::Component::RootDir) => {
            let fd = unsafe {
                libc::open(
                    c"/".as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
                )
            };
            if fd < 0 {
                return Err(std::io::Error::last_os_error().into());
            }
            unsafe { OwnedFd::from_raw_fd(fd) }
        }
        _ => return Err("component-wise open requires an absolute path".into()),
    };
    let remaining: std::path::PathBuf = components.collect();
    open_componentwise_from(anchor.as_raw_fd(), &remaining, final_flags)
}

// Resolve an already validated relative path one component at a time from an
// open anchor directory descriptor. The anchor descriptor is the trust boundary:
// no component can leave it (`..` and root components are rejected), and
// O_NOFOLLOW refuses a symlink at every step. Used as the openat2 fallback for
// both the absolute-path scan open and the home-anchored quarantine open.
pub(crate) fn open_componentwise_from(
    anchor: std::os::fd::RawFd,
    relative: &std::path::Path,
    final_flags: i32,
) -> Result<std::fs::File, BoxError> {
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    if relative.is_absolute() || relative.as_os_str().is_empty() {
        return Err("component-wise open requires a relative file path".into());
    }
    let duplicate = unsafe { libc::fcntl(anchor, libc::F_DUPFD_CLOEXEC, 3) };
    if duplicate < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let mut current: OwnedFd = unsafe { OwnedFd::from_raw_fd(duplicate) };
    let components: Vec<_> = relative.components().collect();
    let mut opened = false;
    for (index, component) in components.iter().enumerate() {
        match component {
            std::path::Component::Normal(name) => {
                let name_c = std::ffi::CString::new(name.as_encoded_bytes())?;
                let is_last = index + 1 == components.len();
                let flags = if is_last {
                    final_flags | libc::O_CLOEXEC | libc::O_NOFOLLOW
                } else {
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW
                };
                let fd = unsafe { libc::openat(current.as_raw_fd(), name_c.as_ptr(), flags) };
                if fd < 0 {
                    return Err(std::io::Error::last_os_error().into());
                }
                current = unsafe { OwnedFd::from_raw_fd(fd) };
                opened = true;
            }
            std::path::Component::CurDir => continue,
            _ => return Err("component-wise open rejects parent or root components".into()),
        }
    }
    if !opened {
        return Err("component-wise open requires a file component".into());
    }
    Ok(std::fs::File::from(current))
}

fn process_command(
    core: &mut KernelCore,
    quarantine: &QuarantineBroker,
    scanner: &MalwareScanner,
    canary: &CanaryBroker,
    parts: &[&str],
) -> Result<String, BoxError> {
    match parts {
        ["PING"] => Ok(core.ping_mode()),
        ["CELL_POLICY_EPOCH"] => core.cell_policy_epoch(),
        ["CELL_POLICY_SET", cgroup_id, flags] => core.set_cell_policy(cgroup_id, flags),
        ["CELL_POLICY_DEL", cgroup_id] => core.delete_cell_policy(cgroup_id),
        ["CELL_LSM_EVENTS"] => core.take_cell_lsm_events(),
        ["EXEC_EVENTS"] => core.take_exec_events(),
        ["EXEC_ARGV_EVENTS"] => core.xdr_kernel.take_exec_argv_events(),
        ["KERNEL_PROBE_EVENTS"] => core.xdr_kernel.take_kernel_probe_events(),
        ["EGRESS_EVENTS"] => core.take_egress_events(),
        ["INGRESS_EVENTS"] => core.take_ingress_events(),
        ["INGRESS_HEALTH"] => core.ingress_health(),
        ["STYX_VERSION"] => core.styx_version(),
        ["STYX_EPOCH"] => core.styx_epoch(),
        ["STYX_GLOBAL", args @ ..] => core.styx_set_global(args),
        ["STYX_MODE_SET", args @ ..] => core.styx_mode_set(args),
        ["STYX_MODE_DEL", args @ ..] => core.styx_mode_delete(args),
        ["STYX_ALLOW_ADD", args @ ..] => core.styx_allow(args, true),
        ["STYX_ALLOW_DEL", args @ ..] => core.styx_allow(args, false),
        ["STYX_BLOCK_ADD", args @ ..] => core.styx_block(args, true),
        ["STYX_BLOCK_DEL", args @ ..] => core.styx_block(args, false),
        ["STYX_RESOLVER_ADD", args @ ..] => core.styx_resolver(args, true),
        ["STYX_RESOLVER_DEL", args @ ..] => core.styx_resolver(args, false),
        ["STYX_FLOW_EVENTS"] => core.styx_take_flow_events(),
        ["STYX_FLOW_HEALTH"] => core.styx_flow_health(),
        // Point 1 (§5): Titan exec-gate command surface. Every argument is
        // validated before the first map write; enforcement cannot be claimed
        // while LSM/offsets/attach are not all green.
        ["TITAN_EXEC_VERSION"] => core.titan_exec.version(),
        ["TITAN_EXEC_EPOCH"] => core.titan_exec.epoch(),
        ["TITAN_EXEC_STATUS"] => core.titan_exec.status(),
        ["TITAN_EXEC_SET_GLOBAL", mode, flags] => core.titan_exec.set_global(mode, flags),
        ["TITAN_EXEC_ALLOW_ADD", path] => core.titan_exec.allow_add(path),
        ["TITAN_EXEC_ALLOW_ADD_BATCH", token] => core.titan_exec.allow_add_batch(token),
        ["TITAN_EXEC_ALLOW_DEL", dev, ino] => core.titan_exec.allow_del(dev, ino),
        ["TITAN_EXEC_CLEAR"] => core.titan_exec.clear(),
        ["TITAN_EXEC_SCOPE_SET", cgroup, mode, flags] => {
            core.titan_exec.scope_set(cgroup, mode, flags)
        }
        ["TITAN_EXEC_SCOPE_DEL", cgroup] => core.titan_exec.scope_del(cgroup),
        ["TITAN_EXEC_EVENTS"] => core.titan_exec.take_events(),
        ["TITAN_EXEC_HEALTH"] => core.titan_exec.health(),
        // 6.1.0 Module B: worker crash-storm sensor command surface.
        ["WORKER_GUARD_SET", state] => core.worker_guard.set_enabled(state),
        ["WORKER_GUARD_COMM_ADD", comm] => core.worker_guard.comm_add(comm),
        ["WORKER_GUARD_COMM_DEL", comm] => core.worker_guard.comm_del(comm),
        ["WORKER_GUARD_UID_ADD", uid] => core.worker_guard.uid_add(uid),
        ["WORKER_GUARD_UID_DEL", uid] => core.worker_guard.uid_del(uid),
        ["WORKER_GUARD_EVENTS"] => core.worker_guard.take_events(),
        ["WORKER_GUARD_STATUS"] => core.worker_guard.status(),
        ["MALWARE_EVENTS"] => scanner.take_events(),
        // 6.2.0 M2.2: ransomware/rename-storm sensor (kernel audit -> core freeze).
        ["RANSOM_EVENTS"] => core.ransom.take_events(),
        ["RANSOM_STATUS"] => core.ransom.status(),
        ["RANSOM_SET", state] => core.ransom.set_armed_token(state),
        // 6.2.0 M2.4: file_open credential guard (kernel -EACCES, bounded evidence).
        ["CRED_GUARD_EVENTS"] => core.credential_guard.take_events(),
        ["CRED_GUARD_STATUS"] => core.credential_guard.status(),
        ["CRED_GUARD_SET", state] => core.credential_guard.set_armed_token(state),
        ["CLEAR_BLOCKLIST"] => core.clear_blocklist().map(|_| "cleared".into()),
        ["VERIFY_EMPTY"] if core.blocked.is_empty() => Ok("empty".into()),
        ["VERIFY_EMPTY"] => Err("blocklist is not empty".into()),
        ["ADD", target] => core.add(target).map(|_| "added".into()),
        ["DEL", target] => core.del(target).map(|_| "deleted".into()),
        ["ALLOW_ADD", target] => core.allow_add(target).map(|_| "allowlisted".into()),
        ["ALLOW_DEL", target] => core
            .allow_del(target)
            .map(|_| "allowlist entry deleted".into()),
        ["SYSCTL_GET", key] => read_sysctl_value(key),
        ["SYSCTL_SET", key, expected, desired] => compare_set_sysctl(key, expected, desired),
        ["HARDENING_GET"] => hardening_file_state(),
        ["HARDENING_SET", expected, desired] => compare_set_hardening_file(expected, desired),
        ["MALWARE_SCAN", path] => scanner.inspect_token(path),
        ["QUARANTINE_INSPECT", path] => quarantine.inspect_token(path),
        ["QUARANTINE_APPLY", path, object_id, identity] => {
            quarantine.quarantine_token(path, object_id, &parse_quarantine_identity(identity)?)
        }
        ["QUARANTINE_VERIFY", object_id, identity] => {
            quarantine.verify_object(object_id, &parse_quarantine_identity(identity)?)
        }
        ["QUARANTINE_RESTORE", path, object_id, identity] => {
            quarantine.restore_token(path, object_id, &parse_quarantine_identity(identity)?)
        }
        ["XDR_STOP", pid, start, rule] => {
            let pid = pid.parse::<i32>()?;
            let start = start.parse::<u64>()?;
            pidfd_signal(pid, start, libc::SIGSTOP, rule).map(|_| "stopped".into())
        }
        ["XDR_CONT", pid, start, rule] | ["XDR_RESUME", pid, start, rule] => {
            let pid = pid.parse::<i32>()?;
            let start = start.parse::<u64>()?;
            pidfd_signal(pid, start, libc::SIGCONT, rule).map(|_| "resumed".into())
        }
        ["XDR_KILL", pid, start, rule] => {
            let pid = pid.parse::<i32>()?;
            let start = start.parse::<u64>()?;
            pidfd_signal(pid, start, libc::SIGKILL, rule).map(|_| "killed".into())
        }
        // M2.3 (6.2.0 ABI v2): bounded process-tree/process-group response.
        // Wire: XDR_KILL_TREE <pid> <start_ticks> <rule> -> "killed:<n>";
        // XDR_GROUP_STOP|<pgid> <rule> -> "stopped"; XDR_GROUP_CONT -> "resumed".
        ["XDR_KILL_TREE", args @ ..] => {
            let (pid, start, rule) = process_tree::parse_kill_tree_request(args)?;
            process_tree::signal_process_tree(pid, start, &rule)
                .map(|count| format!("killed:{count}"))
        }
        ["XDR_GROUP_STOP", args @ ..] => {
            let (pgid, rule) = process_tree::parse_group_request(args)?;
            process_tree::stop_process_group(pgid, &rule).map(|_| "stopped".to_owned())
        }
        ["XDR_GROUP_CONT", args @ ..] => {
            let (pgid, rule) = process_tree::parse_group_request(args)?;
            process_tree::resume_process_group(pgid, &rule).map(|_| "resumed".to_owned())
        }
        ["CANARY_DEPLOY", path, canary_type, mode, content] => {
            canary.deploy_token(path, canary_type, mode, content)
        }
        ["CANARY_REMOVE", path] => canary.remove_token(path),
        ["CANARY_EVENTS"] => canary.take_events(),
        ["CANARY_STATUS"] => Ok(canary.status()),
        // Point 5 (§5): the lock-down command surface is dispatched by the
        // crate-root ABI layer; unknown LOCKDOWN_* names stay ERR.
        [command, ..] if command.starts_with("LOCKDOWN_") => {
            lockdown_command(&mut core.lockdown, parts)
        }
        _ => Err("unknown command".into()),
    }
}

fn handle_connection(
    mut stream: UnixStream,
    core: &mut KernelCore,
    quarantine: &QuarantineBroker,
    scanner: &MalwareScanner,
    canary: &CanaryBroker,
    control_uid: u32,
    auth_key: &[u8],
    replay: &mut ReplayGuard,
) {
    match peer_uid(&stream) {
        Ok(uid) if uid == control_uid => {}
        Ok(uid) => {
            eprintln!("rejected IPC peer uid={uid}");
            return;
        }
        Err(error) => {
            eprintln!("IPC peer credential check failed: {error}");
            return;
        }
    }
    let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
    let cloned = match stream.try_clone() {
        Ok(value) => value,
        Err(error) => {
            eprintln!("IPC clone failed: {error}");
            return;
        }
    };
    let mut bounded = BufReader::new(cloned).take(MAX_REQUEST_BYTES + 1);
    let mut request = Vec::with_capacity(256);
    if bounded.read_until(b'\n', &mut request).is_err()
        || request.len() as u64 > MAX_REQUEST_BYTES
        || !request.ends_with(b"\n")
        || request.contains(&0)
        || request.contains(&MAC_FIELD_SEPARATOR)
    {
        eprintln!("rejected malformed IPC request");
        return;
    }
    let line = match std::str::from_utf8(&request) {
        Ok(value) => value.trim_end(),
        Err(_) => {
            eprintln!("rejected non-UTF8 IPC request");
            return;
        }
    };
    let fields: Vec<&str> = line.split(' ').collect();
    if fields.len() < 5 || fields.len() > 20 || fields.iter().any(|field| field.is_empty()) {
        eprintln!("rejected invalid IPC field count");
        return;
    }
    let protocol = fields[0];
    let timestamp = fields[1];
    let nonce = fields[2];
    let supplied_mac = fields[fields.len() - 1];
    if protocol != PROTOCOL || !valid_nonce(nonce) {
        eprintln!("rejected invalid IPC protocol header");
        return;
    }
    let now = match unix_seconds() {
        Ok(value) => value,
        Err(error) => {
            eprintln!("system clock unavailable: {error}");
            return;
        }
    };
    let stamp = match timestamp.parse::<u64>() {
        Ok(value) => value,
        Err(_) => {
            eprintln!("rejected invalid IPC timestamp");
            return;
        }
    };
    if let Some(reason) = request_timestamp_error(now, stamp) {
        eprintln!("rejected IPC request with a {reason} timestamp");
        return;
    }
    if verify_mac(auth_key, &fields[..fields.len() - 1], supplied_mac).is_err() {
        eprintln!("rejected unauthenticated IPC request");
        return;
    }
    if !replay.accept(nonce, now, stamp) {
        eprintln!("rejected replayed IPC request");
        let _ = write_response(&mut stream, auth_key, nonce, "ERR", "request rejected");
        return;
    }

    let command = &fields[3..fields.len() - 1];
    match process_command(core, quarantine, scanner, canary, command) {
        Ok(message) => {
            if let Err(error) = write_response(&mut stream, auth_key, nonce, "OK", &message) {
                eprintln!("IPC response failed: {error}");
            }
        }
        Err(error) => {
            eprintln!("IPC command rejected: {error}");
            let _ = write_response(&mut stream, auth_key, nonce, "ERR", "request rejected");
        }
    }
}

fn arg(name: &str, default: &str) -> String {
    let prefix = format!("--{name}=");
    env::args()
        .find_map(|value| value.strip_prefix(&prefix).map(str::to_owned))
        .unwrap_or_else(|| default.to_owned())
}

// Repeatable flag, e.g. `--canary-root=/var/lib/vgt/gedefense/canaries`.
fn multi_arg(name: &str) -> Vec<String> {
    let prefix = format!("--{name}=");
    env::args()
        .filter_map(|value| value.strip_prefix(&prefix).map(str::to_owned))
        .collect()
}

fn flag(name: &str) -> bool {
    let expected = format!("--{name}");
    env::args().any(|value| value == expected)
}

fn valid_interface_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() < libc::IFNAMSIZ
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b':'))
}

fn interface_exists(name: &str) -> bool {
    valid_interface_name(name) && Path::new("/sys/class/net").join(name).exists()
}

fn fallback_interface() -> Result<String, BoxError> {
    let mut candidates = Vec::new();
    for entry in fs::read_dir("/sys/class/net")? {
        let entry = entry?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if name == "lo" || !valid_interface_name(name) {
            continue;
        }
        let state = fs::read_to_string(entry.path().join("operstate")).unwrap_or_default();
        let priority = match state.trim() {
            "up" => 0_u8,
            "unknown" | "dormant" => 1_u8,
            _ => 2_u8,
        };
        candidates.push((priority, name.to_owned()));
    }
    candidates.sort_unstable();
    if let Some((_, name)) = candidates.into_iter().next() {
        eprintln!("no active default route yet; attaching XDP to validated interface {name}");
        return Ok(name);
    }
    if interface_exists("lo") {
        eprintln!("no non-loopback interface present; using loopback fail-safe");
        return Ok("lo".to_owned());
    }
    Err("no validated network interface found".into())
}

fn detect_interface(requested: &str) -> Result<String, BoxError> {
    if requested != "auto" {
        if !interface_exists(requested) {
            return Err("invalid or unavailable interface name".into());
        }
        return Ok(requested.to_owned());
    }
    let routes = fs::read_to_string("/proc/net/route")?;
    for line in routes.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() >= 4 && fields[1] == "00000000" {
            let flags = u32::from_str_radix(fields[3], 16).unwrap_or(0);
            if flags & 0x1 != 0 && interface_exists(fields[0]) {
                return Ok(fields[0].to_owned());
            }
        }
    }
    fallback_interface()
}

fn main() -> Result<(), BoxError> {
    if env::args().any(|value| value == "--version" || value == "-version") {
        println!("{}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }
    eprintln!("GeDefense core startup phase=interface-detection");
    let iface = detect_interface(&arg("interface", "auto"))
        .map_err(|error| std::io::Error::other(format!("interface detection: {error}")))?;
    let object = arg(
        "bpf-object",
        "/opt/vgt/gedefense/current/lib/gedefense/gedefense-ebpf",
    );
    let require_cell_lsm = flag("require-bpf-lsm");
    let socket = arg("socket", "/run/vgt-gedefense/core.sock");
    let scan_socket = arg("scan-socket", "/run/gedefense-scan/scan.sock");
    let auth_key_path = arg("auth-key", "/etc/vgt/gedefense/secrets/core-ipc.key");
    let storage_key_path = arg(
        "storage-key",
        "/etc/vgt/gedefense/secrets/storage-master.key",
    );
    let quarantine_dir = arg(
        "quarantine-dir",
        "/var/lib/vgt/gedefense/quarantine/objects",
    );
    let control_user = arg("control-user", "gedefense");
    let malware_hashes = arg("malware-hashes", "/etc/vgt/gedefense/malware-hashes.sha256");
    let lockdown_state_path = arg("lockdown-state", lockdown::DEFAULT_STATE_FILE);
    eprintln!("GeDefense core startup phase=control-identity");
    let (control_uid, control_gid) = lookup_identity(&control_user)
        .map_err(|error| std::io::Error::other(format!("control identity: {error}")))?;
    eprintln!("GeDefense core startup phase=auth-key");
    let auth_key = load_auth_key(&auth_key_path, control_gid)
        .map_err(|error| std::io::Error::other(format!("auth key: {error}")))?;
    eprintln!("GeDefense core startup phase=quarantine-vault");
    let mut storage_key = load_secret_key(&storage_key_path, control_gid, "storage master key")
        .map_err(|error| std::io::Error::other(format!("storage key: {error}")))?;
    let quarantine = Arc::new(
        QuarantineBroker::new(&quarantine_dir, &storage_key)
            .map_err(|error| std::io::Error::other(format!("quarantine vault: {error}")))?,
    );
    storage_key.fill(0);
    eprintln!("GeDefense core startup phase=malware-on-access");
    let scanner = MalwareScanner::load(&malware_hashes)
        .map_err(|error| std::io::Error::other(format!("malware signatures: {error}")))?;
    scanner
        .start_on_access(&[Path::new("/home").to_path_buf()])
        .map_err(|error| std::io::Error::other(format!("on-access guard: {error}")))?;
    // M1.1 (6.2.0): the asynchronous FAN_CLOSE_WRITE sensor for the writable
    // drop roots. It never registers a permission event, so it cannot slow down
    // or block a writer; the roots default to the four drop paths the systemd
    // unit keeps writable and can be overridden with repeated
    // `--on-write-watch-root=` flags (each value is a comma-separated list).
    eprintln!("GeDefense core startup phase=malware-on-write");
    let malware_inode_lock: credential_guard::SharedMalwareInodeLock =
        Arc::new(std::sync::Mutex::new(None));
    let on_write_roots = on_write::resolve_roots(&multi_arg("on-write-watch-root"))
        .map_err(|error| std::io::Error::other(format!("on-write watch roots: {error}")))?;
    on_write::OnWriteSensor::start(
        scanner.clone(),
        Arc::clone(&quarantine),
        Arc::clone(&malware_inode_lock),
        &on_write_roots,
    )
        .map_err(|error| std::io::Error::other(format!("on-write sensor: {error}")))?;
    eprintln!("GeDefense core startup phase=canary-broker");
    // The unprivileged control plane cannot create decoys outside its sandbox
    // (ProtectSystem=strict, PrivateTmp) and cannot observe host file accesses.
    // The broker owns both: atomic deployment inside a validated canary root and
    // a dedicated fanotify instance per registered decoy.
    let canary_roots = collect_canary_roots(&multi_arg("canary-root"))
        .map_err(|error| std::io::Error::other(format!("canary roots: {error}")))?;
    let canary = CanaryBroker::new(&canary_roots)
        .map_err(|error| std::io::Error::other(format!("canary broker: {error}")))?;
    canary
        .start_watch()
        .map_err(|error| std::io::Error::other(format!("canary fanotify sensor: {error}")))?;
    eprintln!("GeDefense core startup phase=user-scan-socket");
    // F-04: self-healing fallback - the persisted hardening profile is applied
    // to the live kernel again here, after systemd-sysctl has run. Later-sorting
    // external sysctl.d files therefore cannot silently win over the operator's
    // persisted GeDefense intent.
    reassert_persisted_hardening();
    let scan_parent = Path::new(&scan_socket)
        .parent()
        .ok_or("user scan socket parent is missing")?;
    if scan_parent != Path::new("/run/gedefense-scan") {
        return Err("user scan socket escaped runtime jail".into());
    }
    fs::create_dir_all(scan_parent)?;
    let scan_parent_metadata = fs::symlink_metadata(scan_parent)?;
    if !scan_parent_metadata.is_dir()
        || scan_parent_metadata.file_type().is_symlink()
        || scan_parent_metadata.uid() != 0
        || scan_parent_metadata.gid() != control_gid
    {
        return Err("user scan runtime directory ownership rejected".into());
    }
    // F-18: the user scan socket is a root-executing service surface. It is
    // restricted to the control-plane account instead of being world-writable.
    fs::set_permissions(scan_parent, fs::Permissions::from_mode(0o750))?;
    let scan_listener = bind_secure_runtime_socket(Path::new(&scan_socket), control_gid, 0o660)
        .map_err(|error| std::io::Error::other(format!("user scan IPC bind: {error}")))?;
    let scan_worker = scanner.clone();
    std::thread::Builder::new()
        .name("gedefense-user-scan".to_owned())
        .spawn(move || {
            for incoming in scan_listener.incoming() {
                match incoming {
                    Ok(stream) => {
                        if let Err(error) = handle_user_scan(stream, &scan_worker, control_uid) {
                            eprintln!("GeDefense user scan IPC rejected: {error}");
                        }
                    }
                    Err(error) => {
                        // F-HOTFIX-1: an accept() error (EMFILE/ENFILE/ECONNABORTED)
                        // must not abort the privileged core. Back off briefly and keep
                        // the enforcement daemon and its IPC response channel online.
                        eprintln!("GeDefense user scan IPC accept error (core stays online): {error}");
                        std::thread::sleep(std::time::Duration::from_millis(200));
                    }
                }
            }
        })?;
    eprintln!("GeDefense core startup phase=ipc-socket");
    let socket_parent = Path::new(&socket)
        .parent()
        .ok_or("IPC socket parent is missing")?;
    fs::create_dir_all(socket_parent)
        .map_err(|error| std::io::Error::other(format!("IPC directory: {error}")))?;
    // FIND-034: the control socket is created through the same hardened helper as
    // the user scan socket. The previous inline path only set 0660: it never
    // rejected a symlinked socket path, never verified the owning group and never
    // checked that the result stayed inaccessible to "other".
    let listener = bind_secure_runtime_socket(Path::new(&socket), control_gid, 0o660)
        .map_err(|error| std::io::Error::other(format!("IPC socket hardening: {error}")))?;
    eprintln!("GeDefense core startup phase=xdp-load interface={iface}");
    let mut core = KernelCore::load(&object, &iface, require_cell_lsm, &lockdown_state_path)
        .map_err(|error| {
            std::io::Error::other(format!("kernel data-plane load/attach: {error}"))
        })?;
    if let Ok(mut slot) = malware_inode_lock.lock() {
        *slot = Some(core.credential_guard.malware_inode_lock_handle());
    }
    // Point 5 (§5): re-arm the persisted lockdown (drop/USB/TB/hardening and
    // the uevent monitor) before the IPC accept loop serves the first request.
    match core.lockdown.startup_rearm() {
        Ok(state) => eprintln!("GeDefense core startup phase=lockdown-rearm state={state}"),
        Err(error) => eprintln!("GeDefense core lockdown re-arm: {error}"),
    }
    let mut replay = ReplayGuard::new();
    eprintln!(
        "GeDefense Rust core online: interface={iface} ingress={} cgroup_egress=attached cell_lsm={} titan_exec={} titan_exec_attached={} on_access=fanotify-exec user_scan=peercred-jail canary=fanotify-jail authenticated_ipc=VGT3 socket={socket} lockdown={}",
        core.mode,
        if core.cell_lsm_attached { "attached" } else { "optional-unavailable" },
        core.titan_exec.state_text(),
        core.titan_exec.attached,
        core.lockdown.state_text()
    );
    for incoming in listener.incoming() {
        match incoming {
            Ok(stream) => handle_connection(
                stream,
                &mut core,
                &quarantine,
                &scanner,
                &canary,
                control_uid,
                &auth_key,
                &mut replay,
            ),
            Err(error) => eprintln!("IPC accept error: {error}"),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    // 6.1.0 policy-bit expectations are test-only: the production path only
    // needs the aggregate mask, so these stay out of the shipped import set.
    use gedefense_common::{
        CELL_LSM_DENY_AF_PACKET, CELL_LSM_DENY_NON_UNIX_SOCKET, CELL_LSM_DENY_RDS,
    };

    #[test]
    fn target_parser_normalizes_networks() {
        match parse_target("203.0.113.77/24").expect("IPv4 target") {
            Target::V4(address, prefix) => {
                assert_eq!(address, Ipv4Addr::new(203, 0, 113, 0));
                assert_eq!(prefix, 24);
            }
            Target::V6(_, _) => panic!("unexpected IPv6 target"),
        }
        match parse_target("2001:db8::1234/64").expect("IPv6 target") {
            Target::V6(address, prefix) => {
                assert_eq!(address, "2001:db8::".parse::<Ipv6Addr>().unwrap());
                assert_eq!(prefix, 64);
            }
            Target::V4(_, _) => panic!("unexpected IPv4 target"),
        }
    }

    #[test]
    fn target_parser_rejects_dangerous_or_invalid_networks() {
        assert!(parse_target("0.0.0.0/0").is_err());
        assert!(parse_target("::/0").is_err());
        assert!(parse_target("192.0.2.1/33").is_err());
        assert!(parse_target("2001:db8::1/129").is_err());
    }

    #[test]
    fn protocol_tokens_are_strict() {
        assert!(valid_rule_token("XDR.MEMFD_EXEC"));
        assert!(!valid_rule_token("XDR MEMFD EXEC"));
        assert!(!valid_rule_token(""));
        assert!(valid_nonce("0123456789abcdef0123456789ABCDEF"));
        assert!(!valid_nonce("0123"));
        assert!(!valid_nonce("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"));
    }

    #[test]
    fn cell_lsm_policy_tokens_are_strict() {
        assert_eq!(parse_cell_cgroup_id("42").unwrap(), 42);
        assert!(parse_cell_cgroup_id("0").is_err());
        assert!(parse_cell_cgroup_id("-1").is_err());
        assert_eq!(
            parse_cell_policy_flags("1").unwrap(),
            CELL_LSM_DENY_NON_UNIX_SOCKET
        );
        // 6.1.0: bit 0 (NON_UNIX) and bit 1 (AF_PACKET) are both known, so 3 is
        // a valid policy word. FIND-004: the old assertion still encoded the
        // pre-6.1.0 exclusive contract and failed.
        assert_eq!(
            parse_cell_policy_flags("3").unwrap(),
            CELL_LSM_DENY_NON_UNIX_SOCKET | CELL_LSM_DENY_AF_PACKET
        );
        // Every defined bit (0x7f = all seven) is accepted.
        assert_eq!(parse_cell_policy_flags("127").unwrap(), 0x7f);
        assert_eq!(parse_cell_policy_flags("127").unwrap(), CELL_LSM_DENY_ALL_KNOWN);
        assert_eq!(parse_cell_policy_flags("64").unwrap(), CELL_LSM_DENY_RDS);
        // Zero and unknown bits stay rejected.
        assert!(parse_cell_policy_flags("0").is_err());
        assert!(parse_cell_policy_flags("128").is_err());
        assert!(parse_cell_policy_flags("255").is_err());
    }

    #[test]
    fn interface_names_reject_path_and_control_characters() {
        assert!(valid_interface_name("enp0s3"));
        assert!(valid_interface_name("veth.secure-1"));
        assert!(!valid_interface_name("../eth0"));
        assert!(!valid_interface_name("eth0/peer"));
        assert!(!valid_interface_name("eth0\n"));
        assert!(!valid_interface_name(""));
    }

    #[test]
    fn replay_guard_rejects_duplicates_and_expires_old_entries() {
        let mut guard = ReplayGuard::new();
        let nonce = "0123456789abcdef0123456789abcdef";
        assert!(guard.accept(nonce, 100, 100));
        assert!(!guard.accept(nonce, 101, 101));
        // The same nonce with a *fresh* timestamp after the entry expired is a
        // new request, not a replay: the guard only holds nonces, not identities.
        assert!(guard.accept(
            nonce,
            100 + CLOCK_WINDOW_SECS + 1,
            100 + CLOCK_WINDOW_SECS + 1
        ));
    }

    #[test]
    fn replay_guard_rejects_future_timestamps_and_closes_the_window_gap() {
        // The old |now - stamp| <= CLOCK_WINDOW_SECS check accepted a timestamp a
        // whole window in the future. The nonce was cached against the arrival
        // time but the timestamp stayed valid for a second window after the cache
        // entry expired, so [t+31, t+60] was a replay gap. Finding FIND-034.
        assert_eq!(request_timestamp_error(1_000, 1_000), None);
        assert_eq!(request_timestamp_error(1_000, 1_005), None);
        assert_eq!(
            request_timestamp_error(1_000, 1_000 + CLOCK_FUTURE_TOLERANCE_SECS),
            None
        );
        assert_eq!(
            request_timestamp_error(1_000, 1_001 + CLOCK_FUTURE_TOLERANCE_SECS),
            Some("future")
        );
        assert_eq!(request_timestamp_error(1_000, 1_030), Some("future"));
        assert_eq!(request_timestamp_error(1_000, 969), Some("stale"));
        assert_eq!(request_timestamp_error(1_000, 970), None);

        let nonce = "ffffffffffffffffffffffffffffffff";
        let mut guard = ReplayGuard::new();
        // A request with the maximum tolerated future stamp is accepted ...
        assert!(guard.accept(nonce, 1_000, 1_005));
        // ... and a duplicate inside the window is still a replay ...
        assert!(!guard.accept(nonce, 1_010, 1_005));
        // ... but at t+45 the request is both cache-expired and outside the
        // timestamp window: the replayed request must be refused.
        assert!(!guard.accept(nonce, 1_045, 1_005));
    }

    #[test]
    fn replay_guard_keeps_accepting_new_requests_when_full() {
        // A burst larger than the cache must not lock the channel out.
        //
        // This is the shape the control plane produces whenever it applies a blocklist
        // larger than REPLAY_CACHE_CAPACITY: one command per entry, all inside one clock
        // window. The guard used to refuse every command past the 4096th as a replay -
        // including the health checks that decide whether the core is reachable - so the
        // platform reported its kernel channel offline while the kernel was answering,
        // and the list could never be applied in full.
        let mut guard = ReplayGuard::new();

        for i in 0..REPLAY_CACHE_CAPACITY {
            let nonce = format!("{i:032}");
            assert!(
                guard.accept(&nonce, 100, 100),
                "request {i} was refused before the cache was full"
            );
        }

        // One past the capacity. A nonce never seen before is not a replay.
        let fresh = "ffffffffffffffffffffffffffffffff";
        assert!(
            guard.accept(fresh, 100, 100),
            "a new request was refused because the cache was full"
        );

        // The duplicate check still holds at capacity, which is the property the guard
        // exists for.
        assert!(!guard.accept(fresh, 101, 101));

        // And the cache stays bounded while doing so.
        assert!(guard.set.len() <= REPLAY_CACHE_CAPACITY);
        assert!(guard.order.len() <= REPLAY_CACHE_CAPACITY);
    }

    #[test]
    fn replay_guard_evicts_in_arrival_order() {
        // Eviction takes the oldest entry, so the window still covers the most recent
        // commands - the ones a replay would have to imitate to be useful.
        let mut guard = ReplayGuard::new();
        for i in 0..REPLAY_CACHE_CAPACITY {
            assert!(guard.accept(&format!("{i:032}"), 100, 100));
        }
        assert!(guard.accept("ffffffffffffffffffffffffffffffff", 100, 100));

        // The first nonce is the one that was evicted, so it is accepted again.
        assert!(guard.accept(&format!("{:032}", 0), 100, 100));
        // The most recently accepted one is still held, so its replay is refused.
        assert!(!guard.accept("ffffffffffffffffffffffffffffffff", 100, 100));
    }

    #[test]
    fn cell_lsm_denials_with_af_unspec_are_skipped_not_wedged() {
        // The kernel LSM hook reports socket(2) creations verbatim; AF_UNSPEC (0)
        // is a legal family and was previously treated as invalid metadata, which
        // failed the whole event drain. One such record must be skipped only.
        let mut item = [0u8; std::mem::size_of::<CellLsmDenyEvent>()];
        item[0..8].copy_from_slice(&42u64.to_ne_bytes());
        item[8..12].copy_from_slice(&4242u32.to_ne_bytes());
        item[12..16].copy_from_slice(&1000u32.to_ne_bytes());
        item[16..20].copy_from_slice(&libc::AF_UNSPEC.to_ne_bytes());
        item[20] = ACTION_DROP;
        assert_eq!(
            decode_cell_lsm_deny_event(&item).expect("AF_UNSPEC is not corruption"),
            None
        );

        // A representable family still produces the typed record.
        item[16..20].copy_from_slice(&libc::AF_INET.to_ne_bytes());
        assert_eq!(
            decode_cell_lsm_deny_event(&item).expect("IPv4 denial"),
            Some("42:4242:1000:2".to_owned())
        );

        // AF_UNIX, unknown and negative families stay invalid metadata.
        for family in [libc::AF_UNIX, -1, i32::from(u8::MAX) + 1] {
            item[16..20].copy_from_slice(&family.to_ne_bytes());
            assert!(
                decode_cell_lsm_deny_event(&item).is_err(),
                "accepted family {family}"
            );
        }
        item[16..20].copy_from_slice(&libc::AF_INET.to_ne_bytes());
        item[20] = 0;
        assert!(decode_cell_lsm_deny_event(&item).is_err(), "accepted a non-drop action");
    }

    #[test]
    fn sysctl_contract_is_exact_and_typed() {
        let (_, binary) =
            sysctl_spec("net.ipv4.conf.all.accept_redirects").expect("allowlisted sysctl");
        assert_eq!(binary, &["0", "1"]);
        let (_, ternary) = sysctl_spec("kernel.kptr_restrict").expect("allowlisted sysctl");
        assert_eq!(ternary, &["0", "1", "2"]);
        // The user-namespace boundary is a managed control: it must be allowlisted as a typed binary so
        // the transactional applier can set it and verify the post-state, and it must not become a way
        // to write an arbitrary path.
        let (userns_path, userns_domain) =
            sysctl_spec("kernel.unprivileged_userns_clone").expect("allowlisted userns sysctl");
        assert_eq!(userns_path, "/proc/sys/kernel/unprivileged_userns_clone");
        assert_eq!(userns_domain, &["0", "1"]);
        let (mptcp_path, mptcp_domain) =
            sysctl_spec("net.mptcp.enabled").expect("allowlisted MPTCP mitigation");
        assert_eq!(mptcp_path, "/proc/sys/net/mptcp/enabled");
        assert_eq!(mptcp_domain, &["0", "1"]);
        assert!(sysctl_spec("user.max_user_namespaces").is_none());
        assert!(sysctl_spec("kernel.core_pattern").is_none());
        assert!(sysctl_spec("../kernel/kptr_restrict").is_none());
    }

    #[test]
    fn legacy_hardening_profiles_are_recognized_for_upgrade() {
        assert_eq!(
            recognized_hardening_state(LEGACY_HARDENING_SERVER).as_deref(),
            Some("linux-server-balanced")
        );
        assert_eq!(
            recognized_hardening_state(LEGACY_HARDENING_ASTRAEAOS).as_deref(),
            Some("astraeaos-workstation-strict")
        );
    }

    #[test]
    fn custom_hardening_profiles_are_deterministic_and_bounded() {
        let profile = hardening_content("astraeaos-custom-0083").expect("valid custom profile");
        assert!(profile.contains("# Profile: astraeaos-custom-0083\n"));
        assert!(profile.contains("kernel.randomize_va_space = 2\n"));
        assert!(profile.contains("kernel.kptr_restrict = 2\n"));
        assert!(profile.contains("net.ipv4.tcp_syncookies = 1\n"));
        assert_eq!(
            recognized_hardening_state(&profile).as_deref(),
            Some("astraeaos-custom-0083")
        );
        for invalid in [
            "astraeaos-custom-0000",
            "astraeaos-custom-200000", // above the 21-bit catalogue ceiling
            "astraeaos-custom-400000", // above the 21-bit catalogue ceiling
            "astraeaos-custom-xyz1",
            "astraeaos-custom-001", // shorter than Go's %04x form
        ] {
            assert!(hardening_content(invalid).is_none(), "accepted {invalid}");
        }
        // The M5.1 high control bit (1 << 20) and the complete CIS profile are
        // now part of the same closed vocabulary the Go catalogue can emit.
        let high = hardening_content("astraeaos-custom-100000").expect("high custom mask");
        assert!(high.contains("net.ipv6.conf.all.disable_ipv6 = 1\n"));
        let cis = hardening_content("astraeaos-cis-l1").expect("CIS profile");
        assert!(cis.contains("net.ipv4.conf.all.rp_filter = 1\n"));
        assert!(cis.contains("fs.protected_hardlinks = 1\n"));
        assert!(cis.contains("kernel.perf_event_paranoid = 3\n"));
        assert_eq!(
            recognized_hardening_state(&cis).as_deref(),
            Some("astraeaos-cis-l1")
        );
    }

    fn test_hardening_directory(label: &str) -> std::path::PathBuf {
        let mut path = std::env::temp_dir();
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or(0);
        path.push(format!(
            "vgt-hardening-{label}-{}-{nanos}",
            std::process::id()
        ));
        fs::create_dir_all(&path).expect("create hardening fixture directory");
        path
    }

    fn write_managed_hardening_fixture(
        directory: &Path,
        name: &str,
        profile: &str,
    ) -> std::path::PathBuf {
        let path = directory.join(name);
        let content = hardening_content(profile).expect("managed profile content");
        fs::write(&path, content).expect("write hardening fixture");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).expect("fixture permissions");
        path
    }

    fn directory_entries(directory: &Path) -> Vec<String> {
        fs::read_dir(directory)
            .expect("read hardening fixture directory")
            .map(|entry| {
                entry
                    .expect("directory entry")
                    .file_name()
                    .to_string_lossy()
                    .into_owned()
            })
            .collect()
    }

    // F-04: the exact defect the audit reproduced. A SET from absent to a
    // profile must be readable back through the same GET path, and removing it
    // must leave no stray files behind.
    #[test]
    fn hardening_compare_set_uses_one_canonical_file() {
        let directory = test_hardening_directory("roundtrip");
        assert_eq!(
            hardening_file_state_in(&directory).expect("initial state"),
            "absent"
        );
        assert_eq!(
            compare_set_hardening_file_in(&directory, "absent", "linux-server-balanced")
                .expect("create persistent hardening"),
            "linux-server-balanced"
        );
        assert_eq!(
            hardening_file_state_in(&directory).expect("post-set state"),
            "linux-server-balanced"
        );
        assert!(directory.join(HARDENING_FILE_NAME).is_file());
        assert!(!directory.join(LEGACY_HARDENING_FILE_NAMES[0]).exists());

        assert_eq!(
            compare_set_hardening_file_in(
                &directory,
                "linux-server-balanced",
                "astraeaos-workstation-strict"
            )
            .expect("replace persistent hardening"),
            "astraeaos-workstation-strict"
        );
        assert_eq!(
            hardening_file_state_in(&directory).expect("post-replace state"),
            "astraeaos-workstation-strict"
        );

        assert_eq!(
            compare_set_hardening_file_in(&directory, "astraeaos-workstation-strict", "absent")
                .expect("remove persistent hardening"),
            "absent"
        );
        assert_eq!(
            hardening_file_state_in(&directory).expect("post-remove state"),
            "absent"
        );
        assert!(!directory.join(HARDENING_FILE_NAME).exists());
        assert!(
            directory_entries(&directory).is_empty(),
            "temporary or stale files left behind: {:?}",
            directory_entries(&directory)
        );
        fs::remove_dir_all(&directory).ok();
    }

    // F-04 migration: a legacy 99-zzz file is migrated to the canonical path
    // instead of being ignored (which made GET report absent forever).
    #[test]
    fn hardening_migrates_legacy_99_file() {
        let directory = test_hardening_directory("migrate");
        write_managed_hardening_fixture(
            &directory,
            LEGACY_HARDENING_FILE_NAMES[0],
            "linux-server-balanced",
        );
        assert_eq!(
            hardening_file_state_in(&directory).expect("migrated state"),
            "linux-server-balanced"
        );
        assert!(directory.join(HARDENING_FILE_NAME).is_file());
        assert!(!directory.join(LEGACY_HARDENING_FILE_NAMES[0]).exists());
        fs::remove_dir_all(&directory).ok();
    }

    // F-04 reconciliation: managed legacy strays are cleaned once the canonical
    // file is authoritative, so they cannot win the sysctl.d sort order at boot.
    #[test]
    fn hardening_reconciles_managed_legacy_strays() {
        let directory = test_hardening_directory("reconcile");
        write_managed_hardening_fixture(&directory, HARDENING_FILE_NAME, "linux-server-balanced");
        write_managed_hardening_fixture(
            &directory,
            LEGACY_HARDENING_FILE_NAMES[0],
            "linux-server-balanced",
        );
        write_managed_hardening_fixture(
            &directory,
            LEGACY_HARDENING_FILE_NAMES[1],
            "linux-server-balanced",
        );
        assert_eq!(
            hardening_file_state_in(&directory).expect("reconciled state"),
            "linux-server-balanced"
        );
        assert!(!directory.join(LEGACY_HARDENING_FILE_NAMES[0]).exists());
        assert!(!directory.join(LEGACY_HARDENING_FILE_NAMES[1]).exists());
        fs::remove_dir_all(&directory).ok();
    }

    // F-04 negative: a stray file that GeDefense does not manage is never
    // deleted and never silently ignored - the state read fails closed.
    #[test]
    fn hardening_rejects_unmanaged_stray_files() {
        let directory = test_hardening_directory("unmanaged");
        write_managed_hardening_fixture(&directory, HARDENING_FILE_NAME, "linux-server-balanced");
        let stray = directory.join(LEGACY_HARDENING_FILE_NAMES[0]);
        fs::write(&stray, "kernel.foo = 1\n").expect("write unmanaged stray");
        assert!(hardening_file_state_in(&directory).is_err());
        assert!(stray.exists(), "unmanaged file must not be deleted");

        let directory = test_hardening_directory("unmanaged-canonical");
        fs::write(directory.join(HARDENING_FILE_NAME), "kernel.foo = 1\n")
            .expect("write unmanaged canonical file");
        assert!(
            compare_set_hardening_file_in(&directory, "absent", "linux-server-balanced").is_err()
        );
        fs::remove_dir_all(&directory).ok();
    }

    #[test]
    fn hardening_multiple_legacy_files_fail_closed() {
        let directory = test_hardening_directory("multiple-legacy");
        write_managed_hardening_fixture(
            &directory,
            LEGACY_HARDENING_FILE_NAMES[0],
            "linux-server-balanced",
        );
        write_managed_hardening_fixture(
            &directory,
            LEGACY_HARDENING_FILE_NAMES[1],
            "astraeaos-workstation-strict",
        );
        assert!(hardening_file_state_in(&directory).is_err());
        fs::remove_dir_all(&directory).ok();
    }

    #[test]
    fn hardening_compare_set_precondition_mismatch_keeps_state() {
        let directory = test_hardening_directory("precondition");
        compare_set_hardening_file_in(&directory, "absent", "linux-server-balanced")
            .expect("create persistent hardening");
        assert!(compare_set_hardening_file_in(
            &directory,
            "astraeaos-workstation-strict",
            "absent"
        )
        .is_err());
        assert_eq!(
            hardening_file_state_in(&directory).expect("state after rejected compare-set"),
            "linux-server-balanced"
        );
        fs::remove_dir_all(&directory).ok();
    }

    // F-04 apply-on-boot support: only allowlisted, typed sysctl assignments may
    // be derived from a persisted profile.
    #[test]
    fn hardening_assignments_are_allowlisted_and_typed() {
        let assignments =
            parse_hardening_assignments(&hardening_content("linux-server-balanced").unwrap())
                .expect("parse managed profile");
        assert!(assignments
            .iter()
            .any(|(key, value)| key == "kernel.kptr_restrict" && value == "2"));
        assert!(assignments
            .iter()
            .any(|(key, value)| key == "net.ipv4.tcp_syncookies" && value == "1"));
        for invalid in [
            "kernel.core_pattern = /tmp/evil\n",
            "kernel.kptr_restrict = 9\n",
            "kernel.kptr_restrict = 2\nkernel.kptr_restrict = 0\n",
            "# only a comment\n",
            "not an assignment\n",
        ] {
            assert!(
                parse_hardening_assignments(invalid).is_err(),
                "accepted {invalid:?}"
            );
        }
        let custom = hardening_content("astraeaos-custom-0001").expect("custom profile");
        assert_eq!(
            parse_hardening_assignments(&custom)
                .expect("custom assignments")
                .len(),
            1
        );
    }

    // F-20: the length-less 0x1f packing is only safe when no field contains the
    // delimiter; the wire format itself stays compatible for valid fields.
    #[test]
    fn mac_field_packing_is_unambiguous() {
        let key = b"0123456789abcdef0123456789abcdef";
        assert_eq!(pack_mac_fields(&["a", "b"]).unwrap(), b"a\x1fb");
        assert_ne!(
            authenticated_mac(key, &["ab", "c"]).unwrap(),
            authenticated_mac(key, &["a", "bc"]).unwrap()
        );
        assert!(pack_mac_fields(&["a\x1fb", "c"]).is_err());
        assert!(authenticated_mac(key, &["a\x1fb", "c"]).is_err());
        assert!(verify_mac(key, &["a\x1fb", "c"], &"00".repeat(32)).is_err());

        // Compatibility: for delimiter-free fields the MAC is byte-identical to
        // the previous separator packing used by the control plane.
        let mut legacy = HmacSha256::new_from_slice(key).unwrap();
        legacy.update(b"VGT3");
        legacy.update(&[MAC_FIELD_SEPARATOR]);
        legacy.update(b"0123456789abcdef0123456789abcdef");
        assert_eq!(
            authenticated_mac(key, &["VGT3", "0123456789abcdef0123456789abcdef"]).unwrap(),
            legacy.finalize().into_bytes().to_vec()
        );
        let mac = authenticated_mac(key, &["safe", "fields"]).unwrap();
        verify_mac(key, &["safe", "fields"], &hex::encode(&mac)).expect("valid MAC");
        assert!(verify_mac(key, &["safe", "changed"], &hex::encode(&mac)).is_err());
    }

    // F-18: the root scanner's user scan socket is restricted to the control
    // group and never world-accessible; a symlinked socket path is rejected.
    #[test]
    fn runtime_socket_permissions_are_restricted() {
        let directory = test_hardening_directory("socket");
        let path = directory.join("scan.sock");
        let listener = UnixListener::bind(&path).expect("bind test socket");
        let gid = unsafe { libc::getgid() };
        secure_runtime_socket(&path, gid, 0o660).expect("secure runtime socket");
        let mode = fs::symlink_metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o660);
        assert_eq!(mode & 0o007, 0, "socket must not be accessible to other");
        drop(listener);

        let target = directory.join("target.sock");
        let target_listener = UnixListener::bind(&target).expect("bind target socket");
        let link = directory.join("link.sock");
        std::os::unix::fs::symlink(&target, &link).expect("create symlink");
        assert!(secure_runtime_socket(&link, gid, 0o660).is_err());
        drop(target_listener);
        fs::remove_dir_all(&directory).ok();
    }

    // FIND-034: the main control socket must take the same hardened route as the
    // user scan socket - 0660, group-restricted, never world-accessible - instead
    // of an inline bind + set_permissions without a symlink/ownership guard.
    #[test]
    fn ipc_socket_binding_is_hardened() {
        let directory = test_hardening_directory("ipc-socket");
        let path = directory.join("core.sock");
        let gid = unsafe { libc::getgid() };
        let listener =
            bind_secure_runtime_socket(&path, gid, 0o660).expect("bind hardened IPC socket");
        let metadata = fs::symlink_metadata(&path).expect("IPC socket metadata");
        let mode = metadata.permissions().mode() & 0o777;
        assert_eq!(mode, 0o660);
        assert_eq!(mode & 0o007, 0, "IPC socket must not be accessible to other");
        assert!(!metadata.file_type().is_symlink());
        assert_eq!(metadata.gid(), gid);
        drop(listener);

        // A symlink at the socket path is never accepted as the socket itself.
        let target = directory.join("target.sock");
        let target_listener = UnixListener::bind(&target).expect("bind target socket");
        let link = directory.join("linked.sock");
        std::os::unix::fs::symlink(&target, &link).expect("create symlink");
        assert!(secure_runtime_socket(&link, gid, 0o660).is_err());
        drop(target_listener);
        fs::remove_dir_all(&directory).ok();
    }

    // ------------------------------------------------------------------
    // P3-T4: pure STYX contracts (§3.3/§4/§5) that need no live kernel map.
    // ------------------------------------------------------------------

    fn styx_cidr(family: u8, text: &str) -> styx_flow::StyxCidr {
        styx_flow::parse_cidr(family, text).expect("valid fixture cidr")
    }

    fn styx_allow(args: &[&str]) -> styx_flow::StyxAllowRequest {
        styx_flow::parse_allow_request(args).expect("valid fixture allow request")
    }

    #[test]
    fn styx_cidr_parsing_accepts_canonical_forms_only() {
        assert_eq!(
            styx_cidr(4, "203.0.113.0/24").address,
            IpAddr::V4(Ipv4Addr::new(203, 0, 113, 0))
        );
        assert_eq!(styx_cidr(4, "203.0.113.7").prefix, 32);
        assert_eq!(styx_cidr(4, "0.0.0.0/0").prefix, 0);
        assert_eq!(styx_cidr(6, "2001:db8::/32").prefix, 32);
        assert_eq!(styx_cidr(6, "::1/128").address, IpAddr::V6(Ipv6Addr::LOCALHOST));
        for (family, token) in [
            (4u8, "203.0.113.9/24"), // host bits set
            (4, "1.2.3.4/0"),
            (4, "0.0.0.0/33"),
            (4, "2001:db8::/32"),
            (6, "203.0.113.0/24"),
            (6, "2001:db8::1/129"),
            (6, "::ffff:1.2.3.4/128"),
            (4, " 10.0.0.0/8"),
            (4, "10.0.0.0/8\n"),
            (4, "10.0.0.0/8\0"),
            (4, ""),
            (4, "10.0.0.0/"),
            (4, "10.0.0.0/8/8"),
            (5, "10.0.0.0/8"),
        ] {
            assert!(
                styx_flow::parse_cidr(family, token).is_err(),
                "{family} {token:?} was accepted"
            );
        }
        let oversized = format!("10.0.0.0/8{}", "0".repeat(140));
        assert!(styx_flow::parse_cidr(4, &oversized).is_err());
    }

    #[test]
    fn styx_veto_cidr_enforces_the_seed_prefix_ranges() {
        for token in [
            "0.0.0.0/8",
            "169.254.0.0/16",
            "100.100.100.200/32",
            "224.0.0.0/4",
        ] {
            assert!(styx_flow::parse_prefix_cidr(4, token).is_ok(), "{token}");
        }
        for token in ["0.0.0.0/0", "10.0.0.0/1", "10.0.0.0/3"] {
            assert!(styx_flow::parse_prefix_cidr(4, token).is_err(), "{token}");
        }
        for token in ["fd00:ec2::254/128", "fe80::/10", "ff00::/8"] {
            assert!(styx_flow::parse_prefix_cidr(6, token).is_ok(), "{token}");
        }
        for token in ["::/0", "2001:db8::/7"] {
            assert!(styx_flow::parse_prefix_cidr(6, token).is_err(), "{token}");
        }
    }

    #[test]
    fn styx_numeric_and_flag_arguments_are_strict() {
        assert_eq!(styx_flow::parse_u16("443").unwrap(), 443);
        assert_eq!(styx_flow::parse_cgroup_id("42").unwrap(), 42);
        for token in ["", " 1", "1 ", "+1", "-1", "0x10", "1_0", "\u{661}"] {
            assert!(styx_flow::parse_u16(token).is_err(), "{token:?}");
        }
        for token in ["0", "1", "2"] {
            assert_eq!(
                styx_flow::parse_mode(token).unwrap(),
                token.parse::<u8>().unwrap()
            );
        }
        for token in ["3", "7", "255", "-1"] {
            assert!(styx_flow::parse_mode(token).is_err(), "{token}");
        }
        assert_eq!(styx_flow::parse_mode_flags("120").unwrap(), 120);
        for token in ["7", "128", "255"] {
            assert!(styx_flow::parse_mode_flags(token).is_err(), "{token}");
        }
        assert_eq!(styx_flow::parse_global_flags("0").unwrap(), 0);
        assert_eq!(
            styx_flow::parse_global_flags("1").unwrap(),
            gedefense_common::STYX_FLAG_LOG_FLOWS
        );
        for token in ["2", "64", "255"] {
            assert!(styx_flow::parse_global_flags(token).is_err(), "{token}");
        }
        assert_eq!(styx_flow::parse_port_range("0", "65535").unwrap(), (0, 65535));
        assert_eq!(styx_flow::parse_port_range("443", "443").unwrap(), (443, 443));
        assert!(styx_flow::parse_port_range("443", "80").is_err());
        for token in ["0", "1", "2", "3"] {
            assert_eq!(
                styx_flow::parse_proto_mask(token).unwrap(),
                token.parse::<u8>().unwrap()
            );
        }
        assert!(styx_flow::parse_proto_mask("4").is_err());
    }

    #[test]
    fn styx_allow_request_validates_scope_family_and_shape() {
        let request = styx_allow(&["4", "cell", "42", "203.0.113.0/24", "0", "65535", "3"]);
        assert_eq!(request.cgroup_id, 42);
        assert_eq!(request.scope, styx_flow::StyxScope::Cell);
        let request = styx_allow(&["6", "global", "0", "2001:db8::/32", "53", "53", "1"]);
        assert_eq!(request.scope, styx_flow::StyxScope::Global);
        assert_eq!(request.cidr.family, 6);
        for args in [
            &["4", "cell", "0", "203.0.113.0/24", "0", "65535", "3"][..],
            &["4", "global", "42", "203.0.113.0/24", "0", "65535", "3"],
            &["5", "cell", "42", "203.0.113.0/24", "0", "65535", "3"],
            &["4", "zone", "42", "203.0.113.0/24", "0", "65535", "3"],
            &["4", "cell", "42", "203.0.113.0/24", "65535", "0", "3"],
            &["4", "cell", "42", "203.0.113.0/24", "0", "65535", "4"],
            &["4", "cell", "42", "203.0.113.9/24", "0", "65535", "3"],
            &["4", "cell", "42"],
        ] {
            assert!(
                styx_flow::parse_allow_request(args).is_err(),
                "{args:?} was accepted"
            );
        }
        assert_eq!(
            styx_flow::parse_allow_request(&["4", "cell"]).unwrap_err(),
            styx_flow::UNKNOWN_COMMAND
        );
    }

    #[test]
    fn styx_command_shapes_reject_unknown_arity_and_bad_values() {
        use styx_flow::UNKNOWN_COMMAND;
        assert_eq!(styx_flow::parse_global_request(&[]).unwrap_err(), UNKNOWN_COMMAND);
        assert_eq!(
            styx_flow::parse_global_request(&["1"]).unwrap_err(),
            UNKNOWN_COMMAND
        );
        assert_eq!(
            styx_flow::parse_global_request(&["1", "0", "0"]).unwrap_err(),
            UNKNOWN_COMMAND
        );
        assert_eq!(styx_flow::parse_global_request(&["1", "0"]).unwrap().mode, 1);
        assert!(styx_flow::parse_global_request(&["3", "0"]).is_err());
        assert_eq!(
            styx_flow::parse_mode_set_request(&["9", "2", "64"]).unwrap(),
            (9, 2, 64)
        );
        assert_eq!(
            styx_flow::parse_mode_set_request(&["0", "2", "0"]).unwrap_err(),
            "styx cgroup id must be non-zero"
        );
        assert_eq!(styx_flow::parse_mode_del_request(&["9"]).unwrap(), 9);
        assert_eq!(
            styx_flow::parse_mode_del_request(&["9", "9"]).unwrap_err(),
            UNKNOWN_COMMAND
        );
        assert_eq!(
            styx_flow::parse_prefix_request(&["4", "169.254.0.0/16"])
                .unwrap()
                .prefix,
            16
        );
        assert_eq!(
            styx_flow::parse_prefix_request(&["4"]).unwrap_err(),
            UNKNOWN_COMMAND
        );
    }

    #[test]
    fn styx_cell_v4_allow_keys_follow_section_four() {
        use styx_flow::StyxAllowKey;
        let cgroup = 0x0102_0304_0506_0708u64;
        match styx_allow(&["4", "cell", "72623859790382856", "0.0.0.0/0", "0", "65535", "3"])
            .allow_key()
            .unwrap()
        {
            StyxAllowKey::CellV4(key, prefix) => {
                assert_eq!(prefix, 64);
                assert_eq!(&key[..8], &cgroup.to_le_bytes());
                assert_eq!(&key[8..], &[0u8; 8]);
            }
            other => panic!("{other:?}"),
        }
        match styx_allow(&["4", "cell", "7", "10.0.0.0/8", "0", "65535", "3"])
            .allow_key()
            .unwrap()
        {
            StyxAllowKey::CellV4(key, prefix) => {
                assert_eq!(prefix, 72);
                assert_eq!(&key[8..12], &[10, 0, 0, 0]);
            }
            other => panic!("{other:?}"),
        }
        match styx_allow(&["4", "cell", "7", "203.0.113.9/32", "443", "443", "3"])
            .allow_key()
            .unwrap()
        {
            StyxAllowKey::CellV4(key, prefix) => {
                assert_eq!(prefix, 112);
                assert_eq!(&key[12..14], &443u16.to_be_bytes());
                assert_eq!(key[14], 0);
            }
            other => panic!("{other:?}"),
        }
        match styx_allow(&["4", "cell", "7", "203.0.113.9/32", "443", "443", "1"])
            .allow_key()
            .unwrap()
        {
            StyxAllowKey::CellV4(key, prefix) => {
                assert_eq!(prefix, 120);
                assert_eq!(key[14], gedefense_common::STYX_PROTO_TCP);
            }
            other => panic!("{other:?}"),
        }
        assert!(styx_allow(&["4", "cell", "7", "10.0.0.0/8", "443", "443", "3"])
            .allow_key()
            .is_err());
        assert!(styx_allow(&["4", "cell", "7", "203.0.113.9/32", "0", "65535", "1"])
            .allow_key()
            .is_err());
        assert!(styx_allow(&["4", "cell", "7", "203.0.113.9/32", "1", "2", "3"])
            .allow_key()
            .is_err());
    }

    #[test]
    fn styx_cell_v6_and_global_keys_follow_section_four() {
        use styx_flow::StyxAllowKey;
        match styx_allow(&["6", "cell", "7", "2001:db8::/64", "53", "53", "1"])
            .allow_key()
            .unwrap()
        {
            StyxAllowKey::CellV6(key, prefix) => {
                assert_eq!(prefix, 128);
                assert_eq!(&key[..8], &7u64.to_le_bytes());
                assert_eq!(&key[8..12], &[0x20, 0x01, 0x0d, 0xb8]);
            }
            other => panic!("{other:?}"),
        }
        match styx_allow(&["4", "global", "0", "203.0.113.0/24", "0", "65535", "3"])
            .allow_key()
            .unwrap()
        {
            StyxAllowKey::GlobalV4(key, prefix) => {
                assert_eq!(prefix, 24);
                assert_eq!(&key[..4], &[203, 0, 113, 0]);
            }
            other => panic!("{other:?}"),
        }
        match styx_allow(&["4", "global", "0", "203.0.113.9/32", "53", "53", "2"])
            .allow_key()
            .unwrap()
        {
            StyxAllowKey::GlobalV4(key, prefix) => {
                assert_eq!(prefix, 56);
                assert_eq!(&key[4..6], &53u16.to_be_bytes());
                assert_eq!(key[6], gedefense_common::STYX_PROTO_UDP);
            }
            other => panic!("{other:?}"),
        }
        // §4 prefixes 48 (global-v4 +port) and 144/152 (global-v6) as well as
        // the full 192-bit cell-v6 lookup key must be exactly reproducible.
        match styx_allow(&["4", "global", "0", "203.0.113.9/32", "53", "53", "3"])
            .allow_key()
            .unwrap()
        {
            StyxAllowKey::GlobalV4(_, prefix) => assert_eq!(prefix, 48),
            other => panic!("{other:?}"),
        }
        match styx_allow(&["6", "cell", "7", "2001:db8::1/128", "0", "65535", "3"])
            .allow_key()
            .unwrap()
        {
            StyxAllowKey::CellV6(_, prefix) => assert_eq!(prefix, 192),
            other => panic!("{other:?}"),
        }
        match styx_allow(&["6", "global", "0", "2001:db8::1/128", "853", "853", "3"])
            .allow_key()
            .unwrap()
        {
            StyxAllowKey::GlobalV6(_, prefix) => assert_eq!(prefix, 144),
            other => panic!("{other:?}"),
        }
        match styx_allow(&["6", "global", "0", "2001:db8::/128", "853", "853", "1"])
            .allow_key()
            .unwrap()
        {
            StyxAllowKey::GlobalV6(key, prefix) => {
                assert_eq!(prefix, 152);
                assert_eq!(&key[16..18], &853u16.to_be_bytes());
                assert_eq!(key[18], gedefense_common::STYX_PROTO_TCP);
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn styx_policy_prefix_keys_are_bare_networks() {
        use styx_flow::StyxPrefixKey;
        assert_eq!(
            styx_flow::parse_prefix_cidr(4, "169.254.0.0/16")
                .unwrap()
                .prefix_key()
                .unwrap(),
            StyxPrefixKey::V4([169, 254, 0, 0], 16)
        );
        match styx_flow::parse_prefix_cidr(6, "fe80::/10")
            .unwrap()
            .prefix_key()
            .unwrap()
        {
            StyxPrefixKey::V6(key, prefix) => {
                assert_eq!(prefix, 10);
                assert_eq!(&key[..2], &[0xfe, 0x80]);
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn styx_global_word_packs_epoch_flags_and_mode() {
        let word =
            styx_flow::encode_styx_global(0xdead_beef, 2, gedefense_common::STYX_FLAG_LOG_FLOWS);
        assert_eq!(word & 0xffff_ffff, 0xdead_beef);
        assert_eq!(
            (word >> 32) as u8,
            gedefense_common::STYX_FLAG_LOG_FLOWS
        );
        assert_eq!((word >> 40) as u8, 2);
        assert_eq!(styx_flow::encode_styx_global(1, 0, 0), 1);
    }

    fn styx_fixture_event() -> gedefense_common::FlowEvent {
        gedefense_common::FlowEvent {
            cgroup_id: 0x0102_0304_0506_0708,
            ts_ns: 9,
            tx_bytes: 10,
            rx_bytes: 0,
            pid: 42,
            uid: 1000,
            dst: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 203, 0, 113, 9],
            src: [0u8; 16],
            dst_port: 443,
            src_port: 51_234,
            packets: 3,
            proto: gedefense_common::STYX_PROTO_TCP,
            family: NETWORK_FAMILY_V4,
            direction: gedefense_common::STYX_DIR_EGRESS,
            tcp_flags: 0x18,
            verdict: gedefense_common::STYX_VERDICT_ALLOW,
            reserved: [0; 3],
            comm: *b"curl\0\0\0\0\0\0\0\0\0\0\0\0",
        }
    }

    #[test]
    fn styx_flow_text_wire_matches_the_contract() {
        let text =
            styx_flow::encode_styx_flow_event_text(&styx_fixture_event()).expect("encodable event");
        assert_eq!(
            text,
            "0102030405060708:9:10:0:42:1000:cb007109:443:51234:3:4:6:1:24:0:6375726c"
        );
        assert_eq!(text.split(':').count(), 16);
        // A comm with bytes the Go decoder refuses degrades to an empty field ...
        let mut event = styx_fixture_event();
        event.comm = *b"Web Content\0\0\0\0\0";
        let text = styx_flow::encode_styx_flow_event_text(&event).expect("encodable event");
        assert!(text.ends_with(':'), "comm field not degraded: {text}");
        // ... while non-representable records are skipped instead of poisoning
        // an entire batch.
        let mut event = styx_fixture_event();
        event.pid = i32::MAX as u32 + 1;
        assert!(styx_flow::encode_styx_flow_event_text(&event).is_none());
        let mut event = styx_fixture_event();
        event.family = NETWORK_FAMILY_V6;
        event.dst = [0u8; 16];
        assert!(styx_flow::encode_styx_flow_event_text(&event).is_none());
        let mut event = styx_fixture_event();
        event.comm = [b'x'; 16];
        assert!(styx_flow::encode_styx_flow_event_text(&event).is_none());
    }

    #[test]
    fn styx_flow_batch_is_bounded_and_reports_drops() {
        // 6.2.0 flow-telemetry contract: the eBPF ring grew to 16 MiB, the core
        // drains 64 records per poll and the response ceiling covers the whole
        // base64url-encoded batch. Pinning the numbers here makes an accidental
        // rollback to the 8-record/2048-byte StyX limits fail loudly.
        assert_eq!(styx_flow::MAX_STYX_FLOW_EVENTS_PER_RESPONSE, 64);
        assert_eq!(styx_flow::MAX_STYX_FLOW_PAYLOAD_BYTES, 16 * 1024);
        assert_eq!(MAX_RESPONSE_BYTES, 24 * 1024);
        // base64url(16 KiB) plus the "VGT3R <nonce> <status> <payload> <mac>"
        // line must fit the control-plane reader after the Go-side update.
        assert!(styx_flow::MAX_STYX_FLOW_PAYLOAD_BYTES.div_ceil(3) * 4 + 128 < MAX_RESPONSE_BYTES);
        assert_eq!(styx_flow_batch_response(&[], 0), "empty");
        assert_eq!(styx_flow_batch_response(&[], 7), "7|");
        assert_eq!(
            styx_flow_batch_response(&["a".to_owned(), "b".to_owned()], 3),
            "3|a,b"
        );
        let mut event = styx_fixture_event();
        event.cgroup_id = u64::MAX;
        event.ts_ns = u64::MAX;
        event.tx_bytes = u64::MAX;
        event.rx_bytes = u64::MAX;
        event.pid = i32::MAX as u32;
        event.uid = u32::MAX;
        event.packets = u32::MAX;
        event.family = NETWORK_FAMILY_V6;
        event.dst = [0xff; 16];
        event.proto = 0;
        event.tcp_flags = 0;
        event.dst_port = 0;
        event.src_port = 0;
        event.comm = *b"fifteen-char-na\0";
        let record = styx_flow::encode_styx_flow_event_text(&event).expect("maximal record");
        let records = vec![record; styx_flow::MAX_STYX_FLOW_EVENTS_PER_RESPONSE];
        let batch = styx_flow_batch_response(&records, u64::MAX);
        assert_eq!(
            batch.split(',').count(),
            styx_flow::MAX_STYX_FLOW_EVENTS_PER_RESPONSE
        );
        assert!(
            batch.len() <= styx_flow::MAX_STYX_FLOW_PAYLOAD_BYTES,
            "batch of {batch:?} bytes"
        );
    }

    #[test]
    fn styx_flow_health_has_six_decimal_fields() {
        assert_eq!(
            styx_flow::encode_styx_flow_health(&[1, 2, 3, 4, 5, 6]),
            "1:2:3:4:5:6"
        );
        let maximal = styx_flow::encode_styx_flow_health(&[u64::MAX; 6]);
        assert_eq!(maximal.split(':').count(), 6);
        assert!(maximal.len() <= 160);
    }

    #[test]
    fn styx_epoch_is_sixteen_lowercase_hex_characters() {
        let (value, hex_epoch) = random_styx_epoch().expect("random epoch");
        assert_eq!(hex_epoch.len(), 16);
        assert!(hex_epoch
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()));
        assert_eq!(hex_epoch, format!("{value:016x}"));
    }

    #[test]
    fn styx_map_results_are_explicit_and_deletes_idempotent() {
        assert_eq!(styx_map_result(Ok(()), true).unwrap(), "added");
        assert_eq!(styx_map_result(Ok(()), false).unwrap(), "deleted");
        assert_eq!(
            styx_map_result(Err(MapError::KeyNotFound), false).unwrap(),
            "deleted"
        );
        assert!(styx_map_result(Err(MapError::KeyNotFound), true).is_err());
        assert!(styx_map_result(Err(MapError::InvalidMapType { map_type: 0 }), false).is_err());
    }

    // ---- Point 1: synthetic BTF fixtures for the mini parser (§4.1/§6). ----
    //
    // The parser module is capped at 500 lines, so its fixtures live here. The
    // `6.18`/`7.0` layouts below use the §4.1 golden values (BTF-verified on
    // those kernels); broken variants must be `Err`, never a heuristic.

    struct BtfFixture {
        strings: Vec<u8>,
        types: Vec<Vec<u8>>,
    }

    impl BtfFixture {
        fn new() -> Self {
            Self {
                strings: vec![0],
                types: Vec::new(),
            }
        }

        fn name(&mut self, name: &str) -> u32 {
            let offset = self.strings.len() as u32;
            self.strings.extend_from_slice(name.as_bytes());
            self.strings.push(0);
            offset
        }

        fn push(
            &mut self,
            name_off: u32,
            kind: u8,
            vlen: u16,
            flag: bool,
            value: u32,
            extra: &[u8],
        ) -> u32 {
            let mut info = (u32::from(kind) << 24) | u32::from(vlen);
            if flag {
                info |= 1 << 31;
            }
            let mut encoded = Vec::with_capacity(12 + extra.len());
            encoded.extend_from_slice(&name_off.to_le_bytes());
            encoded.extend_from_slice(&info.to_le_bytes());
            encoded.extend_from_slice(&value.to_le_bytes());
            encoded.extend_from_slice(extra);
            self.types.push(encoded);
            self.types.len() as u32
        }

        fn int(&mut self, name: &str, size: u32) -> u32 {
            let name_off = self.name(name);
            self.push(name_off, 1, 0, false, size, &size.to_le_bytes())
        }

        fn pointer(&mut self, pointee: u32) -> u32 {
            self.push(0, 2, 0, false, pointee, &[])
        }

        fn record(
            &mut self,
            name: &str,
            union: bool,
            flag: bool,
            size: u32,
            members: &[(u32, u32, u32)],
        ) -> u32 {
            let name_off = self.name(name);
            let mut extra = Vec::new();
            for (member_name, type_id, offset_bits) in members {
                extra.extend_from_slice(&member_name.to_le_bytes());
                extra.extend_from_slice(&type_id.to_le_bytes());
                extra.extend_from_slice(&offset_bits.to_le_bytes());
            }
            self.push(
                name_off,
                if union { 5 } else { 4 },
                members.len() as u16,
                flag,
                size,
                &extra,
            )
        }

        fn func_proto(&mut self, params: u16, param_type: u32) -> u32 {
            let mut extra = Vec::new();
            for _ in 0..params {
                extra.extend_from_slice(&0u32.to_le_bytes());
                extra.extend_from_slice(&param_type.to_le_bytes());
            }
            self.push(0, 13, params, false, 0, &extra)
        }

        fn func(&mut self, name: &str, proto: u32) -> u32 {
            let name_off = self.name(name);
            self.push(name_off, 12, 0, false, proto, &[])
        }

        fn finish(self) -> Vec<u8> {
            let type_len: u32 = self.types.iter().map(|encoded| encoded.len() as u32).sum();
            let mut data = Vec::new();
            data.extend_from_slice(&btf_offsets::BTF_MAGIC.to_le_bytes());
            data.push(btf_offsets::BTF_VERSION);
            data.push(0);
            data.extend_from_slice(&(btf_offsets::BTF_HEADER_BYTES as u32).to_le_bytes());
            data.extend_from_slice(&0u32.to_le_bytes());
            data.extend_from_slice(&type_len.to_le_bytes());
            data.extend_from_slice(&type_len.to_le_bytes());
            data.extend_from_slice(&(self.strings.len() as u32).to_le_bytes());
            for encoded in &self.types {
                data.extend_from_slice(encoded);
            }
            data.extend_from_slice(&self.strings);
            data
        }
    }

    #[derive(Clone, Copy, Debug)]
    struct TitanBtfSpec {
        inode_size: u32,
        file_size: u32,
        bprm_size: u32,
        super_size: u32,
        bprm_nargs: u16,
        mmap_nargs: u16,
        i_ino_off: u32,
        drop_ino: bool,
        drop_super: bool,
        duplicate_inode: bool,
        // §4.1 ctime-Layout-Vertrag: `false` = legacy timespec64, `true` =
        // modern split `i_ctime_sec`/`i_ctime_nsec`; width 2 is the invalid probe.
        ctime_split: bool,
        split_nsec_width: u32,
        drop_ctime: bool,
    }

    impl Default for TitanBtfSpec {
        fn default() -> Self {
            Self {
                inode_size: 600,
                file_size: 256,
                bprm_size: 128,
                super_size: 256,
                bprm_nargs: 1,
                mmap_nargs: 4,
                i_ino_off: 64,
                drop_ino: false,
                drop_super: false,
                duplicate_inode: false,
                ctime_split: false,
                split_nsec_width: 4,
                drop_ctime: false,
            }
        }
    }

    /// Synthetic vmlinux-BTF with the §4.1 layout: anonymous union (`i_nlink`),
    /// `kind_flag` bitfield (`i_opflags`), both ctime layouts and both LSM hooks.
    fn titan_btf_fixture(spec: &TitanBtfSpec) -> Vec<u8> {
        let mut fixture = BtfFixture::new();
        let u16t = fixture.int("u16", 2);
        let u32t = fixture.int("u32", 4);
        let u64t = fixture.int("u64", 8);
        let i64t = fixture.int("i64", 8);
        let ulong = fixture.int("unsigned long", 8);
        let pointer = fixture.pointer(u32t);
        let tv_sec = fixture.name("tv_sec");
        let tv_nsec = fixture.name("tv_nsec");
        let timespec = fixture.record(
            "timespec64",
            false,
            false,
            16,
            &[(tv_sec, i64t, 0), (tv_nsec, i64t, 64)],
        );
        let i_nlink = fixture.name("i_nlink");
        let alternate = fixture.name("__i_nlink");
        let anonymous_union = fixture.record("", true, false, 4, &[(i_nlink, u32t, 0), (alternate, u32t, 0)]);
        let i_uid = fixture.name("i_uid");
        let d_parent = fixture.name("d_parent");
        let d_inode = fixture.name("d_inode");
        let path_mnt = fixture.name("mnt");
        let path_dentry = fixture.name("dentry");
        let f_path = fixture.name("f_path");
        let bprm_filename = fixture.name("filename");
        let i_mode = fixture.name("i_mode");
        let i_opflags = fixture.name("i_opflags");
        let i_ino = fixture.name("i_ino");
        let i_sb = fixture.name("i_sb");
        let i_generation = fixture.name("i_generation");
        let i_ctime = fixture.name("i_ctime");
        let i_ctime_sec = fixture.name("i_ctime_sec");
        let i_ctime_nsec = fixture.name("i_ctime_nsec");
        let split_nsec = match spec.split_nsec_width {
            8 => u64t,
            4 => u32t,
            _ => u16t,
        };
        let mut inode_members = vec![
            (i_mode, u16t, 0),
            (i_opflags, u16t, 16 | (4 << 24)),
            (i_uid, u32t, 8 * 8),
            (i_sb, pointer, 40 * 8),
            (0, anonymous_union, 72 * 8),
            (i_generation, u32t, 124 * 8),
        ];
        if spec.ctime_split {
            inode_members.push((i_ctime_sec, u64t, 104 * 8));
            inode_members.push((i_ctime_nsec, split_nsec, 120 * 8));
        } else if !spec.drop_ctime {
            inode_members.push((i_ctime, timespec, 128 * 8));
        }
        if !spec.drop_ino {
            inode_members.push((i_ino, u64t, spec.i_ino_off * 8));
        }
        fixture.record("inode", false, true, spec.inode_size, &inode_members);
        if spec.duplicate_inode {
            fixture.record("inode", false, false, spec.inode_size, &[(i_mode, u16t, 0)]);
        }
        let f_inode = fixture.name("f_inode");
        // §4.1 ABI 2: the bounded `file -> f_path.dentry -> d_parent` chain for
        // the UNTRUSTED world-writable ancestor check. The dentry walk below
        // reads the inode mode of each ancestor directory.
        let _dentry = fixture.record(
            "dentry",
            false,
            false,
            256,
            &[(d_parent, pointer, 16 * 8), (d_inode, pointer, 24 * 8)],
        );
        let path = fixture.record(
            "path",
            false,
            false,
            16,
            &[(path_mnt, pointer, 0), (path_dentry, pointer, 8 * 8)],
        );
        fixture.record(
            "file",
            false,
            false,
            spec.file_size,
            &[(f_inode, pointer, 32 * 8), (f_path, path, 96 * 8)],
        );
        let bprm_file = fixture.name("file");
        fixture.record(
            "linux_binprm",
            false,
            false,
            spec.bprm_size,
            &[(bprm_file, pointer, 64 * 8), (bprm_filename, pointer, 8 * 8)],
        );
        if !spec.drop_super {
            let s_dev = fixture.name("s_dev");
            let s_magic = fixture.name("s_magic");
            fixture.record(
                "super_block",
                false,
                false,
                spec.super_size,
                &[(s_dev, u32t, 16 * 8), (s_magic, ulong, 96 * 8)],
            );
        }
        let bprm_proto = fixture.func_proto(spec.bprm_nargs, pointer);
        fixture.func("bpf_lsm_bprm_check_security", bprm_proto);
        let mmap_proto = fixture.func_proto(spec.mmap_nargs, pointer);
        fixture.func("bpf_lsm_mmap_file", mmap_proto);
        fixture.finish()
    }

    /// Parses a synthetic BTF image and resolves the validated §4.1 offsets.
    fn resolve_titan_btf(data: Vec<u8>) -> Result<btf_offsets::TitanExecOffsets, String> {
        btf_offsets::VmlinuxBtf::parse(data)?.resolve_titan_exec()
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

    #[test]
    fn titan_btf_golden_offsets_resolve_for_6_18_and_7_0() {
        // Golden values from §4.1 (x86_64, BTF-verified on 6.18/7.0); the 7.0
        // fixture only grows the inode struct, so the field offsets must stay.
        for (label, inode_size) in [("6.18", 600u32), ("7.0", 640)] {
            let spec = TitanBtfSpec {
                inode_size,
                ..Default::default()
            };
            let offsets =
                resolve_titan_btf(titan_btf_fixture(&spec)).expect(label);
            let resolved = [
                (offsets.bprm_file_off, 64),
                (offsets.file_f_inode_off, 32),
                (offsets.inode_i_ino_off, 64),
                (offsets.inode_i_sb_off, 40),
                (offsets.inode_i_nlink_off, 72),
                (offsets.inode_i_mode_off, 0),
                (offsets.inode_i_generation_off, 124),
                (offsets.super_s_dev_off, 16),
                (offsets.super_s_magic_off, 96),
                (offsets.inode_i_ctime_sec_off, 128),
                (offsets.inode_i_ctime_nsec_off, 136),
                (offsets.inode_i_ctime_nsec_width, 8),
                // §4.1 ABI 2: UNTRUSTED exec-mode facts of the golden layout.
                (offsets.bprm_filename_off, 8),
                (offsets.inode_i_uid_off, 8),
                (offsets.file_f_path_dentry_off, 104),
                (offsets.dentry_d_parent_off, 16),
                (offsets.dentry_d_inode_off, 24),
                (offsets.dentry_size, 256),
                (offsets.bprm_nargs, 1),
                (offsets.mmap_nargs, 4),
                (offsets.mmap_file_arg_idx, 0),
                (offsets.mmap_prot_arg_idx, 2),
                (offsets.mmap_flags_arg_idx, 3),
                (offsets.bprm_retval_slot, 1),
                (offsets.mmap_retval_slot, 4),
                (offsets.inode_size, inode_size),
                (offsets.file_size, 256),
                (offsets.bprm_size, 128),
            ];
            for (actual, expected) in resolved {
                assert_eq!(actual, expected, "{label}");
            }
            assert!(titan_exec_offsets_match_ebpf_slots(&offsets), "{label}");
            let table = encode_titan_exec_offsets_table(&offsets);
            assert_eq!(table.len(), btf_offsets::TITAN_EXEC_OFFSETS_TABLE_LEN);
            assert_eq!(table[btf_offsets::OFF_MAGIC], gedefense_common::TITAN_EXEC_OFFSETS_MAGIC);
            assert_eq!(table[btf_offsets::OFF_ABI], gedefense_common::TITAN_EXEC_OFFSETS_ABI);
            assert_eq!(table[btf_offsets::OFF_BPRM_FILE], 64);
            assert_eq!(table[btf_offsets::OFF_FILE_F_INODE], 32);
            assert_eq!(table[btf_offsets::OFF_TMPFS_MAGIC], btf_offsets::TMPFS_MAGIC);
            assert_eq!(table[btf_offsets::OFF_DEVTMPFS_MAGIC], btf_offsets::DEVTMPFS_MAGIC);
            assert_eq!(table[btf_offsets::OFF_PROC_MAGIC], btf_offsets::PROC_SUPER_MAGIC);
            assert_eq!(table[btf_offsets::OFF_SYSFS_MAGIC], btf_offsets::SYSFS_MAGIC);
            assert_eq!(table[btf_offsets::OFF_OVERLAY_MAGIC], btf_offsets::OVERLAYFS_SUPER_MAGIC);
            assert_eq!(table[btf_offsets::OFF_BPRM_NARGS], 1);
            assert_eq!(table[btf_offsets::OFF_MMAP_NARGS], 4);
            assert_eq!(table[btf_offsets::OFF_MMAP_PROT_ARG], 2);
            assert_eq!(table[btf_offsets::OFF_INODE_I_CTIME_SEC], 128);
            assert_eq!(table[btf_offsets::OFF_INODE_I_CTIME_NSEC], 136);
            assert_eq!(table[btf_offsets::OFF_INODE_I_CTIME_NSEC_WIDTH], 8);
            assert_eq!(table[btf_offsets::OFF_BPRM_FILENAME], 8);
            assert_eq!(table[btf_offsets::OFF_INODE_I_UID], 8);
            assert_eq!(table[btf_offsets::OFF_FILE_F_PATH_DENTRY], 104);
            assert_eq!(table[btf_offsets::OFF_DENTRY_D_PARENT], 16);
            assert_eq!(table[btf_offsets::OFF_DENTRY_D_INODE], 24);
            assert_eq!(table[btf_offsets::OFF_DENTRY_SIZE], 256);
            assert!(
                table[btf_offsets::OFF_RESERVED_FIRST..]
                    .iter()
                    .all(|value| *value == 0),
                "{label}"
            );
        }
    }

    #[test]
    fn titan_btf_split_ctime_layout_publishes_the_nsec_width() {
        // §4.1 ctime-Layout-Vertrag: modern kernels have i_ctime_sec (8 B) +
        // i_ctime_nsec (4 B) instead of a timespec64; both must resolve and the
        // width index 28 must follow the real field width.
        let legacy = resolve_titan_btf(titan_btf_fixture(&TitanBtfSpec::default()))
            .expect("legacy timespec64 layout");
        assert_eq!(
            (
                legacy.inode_i_ctime_sec_off,
                legacy.inode_i_ctime_nsec_off,
                legacy.inode_i_ctime_nsec_width
            ),
            (128, 136, 8)
        );
        let split = resolve_titan_btf(titan_btf_fixture(&TitanBtfSpec {
            ctime_split: true,
            ..Default::default()
        }))
        .expect("split modern layout");
        assert_eq!(
            (
                split.inode_i_ctime_sec_off,
                split.inode_i_ctime_nsec_off,
                split.inode_i_ctime_nsec_width
            ),
            (104, 120, 4)
        );
        assert!(titan_exec_offsets_match_ebpf_slots(&split));
        let table = encode_titan_exec_offsets_table(&split);
        assert_eq!(table[btf_offsets::OFF_INODE_I_CTIME_NSEC_WIDTH], 4);
        // A split layout whose nsec field is 8 B is declared/reported as width 8
        // (eBPF reads u64 for 8, u32 for 4).
        let wide = resolve_titan_btf(titan_btf_fixture(&TitanBtfSpec {
            ctime_split: true,
            split_nsec_width: 8,
            ..Default::default()
        }))
        .expect("wide split layout");
        assert_eq!(wide.inode_i_ctime_nsec_width, 8);
        // Implausible width and a fully missing ctime pair are Err (fail-safe).
        for spec in [
            TitanBtfSpec {
                ctime_split: true,
                split_nsec_width: 2,
                ..Default::default()
            },
            TitanBtfSpec {
                drop_ctime: true,
                ..Default::default()
            },
        ] {
            assert!(resolve_titan_btf(titan_btf_fixture(&spec)).is_err(), "{spec:?}");
        }
    }

    #[test]
    fn titan_btf_live_vmlinux_resolves_all_offsets() {
        // §4.1 Real-BTF-Gate: with a live /sys/kernel/btf/vmlinux every offset
        // (including the ctime variant) must resolve and validate. Without the
        // file this is a documented SKIP, never a silent pass.
        if !Path::new(btf_offsets::VMLINUX_BTF_PATH).is_file() {
            eprintln!(
                "SKIP titan_btf_live_vmlinux_resolves_all_offsets: {} is absent on this host",
                btf_offsets::VMLINUX_BTF_PATH
            );
            return;
        }
        let offsets = btf_offsets::resolve_vmlinux_offsets()
            .expect("live vmlinux BTF must resolve the §4.1 offsets");
        eprintln!("live BTF §4.1 offsets: {offsets:?}");
        assert!(titan_exec_offsets_match_ebpf_slots(&offsets));
        assert!(matches!(offsets.inode_i_ctime_nsec_width, 4 | 8));
        assert!(offsets.inode_i_ctime_nsec_off > offsets.inode_i_ctime_sec_off);
        assert!(offsets.inode_i_ctime_sec_off + 8 <= offsets.inode_size);
        assert!(
            offsets.inode_i_ctime_nsec_off + offsets.inode_i_ctime_nsec_width
                <= offsets.inode_size
        );
        // §4.1 ABI 2 (UNTRUSTED): every new field must fit its real struct.
        assert!(offsets.inode_i_uid_off + 4 <= offsets.inode_size);
        assert!(offsets.bprm_filename_off + 8 <= offsets.bprm_size);
        assert!(offsets.file_f_path_dentry_off + 8 <= offsets.file_size);
        assert!(offsets.dentry_d_parent_off + 8 <= offsets.dentry_size);
        assert!(offsets.dentry_d_inode_off + 8 <= offsets.dentry_size);
        assert!(offsets.dentry_size > 0);
        let table = encode_titan_exec_offsets_table(&offsets);
        assert_eq!(
            table[btf_offsets::OFF_INODE_I_CTIME_NSEC_WIDTH],
            offsets.inode_i_ctime_nsec_width
        );
        assert_eq!(
            table[btf_offsets::OFF_MAGIC],
            gedefense_common::TITAN_EXEC_OFFSETS_MAGIC
        );
    }

    #[test]
    fn titan_btf_rejects_broken_headers_truncation_and_implausible_layouts() {
        let good = titan_btf_fixture(&TitanBtfSpec::default());
        let mut wrong_magic = good.clone();
        wrong_magic[0] ^= 0xff;
        let mut wrong_version = good.clone();
        wrong_version[2] = 2;
        let mut wrong_hdr_len = good.clone();
        wrong_hdr_len[4] = 23;
        let mut oversized_hdr_len = good.clone();
        oversized_hdr_len[4..8].copy_from_slice(&(good.len() as u32 + 1).to_le_bytes());
        let broken_bodies: Vec<(&str, Vec<u8>)> = vec![
            ("empty", Vec::new()),
            ("short header", good[..12].to_vec()),
            ("wrong magic", wrong_magic),
            ("wrong version", wrong_version),
            ("wrong hdr_len", wrong_hdr_len),
            ("hdr_len beyond image", oversized_hdr_len),
            ("truncated string table", good[..good.len() - 4].to_vec()),
        ];
        for (label, data) in broken_bodies {
            assert!(resolve_titan_btf(data).is_err(), "{label}");
        }
        let broken_layouts = [
            ("offset beyond inode", TitanBtfSpec { inode_size: 100, ..Default::default() }),
            ("missing i_ino", TitanBtfSpec { drop_ino: true, ..Default::default() }),
            ("missing super_block", TitanBtfSpec { drop_super: true, ..Default::default() }),
            ("ambiguous inode", TitanBtfSpec { duplicate_inode: true, ..Default::default() }),
            ("bprm arity 2", TitanBtfSpec { bprm_nargs: 2, ..Default::default() }),
            ("mmap arity 2", TitanBtfSpec { mmap_nargs: 2, ..Default::default() }),
            ("mmap arity 6", TitanBtfSpec { mmap_nargs: 6, ..Default::default() }),
        ];
        for (label, spec) in broken_layouts {
            assert!(
                resolve_titan_btf(titan_btf_fixture(&spec)).is_err(),
                "{label}"
            );
        }
        // §4.1 accepts mmap arities 3..=5 for index computation, but the eBPF
        // slots are fixed: only arity 4 may ever be attached.
        for arity in [3u16, 5] {
            let spec = TitanBtfSpec {
                mmap_nargs: arity,
                ..Default::default()
            };
            let offsets = resolve_titan_btf(titan_btf_fixture(&spec))
                .expect("arity is plausible");
            assert!(!titan_exec_offsets_match_ebpf_slots(&offsets), "arity {arity}");
        }
    }

    #[test]
    fn titan_btf_accepts_extended_v1_header() {
        let baseline_data = titan_btf_fixture(&TitanBtfSpec::default());
        let baseline = resolve_titan_btf(baseline_data.clone()).expect("baseline BTF");
        // Kernel 7.3 grows the BTF v1 header to 32 bytes; the section offsets
        // stay relative to hdr_len, so an 8-byte extension must parse exactly
        // like the 24-byte header (and must not be mistaken for section data).
        let mut extended = baseline_data;
        extended.splice(24..24, [0u8; 8]);
        extended[4..8].copy_from_slice(&32u32.to_le_bytes());
        let offsets = resolve_titan_btf(extended).expect("32-byte BTF header");
        assert_eq!(offsets.file_f_inode_off, baseline.file_f_inode_off);
        assert_eq!(offsets.inode_i_ino_off, baseline.inode_i_ino_off);
        assert_eq!(offsets.inode_i_mode_off, baseline.inode_i_mode_off);
        assert_eq!(offsets.bprm_nargs, baseline.bprm_nargs);
        assert_eq!(offsets.mmap_nargs, baseline.mmap_nargs);
    }

    #[test]
    fn titan_btf_from_path_is_bounded_and_strict() {
        let directory = test_titan_directory("btf");
        let path = directory.join("vmlinux.btf");
        fs::write(&path, titan_btf_fixture(&TitanBtfSpec::default())).expect("write fixture");
        let text = path.to_string_lossy().into_owned();
        let offsets = btf_offsets::VmlinuxBtf::from_path(&text)
            .expect("parse fixture file")
            .resolve_titan_exec()
            .expect("resolve fixture file");
        assert_eq!(offsets.inode_i_nlink_off, 72);
        assert!(btf_offsets::VmlinuxBtf::from_path(&directory.join("absent").to_string_lossy())
            .is_err());
        let oversized = directory.join("oversized.btf");
        fs::write(&oversized, vec![0u8; btf_offsets::MAX_VMLINUX_BTF_BYTES + 1])
            .expect("write oversized fixture");
        assert!(btf_offsets::VmlinuxBtf::from_path(&oversized.to_string_lossy()).is_err());
        fs::remove_dir_all(directory).expect("cleanup");
    }

    // ---- Point 1: pure Titan exec-gate helpers (§5/§6). ----

    #[test]
    fn titan_exec_lsm_activation_probe_is_strict() {
        assert!(!titan_exec::bpf_lsm_active_from_list(""));
        assert!(!titan_exec::bpf_lsm_active_from_list(
            "lockdown,capability,landlock,yama,apparmor,ima,evm"
        ));
        assert!(titan_exec::bpf_lsm_active_from_list("lockdown,bpf,capability,landlock"));
        assert!(titan_exec::bpf_lsm_active_from_list("bpf"));
        assert!(titan_exec::bpf_lsm_active_from_list(" bpf "));
        assert!(titan_exec::bpf_lsm_active_from_list("lockdown,bpf\n"));
        assert!(titan_exec::bpf_lsm_active_from_list("bpf,bpf,capability"));
        assert!(!titan_exec::bpf_lsm_active_from_list("bpflsm,bpf_lsm,BPF"));
        assert!(!titan_exec::bpf_lsm_active_from_list("lockdown,capability,"));
    }

    #[test]
    fn titan_exec_arguments_are_strict() {
        assert_eq!(titan_exec::parse_mode("0").unwrap(), 0);
        assert_eq!(titan_exec::parse_mode("3").unwrap(), 3);
        // §4.2 ABI 2: UNTRUSTED (4) is a valid global mode ...
        assert_eq!(titan_exec::parse_mode("4").unwrap(), 4);
        for token in ["5", "-1", "+1", " 1", "1 ", "", "0x1", "1.0"] {
            assert!(titan_exec::parse_mode(token).is_err(), "{token:?}");
        }
        // ... but it is not representable in a per-cgroup scope value.
        assert_eq!(titan_exec::parse_scope_mode("3").unwrap(), 3);
        assert!(titan_exec::parse_scope_mode("4").is_err());
        assert_eq!(titan_exec::mode_name(4), "untrusted");
        assert_eq!(titan_exec::mode_name(3), "strict");
        assert_eq!(titan_exec::parse_global_flags("0").unwrap(), 0);
        assert_eq!(titan_exec::parse_global_flags("1").unwrap(), 1);
        for token in ["2", "255"] {
            assert!(titan_exec::parse_global_flags(token).is_err(), "{token:?}");
        }
        assert_eq!(titan_exec::parse_scope_flags("1").unwrap(), 1);
        assert!(titan_exec::parse_scope_flags("2").is_err());
        assert_eq!(titan_exec::parse_scope_cgroup("42").unwrap(), 42);
        assert!(titan_exec::parse_scope_cgroup("0").is_err());
        assert_eq!(titan_exec::parse_policy_dev("2049").unwrap(), 2049);
        assert!(titan_exec::parse_policy_dev("0").is_err());
        assert!(titan_exec::parse_policy_dev("4294967296").is_err());
        assert_eq!(titan_exec::parse_policy_ino("12345").unwrap(), 12_345);
        assert!(titan_exec::parse_policy_ino("0").is_err());
        assert_eq!(titan_exec::parse_u8("255").unwrap(), 255);
        assert!(titan_exec::parse_u8("256").is_err());
    }

    #[test]
    fn titan_exec_policy_store_is_bounded_and_idempotent() {
        let mut store = titan_exec::TitanExecPolicy::new();
        let entry = titan_exec::PolicyEntry {
            action: titan_exec::TITAN_EXEC_ALLOW_ACTION,
            flags: 1,
            ctime_ns: 7,
        };
        assert!(store.insert(1, 2, entry).unwrap());
        assert!(!store.insert(1, 2, entry).unwrap());
        assert_eq!(store.entry(1, 2), Some(entry));
        assert_eq!(store.entry_count(), 1);
        assert_eq!(store.keys(), vec![(1, 2)]);
        assert!(store.insert(0, 2, entry).is_err());
        assert!(store.insert(1, 0, entry).is_err());
        assert!(store.insert(2, 3, titan_exec::PolicyEntry { action: 2, ..entry }).is_err());
        assert!(store.remove(1, 2));
        assert!(!store.remove(1, 2));
        assert_eq!(store.entry_count(), 0);
        for index in 0..titan_exec::TITAN_EXEC_MAX_POLICY_ENTRIES {
            store.insert(index as u32 + 1, 1, entry).unwrap();
        }
        assert!(store.insert(u32::MAX, u64::MAX, entry).is_err());
        store.clear();
        assert_eq!(store.entry_count(), 0);
        let scope_value = encode_titan_exec_scope_value(2, 1).unwrap();
        assert!(store.scope_set(7, scope_value).is_ok());
        assert_eq!(store.scope_remove(7), true);
        assert_eq!(store.scope_remove(7), false);
        assert!(store.scope_set(0, 0).is_err());
        for cgroup in 1..=titan_exec::TITAN_EXEC_MAX_SCOPES as u64 {
            store.scope_set(cgroup, 0).unwrap();
        }
        assert!(store.scope_set(u64::MAX, 0).is_err());
        assert!(store.scope_set(1, 3).is_ok());
        assert_eq!(store.scope_count(), titan_exec::TITAN_EXEC_MAX_SCOPES);
    }

    #[test]
    fn titan_exec_path_validation_rejects_non_canonical_paths() {
        assert!(titan_exec::validate_exec_path("/usr/bin/true").is_ok());
        for path in [
            "", "relative/path", "/usr/../bin/true", "/usr/./bin/true", "/usr//bin/true",
            "/usr/bin/true/", "/", ".", "//etc/passwd", "/usr/\0x", "/usr/bin/tr\nue",
            "/usr/bin/tr\tue",
        ] {
            assert!(titan_exec::validate_exec_path(path).is_err(), "{path:?}");
        }
        let too_long = format!("/{}", "a".repeat(titan_exec::TITAN_EXEC_MAX_PATH_BYTES));
        assert!(titan_exec::validate_exec_path(&too_long).is_err());
    }

    #[test]
    fn titan_exec_path_resolver_is_fd_safe() {
        let directory = test_titan_directory("paths");
        let executable = directory.join("tool");
        fs::write(&executable, b"#!/bin/sh\n").expect("write executable");
        fs::set_permissions(&executable, fs::Permissions::from_mode(0o755)).expect("mode");
        let path = executable.to_string_lossy().into_owned();
        let identity = titan_exec::resolve_exec_path(&path).expect("resolve executable");
        let metadata = fs::metadata(&executable).expect("stat executable");
        assert_eq!(u64::from(identity.dev), metadata.dev() & u64::from(u32::MAX));
        assert_eq!(identity.ino, metadata.ino());
        assert_ne!(identity.mode & 0o111, 0);
        let expected_ctime = u64::try_from(metadata.ctime()).expect("ctime")
            * 1_000_000_000
            + u64::try_from(metadata.ctime_nsec()).expect("ctime_nsec");
        assert_eq!(identity.ctime_ns, expected_ctime);

        // A hard link is the same inode identity; a symlink is refused without
        // being followed (O_PATH|O_NOFOLLOW + fstat on the fd).
        let hardlink = directory.join("hardlink");
        fs::hard_link(&executable, &hardlink).expect("hard link");
        let linked = titan_exec::resolve_exec_path(&hardlink.to_string_lossy()).expect("hardlink");
        assert_eq!((linked.dev, linked.ino), (identity.dev, identity.ino));
        let symlink = directory.join("symlink");
        std::os::unix::fs::symlink(&executable, &symlink).expect("symlink");
        assert_eq!(
            titan_exec::resolve_exec_path(&symlink.to_string_lossy()).unwrap_err(),
            titan_exec::PathReject::Symlink
        );

        let plain = directory.join("plain");
        fs::write(&plain, b"data").expect("write plain");
        assert_eq!(
            titan_exec::resolve_exec_path(&plain.to_string_lossy()).unwrap_err(),
            titan_exec::PathReject::NotExecutable
        );
        assert_eq!(
            titan_exec::resolve_exec_path(&directory.to_string_lossy()).unwrap_err(),
            titan_exec::PathReject::NotRegular
        );
        assert_eq!(
            titan_exec::resolve_exec_path(&directory.join("absent").to_string_lossy()).unwrap_err(),
            titan_exec::PathReject::Open
        );

        // The policy fingerprint is the fstat ctime: a rewrite changes it, which
        // is what REQUIRE_CTIME detects in the kernel (TOCTOU mitigation).
        std::thread::sleep(Duration::from_millis(20));
        fs::write(&executable, b"#!/bin/sh\necho\n").expect("rewrite executable");
        let rewritten = titan_exec::resolve_exec_path(&path).expect("resolve rewritten");
        assert_ne!(rewritten.ctime_ns, identity.ctime_ns);
        fs::remove_dir_all(directory).expect("cleanup");
    }

    #[test]
    fn titan_exec_batch_decode_is_bounded_and_accepts_both_alphabets() {
        use base64::engine::general_purpose::STANDARD;
        use base64::Engine as _;
        let text = "/usr/bin/true\n/usr/bin/false\n";
        assert_eq!(titan_exec::decode_allow_batch(&URL_SAFE_NO_PAD.encode(text)).unwrap().len(), 2);
        assert_eq!(titan_exec::decode_allow_batch(&STANDARD.encode(text)).unwrap().len(), 2);
        assert!(titan_exec::decode_allow_batch(&URL_SAFE_NO_PAD.encode("/usr/bin/true")).is_ok());
        assert!(titan_exec::decode_allow_batch(&URL_SAFE_NO_PAD.encode("/usr/bin/true\n\n")).is_err());
        assert!(titan_exec::decode_allow_batch("not base64 !!!").is_err());
        assert!(titan_exec::decode_allow_batch("").is_err());
        assert!(titan_exec::decode_allow_batch(&URL_SAFE_NO_PAD.encode("relative")).is_err());
        assert!(titan_exec::decode_allow_batch(
            &URL_SAFE_NO_PAD.encode("/usr/bin/true\n\n/usr/bin/false")
        )
        .is_err());
        let too_large = (0..60)
            .map(|index| format!("/usr/bin/tool-with-a-long-name-{index:03}"))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(titan_exec::decode_allow_batch(&URL_SAFE_NO_PAD.encode(&too_large)).is_err());
        let too_many = vec!["/a"; titan_exec::TITAN_EXEC_MAX_BATCH_PATHS + 1].join("\n");
        assert!(titan_exec::decode_allow_batch(&URL_SAFE_NO_PAD.encode(&too_many)).is_err());
        assert_eq!(
            titan_exec::encode_allow_batch_response(3, 0, titan_exec::BATCH_ERROR_NONE),
            "added:3;rejected:0;error=none"
        );
        assert_eq!(
            titan_exec::encode_allow_batch_response(1, 2, "symlink"),
            "added:1;rejected:2;error=symlink"
        );
        assert_eq!(titan_exec::PathReject::Symlink.token(), "symlink");
        assert_eq!(titan_exec::PathReject::NotExecutable.token(), "not-executable");
    }

    fn titan_fixture_event() -> gedefense_common::TitanExecEvent {
        gedefense_common::TitanExecEvent {
            cgroup_id: 0x0102_0304_0506_0708,
            ts_ns: 9,
            dev: 0x0801,
            inode_mode: 0o100_755,
            ino: 0x1122_3344_5566_7788,
            generation: 7,
            pid: 42,
            tgid: 41,
            uid: 1000,
            gid: 1001,
            prot: 4,
            f_flags: 0x8000,
            hook: gedefense_common::TITAN_EXEC_HOOK_BPRM,
            action: gedefense_common::TITAN_EXEC_ACTION_AUDIT,
            reason: gedefense_common::TITAN_EXEC_REASON_NOT_ALLOWLISTED,
            flags: 3,
            comm: *b"untrusted-bin\0\0\0",
            reserved: [0; 8],
        }
    }

    #[test]
    fn titan_exec_event_text_wire_matches_section_three_three() {
        let text = titan_exec::encode_exec_event_text(&titan_fixture_event());
        assert_eq!(
            text,
            "72623859790382856:9:2049:33261:1234605616436508552:7:42:41:1000:1001:4:32768:1:1:4:756e747275737465642d62696e"
        );
        assert_eq!(text.split(':').count(), 16);
        assert_eq!(titan_exec::encode_exec_events_batch(&[], 0).unwrap(), "empty");
        assert_eq!(titan_exec::encode_exec_events_batch(&[], 7).unwrap(), "7|");
        assert_eq!(
            titan_exec::encode_exec_events_batch(&["a".to_owned(), "b".to_owned()], 3).unwrap(),
            "3|a,b"
        );
        let records = vec![text; titan_exec::TITAN_EXEC_MAX_EVENTS_PER_RESPONSE];
        let batch = titan_exec::encode_exec_events_batch(&records, u64::MAX).unwrap();
        assert_eq!(
            batch.split(',').count(),
            titan_exec::TITAN_EXEC_MAX_EVENTS_PER_RESPONSE
        );
        assert!(batch.len() <= titan_exec::TITAN_EXEC_MAX_PAYLOAD_BYTES);
        let too_many = vec!["a".to_owned(); titan_exec::TITAN_EXEC_MAX_EVENTS_PER_RESPONSE + 1];
        assert!(titan_exec::encode_exec_events_batch(&too_many, 0).is_err());
    }

    #[test]
    fn titan_exec_health_and_status_follow_the_contract() {
        assert_eq!(
            titan_exec::encode_exec_health(&[1, 2, 3, 4, 5, 6]),
            "1:2:3:4:5:6"
        );
        let maximal = titan_exec::encode_exec_health(&[u64::MAX; 6]);
        assert_eq!(maximal.split(':').count(), 6);
        let status = titan_exec::encode_exec_status(&titan_exec::StatusView {
            state: titan_exec::ExecState::Inactive,
            mode: 0,
            flags: 0,
            path_bpf_lsm: false,
            lsm_active: false,
            offsets_valid: false,
            entries: 0,
            scopes: 0,
            epoch: "0011223344556677",
        });
        assert_eq!(
            status,
            "status=inactive;mode=0;flags=0;path=none;lsm=inactive;offsets=invalid;entries=0;scopes=0;epoch=0011223344556677"
        );
        assert_eq!(
            titan_exec::exec_state(true, true, true).text(),
            "applied"
        );
        assert_eq!(
            titan_exec::exec_state(false, true, true).text(),
            "unavailable"
        );
        assert_eq!(
            titan_exec::exec_state(false, true, false).text(),
            "unavailable"
        );
        assert_eq!(titan_exec::exec_state(false, false, true).text(), "inactive");
        assert_eq!(titan_exec::exec_state(false, false, false).text(), "inactive");
        for (mode, name) in [(0u8, "off"), (1, "observe"), (2, "contain"), (3, "strict")] {
            assert_eq!(titan_exec::ping_titan_exec_token(false, mode), "inactive");
            assert_eq!(titan_exec::ping_titan_exec_token(true, mode), name);
        }
    }

    #[test]
    fn titan_exec_map_encoders_match_abi_one() {
        let key = encode_titan_exec_policy_key(0x0801_0002, 0x1122_3344_5566_7788);
        assert_eq!(&key[0..4], &0x0801_0002u32.to_le_bytes());
        assert_eq!(&key[4..12], &0x1122_3344_5566_7788u64.to_le_bytes());
        assert_eq!(&key[12..16], &[0u8; 4]);
        let entry = titan_exec::PolicyEntry {
            action: titan_exec::TITAN_EXEC_ALLOW_ACTION,
            flags: titan_exec::TITAN_EXEC_POLICY_FLAG_REQUIRE_CTIME,
            ctime_ns: 0x0102_0304_0506_0708,
        };
        let value = encode_titan_exec_policy_value(&entry);
        assert_eq!(value[0], 1);
        assert_eq!(value[1], 1);
        assert_eq!(&value[2..4], &[0u8; 2]);
        assert_eq!(&value[4..12], &0x0102_0304_0506_0708u64.to_le_bytes());
        assert_eq!(&value[12..16], &[0u8; 4]);
        assert_eq!(encode_titan_exec_scope_value(2, 1).unwrap(), 0b1001);
        assert_eq!(encode_titan_exec_scope_value(0, 0).unwrap(), 0);
        assert!(encode_titan_exec_scope_value(4, 0).is_err());
        assert!(encode_titan_exec_scope_value(0, 2).is_err());
        let word = encode_titan_exec_state(0xdead_beef, 2, 0b101);
        assert_eq!(word & 0xffff_ffff, 0xdead_beef);
        assert_eq!(((word >> 32) & 0xff) as u8, 2);
        assert_eq!(((word >> 40) & 0xff) as u8, 0b101);
        assert_eq!(
            ((word >> 48) & 0xff) as u8,
            gedefense_common::TITAN_EXEC_STATE_ABI
        );
        assert_eq!(
            ((word >> 56) & 0xff) as u8,
            gedefense_common::TITAN_EXEC_STATE_MAGIC
        );
        assert_eq!(encode_titan_exec_state_flags(false, false, false), 0);
        assert_eq!(
            encode_titan_exec_state_flags(true, true, true),
            titan_exec::TITAN_EXEC_STATE_FLAG_OFFSETS_VALID
                | titan_exec::TITAN_EXEC_STATE_FLAG_LSM_ACTIVE
                | titan_exec::TITAN_EXEC_STATE_FLAG_CTIME_CHECK
        );
        assert_eq!(
            encode_titan_exec_state_flags(true, false, false),
            titan_exec::TITAN_EXEC_STATE_FLAG_OFFSETS_VALID
        );
    }

    // ---------------------------------------------------------------------
    // Point 5 (§5/§6/§10): lockdown ABI, state machine and monitor tests.
    // All of these run without root: the eBPF word is an in-memory fake and
    // sysfs/proc/sysctl trees are temp-dir fakes.
    // ---------------------------------------------------------------------

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

    struct FakeNetCounters {
        drops: u64,
        witness: u64,
    }

    impl lockdown::NetCounters for FakeNetCounters {
        fn net_counters(&self) -> Result<(u64, u64), String> {
            Ok((self.drops, self.witness))
        }
    }

    fn lockdown_fixture(label: &str) -> std::path::PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|value| value.as_nanos())
            .unwrap_or(0);
        let root = std::env::temp_dir().join(format!(
            "vgt-lockdown-{label}-{}-{nanos}",
            std::process::id()
        ));
        for directory in [
            "sys/bus/usb/devices",
            "sys/bus/thunderbolt/devices",
            "sys/kernel/security",
            "proc/sys/kernel",
            "state",
        ] {
            fs::create_dir_all(root.join(directory)).expect("lockdown fixture dir");
        }
        fs::write(root.join("sys/bus/usb/drivers_autoprobe"), "1\n").expect("autoprobe");
        for (name, value) in [
            ("kexec_load_disabled", "0"),
            ("sysrq", "1"),
            ("modules_disabled", "0"),
            ("unprivileged_bpf_disabled", "2"),
        ] {
            fs::write(root.join("proc/sys/kernel").join(name), format!("{value}\n"))
                .expect("sysctl fixture");
        }
        fs::write(root.join("sys/kernel/security/lockdown"), "none [integrity] confidentiality\n")
            .expect("kernel lockdown fixture");
        root
    }

    fn lockdown_state_path(root: &Path) -> std::path::PathBuf {
        root.join("state/LOCKDOWN.state")
    }

    fn lockdown_core_with(
        root: &Path,
        word: std::sync::Arc<MemoryWordStore>,
        nets: (u64, u64),
    ) -> lockdown::LockdownCore {
        let config = lockdown::LockdownConfig {
            state_file: lockdown_state_path(root),
            usb: crate::lockdown_usb::UsbPaths::new(root.join("sys")),
            hardening: crate::lockdown_hardening::HardeningPaths::for_root(root),
            proc_root: root.join("proc"),
            monitors: false,
        };
        lockdown::LockdownCore::new(
            config,
            word,
            std::sync::Arc::new(FakeNetCounters { drops: nets.0, witness: nets.1 }),
        )
        .expect("lockdown core")
    }

    fn lockdown_core(root: &Path, word: std::sync::Arc<MemoryWordStore>) -> lockdown::LockdownCore {
        lockdown_core_with(root, word, (0, 0))
    }

    fn lockdown_word(store: &MemoryWordStore) -> gedefense_common::LockdownWord {
        gedefense_common::decode_lockdown_word(store.word()).expect("decoded lockdown word")
    }

    fn lockdown_command_raw(core: &mut lockdown::LockdownCore, parts: &[&str]) -> Result<String, BoxError> {
        lockdown_command(core, parts)
    }

    #[test]
    fn lockdown_dispatch_arm_trigger_clear_matches_the_section_five_abi() {
        let root = lockdown_fixture("dispatch");
        let store = std::sync::Arc::new(MemoryWordStore::new());
        let mut core = lockdown_core(&root, std::sync::Arc::clone(&store));
        let epoch = format!("{:08x}", core.epoch());
        assert_eq!(lockdown_command_raw(&mut core, &["LOCKDOWN_VERSION"]).unwrap(), "lockdown-v1");
        assert_eq!(lockdown_command_raw(&mut core, &["LOCKDOWN_EPOCH"]).unwrap(), epoch);
        let status = lockdown_command_raw(&mut core, &["LOCKDOWN_STATUS"]).unwrap();
        assert!(
            status.starts_with("state=off;epoch=") && status.ends_with(";mode=unlocked;flags=0;phases=-;unsupported=sessions,dm"),
            "{status}"
        );
        assert_eq!(core.ping_suffix(), "+lockdown:off");

        assert_eq!(
            lockdown_command_raw(&mut core, &["LOCKDOWN_ARM", "locked", "manual", "3"]).unwrap(),
            format!("armed:{epoch}")
        );
        assert_eq!(core.ping_suffix(), "+lockdown:armed");
        assert_eq!(lockdown_word(&store).mode, gedefense_common::LOCKDOWN_MODE_ARMED);
        assert_eq!(lockdown_word(&store).flags, 0, "arm alone must not drop");
        assert_eq!(
            lockdown_command_raw(&mut core, &["LOCKDOWN_ARM", "locked", "manual", "3"]).unwrap(),
            format!("armed-unchanged:{epoch}")
        );
        assert_eq!(
            lockdown_command_raw(&mut core, &["LOCKDOWN_SET_MODE", "unlocked"]).unwrap(),
            "applied"
        );

        // TRIGGER creates a new epoch and reports applied/unsupported phases;
        // flags=5 = auto_network_drop + freeze_brokers (loopback NOT kept).
        let triggered = lockdown_command_raw(&mut core, &["LOCKDOWN_TRIGGER", "uevent", "usb-unknown", "5"]).unwrap();
        let armed_epoch = format!("{:08x}", core.epoch());
        assert_ne!(armed_epoch, epoch, "every trigger gets a new epoch");
        assert_eq!(
            triggered,
            format!("triggered:{armed_epoch};phases=net,usb,tb,brokers,cells=delegated;unsupported=sessions,dm")
        );
        assert_eq!(core.ping_suffix(), "+lockdown:active");
        let word = lockdown_word(&store);
        assert_eq!(word.epoch, core.epoch());
        assert_ne!(word.flags & gedefense_common::LOCKDOWN_FLAG_DROP_ALL, 0);
        assert_eq!(word.flags & gedefense_common::LOCKDOWN_FLAG_ALLOW_LOOPBACK, 0);
        let status = lockdown_command_raw(&mut core, &["LOCKDOWN_STATUS"]).unwrap();
        assert!(status.starts_with("state=active;"), "{status}");
        assert!(status.contains(";mode=unlocked;flags=49;"), "{status}");
        assert!(status.contains(";phases=net,usb,tb,brokers,cells=delegated;"), "{status}");

        // ARM during an active latch never lowers it.
        assert_eq!(
            lockdown_command_raw(&mut core, &["LOCKDOWN_ARM", "locked", "manual", "3"]).unwrap(),
            format!("armed-unchanged:{armed_epoch}")
        );
        assert_eq!(core.state_text(), "active");

        // Wrong expected epoch is a compare-set rejection, not a partial clear.
        assert!(lockdown_command_raw(&mut core, &["LOCKDOWN_CLEAR", "deadbeef", "manual"]).is_err());
        assert_eq!(core.state_text(), "active");
        assert_eq!(
            lockdown_command_raw(&mut core, &["LOCKDOWN_CLEAR", &armed_epoch, "manual"]).unwrap(),
            "cleared"
        );
        assert_eq!(core.ping_suffix(), "+lockdown:off");
        assert_eq!(lockdown_word(&store).mode, gedefense_common::LOCKDOWN_MODE_OFF);
        assert!(!lockdown_state_path(&root).exists(), "clear removes the latch file");
        assert_eq!(
            lockdown_command_raw(&mut core, &["LOCKDOWN_CLEAR", &armed_epoch, "manual"]).unwrap(),
            "already-off"
        );
    }

    #[test]
    fn lockdown_token_and_size_boundaries_are_rejected() {
        let root = lockdown_fixture("tokens");
        let store = std::sync::Arc::new(MemoryWordStore::new());
        let mut core = lockdown_core(&root, std::sync::Arc::clone(&store));
        assert!(lockdown_command_raw(&mut core, &["LOCKDOWN_ARM", "bogus", "manual", "1"]).is_err());
        assert!(lockdown_command_raw(&mut core, &["LOCKDOWN_ARM", "locked", "bogus", "1"]).is_err());
        assert!(lockdown_command_raw(&mut core, &["LOCKDOWN_ARM", "locked", "manual", "16"]).is_err());
        assert!(lockdown_command_raw(&mut core, &["LOCKDOWN_ARM", "locked", "manual", "x"]).is_err());
        assert!(lockdown_command_raw(&mut core, &["LOCKDOWN_TRIGGER", "nope", "manual", "1"]).is_err());
        assert!(lockdown_command_raw(&mut core, &["LOCKDOWN_CLEAR", "123", "manual"]).is_err());
        assert!(lockdown_command_raw(&mut core, &["LOCKDOWN_CLEAR", "zzzzzzzz", "manual"]).is_err());
        assert!(lockdown_command_raw(&mut core, &["LOCKDOWN_PHASE", "bogus", "on"]).is_err());
        assert!(lockdown_command_raw(&mut core, &["LOCKDOWN_PHASE", "net", "toggle"]).is_err());
        assert!(lockdown_command_raw(&mut core, &["LOCKDOWN_BOGUS"]).is_err());
        assert!(lockdown_command_raw(&mut core, &["LOCKDOWN_ARM"]).is_err());
        // Every §5 answer stays well below the 2048-byte IPC response budget.
        lockdown_command_raw(&mut core, &["LOCKDOWN_ARM", "locked", "tamper", "15"]).unwrap();
        lockdown_command_raw(&mut core, &["LOCKDOWN_TRIGGER", "manual", "tamper", "15"]).unwrap();
        for parts in [
            vec!["LOCKDOWN_STATUS"],
            vec!["LOCKDOWN_EVENTS"],
            vec!["LOCKDOWN_HEALTH"],
            vec!["LOCKDOWN_EPOCH"],
        ] {
            let answer = lockdown_command_raw(&mut core, &parts).unwrap();
            assert!(answer.len() <= MAX_RESPONSE_BYTES, "{parts:?} answer too long");
        }
    }

    #[test]
    fn lockdown_word_read_back_failures_are_never_claimed() {
        let root = lockdown_fixture("readback");
        let store = std::sync::Arc::new(MemoryWordStore::new());
        store.ignore_writes();
        let mut core = lockdown_core(&root, std::sync::Arc::clone(&store));
        // ARM cannot claim armed without a successful verified write.
        assert!(lockdown_command_raw(&mut core, &["LOCKDOWN_ARM", "locked", "manual", "1"]).is_err());
        assert_eq!(core.state_text(), "off");
        // A trigger still runs the other phases, but NET is not in the applied
        // CSV and the state is degraded: no "network down" claim without read-back.
        let triggered = lockdown_command_raw(&mut core, &["LOCKDOWN_TRIGGER", "manual", "tamper", "1"]).unwrap();
        assert!(!triggered.contains("phases=net"), "{triggered}");
        assert_eq!(core.state_text(), "degraded");
        let status = lockdown_command_raw(&mut core, &["LOCKDOWN_STATUS"]).unwrap();
        assert!(status.contains(";phases=usb,tb,cells=delegated;"), "{status}");
        assert_eq!(store.word(), 0, "no write was persisted");
    }

    #[test]
    fn lockdown_state_file_is_atomic_0640_and_rearms_verified() {
        let root = lockdown_fixture("rearm");
        let store = std::sync::Arc::new(MemoryWordStore::new());
        let mut core = lockdown_core(&root, std::sync::Arc::clone(&store));
        lockdown_command_raw(&mut core, &["LOCKDOWN_ARM", "locked", "manual", "9"]).unwrap();
        lockdown_command_raw(&mut core, &["LOCKDOWN_TRIGGER", "policy", "boot-trust-drift", "9"]).unwrap();
        let epoch = format!("{:08x}", core.epoch());
        let path = lockdown_state_path(&root);
        let metadata = fs::metadata(&path).expect("state file");
        assert_eq!(metadata.permissions().mode() & 0o777, 0o640);
        let content = fs::read_to_string(&path).expect("state file content");
        let fields: Vec<&str> = content.trim_end().split('|').collect();
        assert_eq!(fields.len(), 5, "{content}");
        assert_eq!(fields[0], epoch);
        assert_eq!(fields[1], "locked");
        assert_eq!(fields[2], "09");
        assert_eq!(fields[3], "net,usb,tb,hardening", "flags=9 selects hardening");
        // Phase 1 hardening applied for real in the fake sysctl tree.
        assert_eq!(fs::read_to_string(root.join("proc/sys/kernel/kexec_load_disabled")).unwrap().trim(), "1");
        assert_eq!(fs::read_to_string(root.join("proc/sys/kernel/sysrq")).unwrap().trim(), "0");

        // Re-arm from the file applies drop/USB/TB/hardening again and verifies.
        let rearm_store = std::sync::Arc::new(MemoryWordStore::new());
        let mut rearmed = lockdown_core(&root, std::sync::Arc::clone(&rearm_store));
        assert_eq!(rearmed.startup_rearm().unwrap(), "active");
        let word = lockdown_word(&rearm_store);
        assert_eq!(word.epoch, core.epoch());
        assert_ne!(word.flags & gedefense_common::LOCKDOWN_FLAG_DROP_ALL, 0);
        assert_ne!(word.flags & gedefense_common::LOCKDOWN_FLAG_USB_LOCKED, 0);
        assert_ne!(word.flags & gedefense_common::LOCKDOWN_FLAG_HARDENING_APPLIED, 0);

        // Corrupt file: degraded + latched, but no unverified enforcement action.
        fs::write(&path, "garbage|not-a-state\n").expect("corrupt state");
        let corrupt_store = std::sync::Arc::new(MemoryWordStore::new());
        let mut corrupt = lockdown_core(&root, std::sync::Arc::clone(&corrupt_store));
        assert_eq!(corrupt.startup_rearm().unwrap(), "degraded");
        assert_eq!(corrupt.state_text(), "degraded");
        assert_eq!(corrupt_store.word(), 0, "corrupt state must not fake enforcement");
        assert_eq!(corrupt_store.writes(), 0);
        let epoch = format!("{:08x}", corrupt.epoch());
        assert_eq!(
            lockdown_command_raw(&mut corrupt, &["LOCKDOWN_CLEAR", &epoch, "manual"]).unwrap(),
            "cleared"
        );
        assert!(!path.exists());
    }

    #[test]
    fn lockdown_phase_command_matrix_is_honest() {
        let root = lockdown_fixture("phases");
        let store = std::sync::Arc::new(MemoryWordStore::new());
        let mut core = lockdown_core(&root, std::sync::Arc::clone(&store));
        assert_eq!(
            lockdown_command_raw(&mut core, &["LOCKDOWN_PHASE", "net", "on"]).unwrap(),
            "failed:net:not-armed"
        );
        lockdown_command_raw(&mut core, &["LOCKDOWN_ARM", "locked", "manual", "8"]).unwrap();
        assert_eq!(
            lockdown_command_raw(&mut core, &["LOCKDOWN_PHASE", "cells", "on"]).unwrap(),
            "unsupported:cells:delegated-to-control"
        );
        assert_eq!(
            lockdown_command_raw(&mut core, &["LOCKDOWN_PHASE", "sessions", "on"]).unwrap(),
            "unsupported:sessions:no-dbus-session-lock"
        );
        assert_eq!(
            lockdown_command_raw(&mut core, &["LOCKDOWN_PHASE", "dm", "on"]).unwrap(),
            "unsupported:dm:no-device-mapper"
        );
        assert_eq!(
            lockdown_command_raw(&mut core, &["LOCKDOWN_PHASE", "kernel-lockdown", "on"]).unwrap(),
            "unsupported:kernel-lockdown:boot-parameter-immutable"
        );
        // Explicit single-phase command may set modules_disabled (auto never).
        assert_eq!(
            lockdown_command_raw(&mut core, &["LOCKDOWN_PHASE", "hardening", "on"]).unwrap(),
            "applied:hardening"
        );
        assert_eq!(fs::read_to_string(root.join("proc/sys/kernel/modules_disabled")).unwrap().trim(), "1");
        assert_eq!(
            lockdown_command_raw(&mut core, &["LOCKDOWN_PHASE", "hardening", "off"]).unwrap(),
            "unsupported:hardening:irreversible-until-reboot"
        );
        for phase in ["net", "usb", "tb", "brokers"] {
            assert_eq!(
                lockdown_command_raw(&mut core, &["LOCKDOWN_PHASE", phase, "on"]).unwrap(),
                format!("applied:{phase}")
            );
            assert_eq!(
                lockdown_command_raw(&mut core, &["LOCKDOWN_PHASE", phase, "off"]).unwrap(),
                format!("applied:{phase}")
            );
        }
        assert_eq!(core.ping_suffix(), "+lockdown:active");
    }

    #[test]
    fn lockdown_auto_network_drop_survives_a_later_phase_refresh() {
        let root = lockdown_fixture("auto-drop-phase");
        let store = std::sync::Arc::new(MemoryWordStore::new());
        let mut core = lockdown_core(&root, std::sync::Arc::clone(&store));
        // flags=3 = auto_network_drop + allow_loopback.
        lockdown_command_raw(&mut core, &["LOCKDOWN_ARM", "locked", "manual", "3"]).unwrap();
        core.shared.auto_network_drop().expect("auto drop write");
        assert!(core.shared.auto_drop(), "auto-drop ownership is recorded");
        let word = lockdown_word(&store);
        assert_eq!(word.epoch, core.epoch());
        assert_ne!(word.flags & gedefense_common::LOCKDOWN_FLAG_DROP_ALL, 0);
        assert_ne!(word.flags & gedefense_common::LOCKDOWN_FLAG_ALLOW_LOOPBACK, 0);
        // A later USB phase refresh must keep the drop and add its own bit.
        assert_eq!(
            lockdown_command_raw(&mut core, &["LOCKDOWN_PHASE", "usb", "on"]).unwrap(),
            "applied:usb"
        );
        let word = lockdown_word(&store);
        assert_ne!(word.flags & gedefense_common::LOCKDOWN_FLAG_DROP_ALL, 0, "phase refresh cleared the auto drop");
        assert_ne!(word.flags & gedefense_common::LOCKDOWN_FLAG_USB_LOCKED, 0, "USB phase bit was not persisted");
        assert_ne!(word.flags & gedefense_common::LOCKDOWN_FLAG_ALLOW_LOOPBACK, 0);
    }

    #[test]
    fn lockdown_auto_network_drop_survives_a_startup_rearm() {
        let root = lockdown_fixture("auto-drop-rearm");
        let store = std::sync::Arc::new(MemoryWordStore::new());
        let mut core = lockdown_core(&root, std::sync::Arc::clone(&store));
        // flags=3 = auto_network_drop + allow_loopback.
        lockdown_command_raw(&mut core, &["LOCKDOWN_ARM", "locked", "manual", "3"]).unwrap();
        core.shared.auto_network_drop().expect("auto drop write");
        assert_eq!(
            lockdown_command_raw(&mut core, &["LOCKDOWN_PHASE", "usb", "on"]).unwrap(),
            "applied:usb"
        );
        let before = lockdown_word(&store);
        assert_ne!(before.flags & gedefense_common::LOCKDOWN_FLAG_DROP_ALL, 0);

        // A daemon restart re-arms from the persisted USB phase. The DROP_ALL
        // already verified in the kernel word must not be cleared silently.
        let mut restarted = lockdown_core(&root, std::sync::Arc::clone(&store));
        restarted.startup_rearm().expect("startup rearm");
        let after = lockdown_word(&store);
        assert_eq!(after.epoch, before.epoch);
        assert_ne!(
            after.flags & gedefense_common::LOCKDOWN_FLAG_DROP_ALL,
            0,
            "startup re-arm cleared the auto-drop"
        );
        assert_ne!(after.flags & gedefense_common::LOCKDOWN_FLAG_USB_LOCKED, 0);
        assert!(restarted.shared.auto_drop(), "auto-drop ownership was not re-established");
    }

    #[test]
    fn lockdown_auto_network_drop_is_released_by_an_explicit_net_phase_off() {        let root = lockdown_fixture("auto-drop-net-off");
        let store = std::sync::Arc::new(MemoryWordStore::new());
        let mut core = lockdown_core(&root, std::sync::Arc::clone(&store));
        lockdown_command_raw(&mut core, &["LOCKDOWN_ARM", "locked", "manual", "1"]).unwrap();
        core.shared.auto_network_drop().expect("auto drop write");
        assert_ne!(lockdown_word(&store).flags & gedefense_common::LOCKDOWN_FLAG_DROP_ALL, 0);
        assert_eq!(
            lockdown_command_raw(&mut core, &["LOCKDOWN_PHASE", "net", "off"]).unwrap(),
            "applied:net"
        );
        assert!(!core.shared.auto_drop(), "explicit NET off clears the auto-drop flag");
        assert_eq!(lockdown_word(&store).flags & gedefense_common::LOCKDOWN_FLAG_DROP_ALL, 0);
    }

    #[test]
    fn lockdown_auto_network_drop_is_cleared_by_clear() {
        let root = lockdown_fixture("auto-drop-clear");
        let store = std::sync::Arc::new(MemoryWordStore::new());
        let mut core = lockdown_core(&root, std::sync::Arc::clone(&store));
        lockdown_command_raw(&mut core, &["LOCKDOWN_ARM", "locked", "manual", "1"]).unwrap();
        core.shared.auto_network_drop().expect("auto drop write");
        assert!(core.shared.auto_drop());
        let epoch = format!("{:08x}", core.epoch());
        assert_eq!(
            lockdown_command_raw(&mut core, &["LOCKDOWN_CLEAR", &epoch, "manual"]).unwrap(),
            "cleared"
        );
        assert!(!core.shared.auto_drop(), "CLEAR releases the auto-drop flag");
        let word = lockdown_word(&store);
        assert_eq!(word.mode, gedefense_common::LOCKDOWN_MODE_OFF);
        assert_eq!(word.flags, 0, "CLEAR writes the OFF word");
    }

    #[test]
    fn lockdown_explicit_hardening_phase_covers_modules_disabled_only_on_request() {
        let root = lockdown_fixture("explicit-modules");
        let store = std::sync::Arc::new(MemoryWordStore::new());
        let mut core = lockdown_core(&root, std::sync::Arc::clone(&store));
        lockdown_command_raw(&mut core, &["LOCKDOWN_ARM", "locked", "manual", "8"]).unwrap();
        // Automatic trigger (hardening_apply flag) never writes modules_disabled.
        lockdown_command_raw(&mut core, &["LOCKDOWN_TRIGGER", "manual", "tamper", "8"]).unwrap();
        let modules = root.join("proc/sys/kernel/modules_disabled");
        assert_eq!(fs::read_to_string(&modules).unwrap().trim(), "0");
        assert_eq!(fs::read_to_string(root.join("proc/sys/kernel/kexec_load_disabled")).unwrap().trim(), "1");
        // A failing modules_disabled write makes the explicit phase fail visibly.
        fs::write(&modules, "7\n").unwrap();
        let response = lockdown_command_raw(&mut core, &["LOCKDOWN_PHASE", "hardening", "on"]).unwrap();
        assert!(response.starts_with("failed:hardening:"), "{response}");
        assert_eq!(core.state_text(), "degraded");
        // A writable knob is applied and verified by the explicit command.
        fs::write(&modules, "0\n").unwrap();
        assert_eq!(
            lockdown_command_raw(&mut core, &["LOCKDOWN_PHASE", "hardening", "on"]).unwrap(),
            "applied:hardening"
        );
        assert_eq!(fs::read_to_string(&modules).unwrap().trim(), "1");
    }

    #[test]
    fn lockdown_events_and_health_wire_formats_are_bounded() {
        let root = lockdown_fixture("events");
        let store = std::sync::Arc::new(MemoryWordStore::new());
        let mut core = lockdown_core_with(&root, std::sync::Arc::clone(&store), (7, 3));
        assert_eq!(lockdown_command_raw(&mut core, &["LOCKDOWN_HEALTH"]).unwrap(), "7:3:0:0:0:0");
        lockdown_command_raw(&mut core, &["LOCKDOWN_ARM", "locked", "manual", "1"]).unwrap();
        lockdown_command_raw(&mut core, &["LOCKDOWN_TRIGGER", "manual", "tamper", "1"]).unwrap();
        let events = lockdown_command_raw(&mut core, &["LOCKDOWN_EVENTS"]).unwrap();
        let (dropped, records) = events.split_once('|').expect("dropped|records");
        assert!(dropped.parse::<u64>().is_ok());
        let records: Vec<&str> = records.split(',').collect();
        assert!(!records.is_empty() && records.len() <= lockdown_uevent::EVENTS_PER_RESPONSE);
        let mut last_seq = 0u64;
        for record in records {
            let fields: Vec<&str> = record.split(':').collect();
            assert_eq!(fields.len(), 6, "{record}");
            for field in &fields {
                assert!(field.parse::<u64>().is_ok(), "{record}");
            }
            let seq = fields[0].parse::<u64>().unwrap();
            assert!(seq > last_seq, "sequences must increase");
            assert!(matches!(fields[5].parse::<u8>().unwrap(), 1..=5), "{record}");
            last_seq = seq;
        }
        // The queue drains: a second read is empty (no duplication/loss).
        assert_eq!(lockdown_command_raw(&mut core, &["LOCKDOWN_EVENTS"]).unwrap(), "empty");
        let health = lockdown_command_raw(&mut core, &["LOCKDOWN_HEALTH"]).unwrap();
        let values: Vec<&str> = health.split(':').collect();
        assert_eq!(values.len(), 6, "{health}");
        assert!(values.iter().all(|value| value.parse::<u64>().is_ok()));
        assert_eq!(lockdown_command_raw(&mut core, &["LOCKDOWN_HEALTH"]).unwrap().split(':').next(), Some("7"));
    }

    struct FakeUeventSource {
        queue: VecDeque<lockdown_uevent::Poll>,
    }

    impl lockdown_uevent::UeventSource for FakeUeventSource {
        fn next(&mut self) -> lockdown_uevent::Poll {
            self.queue.pop_front().unwrap_or(lockdown_uevent::Poll::Timeout)
        }
    }

    fn uevent_payload(devpath: &str, subsystem: &str) -> Vec<u8> {
        format!("add@{devpath}\0ACTION=add\0SUBSYSTEM={subsystem}\0DEVPATH={devpath}\0").into_bytes()
    }

    fn wait_for_word(store: &MemoryWordStore) -> u64 {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        while store.word() == 0 && std::time::Instant::now() < deadline {
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        store.word()
    }

    #[test]
    fn lockdown_uevent_loop_blocks_data_devices_and_drops_network() {
        let root = crate::lockdown_usb::tests::fixture("uevent-loop");
        let devpath = "/devices/pci0000:00/usb1/1-3";
        let dir = root.join("sys").join(devpath.trim_start_matches('/'));
        fs::create_dir_all(&dir).expect("uevent device");
        fs::write(dir.join("bDeviceClass"), "08\n").expect("class");
        fs::write(dir.join("bNumInterfaces"), "01\n").expect("interfaces");
        fs::write(dir.join("bNumConfigurations"), "01\n").expect("config");
        fs::write(dir.join("authorized"), "1\n").expect("authorized");
        let word = std::sync::Arc::new(MemoryWordStore::new());
        let shared_word: std::sync::Arc<dyn lockdown::LockdownWordStore> = word.clone();
        let shared = std::sync::Arc::new(LockdownShared::new(
            shared_word,
            UeventPolicy { arm: ArmMode::Locked, auto_network_drop: true, allow_loopback: true, epoch: 0x1234_5678 },
        ));
        let source = FakeUeventSource { queue: VecDeque::from([lockdown_uevent::Poll::Message(uevent_payload(devpath, "usb"))]) };
        let mut monitor = lockdown_uevent::start_with_source(
            Box::new(source),
            std::sync::Arc::clone(&shared),
            crate::lockdown_usb::UsbPaths::new(root.join("sys")),
        )
        .expect("uevent monitor thread");
        let persisted = wait_for_word(&word);
        monitor.stop();
        assert_ne!(persisted, 0, "auto_network_drop must write the kernel word");
        let decoded = gedefense_common::decode_lockdown_word(persisted).expect("drop word");
        assert_eq!(decoded.epoch, 0x1234_5678);
        assert_ne!(decoded.flags & gedefense_common::LOCKDOWN_FLAG_DROP_ALL, 0);
        assert_eq!(fs::read_to_string(dir.join("authorized")).unwrap().trim(), "0");
        let (uevents, usb_blocks, tb_blocks) = shared.uevent_counters();
        assert_eq!((uevents, usb_blocks, tb_blocks), (1, 1, 0));
        let (_dropped, records) = shared.take_events(lockdown_uevent::EVENTS_PER_RESPONSE);
        assert!(records.iter().any(|event| {
            event.phase == gedefense_common::LOCKDOWN_PHASE_USB
                && event.outcome == gedefense_common::LOCKDOWN_OUTCOME_APPLIED
                && event.source == gedefense_common::LOCKDOWN_SOURCE_UEVENT
        }));
    }

    #[test]
    fn lockdown_uevent_loop_never_blocks_power_only_or_audits_while_unlocked() {
        let root = crate::lockdown_usb::tests::fixture("uevent-audit");
        let devpath = "/devices/pci0000:00/usb1/1-4";
        let dir = root.join("sys").join(devpath.trim_start_matches('/'));
        fs::create_dir_all(&dir).expect("uevent device");
        fs::write(dir.join("bDeviceClass"), "00\n").expect("class");
        fs::write(dir.join("bNumInterfaces"), "00\n").expect("interfaces");
        fs::write(dir.join("bNumConfigurations"), "01\n").expect("config");
        // Power-only charger: no block, no word write (Lade-Kabel-DoS-Schutz).
        let word = std::sync::Arc::new(MemoryWordStore::new());
        let shared_word: std::sync::Arc<dyn lockdown::LockdownWordStore> = word.clone();
        let shared = std::sync::Arc::new(LockdownShared::new(
            shared_word,
            UeventPolicy { arm: ArmMode::Locked, auto_network_drop: true, allow_loopback: true, epoch: 9 },
        ));
        let source = FakeUeventSource { queue: VecDeque::from([lockdown_uevent::Poll::Message(uevent_payload(devpath, "usb"))]) };
        let mut monitor = lockdown_uevent::start_with_source(
            Box::new(source),
            std::sync::Arc::clone(&shared),
            crate::lockdown_usb::UsbPaths::new(root.join("sys")),
        )
        .expect("uevent monitor thread");
        std::thread::sleep(std::time::Duration::from_millis(60));
        monitor.stop();
        assert_eq!(word.word(), 0, "power-only device never triggers a drop");
        assert_eq!(shared.uevent_counters().1, 0);

        // Unlocked arm mode: audit only, nothing is written or blocked.
        let unlocked = std::sync::Arc::new(LockdownShared::new(
            std::sync::Arc::new(MemoryWordStore::new()),
            UeventPolicy { arm: ArmMode::Unlocked, auto_network_drop: true, allow_loopback: true, epoch: 9 },
        ));
        let source = FakeUeventSource { queue: VecDeque::from([lockdown_uevent::Poll::Message(uevent_payload(devpath, "usb"))]) };
        let mut monitor = lockdown_uevent::start_with_source(
            Box::new(source),
            std::sync::Arc::clone(&unlocked),
            crate::lockdown_usb::UsbPaths::new(root.join("sys")),
        )
        .expect("uevent monitor thread");
        std::thread::sleep(std::time::Duration::from_millis(60));
        monitor.stop();
        let (_dropped, records) = unlocked.take_events(lockdown_uevent::EVENTS_PER_RESPONSE);
        assert!(records.iter().any(|event| event.outcome == gedefense_common::LOCKDOWN_OUTCOME_SKIPPED));
    }

    #[test]
    fn lockdown_usb_uevent_device_paths_are_bounded_and_traversal_free() {
        let root = crate::lockdown_usb::tests::fixture("main-devpath");
        let paths = crate::lockdown_usb::UsbPaths::new(root.join("sys"));
        let dir = root.join("sys/devices/pci0000:00/usb1/1-1");
        fs::create_dir_all(&dir).expect("devpath fixture");
        fs::write(dir.join("bDeviceClass"), "08\n").expect("class");
        fs::write(dir.join("authorized"), "1\n").expect("authorized");
        assert_eq!(
            crate::lockdown_usb::apply_device(&paths, "/devices/pci0000:00/usb1/1-1"),
            Ok(crate::lockdown_usb::DevicePolicy::Block)
        );
        assert_eq!(fs::read_to_string(dir.join("authorized")).unwrap().trim(), "0");
        assert_eq!(crate::lockdown_usb::apply_device(&paths, "/devices/../etc/passwd"), Err("invalid-devpath"));
        assert_eq!(crate::lockdown_usb::apply_device(&paths, "/devices/absent"), Err("not-present"));
        assert_eq!(crate::lockdown_usb::apply_device(&paths, "relative/path"), Err("invalid-devpath"));
    }

    #[test]
    fn lockdown_usb_release_reauthorizes_and_missing_tree_is_unsupported() {
        let root = crate::lockdown_usb::tests::fixture("main-release");
        let paths = crate::lockdown_usb::UsbPaths::new(root.join("sys"));
        let storage = crate::lockdown_usb::tests::usb_device(&root, "1-3", "08", "01", "01", Some("0"));
        assert_eq!(crate::lockdown_usb::apply_usb(&paths).outcome, gedefense_common::LOCKDOWN_OUTCOME_APPLIED);
        assert_eq!(crate::lockdown_usb::release_usb(&paths).outcome, gedefense_common::LOCKDOWN_OUTCOME_APPLIED);
        assert_eq!(fs::read_to_string(storage.join("authorized")).unwrap().trim(), "1");
        let missing = crate::lockdown_usb::UsbPaths::new(root.join("absent"));
        let report = crate::lockdown_usb::apply_usb(&missing);
        assert_eq!(report.outcome, gedefense_common::LOCKDOWN_OUTCOME_UNSUPPORTED);
        assert_eq!(report.reason, "not-present");
        assert_eq!(crate::lockdown_usb::apply_tb(&missing).outcome, gedefense_common::LOCKDOWN_OUTCOME_UNSUPPORTED);
    }

    #[test]
    fn lockdown_modules_never_use_shell_or_kill_primitives() {
        // Adversarial guard for the "no shell, no kill" contract (§§1.1/6.4).
        for (name, source) in [
            ("lockdown.rs", include_str!("lockdown.rs")),
            ("lockdown_usb.rs", include_str!("lockdown_usb.rs")),
            ("lockdown_uevent.rs", include_str!("lockdown_uevent.rs")),
            ("lockdown_hardening.rs", include_str!("lockdown_hardening.rs")),
            ("lockdown_brokers.rs", include_str!("lockdown_brokers.rs")),
        ] {
            for forbidden in ["Command::new", "process::Command", "SIGKILL", "/bin/sh", "sh -c"] {
                assert!(!source.contains(forbidden), "{name} must not contain {forbidden}");
            }
        }
        let brokers = include_str!("lockdown_brokers.rs");
        assert!(brokers.contains("libc::SIGSTOP") && brokers.contains("libc::SIGCONT"));
    }
}
