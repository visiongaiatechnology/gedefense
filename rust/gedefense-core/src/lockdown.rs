//! Point 5 (§5/§6/§9): core lockdown state machine, persistence and re-arm.
//!
//! The crate-root ABI layer parses the §5 tokens and formats the answers; here
//! lives the typed state (arm mode, epoch, latch, per-phase outcomes, monitor).
//! Kernel word/net/monitor, USB/TB, hardening and broker helpers are further
//! `LockdownCore` methods in their modules, so every orchestration path enforces
//! through one code path and never upgrades an outcome. Startup re-arm applies
//! the persisted intent before IPC; a corrupt file latches `degraded`.

use crate::lockdown_brokers::BrokerFreezer;
use crate::lockdown_hardening::HardeningPaths;
use crate::lockdown_uevent::Monitor;
use crate::lockdown_usb::UsbPaths;
use crate::{ArmMode, LoadedPhase, LockdownShared, LockdownStateLoad, UeventPolicy};
use gedefense_common::{
    decode_lockdown_word, LockdownEvent, LOCKDOWN_FLAG_DROP_ALL, LOCKDOWN_OUTCOME_APPLIED,
    LOCKDOWN_OUTCOME_FAILED, LOCKDOWN_OUTCOME_PARTIAL, LOCKDOWN_OUTCOME_SKIPPED,
    LOCKDOWN_OUTCOME_UNSUPPORTED, LOCKDOWN_PHASE_BROKERS, LOCKDOWN_PHASE_CELLS,
    LOCKDOWN_PHASE_DM, LOCKDOWN_PHASE_HARDENING, LOCKDOWN_PHASE_INTENT, LOCKDOWN_PHASE_NET,
    LOCKDOWN_PHASE_SESSIONS, LOCKDOWN_PHASE_TB, LOCKDOWN_PHASE_USB, LOCKDOWN_REASON_POLICY,
    LOCKDOWN_SOURCE_MANUAL, LOCKDOWN_SOURCE_POLICY,
};
use std::{
    fs,
    path::{Path, PathBuf},
    sync::Arc,
};

/// §5 `LOCKDOWN_VERSION` payload.
pub(crate) const VERSION: &str = "lockdown-v1";
/// §5 state file path.
pub(crate) const DEFAULT_STATE_FILE: &str = "/var/lib/vgt/gedefense/LOCKDOWN.state";
pub(crate) const POLICY_AUTO_NETWORK_DROP: u8 = 1 << 0;
pub(crate) const POLICY_ALLOW_LOOPBACK: u8 = 1 << 1;
pub(crate) const POLICY_FREEZE_BROKERS: u8 = 1 << 2;
pub(crate) const POLICY_HARDENING_APPLY: u8 = 1 << 3;
pub(crate) const POLICY_FLAGS_KNOWN: u8 = POLICY_AUTO_NETWORK_DROP
    | POLICY_ALLOW_LOOPBACK
    | POLICY_FREEZE_BROKERS
    | POLICY_HARDENING_APPLY;
pub(crate) const DELEGATED: u8 = 0x80;
pub(crate) const REASON_SESSIONS: &str = "no-dbus-session-lock";
pub(crate) const REASON_DM: &str = "no-device-mapper";
pub(crate) const PHASE_COUNT: usize = LOCKDOWN_PHASE_DM as usize + 1;

/// Kernel `LOCKDOWN_STATE` access (eBPF map / test fake); writes verify.
pub(crate) trait LockdownWordStore: Send + Sync {
    fn write(&self, word: u64) -> Result<(), String>;
    fn read(&self) -> Result<u64, String>;
}

/// §5 health source: per-CPU sums of `LOCKDOWN_DROPS`/`WITNESS_PASSES`.
pub(crate) trait NetCounters: Send + Sync {
    fn net_counters(&self) -> Result<(u64, u64), String>;
}

#[derive(Clone, Debug)]
pub(crate) struct LockdownConfig {
    pub(crate) state_file: PathBuf,
    pub(crate) usb: UsbPaths,
    pub(crate) hardening: HardeningPaths,
    pub(crate) proc_root: PathBuf,
    pub(crate) monitors: bool,
}

impl Default for LockdownConfig {
    fn default() -> Self {
        Self {
            state_file: PathBuf::from(DEFAULT_STATE_FILE),
            usb: UsbPaths::system(),
            hardening: HardeningPaths::system(),
            proc_root: PathBuf::from("/proc"),
            monitors: true,
        }
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Latch {
    Off,
    Armed,
    Active,
}

/// §5 ARM result: first arm vs. idempotent repeat.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ArmOutcome {
    Armed(u32),
    Unchanged(u32),
}

/// §5 CLEAR result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ClearOutcome {
    Cleared,
    AlreadyOff,
}

/// §5 `LOCKDOWN_PHASE` result, formatted by the ABI layer in `main.rs`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PhaseOutcome {
    Applied,
    Unsupported(&'static str),
    Failed(&'static str),
}

pub(crate) struct LockdownCore {
    pub(crate) config: LockdownConfig,
    pub(crate) shared: Arc<LockdownShared>,
    pub(crate) net: Arc<dyn NetCounters>,
    pub(crate) brokers: BrokerFreezer,
    pub(crate) epoch: u32,
    pub(crate) arm_mode: ArmMode,
    pub(crate) policy: u8,
    pub(crate) latch: Latch,
    pub(crate) degraded: bool,
    pub(crate) phases: [u8; PHASE_COUNT],
    pub(crate) monitor: Option<Monitor>,
}

impl LockdownCore {
    pub(crate) fn new(
        config: LockdownConfig,
        word: Arc<dyn LockdownWordStore>,
        net: Arc<dyn NetCounters>,
    ) -> Result<Self, String> {
        let epoch = new_epoch(0)?;
        let shared = Arc::new(LockdownShared::new(
            word,
            UeventPolicy { arm: ArmMode::Unlocked, auto_network_drop: false, allow_loopback: true, epoch },
        ));
        Ok(Self {
            config,
            shared,
            net,
            brokers: BrokerFreezer::new(),
            epoch,
            arm_mode: ArmMode::Unlocked,
            policy: POLICY_ALLOW_LOOPBACK,
            latch: Latch::Off,
            degraded: false,
            phases: [0; PHASE_COUNT],
            monitor: None,
        })
    }

    pub(crate) fn version(&self) -> &'static str { VERSION }
    pub(crate) fn epoch(&self) -> u32 { self.epoch }
    pub(crate) fn arm_mode(&self) -> ArmMode { self.arm_mode }
    pub(crate) fn policy_flags(&self) -> u8 { self.policy }
    pub(crate) fn phase_outcome(&self, phase: u8) -> u8 { self.phases[phase as usize] }
    pub(crate) fn state_text(&self) -> &'static str {
        if self.degraded {
            "degraded"
        } else {
            match self.latch {
                Latch::Off => "off",
                Latch::Armed => "armed",
                Latch::Active => "active",
            }
        }
    }
    pub(crate) fn ping_suffix(&self) -> String { format!("+lockdown:{}", self.state_text()) }
    #[allow(dead_code)] // §6.4 honest status string, reported through health/phase
    pub(crate) fn broker_status(&self) -> &'static str {
        if self.brokers.frozen_count() > 0 {
            crate::lockdown_brokers::BROKER_STATUS
        } else {
            "unfrozen"
        }
    }
    /// §5 STATUS `flags`: the verified kernel state word, 0 if unreadable.
    pub(crate) fn word_flags(&self) -> u8 { self.shared.word_flags(self.epoch) }
    pub(crate) fn take_events(&self, max: usize) -> (u64, Vec<LockdownEvent>) { self.shared.take_events(max) }
    pub(crate) fn uevent_counters(&self) -> (u64, u64, u64) { self.shared.uevent_counters() }
    pub(crate) fn broker_frozen(&self) -> u64 { self.brokers.frozen_count() }
    pub(crate) fn net_counters(&self) -> Result<(u64, u64), String> { self.net.net_counters() }
    pub(crate) fn state_file(&self) -> &Path { &self.config.state_file }
    fn phase_result(outcome: u8, why: &'static str) -> PhaseOutcome {
        match outcome {
            LOCKDOWN_OUTCOME_APPLIED => PhaseOutcome::Applied,
            LOCKDOWN_OUTCOME_UNSUPPORTED => PhaseOutcome::Unsupported(why),
            LOCKDOWN_OUTCOME_PARTIAL => PhaseOutcome::Failed("partial"),
            _ => PhaseOutcome::Failed(why),
        }
    }

    /// §5 ARM: arms the policy without triggering enforcement (§6).
    pub(crate) fn arm(&mut self, mode: ArmMode, reason: u8, flags: u8) -> Result<ArmOutcome, String> {
        if flags & !POLICY_FLAGS_KNOWN != 0 {
            return Err("unknown lockdown policy flag".into());
        }
        if self.latch == Latch::Active {
            // ARM never touches an active latch; only CLEAR/PHASE may change it.
            self.emit(LOCKDOWN_SOURCE_MANUAL, reason, LOCKDOWN_PHASE_INTENT, LOCKDOWN_OUTCOME_APPLIED, 0);
            return Ok(ArmOutcome::Unchanged(self.epoch));
        }
        let unchanged = self.latch == Latch::Armed && self.arm_mode == mode && self.policy == flags;
        let previous = (self.arm_mode, self.policy);
        self.arm_mode = mode;
        self.policy = flags;
        if !unchanged {
            if let Err(error) = self.write_word_verified(LOCKDOWN_STATE_ARMED, 0) {
                // No partial change: an unverified arm keeps the old state.
                self.arm_mode = previous.0;
                self.policy = previous.1;
                return Err(error.to_owned());
            }
            self.latch = Latch::Armed;
        }
        self.sync_policy();
        if self.ensure_monitor().is_err() {
            self.emit(LOCKDOWN_SOURCE_MANUAL, reason, LOCKDOWN_PHASE_USB, LOCKDOWN_OUTCOME_UNSUPPORTED, 0);
        }
        self.persist();
        self.emit(LOCKDOWN_SOURCE_MANUAL, reason, LOCKDOWN_PHASE_INTENT, LOCKDOWN_OUTCOME_APPLIED, 0);
        Ok(if unchanged { ArmOutcome::Unchanged(self.epoch) } else { ArmOutcome::Armed(self.epoch) })
    }

    /// §5 SET_MODE: changes only the arm mode, never triggers.
    pub(crate) fn set_mode(&mut self, mode: ArmMode) -> Result<(), String> {
        if self.latch == Latch::Off {
            self.write_word_verified(LOCKDOWN_STATE_ARMED, 0).map_err(str::to_owned)?;
            self.latch = Latch::Armed;
        }
        self.arm_mode = mode;
        self.sync_policy();
        if self.ensure_monitor().is_err() {
            self.degraded = true;
        }
        self.persist();
        Ok(())
    }

    /// One §6 phase: the single path used by trigger, re-arm and operator.
    fn apply_phase(&mut self, phase: u8) -> (u8, &'static str) {
        match phase {
            LOCKDOWN_PHASE_NET => self.net_phase(),
            LOCKDOWN_PHASE_USB => self.usb_phase(false),
            LOCKDOWN_PHASE_TB => self.usb_phase(true),
            LOCKDOWN_PHASE_HARDENING => self.hardening_phase(false),
            LOCKDOWN_PHASE_BROKERS => self.broker_phase(),
            LOCKDOWN_PHASE_CELLS => (DELEGATED, "delegated-to-control"),
            LOCKDOWN_PHASE_SESSIONS => (LOCKDOWN_OUTCOME_UNSUPPORTED, REASON_SESSIONS),
            LOCKDOWN_PHASE_DM => (LOCKDOWN_OUTCOME_UNSUPPORTED, REASON_DM),
            _ => (LOCKDOWN_OUTCOME_UNSUPPORTED, "not-an-operator-phase"),
        }
    }

    /// §5/§6 TRIGGER: new epoch, every phase in order; failures degrade.
    pub(crate) fn trigger(&mut self, source: u8, reason: u8, flags: u8) -> Result<u32, String> {
        if flags & !POLICY_FLAGS_KNOWN != 0 {
            return Err("unknown lockdown policy flag".into());
        }
        self.epoch = new_epoch(self.epoch)?;
        // A new epoch invalidates any hotplug auto-drop of the previous epoch;
        // the phase loop below owns the flag bits from here on.
        self.shared.clear_auto_drop();
        self.policy = flags;
        self.latch = Latch::Active;
        self.degraded = false;
        self.phases = [0; PHASE_COUNT];
        self.sync_policy();
        self.phases[LOCKDOWN_PHASE_INTENT as usize] = LOCKDOWN_OUTCOME_APPLIED;
        self.emit(source, reason, LOCKDOWN_PHASE_INTENT, LOCKDOWN_OUTCOME_APPLIED, 0);
        if self.ensure_monitor().is_err() {
            self.emit(source, reason, LOCKDOWN_PHASE_USB, LOCKDOWN_OUTCOME_UNSUPPORTED, 0);
        }
        for phase in [LOCKDOWN_PHASE_NET, LOCKDOWN_PHASE_USB, LOCKDOWN_PHASE_TB, LOCKDOWN_PHASE_HARDENING, LOCKDOWN_PHASE_BROKERS] {
            let enabled = match phase {
                LOCKDOWN_PHASE_HARDENING => self.policy & POLICY_HARDENING_APPLY != 0,
                LOCKDOWN_PHASE_BROKERS => self.policy & POLICY_FREEZE_BROKERS != 0,
                _ => true,
            };
            let (outcome, _) = if enabled {
                self.apply_phase(phase)
            } else {
                (LOCKDOWN_OUTCOME_SKIPPED, "not-requested")
            };
            self.phases[phase as usize] = outcome;
            if matches!(outcome, LOCKDOWN_OUTCOME_FAILED | LOCKDOWN_OUTCOME_PARTIAL) {
                self.degraded = true;
            }
            self.emit(source, reason, phase, outcome, 0);
        }
        // USB/TB/hardening flags must land in the word once their phase applied.
        if let Err(error) = self.refresh_word() {
            self.degraded = true;
            self.emit(source, reason, LOCKDOWN_PHASE_NET, LOCKDOWN_OUTCOME_PARTIAL, error.len() as u64);
        }
        self.phases[LOCKDOWN_PHASE_CELLS as usize] = DELEGATED;
        self.emit(source, reason, LOCKDOWN_PHASE_CELLS, LOCKDOWN_OUTCOME_SKIPPED, 0);
        for phase in [LOCKDOWN_PHASE_SESSIONS, LOCKDOWN_PHASE_DM] {
            self.phases[phase as usize] = LOCKDOWN_OUTCOME_UNSUPPORTED;
            self.emit(source, reason, phase, LOCKDOWN_OUTCOME_UNSUPPORTED, 0);
        }
        self.sync_policy();
        self.persist();
        Ok(self.epoch)
    }

    /// §5 CLEAR: epoch compare-set, then reversible release and word OFF.
    pub(crate) fn clear(&mut self, expected_epoch: u32, reason: u8) -> Result<ClearOutcome, String> {
        if expected_epoch != self.epoch {
            return Err("lockdown epoch mismatch".into());
        }
        if self.latch == Latch::Off {
            return Ok(ClearOutcome::AlreadyOff);
        }
        self.stop_monitor();
        let mut release_failed = false;
        // Partial phases may already have blocked/frozen entries: release them.
        if matches!(self.phases[LOCKDOWN_PHASE_USB as usize], LOCKDOWN_OUTCOME_APPLIED | LOCKDOWN_OUTCOME_PARTIAL) {
            release_failed |= self.usb_release(false).0 != LOCKDOWN_OUTCOME_APPLIED;
        }
        if matches!(self.phases[LOCKDOWN_PHASE_TB as usize], LOCKDOWN_OUTCOME_APPLIED | LOCKDOWN_OUTCOME_PARTIAL) {
            release_failed |= self.usb_release(true).0 != LOCKDOWN_OUTCOME_APPLIED;
        }
        if matches!(self.phases[LOCKDOWN_PHASE_BROKERS as usize], LOCKDOWN_OUTCOME_APPLIED | LOCKDOWN_OUTCOME_PARTIAL) {
            release_failed |= self.broker_release().0 == LOCKDOWN_OUTCOME_FAILED;
        }
        // Kernel enforcement ends before the latch is released; a failed write
        // stays an error and leaves the stored latch untouched.
        self.write_word_verified(LOCKDOWN_STATE_OFF, 0).map_err(str::to_owned)?;
        // The kernel word is off and verified: the hotplug auto-drop is gone.
        self.shared.clear_auto_drop();
        self.latch = Latch::Off;
        self.phases = [0; PHASE_COUNT];
        self.degraded = release_failed;
        if self.remove_state_file().is_err() {
            // Never leave an active-looking file behind: rewrite the cleared
            // (armed, no phases) shape so a restart cannot re-drop silently.
            self.degraded = true;
            self.persist();
        }
        self.emit(LOCKDOWN_SOURCE_MANUAL, reason, LOCKDOWN_PHASE_INTENT, LOCKDOWN_OUTCOME_APPLIED, 0);
        Ok(ClearOutcome::Cleared)
    }

    /// §5 LOCKDOWN_PHASE: one phase for operator tests, idempotent and honest.
    pub(crate) fn phase(&mut self, phase: u8, on: bool) -> Result<PhaseOutcome, String> {
        if phase as usize >= PHASE_COUNT {
            return Err("unknown lockdown phase".into());
        }
        if phase == LOCKDOWN_PHASE_INTENT || phase == LOCKDOWN_PHASE_CELLS {
            return Ok(PhaseOutcome::Unsupported(if phase == LOCKDOWN_PHASE_CELLS {
                "delegated-to-control"
            } else {
                "not-an-operator-phase"
            }));
        }
        if phase == LOCKDOWN_PHASE_SESSIONS {
            return Ok(PhaseOutcome::Unsupported(REASON_SESSIONS));
        }
        if phase == LOCKDOWN_PHASE_DM {
            return Ok(PhaseOutcome::Unsupported(REASON_DM));
        }
        if !on {
            return Ok(self.release_phase(phase));
        }
        if self.latch == Latch::Off {
            return Ok(PhaseOutcome::Failed("not-armed"));
        }
        let (outcome, why) = match phase {
            // Explicit operator single-phase command: modules_disabled may be
            // set here (the automatic trigger path never touches it).
            LOCKDOWN_PHASE_HARDENING => self.hardening_phase(true),
            _ => self.apply_phase(phase),
        };
        self.phases[phase as usize] = outcome;
        if outcome == LOCKDOWN_OUTCOME_APPLIED {
            if self.latch == Latch::Armed {
                self.latch = Latch::Active;
            }
            if let Err(error) = self.refresh_word() {
                self.degraded = true;
                return Ok(PhaseOutcome::Failed(error));
            }
        } else {
            self.degraded = true;
        }
        self.emit(LOCKDOWN_SOURCE_MANUAL, LOCKDOWN_REASON_POLICY, phase, outcome, 0);
        self.persist();
        Ok(Self::phase_result(outcome, why))
    }

    fn release_phase(&mut self, phase: u8) -> PhaseOutcome {
        let (outcome, why) = match phase {
            LOCKDOWN_PHASE_NET => {
                // An explicit NET release also releases a hotplug auto-drop.
                self.phases[phase as usize] = 0;
                self.shared.clear_auto_drop();
                match self.refresh_word() {
                    Ok(()) => (LOCKDOWN_OUTCOME_APPLIED, "applied"),
                    Err(error) => (LOCKDOWN_OUTCOME_FAILED, error),
                }
            }
            LOCKDOWN_PHASE_USB => self.usb_release(false),
            LOCKDOWN_PHASE_TB => self.usb_release(true),
            LOCKDOWN_PHASE_BROKERS => self.broker_release(),
            // kexec_load_disabled/sysrq/modules_disabled cannot be unset before
            // a reboot: the clear path never pretends a rollback happened.
            _ => (LOCKDOWN_OUTCOME_UNSUPPORTED, "irreversible-until-reboot"),
        };
        if outcome == LOCKDOWN_OUTCOME_APPLIED {
            self.phases[phase as usize] = 0;
            let _ = self.refresh_word();
        }
        self.emit(LOCKDOWN_SOURCE_MANUAL, LOCKDOWN_REASON_POLICY, phase, outcome, 0);
        self.persist();
        Self::phase_result(outcome, why)
    }

    /// Startup re-arm (§5): applies the persisted intent before IPC is ready.
    pub(crate) fn startup_rearm(&mut self) -> Result<String, String> {
        match crate::load_lockdown_state(&self.config.state_file) {
            LockdownStateLoad::Absent => {
                if self.write_word_verified(LOCKDOWN_STATE_OFF, 0).is_err() {
                    self.degraded = true;
                }
                Ok(self.state_text().to_owned())
            }
            LockdownStateLoad::Corrupt => {
                // Fail-closed latch, but no enforcement action without a verify.
                self.degraded = true;
                self.latch = Latch::Active;
                self.sync_policy();
                self.emit(LOCKDOWN_SOURCE_POLICY, LOCKDOWN_REASON_POLICY, LOCKDOWN_PHASE_INTENT, LOCKDOWN_OUTCOME_FAILED, 0);
                Ok("degraded".to_owned())
            }
            LockdownStateLoad::Valid(state) => {
                self.epoch = state.epoch;
                self.arm_mode = state.mode;
                self.policy = state.flags;
                let persisted: Vec<u8> = state.phases.iter().map(|phase| phase.phase).collect();
                self.phases = [0; PHASE_COUNT];
                // FIND-003: a verified DROP_ALL left in the kernel word by an
                // auto-drop must survive startup re-arm, not be cleared by the
                // phase refresh below. Only a word of this epoch and mode counts.
                let previous = self.shared.word.read().ok().and_then(decode_lockdown_word);
                if previous.is_some_and(|word| {
                    word.epoch == self.epoch
                        && word.mode == LOCKDOWN_STATE_ARMED
                        && word.flags & LOCKDOWN_FLAG_DROP_ALL != 0
                }) {
                    self.shared.mark_auto_drop();
                }
                let active = persisted.iter().any(|phase| *phase != LOCKDOWN_PHASE_INTENT);
                self.latch = if active { Latch::Active } else { Latch::Armed };
                self.sync_policy();
                if active {
                    // Re-apply in contract order and claim only verified phases:
                    // the flag bits never run ahead of the kernel read-back.
                    for phase in [LOCKDOWN_PHASE_NET, LOCKDOWN_PHASE_USB, LOCKDOWN_PHASE_TB, LOCKDOWN_PHASE_HARDENING, LOCKDOWN_PHASE_BROKERS] {
                        if !persisted.contains(&phase) {
                            continue;
                        }
                        let (outcome, _) = self.apply_phase(phase);
                        if outcome == LOCKDOWN_OUTCOME_APPLIED {
                            self.phases[phase as usize] = outcome;
                        } else {
                            self.degraded = true;
                            eprintln!("lockdown re-arm: phase {phase} outcome {outcome}; latched degraded");
                        }
                        self.emit(LOCKDOWN_SOURCE_POLICY, LOCKDOWN_REASON_POLICY, phase, outcome, 0);
                        if let Err(error) = self.refresh_word() {
                            self.degraded = true;
                            eprintln!("lockdown re-arm: word verify failed ({error}); latched degraded");
                        }
                    }
                }
                if self.config.monitors {
                    let _ = self.ensure_monitor();
                }
                self.persist();
                Ok(self.state_text().to_owned())
            }
        }
    }

    fn persist(&self) {
        if let Err(error) = crate::persist_lockdown_state(self) {
            eprintln!("lockdown state file update failed: {error}");
        }
    }

    fn remove_state_file(&self) -> Result<(), String> {
        match fs::remove_file(&self.config.state_file) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(_) => Err("lockdown state file reset failed".into()),
        }
    }

    /// Persisted applied-phase list for `epoch|mode|flags|phases|ts`.
    pub(crate) fn applied_phases(&self) -> Vec<LoadedPhase> {
        (0..PHASE_COUNT as u8)
            .filter(|phase| *phase != LOCKDOWN_PHASE_INTENT && self.phases[*phase as usize] == LOCKDOWN_OUTCOME_APPLIED)
            .map(|phase| LoadedPhase { phase })
            .collect()
    }
}

const LOCKDOWN_STATE_OFF: u8 = gedefense_common::LOCKDOWN_MODE_OFF;
const LOCKDOWN_STATE_ARMED: u8 = gedefense_common::LOCKDOWN_MODE_ARMED;
/// New non-zero epoch, guaranteed different from `previous` on a trigger.
fn new_epoch(previous: u32) -> Result<u32, String> {
    for _ in 0..4 {
        let (word, _) = crate::random_epoch_word().map_err(|error| error.to_string())?;
        let epoch = word as u32;
        if epoch != 0 && epoch != previous {
            return Ok(epoch);
        }
    }
    Ok(if previous == u32::MAX { 1 } else { previous.saturating_add(1) })
}
