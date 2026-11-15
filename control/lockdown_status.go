// SPDX-FileCopyrightText: 2026 VisionGaia Technology
// SPDX-License-Identifier: AGPL-3.0-only

package main

// POINT 5 / P5-T3: the bounded lockdown status projection and the audit/event
// helpers. The projection performs no core, helper or filesystem I/O, so an
// authenticated GET is always cheap and a slow phase can never block it. The
// kernel projection is only ever replaced by a phase result or a bounded poll.

import (
	"errors"
)

// ---------------------------------------------------------------- projection

// StatusView is the bounded, secret-free status projection. It performs no core,
// helper or filesystem I/O, so an authenticated GET is always cheap.
func (e *LockdownEngine) StatusView() LockdownStatusView {
	e.stateMu.RLock()
	defer e.stateMu.RUnlock()
	return e.statusViewLocked()
}

func (e *LockdownEngine) statusViewLocked() LockdownStatusView {
	settings := e.effectiveSettings()
	view := LockdownStatusView{
		Enabled: settings.Enabled, State: e.doc.State, Latched: e.doc.Latched,
		Mode: e.doc.Mode, Epoch: e.doc.Epoch,
		Armed:    e.doc.State == lockdownStateArmed || e.doc.State == lockdownStateActive || e.doc.State == lockdownStateTriggering,
		Settings: lockdownSettingsView(settings),
		// The evidence and persistence health of the engine is a fact, not a
		// phase result; it is reported separately so a degraded audit path cannot
		// look like a failed isolation.
		Evidence:            "healthy",
		DuressConfigured:    settings.DuressTokenPath != "",
		PendingSources:      e.pendingSourceCountLocked(),
		FalsePositiveGuards: e.falsePositiveGuards,
		DroppedCoreEvents:   e.droppedEvents,
		UpdatedAt:           e.doc.UpdatedAt,
		Phases:              append([]LockdownPhaseView{}, e.doc.Phases...),
		Trigger:             lockdownTriggerView(e.doc.Trigger),
		LastClear:           e.doc.LastClear,
	}
	if e.doc.Phases == nil {
		view.Phases = []LockdownPhaseView{}
	}
	view.Core = LockdownCoreView{
		Capability: e.coreCapability, State: e.coreState, Epoch: e.coreEpoch,
		Flags: e.coreFlags, Applied: append([]string{}, e.coreApplied...),
		Unsupported: append([]string{}, e.coreUnsupported...), Health: e.coreHealth,
		LastError: lockdownReasonText(e.coreLastErr),
	}
	if !e.coreHealthAt.IsZero() {
		at := e.coreHealthAt
		view.Core.PolledAt = &at
	}
	view.Cooldown = LockdownCooldownView{Seconds: settings.CooldownSeconds}
	if !e.lastAutomaticAt.IsZero() {
		at := e.lastAutomaticAt
		view.Cooldown.LastAutomaticAt = &at
		remaining := settings.CooldownSeconds - int(e.now().Sub(e.lastAutomaticAt).Seconds())
		if remaining > 0 {
			view.Cooldown.Active = true
			view.Cooldown.RemainingSeconds = remaining
		}
	}
	if e.corrupt {
		view.Evidence = "degraded"
		view.Degraded = "the persisted latch document could not be trusted and the engine latched fail-closed"
	}
	if e.persistErr != "" {
		view.Evidence = "degraded"
		view.Degraded = lockdownReasonText(e.persistErr)
	}
	if e.evidenceErr != "" {
		view.Evidence = "degraded"
		if view.Degraded == "" {
			view.Degraded = "audit evidence is unavailable; isolation phases are not claimed"
		}
	}
	if e.state == nil || e.state.EvidenceLedger() == nil {
		// A platform without the mandatory ledger is already degraded; the lockdown
		// status must not present that as a healthy audit path.
		view.Evidence = "unavailable"
		if view.Degraded == "" {
			view.Degraded = "no evidence ledger is attached; isolation phases would not run"
		}
	}
	if e.coreLastErr != "" && view.Degraded == "" {
		view.Degraded = "kernel phase projection: " + lockdownReasonText(e.coreLastErr)
	}
	if e.coreState == "degraded" {
		// The core latches a degraded state when a phase failed/partial or the
		// re-arm read-back failed. The Go latch stays authoritative, but the
		// operator must see that the kernel side is not cleanly applied.
		view.Evidence = "degraded"
		if view.Degraded == "" {
			view.Degraded = "the core reports the kernel lockdown state as degraded; the phase set is not cleanly applied"
		}
	}
	return view
}

func lockdownTriggerView(trigger *lockdownTriggerState) *LockdownTriggerView {
	if trigger == nil {
		return nil
	}
	return &LockdownTriggerView{
		Source: trigger.Source, Reason: trigger.Reason, Mode: trigger.Mode,
		At: trigger.At, Epoch: trigger.Epoch, Fingerprint: trigger.Fingerprint,
		Incident: trigger.Incident, Operator: trigger.Operator,
	}
}

func (e *LockdownEngine) pendingSourceCountLocked() int {
	count := 0
	now := e.now()
	for source, at := range e.pendingSources {
		if now.Sub(at) > lockdownSourceCorrelationWindow {
			delete(e.pendingSources, source)
			continue
		}
		count++
	}
	return count
}

func lockdownReasonText(value string) string {
	return lockdownTruncateText(value, lockdownMaxPhaseDetailBytes)
}

// ------------------------------------------------------------ evidence/events

// recordEvidence commits one record. A missing ledger is reported to the caller
// so the phase orchestration can refuse to isolate without an audit trail; a
// present-but-failing ledger is recorded as degraded and also returned.
func (e *LockdownEngine) recordEvidence(severity, kind, message, target string) error {
	if e.state == nil {
		e.setEvidenceErr("no state is attached")
		return errors.New("no evidence subsystem is attached")
	}
	if e.state.EvidenceLedger() == nil {
		e.setEvidenceErr("evidence ledger is not attached")
		return errors.New("evidence ledger is not attached")
	}
	err := e.state.RecordEvidence(EvidenceRecord{
		Severity: severity, Kind: kind, Source: "lockdown", Message: message, Target: target,
	})
	if err != nil {
		e.setEvidenceErr("evidence commit failed: " + lockdownReasonText(err.Error()))
	}
	return err
}

func (e *LockdownEngine) setEvidenceErr(reason string) {
	e.stateMu.Lock()
	e.evidenceErr = lockdownReasonText(reason)
	e.stateMu.Unlock()
}

func (e *LockdownEngine) addEvent(severity, kind, message string) {
	if e.state == nil {
		return
	}
	e.state.AddEvent(Event{Severity: severity, Kind: kind, Source: "lockdown", Message: message})
}

// lockedMode returns the persisted arm mode.
func (e *LockdownEngine) lockedMode() string {
	e.stateMu.RLock()
	defer e.stateMu.RUnlock()
	return e.doc.Mode
}

// setCoreStatus projects a bounded LOCKDOWN_STATUS answer. It is called by the
// maintenance loop, never by a status request.
func (e *LockdownEngine) setCoreStatus(status CoreLockdownStatus, err error) {
	e.stateMu.Lock()
	defer e.stateMu.Unlock()
	e.corePollAt = e.now()
	if err != nil {
		if errors.Is(err, ErrLockdownUnavailable) {
			e.coreCapability = "missing"
		} else {
			e.coreCapability = "unavailable"
		}
		e.coreLastErr = lockdownReasonText(err.Error())
		return
	}
	e.coreCapability = "available"
	e.coreState = status.State
	e.coreEpoch = status.Epoch
	e.coreFlags = status.Flags
	e.coreApplied = append([]string{}, status.Applied...)
	e.coreUnsupported = append([]string{}, status.Unsupported...)
	e.coreLastErr = ""
	// A core restart mints a new epoch and re-arms from its own state file. While the
	// Go latch is held, the visible epoch follows the kernel so the operator's
	// compare-set clear names the epoch that is actually in force.
	if e.doc.Latched && (status.State == lockdownStateActive || status.State == lockdownStateArmed) &&
		validLockdownEpoch(status.Epoch) && status.Epoch != e.doc.Epoch {
		e.doc.Epoch = status.Epoch
	}
}

func (e *LockdownEngine) setCoreHealth(health CoreLockdownHealth, err error) {
	e.stateMu.Lock()
	defer e.stateMu.Unlock()
	if err != nil {
		e.coreLastErr = lockdownReasonText(err.Error())
		return
	}
	snapshot := health
	e.coreHealth = &snapshot
	e.coreHealthAt = e.now()
	e.coreLastErr = ""
}
