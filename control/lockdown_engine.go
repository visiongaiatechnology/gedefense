// SPDX-FileCopyrightText: 2026 VisionGaia Technology
// SPDX-License-Identifier: AGPL-3.0-only

package main

// POINT 5 / P5-T3: the lockdown engine projection and the operator operations
// (arm, trigger, clear). This file is split out of lockdown.go so every
// lockdown source file stays within the documented 500-line budget.

import (
	"errors"
	"fmt"
	"strings"
)

// ---------------------------------------------------------------- operations

// Arm applies the administrable arm mode. It requires a reachable core: arming
// without the kernel would be exactly the attrappe §9 forbids.
func (e *LockdownEngine) Arm(mode, reasonToken, reasonText, requestID string) (LockdownStatusView, error) {
	settings := e.effectiveSettings()
	if !settings.Enabled {
		return e.StatusView(), errLockdownDisabled
	}
	if _, err := lockdownModeToken(mode); err != nil {
		return e.StatusView(), err
	}
	if _, err := lockdownReasonToken(reasonToken); err != nil {
		return e.StatusView(), err
	}
	e.opsMu.Lock()
	defer e.opsMu.Unlock()
	e.stateMu.RLock()
	latched := e.doc.Latched
	state := e.doc.State
	e.stateMu.RUnlock()
	if latched || state == lockdownStateActive || state == lockdownStateTriggering || state == lockdownStateClearing {
		return e.StatusView(), errLockdownLatched
	}
	if e.core == nil {
		return e.StatusView(), errLockdownCoreUnavailable
	}
	flags := lockdownCoreFlags(settings)
	epoch, err := e.core.LockdownArm(mode, reasonToken, flags)
	if err != nil {
		e.setCoreStatus(CoreLockdownStatus{}, err)
		if errors.Is(err, ErrLockdownUnavailable) {
			return e.StatusView(), errLockdownCapabilityMiss
		}
		return e.StatusView(), fmt.Errorf("%w: %v", errLockdownCoreUnavailable, err)
	}
	e.stateMu.Lock()
	e.doc.State = lockdownStateArmed
	e.doc.Mode = mode
	e.doc.Epoch = epoch
	e.doc.LastError = ""
	persistErr := e.persistLocked()
	e.stateMu.Unlock()
	if persistErr != nil {
		e.addEvent("critical", "lockdown.state.persist_failed",
			"Lockdown arm mode could not be persisted; the kernel holds it until the next restart")
	}
	e.stateMu.Lock()
	e.coreCapability = "available"
	e.coreState = lockdownStateArmed
	e.coreEpoch = epoch
	e.coreFlags = flags
	e.stateMu.Unlock()
	e.addEvent("high", "lockdown.armed", fmt.Sprintf("Kernel lockdown arm mode set to %s (epoch %s)", mode, epoch))
	_ = e.recordEvidence("high", "lockdown.arm",
		"Operator set the kernel lockdown arm mode to "+mode+" ("+lockdownReasonText(reasonText)+")",
		"epoch:"+epoch+" request:"+lockdownReasonText(requestID))
	return e.StatusView(), nil
}

// Trigger latches the engine and runs the documented phase order. It is
// idempotent while latched: a second trigger never re-executes phases.
func (e *LockdownEngine) Trigger(candidate lockdownTriggerCandidate) (LockdownStatusView, error) {
	settings := e.effectiveSettings()
	if !settings.Enabled {
		return e.StatusView(), errLockdownDisabled
	}
	if candidate.Source == "" {
		candidate.Source = lockdownSourceManual
	}
	if candidate.Reason == "" {
		candidate.Reason = lockdownReasonManual
	}
	if _, err := lockdownSourceToken(candidate.Source); err != nil {
		return e.StatusView(), err
	}
	if _, err := lockdownReasonToken(candidate.Reason); err != nil {
		return e.StatusView(), err
	}
	if !candidate.Operator {
		if err := e.applyTriggerGuards(settings, candidate); err != nil {
			return e.StatusView(), err
		}
	}
	return e.startTrigger(settings, candidate)
}

func (e *LockdownEngine) startTrigger(settings LockdownFabricSettings, candidate lockdownTriggerCandidate) (LockdownStatusView, error) {
	e.opsMu.Lock()
	defer e.opsMu.Unlock()
	e.stateMu.Lock()
	if e.doc.Latched || e.doc.State == lockdownStateActive || e.doc.State == lockdownStateTriggering || e.doc.State == lockdownStateClearing {
		view := e.statusViewLocked()
		e.stateMu.Unlock()
		return view, nil
	}
	epoch := e.newEpoch()
	e.doc.State = lockdownStateTriggering
	e.doc.Latched = true
	e.doc.Epoch = epoch
	e.doc.Trigger = &lockdownTriggerState{
		Source: candidate.Source, Reason: candidate.Reason, Mode: e.doc.Mode,
		Fingerprint: candidate.Fingerprint, Incident: candidate.Incident,
		At: e.now(), Epoch: epoch, Operator: candidate.Operator,
	}
	e.doc.Phases = nil
	e.doc.LastError = ""
	persistErr := e.persistLocked()
	e.stateMu.Unlock()
	if persistErr != nil {
		// The in-memory latch stays; the operator sees the critical event. This is
		// the fail-closed direction: a lost document re-latches on restart.
		e.addEvent("critical", "lockdown.state.persist_failed",
			"Lockdown latch could not be persisted; it remains active in memory and re-latches on restart")
	}
	intentTarget := "epoch:" + epoch + " source:" + candidate.Source + " reason:" + candidate.Reason
	intentErr := e.recordEvidence("critical", "lockdown.trigger.intent",
		"Emergency lockdown trigger accepted; isolation phases run only after this intent is committed",
		intentTarget)
	var phases []LockdownPhaseView
	var cellTransactions []string
	if intentErr != nil {
		// §9: phases without intent evidence are not started. The latch stays
		// fail-closed and the status says why nothing is enforced.
		phases = []LockdownPhaseView{{
			Phase: "evidence", Status: lockdownPhaseFailed,
			Detail: "evidence intent could not be committed; no isolation phase was started",
		}}
	} else {
		phases, cellTransactions = e.runPhases(settings, candidate)
	}
	e.stateMu.Lock()
	e.doc.State = lockdownStateActive
	e.doc.Latched = true
	e.doc.Phases = phases
	e.doc.CellTransactions = cellTransactions
	// A frozen process is persisted with its starttime identity so the operator
	// clear can resume exactly that process; the core refuses a recycled PID.
	if e.processPhaseApplied(candidate.PID, phases) {
		e.doc.Trigger.ProcessPID = candidate.PID
		e.doc.Trigger.ProcessStartTicks = candidate.StartTicks
	}
	// The core mints the authoritative epoch on every trigger (§5). The locally
	// minted epoch only covers the window in which the core could not answer; it is
	// replaced here so the operator's clear carries the value the kernel holds.
	if e.coreEpoch != "" && validLockdownEpoch(e.coreEpoch) {
		e.doc.Epoch = e.coreEpoch
	}
	if e.coreCapability != "" {
		e.doc.CoreCapability = e.coreCapability
	}
	if intentErr != nil {
		e.doc.LastError = "evidence unavailable"
	}
	persistErr = e.persistLocked()
	view := e.statusViewLocked()
	e.stateMu.Unlock()
	if persistErr != nil {
		e.addEvent("critical", "lockdown.state.persist_failed",
			"Lockdown latch could not be persisted after the phase run")
	}
	summary := lockdownPhaseSummary(phases)
	outcome := fmt.Sprintf("Emergency lockdown latched (epoch %s): %s. Clear requires an authenticated operator with the matching epoch.", epoch, summary)
	e.addEvent("critical", "lockdown.triggered", outcome)
	_ = e.recordEvidence("critical", "lockdown.trigger.outcome", outcome, intentTarget)
	for _, phase := range phases {
		if phase.Status == lockdownPhaseFailed || phase.Status == lockdownPhasePartial {
			_ = e.recordEvidence("high", "lockdown.phase."+phase.Phase,
				fmt.Sprintf("Lockdown phase %s: %s", phase.Phase, phase.Status), lockdownReasonText(phase.Detail))
		}
	}
	if !candidate.Operator {
		e.stateMu.Lock()
		e.lastAutomaticAt = e.now()
		e.stateMu.Unlock()
	}
	return view, nil
}

// Clear releases the latch. It is operator-only (the API enforces
// authentication, replay and the confirmation phrase) and requires the exact
// expected epoch: a mismatch leaves the engine latched (§7, §9).
func (e *LockdownEngine) Clear(expectedEpoch, reasonToken, reasonText, requestID string) (LockdownStatusView, error) {
	if !validLockdownEpoch(expectedEpoch) {
		return e.StatusView(), errLockdownEpochMismatch
	}
	if _, err := lockdownReasonToken(reasonToken); err != nil {
		return e.StatusView(), err
	}
	e.opsMu.Lock()
	defer e.opsMu.Unlock()
	settings := e.effectiveSettings()
	e.stateMu.RLock()
	latched := e.doc.Latched
	epoch := e.doc.Epoch
	coreCapability := e.coreCapability
	coreState := e.coreState
	cellTransactions := append([]string(nil), e.doc.CellTransactions...)
	processPID, processStartTicks := 0, uint64(0)
	if e.doc.Trigger != nil {
		processPID, processStartTicks = e.doc.Trigger.ProcessPID, e.doc.Trigger.ProcessStartTicks
	}
	e.stateMu.RUnlock()
	if !latched {
		return e.StatusView(), errLockdownNotLatched
	}
	if !validLockdownEpoch(epoch) || expectedEpoch != epoch {
		return e.StatusView(), errLockdownEpochMismatch
	}
	// A core that never implemented the family holds nothing to release, a core the
	// projection knows is "off" holds nothing either, and a core that is unreachable
	// is a different fact: in that case the latch stays (§9: "Core nicht erreichbar
	// -> Latch (falls aktiv) bleibt").
	attemptCore := coreCapability != "missing" && coreState != "off"
	if attemptCore && e.core == nil {
		return e.StatusView(), errLockdownCoreUnavailable
	}
	intentTarget := "epoch:" + epoch + " request:" + lockdownReasonText(requestID)
	intentErr := e.recordEvidence("high", "lockdown.clear.intent",
		"Operator clear accepted for processing; the latch is released only after the kernel clear is acknowledged",
		intentTarget)
	if intentErr != nil {
		// §9 allows the clear to proceed while the audit path is down (gate-exempt,
		// deadlock protection). It must never be silent.
		e.addEvent("critical", "lockdown.evidence.degraded",
			"Lockdown clear proceeding without a committed intent record; the evidence ledger is unavailable")
	}
	e.stateMu.Lock()
	e.doc.State = lockdownStateClearing
	persistErr := e.persistLocked()
	e.stateMu.Unlock()
	if persistErr != nil {
		e.addEvent("critical", "lockdown.state.persist_failed",
			"Lockdown clear transition could not be persisted; the latch stays unless the kernel answer completes it")
	}
	if attemptCore {
		if _, err := e.core.LockdownClear(expectedEpoch, reasonToken); err != nil {
			e.stateMu.Lock()
			e.doc.State = lockdownStateActive
			_ = e.persistLocked()
			e.stateMu.Unlock()
			if errors.Is(err, ErrLockdownUnavailable) {
				// The core no longer speaks the family: nothing is enforcing, so the
				// local latch may be released loudly rather than trapping the operator.
				e.addEvent("critical", "lockdown.core.capability_lost",
					"The core no longer implements the lockdown command family; the kernel phase cannot be confirmed")
			} else {
				e.setCoreStatus(CoreLockdownStatus{}, err)
				if strings.Contains(strings.ToLower(err.Error()), "epoch") {
					// Refresh the projection once so the operator sees the epoch the
					// kernel actually holds, then stay latched.
					if status, statusErr := e.core.LockdownStatus(); statusErr == nil {
						e.setCoreStatus(status, nil)
					}
					return e.StatusView(), errLockdownEpochMismatch
				}
				return e.StatusView(), fmt.Errorf("%w: %v", errLockdownCoreUnavailable, err)
			}
		}
	}
	// Reversibility (§1.3): release the cell freezes and resume the frozen process
	// through the same engines that applied them. A failure is reported loudly
	// instead of silently leaving a workload isolated after a successful clear.
	e.reverseCellFreezes(cellTransactions)
	e.resumeFrozenProcess(processPID, processStartTicks)
	e.stateMu.Lock()
	e.doc.Latched = false
	e.doc.State = lockdownStateDisarmed
	e.doc.Epoch = ""
	e.doc.Phases = nil
	e.doc.Trigger = nil
	e.doc.CellTransactions = nil
	e.doc.LastError = ""
	clearedAt := e.now()
	e.doc.LastClear = &LockdownClearView{At: clearedAt, Reason: lockdownReasonText(reasonText), Epoch: epoch}
	if settings.Enabled && settings.AutoArm {
		// Auto-arm is a start-up policy; after a clear the engine stays disarmed
		// until the next start unless the operator arms it again.
		e.doc.State = lockdownStateDisarmed
	}
	persistErr = e.persistLocked()
	view := e.statusViewLocked()
	e.stateMu.Unlock()
	if persistErr != nil {
		e.addEvent("critical", "lockdown.state.persist_failed",
			"Lockdown clear could not be persisted; a restart re-latches from the last accepted trigger")
	}
	e.addEvent("high", "lockdown.cleared", fmt.Sprintf("Emergency lockdown cleared (epoch %s); the kernel state was released with compare-set semantics", epoch))
	_ = e.recordEvidence("high", "lockdown.clear.outcome",
		"Emergency lockdown cleared by an authenticated operator", "epoch:"+epoch)
	return view, nil
}

// lockdownCoreFlags maps the namespace onto the four documented
// LOCKDOWN_TRIGGER flag bits (§5): bit0 auto_network_drop, bit1 allow_loopback,
// bit2 freeze_brokers, bit3 hardening_apply.
func lockdownCoreFlags(settings LockdownFabricSettings) uint8 {
	var flags uint8
	if settings.NetworkLockdown {
		flags |= 1 << 0
	}
	if settings.AllowLoopback && !settings.DropLoopback {
		flags |= 1 << 1
	}
	if settings.FreezeBrokers {
		flags |= 1 << 2
	}
	if settings.HardeningApply {
		flags |= 1 << 3
	}
	return flags
}

// reverseCellFreezes reverses the recorded cell-freeze transactions through the
// same TransactionEngine that applied them. A failed reversal is reported
// loudly: a successful clear must never leave a workload isolated and silent
// about it.
func (e *LockdownEngine) reverseCellFreezes(transactions []string) {
	if len(transactions) == 0 {
		return
	}
	if e.state == nil || e.state.Transactions() == nil {
		e.addEvent("critical", "lockdown.cells.resume_failed",
			fmt.Sprintf("%d cell freezes remain in force: the transaction engine is unavailable for the reversal", len(transactions)))
		_ = e.recordEvidence("critical", "lockdown.cells.resume_failed",
			"Cell freeze reversal was not possible because the transaction engine is unavailable",
			fmt.Sprintf("transactions:%d", len(transactions)))
		return
	}
	engine := e.state.Transactions()
	failures := 0
	for _, id := range transactions {
		if id == "" {
			continue
		}
		if _, err := engine.Reverse(id, "REVERSE "+id); err != nil {
			failures++
		}
	}
	if failures > 0 {
		message := fmt.Sprintf("%d of %d cell freezes could not be reversed; the workloads stay isolated until an operator retries", failures, len(transactions))
		e.addEvent("critical", "lockdown.cells.resume_failed", message)
		_ = e.recordEvidence("critical", "lockdown.cells.resume_failed", message, "reverse-failed")
		return
	}
	e.addEvent("high", "lockdown.cells.resumed",
		fmt.Sprintf("%d cell freezes were reversed by the authenticated clear", len(transactions)))
}

// resumeFrozenProcess resumes the process the trigger froze, using the persisted
// starttime identity so a recycled PID is refused by the core.
func (e *LockdownEngine) resumeFrozenProcess(pid int, startTicks uint64) {
	if pid <= 0 {
		return
	}
	if e.core == nil {
		e.addEvent("critical", "lockdown.process.resume_failed",
			fmt.Sprintf("Frozen process %d remains stopped: the kernel core is unavailable for the resume", pid))
		return
	}
	if err := e.core.UnfreezeProcess(pid, startTicks); err != nil {
		e.addEvent("critical", "lockdown.process.resume_failed",
			"Frozen process could not be resumed by the clear: "+lockdownReasonText(err.Error()))
		_ = e.recordEvidence("critical", "lockdown.process.resume_failed",
			"Frozen process could not be resumed by the clear", fmt.Sprintf("pid:%d", pid))
		return
	}
	e.addEvent("high", "lockdown.process.resumed",
		fmt.Sprintf("The process frozen by the trigger was resumed (pid %d)", pid))
}
