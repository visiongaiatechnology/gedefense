// SPDX-FileCopyrightText: 2026 VisionGaia Technology
// SPDX-License-Identifier: AGPL-3.0-only

package main

// POINT 5 / P5-T3: the maintenance loop of the Emergency Lockdown engine.
//
// While the namespace is disabled nothing here runs: no core command, no
// boot-trust read, no duress poll and no event. When an operator enables it,
// the loop keeps a bounded kernel projection (10 s), drains the lifecycle-event
// batch and retries the auto-arm a bounded number of times.

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"time"
)

// ------------------------------------------------------------------ run loop

// Run starts the maintenance loop: the optional duress poll (1 s), the boot
// trust reconciliation (60 s), the bounded core projection poll (10 s) and the
// auto-arm retry. Every path is skipped while the namespace is disabled, so the
// shipped default produces no request, no event and no filesystem read.
func (e *LockdownEngine) Run(ctx context.Context) {
	if e == nil {
		return
	}
	ticker := time.NewTicker(lockdownDuressPollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			e.maintenanceTick(now.UTC())
		}
	}
}

func (e *LockdownEngine) maintenanceTick(now time.Time) {
	settings := e.effectiveSettings()
	if !settings.Enabled {
		return
	}
	if settings.DuressTokenPath != "" {
		e.pollDuress(now)
	}
	e.stateMu.RLock()
	bootTrustDue := e.bootTrust != nil && settings.TriggerBootTrustDrift &&
		(e.bootTrustAt.IsZero() || now.Sub(e.bootTrustAt) >= lockdownBootTrustInterval)
	e.stateMu.RUnlock()
	if bootTrustDue {
		e.stateMu.Lock()
		e.bootTrustAt = now
		e.stateMu.Unlock()
		e.reconcileBootTrust(now)
	}
	e.stateMu.RLock()
	coreDue := e.core != nil && (e.corePollAt.IsZero() || now.Sub(e.corePollAt) >= lockdownCorePollInterval)
	e.stateMu.RUnlock()
	if coreDue {
		e.pollCore(now)
	}
	if settings.AutoArm && e.core != nil {
		e.autoArmTick(now)
	}
}

// reconcileBootTrust triggers only on a degradation from VERIFIED to OBSERVE.
// NOT_SUPPORTED is a platform without a hardware root of trust and UNKNOWN is
// an unreadable probe: neither is drift, so neither latches the platform.
// pollCore refreshes the bounded kernel projection and drains the lifecycle
// events. It performs no state transition by itself: a degradation of the core
// is reported, never turned into a fake applied phase.
func (e *LockdownEngine) pollCore(now time.Time) {
	status, err := e.core.LockdownStatus()
	e.setCoreStatus(status, err)
	if err != nil {
		return
	}
	if health, healthErr := e.core.LockdownHealth(); healthErr == nil {
		e.setCoreHealth(health, nil)
	}
	events, dropped, eventErr := e.core.LockdownEvents()
	if eventErr != nil {
		return
	}
	e.projectCoreEvents(events, dropped)
}

func (e *LockdownEngine) projectCoreEvents(events []CoreLockdownEvent, dropped uint64) {
	// The core reports the ring-drop counter as a delta since the previous poll, so
	// every non-zero value is a visibility loss for this interval. The bounded total
	// is accumulated for the status projection.
	e.stateMu.Lock()
	e.droppedEvents += dropped
	total := e.droppedEvents
	e.stateMu.Unlock()
	if dropped > 0 {
		e.addEvent("warning", "lockdown.core_events_dropped",
			fmt.Sprintf("Kernel lockdown event ring lost %d lifecycle records since the last poll (total %d); the kernel counters remain authoritative", dropped, total))
	}
	for _, event := range events {
		severity := "info"
		switch event.Outcome {
		case 4: // FAILED
			severity = "critical"
		case 5: // PARTIAL
			severity = "high"
		}
		message := fmt.Sprintf("Kernel lockdown lifecycle event seq=%d phase=%s outcome=%s source=%s reason=%s",
			event.Seq, lockdownPhaseTokenName(event.Phase), lockdownOutcomeTokenName(event.Outcome),
			lockdownSourceTokenName(event.Source), lockdownReasonTokenName(event.Reason))
		e.addEvent(severity, "lockdown.core.event", message)
		if event.Outcome == 4 || event.Outcome == 5 {
			_ = e.recordEvidence(severity, "lockdown.core.event", message, "seq:"+strconv.FormatUint(event.Seq, 10))
		}
	}
}

func lockdownPhaseTokenName(value uint8) string {
	// §3 LOCKDOWN_PHASE_*: INTENT=0, NET=1 .. DM=8.
	names := []string{"intent", lockdownPhaseNameNet, lockdownPhaseNameUSB, lockdownPhaseNameTB,
		lockdownPhaseNameHardening, lockdownPhaseNameBrokers, lockdownPhaseNameCells,
		lockdownPhaseNameSessions, lockdownPhaseNameDM}
	if int(value) < len(names) {
		return names[value]
	}
	return "unknown"
}

func lockdownSourceTokenName(value uint8) string {
	names := []string{lockdownSourceManual, lockdownSourceUevent, lockdownSourcePolicy, lockdownSourceTimer}
	if int(value) >= 1 && int(value) <= len(names) {
		return names[value-1]
	}
	return "unknown"
}

func lockdownReasonTokenName(value uint8) string {
	names := []string{lockdownReasonManual, lockdownReasonUSBUnknown, lockdownReasonTBUnknown,
		lockdownReasonScreenLock, lockdownReasonTamper, lockdownReasonXDRCritical,
		lockdownReasonBootTrust, lockdownReasonPolicy}
	if int(value) >= 1 && int(value) <= len(names) {
		return names[value-1]
	}
	return "unknown"
}

func lockdownOutcomeTokenName(value uint8) string {
	names := []string{lockdownPhaseApplied, "skipped", lockdownPhaseUnsupported, lockdownPhaseFailed, lockdownPhasePartial}
	if int(value) >= 1 && int(value) <= len(names) {
		return names[value-1]
	}
	return "unknown"
}

// autoArmTick re-arms the kernel arm mode on start when auto_arm is enabled. It
// is retried a bounded number of times and never arms while a latch is held.
func (e *LockdownEngine) autoArmTick(now time.Time) {
	e.stateMu.Lock()
	due := e.autoArmNext.IsZero() || !now.Before(e.autoArmNext)
	attempts := e.autoArmAttempts
	state := e.doc.State
	latched := e.doc.Latched
	e.stateMu.Unlock()
	if !due || latched || attempts >= lockdownAutoArmMaxAttempts || state != lockdownStateDisarmed {
		return
	}
	e.stateMu.Lock()
	e.autoArmAttempts++
	if e.autoArmNext.IsZero() {
		e.autoArmNext = now.Add(lockdownAutoArmRetry)
	}
	e.stateMu.Unlock()
	if _, err := e.Arm(lockdownModeLocked, lockdownReasonManual, "auto-arm on start", "engine-auto-arm"); err != nil {
		e.stateMu.RLock()
		first := e.autoArmAttempts <= 1
		e.stateMu.RUnlock()
		if first {
			e.addEvent("warning", "lockdown.auto_arm_failed",
				"Auto-arm could not arm the kernel: "+lockdownReasonText(err.Error()))
		}
		return
	}
	e.stateMu.Lock()
	e.autoArmNext = time.Time{}
	e.autoArmAttempts = 0
	e.stateMu.Unlock()
	e.addEvent("high", "lockdown.auto_armed",
		"Kernel lockdown arm mode was restored automatically on start because auto_arm is enabled")
}

// sortedStringKeys is a small helper for deterministic presentation of the
// correlated sources. It is kept here so the trigger file owns its vocabulary.
func sortedStringKeys(values map[string]time.Time) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
