// STATUS: DIAMANT VGT SUPREME
// SPDX-FileCopyrightText: 2026 VisionGaia Technology
// SPDX-License-Identifier: AGPL-3.0-only

// Release-gate decisions split out of release.go (refactoring wave 1b,
// structure-only): the Observe/Canary/Enforce ladder decision, the blocker
// evaluation that gates a transition, the fail-closed degradation and
// emergency-stop decisions and the explicit phase transition. The controller
// type, lifecycle, startup/quarantine and kernel reconciliation stay in
// release.go; the soak clocks and readiness windows stay in release_soak.go.

package main

import (
	"errors"
	"fmt"
	"log"
	"os"
	"strings"
	"time"
)

func releaseModes(phase string) (string, string, error) {
	switch phase {
	case ReleasePhaseObserve, ReleasePhaseDegraded:
		return "observe", "observe", nil
	case ReleasePhaseCanary:
		return "observe", "contain", nil
	case ReleasePhaseEnforce:
		return "enforce", "enforce", nil
	default:
		return "", "", fmt.Errorf("unsupported release phase %q", phase)
	}
}

// kernelPolicyVerified reports whether the kernel carries a policy state the platform has
// confirmed, whichever state that is.
//
// Under fail-closed retention a degraded platform keeps its blocklist, so "verified-empty"
// stopped being the only verified state. The operator sees either the empty kernel they asked
// for or the enforcement they already had - and both are confirmed, never assumed.
func kernelPolicyVerified(kernelState string) bool {
	return kernelState == "verified-empty" || kernelState == "verified-enforce"
}

// retainedEnforcementLocked returns the kernel enforcement a transition may actually apply.
//
// A verified kernel enforcement is never lowered by a phase change. Canary applies observe at
// the kernel, so a promotion out of a retained degraded state released every blocked source -
// the same fail-open as the automatic fall-back, one step later. Only the explicit
// RETURN:OBSERVE transition releases the policy, because that is the operator's own
// instruction and it is confirmed by a dedicated phrase.
func (r *ReleaseController) retainedEnforcementLocked(target, requested string) string {
	if target == ReleasePhaseObserve {
		return requested
	}
	if r.status.KernelPolicyState == "verified-enforce" && requested == "observe" {
		return "enforce"
	}
	return requested
}

func (r *ReleaseController) currentBlockersLocked(target string, includeDuration bool) []string {
	snap := r.state.Snapshot()
	releaseCfg := r.effectiveReleaseConfigLocked()
	var blockers []string
	// The quarantine is the first blocker because it has to be the first thing the operator
	// reads: an unverifiable policy is a trust decision, not a transient gate failure. It is
	// also what refuses any promotion while the quarantine is active (FIND-013).
	if r.status.PolicyQuarantined {
		blockers = append(blockers, "signed policy is quarantined after an unverifiable startup; explicit operator recovery required")
	}
	if _, err := os.Stat(r.cfg.Release.EmergencyStopFile); err == nil {
		blockers = append(blockers, "emergency stop is active")
	} else if !errors.Is(err, os.ErrNotExist) {
		blockers = append(blockers, "emergency stop state cannot be verified")
	}
	if r.cfg.Policy.RequireSigned && !snap.Policy.Verified {
		blockers = append(blockers, "signed policy is not verified")
	}
	if snap.Evidence.Enabled && !snap.Evidence.Healthy {
		blockers = append(blockers, "mandatory evidence ledger is unavailable")
	}
	runtime := r.runtimeSettingsLocked()
	if runtime.XDREnabled && snap.XDR.Degraded && !isNonFatalSecCritThrottleReason(snap.XDR.DegradedReason) {
		blockers = append(blockers, "XDR is degraded")
	}
	if r.cfg.L7.Enabled && target != ReleasePhaseObserve && target != ReleasePhaseDegraded && !snap.L7.Healthy {
		blockers = append(blockers, "L7 inspection service is unavailable")
	}
	// A recent passing self-test is accepted in place of the flag. The flag is an
	// inference from events and can be stale; the self-test drove a request through the
	// listener and confirmed the counter moved. Blocking promotion on the weaker of two
	// signals is what left the platform degraded while the path was demonstrably working.
	if r.cfg.L7.InlineEnabled && target != ReleasePhaseObserve && target != ReleasePhaseDegraded &&
		!snap.L7.InlineHealthy && !InlinePathVerifiedBySelfTest(snap.L7, time.Now().UTC()) {
		blockers = append(blockers, "L7 inline service is unavailable")
	}
	// Only kernel rules that the target phase would release are a pre-transition blocker.
	// Under fail-closed retention a promotion keeps the enforcement, so a rule that is
	// already enforced is the protection being retained, not a reconciliation that is
	// pending - treating it as pending refused the very transition that keeps it.
	if targetEnforcement, _, modeErr := releaseModes(target); modeErr == nil {
		targetEnforcement = r.retainedEnforcementLocked(target, targetEnforcement)
		for _, block := range snap.Blocks {
			// Enforce promotion performs an atomic best-effort reconciliation below.
			if targetEnforcement != "enforce" && block.Enforced {
				blockers = append(blockers, "kernel policy reconciliation is pending")
				break
			}
		}
	}
	if !snap.CoreConnected {
		blockers = append(blockers, "authenticated Rust core is offline")
	}
	if target == ReleasePhaseEnforce {
		if len(runtime.ManagementAllowlist) == 0 {
			blockers = append(blockers, "management network allowlist is empty")
		} else if !snap.AllowlistReady {
			blockers = append(blockers, "kernel management allowlist is not synchronized")
		}
		if snap.Coverage.OverallStatus == CoverageOffline || snap.Coverage.OverallStatus == CoverageDegraded {
			blockers = append(blockers, fmt.Sprintf("kinetic sensor coverage is not nominal: %s", snap.Coverage.Summary))
		}
	}
	if target == ReleasePhaseCanary || target == ReleasePhaseEnforce {
		if cov, exists := snap.Coverage.Sensors["xdp_ingress"]; exists && cov.Required && cov.Status != CoverageOnline {
			blockers = append(blockers, "Kinetic ingress sensor is unavailable")
		}
	}
	if r.status.CoreMisses >= releaseCfg.CoreFailureThreshold {
		blockers = append(blockers, "core heartbeat failure threshold reached")
	}
	// Kernel advisories can veto a promotion, but only when the operator asked for that. The default
	// is "report": a host whose distribution has not published a fixed build yet is still protected by
	// everything else this gate covers, and pausing automatic response because the kernel is old would
	// remove protection in the name of protection.
	if r.exposure != nil {
		if blocker := kernelAdvisoryBlocker(target, r.status.Phase, r.cfg.Advisories, r.exposure.Current()); blocker != "" {
			blockers = append(blockers, blocker)
		}
	}
	if r.status.Phase == ReleasePhaseDegraded && !r.status.FailSafeVerified {
		blockers = append(blockers, "fail-safe transition is not verified")
	}
	if (r.status.Phase == ReleasePhaseObserve || r.status.Phase == ReleasePhaseDegraded) &&
		(!r.status.FailSafeVerified || !kernelPolicyVerified(r.status.KernelPolicyState)) {
		blockers = append(blockers, "kernel policy state is not verified")
	}
	if snap.XDR.EvaluationsTotal > 0 {
		dropPermille := snap.XDR.EvaluationDrops * 1000 / snap.XDR.EvaluationsTotal
		if dropPermille > uint64(releaseCfg.MaxEvaluationDropPermille) {
			blockers = append(blockers, fmt.Sprintf("XDR evaluation drop rate is %d permille", dropPermille))
		}
	}
	if includeDuration {
		elapsed := r.sinceElapsed()
		switch target {
		case ReleasePhaseCanary:
			minimum := time.Duration(releaseCfg.MinimumObserveSeconds) * time.Second
			if r.status.Phase != ReleasePhaseObserve && r.status.Phase != ReleasePhaseDegraded {
				blockers = append(blockers, "canary promotion requires observe phase")
			} else if elapsed < minimum {
				blockers = append(blockers, fmt.Sprintf("observe soak time remaining: %s", (minimum-elapsed).Round(time.Second)))
			}
		case ReleasePhaseEnforce:
			minimum := time.Duration(releaseCfg.MinimumCanarySeconds) * time.Second
			if r.status.Phase != ReleasePhaseCanary {
				blockers = append(blockers, "enforce promotion requires canary phase")
			} else if elapsed < minimum {
				blockers = append(blockers, fmt.Sprintf("canary soak time remaining: %s", (minimum-elapsed).Round(time.Second)))
			}
		}
	}
	return blockers
}

func (r *ReleaseController) Transition(target, confirmation, reason string) (ReleaseStatus, error) {
	r.mu.Lock()
	locked := true
	defer func() {
		if locked {
			r.mu.Unlock()
		}
	}()
	target = strings.ToLower(strings.TrimSpace(target))
	if target != ReleasePhaseObserve && target != ReleasePhaseCanary && target != ReleasePhaseEnforce {
		return cloneReleaseStatus(r.status), errors.New("target phase must be observe, canary, or enforce")
	}
	expected := "PROMOTE:" + strings.ToUpper(target)
	if target == ReleasePhaseObserve {
		expected = "RETURN:OBSERVE"
	}
	if confirmation != expected {
		return cloneReleaseStatus(r.status), errors.New("explicit transition confirmation is invalid")
	}
	if len(strings.TrimSpace(reason)) < 8 || len(reason) > 240 {
		return cloneReleaseStatus(r.status), errors.New("transition reason must contain 8-240 characters")
	}
	if target == r.status.Phase {
		return cloneReleaseStatus(r.status), nil
	}
	if target != ReleasePhaseObserve {
		if blockers := r.currentBlockersLocked(target, true); len(blockers) > 0 {
			r.status.Blockers = blockers
			r.status.Ready = false
			r.status.Detail = blockers[0]
			r.state.SetReleaseStatus(r.status)
			return cloneReleaseStatus(r.status), fmt.Errorf("release gate rejected transition: %s", strings.Join(blockers, "; "))
		}
	}
	old := r.status
	oldEnforcement, oldXDR := r.state.Modes()
	newEnforcement, newXDR, err := releaseModes(target)
	if err != nil {
		return cloneReleaseStatus(r.status), err
	}
	// Never lower a verified kernel enforcement by accident: see
	// retainedEnforcementLocked. The operator's own RETURN:OBSERVE is the exception.
	newEnforcement = r.retainedEnforcementLocked(target, newEnforcement)
	if err := r.reconcileLocked(newEnforcement); err != nil {
		return cloneReleaseStatus(r.status), err
	}
	if err := r.policy.Persist(r.cfg.Node.Name, newEnforcement, newXDR, r.state.BlocksSnapshot()); err != nil {
		persistErr := fmt.Errorf("signed policy transition failed: %w", err)
		if rollbackErr := r.reconcileLocked(oldEnforcement); rollbackErr != nil {
			r.state.SetModes("unverified", "observe")
			r.markDegradedLocked(
				"policy transition and kernel rollback failed",
				"unverified",
				false,
			)
			return cloneReleaseStatus(r.status), errors.Join(persistErr, fmt.Errorf("kernel rollback failed: %w", rollbackErr))
		}
		return cloneReleaseStatus(r.status), persistErr
	}
	r.state.SetModes(newEnforcement, newXDR)
	r.state.SetPolicyStatus(r.policy.Status())
	now := time.Now().UTC()
	r.status.Phase = target
	r.status.Since = now
	r.status.LastTransition = &now
	r.monoSince = time.Now()
	r.status.Detail = strings.TrimSpace(reason)
	r.status.Blockers = nil
	r.status.Ready = true
	if newEnforcement == "observe" {
		r.status.KernelPolicyState = "verified-empty"
	} else {
		r.status.KernelPolicyState = "verified-enforce"
	}
	// The transition confirmed the kernel in this pass, so whichever state it produced is a
	// verified one. Tying this flag to "observe" alone made a promoted platform that kept its
	// enforcement report an unverified kernel state.
	r.status.FailSafeVerified = kernelPolicyVerified(r.status.KernelPolicyState)
	// A transition is an explicit operator action and it persisted a fresh, signed document.
	// This is the only kind of path that may end the startup quarantine (FIND-013); the
	// forensic copy of the unverifiable document is kept.
	r.clearPolicyQuarantineLocked("release transition to " + target)
	var enforceHook func(RuntimeSettings)
	var updatedSettings RuntimeSettings
	v6Activated := false
	if newEnforcement == "enforce" && r.settings != nil {
		var armErr error
		updatedSettings, v6Activated, armErr = r.settings.ApplySafeV6DefaultsOnEnforce()
		if armErr != nil {
			log.Printf("release: v6 safe auto-arm settings update failed: %v", armErr)
		} else if v6Activated {
			enforceHook = r.enforceSettingsHook
			r.state.SetSettings(updatedSettings)
			r.state.AddEvent(Event{
				Severity: "info", Kind: "v6.auto_armed", Source: "release-gate",
				Message: "GeDefense V6 safe defaults activated on enforce (styx=monitor, titan_exec=contain, parser_cells=enabled; lockdown and witness remain opt-in)",
			})
		}
	}
	r.state.SetReleaseStatus(r.status)
	r.state.AddEvent(Event{Severity: "high", Kind: "release.transition", Source: "release-gate", Message: fmt.Sprintf("Beta phase changed from %s to %s: %s", old.Phase, target, strings.TrimSpace(reason))})
	_ = oldXDR
	ret := cloneReleaseStatus(r.status)
	r.mu.Unlock()
	locked = false
	if v6Activated && enforceHook != nil {
		enforceHook(updatedSettings)
	}
	return ret, nil
}

// Evaluate runs one release-gate cycle and reports the blockers it found.
//
// Evaluating the blockers is an obligation on every cycle and it is deliberately independent
// of AutoDegrade: an operator who disabled the automatic fall-back must still see what would
// have paused the platform. AutoDegrade gates exactly one thing - the automatic mode switch
// through degradeLocked - and never the detection or the reporting of a blocker (FIND-014).
func (r *ReleaseController) Evaluate() {
	r.mu.Lock()
	defer r.mu.Unlock()
	autoDegrade := r.runtimeSettingsLocked().AutoDegrade
	blockers := r.currentBlockersLocked(r.status.Phase, false)
	// Publish the evaluation before any action is decided, so the status can never contradict
	// the check: a blocker that is present is reported even when nothing is done about it.
	r.status.Blockers = append([]string(nil), blockers...)
	r.status.Ready = len(blockers) == 0
	r.status.AutoDegradeHeld = false
	if len(blockers) > 0 && !autoDegrade &&
		(r.status.Phase == ReleasePhaseCanary || r.status.Phase == ReleasePhaseEnforce) {
		// The platform would have paused, but the operator disabled AutoDegrade. That is a
		// decision, not silence: the held blockers are reported as such.
		r.status.AutoDegradeHeld = true
	}
	if !autoDegrade || len(blockers) == 0 ||
		r.status.Phase == ReleasePhaseObserve || r.status.Phase == ReleasePhaseDegraded {
		// Automatic response is either already paused or the operator owns the mode switch;
		// there is no automatic degradation to make. The evaluation above is reported anyway.
		r.trackNominalLocked()
		r.recoverIfGatesPassLocked()
		r.refreshLocked()
		r.state.SetReleaseStatus(r.status)
		return
	}
	_ = r.degradeLocked(strings.Join(blockers, "; "))
	r.trackNominalLocked()
	r.refreshLocked()
	r.state.SetReleaseStatus(r.status)
}

// FailSafe lowers the release phase and retains the kernel enforcement.
//
// The name is kept because callers across the platform express "fall back because something
// could not be verified" with it. What it does is now fail-closed: the verified kernel policy
// stays in place and only new automatic decisions stop. See degradeLocked.
func (r *ReleaseController) FailSafe(reason string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if strings.TrimSpace(reason) == "" {
		reason = "kernel transaction integrity failure"
	}
	err := r.degradeLocked(reason)
	r.refreshLocked()
	r.state.SetReleaseStatus(r.status)
	return err
}

func (r *ReleaseController) markDegradedLocked(reason, kernelState string, verified bool) {
	now := time.Now().UTC()
	r.status.Phase = ReleasePhaseDegraded
	r.status.Since = now
	r.status.LastTransition = &now
	r.monoSince = time.Now()
	r.status.Ready = false
	r.status.FailSafeVerified = verified
	r.status.KernelPolicyState = kernelState
	r.status.Detail = reason
	r.status.Blockers = []string{reason}
	// Recorded once, at the moment of the fall-back, and never recomputed. It is the
	// answer to "why is this platform in Observe", which the live detail cannot give
	// because it describes the present, not the event.
	r.status.FailSafeReason = reason
	r.status.FailSafeAt = &now
	r.state.SetReleaseStatus(r.status)

	// The fall-back is also a forensic event, not only a phase change. It disables every
	// active response on the host, which is the most consequential thing the platform
	// does on its own, and it was leaving no trace an operator could investigate: the
	// Forensics view counted zero incidents after a fail-safe because only the XDR
	// process pipeline ever created one.
	r.state.AddIncident(XDRIncident{
		ID: randomID(), Time: now, Severity: "critical",
		RuleIDs:  []string{"RELEASE.FAIL_SAFE"},
		Summary:  "Automatic response paused; kernel enforcement retained: " + reason,
		Decision: "fail_safe", Action: "automatic_response_paused",
		Outcome: "kernel blocklist retained and verified; automatic decisions stay paused until the cause clears and the calm holds, or an operator promotes",
	})
}

// degradeLocked lowers the release phase without ever disarming the host.
//
// This function used to reconcile the kernel to observe, which removes every enforced block,
// because the platform could not prove the kernel state. That is fail-open, and it is the
// primitive an attacker wants: one rejected kernel sample, one forensic-log overflow or one
// missed heartbeat ended with an unprotected host and every blocked source released. A host
// was found disarmed for twenty hours after a single malformed ingress event, and every
// control-plane restart disarmed it again.
//
// The kernel policy is retained and verified instead. Blocks the platform owns but that are
// not yet enforced are applied - a strengthening action - nothing is removed, and the
// retained state is confirmed before the phase drops. New automatic decisions stop by
// themselves, because every consumer requires the enforce phase (kinetic_response.go), which
// is the containment this fall-back exists for.
//
// Releasing the kernel policy stays possible, but only through an explicit operator action:
// the RETURN:OBSERVE transition, an emergency stop, or clearing one.
func (r *ReleaseController) degradeLocked(reason string) error {
	// Automatic decisions stop before anything else. "unverified" cannot be mistaken for a
	// state in which new containment is safe.
	r.state.SetModes("unverified", "observe")

	if err := r.reconcileVerifiedLocked(); err != nil {
		// Nothing was removed - the kernel still holds whatever it held - but that state is
		// not confirmed, so it is reported as unverified and the operator is required. The
		// platform does not release blocks it cannot see.
		detail := reason + "; retained kernel policy could not be verified"
		r.markDegradedLocked(detail, "unverified", false)
		r.state.AddEvent(Event{
			Severity: "critical", Kind: "release.degrade_unverified", Source: "release-gate",
			Message: "Enforcement retained but unverified; out-of-band verification required: " + reason,
		})
		log.Printf("release: phase degraded, retained enforcement unverified: %s", reason)
		return fmt.Errorf("fail-closed retention could not verify the kernel policy: %w", err)
	}
	if r.status.PolicyQuarantined {
		// The startup policy document could not be verified and is preserved as evidence. A
		// persist here would overwrite it and put a fresh signature on an intent nobody
		// verified - destroying the evidence and pinning the change (FIND-013). The retention
		// is reported without persistence; only an explicit operator action may re-sign.
		r.state.SetModes("enforce", "observe")
		detail := reason + "; signed policy persistence withheld (startup policy is quarantined)"
		r.markDegradedLocked(detail, "verified-enforce", true)
		r.state.AddEvent(Event{
			Severity: "critical", Kind: "release.degrade_policy_withheld", Source: "release-gate",
			Message: "Automatic response paused and kernel enforcement retained, but the signed policy was not rewritten: " +
				"the startup policy document is quarantined and only an explicit operator recovery may re-sign it: " + reason,
		})
		log.Printf("release: phase degraded, kernel enforcement retained; policy persistence withheld because the startup policy is quarantined: %s", reason)
		return nil
	}
	if err := r.policy.Persist(r.cfg.Node.Name, "enforce", "observe", r.state.BlocksSnapshot()); err != nil {
		r.state.SetPolicyStatus(r.policy.Status())
		detail := reason + "; retained policy persistence failed"
		r.markDegradedLocked(detail, "unverified", false)
		r.state.AddEvent(Event{
			Severity: "critical", Kind: "release.degrade_policy_failed", Source: "release-gate",
			Message: "Kernel enforcement is retained but the signed policy could not be persisted: " + reason,
		})
		log.Printf("release: phase degraded, retained policy persistence failed: %s", reason)
		return fmt.Errorf("fail-closed retention could not persist the signed policy: %w", err)
	}
	r.state.SetPolicyStatus(r.policy.Status())
	// The kernel enforces what the signed policy states; the XDR mode drops to observe so no
	// new active response is issued while the cause is unresolved.
	r.state.SetModes("enforce", "observe")
	r.markDegradedLocked(reason, "verified-enforce", true)
	r.state.AddEvent(Event{
		Severity: "critical", Kind: "release.degraded_enforcement_retained", Source: "release-gate",
		Message: "Automatic response paused; kernel enforcement retained (fail-closed): " + reason,
	})
	log.Printf("release: phase degraded, kernel enforcement retained (fail-closed): %s", reason)
	return nil
}

func (r *ReleaseController) EmergencyStop(reason string) (ReleaseStatus, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(strings.TrimSpace(reason)) < 8 || len(reason) > 240 {
		return cloneReleaseStatus(r.status), errors.New("emergency stop reason must contain 8-240 characters")
	}
	payload := []byte(time.Now().UTC().Format(time.RFC3339Nano) + " " + strings.TrimSpace(reason) + "\n")
	if err := atomicWriteFile(r.cfg.Release.EmergencyStopFile, payload, 0o600); err != nil {
		return cloneReleaseStatus(r.status), err
	}
	degradeErr := r.degradeLocked("emergency stop: " + strings.TrimSpace(reason))
	r.status.EmergencyStop = true
	r.state.SetReleaseStatus(r.status)
	if degradeErr != nil {
		return cloneReleaseStatus(r.status), fmt.Errorf("emergency stop persisted but fail-safe verification failed: %w", degradeErr)
	}
	return cloneReleaseStatus(r.status), nil
}

func (r *ReleaseController) ClearEmergencyStop(confirmation, reason string) (ReleaseStatus, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if confirmation != "CLEAR:EMERGENCY-STOP" {
		return cloneReleaseStatus(r.status), errors.New("explicit emergency-stop clear confirmation is invalid")
	}
	if len(strings.TrimSpace(reason)) < 8 || len(reason) > 240 {
		return cloneReleaseStatus(r.status), errors.New("clear reason must contain 8-240 characters")
	}
	// Clearing an emergency stop releases the kernel policy and persists a fresh signed
	// document. While the startup policy is quarantined that would re-sign the unverifiable
	// document, destroy the evidence and bypass the typed RETURN:OBSERVE recovery - and it
	// would do so even when no emergency-stop marker exists at all. The quarantine may only be
	// ended by the explicit RETURN:OBSERVE operator transition (FIND-013 / verify-policy gap).
	if r.status.PolicyQuarantined {
		r.state.AddEvent(Event{
			Severity: "critical", Kind: "release.emergency_stop_clear_refused", Source: "release-gate",
			Message: "Emergency-stop clear refused: the startup signed policy is quarantined. The emergency-stop marker, the kernel blocklist and the preserved policy document were left unchanged. " +
				"Recovery is the explicit RETURN:OBSERVE operator transition: " + strings.TrimSpace(reason),
		})
		log.Printf("release: emergency-stop clear refused, policy quarantine is active (marker, kernel policy and document unchanged): %s", strings.TrimSpace(reason))
		return cloneReleaseStatus(r.status), errors.New("policy quarantine is active; an unverifiable signed policy may only be released by the explicit RETURN:OBSERVE operator transition")
	}
	if err := os.Remove(r.cfg.Release.EmergencyStopFile); err != nil && !errors.Is(err, os.ErrNotExist) {
		return cloneReleaseStatus(r.status), err
	}
	if err := r.reconcileLocked("observe"); err != nil {
		return cloneReleaseStatus(r.status), err
	}
	if err := r.policy.Persist(r.cfg.Node.Name, "observe", "observe", r.state.BlocksSnapshot()); err != nil {
		return cloneReleaseStatus(r.status), fmt.Errorf("signed policy update failed: %w", err)
	}
	r.state.SetModes("observe", "observe")
	r.state.SetPolicyStatus(r.policy.Status())
	now := time.Now().UTC()
	r.status.Phase = ReleasePhaseObserve
	r.status.Since = now
	r.status.LastTransition = &now
	r.monoSince = time.Now()
	r.status.EmergencyStop = false
	r.status.FailSafeVerified = true
	r.status.KernelPolicyState = "verified-empty"
	r.status.Detail = strings.TrimSpace(reason)
	r.status.Blockers = nil
	r.refreshLocked()
	r.state.SetReleaseStatus(r.status)
	r.state.AddEvent(Event{Severity: "high", Kind: "release.emergency_stop_cleared", Source: "operator", Message: "Emergency stop cleared; system remains in Observe: " + strings.TrimSpace(reason)})
	return cloneReleaseStatus(r.status), nil
}
