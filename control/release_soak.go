// STATUS: DIAMANT VGT SUPREME
// SPDX-FileCopyrightText: 2026 VisionGaia Technology
// SPDX-License-Identifier: AGPL-3.0-only

// Release soak/stability windows split out of release.go (refactoring wave 1b,
// structure-only): the wall-clock and monotonic phase anchors, the nominal-calm
// tracking, the soak-gated recovery/re-arm decisions and the promotion readiness
// windows a client polls. Gate decisions stay in release_gate.go.

package main

import (
	"errors"
	"fmt"
	"log"
	"os"
	"strings"
	"time"
)

// markSinceLocked records a phase transition for the wall clock (for the API) and the
// monotonic clock (for the soak decision). The caller holds r.mu.
func (r *ReleaseController) markSinceLocked() time.Time {
	mono := time.Now()
	r.monoSince = mono
	wall := mono.UTC()
	r.status.Since = wall
	r.status.LastTransition = &wall
	return wall
}

func (r *ReleaseController) markNominalLocked() {
	mono := time.Now()
	r.monoNominal = &mono
	wall := mono.UTC()
	r.status.NominalSince = &wall
}

func (r *ReleaseController) sinceElapsed() time.Duration {
	if !r.monoSince.IsZero() && r.status.Since.Equal(r.monoSince.UTC()) {
		return time.Since(r.monoSince)
	}
	return time.Since(r.status.Since)
}

func (r *ReleaseController) nominalElapsed() time.Duration {
	if r.monoNominal != nil && r.status.NominalSince != nil && r.status.NominalSince.Equal(r.monoNominal.UTC()) {
		return time.Since(*r.monoNominal)
	}
	if r.status.NominalSince != nil {
		return time.Since(*r.status.NominalSince)
	}
	return 0
}

func (r *ReleaseController) refreshLocked() {
	_, emergencyErr := os.Stat(r.cfg.Release.EmergencyStopFile)
	emergencyUnverifiable := false
	switch {
	case emergencyErr == nil:
		r.status.EmergencyStop = true
	case os.IsNotExist(emergencyErr):
		r.status.EmergencyStop = false
	default:
		// "Cannot be read" is not "not set". A marker this platform cannot see must never count as
		// absent, or an unreadable state file would silently clear an operator's emergency stop -
		// exactly the state in which nothing else can be trusted either.
		r.status.EmergencyStop = true
		emergencyUnverifiable = true
	}
	blockers := r.currentBlockersLocked(r.status.Phase, false)
	r.status.Blockers = blockers
	r.status.Ready = len(blockers) == 0
	if emergencyUnverifiable {
		r.status.Detail = "emergency stop state cannot be verified: " + emergencyErr.Error()
	} else if r.status.EmergencyStop {
		r.status.Detail = "emergency stop active"
	} else if len(blockers) > 0 {
		r.status.Detail = blockers[0]
	} else if r.status.Phase == ReleasePhaseDegraded {
		// The phase is the fact; the reason is only the explanation, and it can legitimately be
		// empty - a transient cause that a later verification cleared leaves the platform in the
		// fail-safe with nothing currently blocking. Keying this branch on the reason meant that
		// exactly that state told the operator "release gates satisfied", directly beneath a
		// DEGRADED badge and a fail-safe notice. The sentence now follows the phase and names what
		// the kernel is doing, which is the part the operator needs in order to judge the risk.
		if kernelPolicyVerified(r.status.KernelPolicyState) {
			r.status.Detail = "automatic response paused; kernel enforcement retained and verified"
		} else {
			r.status.Detail = "automatic response paused; kernel enforcement not confirmed"
		}
	} else {
		r.status.Detail = "release gates satisfied"
	}
}

// trackNominalLocked records how long the platform has been free of substantive blockers.
//
// The soak has to measure the *current* calm, not the age of the fall-back: a cause that
// persisted for hours and then cleared would otherwise be treated as already soaked, and the
// phase would flip back on the first healthy sample. Recording when the calm began is what
// makes the recovery resistant to the flapping that caused it.
func (r *ReleaseController) trackNominalLocked() {
	if r.status.Phase != ReleasePhaseDegraded {
		r.status.NominalSince = nil
		return
	}
	if len(r.currentBlockersLocked(ReleasePhaseEnforce, false)) > 0 {
		r.status.NominalSince = nil
		return
	}
	if r.status.NominalSince == nil {
		r.markNominalLocked()
	}
}

// recoverIfGatesPassLocked returns a degraded platform with retained enforcement to the
// enforcing phase once every substantive gate passes again and the calm has held.
//
// Only the promotion ladder is skipped - the degraded phase is neither observe nor canary, so
// ladder conditions cannot apply to it. Every substantive gate is re-evaluated: signed policy,
// evidence ledger, XDR health, L7 health, core connectivity, management allowlist and sensor
// coverage. Nothing is recovered while the retained enforcement is unverified, because
// recovery must never talk the platform into believing a state it could not confirm.
//
// Without this the host stayed paused for twenty hours - protected, but with automatic
// response off - until an operator happened to look.
func (r *ReleaseController) recoverIfGatesPassLocked() {
	if r.status.Phase != ReleasePhaseDegraded || r.status.EmergencyStop {
		return
	}
	// Automatic recovery may not re-establish the signed policy. While the startup document is
	// quarantined the only way out is an explicit operator action (FIND-013); otherwise a calm
	// period would talk the platform into re-signing an unverified state.
	if r.status.PolicyQuarantined {
		return
	}
	if r.status.KernelPolicyState != "verified-enforce" || !r.status.FailSafeVerified {
		return
	}
	releaseCfg := r.effectiveReleaseConfigLocked()
	if r.status.NominalSince == nil {
		return
	}
	if elapsed := r.nominalElapsed(); elapsed < time.Duration(releaseCfg.MinimumObserveSeconds)*time.Second {
		return
	}
	if len(r.currentBlockersLocked(ReleasePhaseEnforce, false)) > 0 {
		return
	}
	if err := r.reconcileVerifiedLocked(); err != nil {
		// The kernel could not be confirmed while recovering. Stay degraded and paused
		// rather than declaring an enforcing state that was not verified.
		log.Printf("release: recovery reconciliation failed, staying degraded: %v", err)
		return
	}
	previousReason := r.status.FailSafeReason
	now := time.Now().UTC()
	r.status.Phase = ReleasePhaseEnforce
	r.status.Since = now
	r.status.LastTransition = &now
	r.monoSince = time.Now()
	r.status.Ready = true
	r.status.Blockers = nil
	r.status.KernelPolicyState = "verified-enforce"
	r.status.FailSafeVerified = true
	r.status.FailSafeReason = ""
	r.status.FailSafeAt = nil
	r.status.NominalSince = nil
	r.status.Detail = "recovered to enforce after the cause cleared and the calm held"
	r.state.SetModes("enforce", "enforce")
	if err := r.policy.Persist(r.cfg.Node.Name, "enforce", "enforce", r.state.BlocksSnapshot()); err != nil {
		r.state.SetPolicyStatus(r.policy.Status())
		log.Printf("release: recovery policy persistence failed: %v", err)
	}
	r.state.SetPolicyStatus(r.policy.Status())
	r.state.AddEvent(Event{
		Severity: "high", Kind: "release.recovered", Source: "release-gate",
		Message: "Automatic response resumed; kernel enforcement stayed in place throughout. Cause was: " + previousReason,
	})
	log.Printf("release: recovered to enforce after a held calm; the cause was: %s", previousReason)
}

// ReArmVerified restores enforcement after the startup self-check verified every module.
//
// It exists because the ladder answers a different question. The observe and canary soaks qualify a
// host that has not been qualified yet - a new kernel, a new interface, a new release. When the
// self-check has just proved every module healthy and the host is the one that was qualified
// before, waiting five more minutes protects nothing; it only leaves the operator wondering whether
// the platform is on. The safety properties are unchanged: an active emergency stop refuses, an
// unsatisfied gate refuses, unverified kernel enforcement refuses, and a changed host goes through
// the visible ladder instead.
func (r *ReleaseController) ReArmVerified(reason string) (ReleaseStatus, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.status.EmergencyStop {
		return cloneReleaseStatus(r.status), errors.New("emergency stop is active")
	}
	// Re-arming is automatic. It may not persist a new signed policy while the startup
	// document is quarantined: that would destroy the evidence and is a trust decision, not a
	// repair (FIND-013).
	if r.status.PolicyQuarantined {
		return cloneReleaseStatus(r.status), errors.New("signed policy is quarantined after an unverifiable startup; explicit operator recovery is required")
	}
	if r.status.Phase == ReleasePhaseEnforce {
		return cloneReleaseStatus(r.status), nil
	}
	if r.status.KernelPolicyState != "verified-enforce" || !r.status.FailSafeVerified {
		return cloneReleaseStatus(r.status), errors.New("kernel enforcement is not verified")
	}
	if blockers := r.currentBlockersLocked(ReleasePhaseEnforce, false); len(blockers) > 0 {
		return cloneReleaseStatus(r.status), fmt.Errorf("release gates are not satisfied: %s", strings.Join(blockers, "; "))
	}
	if err := r.reconcileVerifiedLocked(); err != nil {
		// The kernel could not be confirmed. Stay in the fail-safe: declaring an enforcing state
		// that was not verified is the defect this whole path exists to avoid.
		return cloneReleaseStatus(r.status), fmt.Errorf("kernel could not be confirmed: %w", err)
	}
	now := time.Now().UTC()
	r.status.Phase = ReleasePhaseEnforce
	r.status.Since = now
	r.status.LastTransition = &now
	r.monoSince = time.Now()
	r.status.Ready = true
	r.status.Blockers = nil
	r.status.KernelPolicyState = "verified-enforce"
	r.status.FailSafeVerified = true
	r.status.FailSafeReason = ""
	r.status.FailSafeAt = nil
	r.status.NominalSince = nil
	r.status.Detail = "startup self-check verified every module; enforcement re-armed without the ladder"
	r.state.SetModes("enforce", "enforce")
	if err := r.policy.Persist(r.cfg.Node.Name, "enforce", "enforce", r.state.BlocksSnapshot()); err != nil {
		log.Printf("release: re-arm policy persistence failed: %v", err)
	}
	r.state.SetPolicyStatus(r.policy.Status())
	r.state.AddEvent(Event{
		Severity: "high", Kind: "release.startup_rearmed", Source: "release-gate",
		Message: "Startup self-check verified every module and re-armed protection. Reason: " + reason,
	})
	log.Printf("release: protection re-armed after the startup self-check: %s", reason)
	return cloneReleaseStatus(r.status), nil
}

func (r *ReleaseController) Ready() (bool, []string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.refreshLocked()
	r.state.SetReleaseStatus(r.status)
	return r.status.Ready, append([]string(nil), r.status.Blockers...)
}

type ReleaseReadiness struct {
	Target               string     `json:"target"`
	Ready                bool       `json:"ready"`
	Blockers             []string   `json:"blockers"`
	CurrentPhase         string     `json:"current_phase"`
	ReadyAt              *time.Time `json:"ready_at,omitempty"`
	SoakRemainingSeconds int64      `json:"soak_remaining_seconds"`
	MinimumSoakSeconds   int64      `json:"minimum_soak_seconds"`
	ElapsedSoakSeconds   int64      `json:"elapsed_soak_seconds"`
}

// ReleaseReadinessSet is the readiness of the two promotion targets the dashboard shows together.
// It travels inside the state snapshot so a client never has to poll the readiness endpoint beside
// the status it already receives: a browser capture showed 46 readiness requests against 21 status
// requests, and each of them was a second round trip for data that changes with a transition.
type ReleaseReadinessSet struct {
	Canary  ReleaseReadiness `json:"canary"`
	Enforce ReleaseReadiness `json:"enforce"`
}

func (r *ReleaseController) Readiness(target string) (ReleaseReadiness, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	releaseCfg := r.effectiveReleaseConfigLocked()
	target = strings.ToLower(strings.TrimSpace(target))
	if target == "" {
		switch r.status.Phase {
		case ReleasePhaseObserve, ReleasePhaseDegraded:
			target = ReleasePhaseCanary
		case ReleasePhaseCanary:
			target = ReleasePhaseEnforce
		default:
			target = ReleasePhaseObserve
		}
	}
	if target != ReleasePhaseObserve && target != ReleasePhaseCanary && target != ReleasePhaseEnforce {
		return ReleaseReadiness{}, errors.New("target phase must be observe, canary, or enforce")
	}
	r.refreshLocked()
	blockers := r.currentBlockersLocked(target, true)
	elapsed := r.sinceElapsed()
	var minSoak time.Duration
	switch target {
	case ReleasePhaseCanary:
		minSoak = time.Duration(releaseCfg.MinimumObserveSeconds) * time.Second
	case ReleasePhaseEnforce:
		minSoak = time.Duration(releaseCfg.MinimumCanarySeconds) * time.Second
	}

	var soakRemaining int64
	var readyAt *time.Time
	if minSoak > 0 && elapsed < minSoak {
		rem := minSoak - elapsed
		soakRemaining = int64(rem.Seconds())
		tReady := r.status.Since.Add(minSoak)
		readyAt = &tReady
	}

	return ReleaseReadiness{
		Target:               target,
		Ready:                len(blockers) == 0,
		Blockers:             append([]string{}, blockers...),
		CurrentPhase:         r.status.Phase,
		ReadyAt:              readyAt,
		SoakRemainingSeconds: soakRemaining,
		MinimumSoakSeconds:   int64(minSoak.Seconds()),
		ElapsedSoakSeconds:   int64(elapsed.Seconds()),
	}, nil
}
