// STATUS: DIAMANT VGT SUPREME
package main

import (
	"errors"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	ReleasePhaseObserve  = "observe"
	ReleasePhaseCanary   = "canary"
	ReleasePhaseEnforce  = "enforce"
	ReleasePhaseDegraded = "degraded"
)

type ReleaseStatus struct {
	Channel           string     `json:"channel"`
	Phase             string     `json:"phase"`
	Since             time.Time  `json:"since"`
	Ready             bool       `json:"ready"`
	Blockers          []string   `json:"blockers"`
	CoreMisses        int        `json:"core_misses"`
	EmergencyStop     bool       `json:"emergency_stop"`
	FailSafeVerified  bool       `json:"fail_safe_verified"`
	KernelPolicyState string     `json:"kernel_policy_state"`
	LastTransition    *time.Time `json:"last_transition,omitempty"`
	Detail            string     `json:"detail"`
	// FailSafeReason and FailSafeAt preserve why the platform fell back and when.
	//
	// Detail is recomputed on every refresh from the current blockers, so the cause of a
	// fail-safe was overwritten within seconds of it happening - and once the blockers
	// cleared it read "release gates satisfied" while the platform was still sitting in
	// Observe. The operator was told a fail-safe had fired and never told what fired it.
	//
	// The fall-back is a latch on the *phase*: a fault pauses automatic decisions and the
	// phase does not lift by itself until the cause has cleared and the calm has held. It is
	// deliberately not a latch on the kernel policy. The fall-back retains and verifies the
	// enforcement that was already in place, and the recovery path re-evaluates every
	// substantive gate before automatic decisions resume. Reporting a stale reason as the
	// present state was the original defect, so the cause is kept separate from the live
	// detail and carries the moment it was observed.
	FailSafeReason string     `json:"fail_safe_reason,omitempty"`
	FailSafeAt     *time.Time `json:"fail_safe_at,omitempty"`
	// NominalSince records when the platform last became free of substantive blockers. The
	// recovery soak is measured from this moment rather than from the fall-back, so a cause
	// that persisted for hours does not count as already soaked once it clears.
	NominalSince *time.Time `json:"nominal_since,omitempty"`
}

type ReleaseCore interface {
	Add(string) error
	Delete(string) error
	ClearBlocklist() error
	VerifyBlocklistEmpty() error
}

type ReleaseController struct {
	mu       sync.Mutex
	cfg      Config
	state    *State
	core     ReleaseCore
	policy   *PolicyStore
	settings *SettingsStore
	status   ReleaseStatus
}

func NewReleaseController(cfg Config, state *State, core ReleaseCore, policy *PolicyStore, settings *SettingsStore) *ReleaseController {
	now := time.Now().UTC()
	r := &ReleaseController{
		cfg: cfg, state: state, core: core, policy: policy, settings: settings,
		status: ReleaseStatus{
			Channel: cfg.Release.Channel, Phase: ReleasePhaseObserve, Since: now,
			KernelPolicyState: "unverified", Detail: "beta startup safety gate",
		},
	}
	r.refreshLocked()
	state.SetReleaseStatus(r.status)
	return r
}

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

func (r *ReleaseController) Status() ReleaseStatus {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.refreshLocked()
	r.state.SetReleaseStatus(r.status)
	return cloneReleaseStatus(r.status)
}

func cloneReleaseStatus(in ReleaseStatus) ReleaseStatus {
	out := in
	out.Blockers = append([]string(nil), in.Blockers...)
	return out
}

func (r *ReleaseController) runtimeSettingsLocked() RuntimeSettings {
	if r.settings != nil {
		return r.settings.Get()
	}
	return defaultRuntimeSettings(r.cfg)
}

func (r *ReleaseController) effectiveReleaseConfigLocked() ReleaseConfig {
	cfg := r.cfg.Release
	runtime := r.runtimeSettingsLocked()
	if runtime.FabricVersion >= fabricSettingsVersion {
		cfg.MinimumObserveSeconds = runtime.Protection.MinimumObserveSeconds
		cfg.MinimumCanarySeconds = runtime.Protection.MinimumCanarySeconds
		cfg.CoreFailureThreshold = runtime.Protection.CoreFailureThreshold
		cfg.MaxEvaluationDropPermille = runtime.Protection.MaxEvaluationDropPermille
		cfg.AutoDegrade = runtime.AutoDegrade
	}
	return cfg
}

func (r *ReleaseController) currentBlockersLocked(target string, includeDuration bool) []string {
	snap := r.state.Snapshot()
	releaseCfg := r.effectiveReleaseConfigLocked()
	var blockers []string
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
	if runtime.XDREnabled && snap.XDR.Degraded {
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
		elapsed := time.Since(r.status.Since)
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

func (r *ReleaseController) refreshLocked() {
	_, emergencyErr := os.Stat(r.cfg.Release.EmergencyStopFile)
	r.status.EmergencyStop = emergencyErr == nil
	blockers := r.currentBlockersLocked(r.status.Phase, false)
	r.status.Blockers = blockers
	r.status.Ready = len(blockers) == 0
	if r.status.EmergencyStop {
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

func (r *ReleaseController) Transition(target, confirmation, reason string) (ReleaseStatus, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
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
	r.state.SetReleaseStatus(r.status)
	r.state.AddEvent(Event{Severity: "high", Kind: "release.transition", Source: "release-gate", Message: fmt.Sprintf("Beta phase changed from %s to %s: %s", old.Phase, target, strings.TrimSpace(reason))})
	_ = oldXDR
	return cloneReleaseStatus(r.status), nil
}

// InitializeStartup establishes the kernel state the platform starts from.
//
// Starting in observe and reconciling the kernel to it removed every block the previous
// process had verified, so each control-plane restart disarmed the host until an operator
// promoted it again - the same fail-open as the automatic fall-back, on a routine operation
// that happens on every deploy.
//
// The persisted signed policy is the authority on what the kernel should hold. When it states
// enforcement, that enforcement is applied, verified and retained, and the platform starts in
// the degraded phase: the blocklist is live, new automatic decisions wait for the promotion
// gates, and the state says both of those things. Without a verified enforcement intent the
// kernel is verified empty and the platform starts in observe, exactly as before.
func (r *ReleaseController) InitializeStartup(policyEnforcement string, policyVerified bool) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, err := os.Stat(r.cfg.Release.EmergencyStopFile); err == nil {
		r.status.EmergencyStop = true
		return r.degradeLocked("emergency stop active at startup")
	}
	if !policyVerified || policyEnforcement != "enforce" {
		return r.initializeObserveLocked()
	}

	r.state.SetModes("unverified", "observe")
	if err := r.reconcileVerifiedLocked(); err != nil {
		// The signed policy asked for enforcement and it could not be confirmed. Nothing is
		// removed; the state is reported as unverified and the operator is required.
		r.markDegradedLocked("startup retained enforcement could not be verified", "unverified", false)
		r.state.AddEvent(Event{
			Severity: "critical", Kind: "release.startup_retention_unverified", Source: "release-gate",
			Message: "Signed policy states enforcement but the kernel state could not be verified; out-of-band verification required",
		})
		log.Printf("release: startup enforcement retention failed: %v", err)
		return fmt.Errorf("startup enforcement retention failed: %w", err)
	}
	if err := r.policy.Persist(r.cfg.Node.Name, "enforce", "observe", r.state.BlocksSnapshot()); err != nil {
		r.state.SetPolicyStatus(r.policy.Status())
		r.markDegradedLocked("startup retained policy persistence failed", "unverified", false)
		log.Printf("release: startup retained policy persistence failed: %v", err)
		return fmt.Errorf("startup retained policy persistence failed: %w", err)
	}
	r.state.SetPolicyStatus(r.policy.Status())
	r.state.SetModes("enforce", "observe")

	now := time.Now().UTC()
	r.status.Phase = ReleasePhaseDegraded
	r.status.Since = now
	r.status.LastTransition = &now
	r.status.Ready = false
	r.status.FailSafeVerified = true
	r.status.KernelPolicyState = "verified-enforce"
	r.status.Detail = "startup retained the verified kernel enforcement from the signed policy; automatic response stays paused until the promotion gates pass"
	r.refreshLocked()
	r.state.SetReleaseStatus(r.status)
	r.state.AddEvent(Event{
		Severity: "high", Kind: "release.startup_enforcement_retained", Source: "release-gate",
		Message: "Startup retained verified kernel enforcement from the signed policy; automatic response paused until promotion",
	})
	log.Printf("release: startup retained the verified kernel enforcement (fail-closed)")
	return nil
}

func (r *ReleaseController) initializeObserveLocked() error {
	if err := r.reconcileLocked("observe"); err != nil {
		r.markDegradedLocked("startup kernel observe verification failed", "unverified", false)
		return fmt.Errorf("startup kernel observe reconciliation failed: %w", err)
	}
	r.state.SetModes("observe", "observe")
	if err := r.policy.Persist(r.cfg.Node.Name, "observe", "observe", r.state.BlocksSnapshot()); err != nil {
		r.state.SetPolicyStatus(r.policy.Status())
		r.markDegradedLocked("startup observe policy persistence failed", "verified-empty", false)
		return fmt.Errorf("startup signed observe policy persistence failed: %w", err)
	}
	r.state.SetPolicyStatus(r.policy.Status())
	r.status.Phase = ReleasePhaseObserve
	r.status.FailSafeVerified = true
	r.status.KernelPolicyState = "verified-empty"
	r.status.Detail = "startup kernel blocklist verified empty"
	r.refreshLocked()
	r.state.SetReleaseStatus(r.status)
	r.state.AddEvent(Event{
		Severity: "info", Kind: "release.startup_verified", Source: "release-gate",
		Message: "Startup Observe policy persisted and kernel blocklist verified empty",
	})
	return nil
}

// reconcileVerifiedLocked confirms every block the platform owns with the kernel.
//
// reconcileLocked skips blocks already marked Enforced, which is an inference from an earlier
// pass. That inference is sound while this process owns the kernel state, and unsound the
// moment it does not: after a restart, or while recovering from a fall-back, the platform has
// no evidence about what the previous process left behind. The core exposes no read-back, so
// the confirmation has to be an application: ADD is an unconditional map insert and therefore
// idempotent, and re-applying is also what restores a block the kernel lost without telling
// anyone. A state is only called verified when the kernel said so in this pass.
func (r *ReleaseController) reconcileVerifiedLocked() error {
	if r.core == nil {
		return errors.New("kernel policy confirmation unavailable: core client is nil")
	}
	blocks := r.state.BlocksSnapshot()
	for _, block := range blocks {
		if err := r.core.Add(block.Target); err != nil {
			return fmt.Errorf("kernel policy confirmation failed for %s: %w", block.Target, err)
		}
		r.state.SetBlockEnforced(block.Target, true)
	}
	return nil
}

func (r *ReleaseController) reconcileLocked(enforcement string) error {
	if r.core == nil {
		return errors.New("kernel policy reconciliation unavailable: core client is nil")
	}
	blocks := r.state.BlocksSnapshot()
	if enforcement == "enforce" {
		applied := make([]string, 0, len(blocks))
		for _, block := range blocks {
			if block.Enforced {
				continue
			}
			if err := r.core.Add(block.Target); err != nil {
				var rollbackErrors []error
				for _, target := range applied {
					if rollbackErr := r.core.Delete(target); rollbackErr != nil {
						rollbackErrors = append(rollbackErrors, fmt.Errorf("rollback removal failed for %s: %w", target, rollbackErr))
						continue
					}
					r.state.SetBlockEnforced(target, false)
				}
				applyErr := fmt.Errorf("kernel policy reconciliation failed for %s: %w", block.Target, err)
				return errors.Join(append([]error{applyErr}, rollbackErrors...)...)
			}
			r.state.SetBlockEnforced(block.Target, true)
			applied = append(applied, block.Target)
		}
		return nil
	}
	// The privileged core clears its authoritative mutation ledger rather than
	// trusting the control-plane snapshot. This also removes orphaned entries
	// left by a failed compensating transaction.
	if err := r.core.ClearBlocklist(); err != nil {
		return fmt.Errorf("authoritative kernel blocklist clear failed: %w", err)
	}
	if err := r.core.VerifyBlocklistEmpty(); err != nil {
		return fmt.Errorf("kernel blocklist empty-state verification failed: %w", err)
	}
	for _, block := range blocks {
		if block.Enforced {
			r.state.SetBlockEnforced(block.Target, false)
		}
	}
	return nil
}

func (r *ReleaseController) ObserveCore(success bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	releaseCfg := r.effectiveReleaseConfigLocked()
	if success {
		r.status.CoreMisses = 0
		if r.status.Phase == ReleasePhaseDegraded && !r.status.FailSafeVerified {
			reason := strings.TrimSuffix(r.status.Detail, "; retained kernel policy could not be verified")
			_ = r.degradeLocked(reason)
		}
	} else if r.status.CoreMisses < releaseCfg.CoreFailureThreshold+1 {
		r.status.CoreMisses++
	}
	if releaseCfg.AutoDegrade && r.status.Phase != ReleasePhaseObserve && r.status.CoreMisses >= releaseCfg.CoreFailureThreshold {
		_ = r.degradeLocked("authenticated core heartbeat threshold exceeded")
	}
	r.refreshLocked()
	r.state.SetReleaseStatus(r.status)
}

func (r *ReleaseController) Evaluate() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.runtimeSettingsLocked().AutoDegrade || r.status.Phase == ReleasePhaseObserve || r.status.Phase == ReleasePhaseDegraded {
		r.trackNominalLocked()
		r.recoverIfGatesPassLocked()
		r.refreshLocked()
		r.state.SetReleaseStatus(r.status)
		return
	}
	if blockers := r.currentBlockersLocked(r.status.Phase, false); len(blockers) > 0 {
		_ = r.degradeLocked(strings.Join(blockers, "; "))
	}
	r.trackNominalLocked()
	r.refreshLocked()
	r.state.SetReleaseStatus(r.status)
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
		now := time.Now().UTC()
		r.status.NominalSince = &now
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
	if r.status.KernelPolicyState != "verified-enforce" || !r.status.FailSafeVerified {
		return
	}
	releaseCfg := r.effectiveReleaseConfigLocked()
	if r.status.NominalSince == nil {
		return
	}
	if elapsed := time.Since(*r.status.NominalSince); elapsed < time.Duration(releaseCfg.MinimumObserveSeconds)*time.Second {
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
	elapsed := time.Since(r.status.Since)
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
