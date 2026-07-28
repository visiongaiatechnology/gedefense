package main

import (
	"errors"
	"fmt"
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

func (r *ReleaseController) currentBlockersLocked(target string, includeDuration bool) []string {
	snap := r.state.Snapshot()
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
	for _, block := range snap.Blocks {
		// Enforce promotion performs an atomic best-effort reconciliation below.
		// Only stale kernel rules while leaving Enforce are a pre-transition blocker.
		if target != ReleasePhaseEnforce && block.Enforced {
			blockers = append(blockers, "kernel policy reconciliation is pending")
			break
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
	}
	if r.status.CoreMisses >= r.cfg.Release.CoreFailureThreshold {
		blockers = append(blockers, "core heartbeat failure threshold reached")
	}
	if r.status.Phase == ReleasePhaseDegraded && !r.status.FailSafeVerified {
		blockers = append(blockers, "fail-safe transition is not verified")
	}
	if (r.status.Phase == ReleasePhaseObserve || r.status.Phase == ReleasePhaseDegraded) &&
		(!r.status.FailSafeVerified || r.status.KernelPolicyState != "verified-empty") {
		blockers = append(blockers, "kernel observe state is not verified")
	}
	if snap.XDR.EvaluationsTotal > 0 {
		dropPermille := snap.XDR.EvaluationDrops * 1000 / snap.XDR.EvaluationsTotal
		if dropPermille > uint64(r.cfg.Release.MaxEvaluationDropPermille) {
			blockers = append(blockers, fmt.Sprintf("XDR evaluation drop rate is %d permille", dropPermille))
		}
	}
	if includeDuration {
		elapsed := time.Since(r.status.Since)
		switch target {
		case ReleasePhaseCanary:
			minimum := time.Duration(r.cfg.Release.MinimumObserveSeconds) * time.Second
			if r.status.Phase != ReleasePhaseObserve && r.status.Phase != ReleasePhaseDegraded {
				blockers = append(blockers, "canary promotion requires observe phase")
			} else if elapsed < minimum {
				blockers = append(blockers, fmt.Sprintf("observe soak time remaining: %s", (minimum-elapsed).Round(time.Second)))
			}
		case ReleasePhaseEnforce:
			minimum := time.Duration(r.cfg.Release.MinimumCanarySeconds) * time.Second
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
	r.status.FailSafeVerified = newEnforcement == "observe"
	if newEnforcement == "observe" {
		r.status.KernelPolicyState = "verified-empty"
	} else {
		r.status.KernelPolicyState = "verified-enforce"
	}
	r.state.SetReleaseStatus(r.status)
	r.state.AddEvent(Event{Severity: "high", Kind: "release.transition", Source: "release-gate", Message: fmt.Sprintf("Beta phase changed from %s to %s: %s", old.Phase, target, strings.TrimSpace(reason))})
	_ = oldXDR
	return cloneReleaseStatus(r.status), nil
}

func (r *ReleaseController) InitializeObserve() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.status.EmergencyStop {
		return r.degradeLocked("emergency stop active at startup")
	}
	r.state.SetModes("unverified", "observe")
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
	if success {
		r.status.CoreMisses = 0
		if r.status.Phase == ReleasePhaseDegraded && !r.status.FailSafeVerified {
			reason := strings.TrimSuffix(r.status.Detail, "; kernel fail-safe verification failed")
			_ = r.degradeLocked(reason)
		}
	} else if r.status.CoreMisses < r.cfg.Release.CoreFailureThreshold+1 {
		r.status.CoreMisses++
	}
	if r.runtimeSettingsLocked().AutoDegrade && r.status.Phase != ReleasePhaseObserve && r.status.CoreMisses >= r.cfg.Release.CoreFailureThreshold {
		_ = r.degradeLocked("authenticated core heartbeat threshold exceeded")
	}
	r.refreshLocked()
	r.state.SetReleaseStatus(r.status)
}

func (r *ReleaseController) Evaluate() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.runtimeSettingsLocked().AutoDegrade || r.status.Phase == ReleasePhaseObserve || r.status.Phase == ReleasePhaseDegraded {
		r.refreshLocked()
		r.state.SetReleaseStatus(r.status)
		return
	}
	if blockers := r.currentBlockersLocked(r.status.Phase, false); len(blockers) > 0 {
		_ = r.degradeLocked(strings.Join(blockers, "; "))
	}
	r.refreshLocked()
	r.state.SetReleaseStatus(r.status)
}

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
	r.state.SetReleaseStatus(r.status)
}

func (r *ReleaseController) degradeLocked(reason string) error {
	// Disable all new active XDR decisions before attempting remote kernel
	// reconciliation. "unverified" is intentional: it cannot be mistaken for
	// Observe while stale XDP rules may still exist.
	r.state.SetModes("unverified", "observe")
	if err := r.reconcileLocked("observe"); err != nil {
		detail := reason + "; kernel fail-safe verification failed"
		r.markDegradedLocked(detail, "unverified", false)
		r.state.AddEvent(Event{
			Severity: "critical", Kind: "release.fail_safe_unverified", Source: "release-gate",
			Message: "Active response state is unverified; out-of-band recovery required: " + reason,
		})
		return fmt.Errorf("fail-safe kernel reconciliation failed: %w", err)
	}
	r.status.KernelPolicyState = "verified-empty"
	r.state.SetModes("observe", "observe")
	if err := r.policy.Persist(r.cfg.Node.Name, "observe", "observe", r.state.BlocksSnapshot()); err != nil {
		r.state.SetPolicyStatus(r.policy.Status())
		detail := reason + "; observe policy persistence failed"
		r.markDegradedLocked(detail, "verified-empty", false)
		r.state.AddEvent(Event{
			Severity: "critical", Kind: "release.fail_safe_policy_failed", Source: "release-gate",
			Message: "Kernel blocklist is empty but fail-safe policy persistence failed: " + reason,
		})
		return fmt.Errorf("fail-safe observe policy persistence failed: %w", err)
	}
	r.state.SetPolicyStatus(r.policy.Status())
	r.markDegradedLocked(reason, "verified-empty", true)
	r.state.AddEvent(Event{
		Severity: "critical", Kind: "release.auto_degraded", Source: "release-gate",
		Message: "Active beta response disabled and kernel blocklist verified empty: " + reason,
	})
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
