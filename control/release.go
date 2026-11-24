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
	Channel  string    `json:"channel"`
	Phase    string    `json:"phase"`
	Since    time.Time `json:"since"`
	Ready    bool      `json:"ready"`
	Blockers []string  `json:"blockers"`
	// PolicyQuarantined, PolicyQuarantineDetail and PolicyQuarantineEvidence report the
	// fail-closed startup quarantine of a policy document that could not be verified
	// (FIND-013 / VGT-AUDIT-20261114-GD51). While the quarantine is active the document on
	// disk is forensic evidence, not state: no automatic path may re-sign it, and only an
	// explicit operator action resolves it.
	PolicyQuarantined        bool   `json:"policy_quarantined,omitempty"`
	PolicyQuarantineDetail   string `json:"policy_quarantine_detail,omitempty"`
	PolicyQuarantineEvidence string `json:"policy_quarantine_evidence,omitempty"`
	// AutoDegradeHeld reports that blockers are present while the operator disabled the
	// automatic degradation. It separates "nothing to report" from "reported and
	// intentionally not acted upon" (FIND-014).
	AutoDegradeHeld   bool       `json:"auto_degrade_held,omitempty"`
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
	// monoSince/monoNominal keep the soak decisions on the monotonic clock. The public
	// release status is serialized as UTC, which strips the monotonic reading; without a
	// parallel anchor a forward wall-clock step could shorten a safety soak (F-26 /
	// G-STATE-06).
	monoSince   time.Time
	monoNominal *time.Time
	// exposure is the kernel-advisory measurement. It is attached after construction because the
	// controller is built before the server that owns the measurement, and it stays optional so the
	// release tests can exercise the gate without a host.
	exposure *kernelExposureCache
	// kernelReconciledHook runs after a successful kernel reconciliation. The
	// reconcile owns the kernel blocklist: enforcing re-adds the signed policy
	// blocks, an observe/degrade clears the list. Feed-generated blocks are not
	// part of that signed policy, so without this hook every restart or phase
	// transition silently dropped the validated threat-intelligence publication
	// until the next refresh window.
	kernelReconciledHook func()
	enforceSettingsHook  func(RuntimeSettings)
}

// AttachKernelExposure gives the release gate the kernel-advisory measurement it scores against.
func (r *ReleaseController) AttachKernelExposure(exposure *kernelExposureCache) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.exposure = exposure
}

func NewReleaseController(cfg Config, state *State, core ReleaseCore, policy *PolicyStore, settings *SettingsStore) *ReleaseController {
	mono := time.Now()
	now := mono.UTC()
	r := &ReleaseController{
		cfg: cfg, state: state, core: core, policy: policy, settings: settings,
		monoSince: mono,
		status: ReleaseStatus{
			Channel: cfg.Release.Channel, Phase: ReleasePhaseObserve, Since: now,
			KernelPolicyState: "unverified", Detail: "beta startup safety gate",
		},
	}
	r.refreshLocked()
	state.SetReleaseStatus(r.status)
	return r
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

// InitializeStartup establishes the kernel state the platform starts from.
//
// Starting in observe and reconciling the kernel to it removed every block the previous
// process had verified, so each control-plane restart disarmed the host until an operator
// promoted it again - the same fail-open as the automatic fall-back, on a routine operation
// that happens on every deploy.
//
// The persisted signed policy is the authority on what the kernel should hold:
//
//   - verified enforcement          -> applied, verified and retained; degraded phase
//   - verified, non-enforcing intent -> verified-empty kernel, observe phase (as before)
//   - unverifiable / missing policy  -> enforcement is RETAINED, the phase is degraded and the
//     document is quarantined unmodified. An unreadable policy document is not an observe
//     intent. Clearing the kernel on a corrupt or manipulated state file would let an attacker
//     disarm the host with a restart (F-07 / CHAIN-003), and automatically re-signing a
//     tampered document would destroy the evidence and legitimise the tampering (FIND-013).
//     This path uses the same retention primitive as degradeLocked, minus every write to the
//     policy document, and requires an explicit operator action to release.
func (r *ReleaseController) InitializeStartup(policyEnforcement string, policyVerified bool) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	// The unverifiable-policy branch has to run before the emergency-stop branch: both end in
	// the degraded phase, but only this path must never persist the policy. Letting
	// degradeLocked handle it first would re-sign the tampered document with the platform's
	// own key (FIND-013).
	if !policyVerified {
		return r.quarantineUnverifiedPolicyLocked("startup: signed policy intent could not be verified")
	}
	if _, err := os.Stat(r.cfg.Release.EmergencyStopFile); err == nil {
		r.status.EmergencyStop = true
		return r.degradeLocked("emergency stop active at startup")
	}
	if policyEnforcement != "enforce" {
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
	r.monoSince = time.Now()
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

// quarantineUnverifiedPolicyLocked enters the fail-closed startup quarantine for a policy
// document that could not be verified (FIND-013 / VGT-AUDIT-20261114-GD51).
//
// The startup degradation used to run through degradeLocked, which persists a freshly signed
// document. On a tampered policy.json that overwrote the attacker's own artifact with a valid
// observe policy: the forensic trace was destroyed and the platform was re-signed into an
// intent nobody had verified. The quarantine is deliberately different:
//
//   - the document on disk is never rewritten, re-signed or silently "repaired"; it is
//     preserved unmodified and a one-time forensic copy (0600) is taken, so even a later
//     explicit recovery cannot destroy the evidence;
//   - the kernel enforcement is retained and confirmed - a host that was protecting keeps
//     protecting - while automatic decisions stop (fail-closed in memory);
//   - every automatic path that would persist a new signed policy refuses until an explicit
//     operator action resolves the quarantine. Autonomous recovery is not a recovery path for
//     a trust decision.
//
// The caller holds r.mu.
func (r *ReleaseController) quarantineUnverifiedPolicyLocked(reason string) error {
	r.status.PolicyQuarantined = true
	r.status.PolicyQuarantineDetail = reason
	evidence := ""
	if copyPath, err := r.preservePolicyDocumentLocked(); err != nil {
		// The copy is evidence hygiene, not the safety property: the original is untouched
		// either way. A failed copy is still reported, so the operator does not believe one
		// exists when it does not.
		r.state.AddEvent(Event{
			Severity: "critical", Kind: "policy.quarantine_evidence_failed", Source: "release-gate",
			Message: "Unverifiable signed policy could not be copied for forensics; the original is untouched: " + err.Error(),
		})
		log.Printf("release: policy quarantine: forensic copy failed (the original is still untouched): %v", err)
	} else if copyPath != "" {
		evidence = copyPath
		r.status.PolicyQuarantineEvidence = copyPath
	}

	// Fail-closed in memory, never on disk: automatic decisions stop, the kernel keeps what it
	// can confirm, and the policy document is not touched. Note the difference to the old
	// path: no Persist follows this reconciliation.
	r.state.SetModes("unverified", "observe")
	if err := r.reconcileVerifiedLocked(); err != nil {
		// Nothing was removed - the kernel still holds whatever it held - but that state is
		// not confirmed, so it is reported as unverified and the operator is required.
		detail := reason + "; retained kernel policy could not be verified"
		r.markDegradedLocked(detail, "unverified", false)
		r.state.AddEvent(Event{
			Severity: "critical", Kind: "release.quarantine_unverified", Source: "release-gate",
			Message: "Unverifiable signed policy is quarantined and the retained kernel enforcement could not be verified; out-of-band verification required: " + reason,
		})
		log.Printf("release: policy quarantine active; retained kernel enforcement unverified: %s", reason)
		r.refreshLocked()
		r.state.SetReleaseStatus(r.status)
		return fmt.Errorf("policy quarantine: retained kernel policy could not be verified: %w", err)
	}
	r.state.SetModes("enforce", "observe")
	r.markDegradedLocked(reason, "verified-enforce", true)
	if r.policy != nil {
		r.state.SetPolicyStatus(r.policy.Status())
	}
	r.refreshLocked()
	r.state.SetReleaseStatus(r.status)
	r.state.AddEvent(Event{
		Severity: "critical", Kind: "policy.quarantined", Source: "release-gate",
		Message: "Signed policy could not be verified. The document on disk was preserved unmodified and quarantined in memory · " +
			"no automatic re-signing · kernel enforcement retained and automatic decisions paused · " +
			"recovery is an explicit operator action: investigate the document and its forensic copy (" + quarantineEvidenceLabel(evidence) + "), " +
			"verify host integrity, restore a trusted signed policy backup, then re-establish the policy with the explicit RETURN:OBSERVE operator transition",
	})
	log.Printf("release: signed policy quarantined unmodified (never re-signed); evidence copy %q; kernel enforcement retained. OPERATOR RECOVERY REQUIRED: investigate the policy document/backup and re-establish the policy with the explicit RETURN:OBSERVE transition", quarantineEvidenceLabel(evidence))
	return nil
}

func quarantineEvidenceLabel(path string) string {
	if path == "" {
		return "none created"
	}
	return path
}

// preservePolicyDocumentLocked copies the unverifiable policy document aside before anything
// could legitimately replace it. The original file is opened read-only and never modified; the
// copy is created 0600 and exclusive, so a pre-planted file or symlink at the evidence name
// cannot redirect the write.
func (r *ReleaseController) preservePolicyDocumentLocked() (string, error) {
	stateFile := strings.TrimSpace(r.cfg.Policy.StateFile)
	if stateFile == "" {
		return "", nil
	}
	info, err := os.Stat(stateFile)
	if errors.Is(err, os.ErrNotExist) {
		// A missing document is unverifiable too, but there is nothing to preserve.
		return "", nil
	}
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("policy state %s is not a regular file", stateFile)
	}
	const maxForensicPolicyBytes = 8 << 20
	if info.Size() > maxForensicPolicyBytes {
		return "", fmt.Errorf("policy state %s is larger than %d bytes", stateFile, maxForensicPolicyBytes)
	}
	data, err := os.ReadFile(stateFile)
	if err != nil {
		return "", err
	}
	copyPath := stateFile + ".tampered." + time.Now().UTC().Format("20060102T150405.000000000Z")
	if err := writePolicyEvidenceFile(copyPath, data); err != nil {
		if !errors.Is(err, os.ErrExist) {
			return "", err
		}
		// A collision on the nanosecond stamp is not worth losing the evidence over; one
		// retry is enough, and O_EXCL still refuses to overwrite anything.
		copyPath = stateFile + ".tampered." + time.Now().UTC().Format("20060102T150405.000000000Z")
		if retryErr := writePolicyEvidenceFile(copyPath, data); retryErr != nil {
			return "", errors.Join(err, retryErr)
		}
	}
	return copyPath, nil
}

func writePolicyEvidenceFile(path string, data []byte) error {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err = file.Write(data); err == nil {
		err = file.Sync()
	}
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		_ = os.Remove(path)
		return err
	}
	return os.Chmod(path, 0o600)
}

// clearPolicyQuarantineLocked ends the quarantine after the explicit RETURN:OBSERVE operator
// transition persisted a fresh, verified policy document. It is the only path allowed to end it:
// automatic recovery, the automatic re-arm and the emergency-stop clear all refuse while the
// quarantine is active. The forensic copy is deliberately kept - the evidence has to outlive the
// recovery.
func (r *ReleaseController) clearPolicyQuarantineLocked(method string) {
	if !r.status.PolicyQuarantined {
		return
	}
	evidence := r.status.PolicyQuarantineEvidence
	r.status.PolicyQuarantined = false
	r.status.PolicyQuarantineDetail = ""
	r.state.AddEvent(Event{
		Severity: "high", Kind: "policy.quarantine_cleared", Source: "operator",
		Message: "Policy quarantine cleared by an explicit operator action (" + method + "); a fresh signed policy was persisted. Forensic copy kept: " + quarantineEvidenceLabel(evidence),
	})
	log.Printf("release: policy quarantine cleared by explicit operator action (%s); forensic copy kept: %s", method, quarantineEvidenceLabel(evidence))
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

// SetKernelReconciledHook installs the post-reconcile callback (threat-intel
// kernel republication). It is called with the release mutex held.
func (r *ReleaseController) SetKernelReconciledHook(hook func()) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.kernelReconciledHook = hook
}

// SetEnforceSettingsHook installs the callback invoked (outside r.mu) after
// Transition(enforce) promotes untouched V6 subsystems into their safe armed modes.
func (r *ReleaseController) SetEnforceSettingsHook(hook func(RuntimeSettings)) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.enforceSettingsHook = hook
}

func (r *ReleaseController) notifyKernelReconciledLocked() {
	if r.kernelReconciledHook != nil {
		r.kernelReconciledHook()
	}
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
		r.notifyKernelReconciledLocked()
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
	r.notifyKernelReconciledLocked()
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

// ReconcileVerifiedPolicy re-applies and re-confirms the verified kernel policy. It is the canonical
// repair for the enforcement module of the startup self-check.
func (r *ReleaseController) ReconcileVerifiedPolicy() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.reconcileVerifiedLocked()
}
