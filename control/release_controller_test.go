// STATUS: DIAMANT VGT SUPREME
package main

// Regression tests for VGT-AUDIT-20261114-GD51:
//
//	FIND-013 (HIGH): an unverifiable policy document was overwritten and re-signed by the
//	                 automatic degradation path, destroying the forensic evidence and pinning
//	                 the platform to a state nobody had verified.
//	FIND-014 (HIGH): Evaluate() stopped early when AutoDegrade was disabled, which suppressed
//	                 the blocker evaluation and its reporting instead of only the automatic
//	                 mode switch.

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"
)

func policyArtifactSHA256(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	sum := sha256.Sum256(data)
	return fmt.Sprintf("%x", sum)
}

// tamperedPolicyStartupFixture builds a node that had a valid signed enforcement policy on
// disk and was then tampered with, exactly as an attacker with write access to the state
// directory would leave it. Load() now fails closed, which is what main() passes to
// InitializeStartup as policyVerified=false.
func tamperedPolicyStartupFixture(t *testing.T) (Config, *State, *PolicyStore, *ReleaseController, *releaseCoreStub, []byte) {
	t.Helper()
	dir := t.TempDir()
	cfg := defaultConfig()
	cfg.Policy.StorageKeyFile = ""
	cfg.Node.Name = "policy-tamper-test"
	cfg.Release.MinimumObserveSeconds = 0
	cfg.Release.MinimumCanarySeconds = 0
	cfg.Release.EmergencyStopFile = filepath.Join(dir, "EMERGENCY_STOP")
	cfg.Policy.StateFile = filepath.Join(dir, "policy.json")
	cfg.Policy.SigningKeyFile = filepath.Join(dir, "policy.key")
	cfg.Policy.PublicKeyFile = filepath.Join(dir, "policy.pub")
	if !cfg.Policy.RequireSigned {
		t.Fatal("the fixture requires the signed-policy gate to be enabled")
	}

	state := NewState("test", cfg)
	state.SetCore(true, "native")
	state.SetAllowlistReady(true)
	verifiedAt := time.Now().UTC()
	state.SetSensorCoverage(SensorCoverage{
		Name: "xdp_ingress", Layer: LayerIngressNetwork, Status: CoverageOnline, Required: true,
		LastOK: &verifiedAt, SelfTest: "pass", CoverageReason: "verified tamper-test ingress fixture",
	})

	policy, err := NewPolicyStore(cfg.Policy)
	if err != nil {
		t.Fatalf("policy store: %v", err)
	}
	// A real previous run left a signed enforcement document behind.
	if err := policy.Persist(cfg.Node.Name, "enforce", "observe", nil); err != nil {
		t.Fatalf("seed signed policy: %v", err)
	}
	raw, err := os.ReadFile(cfg.Policy.StateFile)
	if err != nil {
		t.Fatalf("read seeded policy: %v", err)
	}
	// Both words have seven letters, so the document stays structurally valid JSON while the
	// signed payload changes: this is a genuine tamper, not a parse failure.
	tampered := bytes.Replace(raw, []byte(`"enforce"`), []byte(`"observe"`), 1)
	if bytes.Equal(tampered, raw) {
		t.Fatal("fixture did not modify the signed payload")
	}
	if err := os.WriteFile(cfg.Policy.StateFile, tampered, 0o600); err != nil {
		t.Fatalf("tamper policy document: %v", err)
	}

	// Retention is about the enforcement the host already had, so the fixture owns a block.
	if _, err := state.AddBlock("203.0.113.23/32", "retained across the policy tamper", "test", time.Hour, false, cfg.Defense.MaxBlockEntries); err != nil {
		t.Fatalf("seed retained block: %v", err)
	}

	restarted, err := NewPolicyStore(cfg.Policy)
	if err != nil {
		t.Fatalf("policy store after tamper: %v", err)
	}
	if _, err := restarted.Load(); err == nil {
		t.Fatal("the tampered policy document was accepted as verified")
	}
	if restarted.Status().Verified {
		t.Fatalf("status reports a verified policy after tampering: %+v", restarted.Status())
	}
	state.SetPolicyStatus(restarted.Status())

	core := &releaseCoreStub{}
	release := NewReleaseController(cfg, state, core, restarted, nil)
	return cfg, state, restarted, release, core, tampered
}

// TestStartupWithTamperedPolicyIsQuarantinedAndNotResigned is FIND-013's core acceptance test.
//
// The old path degraded through degradeLocked, which calls PolicyStore.Persist and therefore
// overwrote the tampered document with a freshly signed observe policy. The test hashes the
// policy artifacts before and after startup: the tampered document, the generation floor and
// the last-known-good copy must be byte-identical, a forensic copy must exist, and the
// blocker must be reported instead of the degradation silently "repairing" the file.
func TestStartupWithTamperedPolicyIsQuarantinedAndNotResigned(t *testing.T) {
	cfg, state, policy, release, core, tampered := tamperedPolicyStartupFixture(t)

	artifacts := []string{cfg.Policy.StateFile, cfg.Policy.StateFile + ".floor", cfg.Policy.StateFile + ".lastgood"}
	before := map[string]string{}
	for _, path := range artifacts {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("expected policy artifact %s from the previous run: %v", path, err)
		}
		before[path] = policyArtifactSHA256(t, path)
	}

	// main() passes exactly this pair: empty intent plus the failed verification.
	if err := release.InitializeStartup("", policy.Status().Verified); err != nil {
		t.Fatalf("an unverifiable policy must keep the platform running in quarantine: %v", err)
	}

	for _, path := range artifacts {
		if got := policyArtifactSHA256(t, path); got != before[path] {
			t.Fatalf("%s changed during startup (before=%s after=%s): the unverified policy document was rewritten or re-signed", path, before[path], got)
		}
	}
	onDisk, err := os.ReadFile(cfg.Policy.StateFile)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(onDisk, tampered) {
		t.Fatal("the tampered policy document bytes were replaced")
	}

	copies, err := filepath.Glob(cfg.Policy.StateFile + ".tampered.*")
	if err != nil {
		t.Fatal(err)
	}
	if len(copies) != 1 {
		t.Fatalf("expected exactly one one-time forensic copy, got %v", copies)
	}
	copied, err := os.ReadFile(copies[0])
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(copied, tampered) {
		t.Fatal("the forensic copy does not preserve the tampered bytes")
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(copies[0])
		if err != nil {
			t.Fatal(err)
		}
		if perm := info.Mode().Perm(); perm != 0o600 {
			t.Fatalf("forensic copy mode = %o, want 0600", perm)
		}
	}

	status := release.Status()
	if status.Phase != ReleasePhaseDegraded {
		t.Fatalf("phase = %s, want degraded", status.Phase)
	}
	if !status.PolicyQuarantined {
		t.Fatalf("the unverifiable policy is not reported as quarantined: %+v", status)
	}
	if status.PolicyQuarantineEvidence != copies[0] {
		t.Fatalf("reported evidence = %q, want %q", status.PolicyQuarantineEvidence, copies[0])
	}
	if !slices.Contains(status.Blockers, "signed policy is not verified") {
		t.Fatalf("the tamper is not a visible blocker: %v", status.Blockers)
	}
	if !strings.Contains(strings.Join(status.Blockers, " | "), "quarantined") {
		t.Fatalf("the quarantine is not a visible blocker: %v", status.Blockers)
	}
	if status.FailSafeReason == "" || status.FailSafeAt == nil {
		t.Fatalf("the fall-back cause was not preserved: %+v", status)
	}

	// No new signature: a fresh store still refuses the document.
	fresh, err := NewPolicyStore(cfg.Policy)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fresh.Load(); err == nil {
		t.Fatal("the document was re-signed during startup: it verifies after quarantine")
	}
	if policy.Status().Verified {
		t.Fatal("the quarantined policy became verified in memory")
	}

	// In-memory fail-closed: automatic decisions stop, the confirmed kernel enforcement is
	// retained, and nothing is released. "enforce" must not silently become "observe".
	if core.clearCount() != 0 {
		t.Fatal("the quarantine released the kernel blocklist")
	}
	if targets := core.addedTargets(); !slices.Contains(targets, "203.0.113.23/32") {
		t.Fatalf("the retained block was not confirmed with the kernel: %v", targets)
	}
	enforcement, xdrMode := state.Modes()
	if xdrMode != "observe" {
		t.Fatalf("automatic XDR response mode = %s, want observe in quarantine", xdrMode)
	}
	if enforcement == "observe" {
		t.Fatal("the in-memory enforcement switched silently to observe")
	}
	if enforcement != "enforce" {
		t.Fatalf("retained enforcement state = %q, want enforce or unverified", enforcement)
	}
	if status.KernelPolicyState != "verified-enforce" || !status.FailSafeVerified {
		t.Fatalf("the retained kernel enforcement was not verified: %+v", status)
	}

	// The state snapshot served to the dashboard carries the same quarantine and blocker.
	snapshot := state.Snapshot()
	if !snapshot.Release.PolicyQuarantined {
		t.Fatal("the dashboard snapshot does not carry the policy quarantine")
	}
	if !slices.Contains(snapshot.Release.Blockers, "signed policy is not verified") {
		t.Fatalf("the dashboard snapshot hides the tamper blocker: %v", snapshot.Release.Blockers)
	}
}

// TestQuarantinedPolicyIsNotReSignedByAutomaticPaths pins the second half of FIND-013: it is
// not enough that the startup path does not write - every automatic persist has to refuse while
// the quarantine is active.
func TestQuarantinedPolicyIsNotReSignedByAutomaticPaths(t *testing.T) {
	cfg, state, policy, release, core, _ := tamperedPolicyStartupFixture(t)
	if err := release.InitializeStartup("", false); err != nil {
		t.Fatalf("startup quarantine failed: %v", err)
	}
	policyHash := policyArtifactSHA256(t, cfg.Policy.StateFile)

	// A later, unrelated automatic fall-back must not persist the signed policy either.
	if err := release.FailSafe("authenticated core heartbeat threshold exceeded"); err != nil {
		t.Fatalf("fail-safe during quarantine: %v", err)
	}
	if got := policyArtifactSHA256(t, cfg.Policy.StateFile); got != policyHash {
		t.Fatal("an automatic fall-back re-signed the quarantined policy document")
	}
	status := release.Status()
	if status.Phase != ReleasePhaseDegraded || !status.PolicyQuarantined {
		t.Fatalf("the quarantine did not survive the automatic fall-back: %+v", status)
	}
	if core.clearCount() != 0 {
		t.Fatal("the automatic fall-back released the kernel blocklist under quarantine")
	}

	// An automatic recovery may not claim the state either, even after a long calm.
	release.mu.Lock()
	at := time.Now().Add(-24 * time.Hour)
	release.status.NominalSince = &at
	release.status.Since = at
	release.mu.Unlock()
	release.Evaluate()
	if got := policyArtifactSHA256(t, cfg.Policy.StateFile); got != policyHash {
		t.Fatal("an automatic evaluation re-signed the quarantined policy document")
	}
	if phase := release.Status().Phase; phase != ReleasePhaseDegraded {
		t.Fatalf("automatic recovery left the quarantine: phase=%s", phase)
	}
	if _, err := release.ReArmVerified("startup self-check verified every module"); err == nil {
		t.Fatal("automatic re-arm persisted over a quarantined policy")
	}
	if got := policyArtifactSHA256(t, cfg.Policy.StateFile); got != policyHash {
		t.Fatal("automatic re-arm re-signed the quarantined policy document")
	}

	// The shared automatic-persist funnel (block expiry, automatic containment, operator
	// block mutations) refuses as well instead of re-signing the document.
	if err := persistPolicy(policy, cfg, state); !errors.Is(err, errPolicyUnverified) {
		t.Fatalf("persistPolicy returned %v, want errPolicyUnverified", err)
	}
	if got := policyArtifactSHA256(t, cfg.Policy.StateFile); got != policyHash {
		t.Fatal("the automatic-persist funnel re-signed the quarantined policy document")
	}

	// Nothing may promote the platform out of the quarantine automatically.
	if _, err := release.Transition(ReleasePhaseCanary, "PROMOTE:CANARY", "promotion during a policy quarantine"); err == nil {
		t.Fatal("a promotion bypassed the policy quarantine")
	}
}

// TestOperatorRecoveryClearsPolicyQuarantineExplicitly proves that a recovery exists and that it
// is explicit: only a typed operator transition may re-establish a signed policy, and the
// forensic evidence survives it.
func TestOperatorRecoveryClearsPolicyQuarantineExplicitly(t *testing.T) {
	cfg, _, policy, release, _, _ := tamperedPolicyStartupFixture(t)
	if err := release.InitializeStartup("", false); err != nil {
		t.Fatalf("startup quarantine failed: %v", err)
	}
	evidence, err := filepath.Glob(cfg.Policy.StateFile + ".tampered.*")
	if err != nil || len(evidence) != 1 {
		t.Fatalf("fixture did not create the forensic copy: %v %v", evidence, err)
	}

	// A wrong phrase is not a recovery.
	if _, err := release.Transition(ReleasePhaseObserve, "PROMOTE:CANARY", "wrong confirmation must not recover"); err == nil {
		t.Fatal("an invalid confirmation recovered the quarantine")
	}
	if !release.Status().PolicyQuarantined {
		t.Fatal("an invalid confirmation cleared the quarantine")
	}

	status, err := release.Transition(ReleasePhaseObserve, "RETURN:OBSERVE", "operator investigated the tampered policy and re-establishes it deliberately")
	if err != nil {
		t.Fatalf("the explicit operator recovery was refused: %v", err)
	}
	if status.PolicyQuarantined {
		t.Fatalf("the explicit operator transition did not clear the quarantine: %+v", status)
	}
	if !policy.Status().Verified {
		t.Fatal("the explicit operator recovery did not persist a verified policy")
	}
	fresh, err := NewPolicyStore(cfg.Policy)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fresh.Load(); err != nil {
		t.Fatalf("the explicitly restored policy does not verify: %v", err)
	}
	if _, err := os.Stat(evidence[0]); err != nil {
		t.Fatalf("the explicit recovery removed the forensic evidence: %v", err)
	}
}

// TestEmergencyStopClearDoesNotBypassPolicyQuarantine closes the verify-policy gap in FIND-013.
//
// ClearEmergencyStop persists an observe policy and releases the kernel blocklist. Under the
// startup quarantine that was a second, weaker recovery token: it needed no RETURN:OBSERVE and it
// worked even when no emergency-stop marker was active at all. It has to refuse and leave the
// marker, the document, the kernel blocklist and the modes exactly where they were.
func TestEmergencyStopClearDoesNotBypassPolicyQuarantine(t *testing.T) {
	t.Run("quarantine without an active emergency stop", func(t *testing.T) {
		cfg, state, policy, release, core, _ := tamperedPolicyStartupFixture(t)
		if err := release.InitializeStartup("", false); err != nil {
			t.Fatalf("startup quarantine failed: %v", err)
		}
		before := release.Status()
		policyBefore := policyArtifactSHA256(t, cfg.Policy.StateFile)
		enforcementBefore, xdrBefore := state.Modes()
		clearedBefore := core.clearCount()

		if _, err := release.ClearEmergencyStop("CLEAR:EMERGENCY-STOP", "operator tries to clear a stop that is not active"); err == nil {
			t.Fatal("the emergency-stop clear released a quarantined policy without an explicit RETURN:OBSERVE")
		}

		if got := policyArtifactSHA256(t, cfg.Policy.StateFile); got != policyBefore {
			t.Fatal("the refused emergency-stop clear re-signed the quarantined policy document")
		}
		if policy.Status().Verified {
			t.Fatal("the quarantined policy became verified through the emergency-stop clear")
		}
		after := release.Status()
		if !after.PolicyQuarantined {
			t.Fatalf("the emergency-stop clear cleared the quarantine: %+v", after)
		}
		if after.PolicyQuarantineEvidence != before.PolicyQuarantineEvidence {
			t.Fatalf("the evidence reference changed: %q -> %q", before.PolicyQuarantineEvidence, after.PolicyQuarantineEvidence)
		}
		if enforcement, xdrMode := state.Modes(); enforcement != enforcementBefore || xdrMode != xdrBefore {
			t.Fatalf("the refused clear changed the modes: %s/%s -> %s/%s", enforcementBefore, xdrBefore, enforcement, xdrMode)
		}
		if core.clearCount() != clearedBefore {
			t.Fatal("the refused emergency-stop clear released the kernel blocklist")
		}
		fresh, err := NewPolicyStore(cfg.Policy)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := fresh.Load(); err == nil {
			t.Fatal("the refused clear produced a validly signed policy document")
		}
	})

	t.Run("quarantine with an active emergency stop keeps the marker", func(t *testing.T) {
		cfg, state, policy, release, core, _ := tamperedPolicyStartupFixture(t)
		if err := release.InitializeStartup("", false); err != nil {
			t.Fatalf("startup quarantine failed: %v", err)
		}
		if _, err := release.EmergencyStop("operator pauses an already quarantined platform"); err != nil {
			t.Fatalf("emergency stop under quarantine: %v", err)
		}
		markerBefore, err := os.ReadFile(cfg.Release.EmergencyStopFile)
		if err != nil {
			t.Fatalf("the emergency-stop marker is missing: %v", err)
		}
		policyBefore := policyArtifactSHA256(t, cfg.Policy.StateFile)
		clearedBefore := core.clearCount()

		if _, err := release.ClearEmergencyStop("CLEAR:EMERGENCY-STOP", "operator tries to clear the stop before recovering the policy"); err == nil {
			t.Fatal("the emergency-stop clear bypassed the policy quarantine")
		}

		markerAfter, err := os.ReadFile(cfg.Release.EmergencyStopFile)
		if err != nil {
			t.Fatalf("the refused clear removed the emergency-stop marker: %v", err)
		}
		if !bytes.Equal(markerAfter, markerBefore) {
			t.Fatal("the refused clear modified the emergency-stop marker")
		}
		if got := policyArtifactSHA256(t, cfg.Policy.StateFile); got != policyBefore {
			t.Fatal("the refused clear re-signed the quarantined policy document")
		}
		if policy.Status().Verified {
			t.Fatal("the quarantined policy became verified through the emergency-stop clear")
		}
		after := release.Status()
		if !after.PolicyQuarantined || !after.EmergencyStop {
			t.Fatalf("the refused clear left the wrong state: %+v", after)
		}
		if enforcement, _ := state.Modes(); enforcement != "enforce" {
			t.Fatalf("the refused clear released the retained enforcement: %s", enforcement)
		}
		if core.clearCount() != clearedBefore {
			t.Fatal("the refused emergency-stop clear released the kernel blocklist")
		}
	})

	t.Run("without a quarantine the clear still works", func(t *testing.T) {
		cfg, state, policy, release, _ := betaReleaseFixtureWithCore(t)
		if _, err := release.EmergencyStop("operator detected unsafe response behavior"); err != nil {
			t.Fatalf("emergency stop: %v", err)
		}
		status, err := release.ClearEmergencyStop("CLEAR:EMERGENCY-STOP", "operator verified the cause and clears the stop")
		if err != nil {
			t.Fatalf("the normal emergency-stop clear was refused: %v", err)
		}
		if status.Phase != ReleasePhaseObserve || status.EmergencyStop {
			t.Fatalf("the normal clear did not return to observe: %+v", status)
		}
		if status.PolicyQuarantined {
			t.Fatal("a normal clear reported a policy quarantine")
		}
		if !policy.Status().Verified {
			t.Fatal("the normal clear did not persist a verified observe policy")
		}
		if _, err := os.Stat(cfg.Release.EmergencyStopFile); !os.IsNotExist(err) {
			t.Fatalf("the normal clear did not remove the marker: %v", err)
		}
		if enforcement, xdrMode := state.Modes(); enforcement != "observe" || xdrMode != "observe" {
			t.Fatalf("the normal clear left %s/%s, want observe/observe", enforcement, xdrMode)
		}
	})
}

// TestEvaluateReportsBlockersWhenAutoDegradeIsDisabled is FIND-014's acceptance test.
//
// AutoDegrade may only gate the automatic mode switch. The blocker evaluation and its reporting
// run regardless, and "held" is reported explicitly so the operator can distinguish a decision
// from a blind spot. The control case proves the same blocker does trigger the switch when
// AutoDegrade is enabled, so the test cannot pass for the wrong reason.
func TestEvaluateReportsBlockersWhenAutoDegradeIsDisabled(t *testing.T) {
	armEnforceFixture := func(t *testing.T, autoDegrade bool) (Config, *State, *ReleaseController, *releaseCoreStub) {
		t.Helper()
		cfg, state, _, release, core := betaReleaseFixtureWithCore(t)
		release.cfg.Release.AutoDegrade = autoDegrade
		if got := release.runtimeSettingsLocked().AutoDegrade; got != autoDegrade {
			t.Fatalf("fixture AutoDegrade = %v, want %v", got, autoDegrade)
		}
		if _, err := release.Transition(ReleasePhaseCanary, "PROMOTE:CANARY", "enter canary before the injected blocker"); err != nil {
			t.Fatalf("canary transition: %v", err)
		}
		if _, err := release.Transition(ReleasePhaseEnforce, "PROMOTE:ENFORCE", "arm enforcement before the injected blocker"); err != nil {
			t.Fatalf("enforce transition: %v", err)
		}
		// A mandatory sensor that is no longer online is a substantive blocker for the
		// enforced phase: exactly the class of fault the fall-back exists for.
		state.SetSensorCoverage(SensorCoverage{
			Name: "xdp_ingress", Layer: LayerIngressNetwork, Status: CoverageDegraded, Required: true,
			CoverageReason: "synthetic injected release blocker",
		})
		return cfg, state, release, core
	}

	t.Run("AutoDegrade disabled keeps reporting the blocker", func(t *testing.T) {
		cfg, state, release, core := armEnforceFixture(t, false)
		enforcementBefore, xdrBefore := state.Modes()
		clearedBefore := core.clearCount()
		policyBefore := policyArtifactSHA256(t, cfg.Policy.StateFile)

		release.Evaluate()

		status := release.Status()
		if status.Phase != ReleasePhaseEnforce {
			t.Fatalf("AutoDegrade=false silently switched the phase to %s", status.Phase)
		}
		if !slices.Contains(status.Blockers, "Kinetic ingress sensor is unavailable") {
			t.Fatalf("the injected blocker is not reported: %v", status.Blockers)
		}
		if !status.AutoDegradeHeld {
			t.Fatalf("the held automatic degradation is not reported: %+v", status)
		}
		// The blocker is in the snapshot the dashboard reads as well.
		if snapshot := state.Snapshot(); !slices.Contains(snapshot.Release.Blockers, "Kinetic ingress sensor is unavailable") {
			t.Fatalf("the dashboard snapshot hides the blocker: %v", snapshot.Release.Blockers)
		}
		// No silent remediation: the phase, the modes, the kernel blocklist and the signed
		// policy are exactly what they were before the evaluation.
		enforcementAfter, xdrAfter := state.Modes()
		if enforcementAfter != enforcementBefore || xdrAfter != xdrBefore {
			t.Fatalf("AutoDegrade=false changed the modes: %s/%s -> %s/%s", enforcementBefore, xdrBefore, enforcementAfter, xdrAfter)
		}
		if core.clearCount() != clearedBefore {
			t.Fatal("AutoDegrade=false released the kernel blocklist")
		}
		if got := policyArtifactSHA256(t, cfg.Policy.StateFile); got != policyBefore {
			t.Fatal("AutoDegrade=false rewrote the signed policy document")
		}
	})

	t.Run("AutoDegrade enabled switches the mode and still reports", func(t *testing.T) {
		_, state, release, core := armEnforceFixture(t, true)
		clearedBefore := core.clearCount()

		release.Evaluate()

		status := release.Status()
		if status.Phase != ReleasePhaseDegraded {
			t.Fatalf("AutoDegrade=true did not pause the platform: %+v", status)
		}
		if status.AutoDegradeHeld {
			t.Fatalf("a switched platform reports held blockers: %+v", status)
		}
		if enforcement, xdrMode := state.Modes(); enforcement != "enforce" || xdrMode != "observe" {
			t.Fatalf("the automatic mode switch did not retain enforcement: %s/%s", enforcement, xdrMode)
		}
		if core.clearCount() != clearedBefore {
			t.Fatal("the automatic degradation released the kernel blocklist")
		}
	})
}
