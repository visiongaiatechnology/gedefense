// STATUS: DIAMANT VGT SUPREME
package main

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

// releaseCoreStub records what it was asked to do, so a test can prove not only what the
// release controller reported but what it did to the kernel.
type releaseCoreStub struct {
	addErr    error
	deleteErr error
	clearErr  error
	verifyErr error

	mu      sync.Mutex
	added   []string
	cleared int
}

func (s *releaseCoreStub) Add(target string) error {
	if s.addErr != nil {
		return s.addErr
	}
	s.mu.Lock()
	s.added = append(s.added, target)
	s.mu.Unlock()
	return nil
}

func (s *releaseCoreStub) Delete(string) error { return s.deleteErr }

func (s *releaseCoreStub) ClearBlocklist() error {
	s.mu.Lock()
	s.cleared++
	s.mu.Unlock()
	return s.clearErr
}

func (s *releaseCoreStub) VerifyBlocklistEmpty() error { return s.verifyErr }

func (s *releaseCoreStub) addedTargets() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.added...)
}

func (s *releaseCoreStub) clearCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cleared
}

func betaReleaseFixture(t *testing.T) (Config, *State, *PolicyStore, *ReleaseController) {
	t.Helper()
	cfg, state, policy, release, _ := betaReleaseFixtureWithCore(t)
	return cfg, state, policy, release
}

func betaReleaseFixtureWithCore(t *testing.T) (Config, *State, *PolicyStore, *ReleaseController, *releaseCoreStub) {
	t.Helper()
	dir := t.TempDir()
	cfg := defaultConfig()
	cfg.Policy.StorageKeyFile = ""
	cfg.Node.Name = "beta-test"
	cfg.Defense.Allowlist = []string{"192.0.2.10/32"}
	cfg.Release.MinimumObserveSeconds = 0
	cfg.Release.MinimumCanarySeconds = 0
	cfg.Release.EmergencyStopFile = filepath.Join(dir, "EMERGENCY_STOP")
	cfg.Policy.StateFile = filepath.Join(dir, "policy.json")
	cfg.Policy.SigningKeyFile = filepath.Join(dir, "policy.key")
	cfg.Policy.PublicKeyFile = filepath.Join(dir, "policy.pub")
	state := NewState("test", cfg)
	verifiedAt := time.Now().UTC()
	state.SetSensorCoverage(SensorCoverage{
		Name: "xdp_ingress", Layer: LayerIngressNetwork, Status: CoverageOnline, Required: true,
		LastOK: &verifiedAt, SelfTest: "pass", CoverageReason: "verified release-test ingress fixture",
	})
	policy, err := NewPolicyStore(cfg.Policy)
	if err != nil {
		t.Fatal(err)
	}
	state.SetPolicyStatus(policy.Status())
	state.SetCore(true, "native")
	state.SetAllowlistReady(true)
	state.UpdateXDRScan(1, 0, state.started, false, "", 1)
	core := &releaseCoreStub{}
	release := NewReleaseController(cfg, state, core, policy, nil)
	if err := release.InitializeStartup("observe", true); err != nil {
		t.Fatal(err)
	}
	return cfg, state, policy, release, core
}

func TestReleaseRequiresStagedPromotion(t *testing.T) {
	_, state, _, release := betaReleaseFixture(t)
	if _, err := release.Transition(ReleasePhaseEnforce, "PROMOTE:ENFORCE", "attempt direct enforce promotion"); err == nil {
		t.Fatal("direct enforce promotion unexpectedly succeeded")
	}
	status, err := release.Transition(ReleasePhaseCanary, "PROMOTE:CANARY", "start controlled canary phase")
	if err != nil {
		t.Fatal(err)
	}
	if status.Phase != ReleasePhaseCanary {
		t.Fatalf("phase=%s", status.Phase)
	}
	enforcement, xdrMode := state.Modes()
	if enforcement != "observe" || xdrMode != "contain" {
		t.Fatalf("unexpected canary modes %s/%s", enforcement, xdrMode)
	}
	status, err = release.Transition(ReleasePhaseEnforce, "PROMOTE:ENFORCE", "enable gated beta enforcement")
	if err != nil {
		t.Fatal(err)
	}
	if status.Phase != ReleasePhaseEnforce {
		t.Fatalf("phase=%s", status.Phase)
	}
	enforcement, xdrMode = state.Modes()
	if enforcement != "enforce" || xdrMode != "enforce" {
		t.Fatalf("unexpected enforce modes %s/%s", enforcement, xdrMode)
	}
}

func TestReleaseCoreFailuresAutoDegradeRetainsEnforcement(t *testing.T) {
	cfg, state, _, release, core := betaReleaseFixtureWithCore(t)
	if _, err := release.Transition(ReleasePhaseCanary, "PROMOTE:CANARY", "start controlled canary phase"); err != nil {
		t.Fatal(err)
	}
	// The canary transition legitimately reconciles the kernel to observe, so the baseline is
	// taken after it: what must not happen is a *release* during the degradation.
	cleared := core.clearCount()
	for range cfg.Release.CoreFailureThreshold {
		release.ObserveCore(false)
	}
	status := release.Status()
	if status.Phase != ReleasePhaseDegraded {
		t.Fatalf("phase=%s", status.Phase)
	}
	// Fail-closed: the kernel keeps what the platform verified, and the automatic decisions
	// are what stops. Releasing the policy is the operator's explicit RETURN:OBSERVE.
	enforcement, xdrMode := state.Modes()
	if enforcement != "enforce" || xdrMode != "observe" {
		t.Fatalf("a core-heartbeat degradation must retain kernel enforcement: %s/%s", enforcement, xdrMode)
	}
	if status.KernelPolicyState != "verified-enforce" || !status.FailSafeVerified {
		t.Fatalf("retained enforcement was not verified: %+v", status)
	}
	if core.clearCount() != cleared {
		t.Fatal("the degradation released the kernel blocklist")
	}
}

func TestEmergencyStopPersistsAndBlocksPromotion(t *testing.T) {
	cfg, _, _, release := betaReleaseFixture(t)
	status, err := release.EmergencyStop("operator detected unsafe response behavior")
	if err != nil {
		t.Fatal(err)
	}
	if !status.EmergencyStop || status.Phase != ReleasePhaseDegraded {
		t.Fatalf("unexpected emergency status: %+v", status)
	}
	// An emergency stop stops the platform's automatic action. It does not release the kernel
	// policy; that is the operator's explicit RETURN:OBSERVE instruction.
	if !status.FailSafeVerified || status.KernelPolicyState != "verified-enforce" {
		t.Fatalf("emergency stop did not retain verified enforcement: %+v", status)
	}
	data, err := os.ReadFile(cfg.Release.EmergencyStopFile)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "unsafe response behavior") {
		t.Fatalf("missing emergency reason: %q", data)
	}
	if _, err := release.Transition(ReleasePhaseCanary, "PROMOTE:CANARY", "retry canary while stop exists"); err == nil {
		t.Fatal("promotion succeeded while emergency stop existed")
	}
}

func TestReleaseReadinessRejectsKernelStateDrift(t *testing.T) {
	cfg, state, _, release := betaReleaseFixture(t)
	if _, err := state.AddBlock("198.51.100.7/32", "drift test", "test", time.Hour, true, cfg.Defense.MaxBlockEntries); err != nil {
		t.Fatal(err)
	}
	ready, blockers := release.Ready()
	if ready {
		t.Fatal("observe readiness accepted an enforced kernel rule")
	}
	if !slices.Contains(blockers, "kernel policy reconciliation is pending") {
		t.Fatalf("missing kernel reconciliation blocker: %v", blockers)
	}
}

func TestEnforceRequiresSynchronizedManagementAllowlist(t *testing.T) {
	_, state, _, release := betaReleaseFixture(t)
	state.SetAllowlistReady(false)
	if _, err := release.Transition(ReleasePhaseCanary, "PROMOTE:CANARY", "enter canary before allowlist verification"); err != nil {
		t.Fatal(err)
	}
	if _, err := release.Transition(ReleasePhaseEnforce, "PROMOTE:ENFORCE", "attempt enforce without kernel allowlist"); err == nil {
		t.Fatal("enforce succeeded without synchronized management allowlist")
	}
	state.SetAllowlistReady(true)
	if _, err := release.Transition(ReleasePhaseEnforce, "PROMOTE:ENFORCE", "allowlist synchronized and canary complete"); err != nil {
		t.Fatal(err)
	}
}

func TestEmergencyStopReportsUnverifiedRetainedKernelState(t *testing.T) {
	cfg, state, policy, _ := betaReleaseFixture(t)
	if _, err := state.AddBlock("198.51.100.44/32", "rule the kernel has not confirmed", "test", time.Hour, false, cfg.Defense.MaxBlockEntries); err != nil {
		t.Fatal(err)
	}
	release := NewReleaseController(cfg, state, &releaseCoreStub{addErr: errors.New("core unavailable")}, policy, nil)
	status, err := release.EmergencyStop("operator requires immediate fail-closed pause")
	if err == nil {
		t.Fatal("emergency stop falsely reported success")
	}
	if !status.EmergencyStop || status.Phase != ReleasePhaseDegraded {
		t.Fatalf("emergency marker or degraded phase missing: %+v", status)
	}
	if status.FailSafeVerified || status.KernelPolicyState != "unverified" {
		t.Fatalf("an unconfirmed kernel state was falsely verified: %+v", status)
	}
	enforcement, xdrMode := state.Modes()
	if enforcement != "unverified" || xdrMode != "observe" {
		t.Fatalf("unsafe modes after failed confirmation: %s/%s", enforcement, xdrMode)
	}
	if !strings.Contains(status.Detail, "retained kernel policy could not be verified") {
		t.Fatalf("missing opaque operator-visible failure state: %q", status.Detail)
	}
}

// TestRetentionConfirmsEveryBlockWithTheKernel covers the difference between an inference and
// an observation. The core exposes no read-back, so a block that an earlier pass marked
// enforced is re-confirmed rather than trusted; the platform may only call a kernel state
// verified when the kernel said so in this pass. Re-applying is also what restores a block the
// kernel lost without telling anyone.
func TestRetentionConfirmsEveryBlockWithTheKernel(t *testing.T) {
	cfg, state, policy, _ := betaReleaseFixture(t)
	targets := []string{"198.51.100.51/32", "198.51.100.52/32"}
	for _, target := range targets {
		if _, err := state.AddBlock(target, "enforced before the restart", "test", time.Hour, true, cfg.Defense.MaxBlockEntries); err != nil {
			t.Fatal(err)
		}
	}
	core := &releaseCoreStub{}
	release := NewReleaseController(cfg, state, core, policy, nil)
	if err := release.InitializeStartup("enforce", true); err != nil {
		t.Fatal(err)
	}
	got := core.addedTargets()
	for _, target := range targets {
		if !slices.Contains(got, target) {
			t.Fatalf("the retention did not confirm %s with the kernel: %v", target, got)
		}
	}
	status := release.Status()
	if status.KernelPolicyState != "verified-enforce" || !status.FailSafeVerified {
		t.Fatalf("retained enforcement was not verified: %+v", status)
	}
	if status.Phase != ReleasePhaseDegraded {
		t.Fatalf("a retained startup must stay paused for the promotion gates, got %s", status.Phase)
	}
}

func TestRecoveredCoreRetriesUnverifiedRetention(t *testing.T) {
	cfg, state, policy, _ := betaReleaseFixture(t)
	if _, err := state.AddBlock("198.51.100.61/32", "block the kernel had not confirmed", "test", time.Hour, false, cfg.Defense.MaxBlockEntries); err != nil {
		t.Fatal(err)
	}
	core := &releaseCoreStub{addErr: errors.New("core offline")}
	release := NewReleaseController(cfg, state, core, policy, nil)
	if _, err := release.EmergencyStop("core recovery must confirm the retained policy"); err == nil {
		t.Fatal("initial unverified retention unexpectedly succeeded")
	}
	core.addErr = nil
	release.ObserveCore(true)
	status := release.Status()
	if !status.FailSafeVerified || status.KernelPolicyState != "verified-enforce" {
		t.Fatalf("recovered core did not complete the retention verification: %+v", status)
	}
}

// TestAKineticSensorDegradationRetainsTheKernelEnforcement is the reported defect.
//
// A single malformed kernel sample marked the ingress sensor degraded, and the release gate
// answered by removing the entire kernel blocklist: the host was found unprotected, with every
// blocked source released, twenty hours later. The degradation must pause automatic decisions
// and leave the enforcement exactly where it was.
func TestAKineticSensorDegradationRetainsTheKernelEnforcement(t *testing.T) {
	cfg, state, _, release, core := betaReleaseFixtureWithCore(t)
	cfg.Kinetic.EnforcementMode = "block"
	if _, err := release.Transition(ReleasePhaseCanary, "PROMOTE:CANARY", "enter canary before sensor degradation test"); err != nil {
		t.Fatal(err)
	}
	if _, err := state.AddBlock("203.0.113.9/32", "block in place before the fault", "test", time.Hour, false, cfg.Defense.MaxBlockEntries); err != nil {
		t.Fatal(err)
	}
	if _, err := release.Transition(ReleasePhaseEnforce, "PROMOTE:ENFORCE", "arm enforcement before sensor degradation test"); err != nil {
		t.Fatal(err)
	}
	if got := core.addedTargets(); !slices.Contains(got, "203.0.113.9/32") {
		t.Fatalf("the fixture did not enforce a block before the fault: %v", got)
	}

	server := &APIServer{cfg: cfg, state: state, release: release}
	cleared := core.clearCount()
	server.setKineticSensorState(CoverageDegraded, "degraded", "synthetic ingress ring pressure")

	status := release.Status()
	if status.Phase != ReleasePhaseDegraded {
		t.Fatalf("sensor degradation did not pause the platform: %+v", status)
	}
	if status.KernelPolicyState != "verified-enforce" || !status.FailSafeVerified {
		t.Fatalf("the retained kernel policy was not verified: %+v", status)
	}
	if core.clearCount() != cleared {
		t.Fatal("the degradation released the kernel blocklist")
	}
	enforced := false
	for _, block := range state.BlocksSnapshot() {
		if block.Target == "203.0.113.9/32" && block.Enforced {
			enforced = true
		}
	}
	if !enforced {
		t.Fatal("the enforced block was dropped from the policy")
	}
	networkMode, xdrMode := state.Modes()
	if networkMode != "enforce" || xdrMode != "observe" {
		t.Fatalf("the kernel enforcement must survive a sensor fault: %s/%s", networkMode, xdrMode)
	}
}

func TestReleaseEnforceRejectsRequiredL7CoverageGap(t *testing.T) {
	_, state, _, release := betaReleaseFixture(t)
	if _, err := release.Transition(ReleasePhaseCanary, "PROMOTE:CANARY", "start controlled canary phase"); err != nil {
		t.Fatal(err)
	}

	// The gap is established through the L7 status, because that is where the sensor
	// verdict is derived from. Writing the sensor entry directly expressed the condition
	// through a stored copy that the derivation now discards, so the test asserted an
	// implementation detail instead of the state it meant to describe.
	//
	// This is the real condition the gate exists for: inspection is required, the engine
	// is healthy, and not one request has been verified through the path.
	state.UpdateL7Status(func(status *L7Status) {
		status.Enabled = true
		status.Healthy = true
		status.InlineEnabled = true
		status.InlineHealthy = true
		status.CoverageRequired = true
	})

	// Prove the fixture really does derive a mandatory gap, so a later change to the
	// derivation cannot turn this into a test that passes for the wrong reason.
	sensor, ok := state.Snapshot().Kinetic.Coverage.Sensors["l7_application"]
	if !ok {
		t.Fatal("the L7 sensor entry is missing")
	}
	if sensor.Status != CoverageDegraded || !sensor.Required {
		t.Fatalf("the fixture did not establish a required L7 gap: status=%s required=%v", sensor.Status, sensor.Required)
	}

	if _, err := release.Transition(ReleasePhaseEnforce, "PROMOTE:ENFORCE", "must reject incomplete application coverage"); err == nil {
		t.Fatal("enforce promotion unexpectedly succeeded with required L7 coverage degraded")
	}

	// The counter-case: once a request has been verified through the path, the same
	// promotion must be allowed. Without this the test would pass just as well if the
	// gate blocked unconditionally.
	verifiedAt := time.Now().UTC()
	state.UpdateL7Status(func(status *L7Status) {
		status.InlineRequestsTotal = 1
		status.LastInspection = &verifiedAt
	})
	sensor, _ = state.Snapshot().Kinetic.Coverage.Sensors["l7_application"]
	if sensor.Status != CoverageOnline {
		t.Fatalf("a verified path still reports %s", sensor.Status)
	}
	if _, err := release.Transition(ReleasePhaseEnforce, "PROMOTE:ENFORCE", "coverage is now verified end to end"); err != nil {
		t.Fatalf("enforce promotion was refused with verified coverage: %v", err)
	}
}
