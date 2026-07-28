package main

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

type releaseCoreStub struct {
	addErr    error
	deleteErr error
	clearErr  error
	verifyErr error
}

func (s *releaseCoreStub) Add(string) error            { return s.addErr }
func (s *releaseCoreStub) Delete(string) error         { return s.deleteErr }
func (s *releaseCoreStub) ClearBlocklist() error       { return s.clearErr }
func (s *releaseCoreStub) VerifyBlocklistEmpty() error { return s.verifyErr }

func betaReleaseFixture(t *testing.T) (Config, *State, *PolicyStore, *ReleaseController) {
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
	policy, err := NewPolicyStore(cfg.Policy)
	if err != nil {
		t.Fatal(err)
	}
	state.SetPolicyStatus(policy.Status())
	state.SetCore(true, "native")
	state.SetAllowlistReady(true)
	state.UpdateXDRScan(1, 0, state.started, false, "", 1)
	release := NewReleaseController(cfg, state, &releaseCoreStub{}, policy, nil)
	if err := release.InitializeObserve(); err != nil {
		t.Fatal(err)
	}
	return cfg, state, policy, release
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

func TestReleaseCoreFailuresAutoDegrade(t *testing.T) {
	cfg, state, _, release := betaReleaseFixture(t)
	if _, err := release.Transition(ReleasePhaseCanary, "PROMOTE:CANARY", "start controlled canary phase"); err != nil {
		t.Fatal(err)
	}
	for range cfg.Release.CoreFailureThreshold {
		release.ObserveCore(false)
	}
	status := release.Status()
	if status.Phase != ReleasePhaseDegraded {
		t.Fatalf("phase=%s", status.Phase)
	}
	enforcement, xdrMode := state.Modes()
	if enforcement != "observe" || xdrMode != "observe" {
		t.Fatalf("unexpected degraded modes %s/%s", enforcement, xdrMode)
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
	if !status.FailSafeVerified || status.KernelPolicyState != "verified-empty" {
		t.Fatalf("emergency stop was not kernel-verified: %+v", status)
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

func TestEmergencyStopReportsUnverifiedKernelState(t *testing.T) {
	cfg, state, policy, _ := betaReleaseFixture(t)
	if _, err := state.AddBlock("198.51.100.44/32", "forced stale rule", "test", time.Hour, true, cfg.Defense.MaxBlockEntries); err != nil {
		t.Fatal(err)
	}
	release := NewReleaseController(cfg, state, &releaseCoreStub{clearErr: errors.New("core unavailable")}, policy, nil)
	status, err := release.EmergencyStop("operator requires immediate fail-safe shutdown")
	if err == nil {
		t.Fatal("emergency stop falsely reported success")
	}
	if !status.EmergencyStop || status.Phase != ReleasePhaseDegraded {
		t.Fatalf("emergency marker or degraded phase missing: %+v", status)
	}
	if status.FailSafeVerified || status.KernelPolicyState != "unverified" {
		t.Fatalf("stale kernel state was falsely verified: %+v", status)
	}
	enforcement, xdrMode := state.Modes()
	if enforcement != "unverified" || xdrMode != "observe" {
		t.Fatalf("unsafe modes after failed reconciliation: %s/%s", enforcement, xdrMode)
	}
	if !strings.Contains(status.Detail, "kernel fail-safe verification failed") {
		t.Fatalf("missing opaque operator-visible failure state: %q", status.Detail)
	}
}

func TestEmergencyStopRequiresPositiveEmptyMapVerification(t *testing.T) {
	cfg, state, policy, _ := betaReleaseFixture(t)
	release := NewReleaseController(cfg, state, &releaseCoreStub{verifyErr: errors.New("blocklist not empty")}, policy, nil)
	status, err := release.EmergencyStop("verify empty block maps before success")
	if err == nil {
		t.Fatal("emergency stop succeeded without empty-map verification")
	}
	if status.FailSafeVerified || status.KernelPolicyState != "unverified" {
		t.Fatalf("failed verification was not represented safely: %+v", status)
	}
}

func TestRecoveredCoreRetriesUnverifiedFailSafe(t *testing.T) {
	cfg, state, policy, _ := betaReleaseFixture(t)
	core := &releaseCoreStub{verifyErr: errors.New("core offline")}
	release := NewReleaseController(cfg, state, core, policy, nil)
	if _, err := release.EmergencyStop("core recovery must verify empty maps"); err == nil {
		t.Fatal("initial unverified emergency stop unexpectedly succeeded")
	}
	core.verifyErr = nil
	release.ObserveCore(true)
	status := release.Status()
	if !status.FailSafeVerified || status.KernelPolicyState != "verified-empty" {
		t.Fatalf("recovered core did not complete fail-safe verification: %+v", status)
	}
}
