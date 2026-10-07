package main

import (
	"errors"
	"testing"
	"time"
)

func newTestResponseEngine(t *testing.T) (*KineticResponseEngine, *State) {
	t.Helper()
	cfg := defaultConfig()
	cfg.Kinetic.EnforcementMode = "block"
	cfg.Defense.Allowlist = []string{"192.0.2.50", "198.51.100.0/24"}
	state := NewState("4.1.0", cfg)
	armKineticResponseState(state)
	resp := NewKineticResponseEngine(cfg, state, &mockNetworkBlockCore{blocked: make(map[string]bool)})
	return resp, state
}

func armKineticResponseState(state *State) {
	now := time.Now().UTC()
	state.SetCore(true, "test")
	state.SetAllowlistReady(true)
	state.SetPolicyStatus(PolicyStatus{Verified: true, Generation: 1, UpdatedAt: &now, Signer: "test"})
	state.SetSensorCoverage(SensorCoverage{
		Name: "xdp_ingress", Layer: LayerIngressNetwork, Status: CoverageOnline, Required: true,
		LastOK: &now, SelfTest: "pass", CoverageReason: "verified test ingress",
	})
	state.SetModes("enforce", "enforce")
	state.SetReleaseStatus(ReleaseStatus{
		Channel: "test", Phase: ReleasePhaseEnforce, Since: now, Ready: true,
		FailSafeVerified: false, KernelPolicyState: "verified-enforce", Detail: "test enforcement armed",
	})
}

func TestKineticResponseAllowlistProtection(t *testing.T) {
	resp, _ := newTestResponseEngine(t)

	// Direct allowlisted IP
	d1 := NetworkDecision{
		Target:          "192.0.2.50",
		Score:           100,
		Confidence:      1.0,
		SuggestedAction: "block",
		Reason:          "Rate limit test",
		Timestamp:       time.Now().UTC(),
	}
	_, err := resp.ExecuteDecision(d1)
	if !errors.Is(err, ErrAllowlistProtected) {
		t.Fatalf("expected ErrAllowlistProtected for direct allowlisted IP, got: %v", err)
	}

	// Subnet that contains an allowlisted IP (192.0.2.50 is in 192.0.2.0/24)
	d2 := NetworkDecision{
		Target:          "192.0.2.0/24",
		Score:           100,
		Confidence:      1.0,
		SuggestedAction: "block",
		Reason:          "Subnet flood test",
		Timestamp:       time.Now().UTC(),
	}
	_, err2 := resp.ExecuteDecision(d2)
	if !errors.Is(err2, ErrAllowlistProtected) {
		t.Fatalf("expected ErrAllowlistProtected for subnet containing allowlisted IP, got: %v", err2)
	}
}

func TestKineticResponseBroadSectorRejection(t *testing.T) {
	resp, _ := newTestResponseEngine(t)

	// IPv4 /16 macro sector
	d := NetworkDecision{
		Target:          "203.0.0.0/16",
		Score:           150,
		Confidence:      1.0,
		SuggestedAction: "block",
		Reason:          "Macro sector surge test",
		Timestamp:       time.Now().UTC(),
	}
	_, err := resp.ExecuteDecision(d)
	if !errors.Is(err, ErrBroadSectorProtected) {
		t.Fatalf("expected ErrBroadSectorProtected for /16 macro block, got: %v", err)
	}

	// IPv4 /8 global block
	d8 := NetworkDecision{
		Target:          "10.0.0.0/8",
		Score:           150,
		Confidence:      1.0,
		SuggestedAction: "block",
		Reason:          "Class A block test",
		Timestamp:       time.Now().UTC(),
	}
	_, err8 := resp.ExecuteDecision(d8)
	if !errors.Is(err8, ErrBroadSectorProtected) {
		t.Fatalf("expected ErrBroadSectorProtected for /8 block, got: %v", err8)
	}
}

func TestKineticResponseLowEvidenceSubnetRejection(t *testing.T) {
	resp, _ := newTestResponseEngine(t)

	// /24 with low confidence / score
	d := NetworkDecision{
		Target:          "203.0.113.0/24",
		Score:           60,
		Confidence:      0.65,
		SuggestedAction: "block",
		Reason:          "Weak signal test",
		Timestamp:       time.Now().UTC(),
	}
	_, err := resp.ExecuteDecision(d)
	if !errors.Is(err, ErrSubnetEvidenceLow) {
		t.Fatalf("expected ErrSubnetEvidenceLow for /24 with low score, got: %v", err)
	}
}

func TestKineticResponseAdaptiveBackoff(t *testing.T) {
	resp, _ := newTestResponseEngine(t)
	now := time.Now().UTC()

	// Strike 1 on target
	d1 := NetworkDecision{
		Target:          "203.0.113.88",
		Score:           95,
		Confidence:      0.95,
		SuggestedAction: "block",
		BaseTTL:         1 * time.Hour,
		Reason:          "Initial port scan",
		Timestamp:       now,
	}
	b1, err := resp.ExecuteDecision(d1)
	if err != nil {
		t.Fatalf("strike 1 failed: %v", err)
	}
	if err := resp.CommitApplied(d1, b1); err != nil {
		t.Fatalf("strike 1 commit failed: %v", err)
	}
	ttl1 := b1.ExpiresAt.Sub(now).Round(time.Minute)
	if ttl1 != 1*time.Hour {
		t.Fatalf("expected 1h TTL for strike 1, got %v", ttl1)
	}

	// Strike 2 within 24 hours on same target -> TTL doubles to 2h
	now2 := now.Add(10 * time.Minute)
	d2 := NetworkDecision{
		Target:          "203.0.113.88",
		Score:           95,
		Confidence:      0.95,
		SuggestedAction: "block",
		BaseTTL:         1 * time.Hour,
		Reason:          "Repeated port scan",
		Timestamp:       now2,
	}
	b2, err2 := resp.ExecuteDecision(d2)
	if err2 != nil {
		t.Fatalf("strike 2 failed: %v", err2)
	}
	ttl2 := b2.ExpiresAt.Sub(now2).Round(time.Minute)
	if ttl2 != 2*time.Hour {
		t.Fatalf("expected 2h TTL for strike 2 backoff, got %v", ttl2)
	}
}

func TestKineticResponseTTLAndRollback(t *testing.T) {
	resp, state := newTestResponseEngine(t)
	now := time.Now().UTC()

	d := NetworkDecision{
		Target:          "203.0.113.99",
		Score:           95,
		Confidence:      0.95,
		SuggestedAction: "block",
		BaseTTL:         5 * time.Second,
		Reason:          "Temporary test block",
		Timestamp:       now,
	}
	_, err := resp.ExecuteDecision(d)
	if err != nil {
		t.Fatalf("failed to execute block: %v", err)
	}

	// Active block in state
	if len(state.BlocksSnapshot()) != 1 {
		t.Fatalf("expected 1 active block in state")
	}

	// Fast forward 6 seconds -> the single central expiry transaction owns
	// userspace removal, kernel removal, policy persistence and evidence.
	core := &mockNetworkBlockCore{blocked: map[string]bool{"203.0.113.99/32": true}}
	future := now.Add(6 * time.Second)
	reconciled, err := reconcileExpiredNetworkBlocks(future, state, core, nil, resp.cfg, nil)
	if err != nil {
		t.Fatalf("failed to reconcile expired block: %v", err)
	}
	if len(reconciled) != 1 {
		t.Fatalf("expected 1 reconciled expired block, got %d", len(reconciled))
	}
	if len(state.BlocksSnapshot()) != 0 {
		t.Fatalf("expected 0 active blocks in state after rollback")
	}
	if core.blocked["203.0.113.99/32"] {
		t.Fatalf("expected expired target to be removed from kernel mock")
	}
}

type mockNetworkBlockCore struct {
	blocked   map[string]bool
	addErr    error
	deleteErr error
}

func (m *mockNetworkBlockCore) Add(target string) error {
	if m.addErr != nil {
		return m.addErr
	}
	if m.blocked == nil {
		m.blocked = make(map[string]bool)
	}
	m.blocked[target] = true
	return nil
}

func (m *mockNetworkBlockCore) Delete(target string) error {
	if m.deleteErr != nil {
		return m.deleteErr
	}
	delete(m.blocked, target)
	return nil
}

func TestKineticResponseManagementAllowlistImmunityAcrossCIDRs(t *testing.T) {
	cfg := defaultConfig()
	cfg.Kinetic.EnforcementMode = "block"
	cfg.Defense.Allowlist = []string{
		"192.0.2.50",
		"198.51.100.0/24",
		"2001:db8:42::/64",
	}
	state := NewState("4.1.0", cfg)
	resp := NewKineticResponseEngine(cfg, state, nil)

	protected := []string{
		"192.0.2.50",       // exact management IP
		"192.0.2.0/24",     // subnet containing an exact management IP
		"198.51.100.0/24",  // exact management subnet
		"198.51.0.0/16",    // broad sector overlapping the management subnet
		"2001:db8:42::/64", // IPv6 management subnet
	}
	for _, target := range protected {
		if !resp.IsAllowlistProtected(target) {
			t.Fatalf("management target %s was not protected", target)
		}
		decision := NetworkDecision{
			Target: target, Score: 180, Confidence: 1, SuggestedAction: "block",
			BaseTTL: time.Hour, Reason: "allowlist immunity regression", Timestamp: time.Now().UTC(),
		}
		if _, err := resp.ExecuteDecision(decision); !errors.Is(err, ErrAllowlistProtected) {
			t.Fatalf("target %s bypassed management allowlist, got %v", target, err)
		}
	}

	if resp.IsAllowlistProtected("203.0.113.99") {
		t.Fatal("unrelated public test address was incorrectly allowlist-protected")
	}
}

func TestKineticResponseOutcomeCounters(t *testing.T) {
	resp, state := newTestResponseEngine(t)
	now := time.Now().UTC()
	decision := NetworkDecision{
		Target: "203.0.113.199", Score: 100, Confidence: 1, SuggestedAction: "block",
		BaseTTL: time.Minute, Reason: "counter test", Timestamp: now,
	}
	entry, err := resp.ExecuteDecision(decision)
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if err := resp.CommitApplied(decision, entry); err != nil {
		t.Fatalf("commit: %v", err)
	}
	resp.RecordSuppressed()
	resp.RecordApplyRollback(decision, entry, errors.New("persist failed"), nil)
	resp.RecordFailure()

	tel := state.Snapshot().Kinetic
	if tel.BansEnforcedTotal != 1 || tel.ResponseAppliedTotal != 1 {
		t.Fatalf("unexpected applied counters: %+v", tel)
	}
	if tel.ResponseSuppressedTotal != 1 {
		t.Fatalf("expected one suppressed response, got %d", tel.ResponseSuppressedTotal)
	}
	if tel.ResponseRollbackTotal != 1 {
		t.Fatalf("expected one rollback response, got %d", tel.ResponseRollbackTotal)
	}
	if tel.ResponseFailedTotal != 1 {
		t.Fatalf("expected one failed response, got %d", tel.ResponseFailedTotal)
	}
}

func TestKineticResponseAllowlistConcurrentReadsAndUpdates(t *testing.T) {
	resp, _ := newTestResponseEngine(t)
	done := make(chan struct{})

	go func() {
		defer close(done)
		for i := 0; i < 250; i++ {
			resp.UpdateAllowlist([]string{"198.51.100.0/24", "2001:db8:42::/64"})
			resp.UpdateAllowlist([]string{"192.0.2.50", "203.0.113.0/24"})
		}
	}()
	for i := 0; i < 500; i++ {
		_ = resp.IsAllowlistProtected("198.51.100.44")
		_ = resp.IsAllowlistProtected("2001:db8:42::10")
	}
	<-done
}

func TestKineticResponseRequiresLiveReleaseEnforcement(t *testing.T) {
	cfg := defaultConfig()
	cfg.Kinetic.EnforcementMode = "block"
	state := NewState("4.1.0", cfg)
	now := time.Now().UTC()
	state.SetCore(true, "test")
	state.SetAllowlistReady(true)
	state.SetPolicyStatus(PolicyStatus{Verified: true, Generation: 1, UpdatedAt: &now, Signer: "test"})
	state.SetSensorCoverage(SensorCoverage{
		Name: "xdp_ingress", Layer: LayerIngressNetwork, Status: CoverageOnline, Required: true,
		LastOK: &now, SelfTest: "pass", CoverageReason: "verified test ingress",
	})
	state.SetModes("observe", "observe")
	state.SetReleaseStatus(ReleaseStatus{Phase: ReleasePhaseObserve, Ready: true, Since: now})
	resp := NewKineticResponseEngine(cfg, state, &mockNetworkBlockCore{blocked: make(map[string]bool)})

	_, err := resp.ExecuteDecision(NetworkDecision{
		Target: "203.0.113.70", Score: 100, Confidence: 1, SuggestedAction: "block",
		BaseTTL: time.Hour, Reason: "release gate regression", Timestamp: now,
	})
	if !errors.Is(err, ErrResponseNotReady) {
		t.Fatalf("expected ErrResponseNotReady outside enforce phase, got %v", err)
	}
	if len(state.BlocksSnapshot()) != 0 {
		t.Fatal("suppressed response mutated block state")
	}
}

func TestKineticResponseRejectsDegradedIngressImmediately(t *testing.T) {
	resp, state := newTestResponseEngine(t)
	now := time.Now().UTC()
	state.SetSensorCoverage(SensorCoverage{
		Name: "xdp_ingress", Layer: LayerIngressNetwork, Status: CoverageDegraded, Required: true,
		LastError: "ring pressure", SelfTest: "degraded", CoverageReason: "test pressure",
	})

	_, err := resp.ExecuteDecision(NetworkDecision{
		Target: "203.0.113.71", Score: 100, Confidence: 1, SuggestedAction: "block",
		BaseTTL: time.Hour, Reason: "degraded sensor regression", Timestamp: now,
	})
	if !errors.Is(err, ErrResponseNotReady) {
		t.Fatalf("expected degraded ingress to suppress response, got %v", err)
	}
	if len(state.BlocksSnapshot()) != 0 {
		t.Fatal("degraded ingress response mutated block state")
	}
}

func TestKineticSubnetRequiresMultipleContributors(t *testing.T) {
	resp, state := newTestResponseEngine(t)
	now := time.Now().UTC()
	decision := NetworkDecision{
		Target: "203.0.113.0/24", Score: 100, Confidence: 0.95, ContributorCount: 1,
		SuggestedAction: "block", BaseTTL: time.Hour, Reason: "subnet evidence regression", Timestamp: now,
	}
	if _, err := resp.ExecuteDecision(decision); !errors.Is(err, ErrSubnetEvidenceLow) {
		t.Fatalf("single-source subnet block was not rejected: %v", err)
	}

	decision.ContributorCount = 2
	entry, err := resp.ExecuteDecision(decision)
	if err != nil {
		t.Fatalf("multi-source subnet block rejected: %v", err)
	}
	if entry.Target != "203.0.113.0/24" || !entry.Enforced {
		t.Fatalf("unexpected subnet containment entry: %+v", entry)
	}
	if err := resp.RollbackApplied(entry); err != nil {
		t.Fatalf("cleanup rollback failed: %v", err)
	}
	if len(state.BlocksSnapshot()) != 0 {
		t.Fatal("subnet cleanup left stale block state")
	}
}

func TestKineticRollbackRestoresExistingManualBlockExactly(t *testing.T) {
	cfg := defaultConfig()
	cfg.Kinetic.EnforcementMode = "block"
	state := NewState("4.1.0", cfg)
	armKineticResponseState(state)
	now := time.Now().UTC()
	manual, err := state.AddBlockAt("203.0.113.80", "operator maintenance block", "operator", 4*time.Hour, false, cfg.Defense.MaxBlockEntries, now.Add(-time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	core := &mockNetworkBlockCore{blocked: make(map[string]bool)}
	resp := NewKineticResponseEngine(cfg, state, core)
	entry, err := resp.ExecuteDecision(NetworkDecision{
		Target: "203.0.113.80", Score: 100, Confidence: 1, SuggestedAction: "block",
		BaseTTL: time.Hour, Reason: "kinetic overlap", Timestamp: now,
	})
	if err != nil {
		t.Fatalf("execute overlap: %v", err)
	}
	if entry.Source != manual.Source || entry.Reason != manual.Reason || entry.ExpiresAt.Before(manual.ExpiresAt) {
		t.Fatalf("kinetic update weakened/relabelled manual block: before=%+v after=%+v", manual, entry)
	}
	if !entry.Enforced || !core.blocked[entry.Target] {
		t.Fatalf("expected temporary enforcement promotion for existing manual block: %+v", entry)
	}

	if err := resp.RollbackApplied(entry); err != nil {
		t.Fatalf("rollback overlap: %v", err)
	}
	restored, ok := state.BlockByTarget(manual.Target)
	if !ok {
		t.Fatal("manual block disappeared during rollback")
	}
	if restored != manual {
		t.Fatalf("manual block was not restored exactly: before=%+v after=%+v", manual, restored)
	}
	if core.blocked[entry.Target] {
		t.Fatal("kernel rule introduced by failed kinetic transaction survived rollback")
	}
}

func TestKineticRollbackDoesNotCreatePhantomRepeatOffender(t *testing.T) {
	resp, _ := newTestResponseEngine(t)
	now := time.Now().UTC()
	decision := NetworkDecision{
		Target: "203.0.113.90", Score: 100, Confidence: 1, SuggestedAction: "block",
		BaseTTL: time.Hour, Reason: "transaction reputation regression", Timestamp: now,
	}
	first, err := resp.ExecuteDecision(decision)
	if err != nil {
		t.Fatal(err)
	}
	if err := resp.RollbackApplied(first); err != nil {
		t.Fatal(err)
	}
	if len(resp.reputation) != 0 {
		t.Fatalf("rolled-back action advanced reputation: %+v", resp.reputation)
	}

	decision.Timestamp = now.Add(10 * time.Minute)
	second, err := resp.ExecuteDecision(decision)
	if err != nil {
		t.Fatal(err)
	}
	if got := second.ExpiresAt.Sub(decision.Timestamp).Round(time.Minute); got != time.Hour {
		t.Fatalf("rollback created phantom TTL escalation: got %v", got)
	}
	if err := resp.RollbackApplied(second); err != nil {
		t.Fatal(err)
	}
}

func TestKineticKernelApplyFailureCompensatesAndSignalsDivergence(t *testing.T) {
	cfg := defaultConfig()
	cfg.Kinetic.EnforcementMode = "block"
	state := NewState("4.1.0", cfg)
	armKineticResponseState(state)
	core := &mockNetworkBlockCore{blocked: make(map[string]bool), addErr: errors.New("add failed")}
	resp := NewKineticResponseEngine(cfg, state, core)
	decision := NetworkDecision{
		Target: "203.0.113.91", Score: 100, Confidence: 1, SuggestedAction: "block",
		BaseTTL: time.Hour, Reason: "kernel apply regression", Timestamp: time.Now().UTC(),
	}
	if _, err := resp.ExecuteDecision(decision); err == nil || errors.Is(err, ErrKernelStateDivergent) {
		t.Fatalf("expected compensated add failure without divergence, got %v", err)
	}
	if len(state.BlocksSnapshot()) != 0 {
		t.Fatal("failed kernel add left userspace block behind")
	}

	core.deleteErr = errors.New("delete failed")
	if _, err := resp.ExecuteDecision(decision); !errors.Is(err, ErrKernelStateDivergent) {
		t.Fatalf("expected divergence when compensation also fails, got %v", err)
	}
	if len(state.BlocksSnapshot()) != 0 {
		t.Fatal("divergent kernel compensation left false userspace success state")
	}
}

func TestKineticResponseHonorsAutoContainScopeControls(t *testing.T) {
	resp, _ := newTestResponseEngine(t)
	runtime := defaultRuntimeSettings(resp.cfg)
	runtime.Kinetic.AutoContainSingleIP = false
	resp.UpdateConfig(runtime.Kinetic, runtime.Network)

	_, err := resp.ExecuteDecision(NetworkDecision{
		Target: "203.0.113.201", Score: 100, Confidence: 1,
		SuggestedAction: "block", BaseTTL: time.Hour, Reason: "runtime single-IP gate", Timestamp: time.Now().UTC(),
	})
	if !errors.Is(err, ErrAutoContainDisabled) {
		t.Fatalf("expected single-IP auto containment to be suppressed, got %v", err)
	}

	runtime.Kinetic.AutoContainSingleIP = true
	runtime.Kinetic.AutoContainIPv4Subnet = false
	resp.UpdateConfig(runtime.Kinetic, runtime.Network)
	_, err = resp.ExecuteDecision(NetworkDecision{
		Target: "203.0.113.0/24", Score: 100, Confidence: 1, ContributorCount: 4,
		SuggestedAction: "block", BaseTTL: time.Hour, Reason: "runtime subnet gate", Timestamp: time.Now().UTC(),
	})
	if !errors.Is(err, ErrAutoContainDisabled) {
		t.Fatalf("expected /24 auto containment to be suppressed, got %v", err)
	}
}

func TestKineticResponseUsesRuntimeSubnetSourceGate(t *testing.T) {
	resp, _ := newTestResponseEngine(t)
	runtime := defaultRuntimeSettings(resp.cfg)
	runtime.Kinetic.SubnetMinSources = 4
	resp.UpdateConfig(runtime.Kinetic, runtime.Network)

	decision := NetworkDecision{
		Target: "203.0.113.0/24", Score: 100, Confidence: 1, ContributorCount: 3,
		SuggestedAction: "contain", BaseTTL: time.Hour, Reason: "runtime source diversity", Timestamp: time.Now().UTC(),
	}
	if _, err := resp.ExecuteDecision(decision); !errors.Is(err, ErrSubnetEvidenceLow) {
		t.Fatalf("expected runtime source gate to reject three contributors, got %v", err)
	}
	decision.ContributorCount = 4
	if _, err := resp.ExecuteDecision(decision); err != nil {
		t.Fatalf("expected four contributors to satisfy runtime source gate: %v", err)
	}
}
