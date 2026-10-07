package main

import (
	"errors"
	"testing"
	"time"
)

type mockPolicyPersistence struct {
	err    error
	calls  int
	blocks []BlockEntry
	status PolicyStatus
}

func (m *mockPolicyPersistence) Persist(_ string, _, _ string, blocks []BlockEntry) error {
	m.calls++
	m.blocks = append([]BlockEntry(nil), blocks...)
	return m.err
}

func (m *mockPolicyPersistence) Status() PolicyStatus { return m.status }

func addExpiredKineticBlock(t *testing.T, state *State, now time.Time, enforced bool) BlockEntry {
	t.Helper()
	entry, err := state.AddBlockAt(
		"203.0.113.77", "expiry test", "kinetic", time.Second, enforced, 100, now.Add(-2*time.Second),
	)
	if err != nil {
		t.Fatalf("add block: %v", err)
	}
	return entry
}

func TestReconcileExpiredNetworkBlocksCommitsKernelAndPolicy(t *testing.T) {
	cfg := defaultConfig()
	state := NewState("4.1.0", cfg)
	now := time.Now().UTC()
	entry := addExpiredKineticBlock(t, state, now, true)
	core := &mockNetworkBlockCore{blocked: map[string]bool{entry.Target: true}}
	policy := &mockPolicyPersistence{status: PolicyStatus{Verified: true, Generation: 2}}

	removed, err := reconcileExpiredNetworkBlocks(now, state, core, policy, cfg, nil)
	if err != nil {
		t.Fatalf("expiry transaction failed: %v", err)
	}
	if len(removed) != 1 || removed[0].ID != entry.ID {
		t.Fatalf("unexpected removed blocks: %+v", removed)
	}
	if core.blocked[entry.Target] {
		t.Fatalf("kernel mock still contains expired target")
	}
	if policy.calls != 1 || len(policy.blocks) != 0 {
		t.Fatalf("expected one policy persist with zero blocks, calls=%d blocks=%+v", policy.calls, policy.blocks)
	}
	if got := len(state.BlocksSnapshot()); got != 0 {
		t.Fatalf("expected no active blocks, got %d", got)
	}
	if got := state.Snapshot().Kinetic.BansExpiredTotal; got != 1 {
		t.Fatalf("expected kinetic expired counter 1, got %d", got)
	}
}

func TestReconcileExpiredNetworkBlocksDefersOnKernelDeleteFailure(t *testing.T) {
	cfg := defaultConfig()
	state := NewState("4.1.0", cfg)
	now := time.Now().UTC()
	entry := addExpiredKineticBlock(t, state, now, true)
	core := &mockNetworkBlockCore{
		blocked:   map[string]bool{entry.Target: true},
		deleteErr: errors.New("kernel unavailable"),
	}
	policy := &mockPolicyPersistence{}

	removed, err := reconcileExpiredNetworkBlocks(now, state, core, policy, cfg, nil)
	if err == nil {
		t.Fatal("expected deferred kernel-delete error")
	}
	if len(removed) != 0 {
		t.Fatalf("expected no committed removals, got %+v", removed)
	}
	if _, ok := state.BlockByID(entry.ID); !ok {
		t.Fatal("expired block was not restored after kernel delete failure")
	}
	if policy.calls != 0 {
		t.Fatalf("policy must not persist when nothing was removed, got %d calls", policy.calls)
	}
	if got := state.Snapshot().Kinetic.BansExpiredTotal; got != 0 {
		t.Fatalf("expired counter advanced on failed removal: %d", got)
	}
}

func TestReconcileExpiredNetworkBlocksRollsBackOnPolicyFailure(t *testing.T) {
	cfg := defaultConfig()
	state := NewState("4.1.0", cfg)
	now := time.Now().UTC()
	entry := addExpiredKineticBlock(t, state, now, true)
	core := &mockNetworkBlockCore{blocked: map[string]bool{entry.Target: true}}
	policy := &mockPolicyPersistence{err: errors.New("disk full")}

	removed, err := reconcileExpiredNetworkBlocks(now, state, core, policy, cfg, nil)
	if err == nil {
		t.Fatal("expected policy persistence failure")
	}
	if len(removed) != 0 {
		t.Fatalf("failed transaction must not report committed removals: %+v", removed)
	}
	if _, ok := state.BlockByID(entry.ID); !ok {
		t.Fatal("userspace block was not restored after persistence failure")
	}
	if !core.blocked[entry.Target] {
		t.Fatal("kernel block was not restored after persistence failure")
	}
	if got := state.Snapshot().Kinetic.BansExpiredTotal; got != 0 {
		t.Fatalf("expired counter advanced on rolled-back transaction: %d", got)
	}
}
