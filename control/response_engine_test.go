// STATUS: DIAMANT VGT SUPREME
package main

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

type mockActionDispatcher struct {
	blockedIPs     map[string]bool
	frozenPIDs     map[int]bool
	freezeTicks    map[int]uint64
	unfreezeTicks  map[int]uint64
	cellPolicies   map[uint64]uint8
	failNextAction bool
}

func newMockDispatcher() *mockActionDispatcher {
	return &mockActionDispatcher{
		blockedIPs:    make(map[string]bool),
		frozenPIDs:    make(map[int]bool),
		freezeTicks:   make(map[int]uint64),
		unfreezeTicks: make(map[int]uint64),
		cellPolicies:  make(map[uint64]uint8),
	}
}

func (m *mockActionDispatcher) BlockIP(ip string) error {
	if m.failNextAction {
		return errors.New("kernel trie allocation failed")
	}
	m.blockedIPs[ip] = true
	return nil
}

func (m *mockActionDispatcher) UnblockIP(ip string) error {
	delete(m.blockedIPs, ip)
	return nil
}

func (m *mockActionDispatcher) FreezeProcess(pid int, startTicks uint64, reason string) error {
	if m.failNextAction {
		return errors.New("pidfd signal rejected")
	}
	if startTicks == 0 {
		return errors.New("pidfd_signal rejected: zero start_ticks")
	}
	m.frozenPIDs[pid] = true
	m.freezeTicks[pid] = startTicks
	return nil
}

func (m *mockActionDispatcher) UnfreezeProcess(pid int, startTicks uint64) error {
	if m.failNextAction {
		return errors.New("pidfd signal rejected")
	}
	if startTicks == 0 {
		return errors.New("pidfd_signal rejected: zero start_ticks")
	}
	delete(m.frozenPIDs, pid)
	m.unfreezeTicks[pid] = startTicks
	return nil
}

func (m *mockActionDispatcher) SetCellPolicy(cgroupID uint64, flags uint8) error {
	m.cellPolicies[cgroupID] = flags
	return nil
}

func (m *mockActionDispatcher) DeleteCellPolicy(cgroupID uint64) error {
	delete(m.cellPolicies, cgroupID)
	return nil
}

func TestResponseEngine_ApplyAndAutoRollback(t *testing.T) {
	dispatcher := newMockDispatcher()
	cfg := DefaultResponseConfig()
	cfg.ActorBanTTL = 2 * time.Second
	engine := NewResponseEngine(cfg, dispatcher, nil)

	ctx := context.Background()
	now := time.Now().UTC()

	// 1. Apply IP block
	rec, err := engine.ApplyResponse(
		ctx, now, "inc-100", ActionContainIP, "IP", "203.0.113.55", 95, "BRUTE_FORCE", "evidence-root-1",
	)
	if err != nil {
		t.Fatalf("failed to apply containment: %v", err)
	}
	if rec.Status != StatusApplied {
		t.Fatalf("expected status APPLIED, got %s", rec.Status)
	}
	if !dispatcher.blockedIPs["203.0.113.55"] {
		t.Fatal("expected IP to be blocked in kernel dispatcher")
	}

	// Verify active response
	active := engine.ActiveResponses()
	if len(active) != 1 {
		t.Fatalf("expected 1 active response, got %d", len(active))
	}

	// 2. Advance time past TTL and test rollback
	future := now.Add(3 * time.Second)
	rolledBack, err := engine.RollbackExpired(ctx, future)
	if err != nil {
		t.Fatalf("failed to rollback expired: %v", err)
	}
	if len(rolledBack) != 1 {
		t.Fatalf("expected 1 rolled back record, got %d", len(rolledBack))
	}
	if rolledBack[0].Status != StatusRolledBack {
		t.Fatalf("expected status ROLLED_BACK, got %s", rolledBack[0].Status)
	}

	// Verify dispatcher unblocked
	if dispatcher.blockedIPs["203.0.113.55"] {
		t.Fatal("expected IP to be unblocked in kernel dispatcher after rollback")
	}
	if len(engine.ActiveResponses()) != 0 {
		t.Fatalf("expected 0 active responses, got %d", len(engine.ActiveResponses()))
	}
}

func TestResponseEngine_EscalationPolicy(t *testing.T) {
	dispatcher := newMockDispatcher()
	cfg := DefaultResponseConfig()
	cfg.ActorBanTTL = 100 * time.Second
	cfg.EscalationEnabled = true
	engine := NewResponseEngine(cfg, dispatcher, nil)

	ctx := context.Background()
	now := time.Now().UTC()

	// First violation
	r1, err := engine.ApplyResponse(ctx, now, "inc-1", ActionContainIP, "IP", "198.51.100.10", 90, "RULE_1", "ev-1")
	if err != nil {
		t.Fatalf("r1 failed: %v", err)
	}
	dur1 := r1.ExpiresAt.Sub(r1.StartedAt)
	if dur1 != 100*time.Second {
		t.Fatalf("expected first TTL 100s, got %s", dur1)
	}

	// Second violation within 2 hours -> 4x escalation
	later := now.Add(2 * time.Hour)
	r2, err := engine.ApplyResponse(ctx, later, "inc-2", ActionContainIP, "IP", "198.51.100.10", 95, "RULE_2", "ev-2")
	if err != nil {
		t.Fatalf("r2 failed: %v", err)
	}
	dur2 := r2.ExpiresAt.Sub(r2.StartedAt)
	if dur2 != 400*time.Second {
		t.Fatalf("expected escalated TTL 400s (4x), got %s", dur2)
	}
}

func TestResponseEngine_ValidationExceptions(t *testing.T) {
	dispatcher := newMockDispatcher()
	engine := NewResponseEngine(DefaultResponseConfig(), dispatcher, nil)
	ctx := context.Background()
	now := time.Now().UTC()

	// Empty target ID -> validation error
	_, err := engine.ApplyResponse(ctx, now, "inc-err", ActionContainIP, "IP", "", 80, "REASON", "")
	if err == nil {
		t.Fatal("expected error on empty target ID, got nil")
	}
	var valErr *ResponseValidationException
	if !errors.As(err, &valErr) {
		t.Fatalf("expected ResponseValidationException, got %T", err)
	}

	// Invalid IP format
	_, err = engine.ApplyResponse(ctx, now, "inc-err", ActionContainIP, "IP", "not-a-valid-ip", 80, "REASON", "")
	if err == nil {
		t.Fatal("expected error on malformed IP, got nil")
	}
	if !errors.As(err, &valErr) {
		t.Fatalf("expected ResponseValidationException, got %T", err)
	}
}

func TestResponseEngine_FreezeAndUnfreezeLifecycle(t *testing.T) {
	dispatcher := newMockDispatcher()
	cfg := DefaultResponseConfig()
	cfg.ProcessRestrTTL = 2 * time.Second
	engine := NewResponseEngine(cfg, dispatcher, nil)

	ctx := context.Background()
	now := time.Now().UTC()

	// 1. Apply process freeze with explicit start_ticks
	const testPID = 4242
	const expectedTicks = uint64(999888777)
	targetID := fmt.Sprintf("%d:%d", testPID, expectedTicks)

	rec, err := engine.ApplyResponse(
		ctx, now, "inc-freeze-1", ActionFreezeExecution, "PID", targetID, 95, "XDR.MEMFD_EXEC", "evidence-freeze-root",
	)
	if err != nil {
		t.Fatalf("failed to apply process freeze containment: %v", err)
	}
	if rec.Status != StatusApplied {
		t.Fatalf("expected status APPLIED, got %s", rec.Status)
	}
	if !dispatcher.frozenPIDs[testPID] {
		t.Fatalf("expected PID %d to be marked frozen in dispatcher", testPID)
	}
	if dispatcher.freezeTicks[testPID] != expectedTicks {
		t.Fatalf("expected FreezeProcess startTicks %d, got %d", expectedTicks, dispatcher.freezeTicks[testPID])
	}

	// Verify RollbackJSON contains the resolved non-zero start_ticks
	if !strings.Contains(rec.RollbackJSON, fmt.Sprintf("%d", expectedTicks)) {
		t.Fatalf("expected RollbackJSON to contain start_ticks %d, got %s", expectedTicks, rec.RollbackJSON)
	}

	// 2. Advance time past TTL and test rollback unfreeze
	future := now.Add(3 * time.Second)
	rolledBack, err := engine.RollbackExpired(ctx, future)
	if err != nil {
		t.Fatalf("failed to rollback expired freeze: %v", err)
	}
	if len(rolledBack) != 1 {
		t.Fatalf("expected 1 rolled back record, got %d", len(rolledBack))
	}
	if rolledBack[0].Status != StatusRolledBack {
		t.Fatalf("expected status ROLLED_BACK, got %s", rolledBack[0].Status)
	}

	// Verify unfreeze was invoked with matching non-zero startTicks
	if dispatcher.frozenPIDs[testPID] {
		t.Fatalf("expected PID %d to be unfrozen in dispatcher", testPID)
	}
	if dispatcher.unfreezeTicks[testPID] != expectedTicks {
		t.Fatalf("expected UnfreezeProcess startTicks %d, got %d", expectedTicks, dispatcher.unfreezeTicks[testPID])
	}
	if len(engine.ActiveResponses()) != 0 {
		t.Fatalf("expected 0 active responses, got %d", len(engine.ActiveResponses()))
	}
}

func TestResponseEngine_FreezeRejectsZeroStartTicks(t *testing.T) {
	dispatcher := newMockDispatcher()
	engine := NewResponseEngine(DefaultResponseConfig(), dispatcher, nil)
	ctx := context.Background()
	now := time.Now().UTC()

	// Using PID without ticks when /proc is unavailable (or PID does not exist) yields startTicks = 0.
	// The mock dispatcher enforces non-zero startTicks, rejecting zero start_ticks.
	_, err := engine.ApplyResponse(
		ctx, now, "inc-zero-ticks", ActionFreezeExecution, "PID", "999999999", 90, "XDR.MEMFD_EXEC", "",
	)
	if err == nil {
		t.Fatal("expected freeze to fail when startTicks is 0, got nil")
	}
	var secErr *ResponseSecurityException
	if !errors.As(err, &secErr) {
		t.Fatalf("expected ResponseSecurityException, got %T: %v", err, err)
	}
	if !strings.Contains(secErr.Error(), "zero start_ticks") {
		t.Fatalf("expected error mentioning zero start_ticks, got %v", secErr)
	}
}

func TestResponseEngine_FreezeValidationExceptions(t *testing.T) {
	dispatcher := newMockDispatcher()
	engine := NewResponseEngine(DefaultResponseConfig(), dispatcher, nil)
	ctx := context.Background()
	now := time.Now().UTC()

	invalidTargets := []string{
		"not-a-pid",
		"abc:12345",
		"1234:not-a-number",
		"-10",
		"0",
	}

	for _, target := range invalidTargets {
		_, err := engine.ApplyResponse(ctx, now, "inc-val", ActionFreezeExecution, "PID", target, 90, "REASON", "")
		if err == nil {
			t.Fatalf("expected validation error for target %q, got nil", target)
		}
		var valErr *ResponseValidationException
		if !errors.As(err, &valErr) {
			t.Fatalf("expected ResponseValidationException for target %q, got %T: %v", target, err, err)
		}
	}
}

func TestResolveProcessTargetAndStartTicks(t *testing.T) {
	// Resolving invalid / non-existent PIDs returns 0 start ticks
	if ticks := ResolveProcessStartTicks(0); ticks != 0 {
		t.Fatalf("expected 0 ticks for PID 0, got %d", ticks)
	}
	if ticks := ResolveProcessStartTicks(-1); ticks != 0 {
		t.Fatalf("expected 0 ticks for PID -1, got %d", ticks)
	}

	// Parsing explicit targetID "pid:start_ticks"
	pid, ticks, err := ResolveProcessTarget("12345:67890")
	if err != nil || pid != 12345 || ticks != 67890 {
		t.Fatalf("ResolveProcessTarget failed: pid=%d ticks=%d err=%v", pid, ticks, err)
	}

	// Parsing invalid targets
	if _, _, err := ResolveProcessTarget("invalid"); err == nil {
		t.Fatal("expected error for invalid PID, got nil")
	}
	if _, _, err := ResolveProcessTarget("1234:badticks"); err == nil {
		t.Fatal("expected error for bad ticks, got nil")
	}
}
