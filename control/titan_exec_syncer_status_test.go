// STATUS: DIAMANT VGT SUPREME
package main

// POINT 1 / P1-T2 tests: status honesty of the Titan exec-gate syncer - the
// default-off upgrade contract, missing capability, inactive enforcement, the
// bounded retry and the surgical-vs-clear removal choice - plus the bounded batch
// chunking that keeps one ALLOW_ADD_BATCH inside the §5 wire limits.

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

func TestTitanExecPolicySyncerDefaultOffDoesNotEnableAnything(t *testing.T) {
	core := newTitanExecFakeCore()
	state := NewState("test", defaultConfig())
	syncer := NewTitanExecPolicySyncer(core, state, defaultRuntimeSettings(defaultConfig()), titanExecPlanDeps{Packages: newFakeTitanPackages()})
	status := syncer.Sync(context.Background())
	if status.State != TitanExecSyncStateApplied || status.Enabled || status.Mode != TitanExecModeOff {
		t.Fatalf("default-off sync claimed more than off: %+v", status)
	}
	for _, call := range core.callSequence() {
		switch {
		case call == "version" || call == "epoch" || call == "status" || call == "global:0:0" || call == "clear":
		default:
			t.Fatalf("default-off sync sent an unexpected command: %v", core.callSequence())
		}
	}
	if entries, scopes, _ := core.counts(); entries != 0 || scopes != 0 {
		t.Fatalf("default-off sync wrote kernel state: entries=%d scopes=%d", entries, scopes)
	}
}

func TestTitanExecPolicySyncerCapabilityMissingIsNotDegradation(t *testing.T) {
	core, syncer, state, _, _ := titanExecSyncerFixture(t, "tool-a")
	core.versionErr = ErrTitanExecUnavailable
	status := syncer.Sync(context.Background())
	if status.State != TitanExecSyncStateCapabilityMissing || status.Capability != titanExecCapabilityMissing {
		t.Fatalf("old core did not map to capability-missing: %+v", status)
	}
	for _, call := range core.callSequence() {
		if call != "version" {
			t.Fatalf("capability-missing path issued a policy command: %v", core.callSequence())
		}
	}
	snapshot := state.Snapshot()
	if snapshot.XDR.Degraded {
		t.Fatal("a missing TitanExec capability degraded XDR globally")
	}
	if hasStyxEventOfKind(snapshot.Events, "titan_exec.policy_sync_failed") {
		t.Fatal("a missing capability was reported as a policy sync failure")
	}
	if !hasStyxEventOfKind(snapshot.Events, "titan_exec.capability_missing") || syncer.CapabilityKnown() {
		t.Fatal("the missing capability was not reported as an operator-visible fact")
	}
}

func TestTitanExecPolicySyncerRetriesFailureThenApplies(t *testing.T) {
	core, syncer, state, _, _ := titanExecSyncerFixture(t, "tool-a")
	clock := time.Date(2026, 2, 1, 12, 0, 0, 0, time.UTC)
	syncer.now = func() time.Time { return clock }
	core.setFailure("global:1:0", errors.New("simulated map write failure"))
	failed := syncer.Sync(context.Background())
	if failed.State != TitanExecSyncStateFailed || failed.LastError == "" {
		t.Fatalf("failed sync was not reported: %+v", failed)
	}
	if countStyxEventsOfKind(state.Snapshot().Events, "titan_exec.policy_sync_failed") != 1 {
		t.Fatal("the failed sync did not record exactly one titan_exec.policy_sync_failed event")
	}
	core.setFailure("", nil)
	callsBefore := len(core.callSequence())
	if due := syncer.SyncIfDue(context.Background()); due.State != TitanExecSyncStateFailed {
		t.Fatalf("SyncIfDue retried before the backoff elapsed: %+v", due)
	}
	if len(core.callSequence()) != callsBefore {
		t.Fatal("SyncIfDue issued a core command before the retry interval elapsed")
	}
	clock = clock.Add(titanExecPolicySyncRetryInterval + time.Second)
	if got := syncer.SyncIfDue(context.Background()); got.State != TitanExecSyncStateApplied {
		t.Fatalf("retry after the backoff did not apply: %+v", got)
	}
	if countStyxEventsOfKind(state.Snapshot().Events, "titan_exec.policy_sync_failed") != 1 {
		t.Fatal("the retry reported the old failure again")
	}
}

func TestTitanExecPolicySyncerInactiveEnforcementIsHonest(t *testing.T) {
	core, syncer, state, settings, _ := titanExecSyncerFixture(t, "tool-a")
	settings.TitanExec.Mode = TitanExecModeContain
	syncer.Configure(settings)
	core.status.LSM = titanExecLSMInactive
	core.status.Path = titanExecPathNone
	status := syncer.Sync(context.Background())
	if status.State != TitanExecSyncStateInactive || !strings.Contains(status.LastError, "BPF-LSM") {
		t.Fatalf("inactive enforcement was not reported honestly: %+v", status)
	}
	for _, call := range core.callSequence() {
		if strings.HasPrefix(call, "global:2") || strings.HasPrefix(call, "global:3") {
			t.Fatalf("enforcement was pushed on an inactive hook: %v", core.callSequence())
		}
	}
	if !hasStyxEventOfKind(state.Snapshot().Events, "titan_exec.enforcement_inactive") {
		t.Fatal("the inactive enforcement was not reported as an operator-visible fact")
	}
	// Once the operator activates BPF-LSM and the core attaches, the retry applies.
	core.status.LSM = titanExecLSMActive
	core.status.Path = titanExecPathBPFLSM
	if got := syncer.Sync(context.Background()); got.State != TitanExecSyncStateApplied || got.Mode != TitanExecModeContain {
		t.Fatalf("activation was not picked up by the bounded retry: %+v", got)
	}
	// Invalid offsets are `unavailable`, never `applied`.
	core.status.Offsets = titanExecOffsetsInvalid
	syncer.Configure(titanExecSyncerSettings(t.TempDir()))
	if got := syncer.Sync(context.Background()); got.State != TitanExecSyncStateUnavailable {
		t.Fatalf("invalid offsets did not map to unavailable: %+v", got)
	}
}

func TestTitanExecPolicySyncerBatchRejectionFails(t *testing.T) {
	root := t.TempDir()
	names := make([]string, 20)
	for index := range names {
		names[index] = fmt.Sprintf("tool-%02d", index)
	}
	paths := titanExecSyncerWriteExecutables(t, root, names...)
	packages := newFakeTitanPackages()
	for _, path := range paths {
		packages.own(path, "dpkg", "coreutils")
	}
	core := newTitanExecFakeCore()
	core.batchReject = 1
	state := NewState("test", defaultConfig())
	syncer := NewTitanExecPolicySyncer(core, state, titanExecSyncerSettings(root), titanExecPlanDeps{Packages: packages})
	status := syncer.Sync(context.Background())
	if status.State != TitanExecSyncStateFailed || status.State == TitanExecSyncStateApplied {
		t.Fatalf("a partially rejected batch was reported as applied: %+v", status)
	}
	if !strings.Contains(status.LastError, "rejected") {
		t.Fatalf("the batch rejection reason was lost: %+v", status)
	}
	if len(core.batches) == 0 {
		t.Fatal("the large plan did not use the bounded batch command")
	}
}

func TestTitanExecPolicySyncerSurgicalDeleteForKnownIdentities(t *testing.T) {
	root := t.TempDir()
	paths := titanExecSyncerWriteExecutables(t, root, "tool-a", "tool-b")
	packages := newFakeTitanPackages()
	for _, path := range paths {
		packages.own(path, "dpkg", "coreutils")
	}
	core := newTitanExecFakeCore()
	syncer := NewTitanExecPolicySyncer(core, newStateForTitanExecTest(), titanExecSyncerSettings(root), titanExecPlanDeps{Packages: packages})
	if got := syncer.Sync(context.Background()); got.State != TitanExecSyncStateApplied || got.AppliedEntries != 2 {
		t.Fatalf("initial sync failed: %+v", got)
	}
	// A small policy is added entry-by-entry, so the kernel identity is known and the
	// removal of one file can delete exactly that inode (§5 adds before deletes).
	if err := os.Remove(paths[0]); err != nil {
		t.Fatal(err)
	}
	core.clearCalls()
	status := syncer.Sync(context.Background())
	if status.State != TitanExecSyncStateApplied || status.AppliedEntries != 1 {
		t.Fatalf("post-removal sync failed: %+v", status)
	}
	calls := core.callSequence()
	if callIndex(calls, "clear") >= 0 {
		t.Fatalf("a known identity was removed with a full clear: %v", calls)
	}
	deleted := false
	for _, call := range calls {
		if strings.HasPrefix(call, "del:") {
			deleted = true
		}
	}
	if !deleted {
		t.Fatalf("the stale inode was not deleted: %v", calls)
	}
	if last := calls[len(calls)-1]; last != "global:1:0" {
		t.Fatalf("the configured mode was not restored last: %v", calls)
	}
}

func TestTitanExecPlanAddBatchesAreBounded(t *testing.T) {
	if batches, singles := titanExecPlanAddBatches(nil); len(batches) != 0 || len(singles) != 0 {
		t.Fatal("an empty plan produced batches")
	}
	small := make([]titanExecPlanEntry, titanExecSingleAddThreshold)
	for index := range small {
		small[index] = titanExecPlanEntry{Path: fmt.Sprintf("/opt/tool-%02d", index)}
	}
	if batches, singles := titanExecPlanAddBatches(small); len(batches) != 0 || len(singles) != len(small) {
		t.Fatalf("a small policy was not pushed individually: batches=%d singles=%d", len(batches), len(singles))
	}
	many := make([]titanExecPlanEntry, 0, 450)
	for index := 0; index < 450; index++ {
		many = append(many, titanExecPlanEntry{Path: fmt.Sprintf("/x%02d", index)})
	}
	batches, singles := titanExecPlanAddBatches(many)
	if len(singles) != 0 || len(batches) != 3 {
		t.Fatalf("450 short paths did not chunk into three batches: batches=%d", len(batches))
	}
	for _, batch := range batches {
		decoded := len(strings.Join(batch, "\n"))
		if len(batch) > titanExecMaxBatchPaths || decoded > titanExecMaxBatchBytes {
			t.Fatalf("batch exceeds the §5 bounds: paths=%d bytes=%d", len(batch), decoded)
		}
	}
	long := []titanExecPlanEntry{{Path: "/" + strings.Repeat("a", 1500)}, {Path: "/" + strings.Repeat("b", 1500)}}
	batches, singles = titanExecPlanAddBatches(long)
	if len(singles) != 2 || len(batches) != 0 {
		t.Fatalf("oversized paths were not promoted to single adds: batches=%d singles=%d", len(batches), len(singles))
	}
}

// TestTitanExecPolicySyncerRejectedEnforcementIsNeverApplied pins the ABI note of
// P1-T3: the core refuses SET_GLOBAL(mode>0) with a generic ERR when the hook is not
// ready. The control plane must never turn that into `applied`; the honest status is
// `failed` (retried) or `inactive` (reported from the probed LSM/offset/attach facts).
func TestTitanExecPolicySyncerRejectedEnforcementIsNeverApplied(t *testing.T) {
	core, syncer, state, settings, _ := titanExecSyncerFixture(t, "tool-a")
	settings.TitanExec.Mode = TitanExecModeContain
	syncer.Configure(settings)
	core.setFailure("global:2:0", errors.New("core rejected command: request rejected"))
	status := syncer.Sync(context.Background())
	if status.State == TitanExecSyncStateApplied {
		t.Fatalf("a rejected enforcement push was claimed as applied: %+v", status)
	}
	if status.State != TitanExecSyncStateFailed || status.LastError == "" {
		t.Fatalf("a rejected enforcement push was not reported as failed: %+v", status)
	}
	if !hasStyxEventOfKind(state.Snapshot().Events, "titan_exec.policy_sync_failed") {
		t.Fatal("the rejected enforcement was not reported as an operator-visible failure")
	}
	// The bounded retry applies once the core accepts the mode again.
	core.setFailure("", nil)
	if got := syncer.Sync(context.Background()); got.State != TitanExecSyncStateApplied || got.Mode != TitanExecModeContain {
		t.Fatalf("retry after the core rejection did not apply: %+v", got)
	}
}

func newStateForTitanExecTest() *State { return NewState("test", defaultConfig()) }
