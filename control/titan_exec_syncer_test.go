// STATUS: DIAMANT VGT SUPREME
package main

// POINT 1 / P1-T2 tests: Titan exec-gate syncer against an in-process fake core
// (fail-safe ordering, disable path, epoch resync) with the fake-core fixture the
// status/retry/client tests share. The syncer uses the real plan compiler, so these
// tests also exercise the documented evidence ladder.

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// ------------------------------------------------------------ fake core

type titanExecGlobalCall struct {
	Mode  uint8
	Flags uint8
}

type titanExecFakeCore struct {
	mu sync.Mutex

	calls []string

	version    string
	versionErr error
	epoch      string
	epochErr   error
	status     TitanExecCoreStatus
	statusErr  error
	failPrefix string
	failErr    error

	globalCalls []titanExecGlobalCall
	allow       map[string]TitanExecAllowIdentity
	scopes      map[uint64][2]uint8
	batches     [][]string
	clears      int
	batchReject int
	nextID      uint32
}

func newTitanExecFakeCore() *titanExecFakeCore {
	return &titanExecFakeCore{
		version: titanExecSupportedVersion,
		epoch:   "0123456789abcdef",
		status: TitanExecCoreStatus{
			State: "applied", Path: titanExecPathBPFLSM, LSM: titanExecLSMActive,
			Offsets: titanExecOffsetsValid, Epoch: "0123456789abcdef",
		},
		allow:  map[string]TitanExecAllowIdentity{},
		scopes: map[uint64][2]uint8{},
	}
}

func (c *titanExecFakeCore) record(call string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.calls = append(c.calls, call)
	if c.failPrefix != "" && strings.HasPrefix(call, c.failPrefix) && c.failErr != nil {
		return c.failErr
	}
	return nil
}

func (c *titanExecFakeCore) setFailure(prefix string, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.failPrefix, c.failErr = prefix, err
}

func (c *titanExecFakeCore) setEpoch(epoch string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.epoch = epoch
}

func (c *titanExecFakeCore) callSequence() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.calls...)
}

func (c *titanExecFakeCore) clearCalls() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.calls = nil
	c.globalCalls = nil
	c.batches = nil
}

func (c *titanExecFakeCore) counts() (int, int, int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.allow), len(c.scopes), c.clears
}

func (c *titanExecFakeCore) TitanExecVersion() (string, error) {
	if err := c.record("version"); err != nil {
		return "", err
	}
	return c.version, c.versionErr
}

func (c *titanExecFakeCore) TitanExecEpoch() (string, error) {
	if err := c.record("epoch"); err != nil {
		return "", err
	}
	return c.epoch, c.epochErr
}

func (c *titanExecFakeCore) TitanExecStatus() (TitanExecCoreStatus, error) {
	if err := c.record("status"); err != nil {
		return TitanExecCoreStatus{}, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	status := c.status
	status.Epoch = c.epoch
	status.Entries = len(c.allow)
	status.Scopes = len(c.scopes)
	return status, c.statusErr
}

func (c *titanExecFakeCore) TitanExecSetGlobal(mode, flags uint8) error {
	call := fmt.Sprintf("global:%d:%d", mode, flags)
	if err := c.record(call); err != nil {
		return err
	}
	c.mu.Lock()
	c.globalCalls = append(c.globalCalls, titanExecGlobalCall{Mode: mode, Flags: flags})
	c.mu.Unlock()
	return nil
}

func (c *titanExecFakeCore) TitanExecAllowAdd(path string) (TitanExecAllowIdentity, error) {
	if err := c.record("add:" + path); err != nil {
		return TitanExecAllowIdentity{}, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.nextID++
	identity := TitanExecAllowIdentity{State: "added", Dev: 1000 + c.nextID, Ino: 2000 + uint64(c.nextID)}
	c.allow[path] = identity
	return identity, nil
}

func (c *titanExecFakeCore) TitanExecAllowAddBatch(paths []string) (TitanExecBatchResult, error) {
	call := "batch:" + strings.Join(paths, "|")
	if err := c.record(call); err != nil {
		return TitanExecBatchResult{}, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.batches = append(c.batches, append([]string(nil), paths...))
	for _, path := range paths {
		c.nextID++
		c.allow[path] = TitanExecAllowIdentity{State: "added", Dev: 1000 + c.nextID, Ino: 2000 + uint64(c.nextID)}
	}
	if c.batchReject > 0 {
		return TitanExecBatchResult{Added: len(paths) - c.batchReject, Rejected: c.batchReject, Error: "symlink rejected"}, nil
	}
	return TitanExecBatchResult{Added: len(paths)}, nil
}

func (c *titanExecFakeCore) TitanExecAllowDel(dev uint32, ino uint64) error {
	if err := c.record(fmt.Sprintf("del:%d:%d", dev, ino)); err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for path, identity := range c.allow {
		if identity.Dev == dev && identity.Ino == ino {
			delete(c.allow, path)
		}
	}
	return nil
}

func (c *titanExecFakeCore) TitanExecClear() error {
	if err := c.record("clear"); err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.clears++
	c.allow = map[string]TitanExecAllowIdentity{}
	return nil
}

func (c *titanExecFakeCore) TitanExecScopeSet(cgroupID uint64, mode, flags uint8) error {
	if err := c.record(fmt.Sprintf("scope:%d:%d:%d", cgroupID, mode, flags)); err != nil {
		return err
	}
	c.mu.Lock()
	c.scopes[cgroupID] = [2]uint8{mode, flags}
	c.mu.Unlock()
	return nil
}

func (c *titanExecFakeCore) TitanExecScopeDel(cgroupID uint64) error {
	if err := c.record(fmt.Sprintf("scopedel:%d", cgroupID)); err != nil {
		return err
	}
	c.mu.Lock()
	delete(c.scopes, cgroupID)
	c.mu.Unlock()
	return nil
}

// ---------------------------------------------------------------- fixtures

func titanExecSyncerWriteExecutables(t *testing.T, root string, names ...string) []string {
	t.Helper()
	paths := make([]string, 0, len(names))
	for _, name := range names {
		path := filepath.Join(root, name)
		if err := os.WriteFile(path, []byte("#!/bin/sh\n"), 0o755); err != nil {
			t.Fatal(err)
		}
		paths = append(paths, path)
	}
	return paths
}

func titanExecSyncerSettings(root string) RuntimeSettings {
	settings := defaultRuntimeSettings(defaultConfig())
	settings.TitanExec = &TitanExecFabricSettings{
		Enabled: true, Mode: TitanExecModeObserve, ExecRoots: []string{root},
		MaxEntries: 64, MaxScopes: 16,
	}
	return settings
}

func titanExecSyncerFixture(t *testing.T, names ...string) (*titanExecFakeCore, *titanExecPolicySyncer, *State, RuntimeSettings, []string) {
	t.Helper()
	root := t.TempDir()
	paths := titanExecSyncerWriteExecutables(t, root, names...)
	packages := newFakeTitanPackages()
	for _, path := range paths {
		packages.own(path, "dpkg", "coreutils")
	}
	settings := titanExecSyncerSettings(root)
	core := newTitanExecFakeCore()
	state := NewState("test", defaultConfig())
	syncer := NewTitanExecPolicySyncer(core, state, settings, titanExecPlanDeps{Packages: packages})
	return core, syncer, state, settings, paths
}

func titanExecDisabledSettings() RuntimeSettings {
	settings := defaultRuntimeSettings(defaultConfig())
	namespace := defaultTitanExecFabricSettings()
	settings.TitanExec = &namespace
	return settings
}

// ---------------------------------------------------------------- syncer

func TestTitanExecPolicySyncerPushOrderIsFailSafe(t *testing.T) {
	core, syncer, state, _, paths := titanExecSyncerFixture(t, "tool-a", "tool-b")
	status := syncer.Sync(context.Background())
	if status.State != TitanExecSyncStateApplied {
		t.Fatalf("sync did not reach applied: %+v", status)
	}
	if status.Capability != titanExecSupportedVersion || status.Epoch != core.epoch ||
		status.Path != titanExecPathBPFLSM || status.LSM != titanExecLSMActive || status.Offsets != titanExecOffsetsValid {
		t.Fatalf("capability facts were not recorded honestly: %+v", status)
	}
	if !status.Enabled || status.Mode != TitanExecModeObserve || status.AppliedEntries != len(paths) {
		t.Fatalf("applied status does not describe the plan: %+v", status)
	}
	calls := core.callSequence()
	if len(calls) < 6 || calls[0] != "version" || calls[1] != "epoch" || calls[2] != "status" || calls[3] != "global:0:0" {
		t.Fatalf("fail-safe order violated at the start: %v", calls)
	}
	if last := calls[len(calls)-1]; last != "global:1:0" {
		t.Fatalf("the configured mode was not applied last: %v", calls)
	}
	for _, path := range paths {
		if callIndex(calls, "add:"+path) < 0 {
			t.Fatalf("allow entry %q was never sent: %v", path, calls)
		}
	}
	if callIndex(calls, "clear") >= 0 {
		t.Fatalf("an incremental push cleared the map: %v", calls)
	}
	entries, scopes, _ := core.counts()
	if entries != len(paths) || scopes != 0 {
		t.Fatalf("fake core state is wrong: entries=%d scopes=%d", entries, scopes)
	}
	if hasStyxEventOfKind(state.Snapshot().Events, "titan_exec.policy_sync_failed") {
		t.Fatal("a successful sync reported a failure event")
	}
	if !hasStyxEventOfKind(state.Snapshot().Events, "titan_exec.policy_applied") {
		t.Fatal("a successful sync did not record titan_exec.policy_applied")
	}
}

func TestTitanExecPolicySyncerSteadyStateAndEpochResync(t *testing.T) {
	core, syncer, _, _, _ := titanExecSyncerFixture(t, "tool-a")
	if got := syncer.Sync(context.Background()); got.State != TitanExecSyncStateApplied {
		t.Fatalf("initial sync failed: %+v", got)
	}
	core.clearCalls()
	if got := syncer.Sync(context.Background()); got.State != TitanExecSyncStateApplied {
		t.Fatalf("steady-state sync failed: %+v", got)
	}
	calls := core.callSequence()
	if len(calls) != 3 || calls[0] != "version" || calls[1] != "epoch" || calls[2] != "status" {
		t.Fatalf("an unchanged plan rewrote the kernel: %v", calls)
	}
	// A core restart (new epoch, empty maps) must force the full fail-safe push.
	core.clearCalls()
	core.setEpoch("fedcba9876543210")
	status := syncer.Sync(context.Background())
	if status.State != TitanExecSyncStateApplied || status.Epoch != "fedcba9876543210" {
		t.Fatalf("resync after a core restart failed: %+v", status)
	}
	calls = core.callSequence()
	if callIndex(calls, "global:0:0") < 0 || callIndex(calls, "global:1:0") < 0 {
		t.Fatalf("epoch change did not re-run the fail-safe global push: %v", calls)
	}
}

func TestTitanExecPolicySyncerDisableTurnsGlobalOffFirst(t *testing.T) {
	core, syncer, state, settings, _ := titanExecSyncerFixture(t, "tool-a")
	settings.TitanExec.StrictCgroups = []uint64{77}
	syncer.Configure(settings)
	if got := syncer.Sync(context.Background()); got.State != TitanExecSyncStateApplied {
		t.Fatalf("initial sync failed: %+v", got)
	}
	core.clearCalls()
	syncer.Configure(titanExecDisabledSettings())
	status := syncer.Sync(context.Background())
	if status.State != TitanExecSyncStateApplied || status.Enabled || status.Mode != TitanExecModeOff {
		t.Fatalf("disable sync did not apply off: %+v", status)
	}
	calls := core.callSequence()
	if len(calls) < 5 || calls[3] != "global:0:0" {
		t.Fatalf("global off was not the first policy command: %v", calls)
	}
	if callIndex(calls, "global:1:0") >= 0 || callIndex(calls, "global:2:0") >= 0 || callIndex(calls, "global:3:0") >= 0 {
		t.Fatalf("disable sync re-enabled the gate: %v", calls)
	}
	if callIndex(calls, "clear") < 0 || callIndex(calls, "scopedel:77") < 0 {
		t.Fatalf("disable sync did not clear the allowlist or the scopes: %v", calls)
	}
	for _, call := range calls {
		if strings.HasPrefix(call, "add:") || strings.HasPrefix(call, "batch:") || strings.HasPrefix(call, "scope:") {
			t.Fatalf("disable sync installed policy: %v", calls)
		}
	}
	if entries, scopes, clears := core.counts(); entries != 0 || scopes != 0 || clears == 0 {
		t.Fatalf("disable sync left kernel state behind: entries=%d scopes=%d clears=%d", entries, scopes, clears)
	}
	if !hasStyxEventOfKind(state.Snapshot().Events, "titan_exec.policy_applied") {
		t.Fatal("the disable sync did not record titan_exec.policy_applied")
	}
}

// TestTitanExecPolicySyncerDefaultOffDoesNotEnableAnything pins the upgrade contract:
// a fresh document (enabled=false, mode=off) must never enable anything.
