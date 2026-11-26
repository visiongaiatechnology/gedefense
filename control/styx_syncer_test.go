// STATUS: DIAMANT VGT SUPREME
package main

// POINT 3 / P3-T5 syncer tests: fake core, shared fixtures and the fail-safe
// ordering/retry/epoch contract.

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

// ------------------------------------------------------------ fake core

type styxCoreGlobalCall struct {
	Mode  uint8
	Flags uint8
}

type styxPolicyFakeCore struct {
	mu sync.Mutex

	calls []string

	version    string
	versionErr error
	epoch      string
	epochErr   error
	failPrefix string
	failErr    error

	globalCalls []styxCoreGlobalCall
	cells       map[uint64][2]uint8
	allow       map[string]struct{}
	resolvers   map[string]struct{}
}

func newStyxPolicyFakeCore() *styxPolicyFakeCore {
	return &styxPolicyFakeCore{
		version:   styxWireVersion,
		epoch:     "0123456789abcdef",
		cells:     map[uint64][2]uint8{},
		allow:     map[string]struct{}{},
		resolvers: map[string]struct{}{},
	}
}

func (c *styxPolicyFakeCore) record(call string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.calls = append(c.calls, call)
	if c.failPrefix != "" && strings.HasPrefix(call, c.failPrefix) && c.failErr != nil {
		return c.failErr
	}
	return nil
}

func (c *styxPolicyFakeCore) setFailure(prefix string, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.failPrefix, c.failErr = prefix, err
}

func (c *styxPolicyFakeCore) setEpoch(epoch string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.epoch = epoch
}

func (c *styxPolicyFakeCore) callSequence() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.calls...)
}

func (c *styxPolicyFakeCore) clearCalls() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.calls = nil
	c.globalCalls = nil
}

func (c *styxPolicyFakeCore) cellCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.cells)
}

func (c *styxPolicyFakeCore) stateCounts() (int, int, int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.cells), len(c.allow), len(c.resolvers)
}

func (c *styxPolicyFakeCore) StyxVersion() (string, error) {
	if err := c.record("version"); err != nil {
		return "", err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.versionErr != nil {
		return "", c.versionErr
	}
	return c.version, nil
}

func (c *styxPolicyFakeCore) StyxEpoch() (string, error) {
	if err := c.record("epoch"); err != nil {
		return "", err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.epochErr != nil {
		return "", c.epochErr
	}
	return c.epoch, nil
}

func (c *styxPolicyFakeCore) StyxGlobal(mode, flags uint8) error {
	if err := c.record(fmt.Sprintf("global:%d:%d", mode, flags)); err != nil {
		return err
	}
	c.mu.Lock()
	c.globalCalls = append(c.globalCalls, styxCoreGlobalCall{Mode: mode, Flags: flags})
	c.mu.Unlock()
	return nil
}

func (c *styxPolicyFakeCore) StyxModeSet(cgroupID uint64, mode, flags uint8) error {
	if err := c.record(fmt.Sprintf("mode:set:%d:%d:%d", cgroupID, mode, flags)); err != nil {
		return err
	}
	c.mu.Lock()
	c.cells[cgroupID] = [2]uint8{mode, flags}
	c.mu.Unlock()
	return nil
}

func (c *styxPolicyFakeCore) StyxModeDel(cgroupID uint64) error {
	if err := c.record(fmt.Sprintf("mode:del:%d", cgroupID)); err != nil {
		return err
	}
	c.mu.Lock()
	delete(c.cells, cgroupID)
	c.mu.Unlock()
	return nil
}

func (c *styxPolicyFakeCore) StyxAllowAdd(family uint8, scope string, cgroupID uint64, cidr string, portLo, portHi uint16, protoMask uint8) error {
	call := fmt.Sprintf("allow:add:%d:%s:%d:%s:%d:%d:%d", family, scope, cgroupID, cidr, portLo, portHi, protoMask)
	if err := c.record(call); err != nil {
		return err
	}
	c.mu.Lock()
	c.allow[call] = struct{}{}
	c.mu.Unlock()
	return nil
}

func (c *styxPolicyFakeCore) StyxAllowDel(family uint8, scope string, cgroupID uint64, cidr string, portLo, portHi uint16, protoMask uint8) error {
	if err := c.record(fmt.Sprintf("allow:del:%d:%s:%d:%s:%d:%d:%d", family, scope, cgroupID, cidr, portLo, portHi, protoMask)); err != nil {
		return err
	}
	c.mu.Lock()
	delete(c.allow, fmt.Sprintf("allow:add:%d:%s:%d:%s:%d:%d:%d", family, scope, cgroupID, cidr, portLo, portHi, protoMask))
	c.mu.Unlock()
	return nil
}

func (c *styxPolicyFakeCore) StyxResolverAdd(family uint8, cidr string) error {
	call := fmt.Sprintf("resolver:add:%d:%s", family, cidr)
	if err := c.record(call); err != nil {
		return err
	}
	c.mu.Lock()
	c.resolvers[call] = struct{}{}
	c.mu.Unlock()
	return nil
}

func (c *styxPolicyFakeCore) StyxResolverDel(family uint8, cidr string) error {
	if err := c.record(fmt.Sprintf("resolver:del:%d:%s", family, cidr)); err != nil {
		return err
	}
	c.mu.Lock()
	delete(c.resolvers, fmt.Sprintf("resolver:add:%d:%s", family, cidr))
	c.mu.Unlock()
	return nil
}

// ------------------------------------------------------------- fixtures

func styxPolicyTestSettings() RuntimeSettings {
	settings := defaultRuntimeSettings(defaultConfig())
	settings.Styx = &StyxFabricSettings{
		Enabled:      true,
		Mode:         StyxModeMonitor,
		LogFlows:     true,
		DnsResolvers: []string{"9.9.9.9/32", "2001:db8::1/128"},
		PerCell: []StyxCellMode{
			{CgroupID: 200, Mode: StyxModeMonitor, DnsResolver: true},
			{CgroupID: 100, Mode: StyxModeEnforce, AllowHostAllowlist: true},
		},
		Allowlist: []StyxAllowRule{
			{CgroupID: 100, CIDR: "203.0.113.10/32", PortLo: 443, PortHi: 443, Proto: "tcp"},
			{CgroupID: 100, CIDR: "198.51.100.0/24"},
		},
	}
	return settings
}

func styxDisabledSettings(settings RuntimeSettings) RuntimeSettings {
	out := settings
	disabled := defaultStyxFabricSettings()
	out.Styx = &disabled
	return out
}

func styxFakeCoreWithPolicy(t *testing.T) (*styxPolicyFakeCore, *styxPolicySyncer, *State) {
	t.Helper()
	core := newStyxPolicyFakeCore()
	state := NewState("test", defaultConfig())
	syncer := NewStyxPolicySyncer(core, state, styxPolicyTestSettings())
	return core, syncer, state
}

func styxPolicyTestPlan(t *testing.T, settings RuntimeSettings) styxPolicyPlan {
	t.Helper()
	plan, err := buildStyxPolicyPlan(effectiveStyxFabricSettings(settings))
	if err != nil {
		t.Fatalf("settings produced no plan: %v", err)
	}
	return plan
}

// ---------------------------------------------------------------- syncer

func TestStyxPolicySyncerPushOrderIsFailSafe(t *testing.T) {
	core, syncer, state := styxFakeCoreWithPolicy(t)
	status := syncer.Sync(context.Background())
	if status.State != StyxSyncStateApplied {
		t.Fatalf("sync did not reach applied: %+v (last error %q)", status, status.LastError)
	}
	if status.Capability != styxWireVersion || status.Version != styxWireVersion || status.Epoch != core.epoch {
		t.Fatalf("capability/epoch not recorded: %+v", status)
	}
	if !status.Enabled || status.Mode != StyxModeMonitor || !status.LogFlows {
		t.Fatalf("applied status does not describe the plan: %+v", status)
	}
	if status.Cells != 2 || status.AllowRules != 2 || status.Resolvers != 2 {
		t.Fatalf("applied counters are wrong: %+v", status)
	}
	calls := core.callSequence()
	positions := map[string]int{
		"global:0:0":        callIndex(calls, "global:0:0"),
		"global:1:1":        callIndex(calls, "global:1:1"),
		"mode:set:100:2:96": callIndex(calls, "mode:set:100:2:96"),
		"mode:set:200:1:72": callIndex(calls, "mode:set:200:1:72"),
		"allow:add:4:cell:100:198.51.100.0/24:0:65535:0": callIndex(calls, "allow:add:4:cell:100:198.51.100.0/24:0:65535:0"),
		"allow:add:4:cell:100:203.0.113.10/32:443:443:1": callIndex(calls, "allow:add:4:cell:100:203.0.113.10/32:443:443:1"),
		"resolver:add:4:9.9.9.9/32":                      callIndex(calls, "resolver:add:4:9.9.9.9/32"),
		"resolver:add:6:2001:db8::1/128":                 callIndex(calls, "resolver:add:6:2001:db8::1/128"),
	}
	for name, position := range positions {
		if position < 0 {
			t.Fatalf("%s was never sent; calls=%v", name, calls)
		}
	}
	ordered := []string{
		"global:0:0", "mode:set:100:2:96", "mode:set:200:1:72",
		"allow:add:4:cell:100:198.51.100.0/24:0:65535:0",
		"allow:add:4:cell:100:203.0.113.10/32:443:443:1",
		"resolver:add:4:9.9.9.9/32", "resolver:add:6:2001:db8::1/128",
		"global:1:1",
	}
	for index := 1; index < len(ordered); index++ {
		if positions[ordered[index-1]] >= positions[ordered[index]] {
			t.Fatalf("fail-safe/ordered sync contract violated: %v", calls)
		}
	}
	events := state.Snapshot().Events
	if hasStyxEventOfKind(events, "styx.policy_sync_failed") {
		t.Fatal("a successful sync reported a failure event")
	}
	if !hasStyxEventOfKind(events, "styx.policy_applied") {
		t.Fatal("a successful sync did not record styx.policy_applied")
	}
}

func TestStyxPolicySyncerSteadyStateDoesNotRewrite(t *testing.T) {
	core, syncer, _ := styxFakeCoreWithPolicy(t)
	if got := syncer.Sync(context.Background()); got.State != StyxSyncStateApplied {
		t.Fatalf("initial sync failed: %+v", got)
	}
	core.clearCalls()
	if got := syncer.Sync(context.Background()); got.State != StyxSyncStateApplied {
		t.Fatalf("steady-state sync failed: %+v", got)
	}
	for _, call := range core.callSequence() {
		if strings.HasPrefix(call, "global:") || strings.HasPrefix(call, "mode:") ||
			strings.HasPrefix(call, "allow:") || strings.HasPrefix(call, "resolver:") {
			t.Fatalf("an unchanged plan rewrote the kernel: %v", core.callSequence())
		}
	}
	// The capability/epoch probes still ran, so a core restart is noticed.
	if calls := core.callSequence(); len(calls) != 2 || calls[0] != "version" || calls[1] != "epoch" {
		t.Fatalf("steady-state poll did not only probe capability/epoch: %v", calls)
	}
}

func TestStyxPolicySyncerDisableTurnsGlobalOffFirst(t *testing.T) {
	core, syncer, state := styxFakeCoreWithPolicy(t)
	if got := syncer.Sync(context.Background()); got.State != StyxSyncStateApplied {
		t.Fatalf("initial sync failed: %+v", got)
	}
	if cells := core.cellCount(); cells != 2 {
		t.Fatalf("fake core did not receive the cell policies: %d", cells)
	}
	core.clearCalls()

	syncer.Configure(styxDisabledSettings(styxPolicyTestSettings()))
	status := syncer.Sync(context.Background())
	if status.State != StyxSyncStateApplied || status.Enabled || status.Mode != StyxModeOff {
		t.Fatalf("disable sync did not apply off: %+v", status)
	}
	calls := core.callSequence()
	if len(calls) < 3 || calls[0] != "version" || calls[1] != "epoch" || calls[2] != "global:0:0" {
		t.Fatalf("global off was not the first policy command: %v", calls)
	}
	if position := callIndex(calls, "global:1:1"); position >= 0 {
		t.Fatalf("disable sync re-enabled the global policy: %v", calls)
	}
	if callIndex(calls, "mode:del:100") < 0 || callIndex(calls, "mode:del:200") < 0 {
		t.Fatalf("disable sync did not delete the per-cell entries: %v", calls)
	}
	for _, call := range calls {
		if strings.HasPrefix(call, "allow:add") || strings.HasPrefix(call, "resolver:add") || strings.HasPrefix(call, "mode:set") {
			t.Fatalf("disable sync installed policy: %v", calls)
		}
	}
	if cells, allow, resolvers := core.stateCounts(); cells != 0 || allow != 0 || resolvers != 0 {
		t.Fatalf("disable sync left kernel state behind: cells=%d allow=%d resolvers=%d", cells, allow, resolvers)
	}
	if !hasStyxEventOfKind(state.Snapshot().Events, "styx.policy_applied") {
		t.Fatal("the disable sync did not record a styx.policy_applied event")
	}
	// Deletion is idempotent: a second disable sync sends nothing again.
	core.clearCalls()
	if got := syncer.Sync(context.Background()); got.State != StyxSyncStateApplied {
		t.Fatalf("idempotent disable sync failed: %+v", got)
	}
	for _, call := range core.callSequence() {
		if strings.HasPrefix(call, "mode:") || strings.HasPrefix(call, "allow:") || strings.HasPrefix(call, "resolver:") || strings.HasPrefix(call, "global:") {
			t.Fatalf("steady-state disable rewrote the kernel: %v", core.callSequence())
		}
	}
}

// TestStyxPolicySyncerDefaultOffDoesNotEnableAnything pins the upgrade contract of
// §12: a fresh document (enabled=false, mode=off) must only send the fail-safe
// global off. Nothing may be enabled, logged or written per cell.
func TestStyxPolicySyncerDefaultOffDoesNotEnableAnything(t *testing.T) {
	core := newStyxPolicyFakeCore()
	state := NewState("test", defaultConfig())
	settings := defaultRuntimeSettings(defaultConfig())
	if settings.Styx == nil || settings.Styx.Enabled {
		t.Fatalf("test fixture is not the upgrade default: %+v", settings.Styx)
	}
	syncer := NewStyxPolicySyncer(core, state, settings)
	status := syncer.Sync(context.Background())
	if status.State != StyxSyncStateApplied || status.Enabled || status.Mode != StyxModeOff || status.LogFlows {
		t.Fatalf("default-off sync claimed more than off: %+v", status)
	}
	calls := core.callSequence()
	want := []string{"version", "epoch", "global:0:0"}
	if len(calls) != len(want) {
		t.Fatalf("default-off sync sent more than the fail-safe off: %v", calls)
	}
	for index := range want {
		if calls[index] != want[index] {
			t.Fatalf("default-off sync call %d is %q, want %q (calls=%v)", index, calls[index], want[index], calls)
		}
	}
	if cells, allow, resolvers := core.stateCounts(); cells != 0 || allow != 0 || resolvers != 0 {
		t.Fatalf("default-off sync wrote kernel state: cells=%d allow=%d resolvers=%d", cells, allow, resolvers)
	}
}

func TestStyxPolicySyncerCapabilityMissingIsNotDegradation(t *testing.T) {
	core, syncer, state := styxFakeCoreWithPolicy(t)
	core.versionErr = ErrStyxUnavailable
	status := syncer.Sync(context.Background())
	if status.State != StyxSyncStateCapabilityMissing {
		t.Fatalf("old core did not map to capability-missing: %+v", status)
	}
	if status.Capability != styxCapabilityMissing || status.Version != "" || status.Epoch != "" {
		t.Fatalf("capability-missing status is wrong: %+v", status)
	}
	for _, call := range core.callSequence() {
		if call != "version" {
			t.Fatalf("capability-missing path issued a policy command: %v", core.callSequence())
		}
	}
	snapshot := state.Snapshot()
	if snapshot.XDR.Degraded {
		t.Fatal("a missing StyX capability degraded XDR globally")
	}
	if hasStyxEventOfKind(snapshot.Events, "styx.policy_sync_failed") {
		t.Fatal("a missing capability was reported as a policy sync failure")
	}
	if !hasStyxEventOfKind(snapshot.Events, "styx.capability_missing") {
		t.Fatal("the missing capability was not reported as an operator-visible fact")
	}
	if syncer.CapabilityKnown() {
		t.Fatal("capability cannot be known after an unavailable probe")
	}
}

func TestStyxPolicySyncerRetriesFailureThenApplies(t *testing.T) {
	core, syncer, state := styxFakeCoreWithPolicy(t)
	clock := time.Date(2026, 2, 1, 12, 0, 0, 0, time.UTC)
	syncer.now = func() time.Time { return clock }
	core.setFailure("global:1:1", errors.New("simulated map write failure"))
	failed := syncer.Sync(context.Background())
	if failed.State != StyxSyncStateFailed || failed.LastError == "" {
		t.Fatalf("failed sync was not reported: %+v", failed)
	}
	if !hasStyxEventOfKind(state.Snapshot().Events, "styx.policy_sync_failed") {
		t.Fatal("the failed sync did not record styx.policy_sync_failed")
	}
	if countStyxEventsOfKind(state.Snapshot().Events, "styx.policy_sync_failed") != 1 {
		t.Fatal("failure event was not deduplicated")
	}

	// The retry is gated: at the same instant SyncIfDue must not hammer the core.
	core.setFailure("", nil)
	callsBefore := len(core.callSequence())
	if due := syncer.SyncIfDue(context.Background()); due.State != StyxSyncStateFailed {
		t.Fatalf("SyncIfDue retried before the backoff elapsed: %+v", due)
	}
	if len(core.callSequence()) != callsBefore {
		t.Fatal("SyncIfDue issued a core command before the retry interval elapsed")
	}
	clock = clock.Add(styxPolicySyncRetryInterval + time.Second)
	if got := syncer.SyncIfDue(context.Background()); got.State != StyxSyncStateApplied {
		t.Fatalf("retry after the backoff did not apply: %+v", got)
	}
	if countStyxEventsOfKind(state.Snapshot().Events, "styx.policy_sync_failed") != 1 {
		t.Fatal("the retry reported the old failure again")
	}
}

func TestStyxPolicySyncerEpochChangeForcesFullResync(t *testing.T) {
	core, syncer, _ := styxFakeCoreWithPolicy(t)
	if got := syncer.Sync(context.Background()); got.State != StyxSyncStateApplied {
		t.Fatalf("initial sync failed: %+v", got)
	}
	core.clearCalls()
	core.setEpoch("fedcba9876543210")
	status := syncer.Sync(context.Background())
	if status.State != StyxSyncStateApplied || status.Epoch != "fedcba9876543210" {
		t.Fatalf("resync after a core restart failed: %+v", status)
	}
	calls := core.callSequence()
	if callIndex(calls, "global:0:0") < 0 || callIndex(calls, "global:1:1") < 0 {
		t.Fatalf("epoch change did not re-run the fail-safe global push: %v", calls)
	}
	if callIndex(calls, "mode:set:100:2:96") < 0 || callIndex(calls, "mode:set:200:1:72") < 0 {
		t.Fatalf("epoch change did not re-push the per-cell policies: %v", calls)
	}
}
