// STATUS: DIAMANT VGT SUPREME
package main

// M3 tests: durable cgroup_path identity, re-resolution on every sync, drift
// handling and the fail-safe degraded state when a path cannot be resolved. The
// kernel is faked, so the contract is pinned without a privileged host.

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"
)

// ------------------------------------------------------------ fake resolver

type styxFakeCgroupResolver struct {
	mu    sync.Mutex
	ids   map[string]uint64
	errs  map[string]error
	calls []string
}

func newStyxFakeCgroupResolver(ids map[string]uint64) *styxFakeCgroupResolver {
	return &styxFakeCgroupResolver{ids: ids, errs: map[string]error{}}
}

func (r *styxFakeCgroupResolver) Resolve(logicalPath string) (uint64, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, logicalPath)
	if err := r.errs[logicalPath]; err != nil {
		return 0, err
	}
	id, ok := r.ids[logicalPath]
	if !ok {
		return 0, fmt.Errorf("%w: %s", errStyxCgroupPathMissing, logicalPath)
	}
	return id, nil
}

func (r *styxFakeCgroupResolver) set(path string, id uint64, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err != nil {
		r.errs[path] = err
		delete(r.ids, path)
		return
	}
	delete(r.errs, path)
	r.ids[path] = id
}

func (r *styxFakeCgroupResolver) callCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.calls)
}

// ------------------------------------------------------------- fixtures

const styxTestUnitPath = "/system.slice/php8.3-fpm.service"

func styxPathBackedSettings(t *testing.T) RuntimeSettings {
	t.Helper()
	settings := defaultRuntimeSettings(defaultConfig())
	settings.Styx = &StyxFabricSettings{
		Enabled:  true,
		Mode:     StyxModeMonitor,
		LogFlows: true,
		PerCell: []StyxCellMode{{
			CgroupID: 999999, CgroupPath: styxTestUnitPath,
			Mode: StyxModeEnforce, AllowHostAllowlist: true,
		}},
		Allowlist: []StyxAllowRule{{
			CgroupID: 999999, CgroupPath: styxTestUnitPath,
			CIDR: "203.0.113.10/32", PortLo: 443, PortHi: 443, Proto: "tcp",
		}},
	}
	if err := validateStyxFabricSettings(settings.Styx); err != nil {
		t.Fatalf("path-backed settings are invalid: %v", err)
	}
	return settings
}

func styxFakeSyncerWithResolver(t *testing.T, settings RuntimeSettings, resolver styxCgroupResolver) (*styxPolicyFakeCore, *styxPolicySyncer, *State) {
	t.Helper()
	core := newStyxPolicyFakeCore()
	state := NewState("test", defaultConfig())
	syncer := NewStyxPolicySyncer(core, state, settings)
	syncer.resolver = resolver
	return core, syncer, state
}

func hasCallWithPrefix(calls []string, prefix string) bool {
	for _, call := range calls {
		if strings.HasPrefix(call, prefix) {
			return true
		}
	}
	return false
}

// --------------------------------------------------------- path normaliser

func TestNormalizeStyxCgroupPath(t *testing.T) {
	valid := map[string]string{
		"/system.slice/php8.3-fpm.service":                "/system.slice/php8.3-fpm.service",
		"/sys/fs/cgroup/system.slice/nginx.service":       "/system.slice/nginx.service",
		"/system.slice/gedefense\\x2dworker.service":      "/system.slice/gedefense\\x2dworker.service",
		"/user.slice/user-1000.slice/session-3.scope":     "/user.slice/user-1000.slice/session-3.scope",
		"/system.slice/php8.3-fpm.service@abc123.service": "/system.slice/php8.3-fpm.service@abc123.service",
		"/vgt-cells/parser-0123-4567":                     "/vgt-cells/parser-0123-4567",
	}
	for raw, want := range valid {
		got, err := normalizeStyxCgroupPath(raw)
		if err != nil {
			t.Fatalf("valid path %q rejected: %v", raw, err)
		}
		if got != want {
			t.Fatalf("path %q normalised to %q, want %q", raw, got, want)
		}
	}
	invalid := []string{
		"",
		"   ",
		"system.slice/php.service",
		"../etc/passwd",
		"/system.slice/../../etc/passwd",
		"/system.slice//php.service",
		"/sys/fs/cgroup",
		"/sys/fs/cgroup/",
		"/",
		"/system.slice/php service",
		"/system.slice/php\nservice",
		"/system.slice/php\x00service",
		"/system.slice/" + strings.Repeat("a", styxCgroupPathMaxBytes),
	}
	for _, raw := range invalid {
		if _, err := normalizeStyxCgroupPath(raw); err == nil {
			t.Fatalf("hostile cgroup path %q was accepted", raw)
		}
	}
}

// ------------------------------------------------------------- plan builder

func TestStyxPolicyPlanCarriesPathBackedIdentities(t *testing.T) {
	settings := styxPathBackedSettings(t)
	// The settings store drops a stale numeric id when a durable path is present.
	if id := settings.Styx.PerCell[0].CgroupID; id != 0 {
		t.Fatalf("a path-backed cell kept a stale numeric id: %d", id)
	}
	plan, err := buildStyxPolicyPlan(*settings.Styx)
	if err != nil {
		t.Fatal(err)
	}
	// Unresolved at validation time (pure plan builder), so it must not claim a
	// kernel entry - but it also must not be dropped from the persisted revision.
	if len(plan.Cells) != 0 || len(plan.UnresolvedCells) != 1 {
		t.Fatalf("path-backed cell without an id must stay unresolved: %+v", plan)
	}
	if plan.UnresolvedCells[0].CgroupPath != styxTestUnitPath {
		t.Fatalf("unresolved cell lost its path: %+v", plan.UnresolvedCells[0])
	}
	if len(plan.UnresolvedAllow) != 1 || plan.UnresolvedAllow[0].CgroupPath != styxTestUnitPath {
		t.Fatalf("unresolved allow rule lost its path: %+v", plan.UnresolvedAllow)
	}

	// The settings store must preserve the path through validation (normalisation
	// never rewrites an operator value into a numeric id).
	normalized := cloneStyxFabricSettings(*settings.Styx)
	if err := validateStyxFabricSettings(&normalized); err != nil {
		t.Fatal(err)
	}
	if len(normalized.PerCell) != 1 || normalized.PerCell[0].CgroupPath != styxTestUnitPath || normalized.PerCell[0].CgroupID != 0 {
		t.Fatalf("validation did not preserve the durable path / did not drop the stale id: %+v", normalized.PerCell)
	}
	if len(normalized.Allowlist) != 1 || normalized.Allowlist[0].CgroupPath != styxTestUnitPath {
		t.Fatalf("validation did not preserve the allow-rule path: %+v", normalized.Allowlist)
	}
}

func TestStyxPolicyPlanRejectsDuplicateResolvedCgroupIDs(t *testing.T) {
	settings := &StyxFabricSettings{
		Enabled: true, Mode: StyxModeMonitor, LogFlows: true,
		PerCell: []StyxCellMode{
			{CgroupID: 42, CgroupPath: "/system.slice/a.service", Mode: StyxModeEnforce},
			{CgroupID: 42, CgroupPath: "/system.slice/b.service", Mode: StyxModeEnforce},
		},
	}
	if _, err := buildStyxPolicyPlan(*settings); err == nil || !strings.Contains(err.Error(), "same cgroup id") {
		t.Fatalf("two paths resolving to one kernel cgroup were accepted: %v", err)
	}
}

// ------------------------------------------------------------------- syncer

func TestStyxPolicySyncerResolvesPathIdentities(t *testing.T) {
	settings := styxPathBackedSettings(t)
	resolver := newStyxFakeCgroupResolver(map[string]uint64{styxTestUnitPath: 3149})
	core, syncer, _ := styxFakeSyncerWithResolver(t, settings, resolver)

	status := syncer.Sync(context.Background())
	if status.State != StyxSyncStateApplied {
		t.Fatalf("path-backed sync did not apply: %+v (%s)", status, status.DegradedReason)
	}
	if status.Cells != 1 || status.AllowRules != 1 || status.PathsResolved != 2 || status.PathsUnresolved != 0 {
		t.Fatalf("identity counters are wrong: %+v", status)
	}
	calls := core.callSequence()
	for _, want := range []string{
		"mode:set:3149:2:96",
		"allow:add:4:cell:3149:203.0.113.10/32:443:443:1",
	} {
		if callIndex(calls, want) < 0 {
			t.Fatalf("resolved identity was not written (%q missing): %v", want, calls)
		}
	}
	// The stale persisted id must never reach the kernel.
	for _, call := range calls {
		if strings.Contains(call, "999999") {
			t.Fatalf("stale persisted cgroup id was written: %v", calls)
		}
	}

	// Steady state: re-resolution happens but no kernel command is issued.
	core.clearCalls()
	if got := syncer.Sync(context.Background()); got.State != StyxSyncStateApplied {
		t.Fatalf("steady state sync failed: %+v", got)
	}
	for _, call := range core.callSequence() {
		if call != "version" && call != "epoch" {
			t.Fatalf("steady state rewrote the kernel: %v", core.callSequence())
		}
	}
	if resolver.callCount() != 4 {
		t.Fatalf("path identity was not re-resolved on both syncs: %d", resolver.callCount())
	}
}

func TestStyxPolicySyncerHandlesCgroupIDDriftAfterRestart(t *testing.T) {
	settings := styxPathBackedSettings(t)
	resolver := newStyxFakeCgroupResolver(map[string]uint64{styxTestUnitPath: 3149})
	core, syncer, _ := styxFakeSyncerWithResolver(t, settings, resolver)
	if got := syncer.Sync(context.Background()); got.State != StyxSyncStateApplied {
		t.Fatalf("initial sync failed: %+v", got)
	}
	core.clearCalls()

	// A reboot / `systemctl restart` re-creates the cgroup: same path, new inode.
	resolver.set(styxTestUnitPath, 5000, nil)
	status := syncer.Sync(context.Background())
	if status.State != StyxSyncStateApplied {
		t.Fatalf("drift sync did not apply: %+v", status)
	}
	if status.CgroupDriftTotal != 1 {
		t.Fatalf("cgroup drift was not counted: %+v", status)
	}
	calls := core.callSequence()
	if callIndex(calls, "mode:set:5000:2:96") < 0 {
		t.Fatalf("new cgroup id was not applied: %v", calls)
	}
	// The stale identity is removed by the normal desired-vs-applied reconciliation.
	if callIndex(calls, "mode:del:3149") < 0 {
		t.Fatalf("stale cgroup id was not deleted: %v", calls)
	}
	if callIndex(calls, "allow:add:4:cell:5000:203.0.113.10/32:443:443:1") < 0 {
		t.Fatalf("allow rule was not moved to the new cgroup id: %v", calls)
	}
	if callIndex(calls, "allow:del:4:cell:3149:203.0.113.10/32:443:443:1") < 0 {
		t.Fatalf("stale allow rule was not deleted: %v", calls)
	}
	if len(status.Identities) == 0 || status.Identities[0].State != styxIdentityDrifted {
		t.Fatalf("drift is not visible in the identity list: %+v", status.Identities)
	}

	// The drift is reported once, not on every retry/epoch poll.
	core.clearCalls()
	again := syncer.Sync(context.Background())
	if again.CgroupDriftTotal != 1 {
		t.Fatalf("drift counter grew without a new drift: %+v", again)
	}
	for _, call := range core.callSequence() {
		if call != "version" && call != "epoch" {
			t.Fatalf("post-drift steady state rewrote the kernel: %v", core.callSequence())
		}
	}
}

func TestStyxPolicySyncerDegradesInsteadOfWritingStaleCgroupID(t *testing.T) {
	settings := styxPathBackedSettings(t)
	resolver := newStyxFakeCgroupResolver(map[string]uint64{})
	core, syncer, state := styxFakeSyncerWithResolver(t, settings, resolver)

	status := syncer.Sync(context.Background())
	if status.State != StyxSyncStateDegraded {
		t.Fatalf("unresolvable cgroup path did not degrade: %+v", status)
	}
	if !status.Degraded || status.PathsUnresolved != 2 || status.PathsResolved != 0 {
		t.Fatalf("degraded identity counters are wrong: %+v", status)
	}
	if !strings.Contains(status.DegradedReason, "cgroup_path") {
		t.Fatalf("degraded reason does not name the path problem: %q", status.DegradedReason)
	}
	// The global fail-safe policy is still applied; no per-cell id is written.
	if callIndex(core.callSequence(), "global:0:0") < 0 || callIndex(core.callSequence(), "global:1:1") < 0 {
		t.Fatalf("resolvable global policy was not applied: %v", core.callSequence())
	}
	for _, call := range core.callSequence() {
		if strings.HasPrefix(call, "mode:set") || strings.HasPrefix(call, "allow:add") || strings.Contains(call, "999999") {
			t.Fatalf("degraded sync wrote a cell identity anyway: %v", core.callSequence())
		}
	}
	if !hasStyxEventOfKind(state.Snapshot().Events, "styx.cgroup_identity_degraded") {
		t.Fatal("the degraded identity was not reported as an operator-visible event")
	}

	// Once the path becomes resolvable again, the cell is installed and the state
	// recovers - still without ever using the stale persisted id.
	resolver.set(styxTestUnitPath, 3149, nil)
	recovered := syncer.Sync(context.Background())
	if recovered.State != StyxSyncStateApplied || recovered.Degraded || recovered.PathsUnresolved != 0 {
		t.Fatalf("identity recovery was not reported: %+v", recovered)
	}
	if callIndex(core.callSequence(), "mode:set:3149:2:96") < 0 {
		t.Fatalf("recovered identity was not applied: %v", core.callSequence())
	}
	if !hasStyxEventOfKind(state.Snapshot().Events, "styx.cgroup_identity_recovered") {
		t.Fatal("the identity recovery was not reported")
	}
}

func TestStyxPolicySyncerLegacyNumericIDsStayBackwardCompatible(t *testing.T) {
	core, syncer, _ := styxFakeSyncerWithResolver(t, styxPolicyTestSettings(), nil)
	status := syncer.Sync(context.Background())
	if status.State != StyxSyncStateApplied || status.Degraded {
		t.Fatalf("legacy numeric settings no longer apply: %+v", status)
	}
	// Two legacy cells and two legacy allow rules are visible as legacy identities.
	if status.LegacyIDs != 4 || status.PathsResolved != 0 {
		t.Fatalf("legacy identity counters are wrong: %+v", status)
	}
	calls := core.callSequence()
	if callIndex(calls, "mode:set:100:2:96") < 0 || callIndex(calls, "mode:set:200:1:72") < 0 {
		t.Fatalf("legacy numeric ids are no longer written: %v", calls)
	}
}

func TestStyxPolicySyncerInactiveNamespaceDoesNotResolve(t *testing.T) {
	settings := styxPathBackedSettings(t)
	settings.Styx.Enabled = false
	settings.Styx.Mode = StyxModeOff
	resolver := newStyxFakeCgroupResolver(map[string]uint64{})
	_, syncer, _ := styxFakeSyncerWithResolver(t, settings, resolver)

	status := syncer.Sync(context.Background())
	if status.State != StyxSyncStateApplied || status.Degraded {
		t.Fatalf("an inactive namespace must not report identity degradation: %+v", status)
	}
	if resolver.callCount() != 0 {
		t.Fatalf("an inactive namespace performed cgroup resolution: %d", resolver.callCount())
	}
}

// -------------------------------------------------------------- settings JSON

func TestStyxSettingsJSONCarriesCgroupPathBackwardCompatibly(t *testing.T) {
	var legacy StyxCellMode
	if err := json.Unmarshal([]byte(`{"cgroup_id":3149,"mode":"enforce"}`), &legacy); err != nil {
		t.Fatal(err)
	}
	if legacy.CgroupID != 3149 || legacy.CgroupPath != "" || legacy.Mode != StyxModeEnforce {
		t.Fatalf("legacy cell JSON no longer decodes: %+v", legacy)
	}
	var durable StyxCellMode
	if err := json.Unmarshal([]byte(`{"cgroup_id":0,"cgroup_path":"/system.slice/x.service","mode":"monitor"}`), &durable); err != nil {
		t.Fatal(err)
	}
	if durable.CgroupPath != "/system.slice/x.service" {
		t.Fatalf("cgroup_path did not decode: %+v", durable)
	}
	encoded, err := json.Marshal(durable)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(encoded), `"cgroup_path":"/system.slice/x.service"`) {
		t.Fatalf("cgroup_path did not encode: %s", encoded)
	}
}
