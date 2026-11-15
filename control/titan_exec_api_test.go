// STATUS: DIAMANT VGT SUPREME
package main

// POINT 1 / P1-T5 API tests: the read-only Titan exec-gate endpoints, the bounded
// /api/v1/status field, the settings-module runtime detection and the
// status-honesty contract (§8): a core reporting path=none/lsm=inactive or a
// missing capability must never produce an active/enforced claim.

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// ------------------------------------------------------------ fake core

// titanExecPolicyFakeCore is the titanExecPolicyCore surface the syncer probes.
// It answers with explicit facts so the API tests can pin the honest projection
// for an active kernel, an inactive LSM and a pre-TitanExec core.
type titanExecPolicyFakeCore struct {
	mu sync.Mutex

	version    string
	versionErr error
	epoch      string
	coreStatus TitanExecCoreStatus

	calls       []string
	globalCalls [][2]uint8
	globalErr   error
}

func newTitanExecPolicyFakeCore() *titanExecPolicyFakeCore {
	return &titanExecPolicyFakeCore{
		version: titanExecSupportedVersion, epoch: "0123456789abcdef",
		coreStatus: TitanExecCoreStatus{
			State: "applied", Mode: 0, Path: titanExecPathBPFLSM, LSM: titanExecLSMActive,
			Offsets: titanExecOffsetsValid, Epoch: "0123456789abcdef",
		},
	}
}

func (c *titanExecPolicyFakeCore) record(call string) {
	c.mu.Lock()
	c.calls = append(c.calls, call)
	c.mu.Unlock()
}

func (c *titanExecPolicyFakeCore) TitanExecVersion() (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.versionErr != nil {
		return "", c.versionErr
	}
	return c.version, nil
}

func (c *titanExecPolicyFakeCore) TitanExecEpoch() (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.epoch, nil
}

func (c *titanExecPolicyFakeCore) TitanExecStatus() (TitanExecCoreStatus, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.coreStatus, nil
}

func (c *titanExecPolicyFakeCore) TitanExecSetGlobal(mode, flags uint8) error {
	c.record("set_global")
	c.mu.Lock()
	c.globalCalls = append(c.globalCalls, [2]uint8{mode, flags})
	failure := c.globalErr
	c.mu.Unlock()
	return failure
}

func (c *titanExecPolicyFakeCore) TitanExecAllowAdd(path string) (TitanExecAllowIdentity, error) {
	c.record("allow_add")
	return TitanExecAllowIdentity{State: "added", Dev: 1, Ino: 2}, nil
}

func (c *titanExecPolicyFakeCore) TitanExecAllowAddBatch(paths []string) (TitanExecBatchResult, error) {
	c.record("allow_add_batch")
	return TitanExecBatchResult{Added: len(paths)}, nil
}

func (c *titanExecPolicyFakeCore) TitanExecAllowDel(dev uint32, ino uint64) error {
	c.record("allow_del")
	return nil
}

func (c *titanExecPolicyFakeCore) TitanExecClear() error {
	c.record("clear")
	return nil
}

func (c *titanExecPolicyFakeCore) TitanExecScopeSet(cgroupID uint64, mode, flags uint8) error {
	c.record("scope_set")
	return nil
}

func (c *titanExecPolicyFakeCore) TitanExecScopeDel(cgroupID uint64) error {
	c.record("scope_del")
	return nil
}

// --------------------------------------------------------------- fixtures

// titanExecAPIFixture builds a server whose XDR engine carries a wired exec-gate
// syncer against the fake core. The persisted namespace is enabled in observe
// mode, so the honest states (applied/inactive/capability-missing) are all
// reachable without touching a kernel.
func titanExecAPIFixture(t *testing.T, coreStatus TitanExecCoreStatus, capabilityMissing bool, setup ...func(*titanExecPolicyFakeCore)) (*APIServer, *titanExecPolicyFakeCore, *XDREngine) {
	t.Helper()
	server, store, _ := settingsAPIFixture(t)
	current := store.Get()
	namespace := defaultTitanExecFabricSettings()
	namespace.Enabled = true
	namespace.Mode = TitanExecModeObserve
	current.TitanExec = &namespace
	if _, err := store.Update(current); err != nil {
		t.Fatalf("persist titan exec API settings: %v", err)
	}
	fake := newTitanExecPolicyFakeCore()
	fake.coreStatus = coreStatus
	if capabilityMissing {
		fake.versionErr = ErrTitanExecUnavailable
	}
	for _, apply := range setup {
		apply(fake)
	}
	engine := &XDREngine{
		state: server.state, settings: store, correlator: NewIncidentCorrelator(0),
		dedupe: map[string]time.Time{}, degradeCauses: map[string]string{}, forensicFailures: map[string]int{},
		titanExecCapability: titanExecCapabilityUnknown,
	}
	engine.titanExec = NewTitanExecPolicySyncer(fake, server.state, store.Get(), titanExecPlanDeps{})
	engine.titanExec.Sync(context.Background())
	if !capabilityMissing {
		// A core with the command family answers an empty ring even when its LSM
		// hook is not attached; the drain establishes the capability fact without
		// inventing a record.
		engine.consumeTitanExecDrain("empty", nil, time.Now().UTC())
	}
	server.state.SetModes("enforcement", "observe")
	server.xdr = engine
	return server, fake, engine
}

// titanExecAPIActiveFixture additionally drains two kernel decisions and one
// health sample, so the counters/history/kernel-health fields are populated.
func titanExecAPIActiveFixture(t *testing.T) (*APIServer, *titanExecPolicyFakeCore, *XDREngine) {
	t.Helper()
	server, fake, engine := titanExecAPIFixture(t, TitanExecCoreStatus{
		State: "applied", Mode: 0, Path: titanExecPathBPFLSM, LSM: titanExecLSMActive,
		Offsets: titanExecOffsetsValid, Epoch: "0123456789abcdef",
	}, false)
	now := time.Now().UTC()
	engine.consumeTitanExecDrain(titanExecBatch(titanExecDenyRecord("4194000"), titanExecMmapAuditRecord()), nil, now)
	engine.consumeTitanExecHealth(CoreTitanExecHealth{Emitted: 42, RingDrops: 1, Denies: 2, Audits: 3}, nil, now)
	return server, fake, engine
}

func decodeTitanExecJSON(t *testing.T, raw []byte, destination any) {
	t.Helper()
	if err := json.Unmarshal(raw, destination); err != nil {
		t.Fatalf("decode titan exec payload: %v (body=%s)", err, raw)
	}
}

// ------------------------------------------------------------------ status

func TestTitanExecAPIStatusAndEventsAreReadOnlyAndBounded(t *testing.T) {
	server, _, _ := titanExecAPIActiveFixture(t)

	status := fabricRequest(t, server, http.MethodGet, "/api/v1/titan/exec/status", nil)
	if status.Code != http.StatusOK {
		t.Fatalf("titan exec status returned %d: %s", status.Code, status.Body.String())
	}
	var view TitanExecStatusView
	decodeTitanExecJSON(t, status.Body.Bytes(), &view)
	if view.State != TitanExecSyncStateApplied || view.SensorState != "active" {
		t.Fatalf("status does not describe the applied gate honestly: %+v", view)
	}
	if view.Sync.Capability != titanExecSupportedVersion || !view.Sync.Enabled || view.Sync.Mode != TitanExecModeObserve {
		t.Fatalf("sync projection is wrong: %+v", view.Sync)
	}
	if view.Kernel.Path != titanExecPathBPFLSM || view.Kernel.LSM != titanExecLSMActive || view.Kernel.Offsets != titanExecOffsetsValid {
		t.Fatalf("kernel facts are not carried through: %+v", view.Kernel)
	}
	if view.Kernel.Health.Emitted != 42 || view.Kernel.Health.RingDrops != 1 || view.Kernel.HealthAt == nil {
		t.Fatalf("kernel health is missing: %+v", view.Kernel)
	}
	if view.Kernel.HealthError != "" || view.Kernel.DrainError != "" {
		t.Fatalf("healthy status carries a channel error: %+v", view.Kernel)
	}
	if view.Counters.EventsTotal != 2 || view.Counters.Denies != 1 || view.Counters.Audits != 1 ||
		view.Counters.Incidents != 2 || view.Counters.ParseErrors != 0 {
		t.Fatalf("ingestion counters are wrong: %+v", view.Counters)
	}
	if view.HistoryLimit != titanExecEventHistoryLimit {
		t.Fatalf("history bound is not published: %d", view.HistoryLimit)
	}

	events := fabricRequest(t, server, http.MethodGet, "/api/v1/titan/exec/events", nil)
	if events.Code != http.StatusOK {
		t.Fatalf("titan exec events returned %d: %s", events.Code, events.Body.String())
	}
	var history TitanExecEventsView
	decodeTitanExecJSON(t, events.Body.Bytes(), &history)
	if history.Available != 2 || len(history.Events) != 2 || history.Limit != titanExecEventHistoryLimit {
		t.Fatalf("event history is wrong: %+v", history)
	}
	if history.Events[0].RuleID != "TITAN.EXEC_AUDIT" || history.Events[0].Comm != "" {
		t.Fatalf("history is not newest first or lost the comm: %+v", history.Events[0])
	}

	bounded := fabricRequest(t, server, http.MethodGet, "/api/v1/titan/exec/events?limit=9999", nil)
	if bounded.Code != http.StatusOK {
		t.Fatalf("bounded events returned %d", bounded.Code)
	}
	decodeTitanExecJSON(t, bounded.Body.Bytes(), &history)
	if history.Limit != titanExecEventHistoryLimit || len(history.Events) > titanExecEventHistoryLimit {
		t.Fatalf("limit was not clamped to the history bound: %+v", history)
	}

	one := fabricRequest(t, server, http.MethodGet, "/api/v1/titan/exec/events?limit=1", nil)
	if one.Code != http.StatusOK {
		t.Fatalf("limit=1 returned %d", one.Code)
	}
	decodeTitanExecJSON(t, one.Body.Bytes(), &history)
	if history.Limit != 1 || len(history.Events) != 1 || history.Available != 2 {
		t.Fatalf("limit=1 was not honoured: %+v", history)
	}

	for _, invalid := range []string{"?limit=0", "?limit=-3", "?limit=abc"} {
		if rec := fabricRequest(t, server, http.MethodGet, "/api/v1/titan/exec/events"+invalid, nil); rec.Code != http.StatusBadRequest {
			t.Fatalf("invalid %s returned %d: %s", invalid, rec.Code, rec.Body.String())
		}
	}

	// Read-only: the routes only answer GET.
	if rec := fabricRequest(t, server, http.MethodPost, "/api/v1/titan/exec/status", []byte(`{}`)); rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST on the status route returned %d", rec.Code)
	}
	if rec := fabricRequest(t, server, http.MethodPost, "/api/v1/titan/exec/events", []byte(`{}`)); rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST on the events route returned %d", rec.Code)
	}
	if rec := fabricRequestWithoutAuth(t, server, "/api/v1/titan/exec/status"); rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated status returned %d", rec.Code)
	}
	if rec := fabricRequestWithoutAuth(t, server, "/api/v1/titan/exec/events"); rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated events returned %d", rec.Code)
	}
}

func TestTitanExecAPIStatusWithoutEngineIsHonest(t *testing.T) {
	server, _, _ := settingsAPIFixture(t)
	rec := fabricRequest(t, server, http.MethodGet, "/api/v1/titan/exec/status", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status without engine returned %d", rec.Code)
	}
	var view TitanExecStatusView
	decodeTitanExecJSON(t, rec.Body.Bytes(), &view)
	if view.State != TitanExecSyncStateUnavailable || view.SensorState != "unavailable" ||
		view.Kernel.Path != titanExecPathNone || view.Kernel.LSM != titanExecLSMInactive {
		t.Fatalf("status without engine claims more than it can prove: %+v", view)
	}
	events := fabricRequest(t, server, http.MethodGet, "/api/v1/titan/exec/events", nil)
	if events.Code != http.StatusOK {
		t.Fatalf("events without engine returned %d", events.Code)
	}
	var history TitanExecEventsView
	decodeTitanExecJSON(t, events.Body.Bytes(), &history)
	if len(history.Events) != 0 || history.Available != 0 {
		t.Fatalf("events without engine invented records: %+v", history)
	}
}

// TestTitanExecAPIStatusNeverClaimsInactiveEnforcement is the P1/P3 honesty gate:
// a kernel without an active BPF-LSM hook, reported by the core as path=none and
// lsm=inactive, must never surface as an applied/bpf-lsm-cell/enforced state.
func TestTitanExecAPIStatusNeverClaimsInactiveEnforcement(t *testing.T) {
	server, fake, engine := titanExecAPIFixture(t, TitanExecCoreStatus{
		State: "inactive", Mode: 0, Path: titanExecPathNone, LSM: titanExecLSMInactive,
		Offsets: titanExecOffsetsValid, Epoch: "0123456789abcdef",
	}, false)
	if calls := fake.globalCalls; len(calls) != 0 {
		t.Fatalf("enforcement was attempted on an inactive LSM: %+v", calls)
	}
	if status := engine.TitanExecPolicyStatus(); status.State != TitanExecSyncStateInactive {
		t.Fatalf("client-side sync status claims %q, want inactive", status.State)
	}
	rec := fabricRequest(t, server, http.MethodGet, "/api/v1/titan/exec/status", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("inactive status returned %d", rec.Code)
	}
	var view TitanExecStatusView
	decodeTitanExecJSON(t, rec.Body.Bytes(), &view)
	if view.State != TitanExecSyncStateInactive || view.SensorState != "inactive" {
		t.Fatalf("inactive kernel surfaces as %q/%q", view.State, view.SensorState)
	}
	if view.Kernel.Path != titanExecPathNone || view.Kernel.LSM != titanExecLSMInactive {
		t.Fatalf("inactive kernel facts are wrong: %+v", view.Kernel)
	}
	if view.Sync.Mode == "enforce" || strings.Contains(rec.Body.String(), "bpf-lsm-cell") {
		t.Fatalf("the status claims enforcement the kernel cannot provide: %s", rec.Body.String())
	}
	// The existing P3 sensor-label contract stays intact: no cell-LSM claim when
	// the hook is offline, and no regression of the pure composition function.
	if label := xdrSensorMode(true, true, true, true, false); strings.Contains(label, "bpf-lsm-cell") {
		t.Fatalf("xdrSensorMode claims an attached cell LSM on an inactive kernel: %q", label)
	}

	// /api/v1/status carries the same honest projection additively.
	snapshot := fabricRequest(t, server, http.MethodGet, "/api/v1/status", nil)
	if snapshot.Code != http.StatusOK {
		t.Fatalf("status snapshot returned %d", snapshot.Code)
	}
	var payload struct {
		XDR       *XDRStatus       `json:"xdr"`
		TitanExec *TitanExecStatus `json:"titan_exec"`
	}
	decodeTitanExecJSON(t, snapshot.Body.Bytes(), &payload)
	if payload.XDR == nil {
		t.Fatal("status snapshot lost its xdr field")
	}
	if payload.TitanExec == nil {
		t.Fatal("status snapshot is missing the bounded titan_exec field")
	}
	if payload.TitanExec.State != TitanExecSyncStateInactive || payload.TitanExec.SensorState != "inactive" ||
		payload.TitanExec.Path != titanExecPathNone || payload.TitanExec.LSM != titanExecLSMInactive {
		t.Fatalf("bounded titan_exec field claims more than the kernel proves: %+v", payload.TitanExec)
	}
}

func TestTitanExecAPIFailedSyncNeverClaimsEnforcement(t *testing.T) {
	server, _, engine := titanExecAPIFixture(t, TitanExecCoreStatus{
		State: "applied", Mode: 0, Path: titanExecPathBPFLSM, LSM: titanExecLSMActive,
		Offsets: titanExecOffsetsValid, Epoch: "0123456789abcdef",
	}, false, func(fake *titanExecPolicyFakeCore) {
		fake.globalErr = errors.New("simulated kernel map write failure")
	})
	if status := engine.TitanExecPolicyStatus(); status.State != TitanExecSyncStateFailed {
		t.Fatalf("a rejected kernel write was not reported as a failed sync: %+v", status)
	}
	rec := fabricRequest(t, server, http.MethodGet, "/api/v1/titan/exec/status", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("failed-sync status returned %d", rec.Code)
	}
	var view TitanExecStatusView
	decodeTitanExecJSON(t, rec.Body.Bytes(), &view)
	if view.State != TitanExecSyncStateFailed || view.SensorState != "degraded" {
		t.Fatalf("failed sync surfaces as %q/%q", view.State, view.SensorState)
	}
	if !strings.Contains(view.Sync.LastError, "simulated kernel map write failure") {
		t.Fatalf("failed sync does not name its cause: %+v", view.Sync)
	}
	if strings.Contains(rec.Body.String(), "bpf-lsm-cell") {
		t.Fatalf("failed sync claims an attached cell LSM: %s", rec.Body.String())
	}
}

func TestTitanExecAPICapabilityMissingIsHonest(t *testing.T) {
	server, _, _ := titanExecAPIFixture(t, TitanExecCoreStatus{}, true)
	rec := fabricRequest(t, server, http.MethodGet, "/api/v1/titan/exec/status", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("capability-missing status returned %d", rec.Code)
	}
	var view TitanExecStatusView
	decodeTitanExecJSON(t, rec.Body.Bytes(), &view)
	if view.State != TitanExecSyncStateCapabilityMissing || view.Capability != titanExecCapabilityMissing {
		t.Fatalf("old core is not reported as capability-missing: %+v", view)
	}
	if view.SensorState != "unavailable" || view.Kernel.Path != titanExecPathNone || view.Kernel.LSM != titanExecLSMInactive {
		t.Fatalf("capability-missing status invents an active sensor: %+v", view)
	}
	if strings.Contains(rec.Body.String(), "bpf-lsm-cell") || strings.Contains(rec.Body.String(), "bpf-lsm") {
		t.Fatalf("capability-missing status claims a kernel path: %s", rec.Body.String())
	}
	// A missing capability is a capability fact, not an XDR degradation.
	if degraded, reason := server.state.Snapshot().XDR.Degraded, server.state.Snapshot().XDR.DegradedReason; degraded {
		t.Fatalf("capability-missing degraded XDR: %s", reason)
	}
	// The Fabric settings module detects the wired syncer and names the honest
	// engine state instead of claiming the persisted revision was activated.
	module := fabricRequest(t, server, http.MethodGet, "/api/v1/settings/titan_exec", nil)
	if module.Code != http.StatusOK {
		t.Fatalf("settings module returned %d", module.Code)
	}
	var moduleView FabricModuleView
	decodeTitanExecJSON(t, module.Body.Bytes(), &moduleView)
	if moduleView.ApplyState != "engine_unavailable" {
		t.Fatalf("settings module claims %q without a capable core", moduleView.ApplyState)
	}
	if wired, ok := moduleView.Details["wired"].(bool); !ok || !wired {
		t.Fatalf("settings module does not detect the wired syncer: %+v", moduleView.Details)
	}
}

// ------------------------------------------ ingestion projection and bounds

func TestTitanExecCapabilityMissingIsNotDegradation(t *testing.T) {
	engine, state := newTitanExecTestEngine(t, true)
	now := time.Now().UTC()
	if delay := engine.consumeTitanExecDrain("", ErrTitanExecUnavailable, now); delay != titanExecDrainBackoff {
		t.Fatalf("capability-missing drain returned %s, want %s", delay, titanExecDrainBackoff)
	}
	if degraded, _ := engine.degradedState(); degraded {
		t.Fatal("a pre-TitanExec core degraded XDR")
	}
	if engine.titanExecCapabilityKnown() {
		t.Fatal("capability reported as known without a successful drain")
	}
	engine.consumeTitanExecDrain("empty", nil, now)
	if !engine.titanExecCapabilityKnown() {
		t.Fatal("capability was not restored by a successful drain")
	}
	if got := countTitanExecEvents(state.Snapshot().Events, "titan_exec.capability_available"); got != 1 {
		t.Fatalf("capability recovery was not reported exactly once, got %d", got)
	}
}

func TestTitanExecDrainRejectsMalformedBatchWithoutPartialState(t *testing.T) {
	engine, state := newTitanExecTestEngine(t, true)
	now := time.Now().UTC()
	if delay := engine.consumeTitanExecDrain("0|broken", nil, now); delay != titanExecDrainBackoff {
		t.Fatalf("malformed payload returned %s, want %s", delay, titanExecDrainBackoff)
	}
	if got := len(state.Snapshot().Incidents); got != 0 {
		t.Fatalf("malformed batch produced %d incidents", got)
	}
	report := engine.TitanExecEventsReport(titanExecEventHistoryLimit)
	if report.Available != 0 || report.Counters.ParseErrors != 1 || report.Counters.Incidents != 0 {
		t.Fatalf("malformed batch changed more than the parse counter: %+v", report)
	}
}

func TestTitanExecEventHistoryIsBoundedAndNewestFirst(t *testing.T) {
	engine, _ := newTitanExecTestEngine(t, false)
	for batch := 0; batch < 10; batch++ {
		records := make([][]string, 0, 8)
		for index := 0; index < 8; index++ {
			record := titanExecDenyRecord("41" + string(rune('0'+batch)) + string(rune('0'+index)))
			record[1] = "17000000" + string(rune('0'+batch)) + string(rune('0'+index))
			records = append(records, record)
		}
		engine.consumeTitanExecDrain(titanExecBatch(records...), nil, time.Now().UTC())
	}
	report := engine.TitanExecEventsReport(5000)
	if report.Limit != titanExecEventHistoryLimit || report.Available != titanExecEventHistoryLimit ||
		len(report.Events) != titanExecEventHistoryLimit {
		t.Fatalf("event history is not bounded to %d: %+v", titanExecEventHistoryLimit, report)
	}
	if report.Counters.EventsTotal != 80 || report.Counters.Denies != 80 {
		t.Fatalf("event counters are wrong: %+v", report.Counters)
	}
	if report.Events[0].PID != 4197 || report.Events[63].PID == 0 {
		t.Fatalf("history is not newest first: first=%+v", report.Events[0])
	}
}

func TestTitanExecPathEnrichmentIsBoundedAndHonest(t *testing.T) {
	if got := titanExecProcessPath(0); got != "unknown" {
		t.Fatalf("pid 0 resolved to %q", got)
	}
	if got := titanExecProcessPath(4194000); got != "unknown" {
		t.Fatalf("nonexistent pid resolved to %q", got)
	}
	path := titanExecProcessPath(uint32(os.Getpid()))
	if path != "unknown" {
		if !filepath.IsAbs(path) || strings.ContainsAny(path, "\x00\r\n\t") {
			t.Fatalf("process path is not a bounded absolute path: %q", path)
		}
	}
}
