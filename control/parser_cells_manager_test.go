package main

// POINT 2 / P2-T3 manager tests: admission, lifecycle state machine, TTL watchdog,
// evidence-first burn ordering, incident dispatch, export import bounds, helper
// loss and ledger reconciliation - all against the real VGTGC2 fake helper.

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

type parserCellEventLog struct {
	mu       sync.Mutex
	evidence []EvidenceRecord
	events   []Event
	order    []string
}

func (l *parserCellEventLog) record(record EvidenceRecord) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.evidence = append(l.evidence, record)
	l.order = append(l.order, "evidence:"+record.Kind)
	return nil
}

func (l *parserCellEventLog) event(event Event) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.events = append(l.events, event)
	l.order = append(l.order, "event:"+event.Kind)
}

func (l *parserCellEventLog) orderIndex(entry string) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	for index, value := range l.order {
		if value == entry {
			return index
		}
	}
	return -1
}

func (l *parserCellEventLog) count() (evidence, events int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.evidence), len(l.events)
}

type parserCellFixture struct {
	manager  *ParserCellManager
	helper   *parserCellFakeHelper
	state    *State
	settings *SettingsStore
	log      *parserCellEventLog
	offset   time.Duration
}

func parserCellTestSettingsStore(t *testing.T, cfg Config, enabled bool) *SettingsStore {
	t.Helper()
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "runtime.key")
	if err := os.WriteFile(keyPath, make([]byte, 32), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg.Runtime.StorageKeyFile = ""
	store, err := NewSettingsStore(filepath.Join(dir, "runtime.json"), keyPath, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !enabled {
		return store
	}
	current := store.Get()
	cells := defaultParserCellsFabricSettings()
	cells.Enabled = true
	current.ParserCells = &cells
	updated, err := store.Update(current)
	if err != nil {
		t.Fatalf("enable parser cells in the test store: %v", err)
	}
	_ = updated
	return store
}

func newParserCellFixture(t *testing.T, enabled bool) *parserCellFixture {
	return newParserCellFixtureWith(t, enabled, nil)
}

// newParserCellFixtureWith allows a test to adjust the bootstrap parser-cell
// configuration (imports directory, Wayland profile declarations) before the
// manager is constructed.
func newParserCellFixtureWith(t *testing.T, enabled bool, mutateConfig func(*ParserCellsConfig)) *parserCellFixture {
	t.Helper()
	cfg := defaultConfig()
	state := NewState("test", cfg)
	settings := parserCellTestSettingsStore(t, cfg, enabled)
	helper := newParserCellFakeHelper(t)
	if mutateConfig != nil {
		mutateConfig(&helper.cfg)
	}
	manager := NewParserCellManager(helper.cfg, state, settings, nil, nil)
	manager.client = helper.client(t)
	manager.clientErr = nil
	log := &parserCellEventLog{}
	fixture := &parserCellFixture{manager: manager, helper: helper, state: state, settings: settings, log: log}
	manager.now = func() time.Time { return time.Now().Add(fixture.offset) }
	manager.evidence = log.record
	manager.addEvent = log.event
	helper.set(func(h *parserCellFakeHelper) {
		h.onCall = func(command string) { log.mu.Lock(); log.order = append(log.order, "helper:"+command); log.mu.Unlock() }
	})
	return fixture
}

func (f *parserCellFixture) advance(duration time.Duration) { f.offset += duration }

func (f *parserCellFixture) updateCells(t *testing.T, mutate func(*ParserCellsFabricSettings)) {
	t.Helper()
	current := f.settings.Get()
	cells := defaultParserCellsFabricSettings()
	if current.ParserCells != nil {
		cells = *current.ParserCells
	}
	mutate(&cells)
	current.ParserCells = &cells
	updated, err := f.settings.Update(current)
	if err != nil {
		t.Fatalf("update parser cell settings: %v", err)
	}
	f.manager.Configure(updated)
}

func (f *parserCellFixture) openCell(t *testing.T, ttlSeconds int) ParserCellRuntime {
	t.Helper()
	input, err := f.manager.StageInput([]byte("parser document"))
	if err != nil {
		t.Fatalf("stage input: %v", err)
	}
	runtime, err := f.manager.Create("pdf-viewer", input.Token, input.SHA256, input.Size, ttlSeconds)
	if err != nil {
		t.Fatalf("open parser cell: %v", err)
	}
	return runtime
}

// ------------------------------------------------------------------- tests

func TestParserCellsManagerDefaultOffIsInert(t *testing.T) {
	fixture := newParserCellFixture(t, false)
	status := fixture.manager.Status()
	if status.Enabled || status.Available || status.Helper != "disabled" {
		t.Fatalf("disabled manager claims a runtime: %+v", status)
	}
	fixture.manager.refresh(fixture.manager.now())
	if requests := fixture.helper.requestCount(); requests != 0 {
		t.Fatalf("disabled manager contacted the helper %d times", requests)
	}
	if _, err := fixture.manager.StageInput([]byte("x")); parserCellErrorCode(err) != "disabled" {
		t.Fatalf("staging while disabled was not refused: %v", err)
	}
	if _, err := fixture.manager.Create("pdf-viewer", strings.Repeat("a", 32), strings.Repeat("b", 64), 1, 30); parserCellErrorCode(err) != "disabled" {
		t.Fatalf("create while disabled was not refused: %v", err)
	}
	if evidence, events := fixture.log.count(); evidence != 0 || events != 0 {
		t.Fatalf("disabled manager emitted %d evidence and %d events", evidence, events)
	}
}

func TestParserCellsManagerMissingHelperIsCapabilityMissing(t *testing.T) {
	cfg := defaultConfig()
	state := NewState("test", cfg)
	settings := parserCellTestSettingsStore(t, cfg, true)
	missing := filepath.Join(t.TempDir(), "absent")
	manager := NewParserCellManager(ParserCellsConfig{Socket: missing, AuthKeyFile: missing,
		InputDir: filepath.Join(t.TempDir(), "in"), ImportsDir: filepath.Join(t.TempDir(), "out"),
		RequestTimeoutMillis: 500, PeerUID: -1}, state, settings, nil, nil)
	manager.Configure(settings.Get())
	status := manager.Status()
	if !status.Enabled || status.Available || status.Helper != "unavailable" {
		t.Fatalf("missing helper was not reported honestly: %+v", status)
	}
	if _, err := manager.StageInput([]byte("x")); !errors.Is(err, ErrParserCellsRuntimeUnavailable) {
		t.Fatalf("staging without a helper was not capability-missing: %v", err)
	}
	_, err := manager.Create("pdf-viewer", strings.Repeat("a", 32), strings.Repeat("b", 64), 1, 30)
	if !errors.Is(err, ErrParserCellsRuntimeUnavailable) || parserCellErrorCode(err) != "capability-missing" {
		t.Fatalf("create without a helper must be capability-missing: %v", err)
	}
	manager.refresh(manager.now())
}

func TestParserCellsManagerStateMachineAndExport(t *testing.T) {
	fixture := newParserCellFixture(t, true)
	fixture.helper.set(func(h *parserCellFakeHelper) { h.export = []byte("untrusted parser export") })
	runtime := fixture.openCell(t, 120)
	if runtime.State != parserCellStateIsolated || !runtime.Sandbox || !runtime.NetNS || runtime.CellClass != parserCellsClassEphemeral {
		t.Fatalf("created cell is not attested/isolated: %+v", runtime)
	}
	if runtime.Layers.Sandbox != "attested" {
		t.Fatalf("sandbox layer was not attested: %+v", runtime.Layers)
	}
	status := fixture.manager.Status()
	if !status.Enabled || !status.Available || status.Active != 1 || len(status.Cells) != 1 {
		t.Fatalf("status does not reflect the open cell: %+v", status)
	}
	if _, err := fixture.manager.Freeze(runtime.UUID); err != nil {
		t.Fatalf("freeze: %v", err)
	}
	if _, err := fixture.manager.Unfreeze(runtime.UUID); err != nil {
		t.Fatalf("unfreeze: %v", err)
	}
	burned, err := fixture.manager.Burn(runtime.UUID, "operator confirmed burn")
	if err != nil {
		t.Fatalf("burn: %v", err)
	}
	if burned.State != parserCellStateBurned || !burned.Terminal {
		t.Fatalf("burned cell is not terminal: %+v", burned)
	}
	if status := fixture.manager.Status(); status.Active != 0 || status.Burned != 1 {
		t.Fatalf("counters after burn are wrong: %+v", status)
	}
	if index := fixture.log.orderIndex("evidence:cells.parser.burn.intent"); index < 0 {
		t.Fatal("burn intent evidence was not recorded")
	}
	intentIndex := fixture.log.orderIndex("evidence:cells.parser.burn.intent")
	burnIndex := fixture.log.orderIndex("helper:CELL_BURN")
	if intentIndex < 0 || burnIndex < 0 || intentIndex > burnIndex {
		t.Fatalf("evidence was not committed before the destructive call: intent=%d burn=%d", intentIndex, burnIndex)
	}
	cell, ok := fixture.manager.Cell(runtime.UUID)
	if !ok || cell.Export == nil || cell.Export.SHA256 == "" || cell.Export.Scan != "airlock-unavailable" {
		t.Fatalf("burned export was not imported as untrusted evidence: %+v", cell.Export)
	}
	data, meta, err := fixture.manager.ExportDownload(runtime.UUID)
	if err != nil || string(data) != "untrusted parser export" || meta.SHA256 != cell.Export.SHA256 {
		t.Fatalf("export download: %q %+v err=%v", data, meta, err)
	}
	if _, err := os.Stat(filepath.Join(fixture.helper.cfg.InputDir, runtime.InputToken+parserCellInputSuffix)); !os.IsNotExist(err) {
		t.Fatalf("staged input survived the burn: %v", err)
	}
	if second, err := fixture.manager.Burn(runtime.UUID, "repeat"); err != nil || second.State != parserCellStateBurned {
		t.Fatalf("burn is not idempotent: %+v err=%v", second, err)
	}
}

func TestParserCellsManagerTTLIsEvidenceFirst(t *testing.T) {
	fixture := newParserCellFixture(t, true)
	runtime := fixture.openCell(t, 5)
	if runtime.State != parserCellStateIsolated {
		t.Fatalf("cell not open: %+v", runtime)
	}
	fixture.advance(4200 * time.Millisecond)
	fixture.manager.refresh(fixture.manager.now())
	cell, ok := fixture.manager.Cell(runtime.UUID)
	if !ok || cell.State != parserCellStateBurned {
		t.Fatalf("TTL deadline did not burn the cell: %+v", cell)
	}
	intentIndex := fixture.log.orderIndex("evidence:cells.parser.burn.intent")
	burnIndex := fixture.log.orderIndex("helper:CELL_BURN")
	if intentIndex < 0 || burnIndex < 0 || intentIndex > burnIndex {
		t.Fatalf("TTL burn was not evidence-first: intent=%d burn=%d", intentIndex, burnIndex)
	}
	if cell.BurnReason != parserCellGoBurnReasonTTL {
		t.Fatalf("TTL burn reason is wrong: %q", cell.BurnReason)
	}
}

func TestParserCellsManagerAdmissionRejects(t *testing.T) {
	fixture := newParserCellFixture(t, true)
	fixture.updateCells(t, func(settings *ParserCellsFabricSettings) { settings.Profiles = []string{"media-thumb"} })
	input, err := fixture.manager.StageInput([]byte("document"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.manager.Create("pdf-viewer", input.Token, input.SHA256, input.Size, 30); parserCellErrorCode(err) != "profile-unknown" {
		t.Fatalf("profile allowlist was not enforced: %v", err)
	}
	fixture.updateCells(t, func(settings *ParserCellsFabricSettings) { settings.Profiles = nil })
	// A tampered staging file must never reach the helper.
	tampered := filepath.Join(fixture.helper.cfg.InputDir, input.Token+parserCellInputSuffix)
	if err := os.WriteFile(tampered, []byte("evil"), 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.manager.Create("pdf-viewer", input.Token, input.SHA256, input.Size, 30); parserCellErrorCode(err) != "input-invalid" {
		t.Fatalf("tampered input was not refused: %v", err)
	}
	if _, err := fixture.manager.Create("pdf-viewer", strings.Repeat("a", 32), strings.Repeat("b", 64), 1, 30); parserCellErrorCode(err) != "input-missing" {
		t.Fatalf("unknown input token was not refused: %v", err)
	}
	// Helper without a sandbox capability: no cell may be claimed.
	fixture.helper.set(func(h *parserCellFakeHelper) { h.sandbox = false })
	fixture.invalidateCapabilities()
	if _, err := fixture.openCellExpectError(t); parserCellErrorCode(err) != "capability-missing" {
		t.Fatalf("sandbox=false helper was not capability-missing: %v", err)
	}
	fixture.helper.set(func(h *parserCellFakeHelper) { h.sandbox = true })
	fixture.invalidateCapabilities()
	// Evidence gate closed: create refuses, burn would still run.
	fixture.state.mu.Lock()
	fixture.state.evidenceErr = errors.New("ledger down")
	fixture.state.mu.Unlock()
	if _, err := fixture.openCellExpectError(t); parserCellErrorCode(err) != "evidence-gate" {
		t.Fatalf("closed evidence gate was not enforced: %v", err)
	}
	fixture.state.mu.Lock()
	fixture.state.evidenceErr = nil
	fixture.state.mu.Unlock()
}

func (f *parserCellFixture) openCellExpectError(t *testing.T) (ParserCellRuntime, error) {
	t.Helper()
	input, err := f.manager.StageInput([]byte("document"))
	if err != nil {
		return ParserCellRuntime{}, err
	}
	return f.manager.Create("pdf-viewer", input.Token, input.SHA256, input.Size, 30)
}

func TestParserCellsManagerConcurrencyLimit(t *testing.T) {
	fixture := newParserCellFixture(t, true)
	fixture.updateCells(t, func(settings *ParserCellsFabricSettings) { settings.MaxConcurrent = 1 })
	fixture.helper.set(func(h *parserCellFakeHelper) { h.export = nil })
	if runtime := fixture.openCell(t, 120); runtime.UUID == "" {
		t.Fatal("first cell has no uuid")
	}
	if _, err := fixture.openCellExpectError(t); parserCellErrorCode(err) != "cell-limit" {
		t.Fatalf("concurrency bound was not enforced: %v", err)
	}
}

func TestParserCellsManagerIncidentDispatch(t *testing.T) {
	fixture := newParserCellFixture(t, true)
	runtime := fixture.openCell(t, 120)
	if handled, err := fixture.manager.BurnForIncident(runtime.CgroupID, 50, "INC-LOW", "below threshold"); handled || err != nil {
		t.Fatalf("below-threshold incident was handled: %v %v", handled, err)
	}
	if _, ok := fixture.manager.Cell(runtime.UUID); !ok {
		t.Fatal("below-threshold incident destroyed the cell")
	}
	handled, err := fixture.manager.BurnForIncident(runtime.CgroupID, 95, "INC-HIGH", "score above threshold")
	if !handled || err != nil {
		t.Fatalf("incident dispatch failed: %v %v", handled, err)
	}
	if cell, _ := fixture.manager.Cell(runtime.UUID); cell.State != parserCellStateBurned {
		t.Fatalf("incident did not burn the parser-ephemeral cell: %+v", cell)
	}
	incidentIndex := fixture.log.orderIndex("evidence:cells.parser.incident_burn")
	burnIndex := fixture.log.orderIndex("helper:CELL_BURN")
	if incidentIndex < 0 || burnIndex < 0 || incidentIndex > burnIndex {
		t.Fatalf("incident burn was not evidence-first: intent=%d burn=%d", incidentIndex, burnIndex)
	}
	if handled, _ := fixture.manager.BurnForIncident(999999, 100, "INC-X", "unknown cgroup"); handled {
		t.Fatal("an unknown cgroup was claimed as handled")
	}
	fixture.manager.Configure(RuntimeSettings{ParserCells: &ParserCellsFabricSettings{Enabled: false}})
	if handled, _ := fixture.manager.BurnForIncident(runtime.CgroupID, 100, "INC-X", "disabled"); handled {
		t.Fatal("a disabled manager dispatched an incident burn")
	}
}

func (f *parserCellFixture) invalidateCapabilities() {
	f.manager.mu.Lock()
	f.manager.capsKnown = false
	f.manager.mu.Unlock()
}

// enableStyx makes the persisted StyX namespace executable for kernel-layer tests:
// L3 is only attached when the operator enabled StyX (fake-core tests then also
// need a core that answers STYX_VERSION).
func (f *parserCellFixture) enableStyx(t *testing.T) {
	t.Helper()
	current := f.settings.Get()
	styx := defaultStyxFabricSettings()
	styx.Enabled = true
	styx.Mode = StyxModeMonitor
	current.Styx = &styx
	updated, err := f.settings.Update(current)
	if err != nil {
		t.Fatalf("enable StyX for the kernel-layer test: %v", err)
	}
	f.manager.Configure(updated)
}

func TestParserCellsManagerHelperRestartMarksCellsLost(t *testing.T) {
	fixture := newParserCellFixture(t, true)
	runtime := fixture.openCell(t, 120)
	fixture.manager.health(fixture.manager.now())
	fixture.helper.set(func(h *parserCellFakeHelper) { h.startedAt += 500 })
	fixture.manager.health(fixture.manager.now())
	cell, _ := fixture.manager.Cell(runtime.UUID)
	if cell.State != parserCellStateFailed || !cell.Terminal {
		t.Fatalf("helper restart was not detected as lost cells: %+v", cell)
	}
	if fixture.log.orderIndex("evidence:cells.parser.reconciled") < 0 {
		t.Fatal("lost cells were not recorded as evidence")
	}
}

func TestParserCellsManagerReconcileAdoptsUnknownCells(t *testing.T) {
	fixture := newParserCellFixture(t, true)
	adoptedUUID := strings.Repeat("e", 32)
	fixture.helper.set(func(h *parserCellFakeHelper) {
		h.cells[adoptedUUID] = &ParserCellRemote{UUID: adoptedUUID, Generation: 3, CgroupID: 5150,
			Profile: "pdf-viewer", State: "isolated", ExpiresAt: time.Now().Unix() + 90, PID: 321}
	})
	fixture.manager.reconcile(fixture.manager.now())
	status := fixture.manager.Status()
	if len(status.Cells) != 1 || !status.Cells[0].Adopted || status.Cells[0].UUID != adoptedUUID {
		t.Fatalf("reconcile did not adopt the helper-side cell: %+v", status.Cells)
	}
	fixture.helper.set(func(h *parserCellFakeHelper) { delete(h.cells, adoptedUUID) })
	fixture.manager.reconcile(fixture.manager.now())
	cell, ok := fixture.manager.Cell(adoptedUUID)
	if !ok || cell.State != parserCellStateBurned || !cell.Terminal {
		t.Fatalf("a helper-ended cell was not reconciled to burned: %+v", cell)
	}
}

func TestParserCellsStagingFileModeIsHelperCompatible(t *testing.T) {
	fixture := newParserCellFixture(t, true)
	// The control unit ships UMask=0077: without the explicit chmod the staged
	// document would be 0600 and the helper's config::validate_input (exactly 0640)
	// would reject it as input-invalid.
	previous := syscall.Umask(0o077)
	defer syscall.Umask(previous)
	input, err := fixture.manager.StageInput([]byte("parser document"))
	if err != nil {
		t.Fatalf("stage input: %v", err)
	}
	path := filepath.Join(fixture.helper.cfg.InputDir, input.Token+parserCellInputSuffix)
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("staged file missing: %v", err)
	}
	if mode := info.Mode().Perm(); mode != 0o640 {
		t.Fatalf("staged file mode is %04o, the helper requires 0640", mode)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		t.Fatalf("staged input is not a regular file: %v", info.Mode())
	}
}

func TestParserCellsManagerWaylandProfileIsRefusedFailClosed(t *testing.T) {
	fixture := newParserCellFixtureWith(t, true, func(cfg *ParserCellsConfig) {
		cfg.WaylandProfiles = []string{"wayland-viewer"}
	})
	fixture.helper.set(func(h *parserCellFakeHelper) { h.profiles = append(h.profiles, "wayland-viewer") })
	input, err := fixture.manager.StageInput([]byte("document"))
	if err != nil {
		t.Fatalf("stage input: %v", err)
	}
	if _, err := fixture.manager.Create("wayland-viewer", input.Token, input.SHA256, input.Size, 30); parserCellErrorCode(err) != "capability-missing" {
		t.Fatalf("declared wayland profile was not refused capability-missing: %v", err)
	}
	if status := fixture.manager.Status(); status.Wayland {
		t.Fatalf("phase-1 status claims wayland support: %+v", status)
	}
	for _, command := range fixture.helper.commands() {
		if command == "CELL_CREATE" {
			t.Fatal("a refused wayland profile still reached the helper spawn")
		}
	}
	// A helper that does negotiate the additive capability may serve the profile.
	fixture.helper.set(func(h *parserCellFakeHelper) { h.wayland = "true" })
	fixture.invalidateCapabilities()
	if _, err := fixture.manager.Create("wayland-viewer", input.Token, input.SHA256, input.Size, 30); err != nil {
		t.Fatalf("advertised wayland capability was ignored: %v", err)
	}
	if !fixture.manager.Status().Wayland {
		t.Fatal("status did not carry the negotiated wayland capability")
	}
}

func TestParserCellsManagerExportImportBounds(t *testing.T) {
	fixture := newParserCellFixture(t, true)
	fixture.updateCells(t, func(settings *ParserCellsFabricSettings) { settings.MaxExportBytes = 1024 })
	fixture.helper.set(func(h *parserCellFakeHelper) { h.export = []byte(strings.Repeat("X", 2048)) })
	runtime := fixture.openCell(t, 120)
	if _, err := fixture.manager.Burn(runtime.UUID, "bounded export burn"); err != nil {
		t.Fatalf("burn: %v", err)
	}
	cell, _ := fixture.manager.Cell(runtime.UUID)
	if cell.Export != nil {
		t.Fatalf("an oversized export was imported: %+v", cell.Export)
	}
	if fixture.log.orderIndex("event:cells.parser.export_missing") < 0 {
		t.Fatal("the rejected export was not reported")
	}
}
