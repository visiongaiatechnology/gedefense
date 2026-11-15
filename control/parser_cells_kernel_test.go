package main

// POINT 2 / P2-T3 kernel-layer tests: the §5 admission gate against a fake
// privileged core. A layer may only be reported as applied after the core
// acknowledged the command; a missing LSM/StyX/Titan capability is `unavailable`
// and (when required) refuses the cell instead of faking isolation.

import (
	"errors"
	"sync"
	"testing"
)

type parserCellFakeCore struct {
	mu        sync.Mutex
	calls     []string
	setErr    error
	styxErr   error
	titanErr  error
	titanPath string
	titanLSM  string
}

func (c *parserCellFakeCore) record(call string) {
	c.mu.Lock()
	c.calls = append(c.calls, call)
	c.mu.Unlock()
}

func (c *parserCellFakeCore) recorded() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.calls...)
}

func (c *parserCellFakeCore) has(call string) bool {
	for _, entry := range c.recorded() {
		if entry == call {
			return true
		}
	}
	return false
}

func (c *parserCellFakeCore) CellPolicyEpoch() (string, error) {
	c.record("CELL_POLICY_EPOCH")
	return "0123456789abcdef", nil
}

func (c *parserCellFakeCore) CellPolicySet(cgroupID uint64, flags uint8) error {
	c.record("CELL_POLICY_SET")
	return c.setErr
}

func (c *parserCellFakeCore) CellPolicyDelete(cgroupID uint64) error {
	c.record("CELL_POLICY_DEL")
	return nil
}

func (c *parserCellFakeCore) StyxVersion() (string, error) {
	c.record("STYX_VERSION")
	return styxWireVersion, c.styxErr
}

func (c *parserCellFakeCore) StyxModeSet(cgroupID uint64, mode, flags uint8) error {
	c.record("STYX_MODE_SET")
	return nil
}

func (c *parserCellFakeCore) StyxModeDel(cgroupID uint64) error {
	c.record("STYX_MODE_DEL")
	return nil
}

func (c *parserCellFakeCore) TitanExecVersion() (string, error) {
	c.record("TITAN_EXEC_VERSION")
	return titanExecSupportedVersion, c.titanErr
}

func (c *parserCellFakeCore) TitanExecStatus() (TitanExecCoreStatus, error) {
	c.record("TITAN_EXEC_STATUS")
	path, lsm := c.titanPath, c.titanLSM
	if path == "" {
		path = titanExecPathBPFLSM
	}
	if lsm == "" {
		lsm = titanExecLSMActive
	}
	return TitanExecCoreStatus{State: "applied", Path: path, LSM: lsm, Offsets: titanExecOffsetsValid}, nil
}

func (c *parserCellFakeCore) TitanExecScopeSet(cgroupID uint64, mode, flags uint8) error {
	c.record("TITAN_EXEC_SCOPE_SET")
	return nil
}

func (c *parserCellFakeCore) TitanExecScopeDel(cgroupID uint64) error {
	c.record("TITAN_EXEC_SCOPE_DEL")
	return nil
}

func parserCellKernelSettings(styxEnabled, requireLayers bool) RuntimeSettings {
	settings := defaultRuntimeSettings(defaultConfig())
	styx := defaultStyxFabricSettings()
	styx.Enabled = styxEnabled
	styx.Mode = StyxModeMonitor
	settings.Styx = &styx
	cells := defaultParserCellsFabricSettings()
	cells.Enabled = true
	cells.RequireHostLayers = requireLayers
	settings.ParserCells = &cells
	return settings
}

func newParserCellFakeKernel(core parserCellKernelCore, settings RuntimeSettings, bpfLSM bool) *parserCellKernel {
	return &parserCellKernel{
		core:     core,
		facts:    func() PlatformCapabilities { return PlatformCapabilities{HasBPFLSM: bpfLSM} },
		settings: func() RuntimeSettings { return settings },
		scopes:   make(map[uint64]parserCellKernelScope),
	}
}

// newParserCellFakeKernelDynamic follows the live persisted revision, which is what
// the manager passes into Apply: a layer that the operator enables after the fixture
// was built must still be probed.
func newParserCellFakeKernelDynamic(core parserCellKernelCore, settings func() RuntimeSettings, bpfLSM bool) *parserCellKernel {
	return &parserCellKernel{
		core:     core,
		facts:    func() PlatformCapabilities { return PlatformCapabilities{HasBPFLSM: bpfLSM} },
		settings: settings,
		scopes:   make(map[uint64]parserCellKernelScope),
	}
}

func TestParserCellsKernelAppliesAndRemovesEveryAvailableLayer(t *testing.T) {
	core := &parserCellFakeCore{}
	kernel := newParserCellFakeKernel(core, parserCellKernelSettings(true, false), true)
	layers, err := kernel.Apply(4242, parserCellKernelSettings(true, false))
	if err != nil {
		t.Fatalf("layer attach: %v", err)
	}
	if layers.CellLSM != parserCellLayerApplied || layers.StyxEgress != parserCellLayerApplied || layers.TitanExec != parserCellLayerApplied {
		t.Fatalf("an acknowledged layer was not reported applied: %+v", layers)
	}
	for _, call := range []string{"CELL_POLICY_SET", "STYX_MODE_SET", "TITAN_EXEC_SCOPE_SET"} {
		if !core.has(call) {
			t.Fatalf("core never received %s: %v", call, core.recorded())
		}
	}
	if err := kernel.Remove(4242); err != nil {
		t.Fatalf("layer removal: %v", err)
	}
	for _, call := range []string{"CELL_POLICY_DEL", "STYX_MODE_DEL", "TITAN_EXEC_SCOPE_DEL"} {
		if !core.has(call) {
			t.Fatalf("burn did not remove the %s scope: %v", call, core.recorded())
		}
	}
	if len(kernel.scopes) != 0 {
		t.Fatalf("scope register survived removal: %v", kernel.scopes)
	}
}

func TestParserCellsKernelReassertsDynamicScopes(t *testing.T) {
	core := &parserCellFakeCore{}
	settings := parserCellKernelSettings(true, false)
	kernel := newParserCellFakeKernel(core, settings, true)
	if _, err := kernel.Apply(7001, settings); err != nil {
		t.Fatal(err)
	}
	before := len(core.recorded())
	kernel.Reassert(settings, []uint64{7001})
	if len(core.recorded()) <= before {
		t.Fatal("reassert did not re-apply the registered dynamic scope")
	}
	// A scope whose cell is gone must be removed, not re-applied.
	kernel.Reassert(settings, nil)
	if len(kernel.scopes) != 0 {
		t.Fatalf("reassert kept a scope whose cell is gone: %v", kernel.scopes)
	}
}

func TestParserCellsKernelCapabilityHonesty(t *testing.T) {
	// No BPF-LSM: neither L2 nor L4 may be claimed, StyX stays available if enabled.
	core := &parserCellFakeCore{}
	settings := parserCellKernelSettings(true, true)
	kernel := newParserCellFakeKernel(core, settings, false)
	availability := kernel.Availability(settings)
	if availability.BPFLSM || availability.CellLSM == parserCellLayerAvailable || availability.TitanExec == parserCellLayerAvailable {
		t.Fatalf("inactive BPF-LSM was reported as available: %+v", availability)
	}
	if availability.StyxEgress != parserCellLayerAvailable {
		t.Fatalf("enabled StyX was not probed as available: %+v", availability)
	}
	layers, err := kernel.Apply(8100, settings)
	if err != nil {
		t.Fatalf("unavailable layers must not be an attach failure: %v", err)
	}
	if layers.CellLSM != parserCellLayerUnavailable || layers.TitanExec != parserCellLayerUnavailable ||
		layers.StyxEgress != parserCellLayerApplied {
		t.Fatalf("capability truth was not preserved: %+v", layers)
	}
	if parserCellHostLayersSatisfied(true, layers) {
		t.Fatal("required host layers were satisfied with two unavailable layers")
	}
	// Titan capability known but its hook inactive: L4 must stay unavailable.
	inactive := newParserCellFakeKernel(&parserCellFakeCore{titanPath: titanExecPathNone, titanLSM: titanExecLSMInactive},
		parserCellKernelSettings(false, false), true)
	if layering := inactive.Availability(parserCellKernelSettings(false, false)); layering.TitanExec == parserCellLayerAvailable {
		t.Fatalf("inactive Titan hook was reported as available: %+v", layering)
	}
	// StyX disabled by the operator: L3 unavailable even if the core speaks the ABI.
	disabled := newParserCellFakeKernel(&parserCellFakeCore{}, parserCellKernelSettings(false, false), true)
	if layering := disabled.Availability(parserCellKernelSettings(false, false)); layering.StyxEgress == parserCellLayerAvailable {
		t.Fatalf("disabled StyX was reported as available: %+v", layering)
	}
}

func TestParserCellsKernelAcknowledgementFailureIsReported(t *testing.T) {
	core := &parserCellFakeCore{setErr: errors.New("core rejected the cell")}
	settings := parserCellKernelSettings(false, false)
	kernel := newParserCellFakeKernel(core, settings, true)
	layers, err := kernel.Apply(9001, settings)
	if err == nil {
		t.Fatal("a failed Cell-LSM acknowledgement was swallowed")
	}
	if layers.CellLSM != parserCellLayerFailed {
		t.Fatalf("failed layer is not reported as failed: %+v", layers)
	}
	if parserCellHostLayersSatisfied(false, layers) != true {
		t.Fatal("L1-only mode must not turn an optional layer failure into a refusal")
	}
}

func TestParserCellsManagerRequireHostLayers(t *testing.T) {
	// L1-only default: the helper sandbox is enough even without host layers.
	fixture := newParserCellFixture(t, true)
	settings := parserCellKernelSettings(false, false)
	fixture.manager.kernel = newParserCellFakeKernel(&parserCellFakeCore{}, settings, false)
	fixture.updateCells(t, func(cells *ParserCellsFabricSettings) { cells.RequireHostLayers = false })
	runtime := fixture.openCell(t, 120)
	if runtime.State != parserCellStateIsolated || runtime.Layers.CellLSM != parserCellLayerUnavailable {
		t.Fatalf("L1-only cell must be isolated with honest layer status: %+v", runtime)
	}

	// Required layers with an bpf-LSM-less host: the cell must be refused and the
	// helper cell burned instead of being claimed as isolated.
	strict := newParserCellFixture(t, true)
	strict.enableStyx(t)
	strictCore := &parserCellFakeCore{}
	strict.manager.kernel = newParserCellFakeKernelDynamic(strictCore, strict.settings.Get, false)
	strict.updateCells(t, func(cells *ParserCellsFabricSettings) { cells.RequireHostLayers = true })
	_, err := strict.openCellExpectError(t)
	if parserCellErrorCode(err) != "host-layers-required" {
		t.Fatalf("missing required host layers were not refused: %v", err)
	}
	if len(strict.manager.Status().Cells) != 0 || strict.manager.Status().Active != 0 {
		t.Fatalf("a refused cell was still tracked as active: %+v", strict.manager.Status())
	}
	if strict.log.orderIndex("helper:CELL_BURN") < 0 {
		t.Fatal("the helper cell of a refused admission was not burned")
	}

	// Required layers with a complete capability set: applied and isolated.
	complete := newParserCellFixture(t, true)
	complete.enableStyx(t)
	completeCore := &parserCellFakeCore{}
	complete.manager.kernel = newParserCellFakeKernelDynamic(completeCore, complete.settings.Get, true)
	complete.updateCells(t, func(cells *ParserCellsFabricSettings) { cells.RequireHostLayers = true })
	opened := complete.openCell(t, 120)
	if opened.State != parserCellStateIsolated || opened.Layers.CellLSM != parserCellLayerApplied ||
		opened.Layers.StyxEgress != parserCellLayerApplied || opened.Layers.TitanExec != parserCellLayerApplied || !opened.Layers.Satisfied {
		t.Fatalf("complete host layers did not produce an isolated cell: %+v", opened)
	}
	if _, err := complete.manager.Burn(opened.UUID, "verify removal"); err != nil {
		t.Fatal(err)
	}
	for _, call := range []string{"CELL_POLICY_DEL", "STYX_MODE_DEL", "TITAN_EXEC_SCOPE_DEL"} {
		if !completeCore.has(call) {
			t.Fatalf("burn did not remove layer scope %s: %v", call, completeCore.recorded())
		}
	}
}
