package main

// POINT 2 / P2-T3 supervision tests (T5 review fixes): the burned-cell export must
// be imported into the control-owned parser-imports root durably and provably, a
// failed write must never be reported as "stored", and a cell adopted after a
// control-plane restart must get its dynamic host layers re-applied (or be
// reported degraded - never isolated without proof).

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestParserCellsExportImportIsDurableAndDownloadable(t *testing.T) {
	// The production unit runs with UMask=0077: the import must still materialise an
	// exact 0640 file, otherwise the download path (which re-checks the mode) and
	// the helper-side export contract break.
	previousUmask := syscall.Umask(0o077)
	defer syscall.Umask(previousUmask)
	fixture := newParserCellFixture(t, true)
	export := []byte("untrusted parser export bytes")
	fixture.helper.set(func(h *parserCellFakeHelper) { h.export = export })
	runtime := fixture.openCell(t, 120)
	if _, err := fixture.manager.Burn(runtime.UUID, "operator burn"); err != nil {
		t.Fatalf("burn: %v", err)
	}
	cell, ok := fixture.manager.Cell(runtime.UUID)
	if !ok || cell.Export == nil {
		t.Fatalf("burned export was not imported under umask 0077: %+v", cell.Export)
	}
	path := filepath.Join(fixture.helper.cfg.ImportsDir, runtime.UUID+parserCellExportSuffix)
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("imported export file missing in parser-imports: %v", err)
	}
	if info.Mode().Perm() != 0o640 || !info.Mode().IsRegular() {
		t.Fatalf("imported export mode is %v, want regular 0640", info.Mode())
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(stat.Uid) != os.Getuid() {
		t.Fatalf("imported export owner is not the control user: %+v", info.Sys())
	}
	stored, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(stored, export) {
		t.Fatalf("imported export bytes differ: %q err=%v", stored, err)
	}
	if cell.Export.Path != path || cell.Export.Size != int64(len(export)) || cell.Export.Scan == "" {
		t.Fatalf("export metadata does not describe the stored file: %+v", cell.Export)
	}
	data, meta, err := fixture.manager.ExportDownload(runtime.UUID)
	if err != nil || !bytes.Equal(data, export) || meta.SHA256 != cell.Export.SHA256 {
		t.Fatalf("download: %q %+v err=%v", data, meta, err)
	}
	// A tampered/relaxed mode must not be served: the download path re-checks it.
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := fixture.manager.ExportDownload(runtime.UUID); parserCellErrorCode(err) != "export-missing" {
		t.Fatalf("mode-tampered import was served: %v", err)
	}
}

func TestParserCellsExportImportWriteFailureNeverClaimsStored(t *testing.T) {
	readOnly := filepath.Join(t.TempDir(), "imports-readonly")
	if err := os.Mkdir(readOnly, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(readOnly, 0o700) })
	fixture := newParserCellFixtureWith(t, true, func(cfg *ParserCellsConfig) { cfg.ImportsDir = readOnly })
	fixture.helper.set(func(h *parserCellFakeHelper) { h.export = []byte("cannot be stored") })
	runtime := fixture.openCell(t, 120)
	if _, err := fixture.manager.Burn(runtime.UUID, "operator burn"); err != nil {
		t.Fatalf("burn itself must still succeed: %v", err)
	}
	cell, ok := fixture.manager.Cell(runtime.UUID)
	if !ok || cell.Export != nil {
		t.Fatalf("unwritable imports directory still claimed a stored export: %+v", cell.Export)
	}
	if !strings.Contains(cell.LastError, "export import write failed") {
		t.Fatalf("cell does not state the failed import: %q", cell.LastError)
	}
	if fixture.log.orderIndex("event:cells.parser.export_failed") < 0 {
		t.Fatal("failed export import was not reported")
	}
	if fixture.log.orderIndex("event:cells.parser.export_imported") >= 0 {
		t.Fatal("failed export import was reported as imported")
	}
	if _, _, err := fixture.manager.ExportDownload(runtime.UUID); parserCellErrorCode(err) != "export-missing" {
		t.Fatalf("failed import is downloadable: %v", err)
	}
	if entries, err := os.ReadDir(readOnly); err == nil && len(entries) != 0 {
		t.Fatalf("failed import left files behind: %v", entries)
	}
}

func TestParserCellsManagerAdoptedCellReassertsHostLayers(t *testing.T) {
	fixture := newParserCellFixture(t, true)
	fixture.enableStyx(t)
	core := &parserCellFakeCore{}
	fixture.manager.kernel = newParserCellFakeKernelDynamic(core, fixture.settings.Get, true)
	adoptedUUID := strings.Repeat("e", 32)
	fixture.helper.set(func(h *parserCellFakeHelper) {
		h.cells[adoptedUUID] = &ParserCellRemote{UUID: adoptedUUID, Generation: 3, CgroupID: 5150,
			Profile: "pdf-viewer", State: "isolated", ExpiresAt: time.Now().Unix() + 90, PID: 321}
	})
	fixture.manager.reconcile(fixture.manager.now())
	cell, ok := fixture.manager.Cell(adoptedUUID)
	if !ok || !cell.Adopted {
		t.Fatalf("cell was not adopted: %+v", cell)
	}
	if cell.Layers.CellLSM != parserCellLayerApplied || cell.Layers.StyxEgress != parserCellLayerApplied || cell.Layers.TitanExec != parserCellLayerApplied {
		t.Fatalf("adopted cell host layers were not re-applied: %+v", cell.Layers)
	}
	if cell.State != parserCellStateIsolated {
		t.Fatalf("adopted cell state is not isolated after a proven re-attach: %+v", cell)
	}
	for _, call := range []string{"CELL_POLICY_SET", "STYX_MODE_SET", "TITAN_EXEC_SCOPE_SET"} {
		if !core.has(call) {
			t.Fatalf("adopted cell did not issue %s: %v", call, core.recorded())
		}
	}
	// The re-attached scope must be removed when the cell ends.
	fixture.helper.set(func(h *parserCellFakeHelper) { delete(h.cells, adoptedUUID) })
	fixture.manager.reconcile(fixture.manager.now())
	for _, call := range []string{"CELL_POLICY_DEL", "STYX_MODE_DEL", "TITAN_EXEC_SCOPE_DEL"} {
		if !core.has(call) {
			t.Fatalf("reconciled-ended adopted cell did not remove %s", call)
		}
	}
}

func TestParserCellsManagerAdoptedCellWithoutRequiredLayersIsDegraded(t *testing.T) {
	fixture := newParserCellFixture(t, true)
	fixture.updateCells(t, func(cells *ParserCellsFabricSettings) { cells.RequireHostLayers = true })
	core := &parserCellFakeCore{}
	// No bpf-LSM and StyX disabled: L2/L3/L4 cannot be applied.
	fixture.manager.kernel = newParserCellFakeKernelDynamic(core, fixture.settings.Get, false)
	adoptedUUID := strings.Repeat("f", 32)
	fixture.helper.set(func(h *parserCellFakeHelper) {
		h.cells[adoptedUUID] = &ParserCellRemote{UUID: adoptedUUID, Generation: 4, CgroupID: 6160,
			Profile: "pdf-viewer", State: "isolated", ExpiresAt: time.Now().Unix() + 90, PID: 322}
	})
	fixture.manager.reconcile(fixture.manager.now())
	cell, _ := fixture.manager.Cell(adoptedUUID)
	if cell.State != parserCellStateDegraded || cell.LastError == "" || cell.Layers.Satisfied {
		t.Fatalf("adopted cell without required layers was not degraded honestly: %+v", cell)
	}
	if cell.Layers.CellLSM != parserCellLayerUnavailable || cell.Layers.TitanExec != parserCellLayerUnavailable {
		t.Fatalf("unavailable layers were not reported: %+v", cell.Layers)
	}
}
