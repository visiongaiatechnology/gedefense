// SPDX-FileCopyrightText: 2026 VisionGaia Technology
// SPDX-License-Identifier: AGPL-3.0-only

package main

// Tests for the local cgroup-v2 cell registry fallback and the honest
// platform-unsupported state.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func newLocalCellsTestAdapter(t *testing.T) (*GaiaCellsAdapter, string) {
	t.Helper()
	base := t.TempDir()
	root := filepath.Join(base, "vgt-cells")
	for _, name := range []string{"cell-alpha", "cell-beta"} {
		dir := filepath.Join(root, name)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "cgroup.freeze"), []byte("0"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "cgroup.events"), []byte("populated 1\nfrozen 0\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	adapter := NewGaiaCellsAdapter(CellsConfig{
		Enabled: true, Socket: filepath.Join(base, "missing.sock"),
		AuthKeyFile: filepath.Join(base, "missing.key"), RequestTimeoutMillis: 100,
	})
	adapter.local = newLocalCellRegistry(root)
	return adapter, base
}

func TestGaiaCellsLocalRegistryFallbackIsFunctional(t *testing.T) {
	adapter, _ := newLocalCellsTestAdapter(t)
	status := adapter.Status(true)
	if status.Availability != "local_registry" || !status.Healthy || status.Mode != "local" {
		t.Fatalf("local fallback not active: %+v", status)
	}
	if !status.PlatformSupported || len(status.Cells) != 2 {
		t.Fatalf("local registry did not enumerate its cells: %+v", status)
	}
	cell := status.Cells[0]
	if cell.Profile != "local" || cell.CgroupPath != localCellsLogicalRoot+"/cell-alpha" {
		t.Fatalf("unexpected local cell identity: %+v", cell)
	}
	if err := adapter.Action("FREEZE", cell.UUID, cell.Generation, cell.CgroupID); err != nil {
		t.Fatalf("local freeze failed: %v", err)
	}
	raw, err := os.ReadFile(filepath.Join(adapter.local.root, "cell-alpha", "cgroup.freeze"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(raw)) != "1" {
		t.Fatalf("cgroup.freeze not written: %q", string(raw))
	}
	if refreshed := adapter.Status(true); refreshed.Cells[0].State != "frozen" {
		t.Fatalf("frozen state not reported: %+v", refreshed.Cells[0])
	}
	if err := adapter.Action("UNFREEZE", cell.UUID, cell.Generation, cell.CgroupID); err != nil {
		t.Fatalf("local unfreeze failed: %v", err)
	}
	if err := adapter.Action("REVOKE_NETWORK", cell.UUID, cell.Generation, cell.CgroupID); err == nil ||
		!strings.Contains(err.Error(), "Gaia Cells runtime") {
		t.Fatalf("network isolation must be refused with the runtime reason, got %v", err)
	}
	if err := adapter.Action("FREEZE", cell.UUID, cell.Generation+1, cell.CgroupID); err == nil {
		t.Fatal("local action accepted a stale cell generation")
	}
}

func TestGaiaCellsStatusIsHonestAboutDisabledAndUnsupported(t *testing.T) {
	disabledRoot := t.TempDir()
	disabled := NewGaiaCellsAdapter(CellsConfig{Enabled: false, Socket: "/run/gaia-cells/control.sock",
		AuthKeyFile: "/not/used", RequestTimeoutMillis: 100})
	disabled.local = newLocalCellRegistry(filepath.Join(disabledRoot, "cells"))
	status := disabled.Status(true)
	if status.Availability != "disabled" || status.Healthy || status.Mode != "disabled" {
		t.Fatalf("disabled state is not honest: %+v", status)
	}
	if _, err := disabled.List(); err == nil {
		t.Fatal("disabled adapter unexpectedly listed cells")
	}

	unsupportedBase := t.TempDir()
	unsupported := NewGaiaCellsAdapter(CellsConfig{Enabled: true,
		Socket:      filepath.Join(unsupportedBase, "missing.sock"),
		AuthKeyFile: filepath.Join(unsupportedBase, "missing.key"), RequestTimeoutMillis: 100})
	unsupported.local = newLocalCellRegistry(filepath.Join(unsupportedBase, "no-cells"))
	status = unsupported.Status(true)
	if status.Availability != "platform_unsupported" || status.Healthy || status.Error != "" {
		t.Fatalf("unsupported platform must be neutral, got %+v", status)
	}
	if !strings.Contains(status.Reason, "no local cgroup v2 cell registry") {
		t.Fatalf("unsupported reason is not explicit: %q", status.Reason)
	}
}

func TestGaiaCellsRuntimeNotInstalledFallsBackToLocal(t *testing.T) {
	adapter, _ := newLocalCellsTestAdapter(t)
	if cells, err := adapter.List(); err != nil || len(cells) != 2 {
		t.Fatalf("List() did not fall back to the local registry: cells=%d err=%v", len(cells), err)
	}
}
