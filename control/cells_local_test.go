// SPDX-FileCopyrightText: 2026 VisionGaia Technology
// SPDX-License-Identifier: AGPL-3.0-only

package main

// Tests for the local cgroup-v2 cell registry fallback and the honest
// platform-unsupported state.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
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

// TestGaiaCellIdentityComparisonIgnoresObservationTimestamp is the FIND-031
// regression for the registry side: two listings of the same healthy cell must
// compare as the same identity even though ObservedAt is refreshed, and the
// cgroup id must be the real kernel inode instead of a synthetic hash.
func TestGaiaCellIdentityComparisonIgnoresObservationTimestamp(t *testing.T) {
	adapter, _ := newLocalCellsTestAdapter(t)
	first, err := adapter.List()
	if err != nil || len(first) != 2 {
		t.Fatalf("first listing: cells=%d err=%v", len(first), err)
	}
	time.Sleep(2 * time.Millisecond) // ObservedAt is a real listing timestamp
	second, err := adapter.List()
	if err != nil || len(second) != 2 {
		t.Fatalf("second listing: cells=%d err=%v", len(second), err)
	}
	for index := range first {
		if !sameCellIdentity(first[index], second[index]) {
			t.Fatalf("cell %q identity changed between two healthy listings: %+v vs %+v",
				first[index].Label, first[index], second[index])
		}
		if first[index].ObservedAt.Equal(second[index].ObservedAt) {
			t.Fatalf("cell %q ObservedAt was not refreshed between listings", first[index].Label)
		}
		info, err := os.Lstat(filepath.Join(adapter.local.root, first[index].Label))
		if err != nil {
			t.Fatal(err)
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			t.Skip("kernel inode is not exposed on this platform")
		}
		if stat.Ino != 0 && first[index].CgroupID != stat.Ino {
			t.Fatalf("cell %q CgroupID = %d, want the kernel cgroup inode %d",
				first[index].Label, first[index].CgroupID, stat.Ino)
		}
	}
	// A later ObservedAt alone must never invalidate the identity ...
	later := second[0]
	later.ObservedAt = later.ObservedAt.Add(time.Hour)
	if !sameCellIdentity(first[0], later) {
		t.Fatal("ObservedAt leaked into the Gaia Cell identity comparison")
	}
	// ... while a changed kernel cgroup id must.
	changed := second[0]
	changed.CgroupID++
	if sameCellIdentity(first[0], changed) {
		t.Fatal("a changed kernel cgroup id was accepted as the same Gaia Cell identity")
	}
}

// TestGaiaCellsLocalTransactionAppliesInHealthyState is the end-to-end FIND-031
// regression: a freeze transaction on a healthy local cgroup v2 cell must pass
// preview, apply and verify instead of failing on the per-listing timestamp.
func TestGaiaCellsLocalTransactionAppliesInHealthyState(t *testing.T) {
	adapter, _ := newLocalCellsTestAdapter(t)
	cells, err := adapter.List()
	if err != nil || len(cells) != 2 {
		t.Fatalf("local listing: cells=%d err=%v", len(cells), err)
	}
	cell := cells[0]
	applier := NewCellTransactionApplier(adapter)
	engine, _, _ := newTestTransactionEngine(t, applier, func(EvidenceRecord) error { return nil })
	payload, err := json.Marshal(cellIsolationRequest{
		UUID: cell.UUID, Generation: cell.Generation, CgroupID: cell.CgroupID, Action: "freeze",
	})
	if err != nil {
		t.Fatal(err)
	}
	preview, err := engine.Preview(cellTransactionType, "Freeze local Gaia Cell", "contain suspicious workspace", payload)
	if err != nil {
		t.Fatalf("preview rejected a healthy local cell: %v", err)
	}
	applied, err := engine.Apply(preview.ID, "APPLY "+preview.ID)
	if err != nil || applied.Status != "applied" {
		t.Fatalf("apply failed on a healthy local cell: applied=%+v err=%v", applied, err)
	}
	freezePath := filepath.Join(adapter.local.root, cell.Label, "cgroup.freeze")
	raw, err := os.ReadFile(freezePath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(raw)) != "1" {
		t.Fatalf("cgroup.freeze was not written: %q", string(raw))
	}
	if _, err := engine.Reverse(applied.ID, "REVERSE "+applied.ID); err != nil {
		t.Fatalf("reverse failed on a healthy local cell: %v", err)
	}
	raw, err = os.ReadFile(freezePath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(raw)) != "0" {
		t.Fatalf("cgroup.freeze was not released: %q", string(raw))
	}
}
