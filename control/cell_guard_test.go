// STATUS: PLATIN
// SPDX-FileCopyrightText: 2026 VisionGaia Technology
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"testing"
	"time"
)

// TestCellGuardRefusesWhatItCannotProve pins the safety rule of automatic isolation: no cgroup, no
// isolation; no runtime, no isolation; unknown incident, no isolation. Guessing is how the wrong
// workload gets frozen.
func TestCellGuardRefusesWhatItCannotProve(t *testing.T) {
	cfg := defaultConfig().Cells
	cfg.AutoConfine = true
	guard := NewCellGuard(NewState("test", Config{}), cfg)

	if _, err := guard.Confine(0, cellActionRevokeNetwork, "test"); err == nil {
		t.Fatal("a workload without a cgroup was isolated")
	}
	if _, err := guard.Confine(4242, "", "test"); err == nil {
		t.Fatal("a workload was isolated without a Cells runtime")
	}
	if _, err := guard.ConfineIncident("incident-that-does-not-exist", cellActionRevokeNetwork, "test"); err == nil {
		t.Fatal("an unknown incident was isolated")
	}
	status := guard.Status()
	if status.Isolated != 0 {
		t.Fatalf("the guard reported %d isolations for refused work", status.Isolated)
	}
	if status.Enabled != true || status.Action != cellActionRevokeNetwork {
		t.Fatalf("status = %+v", status)
	}
}

// TestCellGuardCooldownIsBounded makes sure a repeating incident cannot hammer the runtime: the same
// workload is retried after the cooldown, not on every scan.
func TestCellGuardCooldownIsBounded(t *testing.T) {
	cfg := defaultConfig().Cells
	cfg.AutoConfineCooldownSeconds = 300
	now := time.Unix(1_800_000_000, 0).UTC()
	guard := NewCellGuard(NewState("test", Config{}), cfg)
	guard.now = func() time.Time { return now }
	if guard.coolingDown(7) {
		t.Fatal("a fresh cgroup was already cooling down")
	}
	guard.last[7] = now
	if !guard.coolingDown(7) {
		t.Fatal("the cooldown was not honoured")
	}
	now = now.Add(301 * time.Second)
	if guard.coolingDown(7) {
		t.Fatal("the cooldown never expired")
	}
}

// TestCellActionIsNormalised keeps a typo from being forwarded to the runtime as an action name.
func TestCellActionIsNormalised(t *testing.T) {
	if got := normalizeCellAction(""); got != cellActionRevokeNetwork {
		t.Fatalf("empty action = %q", got)
	}
	if got := normalizeCellAction(cellActionFreeze); got != cellActionFreeze {
		t.Fatalf("freeze = %q", got)
	}
	if got := normalizeCellAction("rm -rf"); got != "" {
		t.Fatalf("an unknown action was accepted: %q", got)
	}
}

// TestCellGuardDisabledDoesNotScan proves the default: without auto_confine nothing is isolated by the
// background path.
func TestCellGuardDisabledDoesNotScan(t *testing.T) {
	state := NewState("test", Config{})
	guard := NewCellGuard(state, defaultConfig().Cells)
	state.RestoreIncidents([]XDRIncident{{ID: "inc-1", Score: 240, CellCgroupID: 11}})
	guard.scan()
	if status := guard.Status(); status.Isolated != 0 || status.Refused != 0 {
		t.Fatalf("a disabled guard acted: %+v", status)
	}
}
