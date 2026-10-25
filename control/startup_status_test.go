// SPDX-FileCopyrightText: 2026 VisionGaia Technology
// SPDX-License-Identifier: AGPL-3.0-only

package main

// Tests for the bounded startup self-check status view. The view is what the
// API exposes; it must never hold secrets, never grow with a pathological
// module count and must mark a dead supervisor as stale instead of healthy.

import (
	"strings"
	"testing"
	"time"
)

func TestStartupStatusViewIsBounded(t *testing.T) {
	now := time.Date(2026, 10, 25, 16, 0, 0, 0, time.UTC)
	modules := make([]StartupModuleReport, 0, startupStatusMaxModules+10)
	for index := 0; index < startupStatusMaxModules+10; index++ {
		modules = append(modules, StartupModuleReport{
			Name: "module-" + strings.Repeat("x", index%3), State: startupModuleFailed,
			Detail: strings.Repeat("d", 400), Blocking: true,
		})
	}
	report := StartupReport{
		CheckedAt: now.Add(-time.Minute), Modules: modules, BlockingIssues: 3, Healed: 1,
		ReArm: startupReArmBlocked, ReArmReason: "kernel enforcement is not verified",
		Fingerprint: "release=5.0.0; kernel=7.0.0",
	}
	view := report.statusView(now, now.Add(-2*time.Minute))
	if len(view.Modules) != startupStatusMaxModules {
		t.Fatalf("module list not capped: %d", len(view.Modules))
	}
	for _, module := range view.Modules {
		if len(module.Detail) > 240 {
			t.Fatalf("module detail not bounded: %d", len(module.Detail))
		}
	}
	if view.Stale || view.ReportAgeSec != 120 {
		t.Fatalf("unexpected freshness verdict: %+v", view)
	}
	stale := report.statusView(now, now.Add(-2*startupStatusMaxAge))
	if !stale.Stale {
		t.Fatalf("dead supervisor not reported as stale: %+v", stale)
	}
	if stale.ReportAgeSec < int64(startupStatusMaxAge.Seconds()) {
		t.Fatalf("stale report age=%d", stale.ReportAgeSec)
	}
}

func TestStartupStatusStorePublishesFirstReport(t *testing.T) {
	startupReportStore.mu.Lock()
	startupReportStore.report = StartupReport{}
	startupReportStore.updated = time.Time{}
	startupReportStore.seq = 0
	startupReportStore.mu.Unlock()
	if _, ok := CurrentStartupStatus(); ok {
		t.Fatal("status was reported before the supervisor published anything")
	}
	report := StartupReport{
		CheckedAt: time.Now().UTC(), Modules: []StartupModuleReport{{Name: "core_ipc", State: startupModuleOK}},
		ReArm: startupReArmArmed, ReArmReason: "all modules verified", Fingerprint: "release=5.0.0",
	}
	publishStartupReport(report)
	view, ok := CurrentStartupStatus()
	if !ok {
		t.Fatal("published report not visible")
	}
	if view.ReArm != startupReArmArmed || len(view.Modules) != 1 || view.Modules[0].Name != "core_ipc" {
		t.Fatalf("unexpected view: %+v", view)
	}
	if StartupStatusSequence() == 0 {
		t.Fatal("status sequence did not advance")
	}
	// Mutating the published report of the caller must not mutate the view.
	report.Modules[0].State = "tampered"
	view, _ = CurrentStartupStatus()
	if view.Modules[0].State != startupModuleOK {
		t.Fatal("store exposed mutable caller state")
	}
}
