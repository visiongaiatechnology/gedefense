// STATUS: DIAMANT VGT SUPREME
package main

import (
	"testing"
	"time"
)

func TestBuildOverviewSituationTrafficLights(t *testing.T) {
	now := time.Now().UTC()
	baseSnap := Snapshot{
		CoreConnected: true,
		Enforcement:   "enforce",
		Release:       ReleaseStatus{Phase: "enforce"},
		Protection:    ProtectionStatus{Effective: true},
		Policy:        PolicyStatus{Verified: true},
		FIM:           FIMStatus{Health: fimHealthVerified},
		XDR:           XDRStatus{Enabled: true, Mode: "enforce", Processes: 42},
		L7:            L7Status{Enabled: true, Mode: "enforce"},
	}

	green := buildOverviewSituation(situationInput{
		Now: now, Snap: baseSnap, TLSCapture: "active", TLSHandshakes: 12,
		ExposureServers: 2, StyxState: "active", StyxFlows: 5,
	})
	if green.Level != "green" {
		t.Fatalf("expected green calm posture, got %s (%s)", green.Level, green.Summary)
	}
	if !green.Metrics.FullProtection || green.Metrics.CoveragePercent < 80 {
		t.Fatalf("unexpected coverage/full_protection: %+v", green.Metrics)
	}

	// Unmitigated critical storm -> RED
	red := buildOverviewSituation(situationInput{
		Now: now, Snap: baseSnap, TLSStormActive: true, WorkerStorms: 1,
	})
	if red.Level != "red" {
		t.Fatalf("expected red posture during active crash/tls storm, got %s", red.Level)
	}

	// Partial / observe phase -> YELLOW
	obsSnap := baseSnap
	obsSnap.Release.Phase = "observe"
	obsSnap.Protection.Effective = false
	yellow := buildOverviewSituation(situationInput{Now: now, Snap: obsSnap})
	if yellow.Level != "yellow" {
		t.Fatalf("expected yellow posture in observe phase, got %s", yellow.Level)
	}

	// FIM only new files (0 tampered, 0 missing, 2 new) -> YELLOW, not RED
	newFilesSnap := baseSnap
	newFilesSnap.FIM = FIMStatus{
		Health:   fimHealthTampered,
		LastScan: &FIMScanSummary{Tampered: 0, Missing: 0, New: 2},
	}
	fimWarn := buildOverviewSituation(situationInput{Now: now, Snap: newFilesSnap})
	if fimWarn.Level != "yellow" || fimWarn.StatusCode != "fim_new_files" {
		t.Fatalf("expected yellow fim_new_files when 0 tampered and 2 new, got %s (%s)", fimWarn.Level, fimWarn.StatusCode)
	}

	// FIM actual tampered file -> RED
	tamperSnap := baseSnap
	tamperSnap.FIM = FIMStatus{
		Health:   fimHealthTampered,
		LastScan: &FIMScanSummary{Tampered: 1, Missing: 0, New: 0},
	}
	fimRed := buildOverviewSituation(situationInput{Now: now, Snap: tamperSnap})
	if fimRed.Level != "red" || fimRed.StatusCode != "fim_tamper" {
		t.Fatalf("expected red fim_tamper when file actually tampered, got %s (%s)", fimRed.Level, fimRed.StatusCode)
	}

	// Auto-cooldown: active critical alert / storm (0-15m) -> RED, cooling (15-60m) -> YELLOW, subsided (>60m) with older blocked incidents -> GREEN (calm_mitigated)
	coolingSnap := baseSnap
	coolingSnap.Incidents = []XDRIncident{
		{ID: "storm-1", Time: now.Add(-30 * time.Minute), Severity: "critical", Decision: "alert", Action: "none"},
		{ID: "ban-1", Time: now.Add(-2 * time.Hour), Severity: "high", Decision: "block", Action: "drop"},
		{ID: "ban-2", Time: now.Add(-3 * time.Hour), Severity: "medium", Decision: "block", Action: "drop"},
		{ID: "ban-3", Time: now.Add(-4 * time.Hour), Severity: "medium", Decision: "block", Action: "drop"},
	}
	cooling := buildOverviewSituation(situationInput{
		Now: now, Snap: coolingSnap, WorkerStormsCooling: 1,
		TLSCapture: "active", ExposureServers: 2, StyxState: "active", StyxFlows: 5,
	})
	if cooling.Level != "yellow" || cooling.StatusCode != "elevated_activity" {
		t.Fatalf("expected yellow elevated_activity during 15-60m cooldown, got %s (%s)", cooling.Level, cooling.StatusCode)
	}

	subsidedSnap := baseSnap
	subsidedSnap.Incidents = []XDRIncident{
		{ID: "storm-1", Time: now.Add(-2 * time.Hour), Severity: "critical", Decision: "alert", Action: "none"},
		{ID: "ban-1", Time: now.Add(-2 * time.Hour), Severity: "high", Decision: "block", Action: "drop"},
		{ID: "ban-2", Time: now.Add(-3 * time.Hour), Severity: "medium", Decision: "block", Action: "drop"},
		{ID: "ban-3", Time: now.Add(-4 * time.Hour), Severity: "medium", Decision: "block", Action: "drop"},
		{ID: "ban-4", Time: now.Add(-5 * time.Hour), Severity: "medium", Decision: "block", Action: "drop"},
		{ID: "ban-5", Time: now.Add(-6 * time.Hour), Severity: "medium", Decision: "block", Action: "drop"},
	}
	subsided := buildOverviewSituation(situationInput{
		Now: now, Snap: subsidedSnap,
		TLSCapture: "active", ExposureServers: 2, StyxState: "active", StyxFlows: 5,
	})
	if subsided.Level != "green" || subsided.StatusCode != "calm_mitigated" || subsided.Metrics.CoveragePercent != 100 {
		t.Fatalf("expected green calm_mitigated (100%% coverage) after >60m cooldown, got %s (%s, coverage=%d%%)",
			subsided.Level, subsided.StatusCode, subsided.Metrics.CoveragePercent)
	}
}
