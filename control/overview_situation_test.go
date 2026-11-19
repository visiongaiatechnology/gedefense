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
}
