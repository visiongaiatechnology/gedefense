package main

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestEvaluateCoverageDeterminism(t *testing.T) {
	// 1. All mandatory online
	sensors := map[string]SensorCoverage{
		"xdp_ingress": {
			Name:     "xdp_ingress",
			Layer:    LayerIngressNetwork,
			Status:   CoverageOnline,
			Required: true,
		},
		"host_exec": {
			Name:     "host_exec",
			Layer:    LayerHostXDR,
			Status:   CoverageOnline,
			Required: true,
		},
		"optional_sensor": {
			Name:     "optional_sensor",
			Layer:    LayerApplicationL7,
			Status:   CoverageOffline,
			Required: false,
		},
	}

	cov := EvaluateCoverage(sensors)
	if !cov.Nominal {
		t.Fatalf("expected nominal=true when all required sensors online, got false (%s)", cov.Summary)
	}
	if cov.OverallStatus != CoverageOnline {
		t.Fatalf("expected overall=online, got %s", cov.OverallStatus)
	}

	// 2. Required sensor degraded
	sensors["host_exec"] = SensorCoverage{
		Name:     "host_exec",
		Layer:    LayerHostXDR,
		Status:   CoverageDegraded,
		Required: true,
	}
	cov = EvaluateCoverage(sensors)
	if cov.Nominal {
		t.Fatalf("expected nominal=false when required sensor degraded")
	}
	if cov.OverallStatus != CoverageDegraded {
		t.Fatalf("expected overall=degraded, got %s", cov.OverallStatus)
	}
	if !strings.Contains(cov.Summary, "host_exec") {
		t.Fatalf("expected summary to mention host_exec, got: %s", cov.Summary)
	}

	// 3. Required sensor offline
	sensors["xdp_ingress"] = SensorCoverage{
		Name:     "xdp_ingress",
		Layer:    LayerIngressNetwork,
		Status:   CoverageOffline,
		Required: true,
	}
	cov = EvaluateCoverage(sensors)
	if cov.Nominal {
		t.Fatalf("expected nominal=false when required sensor offline")
	}
	if cov.OverallStatus != CoverageOffline {
		t.Fatalf("expected overall=offline, got %s", cov.OverallStatus)
	}
	if !strings.Contains(cov.Summary, "xdp_ingress") {
		t.Fatalf("expected summary to mention xdp_ingress, got: %s", cov.Summary)
	}
}

func TestKineticEventFingerprintAndSerialization(t *testing.T) {
	now := time.Now().UTC()
	event := KineticEvent{
		ID:            "kin-evt-1234",
		Time:          now,
		Layer:         LayerIngressNetwork,
		Sensor:        "xdp_ingress",
		RuleID:        "NET.INGRESS.IP_RATE",
		Category:      "rate_limit",
		Severity:      "high",
		Score:         85,
		Confidence:    0.95,
		SourceIP:      "198.51.100.42",
		DestinationIP: "203.0.113.1",
		Port:          443,
		Protocol:      "tcp",
		Hits:          36,
		RatePerSec:    18.5,
		Action:        "block",
		Decision:      "quarantine",
	}

	fp1 := event.ComputeFingerprint()
	if fp1 == "" {
		t.Fatalf("expected non-empty fingerprint")
	}

	// Different IP must produce different fingerprint
	eventDiffIP := event
	eventDiffIP.SourceIP = "198.51.100.43"
	fp2 := eventDiffIP.ComputeFingerprint()
	if fp1 == fp2 {
		t.Fatalf("expected different fingerprint for different source IP")
	}

	// JSON serialization / deserialization roundtrip
	data, err := json.Marshal(event)
	if err != nil {
		t.Fatalf("failed to marshal event: %v", err)
	}

	var decoded KineticEvent
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("failed to unmarshal event: %v", err)
	}
	if decoded.RuleID != "NET.INGRESS.IP_RATE" || decoded.SourceIP != "198.51.100.42" {
		t.Fatalf("decoded event mismatch: %+v", decoded)
	}
}

func TestBoundedEventQueueBackpressure(t *testing.T) {
	q := NewBoundedEventQueue(5)

	for i := 0; i < 12; i++ {
		q.Push(KineticEvent{
			ID:     "evt",
			Hits:   i,
			RuleID: "NET.INGRESS.IP_RATE",
		})
	}

	events, drops := q.Snapshot()
	if len(events) != 5 {
		t.Fatalf("expected queue length 5, got %d", len(events))
	}
	if drops != 7 {
		t.Fatalf("expected 7 drops for 12 pushes into cap 5, got %d", drops)
	}
	// Oldest remaining should have Hits: 7
	if events[0].Hits != 7 {
		t.Fatalf("expected oldest event hits=7, got %d", events[0].Hits)
	}
	// Newest should have Hits: 11
	if events[4].Hits != 11 {
		t.Fatalf("expected newest event hits=11, got %d", events[4].Hits)
	}
}

func TestStateKineticAndCoverageIntegration(t *testing.T) {
	cfg := defaultConfig()
	state := NewState("4.1.0", cfg)

	snap := state.Snapshot()
	if snap.Coverage.Nominal || snap.Coverage.OverallStatus != CoverageOffline {
		t.Fatalf("expected fail-safe initial Kinetic coverage to be offline, got: %+v", snap.Coverage)
	}
	verifiedAt := time.Now().UTC()
	state.SetSensorCoverage(SensorCoverage{
		Name: "xdp_ingress", Layer: LayerIngressNetwork, Status: CoverageOnline, Required: true,
		LastOK: &verifiedAt, SelfTest: "pass", CoverageReason: "verified test sensor",
	})
	if ready := state.Snapshot(); !ready.Coverage.Nominal {
		t.Fatalf("expected coverage nominal after verified sensor, got: %s", ready.Coverage.Summary)
	}

	// Artificially degrade xdp_ingress sensor
	state.SetSensorCoverage(SensorCoverage{
		Name:           "xdp_ingress",
		Layer:          LayerIngressNetwork,
		Status:         CoverageDegraded,
		Required:       true,
		CoverageReason: "eBPF ringbuffer read stall",
	})

	snap2 := state.Snapshot()
	if snap2.Coverage.Nominal {
		t.Fatalf("expected snapshot coverage nominal=false after degradation")
	}
	if snap2.Coverage.OverallStatus != CoverageDegraded {
		t.Fatalf("expected snapshot coverage overall=degraded, got %s", snap2.Coverage.OverallStatus)
	}

	cov, ok := state.SensorCoverage("xdp_ingress")
	if !ok || cov.Status != CoverageDegraded {
		t.Fatalf("expected sensor coverage lookup to return degraded, got %+v", cov)
	}
}
