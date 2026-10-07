// STATUS: DIAMANT VGT SUPREME
package main

import (
	"testing"
	"time"
)

// TestEvaluateL7CoverageSeparatesReadyFromSilent pins the distinction that the
// earlier logic collapsed. An engine that is healthy with nothing attached and an
// engine whose attached path has gone silent are different facts, and only the
// second one is a fault.
func TestEvaluateL7CoverageSeparatesReadyFromSilent(t *testing.T) {
	healthyIdle := L7Status{Enabled: true, Healthy: true, InlineEnabled: false}

	// Nothing attached, nothing seen: ready, not a warning.
	if got := EvaluateL7Coverage(healthyIdle, 3600); got != "READY_NOT_ATTACHED" {
		t.Fatalf("an unattached engine reported %q, want READY_NOT_ATTACHED", got)
	}

	// The inline path is attached and silent past the grace period: a real fault.
	attachedSilent := L7Status{Enabled: true, Healthy: true, InlineEnabled: true, InlineHealthy: true}
	if got := EvaluateL7Coverage(attachedSilent, 3600); got != "NO_TRAFFIC_WARNING" {
		t.Fatalf("an attached but silent path reported %q, want NO_TRAFFIC_WARNING", got)
	}

	// Inside the grace period the attached path is still waiting, not degraded.
	if got := EvaluateL7Coverage(attachedSilent, 60); got != "HEALTHY_AWAITING_TRAFFIC" {
		t.Fatalf("a freshly attached path reported %q, want HEALTHY_AWAITING_TRAFFIC", got)
	}

	// Note on a gap: "a producer is attached but has never delivered a request" is
	// NOT expressible with today's fields, because attachment is inferred from
	// traffic having arrived. Distinguishing it needs explicit producer telemetry
	// (producer_attached, last_producer_seen), which is not implemented here. Until
	// then such a producer is reported as READY_NOT_ATTACHED, which is the safe
	// reading: it does not degrade the platform, and it does not claim coverage that
	// has never been demonstrated.

	// Live traffic wins over everything else.
	active := L7Status{Enabled: true, Healthy: true, RequestsTotal: 12}
	if got := EvaluateL7Coverage(active, 60); got != "TRAFFIC_ACTIVE" {
		t.Fatalf("an active path reported %q, want TRAFFIC_ACTIVE", got)
	}

	// Disabled and unhealthy keep their own verdicts.
	if got := EvaluateL7Coverage(L7Status{Enabled: false}, 3600); got != "DISABLED" {
		t.Fatalf("a disabled engine reported %q, want DISABLED", got)
	}
	if got := EvaluateL7Coverage(L7Status{Enabled: true, Healthy: false}, 3600); got != "OFFLINE" {
		t.Fatalf("an unhealthy engine reported %q, want OFFLINE", got)
	}
}

// TestL7CoverageRequirementModes covers the three modes of the new option.
func TestL7CoverageRequirementModes(t *testing.T) {
	cases := []struct {
		mode     string
		enabled  bool
		attached bool
		want     bool
	}{
		{"auto", true, false, false}, // enabled but nothing wired in: not required
		{"auto", true, true, true},   // something is attached: required
		{"auto", false, true, false}, // disabled wins over attachment
		{"required", true, false, true},
		{"required", true, true, true},
		{"required", false, false, false},
		{"optional", true, true, false},
		{"optional", true, false, false},
	}
	for _, tc := range cases {
		got := l7CoverageRequired(tc.mode, tc.enabled, tc.attached)
		if got != tc.want {
			t.Errorf("l7CoverageRequired(%q, enabled=%v, attached=%v) = %v, want %v", tc.mode, tc.enabled, tc.attached, got, tc.want)
		}
	}
}

// TestL7CoverageRequirementDefaultsToAuto proves the shipped configuration and the
// compiled-in default agree, so an operator who never sets the option gets the
// non-degrading behaviour.
func TestL7CoverageRequirementDefaultsToAuto(t *testing.T) {
	cfg := defaultConfig()
	if cfg.L7.CoverageRequired != "auto" {
		t.Fatalf("compiled-in default is %q, want auto", cfg.L7.CoverageRequired)
	}
	// An unknown mode must not silently become "required": it falls back to auto.
	if !l7CoverageRequired("nonsense", true, true) {
		t.Fatal("an unknown mode did not fall back to auto semantics")
	}
	if l7CoverageRequired("nonsense", true, false) {
		t.Fatal("an unknown mode required coverage for an unattached engine")
	}
}

// TestCoverageNotApplicableKeepsThePlatformNominal proves the end-to-end effect:
// an unattached, non-required L7 sensor must not make the system non-nominal. This
// is the defect where the sidebar said SYSTEM NOMINAL while Kinetic said DEGRADED.
func TestCoverageNotApplicableKeepsThePlatformNominal(t *testing.T) {
	sensors := map[string]SensorCoverage{
		"ingress_network": {Name: "ingress_network", Layer: LayerIngressNetwork, Status: CoverageOnline, Required: true},
		"l7_application": {
			Name: "l7_application", Layer: LayerApplicationL7,
			Status: CoverageNotApplicable, Required: false,
			SelfTest: "ready-not-attached",
		},
	}
	coverage := EvaluateCoverage(sensors)
	if !coverage.Nominal {
		t.Fatalf("an available-but-unattached L7 engine made the platform non-nominal: %+v", coverage)
	}
	if coverage.OverallStatus != CoverageOnline {
		t.Fatalf("overall status is %q, want online", coverage.OverallStatus)
	}

	// The same sensor, now required and degraded, must do the opposite. This is the
	// half that stops the fix from becoming a way to hide a genuinely broken path.
	sensors["l7_application"] = SensorCoverage{
		Name: "l7_application", Layer: LayerApplicationL7,
		Status: CoverageDegraded, Required: true,
		SelfTest: "awaiting-traffic", LastError: "attached path is silent",
		LastOK: ptrTime(time.Now().UTC()),
	}
	broken := EvaluateCoverage(sensors)
	if broken.Nominal {
		t.Fatalf("a required and degraded L7 sensor left the platform nominal: %+v", broken)
	}
}

func ptrTime(t time.Time) *time.Time { return &t }
