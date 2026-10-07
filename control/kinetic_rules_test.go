package main

import (
	"strings"
	"testing"
)

func TestKineticRuleRegistry(t *testing.T) {
	reg := NewKineticRuleRegistry()

	expectedRules := []string{
		"NET.INGRESS.IP_RATE",
		"NET.INGRESS.IP_VELOCITY",
		"NET.INGRESS.SYN_FLOOD",
		"NET.INGRESS.PORT_SCAN",
		"NET.INGRESS.PORT_DIVERSITY",
		"NET.INGRESS.SUBNET_V4",
		"NET.INGRESS.SUBNET_V6",
		"NET.INGRESS.WIDE_V4",
		"NET.INGRESS.MALFORMED_TCP",
		"TLS.SNI.INVALID",
		"TLS.SNI.REPEATED_INVALID",
		"TLS.SNI.FOREIGN",
		"TLS.JA3.MALICIOUS",
		"TLS.JA3.STRUCTURAL_SPOOF",
		"TLS.HANDSHAKE.FLOOD",
	}

	for _, ruleID := range expectedRules {
		rule, found := reg.Get(ruleID)
		if !found {
			t.Errorf("expected rule %s in registry, but was missing", ruleID)
			continue
		}
		if rule.DefaultScore <= 0 {
			t.Errorf("rule %s has non-positive score %d", ruleID, rule.DefaultScore)
		}
		if rule.Summary == "" {
			t.Errorf("rule %s missing summary", ruleID)
		}
		if rule.Layer == "" {
			t.Errorf("rule %s missing layer", ruleID)
		}
	}

	all := reg.List()
	if len(all) < len(expectedRules) {
		t.Fatalf("expected at least %d rules, got %d", len(expectedRules), len(all))
	}
}

func TestKineticReleaseGateBlockers(t *testing.T) {
	_, state, _, release := betaReleaseFixture(t)

	// In fixture, all mandatory sensors start online -> canary promotion ready
	blockers := release.currentBlockersLocked(ReleasePhaseCanary, false)
	for _, b := range blockers {
		if strings.Contains(b, "Kinetic") || strings.Contains(b, "sensor coverage") {
			t.Fatalf("unexpected kinetic blocker in healthy fixture: %s", b)
		}
	}

	// Artificially take xdp_ingress sensor offline
	state.SetSensorCoverage(SensorCoverage{
		Name:     "xdp_ingress",
		Layer:    LayerIngressNetwork,
		Status:   CoverageOffline,
		Required: true,
	})

	blockers = release.currentBlockersLocked(ReleasePhaseCanary, false)
	foundSensorBlocker := false
	for _, b := range blockers {
		if b == "Kinetic ingress sensor is unavailable" {
			foundSensorBlocker = true
			break
		}
	}
	if !foundSensorBlocker {
		t.Fatalf("expected 'Kinetic ingress sensor is unavailable' blocker when xdp_ingress offline, got: %v", blockers)
	}

	// For enforce target, should also block on non-nominal coverage
	enforceBlockers := release.currentBlockersLocked(ReleasePhaseEnforce, false)
	foundCoverageBlocker := false
	for _, b := range enforceBlockers {
		if strings.Contains(b, "kinetic sensor coverage is not nominal") {
			foundCoverageBlocker = true
			break
		}
	}
	if !foundCoverageBlocker {
		t.Fatalf("expected coverage blocker in enforce blockers: %v", enforceBlockers)
	}

	// Restore sensor to online
	state.SetSensorCoverage(SensorCoverage{
		Name:     "xdp_ingress",
		Layer:    LayerIngressNetwork,
		Status:   CoverageOnline,
		Required: true,
	})

	blockers = release.currentBlockersLocked(ReleasePhaseCanary, false)
	for _, b := range blockers {
		if b == "Kinetic ingress sensor is unavailable" {
			t.Fatalf("sensor blocker persisted after sensor restored to online: %s", b)
		}
	}
}
