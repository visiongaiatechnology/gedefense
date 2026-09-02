// STATUS: DIAMANT VGT SUPREME
package main

import (
	"context"
	"testing"
	"time"
)

func TestStyxEgress_CloudMetadataSSRFBlock(t *testing.T) {
	correlator := NewIncidentCorrelator(1800 * time.Second)
	var capturedIncident *XDRIncident

	engine := NewStyxEngine(EgressModeDefaultDeny, correlator, func(inc XDRIncident) error {
		capturedIncident = &inc
		return nil
	})

	ctx := context.Background()

	// 1. Attempt connection to AWS/GCP/Azure IMDS 169.254.169.254
	allowed, reason, err := engine.EvaluateEgress(
		ctx, "CELL", "cell-uuid-1", "169.254.169.254", 80, "TCP", 3301, "curl",
	)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if allowed {
		t.Fatal("expected cloud metadata IP to be blocked")
	}
	if reason != "DROP_CLOUD_METADATA_SSRF" {
		t.Fatalf("expected reason DROP_CLOUD_METADATA_SSRF, got %s", reason)
	}

	// Verify Incident was produced with critical severity and causal edge
	if capturedIncident == nil {
		t.Fatal("expected SSRF incident to be captured")
	}
	if capturedIncident.Severity != "CRITICAL" {
		t.Fatalf("expected CRITICAL severity, got %s", capturedIncident.Severity)
	}
	if len(capturedIncident.AttackStory) == 0 {
		t.Fatal("expected attack story attached")
	}
	if capturedIncident.AttackStory[0].CausalEdge != EdgeEgressAttempted {
		t.Fatalf("expected causal edge EGRESS_ATTEMPTED, got %s", capturedIncident.AttackStory[0].CausalEdge)
	}

	drops, metadataHits := engine.Stats()
	if drops != 1 || metadataHits != 1 {
		t.Fatalf("expected 1 drop and 1 metadata hit, got %d, %d", drops, metadataHits)
	}
}

func TestStyxEgress_ScopedWhitelistAndDefaultDeny(t *testing.T) {
	engine := NewStyxEngine(EgressModeDefaultDeny, nil, nil)
	ctx := context.Background()

	// Add Cell rule: allow 198.51.100.0/24 port 443 TCP only for cell "gaiacom"
	err := engine.AddRule(EgressRule{
		ID:          "RULE-GAIACOM-HTTPS",
		ScopeType:   "CELL",
		ScopeID:     "gaiacom",
		Destination: "198.51.100.0/24",
		Port:        443,
		Protocol:    "TCP",
		Action:      "ALLOW",
		Description: "Allow GaiaCom gateway sync",
	})
	if err != nil {
		t.Fatalf("failed to add rule: %v", err)
	}

	// 1. Connection matching whitelist -> must be allowed
	allowed, reason, _ := engine.EvaluateEgress(
		ctx, "CELL", "gaiacom", "198.51.100.42", 443, "TCP", 1234, "gaiacom-daemon",
	)
	if !allowed || reason != "PERMIT_WHITELIST" {
		t.Fatalf("expected allowed on whitelist, got allowed=%t, reason=%s", allowed, reason)
	}

	// 2. Connection from gaiacom to wrong port (80) -> must be dropped (default-deny)
	allowed, reason, _ = engine.EvaluateEgress(
		ctx, "CELL", "gaiacom", "198.51.100.42", 80, "TCP", 1234, "gaiacom-daemon",
	)
	if allowed || reason != "DROP_DEFAULT_DENY" {
		t.Fatalf("expected drop on unlisted port, got allowed=%t, reason=%s", allowed, reason)
	}

	// 3. Connection from another cell ("infinity") to same IP -> must be dropped (isolation)
	allowed, reason, _ = engine.EvaluateEgress(
		ctx, "CELL", "infinity", "198.51.100.42", 443, "TCP", 5678, "infinity-cell",
	)
	if allowed || reason != "DROP_DEFAULT_DENY" {
		t.Fatalf("expected drop for unauthorized cell, got allowed=%t, reason=%s", allowed, reason)
	}
}
