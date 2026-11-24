// STATUS: V6.3.0 AP-6
package main

// V6.3.0 AP-6 regression tests for the GIEF v1.0 envelope: shared fixtures, the
// version/JSON contract, metadata-only attachment and nil-safety. The mapping
// matrices live in gief_mapping_test.go; hash/blindspot honesty in
// gief_evidence_test.go.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"
)

func newGIEFTestEngine(t *testing.T, degraded bool, degradedReason string, hasBPFLSM bool) *XDREngine {
	t.Helper()
	engine := &XDREngine{
		state:         NewState("test", defaultConfig()),
		gief:          NewGIEFEngine(),
		sbc:           NewSBCFusionEngine(),
		platformCaps:  PlatformCapabilities{HasBPFLSM: hasBPFLSM, HasCgroupV2: true, DetectedAt: time.Now().UTC()},
		degradeCauses: map[string]string{},
	}
	if degraded {
		engine.degraded = true
		engine.degradeWhy = degradedReason
	}
	return engine
}

// buildGIEFTestEnvelope classifies and builds an envelope exactly like the
// attachment seam does, so the pure mappings are testable without a logger.
func buildGIEFTestEnvelope(engine *XDREngine, incident XDRIncident, facts giefFacts) GIEFEnvelope {
	family, familyKnown, class := engine.gief.classify(incident)
	return engine.gief.buildEnvelope(giefBuildInput{
		incident: incident, facts: facts, family: family, familyKnown: familyKnown, class: class,
	})
}

func healthyGIEFFacts() giefFacts {
	return giefFacts{capsKnown: true, hasBPFLSM: true, hasCgroupV2: true}
}

func giefTestHash(t *testing.T, value string) string {
	t.Helper()
	digest := sha256.Sum256([]byte(value))
	return hex.EncodeToString(digest[:])
}

func TestGIEFVersionAndJSONShape(t *testing.T) {
	engine := newGIEFTestEngine(t, false, "", true)
	incident := XDRIncident{
		ID: "inc-gief-1", Time: time.Unix(1_700_000_000, 0).UTC(), Severity: "high",
		Score: 150, ResponseScore: 150, KillSignals: 2,
		PID: 4242, UID: 1000, Executable: "/usr/bin/cred-reader",
		RuleIDs: []string{"XDR.CREDENTIAL_READ_BLOCKED"}, Categories: []string{"credential", "access"},
		Decision: "kill", Action: "stop",
	}
	enriched := engine.attachGIEFEnvelope(incident)
	if enriched.GIEF == nil {
		t.Fatal("attachGIEFEnvelope did not attach an envelope")
	}
	if GIEFVersion != "gief/v1.0" || enriched.GIEF.Version != "gief/v1.0" {
		t.Fatalf("version is %q / %q, want gief/v1.0", GIEFVersion, enriched.GIEF.Version)
	}
	if enriched.GIEF.SBCFamily != SBCFamilyCredential {
		t.Fatalf("sbc family is %q, want %q", enriched.GIEF.SBCFamily, SBCFamilyCredential)
	}
	if enriched.GIEF.CorrelationQuality != giefCorrelationObserved {
		t.Fatalf("correlation quality is %q, want OBSERVED", enriched.GIEF.CorrelationQuality)
	}
	if enriched.GIEF.Capability.Level != giefLevelFull || enriched.GIEF.Capability.Visibility != giefVisibilityObserved {
		t.Fatalf("capability is %+v", enriched.GIEF.Capability)
	}
	encoded, err := json.Marshal(enriched)
	if err != nil {
		t.Fatalf("marshal enriched incident: %v", err)
	}
	for _, want := range []string{`"gief":{"version":"gief/v1.0"`, `"capability":{`, `"correlation_quality":"OBSERVED"`, `"sbc_family":"SBC-CRED-04"`} {
		if !strings.Contains(string(encoded), want) {
			t.Fatalf("envelope JSON is missing %q: %s", want, encoded)
		}
	}
	// The untouched input must not have been mutated in place.
	if incident.GIEF != nil {
		t.Fatal("attachment mutated the caller's incident value")
	}
}

func TestGIEFAttachmentIsMetadataOnly(t *testing.T) {
	engine := newGIEFTestEngine(t, false, "", true)
	now := time.Unix(1_700_000_000, 0).UTC()
	// Seed the entity so the second finding carries a fusion context as well.
	engine.attachGIEFEnvelope(XDRIncident{
		ID: "seed", Time: now, Severity: "critical", Executable: "/opt/vendor/agent",
		RuleIDs: []string{"XDR.CREDENTIAL_READ_BLOCKED"}, Categories: []string{"credential"},
		Decision: "alert", Action: "none",
	})
	incident := XDRIncident{
		ID: "inc-immutable", Time: now.Add(time.Minute), Severity: "critical",
		Score: 240, ResponseScore: 190, KillSignals: 3,
		PID: 4242, UID: 0, Executable: "/opt/vendor/agent",
		RuleIDs: []string{"XDR.CREDENTIAL_READ_BLOCKED", "XDR.SELF_TAMPER"}, Categories: []string{"credential", "integrity"},
		Summary: "representative decision-bearing incident", Decision: "kill", Action: "stop",
		RecordHash: giefTestHash(t, "record"), EvidenceRoot: giefTestHash(t, "root"),
	}
	decisionSnapshot := fmt.Sprintf("%d|%d|%d|%s|%s|%v|%v",
		incident.Score, incident.ResponseScore, incident.KillSignals,
		incident.Decision, incident.Action, incident.RuleIDs, incident.Categories)

	enriched := engine.attachGIEFEnvelope(incident)
	enrichedSnapshot := fmt.Sprintf("%d|%d|%d|%s|%s|%v|%v",
		enriched.Score, enriched.ResponseScore, enriched.KillSignals,
		enriched.Decision, enriched.Action, enriched.RuleIDs, enriched.Categories)
	if decisionSnapshot != enrichedSnapshot {
		t.Fatalf("attachment mutated decision fields:\nbefore: %s\nafter:  %s", decisionSnapshot, enrichedSnapshot)
	}
	if !reflect.DeepEqual(incident.RuleIDs, enriched.RuleIDs) || !reflect.DeepEqual(incident.Categories, enriched.Categories) {
		t.Fatal("attachment mutated rule ids or categories")
	}
	if enriched.GIEF == nil {
		t.Fatal("attachment did not produce an envelope")
	}
	if enriched.GIEF.SBC == nil {
		t.Fatal("second finding of the same entity has no fusion context")
	}

	// The full appendIncident path must keep the same guarantee.
	engine.appendIncident(incident)
	var stored *XDRIncident
	for _, candidate := range engine.state.Snapshot().Incidents {
		if candidate.ID == incident.ID {
			copyOfCandidate := candidate
			stored = &copyOfCandidate
		}
	}
	if stored == nil {
		t.Fatal("incident did not reach the state store")
	}
	storedSnapshot := fmt.Sprintf("%d|%d|%d|%s|%s|%v|%v",
		stored.Score, stored.ResponseScore, stored.KillSignals,
		stored.Decision, stored.Action, stored.RuleIDs, stored.Categories)
	if storedSnapshot != decisionSnapshot {
		t.Fatalf("appendIncident path mutated decision fields:\nbefore: %s\nafter:  %s", decisionSnapshot, storedSnapshot)
	}
	if stored.GIEF == nil || stored.GIEF.Version != GIEFVersion {
		t.Fatal("appendIncident path lost the GIEF envelope")
	}
}

func TestGIEFAttachmentIsNilSafe(t *testing.T) {
	var nilEngine *XDREngine
	incident := XDRIncident{ID: "nil-safe", RuleIDs: []string{"XDR.TEMP_EXEC"}}
	if got := nilEngine.attachGIEFEnvelope(incident); got.GIEF != nil {
		t.Fatal("nil engine attached an envelope")
	}
	unwired := &XDREngine{}
	if got := unwired.attachGIEFEnvelope(incident); got.GIEF != nil {
		t.Fatal("engine without a GIEF builder attached an envelope")
	}
}
