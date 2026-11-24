// STATUS: V6.3.0 AP-6
package main

// V6.3.0 AP-6 regression tests for SBC fusion semantics: shared fixtures, the
// corroboration context (read before the current finding and never mutating the
// decision), the JSON contract, concurrent observations and evidence-first
// corroboration events. Graph mathematics (decay/capacity/identity/report) live
// in sbc_graph_test.go.

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

// newSBCTestEngine builds the smallest engine that exercises the fusion seam.
func newSBCTestEngine(t *testing.T) (*XDREngine, *SBCFusionEngine) {
	t.Helper()
	engine := &XDREngine{
		state:         NewState("test", defaultConfig()),
		gief:          NewGIEFEngine(),
		sbc:           NewSBCFusionEngine(),
		platformCaps:  PlatformCapabilities{HasBPFLSM: true, HasCgroupV2: true, DetectedAt: time.Now().UTC()},
		degradeCauses: map[string]string{},
	}
	return engine, engine.sbc
}

// sbcTestIncident builds a representative finding for one entity.
func sbcTestIncident(id, executable, ruleID, severity string, at time.Time) XDRIncident {
	return XDRIncident{
		ID: id, Time: at, Severity: severity, Executable: executable,
		RuleIDs: []string{ruleID}, Categories: []string{"credential"},
		Decision: "alert", Action: "none",
	}
}

func sbcTestBaseTime() time.Time {
	return time.Date(2026, 11, 24, 12, 0, 0, 0, time.UTC)
}

// sbcBoundedFamilyForRule mirrors the GIEF family resolution for test fixtures.
func sbcBoundedFamilyForRule(ruleID string) string {
	classification, ok := giefRuleClassificationFor(ruleID)
	if !ok {
		return SBCDefaultFamily
	}
	return classification.family
}

func TestSBCCorroborationContextAndDecisionImmutability(t *testing.T) {
	engine, _ := newSBCTestEngine(t)
	base := sbcTestBaseTime()
	corroborated := XDRIncident{
		ID: "immutable-2", Time: base.Add(time.Minute), Severity: "high",
		Score: 180, ResponseScore: 150, KillSignals: 2,
		PID: 4242, UID: 0, Executable: "/opt/vendor/agent",
		RuleIDs: []string{"XDR.THREAT_INTEL_C2"}, Categories: []string{"c2"},
		Summary: "representative corroborated finding", Decision: "kill", Action: "stop",
	}
	before := fmt.Sprintf("%d|%d|%d|%s|%s|%v|%v",
		corroborated.Score, corroborated.ResponseScore, corroborated.KillSignals,
		corroborated.Decision, corroborated.Action, corroborated.RuleIDs, corroborated.Categories)

	// Seed a prior finding for the same executable from a different family.
	seed := sbcTestIncident("seed", "/opt/vendor/agent", "XDR.CREDENTIAL_READ_BLOCKED", "critical", base)
	if context := engine.attachGIEFEnvelope(seed); context.GIEF == nil || context.GIEF.SBC != nil {
		t.Fatal("the first observation for an entity must not report corroboration")
	}
	enriched := engine.attachGIEFEnvelope(corroborated)
	if enriched.GIEF == nil || enriched.GIEF.SBC == nil {
		t.Fatal("corroborated finding carries no SBC context")
	}
	if got, want := enriched.GIEF.SBC.Families, []string{SBCFamilyCredential}; len(got) != 1 || got[0] != want[0] {
		t.Fatalf("SBC context families are %v, want %v", got, want)
	}
	if enriched.GIEF.SBC.HalfLifeMinutes != 30 {
		t.Fatalf("SBC context half-life is %v, want 30", enriched.GIEF.SBC.HalfLifeMinutes)
	}
	if enriched.GIEF.SBC.Corroborations != 1 {
		t.Fatalf("SBC context corroborations is %d, want 1", enriched.GIEF.SBC.Corroborations)
	}
	after := fmt.Sprintf("%d|%d|%d|%s|%s|%v|%v",
		enriched.Score, enriched.ResponseScore, enriched.KillSignals,
		enriched.Decision, enriched.Action, enriched.RuleIDs, enriched.Categories)
	if before != after {
		t.Fatalf("fusion context mutated decision fields:\nbefore: %s\nafter:  %s", before, after)
	}
	// Categories never grow through fusion.
	if len(enriched.Categories) != 1 || enriched.Categories[0] != "c2" {
		t.Fatalf("fusion changed the categories: %v", enriched.Categories)
	}

	// The next observation sees both prior families, sorted.
	third := sbcTestIncident("third", "/opt/vendor/agent", "XDR.TEMP_EXEC", "warning", base.Add(2*time.Minute))
	enriched = engine.attachGIEFEnvelope(third)
	if enriched.GIEF == nil || enriched.GIEF.SBC == nil {
		t.Fatal("third observation lost the SBC context")
	}
	wantFamilies := []string{SBCFamilyC2, SBCFamilyCredential}
	if len(enriched.GIEF.SBC.Families) != 2 || enriched.GIEF.SBC.Families[0] != wantFamilies[0] || enriched.GIEF.SBC.Families[1] != wantFamilies[1] {
		t.Fatalf("prior families are %v, want sorted %v", enriched.GIEF.SBC.Families, wantFamilies)
	}
	if enriched.GIEF.SBC.Corroborations != 2 {
		t.Fatalf("corroborations is %d, want 2", enriched.GIEF.SBC.Corroborations)
	}

	// The fusion context must never be consulted by the kill gate: a single
	// kill-eligible category still cannot produce a kill, no matter how many
	// corroborating observations the graph holds.
	for i := 0; i < 50; i++ {
		noise := sbcTestIncident(fmt.Sprintf("noise-%d", i), "/opt/vendor/agent", "XDR.TEMP_EXEC", "warning", base.Add(3*time.Minute))
		engine.attachGIEFEnvelope(noise)
	}
	gateDecision := combineMatches([]RuleMatch{{ID: "XDR.TEMP_EXEC", Category: "origin", Score: 55, KillEligible: true}})
	if gateDecision.Decision != "alert" || gateDecision.KillSignals != 1 {
		t.Fatalf("single-signal kill gate changed: %+v", gateDecision)
	}
}

func TestSBCContextJSONContract(t *testing.T) {
	engine, _ := newSBCTestEngine(t)
	base := sbcTestBaseTime()
	engine.attachGIEFEnvelope(sbcTestIncident("seed", "/opt/sbc/json", "XDR.CREDENTIAL_READ_BLOCKED", "warning", base))
	enriched := engine.attachGIEFEnvelope(sbcTestIncident("second", "/opt/sbc/json", "XDR.THREAT_INTEL_C2", "warning", base.Add(time.Minute)))
	encoded, err := json.Marshal(enriched.GIEF.SBC)
	if err != nil {
		t.Fatalf("marshal SBC context: %v", err)
	}
	for _, want := range []string{`"families":["SBC-CRED-04"]`, `"decayed_score":`, `"half_life_minutes":30`, `"corroborations":1`} {
		if !strings.Contains(string(encoded), want) {
			t.Fatalf("SBC context JSON misses %q: %s", want, encoded)
		}
	}
}

func TestSBCThreadSafeConcurrentObserve(t *testing.T) {
	engine := NewSBCFusionEngine()
	base := sbcTestBaseTime()
	const workers = 8
	const perWorker = 100
	var wg sync.WaitGroup
	for worker := 0; worker < workers; worker++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			for i := 0; i < perWorker; i++ {
				executable := fmt.Sprintf("/opt/sbc/worker-%d", i%4)
				ruleID := "XDR.TEMP_EXEC"
				at := base.Add(time.Duration(i) * time.Second)
				incident := sbcTestIncident(fmt.Sprintf("w%d-%d", worker, i), executable, ruleID, "warning", at)
				engine.observeIncident(incident, sbcBoundedFamilyForRule(ruleID), at)
				_ = engine.Report(at, 0)
			}
		}(worker)
	}
	wg.Wait()
	report := engine.Report(base.Add(perWorker*time.Second), 0)
	if report.Observations != workers*perWorker {
		t.Fatalf("observations is %d, want %d", report.Observations, workers*perWorker)
	}
	if report.Entities != 4 {
		t.Fatalf("entities is %d, want 4", report.Entities)
	}
	if report.Entities > SBCCapacity {
		t.Fatalf("graph exceeded capacity: %d", report.Entities)
	}
}

func TestSBCCorroborationEventIsEvidenceFirst(t *testing.T) {
	engine, fusion := newSBCTestEngine(t)
	base := sbcTestBaseTime()
	seed := XDRIncident{
		ID: "evidence-seed", Time: base, Severity: "critical", Executable: "/opt/sbc/evidence",
		RuleIDs: []string{"XDR.CREDENTIAL_READ_BLOCKED"}, Categories: []string{"credential"},
		Decision: "alert", Action: "none",
	}
	engine.attachGIEFEnvelope(seed)
	second := XDRIncident{
		ID: "evidence-second", Time: base.Add(time.Minute), Severity: "warning", Executable: "/opt/sbc/evidence",
		RuleIDs: []string{"XDR.THREAT_INTEL_C2"}, Categories: []string{"c2"},
		Decision: "alert", Action: "none",
	}
	engine.attachGIEFEnvelope(second)
	if report := fusion.Report(base.Add(2*time.Minute), 0); report.CorroborationEvents != 1 {
		t.Fatalf("corroboration events is %d, want 1", report.CorroborationEvents)
	}
	recorded, err := engine.recordSBCCorroborations(base.Add(2 * time.Minute))
	if err != nil {
		t.Fatalf("evidence-first recording failed: %v", err)
	}
	if recorded != 1 {
		t.Fatalf("recorded %d corroborations, want 1", recorded)
	}
	found := false
	for _, event := range engine.state.Snapshot().Events {
		if event.Kind == "xdr.sbc_correlated" {
			found = true
		}
	}
	if !found {
		t.Fatal("corroboration state event was not published")
	}
	if events := fusion.DrainCorroborations(); len(events) != 0 {
		t.Fatalf("drain left %d events queued", len(events))
	}
}

func TestSBCCorroborationEvidenceFailureIsHonest(t *testing.T) {
	dir := t.TempDir()
	ledger := newTestLedger(t, dir, 1<<20)
	if err := ledger.ApplyPolicy(EvidenceFabricSettings{MaxBytes: 8 << 10}); err != nil {
		t.Fatalf("apply evidence policy: %v", err)
	}
	var exhausted bool
	for attempt := 0; attempt < 4000; attempt++ {
		_, err := ledger.Append(EvidenceRecord{Severity: "info", Kind: "test.fill", Source: "test", Message: "filler record", Target: "fill"})
		if err != nil {
			exhausted = true
			break
		}
	}
	if !exhausted {
		t.Skip("the evidence budget was not reached within the attempt bound on this host")
	}
	state := NewState("test", defaultConfig())
	if err := state.AttachEvidenceLedger(ledger); err != nil {
		t.Fatalf("attach full evidence ledger: %v", err)
	}
	engine := &XDREngine{
		state:         state,
		gief:          NewGIEFEngine(),
		sbc:           NewSBCFusionEngine(),
		platformCaps:  PlatformCapabilities{HasBPFLSM: true, HasCgroupV2: true, DetectedAt: time.Now().UTC()},
		degradeCauses: map[string]string{},
	}
	base := sbcTestBaseTime()
	engine.attachGIEFEnvelope(XDRIncident{
		ID: "fail-seed", Time: base, Severity: "critical", Executable: "/opt/sbc/failing",
		RuleIDs: []string{"XDR.CREDENTIAL_READ_BLOCKED"}, Categories: []string{"credential"},
		Decision: "alert", Action: "none",
	})
	engine.attachGIEFEnvelope(XDRIncident{
		ID: "fail-second", Time: base.Add(time.Minute), Severity: "warning", Executable: "/opt/sbc/failing",
		RuleIDs: []string{"XDR.THREAT_INTEL_C2"}, Categories: []string{"c2"},
		Decision: "alert", Action: "none",
	})
	recorded, err := engine.recordSBCCorroborations(base.Add(2 * time.Minute))
	if err == nil {
		t.Fatal("a failed evidence commit was reported as success")
	}
	if recorded != 0 {
		t.Fatalf("recorded %d corroborations without evidence, want 0", recorded)
	}
	honest := false
	for _, event := range state.Snapshot().Events {
		if event.Kind == "xdr.sbc_correlated_evidence_failed" {
			honest = true
		}
		if event.Kind == "xdr.sbc_correlated" {
			t.Fatal("an unbacked corroboration was published as an evidence-first event")
		}
	}
	if !honest {
		t.Fatal("evidence failure did not produce an honest state event")
	}
}
