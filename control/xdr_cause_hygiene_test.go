// STATUS: DIAMANT VGT SUPREME
package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestASuccessfulVerificationClearsTheCauseItReplaced covers the autonomy gap.
//
// A cause was set when verification failed and cleared only by a rotation or an operator
// recovery - never by a verification that succeeded. One transient failure therefore kept XDR
// degraded, and a degraded XDR blocks every promotion and pauses the automatic response, until
// somebody restarted the control plane. That happened twice on the production host: the state was
// cleared by a restart instead of by the platform noticing that the problem had gone.
func TestASuccessfulVerificationClearsTheCauseItReplaced(t *testing.T) {
	dir := t.TempDir()
	logger, err := NewIncidentLogger(filepath.Join(dir, "incidents.jsonl"), filepath.Join(dir, "xdr.key"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := logger.Append(XDRIncident{
		ID: randomID(), Time: time.Now().UTC(), Severity: "warning", Score: 30,
		RuleIDs: []string{"TEST"}, Categories: []string{"test"}, Summary: "fixture",
		Decision: "alert", Action: "none", Outcome: "observed",
	}); err != nil {
		t.Fatal(err)
	}

	cfg := defaultConfig()
	state := NewState("test-node", cfg)
	ledger, _ := evidenceFixture(t)
	if err := state.AttachEvidenceLedger(ledger); err != nil {
		t.Fatal(err)
	}
	engine := &XDREngine{cfg: cfg, state: state, logger: logger, degradeCauses: map[string]string{}}

	// The state a transient failure leaves behind.
	engine.markDegradedCause("incident_log", "incident log verification failed: transient")
	engine.markDegradedCause("evidence", "mandatory evidence ledger unavailable: transient")
	if degraded, _ := engine.degradedState(); !degraded {
		t.Fatal("the fixture did not establish a degraded state")
	}

	engine.verifyForensicArtefacts(context.Background())

	if degraded, reason := engine.degradedState(); degraded {
		t.Fatalf("a successful verification left XDR degraded: %s", reason)
	}
}

// TestAFailedVerificationStillSetsTheCause is the counter-case: the clearing must rest on an
// observation, not on optimism.
func TestAFailedVerificationStillSetsTheCause(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "incidents.jsonl")
	keyPath := filepath.Join(dir, "xdr.key")
	logger, err := NewIncidentLogger(logPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := logger.Append(XDRIncident{
		ID: randomID(), Time: time.Now().UTC(), Severity: "warning", Score: 30,
		RuleIDs: []string{"TEST"}, Categories: []string{"test"}, Summary: "fixture",
		Decision: "alert", Action: "none", Outcome: "observed",
	}); err != nil {
		t.Fatal(err)
	}
	// Damage the authenticated chain, which is what a verification has to notice.
	raw, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(logPath, []byte(strings.Replace(string(raw), `"score":30`, `"score":31`, 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	damaged, err := NewIncidentLogger(logPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if damaged.Healthy() == nil {
		t.Fatal("the fixture did not damage the chain")
	}

	cfg := defaultConfig()
	state := NewState("test-node", cfg)
	ledger, _ := evidenceFixture(t)
	if err := state.AttachEvidenceLedger(ledger); err != nil {
		t.Fatal(err)
	}
	engine := &XDREngine{cfg: cfg, state: state, logger: damaged, degradeCauses: map[string]string{}}

	engine.verifyForensicArtefacts(context.Background())

	degraded, reason := engine.degradedState()
	if !degraded {
		t.Fatal("a damaged incident chain did not degrade XDR")
	}
	if !strings.Contains(reason, "incident log") {
		t.Fatalf("the degradation does not name the incident log: %s", reason)
	}
}

// TestTheEvidenceCauseFollowsTheLedgerHealth pins the second half: a healthy evidence ledger
// clears the cause that was recorded while it was unavailable.
func TestTheEvidenceCauseFollowsTheLedgerHealth(t *testing.T) {
	cfg := defaultConfig()
	state := NewState("test-node", cfg)
	ledger, _ := evidenceFixture(t)
	if err := state.AttachEvidenceLedger(ledger); err != nil {
		t.Fatal(err)
	}
	engine := &XDREngine{cfg: cfg, state: state, degradeCauses: map[string]string{}}
	engine.markDegradedCause("evidence", "mandatory evidence ledger unavailable")

	engine.verifyForensicArtefacts(context.Background())
	if degraded, reason := engine.degradedState(); degraded {
		t.Fatalf("a healthy evidence ledger did not clear its cause: %s", reason)
	}
}
