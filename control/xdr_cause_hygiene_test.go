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

// TestARepeatedlyFailedVerificationSetsTheCause is the counter-case: the clearing rests on an
// observation, not on optimism - and the degrading rests on a repetition, not on a hiccup.
func TestARepeatedlyFailedVerificationSetsTheCause(t *testing.T) {
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

	// The policy: the first failed check is recorded in the journal and does not pause anything;
	// only a repeated failure is a condition. One hiccup must not become a visible fail-safe.
	engine.verifyForensicArtefacts(context.Background())
	if degraded, reason := engine.degradedState(); degraded {
		t.Fatalf("a single failed check paused the platform: %s", reason)
	}

	engine.verifyForensicArtefacts(context.Background())

	degraded, reason := engine.degradedState()
	if !degraded {
		t.Fatal("a repeatedly failing incident chain did not degrade XDR")
	}
	if !strings.Contains(reason, "incident log") {
		t.Fatalf("the degradation does not name the incident log: %s", reason)
	}
}

// TestAHiccupThatRecoversNeverPausesThePlatform is the case that kept biting: a verification that
// fails once and succeeds on the next pass must leave the platform completely untouched. The old
// behaviour degraded on the first failure and needed the calm of five minutes afterwards, so a
// momentary hiccup was visible to the operator as a fail-safe.
func TestAHiccupThatRecoversNeverPausesThePlatform(t *testing.T) {
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

	cfg := defaultConfig()
	state := NewState("test-node", cfg)
	ledger, _ := evidenceFixture(t)
	if err := state.AttachEvidenceLedger(ledger); err != nil {
		t.Fatal(err)
	}
	engine := &XDREngine{cfg: cfg, state: state, logger: logger, degradeCauses: map[string]string{}}

	// A first failed check, injected the way a momentary read hiccup would arrive: the counter
	// rises without the platform being paused.
	if count, repeated := engine.claimRepeatedFailure("incident_log"); repeated || count != 1 {
		t.Fatalf("the first failure was treated as a condition: count=%d repeated=%v", count, repeated)
	}
	engine.verifyForensicArtefacts(context.Background())
	if degraded, reason := engine.degradedState(); degraded {
		t.Fatalf("a hiccup paused the platform: %s", reason)
	}

	// And the counter is gone with the next successful pass, so an occasional failure can never
	// accumulate into a degradation.
	engine.mu.RLock()
	remaining := len(engine.forensicFailures)
	engine.mu.RUnlock()
	if remaining != 0 {
		t.Fatalf("the failure counter survived a successful pass: %d entries", remaining)
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
