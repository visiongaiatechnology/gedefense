// STATUS: DIAMANT VGT SUPREME
package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestEvidenceBudgetExhaustionIsNotAnIntegrityFailure covers the defect behind
// "XDR is degraded: mandatory evidence ledger is unavailable".
//
// The ledger's size budget and its integrity were the same condition in the code:
// reaching the budget set integrityErr, which quarantines the ledger permanently and
// made State.RecordEvidence report XDR as degraded. A full ledger is not a damaged one.
// The second half of the defect was worse than the first - integrityErr is sticky, so
// raising the administrable budget afterwards could not clear it, which made the
// operator's own retention control unusable at the moment it was needed.
func TestEvidenceBudgetExhaustionIsNotAnIntegrityFailure(t *testing.T) {
	dir := t.TempDir()
	ledger := newTestLedger(t, dir, 1<<20)
	// The administrable policy takes precedence over the constructor argument, and the
	// compiled-in default is 64 MiB. A 64 KiB budget is applied explicitly so the test
	// fills the ledger in seconds: every append fsyncs, so a realistic budget would make
	// this a minutes-long test for no additional coverage.
	if err := ledger.ApplyPolicy(EvidenceFabricSettings{MaxBytes: 64 << 10}); err != nil {
		t.Fatal(err)
	}

	var exhausted error
	for attempt := 0; attempt < 2000; attempt++ {
		_, err := ledger.Append(EvidenceRecord{
			Severity: "info", Kind: "test.fill", Source: "test",
			Message: "filler record", Target: "fill",
		})
		if err != nil {
			exhausted = err
			break
		}
	}
	if exhausted == nil {
		t.Skip("the budget was not reached within the attempt bound on this host")
	}

	// The refusal must be identifiable as capacity, not as corruption.
	if !errors.Is(exhausted, errEvidenceBudgetExhausted) {
		t.Fatalf("budget refusal is not the capacity sentinel: %v", exhausted)
	}

	// The chain must still verify. If a full ledger reported itself corrupt, Verify
	// would refuse and every consumer downstream would believe the evidence is damaged.
	if err := ledger.Verify(); err != nil {
		t.Fatalf("a full ledger failed verification: %v", err)
	}
	status := ledger.Status()
	if !status.Healthy {
		t.Fatal("a full ledger reported itself unhealthy")
	}
	if !status.Full {
		t.Fatal("a full ledger did not report the capacity condition")
	}
	if status.Error != "" {
		t.Fatalf("a full ledger carried an integrity error: %q", status.Error)
	}

	// Raising the budget must resume writes. This is the property that was impossible
	// before: the ledger was quarantined by the budget alone.
	raised := newTestLedger(t, dir, 8<<20)
	if err := raised.ApplyPolicy(EvidenceFabricSettings{MaxBytes: 8 << 20}); err != nil {
		t.Fatal(err)
	}
	if _, err := raised.Append(EvidenceRecord{
		Severity: "info", Kind: "test.after.raise", Source: "test",
		Message: "record after the retention budget was raised", Target: "raise",
	}); err != nil {
		t.Fatalf("raising the retention budget did not resume writes: %v", err)
	}
}

// TestEvidenceIntegrityFailureStillDegrades is the counter-case. The fix must not turn
// a genuinely damaged chain into a capacity warning: tampering has to keep degrading the
// system, otherwise the separation would have removed the alarm instead of the noise.
func TestEvidenceIntegrityFailureStillDegrades(t *testing.T) {
	dir := t.TempDir()
	ledger := newTestLedger(t, dir, 64<<20)
	if _, err := ledger.Append(EvidenceRecord{
		Severity: "info", Kind: "test.chain", Source: "test",
		Message: "first record", Target: "chain",
	}); err != nil {
		t.Fatal(err)
	}

	// Rewrite the ledger behind the object's back, which is exactly what tampering looks
	// like to verifyUnchangedLocked.
	path := filepath.Join(dir, "evidence.jsonl")
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(content, []byte("{\"tampered\":true}\n")...), 0o600); err != nil {
		t.Fatal(err)
	}

	_, appendErr := ledger.Append(EvidenceRecord{
		Severity: "info", Kind: "test.chain2", Source: "test",
		Message: "record after tampering", Target: "chain",
	})
	if appendErr == nil {
		t.Fatal("an append succeeded after the chain was modified")
	}
	if errors.Is(appendErr, errEvidenceBudgetExhausted) {
		t.Fatal("tampering was reported as a capacity condition")
	}
	if ledger.Status().Healthy {
		t.Fatal("a tampered ledger reported itself healthy")
	}
	// And the quarantine is now correct: the object refuses further writes.
	if _, err := ledger.Append(EvidenceRecord{Severity: "info", Kind: "test.chain3", Message: "after quarantine"}); err == nil {
		t.Fatal("a quarantined ledger accepted a write")
	}
}

// newTestLedger builds a ledger in dir with its own signing key.
func newTestLedger(t *testing.T, dir string, maxBytes int64) *EvidenceLedger {
	t.Helper()
	// The ledger generates and persists the signing key when the file is absent. A key
	// file that exists but is empty is rejected, so it must not be pre-created here.
	keyPath := filepath.Join(dir, "evidence.ed25519")
	ledger, err := NewEvidenceLedger(filepath.Join(dir, "evidence.jsonl"), keyPath, "", "test-node", maxBytes)
	if err != nil {
		t.Fatal(err)
	}
	return ledger
}

// TestRaisedBudgetSurvivesARestart covers the boot loop the operator was caught in.
//
// Append consulted the administrable policy while Verify consulted the constructor value
// alone. Raising the budget therefore worked until the next restart, at which point the
// ledger the operator had been told to enlarge was rejected by the process that had been
// told to accept it - with the service refusing to start. The two paths now read one
// budget, and this proves the ledger a raised policy produced is still accepted after a
// restart reconstructs the ledger from configuration.
// TestTheConstructorBudgetIsTheEnforcedBudget covers the silent stop.
//
// main.go constructs the ledger with the administrable budget it read from the settings
// document. The constructor used to seed its policy with the compiled-in default instead,
// and the append path prefers the policy, so the raised budget was discarded the moment the
// service started: administration reported 256 MiB, the ledger enforced 64 MiB, and when the
// file reached it every append failed - while Status() still reported the ledger healthy.
// The platform stopped recording evidence and said nothing about why.
func TestTheConstructorBudgetIsTheEnforcedBudget(t *testing.T) {
	dir := t.TempDir()
	const raised = int64(256 << 20)
	ledger := newTestLedger(t, dir, raised)

	if got := ledger.Status().MaxBytes; got != raised {
		t.Fatalf("the ledger enforces %d bytes, but it was constructed with %d", got, raised)
	}
	if got := ledger.Policy().MaxBytes; got != raised {
		t.Fatalf("the effective budget and the reported policy disagree: policy=%d, enforced=%d",
			got, ledger.Status().MaxBytes)
	}

	// A budget that is administratively lowered after construction still takes effect: the
	// construction seed is a starting point, not a floor the operator cannot go below.
	lowered := EvidenceFabricSettings{MaxBytes: 2 << 20}
	if err := ledger.ApplyPolicy(lowered); err != nil {
		t.Fatal(err)
	}
	if got := ledger.Status().MaxBytes; got != lowered.MaxBytes {
		t.Fatalf("a lowered budget was ignored: enforced=%d, applied=%d", got, lowered.MaxBytes)
	}
}

func TestRaisedBudgetSurvivesARestart(t *testing.T) {
	dir := t.TempDir()

	// The ledger is constructed with the small compiled-in budget, exactly as a service
	// that has not yet read its settings would build it.
	ledger := newTestLedger(t, dir, 1<<20)
	if err := ledger.ApplyPolicy(EvidenceFabricSettings{MaxBytes: 8 << 20}); err != nil {
		t.Fatal(err)
	}

	// Write past the constructor value but well inside the administrable one.
	//
	// Each record carries the largest payload its field bounds allow. That is not padding
	// for its own sake: the ledger fsyncs once per append, so the cost of reaching a given
	// size is the number of records, not the number of bytes. Filling each record to its
	// bound took this test from about forty seconds to under three, which matters because
	// the gate runs the suite ten times over.
	message := strings.Repeat("budget", 4096/6)
	target := strings.Repeat("b", 1024)
	for attempt := 0; attempt < 4000; attempt++ {
		if ledger.Status().StoredBytes > 1200<<10 {
			break
		}
		if _, err := ledger.Append(EvidenceRecord{
			Severity: "info", Kind: "test.bulk", Source: "test",
			Message: message, Target: target,
		}); err != nil {
			t.Fatalf("append refused inside the administrable budget after %d bytes: %v", ledger.Status().StoredBytes, err)
		}
	}
	if ledger.Status().StoredBytes <= 1<<20 {
		t.Fatalf("the fixture never grew past the constructor value: %d bytes", ledger.Status().StoredBytes)
	}

	// Now the restart. The ledger is reconstructed with the same small constructor value,
	// because that is what configuration carries; the administrable policy is what raises
	// it afterwards.
	restarted := newTestLedger(t, dir, 1<<20)
	status := restarted.Status()
	if status.StoredBytes <= 1<<20 {
		t.Fatalf("the fixture did not grow past the constructor value: %d bytes", status.StoredBytes)
	}

	// The default policy is larger than the constructor value here, which is exactly the
	// situation that used to fail: the ledger on disk is bigger than the constructor
	// budget and only the policy can authorise it.
	if err := restarted.Verify(); err != nil {
		t.Fatalf("a ledger written under a raised budget failed verification after a restart: %v", err)
	}
	if err := restarted.ApplyPolicy(EvidenceFabricSettings{MaxBytes: 8 << 20}); err != nil {
		t.Fatal(err)
	}
	if err := restarted.Verify(); err != nil {
		t.Fatalf("verification failed once the raised budget was applied: %v", err)
	}
}
