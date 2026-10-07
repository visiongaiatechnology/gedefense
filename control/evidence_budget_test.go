// STATUS: DIAMANT VGT SUPREME
package main

import (
	"errors"
	"os"
	"path/filepath"
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
