// STATUS: DIAMANT VGT SUPREME
package main

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// The contracts in this file describe one property: verification has to be affordable without
// becoming weaker. Startup verifies an authenticated checkpoint and a bounded window; the
// history is covered by incremental passes that verify every record exactly once; and a forged
// watermark may not be able to skip any of it.

func appendEvidenceRecords(t *testing.T, ledger *EvidenceLedger, count int) {
	t.Helper()
	for i := 0; i < count; i++ {
		if _, err := ledger.Append(EvidenceRecord{
			Time:     time.Date(2026, 10, 9, 12, 0, 0, i, time.UTC),
			Severity: "high", Kind: "test.verification", Source: "test",
			Message: "verification fixture record",
		}); err != nil {
			t.Fatalf("append %d of %d: %v", i+1, count, err)
		}
	}
}

func evidenceLines(t *testing.T, path string) []string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	trimmed := strings.TrimRight(string(raw), "\n")
	if trimmed == "" {
		return nil
	}
	return strings.Split(trimmed, "\n")
}

func writeEvidenceLines(t *testing.T, path string, lines []string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func reloadEvidence(t *testing.T, path string, maxBytes int64) (*EvidenceLedger, error) {
	t.Helper()
	dir := filepath.Dir(path)
	return NewEvidenceLedger(path, filepath.Join(dir, "evidence.ed25519"), filepath.Join(dir, "storage.key"), "test-node", maxBytes)
}

// expectRejectedAtStartup asserts that a construction refuses the ledger, either by failing
// outright or by recording an integrity error the way the running service does.
func expectRejectedAtStartup(t *testing.T, path string, maxBytes int64) {
	t.Helper()
	ledger, err := reloadEvidence(t, path, maxBytes)
	if err != nil {
		return
	}
	if ledger.Healthy() == nil {
		t.Fatal("a damaged ledger was reported healthy at construction")
	}
}

func damageRecord(t *testing.T, lines []string, index int) []string {
	t.Helper()
	record := []byte(lines[index])
	if len(record) == 0 {
		t.Fatalf("record %d is empty", index)
	}
	record[len(record)-1] ^= 0x01
	lines[index] = string(record)
	return lines
}

// TestTheBoundedStartupCheckCoversTheSealedTail pins what the bounded check does detect. It is
// the part of the chain whose integrity decides whether the platform may start at all.
func TestTheBoundedStartupCheckCoversTheSealedTail(t *testing.T) {
	t.Run("truncated tail", func(t *testing.T) {
		ledger, path := evidenceFixture(t)
		appendEvidenceRecords(t, ledger, 4)
		lines := evidenceLines(t, path)
		writeEvidenceLines(t, path, lines[:len(lines)-1])
		expectRejectedAtStartup(t, path, 4<<20)
	})
	t.Run("damaged tail record", func(t *testing.T) {
		ledger, path := evidenceFixture(t)
		appendEvidenceRecords(t, ledger, 4)
		lines := evidenceLines(t, path)
		writeEvidenceLines(t, path, damageRecord(t, lines, len(lines)-1))
		expectRejectedAtStartup(t, path, 4<<20)
	})
	t.Run("one foreign record behind the checkpoint is removed", func(t *testing.T) {
		ledger, path := evidenceFixture(t)
		appendEvidenceRecords(t, ledger, 4)
		lines := evidenceLines(t, path)
		writeEvidenceLines(t, path, append(lines, lines[len(lines)-1]))
		recovered, err := reloadEvidence(t, path, 4<<20)
		if err != nil {
			t.Fatal(err)
		}
		if err := recovered.Healthy(); err != nil {
			t.Fatalf("a single foreign record was not removed: %v", err)
		}
		if status := recovered.Status(); status.Records != 4 {
			t.Fatalf("records=%d, want the four sealed records", status.Records)
		}
		if err := recovered.Verify(); err != nil {
			t.Fatalf("the repaired chain does not verify: %v", err)
		}
	})
	t.Run("several records behind the checkpoint are refused", func(t *testing.T) {
		ledger, path := evidenceFixture(t)
		appendEvidenceRecords(t, ledger, 4)
		lines := evidenceLines(t, path)
		writeEvidenceLines(t, path, append(lines, lines[len(lines)-1], lines[len(lines)-1]))
		expectRejectedAtStartup(t, path, 4<<20)
	})
	t.Run("replaced checkpoint", func(t *testing.T) {
		ledger, path := evidenceFixture(t)
		appendEvidenceRecords(t, ledger, 4)
		if err := os.WriteFile(path+".head", []byte("{\"version\":1,\"sequence\":4,\"head_hash\":\"00\"}\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		expectRejectedAtStartup(t, path, 4<<20)
	})
}

// TestTheStartupCheckIsBoundedAndDetectionIsDeferred is the trade-off, stated as a test.
//
// The whole history is no longer read before the service may start: a 260 MB ledger took more
// than fourteen minutes and the platform could not come up at all. What is given up at startup
// is the detection of damage *outside* the sealed window - and only the timing of it, because
// the full and the incremental passes still refuse that ledger.
func TestTheStartupCheckIsBoundedAndDetectionIsDeferred(t *testing.T) {
	ledger, path := evidenceFixture(t)
	total := evidenceRecentLimit + 64
	appendEvidenceRecords(t, ledger, total)

	lines := evidenceLines(t, path)
	if len(lines) != total {
		t.Fatalf("fixture holds %d records, want %d", len(lines), total)
	}
	writeEvidenceLines(t, path, damageRecord(t, lines, 0))

	reloaded, err := reloadEvidence(t, path, 16<<20)
	if err != nil {
		t.Fatal(err)
	}
	if err := reloaded.Healthy(); err != nil {
		t.Fatalf("the startup check read the whole history instead of the sealed window: %v", err)
	}
	if scope := reloaded.Status().VerifyScope; scope != "tail" {
		t.Fatalf("scope=%q, want the bounded window to be reported as such", scope)
	}
	// Detection is deferred, not lost.
	if err := reloaded.Verify(); err == nil {
		t.Fatal("the full verification did not detect the damaged record")
	}
}

// TestTheIncrementalPassCoversTheHistoryInBoundedChunks proves the mechanism that replaces the
// full walk on the timer: every record is verified exactly once, in order, a chunk at a time,
// and the status says how far it has got.
func TestTheIncrementalPassCoversTheHistoryInBoundedChunks(t *testing.T) {
	ledger, path := evidenceFixture(t)
	total := evidenceRecentLimit + 64
	appendEvidenceRecords(t, ledger, total)

	// The fixture has more records than the sealed window covers, so the startup check reports
	// the bounded scope and leaves the history to the incremental passes.
	reloaded, err := reloadEvidence(t, path, 16<<20)
	if err != nil {
		t.Fatal(err)
	}
	if err := reloaded.Healthy(); err != nil {
		t.Fatal(err)
	}
	if scope := reloaded.Status().VerifyScope; scope != "tail" {
		t.Fatalf("startup scope=%q, want the bounded window", scope)
	}
	reloaded.incrementalChunk = uint64(total) / 2

	if err := reloaded.VerifyIncremental(); err != nil {
		t.Fatalf("first pass: %v", err)
	}
	half := strconv.Itoa(total / 2)
	if scope := reloaded.Status().VerifyScope; scope != "partial:"+half+"/"+strconv.Itoa(total) {
		t.Fatalf("after the first pass scope=%q", scope)
	}
	if err := reloaded.VerifyIncremental(); err != nil {
		t.Fatalf("second pass: %v", err)
	}
	status := reloaded.Status()
	if status.VerifyScope != "full" {
		t.Fatalf("after the last pass scope=%q", status.VerifyScope)
	}
	if status.FullVerifiedAt == nil {
		t.Fatal("a completed coverage did not record when it happened")
	}
	if _, err := os.Stat(path + ".verified"); err != nil {
		t.Fatalf("no authenticated watermark was written: %v", err)
	}

	// Nothing new to verify: the pass is a no-op and keeps the coverage complete.
	if err := reloaded.VerifyIncremental(); err != nil {
		t.Fatalf("idle pass: %v", err)
	}
	if scope := reloaded.Status().VerifyScope; scope != "full" {
		t.Fatalf("an idle pass downgraded the scope to %q", scope)
	}
}

// TestTheIncrementalPassDetectsDamageInTheHistory is the other half of the trade-off: the
// records the startup window did not read are still verified, and damage in them is refused.
func TestTheIncrementalPassDetectsDamageInTheHistory(t *testing.T) {
	ledger, path := evidenceFixture(t)
	total := evidenceRecentLimit + 64
	appendEvidenceRecords(t, ledger, total)

	lines := evidenceLines(t, path)
	writeEvidenceLines(t, path, damageRecord(t, lines, 0))

	reloaded, err := reloadEvidence(t, path, 16<<20)
	if err != nil {
		t.Fatal(err)
	}
	if err := reloaded.Healthy(); err != nil {
		t.Fatalf("the bounded start refused a ledger it had not read: %v", err)
	}
	if err := reloaded.VerifyIncremental(); err == nil {
		t.Fatal("the incremental pass did not detect the damaged record")
	}
	if err := reloaded.Healthy(); err == nil {
		t.Fatal("a failed verification left the ledger healthy")
	}
}

// TestAnInterruptedAppendIsRecovered covers the one inconsistent state the ledger can
// legitimately be in: the append path writes the record and then the checkpoint, so a crash in
// between leaves the file exactly one record ahead of the checkpoint that would seal it.
//
// Both ways of ignoring that are wrong. Refusing to start takes the platform down because a
// forensic log was interrupted; keeping the orphan corrupts the chain at the next append,
// because the next record links to the sealed head and not to the orphan. A well-formed orphan
// is therefore verified and sealed, and an orphan that does not verify is removed.
func TestAnInterruptedAppendIsRecovered(t *testing.T) {
	crashState := func(t *testing.T) (string, string) {
		t.Helper()
		ledger, path := evidenceFixture(t)
		appendEvidenceRecords(t, ledger, 3)
		sealed, err := os.ReadFile(path + ".head")
		if err != nil {
			t.Fatal(err)
		}
		appendEvidenceRecords(t, ledger, 1)
		// Restore the checkpoint from before the fourth record: the record is on disk, the seal
		// that would cover it is not. This is exactly what an interrupted append leaves behind.
		if err := os.WriteFile(path+".head", sealed, 0o600); err != nil {
			t.Fatal(err)
		}
		return path, string(sealed)
	}

	t.Run("a well-formed orphan is sealed", func(t *testing.T) {
		path, _ := crashState(t)
		recovered, err := reloadEvidence(t, path, 4<<20)
		if err != nil {
			t.Fatalf("the interrupted append stopped the service: %v", err)
		}
		if err := recovered.Healthy(); err != nil {
			t.Fatalf("the interrupted append was not recovered: %v", err)
		}
		if status := recovered.Status(); status.Records != 4 {
			t.Fatalf("records=%d, want the orphan to be adopted", status.Records)
		}
		// The repaired chain has to verify end to end, which is what proves the orphan was
		// sealed rather than silently tolerated.
		if err := recovered.Verify(); err != nil {
			t.Fatalf("the repaired chain does not verify: %v", err)
		}
	})

	t.Run("a damaged orphan is removed", func(t *testing.T) {
		path, _ := crashState(t)
		lines := evidenceLines(t, path)
		writeEvidenceLines(t, path, damageRecord(t, lines, len(lines)-1))
		recovered, err := reloadEvidence(t, path, 4<<20)
		if err != nil {
			t.Fatalf("a damaged orphan stopped the service: %v", err)
		}
		if err := recovered.Healthy(); err != nil {
			t.Fatalf("a damaged orphan was not removed: %v", err)
		}
		if status := recovered.Status(); status.Records != 3 {
			t.Fatalf("records=%d, want the damaged orphan to be dropped", status.Records)
		}
		if err := recovered.Verify(); err != nil {
			t.Fatalf("the repaired chain does not verify: %v", err)
		}
	})

	t.Run("the chain keeps working after the repair", func(t *testing.T) {
		path, _ := crashState(t)
		recovered, err := reloadEvidence(t, path, 4<<20)
		if err != nil {
			t.Fatal(err)
		}
		appendEvidenceRecords(t, recovered, 2)
		if err := recovered.Verify(); err != nil {
			t.Fatalf("appending after a repair broke the chain: %v", err)
		}
		if status := recovered.Status(); status.Records != 6 {
			t.Fatalf("records=%d, want six after the repair and two appends", status.Records)
		}
	})
}

// TestAForgedWatermarkCannotSkipVerification covers the obvious attack on an incremental
// verifier: move the watermark forward so the walk starts after the damage.
//
// The watermark is written through the node storage cipher, so a forgery is not readable as a
// watermark at all, and the pass falls back to verifying from the beginning of the chain.
func TestAForgedWatermarkCannotSkipVerification(t *testing.T) {
	ledger, path := evidenceFixture(t)
	total := evidenceRecentLimit + 64
	appendEvidenceRecords(t, ledger, total)

	lines := evidenceLines(t, path)
	writeEvidenceLines(t, path, damageRecord(t, lines, 0))
	// A plaintext forgery that claims the whole chain has already been verified.
	forged := []byte("{\"version\":1,\"sequence\":" + strconv.Itoa(total) + ",\"head_hash\":\"deadbeef\"}\n")
	if err := os.WriteFile(path+".verified", forged, 0o600); err != nil {
		t.Fatal(err)
	}

	reloaded, err := reloadEvidence(t, path, 16<<20)
	if err != nil {
		t.Fatal(err)
	}
	if err := reloaded.VerifyIncremental(); err == nil {
		t.Fatal("a forged watermark skipped the verification of the history")
	}
	if err := reloaded.Healthy(); err == nil {
		t.Fatal("a forged watermark left the ledger healthy after a failed walk")
	}
}
