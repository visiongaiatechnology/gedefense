// STATUS: DIAMANT VGT SUPREME

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func evidenceFixture(t *testing.T) (*EvidenceLedger, string) {
	t.Helper()
	dir := t.TempDir()
	storageKey := filepath.Join(dir, "storage.key")
	if err := os.WriteFile(storageKey, make([]byte, 32), 0o600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "evidence.jsonl")
	ledger, err := NewEvidenceLedger(path, filepath.Join(dir, "evidence.ed25519"), storageKey, "test-node", 4<<20)
	if err != nil {
		t.Fatal(err)
	}
	return ledger, path
}

func TestEvidenceLedgerEncryptsSignsAndReloads(t *testing.T) {
	ledger, path := evidenceFixture(t)
	record, err := ledger.Append(EvidenceRecord{
		Time:     time.Date(2026, 7, 28, 18, 0, 0, 0, time.UTC),
		Severity: "high", Kind: "policy.changed", Source: "operator",
		Message: "signed policy generation activated", Target: "generation:2",
	})
	if err != nil {
		t.Fatal(err)
	}
	if record.Sequence != 1 || record.Hash == "" || record.Signature == "" {
		t.Fatalf("incomplete evidence record: %+v", record)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "signed policy generation activated") {
		t.Fatal("evidence plaintext leaked to disk")
	}
	reloaded, err := NewEvidenceLedger(path, ledger.keyPath, filepath.Join(filepath.Dir(path), "storage.key"), "test-node", 4<<20)
	if err != nil {
		t.Fatal(err)
	}
	if err := reloaded.Verify(); err != nil {
		t.Fatal(err)
	}
	status := reloaded.Status()
	if !status.Healthy || status.Records != 1 || status.HeadHash != record.Hash {
		t.Fatalf("unexpected evidence status: %+v", status)
	}
}

func TestEvidenceLedgerDetectsTamperingAndTruncation(t *testing.T) {
	ledger, path := evidenceFixture(t)
	for _, kind := range []string{"one", "two"} {
		if _, err := ledger.Append(EvidenceRecord{Severity: "info", Kind: kind, Source: "test", Message: "event"}); err != nil {
			t.Fatal(err)
		}
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lastNewline := strings.LastIndex(string(data[:len(data)-1]), "\n")
	if lastNewline < 0 {
		t.Fatal("expected multiple records")
	}
	if err := os.WriteFile(path, data[:lastNewline+1], 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ledger.Verify(); err == nil {
		t.Fatal("live ledger accepted external truncation")
	}
	reloaded, err := NewEvidenceLedger(path, ledger.keyPath, filepath.Join(filepath.Dir(path), "storage.key"), "test-node", 4<<20)
	if err != nil {
		t.Fatal(err)
	}
	if reloaded.Healthy() == nil {
		t.Fatal("reloaded ledger accepted a stale head checkpoint")
	}
}

func TestEvidenceLedgerRefusesSymlinkAndOversizedFields(t *testing.T) {
	ledger, path := evidenceFixture(t)
	if _, err := ledger.Append(EvidenceRecord{
		Severity: "info", Kind: "oversized", Source: "test", Message: strings.Repeat("x", 4097),
	}); err == nil {
		t.Fatal("oversized evidence field accepted")
	}
	link := filepath.Join(filepath.Dir(path), "linked.jsonl")
	if err := os.Symlink(path, link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if _, err := NewEvidenceLedger(link, filepath.Join(filepath.Dir(path), "other.key"), filepath.Join(filepath.Dir(path), "storage.key"), "test-node", 4<<20); err == nil {
		t.Fatal("symlink evidence ledger accepted")
	}
}

// TestVerifyIncrementalIsConsistentUnderConcurrentAppends is the regression for FIND-017. The
// incremental pass used to release the ledger lock, read the checkpoint and the watermark, walk
// the chain, and then write the watermark - a window in which Append could move the files. With
// a chunked pass and a writer appending records in parallel, the pass must neither report a
// false integrity failure nor quarantine a perfectly valid chain (run with -race).
func TestVerifyIncrementalIsConsistentUnderConcurrentAppends(t *testing.T) {
	dir := t.TempDir()
	storageKey := filepath.Join(dir, "storage.key")
	if err := os.WriteFile(storageKey, make([]byte, 32), 0o600); err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(dir, "evidence.ed25519")
	path := filepath.Join(dir, "evidence.jsonl")
	initial, err := NewEvidenceLedger(path, keyPath, storageKey, "test-node", 4<<20)
	if err != nil {
		t.Fatal(err)
	}
	appendEvidenceRecords(t, initial, 16)
	ledger, err := NewEvidenceLedger(path, keyPath, storageKey, "test-node", 4<<20)
	if err != nil {
		t.Fatal(err)
	}
	ledger.incrementalChunk = 5

	const appendedRecords = 64
	var wg sync.WaitGroup
	errs := make(chan error, 2)
	stop := make(chan struct{})
	appenderDone := make(chan struct{})
	wg.Add(2)
	go func() {
		defer wg.Done()
		defer close(appenderDone)
		for i := 0; i < appendedRecords; i++ {
			if _, err := ledger.Append(EvidenceRecord{
				Severity: "info", Kind: "race.append", Source: "test",
				Message: fmt.Sprintf("concurrent append %d", i),
			}); err != nil {
				errs <- fmt.Errorf("concurrent append: %w", err)
				return
			}
		}
	}()
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			if err := ledger.VerifyIncremental(); err != nil {
				errs <- fmt.Errorf("incremental verification during append: %w", err)
				return
			}
		}
	}()
	<-appenderDone
	close(stop)
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("append and verification raced into a false failure: %v", err)
	}
	if err := ledger.Healthy(); err != nil {
		t.Fatalf("a valid chain was quarantined by a concurrent append: %v", err)
	}
	// Catch the chunked coverage up and prove the whole chain still verifies end to end.
	for i := 0; i < 1000; i++ {
		if err := ledger.VerifyIncremental(); err != nil {
			t.Fatalf("catching-up pass %d: %v", i, err)
		}
		if ledger.Status().VerifyScope == "full" {
			break
		}
	}
	if scope := ledger.Status().VerifyScope; scope != "full" {
		t.Fatalf("scope after catching up: %q", scope)
	}
	if err := ledger.Verify(); err != nil {
		t.Fatalf("the chain written under concurrent verification does not verify: %v", err)
	}
}

// TestVerifyIncrementalOnAnEmptyLedgerIsNotAnIntegrityFailure pins the normal state between
// construction and the first append: there is no checkpoint file yet, and the incremental pass
// must treat that as "nothing to verify" rather than as a missing, hence damaged, seal.
func TestVerifyIncrementalOnAnEmptyLedgerIsNotAnIntegrityFailure(t *testing.T) {
	ledger, _ := evidenceFixture(t)
	if err := ledger.VerifyIncremental(); err != nil {
		t.Fatalf("an empty ledger failed incremental verification: %v", err)
	}
	if err := ledger.Healthy(); err != nil {
		t.Fatalf("an empty ledger was quarantined by the incremental pass: %v", err)
	}
	if status := ledger.Status(); status.VerifyScope != "empty" {
		t.Fatalf("an empty ledger reported scope %q", status.VerifyScope)
	}
}

// TestVerifyIncrementalWatermarkFailureDoesNotQuarantine pins the second half of FIND-017: a
// watermark that cannot be persisted is a disk condition, not evidence of a damaged chain. The
// pass must stay healthy and report success instead of degrading the platform.
func TestVerifyIncrementalWatermarkFailureDoesNotQuarantine(t *testing.T) {
	ledger, path := evidenceFixture(t)
	appendEvidenceRecords(t, ledger, 5)
	// A directory where the watermark file has to go makes every write fail. The chain itself is
	// untouched and valid.
	if err := os.Mkdir(path+".verified", 0o700); err != nil {
		t.Fatal(err)
	}
	reloaded, err := reloadEvidence(t, path, 4<<20)
	if err != nil {
		t.Fatal(err)
	}
	if err := reloaded.Healthy(); err != nil {
		t.Fatalf("an unwritable coverage hint quarantined the ledger at construction: %v", err)
	}
	if err := reloaded.VerifyIncremental(); err != nil {
		t.Fatalf("a watermark write failure was reported as a verification failure: %v", err)
	}
	if err := reloaded.Healthy(); err != nil {
		t.Fatalf("a healthy chain was quarantined because its watermark could not be written: %v", err)
	}
	if err := reloaded.Verify(); err != nil {
		t.Fatalf("full verification failed because the watermark was unwritable: %v", err)
	}
	if err := reloaded.Healthy(); err != nil {
		t.Fatalf("full verification quarantined the ledger because the watermark was unwritable: %v", err)
	}
}
