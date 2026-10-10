// STATUS: DIAMANT VGT SUPREME
package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// legacyCaseStoreFixture writes an encrypted store in the layout that broke the production host:
// it may hold several records for one fingerprint. The loader rejected the whole store, so the case
// history was permanently unavailable, every incident ingest failed against it, and each failure
// marked XDR degraded - which paused the automatic response in five-minute cycles.
func legacyCaseStoreFixture(t *testing.T, records []SecurityCase) (string, *StorageCipher) {
	t.Helper()
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "storage.key")
	if err := os.WriteFile(keyPath, bytes.Repeat([]byte{0x5a}, 32), 0o600); err != nil {
		t.Fatal(err)
	}
	storage, err := NewStorageCipher(keyPath, "case-repair-node")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "cases.enc")
	plaintext, err := json.Marshal(caseStore{Schema: caseSchema, Revision: 4, Cases: records})
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := storage.Encrypt(path, casePurpose, 4, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	if err := atomicWriteFile(path, sealed, 0o600); err != nil {
		t.Fatal(err)
	}
	return path, storage
}

func caseRecordFixture(id, fingerprint string, updated time.Time, occurrences uint64) SecurityCase {
	return SecurityCase{
		ID: id, Fingerprint: fingerprint, Title: "Executable origin violated trusted policy",
		Status: "open", Severity: "high", Confidence: "high",
		CreatedAt: updated.Add(-time.Hour), UpdatedAt: updated, OccurrenceCount: occurrences,
		Observations: []CaseObservation{{At: updated, Source: "fixture", Message: "observation"}},
	}
}

// TestALegacyStoreWithDuplicateFingerprintsIsRepairedInsteadOfRejected is the root fix: the data is
// migrated deterministically and the case history becomes usable again instead of staying dead.
func TestALegacyStoreWithDuplicateFingerprintsIsRepairedInsteadOfRejected(t *testing.T) {
	fingerprint := strings.Repeat("a", 64)
	newer := time.Unix(1_700_000_500, 0).UTC()
	older := newer.Add(-10 * time.Minute)
	records := []SecurityCase{
		caseRecordFixture("CS-aaaaaaaaaaaaaaaa", fingerprint, older, 3),
		caseRecordFixture("CS-bbbbbbbbbbbbbbbb", fingerprint, newer, 4),
	}
	path, storage := legacyCaseStoreFixture(t, records)

	engine, err := NewCaseEngine(path, storage, func(EvidenceRecord) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	status := engine.Status(10)
	if !status.Healthy {
		t.Fatalf("the repaired store is still unhealthy: %+v", status)
	}
	if status.Count != 1 {
		t.Fatalf("duplicate fingerprints were not merged: count=%d", status.Count)
	}
	if status.Repaired != 1 {
		t.Fatalf("the repair is not reported in the status: repaired=%d", status.Repaired)
	}
	if len(status.Cases) != 1 {
		t.Fatalf("expected exactly one surviving case, got %d", len(status.Cases))
	}
	surviving := status.Cases[0]
	if surviving.ID != "CS-bbbbbbbbbbbbbbbb" {
		t.Fatalf("the merge did not keep the newest record: %s", surviving.ID)
	}
	if surviving.OccurrenceCount != 7 {
		t.Fatalf("occurrence counters were not summed: %d", surviving.OccurrenceCount)
	}
	if !surviving.CreatedAt.Equal(older.Add(-time.Hour)) {
		t.Fatalf("the merge did not keep the earliest creation time: %s", surviving.CreatedAt)
	}
	if !surviving.UpdatedAt.Equal(newer) {
		t.Fatalf("the merge did not keep the latest update time: %s", surviving.UpdatedAt)
	}
	if surviving.Fingerprint != fingerprint {
		t.Fatalf("the surviving record lost its fingerprint: %s", surviving.Fingerprint)
	}

	// The history has to be usable again: this ingest is exactly what kept failing in production.
	if err := engine.IngestIncident(testCaseIncident("incident-repair", "critical")); err != nil {
		t.Fatalf("the repaired store still refuses incidents: %v", err)
	}

	// And the repair is durable: the next start reads a consistent store and repairs nothing.
	reloaded, err := NewCaseEngine(path, storage, func(EvidenceRecord) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	fresh := reloaded.Status(10)
	if !fresh.Healthy {
		t.Fatalf("the repaired store was not written back: %+v", fresh)
	}
	if fresh.Repaired != 0 {
		t.Fatalf("the persisted store still needs repair: repaired=%d", fresh.Repaired)
	}
	if fresh.Count != 2 {
		t.Fatalf("the persisted store lost records: count=%d", fresh.Count)
	}
}

// TestADuplicateCaseIDIsStillRefused keeps the repair honest: one case ID twice is corruption, not a
// legacy layout, and it must keep failing closed.
func TestADuplicateCaseIDIsStillRefused(t *testing.T) {
	updated := time.Unix(1_700_000_500, 0).UTC()
	records := []SecurityCase{
		caseRecordFixture("CS-cccccccccccccccc", strings.Repeat("b", 64), updated, 1),
		caseRecordFixture("CS-cccccccccccccccc", strings.Repeat("c", 64), updated, 1),
	}
	path, storage := legacyCaseStoreFixture(t, records)

	engine, err := NewCaseEngine(path, storage, func(EvidenceRecord) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	if status := engine.Status(10); status.Healthy {
		t.Fatalf("a store with duplicate case IDs was accepted: %+v", status)
	}
	if err := engine.IngestIncident(testCaseIncident("incident-duplicate-id", "critical")); err == nil {
		t.Fatal("a corrupted store accepted a new incident")
	}
}

// TestAResolvedCaseIsNotSilentlyReopenedByTheMerge pins the conservative half of the merge: a closed
// case must never swallow an open one, and an open case must never lose its state to a closed one.
func TestAMergeKeepsAnOpenCaseOpen(t *testing.T) {
	older := time.Unix(1_700_000_000, 0).UTC()
	closed := caseRecordFixture("CS-dddddddddddddddd", strings.Repeat("d", 64), older, 1)
	closed.Status = "resolved"
	closed.Resolution = "operator closed it"
	open := caseRecordFixture("CS-eeeeeeeeeeeeeeee", strings.Repeat("d", 64), older.Add(time.Minute), 1)

	merged := mergeSecurityCases(closed, open)

	if merged.Status != "open" {
		t.Fatalf("the merge lost an open case: %s", merged.Status)
	}
	if merged.Resolution != "" {
		t.Fatalf("the merge kept a resolution on an open case: %q", merged.Resolution)
	}
	if merged.ID != "CS-eeeeeeeeeeeeeeee" {
		t.Fatalf("the merge did not keep the newest record: %s", merged.ID)
	}
}
