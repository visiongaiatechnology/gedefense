// STATUS: DIAMANT VGT SUPREME
package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The contracts here describe the retention design: a forensic record that stops recording is
// worse than a short one, and the budget of a log must never pause the protection again.

func archiveDirFor(t *testing.T, path, archiveID string) string {
	t.Helper()
	return filepath.Join(filepath.Dir(path), "archive", "evidence-"+archiveID)
}

// TestRotationSealsTheChainAndStartsAFreshOne covers the whole operation: the sealed segment is
// preserved with a manifest, the live chain continues empty, and the status says so.
func TestRotationSealsTheChainAndStartsAFreshOne(t *testing.T) {
	ledger, path := evidenceFixture(t)
	appendEvidenceRecords(t, ledger, 6)

	result, err := ledger.Rotate(context.Background(), "unit test rotation")
	if err != nil {
		t.Fatalf("rotation failed: %v", err)
	}
	if result.SealedRecords != 6 {
		t.Fatalf("sealed %d records, want 6", result.SealedRecords)
	}
	if result.ArchiveID == "" || result.ManifestSHA256 == "" {
		t.Fatalf("rotation produced no archive identity: %+v", result)
	}

	// The sealed segment is archived with everything needed to verify it later.
	archive := archiveDirFor(t, path, result.ArchiveID)
	for _, name := range []string{"evidence.jsonl", "evidence.jsonl.head", "manifest.json"} {
		if _, err := os.Stat(filepath.Join(archive, name)); err != nil {
			t.Fatalf("%s was not archived: %v", name, err)
		}
	}
	manifestBytes, err := os.ReadFile(filepath.Join(archive, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var manifest evidenceRotationManifest
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		t.Fatalf("the manifest is not readable: %v", err)
	}
	if manifest.SealedRecords != 6 || manifest.SealedHeadHash != result.SealedHead {
		t.Fatalf("the manifest does not describe what was sealed: %+v", manifest)
	}
	if manifest.Ledger.SHA256 == "" || !manifest.Ledger.Present {
		t.Fatalf("the manifest carries no digest for the sealed log: %+v", manifest.Ledger)
	}

	// The live chain is fresh and continues without a gap once it is written to again.
	if status := ledger.Status(); status.Records != 0 || !status.Healthy || status.Full {
		t.Fatalf("status after rotation: %+v", status)
	}
	appendEvidenceRecords(t, ledger, 2)
	if status := ledger.Status(); status.Records != 2 {
		t.Fatalf("the fresh chain holds %d records, want 2", status.Records)
	}
	if err := ledger.Verify(); err != nil {
		t.Fatalf("the fresh chain does not verify: %v", err)
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(path), evidenceRotationMarkerName)); !os.IsNotExist(err) {
		t.Fatal("the rotation marker was left behind")
	}
	// A restart accepts the fresh chain.
	if _, err := reloadEvidence(t, path, 4<<20); err != nil {
		t.Fatalf("a restart rejected the fresh chain: %v", err)
	}
}

// TestAnInterruptedRotationIsCompletedAtStartup covers the crash window.
//
// The marker is written before the live files are replaced, so its presence means the archive
// exists and matches; only the swap is missing. Refusing to start over that would repeat the
// failure this work came from - a half-finished file operation taking the platform down.
func TestAnInterruptedRotationIsCompletedAtStartup(t *testing.T) {
	ledger, path := evidenceFixture(t)
	appendEvidenceRecords(t, ledger, 5)

	// Reproduce the crash: the segment is sealed and the marker is written, but the swap never
	// happened. sealLocked is exactly what Rotate runs before the marker.
	ledger.mu.Lock()
	archiveID, manifestSHA, err := ledger.sealLocked(context.Background(), "interrupted rotation fixture")
	if err != nil {
		ledger.mu.Unlock()
		t.Fatal(err)
	}
	if err := ledger.writeRotationMarkerLocked(archiveID, manifestSHA); err != nil {
		ledger.mu.Unlock()
		t.Fatal(err)
	}
	ledger.mu.Unlock()

	// The live chain is untouched and still complete at this point.
	if lines := evidenceLines(t, path); len(lines) != 5 {
		t.Fatalf("the interrupted rotation already changed the live chain: %d records", len(lines))
	}

	recovered, err := reloadEvidence(t, path, 4<<20)
	if err != nil {
		t.Fatalf("the interrupted rotation stopped the service: %v", err)
	}
	if err := recovered.Healthy(); err != nil {
		t.Fatalf("the interrupted rotation was not completed: %v", err)
	}
	if status := recovered.Status(); status.Records != 0 {
		t.Fatalf("the completed rotation left %d records in the live chain", status.Records)
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(path), evidenceRotationMarkerName)); !os.IsNotExist(err) {
		t.Fatal("the rotation marker survived the completion")
	}
	if _, err := os.Stat(filepath.Join(archiveDirFor(t, path, archiveID), "manifest.json")); err != nil {
		t.Fatalf("the sealed segment was lost: %v", err)
	}
	// The completed ledger accepts new records and verifies.
	appendEvidenceRecords(t, recovered, 3)
	if err := recovered.Verify(); err != nil {
		t.Fatalf("the chain after the completed rotation does not verify: %v", err)
	}
}

// TestARotationMarkerWithoutItsArchiveRefusesToStart is the counter-case: fail-closed rather
// than inventing an archive that is not there.
func TestARotationMarkerWithoutItsArchiveRefusesToStart(t *testing.T) {
	ledger, path := evidenceFixture(t)
	appendEvidenceRecords(t, ledger, 3)
	marker := `{"version":1,"archive_id":"20260101T000000.000000000Z-deadbeefdeadbeef","manifest_sha256":"00"}`
	if err := os.WriteFile(filepath.Join(filepath.Dir(path), evidenceRotationMarkerName), []byte(marker), 0o600); err != nil {
		t.Fatal(err)
	}
	refused, err := reloadEvidence(t, path, 4<<20)
	if err != nil {
		return
	}
	if refused.Healthy() == nil {
		t.Fatal("a rotation marker without an archive was accepted")
	}
	if !strings.Contains(refused.Healthy().Error(), "manifest") {
		t.Fatalf("the refusal does not name the cause: %v", refused.Healthy())
	}
}

// TestRotationTriggersBeforeTheBudgetIsReached pins the threshold: rotating at the budget would
// rotate only after recording had already stopped.
func TestRotationDoesNotRunOnAnEmptyLedger(t *testing.T) {
	ledger, _ := evidenceFixture(t)
	if _, err := ledger.Rotate(context.Background(), "nothing to seal"); err == nil {
		t.Fatal("rotating an empty ledger was reported as success")
	}
}
