// STATUS: DIAMANT VGT SUPREME
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
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

// writeAuthenticatedRotationMarker writes a marker the way the trusted writer does: sealed with
// the node storage cipher, purpose- and path-bound. It lets a test exercise the completion path
// with attacker-chosen content while keeping the envelope authentic.
func writeAuthenticatedRotationMarker(t *testing.T, ledger *EvidenceLedger, marker evidenceRotationMarker) string {
	t.Helper()
	dir := filepath.Dir(ledger.path)
	markerPath := filepath.Join(dir, evidenceRotationMarkerName)
	raw, err := json.Marshal(marker)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := ledger.crypto.Encrypt(markerPath, evidenceRotationMarkerPurpose, 0, raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(markerPath, append(sealed, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	return markerPath
}

// liveChainFingerprint captures the live chain bytes and checkpoint so a test can prove a
// refused rotation left them byte-for-byte unchanged.
func liveChainFingerprint(t *testing.T, path string) string {
	t.Helper()
	chain, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	head, err := os.ReadFile(path + ".head")
	if err != nil {
		t.Fatal(err)
	}
	return string(chain) + "\x00" + string(head)
}

// assertRotationRefusedUntilRestart reloads the ledger with a marker present and asserts the
// rotation was refused while the live chain stayed unchanged.
func assertRotationRefusedUntilRestart(t *testing.T, path, before string) {
	t.Helper()
	refused, err := reloadEvidence(t, path, 4<<20)
	if err != nil {
		t.Fatalf("a rejected rotation must not fail the start: %v", err)
	}
	if err := refused.Healthy(); err == nil {
		t.Fatal("an unauthenticated or mismatched rotation marker was accepted")
	}
	if after := liveChainFingerprint(t, path); after != before {
		t.Fatal("the live evidence chain changed although the rotation was refused")
	}
}

// TestARotationMarkerWithoutItsArchiveRefusesToStart is the counter-case: fail-closed rather
// than inventing an archive that is not there.
func TestARotationMarkerWithoutItsArchiveRefusesToStart(t *testing.T) {
	ledger, path := evidenceFixture(t)
	appendEvidenceRecords(t, ledger, 3)
	before := liveChainFingerprint(t, path)
	// The marker is authentic (written with the node storage key) but names an archive that
	// never existed.
	marker := evidenceRotationMarker{
		Version: evidenceRotationVersion, ArchiveID: "20260101T000000-000000000Z-deadbeefdeadbeef",
		ManifestSHA256: strings.Repeat("0", 64), SealedHead: ledger.headHash, SealedSequence: ledger.sequence,
	}
	writeAuthenticatedRotationMarker(t, ledger, marker)
	refused, err := reloadEvidence(t, path, 4<<20)
	if err != nil {
		t.Fatal(err)
	}
	if refused.Healthy() == nil {
		t.Fatal("a rotation marker without an archive was accepted")
	}
	if !strings.Contains(refused.Healthy().Error(), "manifest") {
		t.Fatalf("the refusal does not name the cause: %v", refused.Healthy())
	}
	if after := liveChainFingerprint(t, path); after != before {
		t.Fatal("the live evidence chain changed although the rotation was refused")
	}
}

// TestRotationMarkerArchiveIDTraversalIsRefused covers the path-traversal attempt the marker
// used to allow: filepath.Join(dir, "archive", "evidence-"+ArchiveID, "manifest.json") with an
// unvalidated identifier resolves outside the archive root. The marker is sealed like a real
// one, so only the identifier validation can stop it - and it has to, without touching the chain.
func TestRotationMarkerArchiveIDTraversalIsRefused(t *testing.T) {
	hostile := []string{"../../evil", "..", "../archive", "a/b", "/etc/passwd", `..\evil`, "20260101T000000.000000000Z-deadbeef", strings.Repeat("a", 200)}
	for _, archiveID := range hostile {
		t.Run(archiveID, func(t *testing.T) {
			ledger, path := evidenceFixture(t)
			appendEvidenceRecords(t, ledger, 3)
			before := liveChainFingerprint(t, path)
			writeAuthenticatedRotationMarker(t, ledger, evidenceRotationMarker{
				Version: evidenceRotationVersion, ArchiveID: archiveID,
				ManifestSHA256: strings.Repeat("0", 64), SealedHead: ledger.headHash, SealedSequence: ledger.sequence,
			})
			refused, err := reloadEvidence(t, path, 4<<20)
			if err != nil {
				t.Fatal(err)
			}
			if refused.Healthy() == nil {
				t.Fatalf("rotation marker with archive id %q was accepted", archiveID)
			}
			if after := liveChainFingerprint(t, path); after != before {
				t.Fatal("the live evidence chain changed although the rotation was refused")
			}
		})
	}
}

// TestAnUnauthenticatedRotationMarkerIsRefused is the core of the finding: the marker used to be
// plaintext JSON that anyone with write access to the state directory could author. It must now
// be an envelope under the node storage key, and a write-access attacker's marker must not
// complete a chain reset.
func TestAnUnauthenticatedRotationMarkerIsRefused(t *testing.T) {
	ledger, path := evidenceFixture(t)
	appendEvidenceRecords(t, ledger, 4)
	before := liveChainFingerprint(t, path)
	// Exactly the old, unauthenticated marker format - now a forgery.
	plaintext, err := json.Marshal(evidenceRotationMarker{
		Version: evidenceRotationVersion, ArchiveID: "20260101T000000-000000000Z-deadbeefdeadbeef",
		ManifestSHA256: strings.Repeat("0", 64), SealedHead: ledger.headHash, SealedSequence: ledger.sequence,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(filepath.Dir(path), evidenceRotationMarkerName), append(plaintext, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	assertRotationRefusedUntilRestart(t, path, before)
	if _, err := os.Stat(filepath.Join(filepath.Dir(path), evidenceRotationMarkerName)); err != nil {
		t.Fatal("an unauthenticated marker was silently removed instead of reported")
	}
}

// TestATamperedRotationMarkerIsRefused proves the AEAD is actually checked: an attacker who can
// modify the bytes of a genuine marker cannot make the start accept it.
func TestATamperedRotationMarkerIsRefused(t *testing.T) {
	ledger, path := evidenceFixture(t)
	appendEvidenceRecords(t, ledger, 4)
	// Produce a genuine marker through the interrupted-rotation path.
	ledger.mu.Lock()
	archiveID, manifestSHA, err := ledger.sealLocked(context.Background(), "tamper fixture")
	if err == nil {
		err = ledger.writeRotationMarkerLocked(archiveID, manifestSHA)
	}
	ledger.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	before := liveChainFingerprint(t, path)
	markerPath := filepath.Join(filepath.Dir(path), evidenceRotationMarkerName)
	raw, err := os.ReadFile(markerPath)
	if err != nil {
		t.Fatal(err)
	}
	// Flip one character inside the ciphertext envelope. The marker must not authenticate.
	tampered := append([]byte(nil), raw...)
	marker := []byte(`"ciphertext":"`)
	idx := bytes.Index(tampered, marker)
	if idx < 0 {
		t.Fatal("ciphertext field missing from the sealed marker")
	}
	idx += len(marker)
	if tampered[idx] == 'A' {
		tampered[idx] = 'B'
	} else {
		tampered[idx] = 'A'
	}
	if err := os.WriteFile(markerPath, tampered, 0o600); err != nil {
		t.Fatal(err)
	}
	assertRotationRefusedUntilRestart(t, path, before)
}

// TestARotationMarkerThatNamesADifferentHeadIsRefused is the replay case: the manifest hash and
// the marker can agree with each other, but the marker still has to name the authenticated
// predecessor checkpoint. A marker replayed after a newer rotation names a head the current
// checkpoint does not seal, and completing it would destroy evidence it does not describe.
func TestARotationMarkerThatNamesADifferentHeadIsRefused(t *testing.T) {
	ledger, path := evidenceFixture(t)
	appendEvidenceRecords(t, ledger, 3)
	before := liveChainFingerprint(t, path)
	// The archive and the manifest digest are self-consistent, but the sealed head does not
	// match the authenticated live checkpoint.
	archiveID := "20260101T000000-000000000Z-deadbeefdeadbeef"
	archiveDir := archiveDirFor(t, path, archiveID)
	if err := os.MkdirAll(archiveDir, 0o700); err != nil {
		t.Fatal(err)
	}
	manifest := evidenceRotationManifest{
		Version: evidenceRotationVersion, ArchiveID: archiveID,
		SealedRecords: ledger.sequence, SealedHeadHash: strings.Repeat("f", 64),
	}
	manifestBytes, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(archiveDir, "manifest.json"), manifestBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(manifestBytes)
	writeAuthenticatedRotationMarker(t, ledger, evidenceRotationMarker{
		Version: evidenceRotationVersion, ArchiveID: archiveID,
		ManifestSHA256: hex.EncodeToString(digest[:]), SealedHead: ledger.headHash, SealedSequence: ledger.sequence,
	})
	assertRotationRefusedUntilRestart(t, path, before)
}

// TestAHalfFinishedRotationIsCompletedButAMarkerFromAnOlderRotationIsNot covers both sides of
// the idempotency rule: the completion of the interrupted rotation is repeated, but a marker
// copied back after the rotation finished (a replay) is refused.
func TestAMarkerReplayedAfterTheRotationIsRefused(t *testing.T) {
	ledger, path := evidenceFixture(t)
	appendEvidenceRecords(t, ledger, 3)
	ledger.mu.Lock()
	archiveID, manifestSHA, err := ledger.sealLocked(context.Background(), "replay fixture")
	if err == nil {
		err = ledger.writeRotationMarkerLocked(archiveID, manifestSHA)
	}
	ledger.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	markerPath := filepath.Join(filepath.Dir(path), evidenceRotationMarkerName)
	recorded, err := os.ReadFile(markerPath)
	if err != nil {
		t.Fatal(err)
	}
	// Finish the rotation the way a restart would.
	completed, err := reloadEvidence(t, path, 4<<20)
	if err != nil {
		t.Fatal(err)
	}
	if err := completed.Healthy(); err != nil {
		t.Fatalf("the interrupted rotation was not completed: %v", err)
	}
	// A new chain exists now; replay the old marker over it.
	appendEvidenceRecords(t, completed, 2)
	before := liveChainFingerprint(t, path)
	if err := os.WriteFile(markerPath, recorded, 0o600); err != nil {
		t.Fatal(err)
	}
	assertRotationRefusedUntilRestart(t, path, before)
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

// TestRotationTriggersBeforeTheBudgetIsReached pins the threshold: rotating at the budget would
// rotate only after recording had already stopped.
func TestRotationDoesNotRunOnAnEmptyLedger(t *testing.T) {
	ledger, _ := evidenceFixture(t)
	if _, err := ledger.Rotate(context.Background(), "nothing to seal"); err == nil {
		t.Fatal("rotating an empty ledger was reported as success")
	}
}
