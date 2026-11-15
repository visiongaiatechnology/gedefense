// STATUS: DIAMANT VGT SUPREME
package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The contracts here pin the two crash windows the rotation swap really has. The one between the
// fresh-chain rename and its authenticated epoch checkpoint is fail-closed: the next start refuses
// the pending marker, keeps the sealed archive and the predecessor epoch intact and quarantines the
// ledger. Recovery from it is an explicit operator action, never an automatic claim. The window
// after the fresh epoch checkpoint is durable is harmless: only the marker is left behind.

// crashFreshChainSwap reproduces the crash point between the live-chain rename and the fresh
// checkpoint: the sealed segment and the authenticated marker exist, the live log has already been
// replaced by an empty file, and no fresh checkpoint was written.
func crashFreshChainSwap(t *testing.T, ledger *EvidenceLedger, path, reason string) (evidenceCheckpoint, string) {
	t.Helper()
	predecessor, err := readEvidenceCheckpoint(path+".head", ledger.crypto)
	witnessMust(t, err)
	ledger.mu.Lock()
	archiveID, manifestSHA, err := ledger.sealLocked(context.Background(), reason)
	if err == nil {
		err = ledger.writeRotationMarkerLocked(archiveID, manifestSHA)
	}
	ledger.mu.Unlock()
	witnessMust(t, err)
	empty, err := os.CreateTemp(filepath.Dir(path), ".evidence-crash-*")
	witnessMust(t, err)
	witnessMust(t, empty.Chmod(0o600))
	witnessMust(t, empty.Close())
	witnessMust(t, os.Rename(empty.Name(), path))
	return predecessor, archiveID
}

func TestEvidenceRotationCrashWindowIsFailClosed(t *testing.T) {
	ledger, path := evidenceFixture(t)
	appendEvidenceRecords(t, ledger, 2)
	// Establish epoch 1 so the window can be shown not to move it at all.
	if _, err := ledger.Rotate(context.Background(), "epoch one fixture"); err != nil {
		t.Fatal(err)
	}
	appendEvidenceRecords(t, ledger, 4)
	predecessor, archiveID := crashFreshChainSwap(t, ledger, path, "crash window fixture")

	refused, err := reloadEvidence(t, path, 4<<20)
	witnessMust(t, err)
	healthy := refused.Healthy()
	if healthy == nil || !strings.Contains(healthy.Error(), "does not describe the live chain") {
		t.Fatalf("the crash window was not refused; it must never be completed silently: %v", healthy)
	}
	if lines := evidenceLines(t, path); len(lines) != 0 {
		t.Fatalf("the refused start wrote %d records into the live chain", len(lines))
	}
	// No auto-complete and no epoch movement: the predecessor checkpoint is byte-identical.
	durable, err := readEvidenceCheckpoint(path+".head", ledger.crypto)
	witnessMust(t, err)
	if durable.Sequence != predecessor.Sequence || durable.HeadHash != predecessor.HeadHash || durable.LedgerEpoch != predecessor.LedgerEpoch {
		t.Fatalf("the crash window moved the predecessor checkpoint: %+v -> %+v", predecessor, durable)
	}
	marker := filepath.Join(filepath.Dir(path), evidenceRotationMarkerName)
	if _, err := os.Stat(marker); err != nil {
		t.Fatal("the pending marker was cleared although the swap was not completed")
	}
	// Fail-closed is stable: a second start refuses the same way instead of guessing.
	if again, err := reloadEvidence(t, path, 4<<20); err != nil || again.Healthy() == nil {
		t.Fatalf("the quarantine did not persist across a restart: %v", err)
	}
	archive := filepath.Join(filepath.Dir(path), "archive", "evidence-"+archiveID)
	for _, name := range []string{"evidence.jsonl", "evidence.jsonl.head", "manifest.json"} {
		if _, err := os.Stat(filepath.Join(archive, name)); err != nil {
			t.Fatalf("the sealed segment lost %s: %v", name, err)
		}
	}

	// The documented way back is the operator restoring the sealed segment and clearing the
	// marker; only then is the ledger healthy again and the next rotation moves the epoch.
	for _, name := range []string{"evidence.jsonl", "evidence.jsonl.head"} {
		raw, err := os.ReadFile(filepath.Join(archive, name))
		witnessMust(t, err)
		target := path
		if name == "evidence.jsonl.head" {
			target = path + ".head"
		}
		if err := os.WriteFile(target, raw, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	witnessMust(t, os.Remove(marker))
	recovered, err := reloadEvidence(t, path, 4<<20)
	witnessMust(t, err)
	if err := recovered.Healthy(); err != nil {
		t.Fatalf("the documented operator recovery did not heal the ledger: %v", err)
	}
	if view, err := recovered.Checkpoint(); err != nil || view.Sequence != predecessor.Sequence || view.LedgerEpoch != predecessor.LedgerEpoch {
		t.Fatalf("recovered checkpoint view: %+v, %v", view, err)
	}
	if _, err := recovered.Rotate(context.Background(), "rotation after recovery"); err != nil {
		t.Fatalf("the rotation after the recovery failed: %v", err)
	}
	if view, err := recovered.Checkpoint(); err != nil || view.LedgerEpoch != predecessor.LedgerEpoch+1 {
		t.Fatalf("epoch after the recovery rotation: %+v, %v", view, err)
	}
}

func TestEvidenceRotationCrashAfterFreshCheckpointHeals(t *testing.T) {
	ledger, path := evidenceFixture(t)
	appendEvidenceRecords(t, ledger, 2)
	if _, err := ledger.Rotate(context.Background(), "epoch one fixture"); err != nil {
		t.Fatal(err)
	}
	appendEvidenceRecords(t, ledger, 3)
	predecessor, _ := crashFreshChainSwap(t, ledger, path, "crash after checkpoint fixture")
	// The missing half of this crash: the fresh epoch checkpoint was durable, only the marker
	// cleanup and the in-memory reset never happened.
	witnessMust(t, writeEvidenceCheckpoint(path+".head", 0, "", predecessor.LedgerEpoch+1, ledger.crypto))

	healed, err := reloadEvidence(t, path, 4<<20)
	witnessMust(t, err)
	if err := healed.Healthy(); err != nil {
		t.Fatalf("a crash after the durable fresh checkpoint was not healed: %v", err)
	}
	view, err := healed.Checkpoint()
	if view.LedgerEpoch != predecessor.LedgerEpoch+1 || view.Sequence != 0 || view.HeadHash != "" {
		t.Fatalf("fresh chain after the healed crash: %+v, %v", view, err)
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(path), evidenceRotationMarkerName)); !os.IsNotExist(err) {
		t.Fatal("the leftover marker survived the healed start")
	}
	appendEvidenceRecords(t, healed, 1)
	if err := healed.Verify(); err != nil {
		t.Fatalf("the chain after the healed crash does not verify: %v", err)
	}
}
