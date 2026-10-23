// STATUS: DIAMANT VGT SUPREME
// SPDX-FileCopyrightText: 2026 VisionGaia Technology
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"os"
	"path/filepath"
	"testing"
)

// TestArchiveRetentionKeepsTheCeilingAndTheReferencedArchive pins the two properties that make the
// retention safe: the oldest complete archives are removed so the disk cannot fill up, and neither a
// partially written archive nor the one the rotation marker references is ever touched - a start-up
// that finds a marker without its archive refuses to run, so retention must not create that state.
func TestArchiveRetentionKeepsTheCeilingAndTheReferencedArchive(t *testing.T) {
	root := t.TempDir()
	ledger := &EvidenceLedger{path: filepath.Join(root, "evidence.jsonl")}
	archiveRoot := filepath.Join(root, "archive")
	if err := os.MkdirAll(archiveRoot, 0o700); err != nil {
		t.Fatal(err)
	}

	// Timestamp-ordered identifiers, oldest first, as newRecoveryArchiveID produces them.
	ids := []string{
		"20260101T000000.000000000Z-aaaa",
		"20260102T000000.000000000Z-bbbb",
		"20260103T000000.000000000Z-cccc",
		"20260104T000000.000000000Z-dddd",
	}
	for _, id := range ids {
		dir := filepath.Join(archiveRoot, "evidence-"+id)
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "manifest.json"), []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// An archive that is still being written: a directory without a manifest.
	incomplete := filepath.Join(archiveRoot, "evidence-20260105T000000.000000000Z-eeee")
	if err := os.MkdirAll(incomplete, 0o700); err != nil {
		t.Fatal(err)
	}
	// The marker references the oldest archive, which is therefore protected even though it is the
	// first candidate for removal.
	marker := `{"version":1,"archive_id":"` + ids[0] + `","manifest_sha256":"x"}`
	if err := os.WriteFile(filepath.Join(root, evidenceRotationMarkerName), []byte(marker), 0o600); err != nil {
		t.Fatal(err)
	}

	removed, err := ledger.pruneArchivesLocked(2)
	if err != nil {
		t.Fatal(err)
	}
	if removed != 2 {
		t.Fatalf("removed %d archives, want 2", removed)
	}

	for _, id := range []string{ids[1], ids[2]} {
		if _, err := os.Stat(filepath.Join(archiveRoot, "evidence-"+id)); !os.IsNotExist(err) {
			t.Fatalf("archive %s should have been removed", id)
		}
	}
	for _, id := range []string{ids[0], ids[3]} {
		if _, err := os.Stat(filepath.Join(archiveRoot, "evidence-"+id)); err != nil {
			t.Fatalf("archive %s must be kept: %v", id, err)
		}
	}
	if _, err := os.Stat(incomplete); err != nil {
		t.Fatalf("an archive without a manifest must never be removed: %v", err)
	}

	// Without a marker the ceiling applies plainly, and the count never grows beyond it.
	if err := os.Remove(filepath.Join(root, evidenceRotationMarkerName)); err != nil {
		t.Fatal(err)
	}
	if _, err := ledger.pruneArchivesLocked(1); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(archiveRoot)
	if err != nil {
		t.Fatal(err)
	}
	remaining := 0
	for _, entry := range entries {
		if _, err := os.Stat(filepath.Join(archiveRoot, entry.Name(), "manifest.json")); err == nil {
			remaining++
		}
	}
	if remaining != 1 {
		t.Fatalf("%d complete archives remain, want 1", remaining)
	}
}

// TestIncidentArchiveRetentionUsesTheSameRuleAndKeepsIncompleteOnes proves the incident ledger obeys
// the same ceiling as the evidence ledger. Its archives are named by the identifier alone (no prefix),
// so this also pins that the shared rule keeps working when the prefix is empty - and that a directory
// without a manifest, which may be an archive still being written, is never a candidate.
func TestIncidentArchiveRetentionUsesTheSameRuleAndKeepsIncompleteOnes(t *testing.T) {
	root := t.TempDir()
	recoveryRoot := filepath.Join(root, "xdr-recovery")
	if err := os.MkdirAll(recoveryRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	ids := []string{
		"20260101T000000.000000000Z-aaaa",
		"20260102T000000.000000000Z-bbbb",
		"20260103T000000.000000000Z-cccc",
	}
	for _, id := range ids {
		dir := filepath.Join(recoveryRoot, id)
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "manifest.json"), []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	incomplete := filepath.Join(recoveryRoot, "20260104T000000.000000000Z-dddd")
	if err := os.MkdirAll(incomplete, 0o700); err != nil {
		t.Fatal(err)
	}

	removed, err := pruneCompleteArchives(recoveryRoot, "", 1, "")
	if err != nil {
		t.Fatal(err)
	}
	if removed != 2 {
		t.Fatalf("removed %d incident archives, want 2", removed)
	}
	if _, err := os.Stat(filepath.Join(recoveryRoot, ids[2])); err != nil {
		t.Fatalf("the newest incident archive must be kept: %v", err)
	}
	for _, id := range ids[:2] {
		if _, err := os.Stat(filepath.Join(recoveryRoot, id)); !os.IsNotExist(err) {
			t.Fatalf("incident archive %s should have been removed", id)
		}
	}
	if _, err := os.Stat(incomplete); err != nil {
		t.Fatalf("an incomplete archive must never be removed: %v", err)
	}
}
