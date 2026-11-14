// STATUS: DIAMANT VGT SUPREME
package main

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestChronosFIM_CompleteScanAndMerkleRoot(t *testing.T) {
	tempDir := t.TempDir()
	rootDir := filepath.Join(tempDir, "sys_root")
	_ = os.MkdirAll(filepath.Join(rootDir, "bin"), 0755)
	_ = os.MkdirAll(filepath.Join(rootDir, "lib"), 0755)

	// Create files
	_ = os.WriteFile(filepath.Join(rootDir, "bin", "sh"), []byte("bin-sh-content"), 0755)
	_ = os.WriteFile(filepath.Join(rootDir, "bin", "ls"), []byte("bin-ls-content"), 0755)
	_ = os.WriteFile(filepath.Join(rootDir, "lib", "libc.so"), []byte("libc-content"), 0644)

	cpPath := filepath.Join(tempDir, "checkpoint.json")
	scanner, err := NewChronosScanner([]string{rootDir}, cpPath, 10, 0)
	if err != nil {
		t.Fatalf("new scanner failed: %v", err)
	}

	ctx := context.Background()
	cp, err := scanner.Scan(ctx, false)
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}

	if cp.Phase != "COMPLETED" {
		t.Fatalf("expected COMPLETED phase, got %s", cp.Phase)
	}
	if cp.FilesScanned != 3 {
		t.Fatalf("expected 3 files scanned, got %d", cp.FilesScanned)
	}
	if len(cp.MerkleRoot) != 64 {
		t.Fatalf("expected 64-char sha256 merkle root, got %s", cp.MerkleRoot)
	}

	// 2. Tampering test: modify one file and verify Merkle root changes
	_ = os.WriteFile(filepath.Join(rootDir, "bin", "sh"), []byte("tampered-sh-content"), 0755)
	scannerTampered, _ := NewChronosScanner([]string{rootDir}, cpPath+".2", 10, 0)
	cpTampered, err := scannerTampered.Scan(ctx, false)
	if err != nil {
		t.Fatalf("tampered scan failed: %v", err)
	}
	if cpTampered.MerkleRoot == cp.MerkleRoot {
		t.Fatalf("expected different Merkle root after tampering")
	}
}

func TestChronosFIM_ResumableScan(t *testing.T) {
	tempDir := t.TempDir()
	rootDir := filepath.Join(tempDir, "large_root")
	_ = os.MkdirAll(rootDir, 0755)

	// Create 20 files
	for i := 0; i < 20; i++ {
		p := filepath.Join(rootDir, fmt.Sprintf("file_%02d.txt", i))
		_ = os.WriteFile(p, []byte(fmt.Sprintf("content_%d", i)), 0644)
	}

	cpPath := filepath.Join(tempDir, "resumable_cp.json")
	// Batch size of 5 with yield duration to simulate cancellation
	scanner, _ := NewChronosScanner([]string{rootDir}, cpPath, 5, 2*time.Millisecond)

	// Cancel context quickly to simulate interruption
	ctxCancel, cancel := context.WithTimeout(context.Background(), 5*time.Millisecond)
	defer cancel()

	cp1, _ := scanner.Scan(ctxCancel, false)
	if cp1.Phase != "PAUSED" && cp1.Phase != "COMPLETED" {
		t.Fatalf("expected PAUSED or COMPLETED, got %s", cp1.Phase)
	}

	// Resume scan to completion
	resumedScanner, _ := NewChronosScanner([]string{rootDir}, cpPath, 5, 0)
	cpFinal, err := resumedScanner.Scan(context.Background(), true)
	if err != nil {
		t.Fatalf("resumed scan failed: %v", err)
	}

	if cpFinal.Phase != "COMPLETED" {
		t.Fatalf("expected COMPLETED phase on resumed scan, got %s", cpFinal.Phase)
	}
	if cpFinal.FilesScanned != 20 {
		t.Fatalf("expected 20 files scanned after resume, got %d", cpFinal.FilesScanned)
	}
	if len(cpFinal.MerkleRoot) != 64 {
		t.Fatalf("expected valid 64-char Merkle root")
	}
}

// TestChronosFIMCompletedCheckpointForcesAFreshFullWalk is the FIND-030 regression test.
//
// After a completed round, resume=true used to set the checkpoint back to RUNNING and walk from
// its LastVisitedPath, which skipped every path up to (and including) that marker. Consecutive
// full scans therefore re-read nothing and returned the old Merkle root, so a file changed after
// the first completed round was never seen.
func TestChronosFIMCompletedCheckpointForcesAFreshFullWalk(t *testing.T) {
	tempDir := t.TempDir()
	rootDir := filepath.Join(tempDir, "root")
	if err := os.MkdirAll(rootDir, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"a.txt", "b.txt", "c.txt"} {
		if err := os.WriteFile(filepath.Join(rootDir, name), []byte("content-"+name), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	cpPath := filepath.Join(tempDir, "checkpoint.json")
	scanner, err := NewChronosScanner([]string{rootDir}, cpPath, 10, 0)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	first, err := scanner.Scan(ctx, true)
	if err != nil {
		t.Fatalf("initial scan failed: %v", err)
	}
	if first.Phase != "COMPLETED" || first.FilesScanned != 3 {
		t.Fatalf("initial scan did not complete: phase=%s files=%d", first.Phase, first.FilesScanned)
	}
	firstRoot := first.MerkleRoot

	// A change after the completed round has to be observed by the next scan.
	if err := os.WriteFile(filepath.Join(rootDir, "b.txt"), []byte("tampered-content"), 0o644); err != nil {
		t.Fatal(err)
	}
	second, err := scanner.Scan(ctx, true)
	if err != nil {
		t.Fatalf("second scan failed: %v", err)
	}
	if second.Phase != "COMPLETED" {
		t.Fatalf("second scan did not complete: %s", second.Phase)
	}
	if second.FilesScanned != 3 {
		t.Fatalf("a new scan after a completed round only re-read %d of 3 files", second.FilesScanned)
	}
	if second.MerkleRoot == firstRoot {
		t.Fatal("a new scan returned the previous, stale Merkle root")
	}
	if second.ScanID == first.ScanID {
		t.Fatal("a new scan reused the completed scan identity")
	}

	// A second consecutive scan must also re-read every file, and being unchanged it has to
	// produce the same root as the previous full walk.
	third, err := scanner.Scan(ctx, true)
	if err != nil {
		t.Fatalf("third scan failed: %v", err)
	}
	if third.FilesScanned != 3 {
		t.Fatalf("consecutive scan re-read only %d of 3 files", third.FilesScanned)
	}
	if third.MerkleRoot != second.MerkleRoot {
		t.Fatalf("an unchanged tree produced a different root: %s vs %s", third.MerkleRoot, second.MerkleRoot)
	}

	// The same rule holds for a checkpoint that a previous process left COMPLETED on disk.
	reopened, err := NewChronosScanner([]string{rootDir}, cpPath, 10, 0)
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := reopened.LoadCheckpoint()
	if err != nil || loaded == nil || loaded.Phase != "COMPLETED" {
		t.Fatalf("expected a completed checkpoint on disk: %+v err=%v", loaded, err)
	}
	if err := os.WriteFile(filepath.Join(rootDir, "c.txt"), []byte("changed-after-restart"), 0o644); err != nil {
		t.Fatal(err)
	}
	fresh, err := reopened.Scan(ctx, true)
	if err != nil {
		t.Fatalf("scan after restart failed: %v", err)
	}
	if fresh.FilesScanned != 3 {
		t.Fatalf("a persisted completed checkpoint was resumed instead of re-walked: files=%d", fresh.FilesScanned)
	}
	if fresh.MerkleRoot == third.MerkleRoot {
		t.Fatal("a persisted completed checkpoint produced the stale Merkle root")
	}
}

// TestChronosFIMRejectsPlaintextCheckpoint covers the strict storage contract: the checkpoint's
// AEAD binding is its only authenticity proof, so an unencrypted document must not be resumed.
// The scanner starts a fresh full walk instead and replaces the file with a sealed one.
func TestChronosFIMRejectsPlaintextCheckpoint(t *testing.T) {
	tempDir := t.TempDir()
	rootDir := filepath.Join(tempDir, "root")
	if err := os.MkdirAll(rootDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(rootDir, "a.txt"), []byte("content"), 0o644); err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(tempDir, "storage.key")
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, key, 0o600); err != nil {
		t.Fatal(err)
	}
	cipher, err := NewStorageCipher(keyPath, "chronos-test")
	if err != nil {
		t.Fatal(err)
	}
	cpPath := filepath.Join(tempDir, "checkpoint.json")
	plaintext, err := json.Marshal(ChronosCheckpoint{ScanID: "SCAN-legacy", Phase: "COMPLETED", FileHashes: map[string]string{}, StartedAt: time.Now().UTC()})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cpPath, plaintext, 0o600); err != nil {
		t.Fatal(err)
	}
	scanner, err := NewChronosScanner([]string{rootDir}, cpPath, 10, 0, cipher)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := scanner.LoadCheckpoint(); err == nil || !strings.Contains(err.Error(), "unencrypted Chronos checkpoint is rejected") {
		t.Fatalf("a plaintext checkpoint was not refused with a clear error: %v", err)
	}
	// The safe recovery is a fresh walk, and persisting it seals the file again.
	cp, err := scanner.Scan(context.Background(), true)
	if err != nil {
		t.Fatalf("a fresh walk after a refused plaintext checkpoint failed: %v", err)
	}
	if cp.Phase != "COMPLETED" || cp.FilesScanned != 1 {
		t.Fatalf("unexpected recovery scan: phase=%s files=%d", cp.Phase, cp.FilesScanned)
	}
	sealed, err := os.ReadFile(cpPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(sealed), encryptedStorageSchema) {
		t.Fatal("the recovered checkpoint was not sealed")
	}
}

// TestChronosFIMResumeSurvivesADeletedMarker covers the other half of the stale-walk defect: a
// resume whose LastVisitedPath disappeared used to skip the whole root and report an empty walk
// as complete.
func TestChronosFIMResumeSurvivesADeletedMarker(t *testing.T) {
	tempDir := t.TempDir()
	rootDir := filepath.Join(tempDir, "root")
	if err := os.MkdirAll(rootDir, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"a.txt", "b.txt", "c.txt"} {
		if err := os.WriteFile(filepath.Join(rootDir, name), []byte("content-"+name), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	cpPath := filepath.Join(tempDir, "checkpoint.json")
	scanner, err := NewChronosScanner([]string{rootDir}, cpPath, 10, 0)
	if err != nil {
		t.Fatal(err)
	}
	// A previous process was interrupted after a file that no longer exists.
	scanner.checkpoint = &ChronosCheckpoint{
		ScanID:           "SCAN-interrupted",
		Roots:            []string{rootDir},
		CurrentRootIndex: 0,
		LastVisitedPath:  filepath.Join(rootDir, "deleted-marker.txt"),
		FileHashes:       map[string]string{},
		Phase:            "PAUSED",
		StartedAt:        time.Now().UTC(),
		UpdatedAt:        time.Now().UTC(),
	}

	cp, err := scanner.Scan(context.Background(), true)
	if err != nil {
		t.Fatalf("resume with a deleted marker failed: %v", err)
	}
	if cp.Phase != "COMPLETED" {
		t.Fatalf("resume with a deleted marker did not complete: %s", cp.Phase)
	}
	if cp.FilesScanned != 3 {
		t.Fatalf("resume with a deleted marker hashed %d of 3 files", cp.FilesScanned)
	}
	if len(cp.FileHashes) != 3 || len(cp.MerkleRoot) != 64 {
		t.Fatalf("the recovered walk is incomplete: hashes=%d root=%q", len(cp.FileHashes), cp.MerkleRoot)
	}
}
