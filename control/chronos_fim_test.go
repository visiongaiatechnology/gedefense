// STATUS: DIAMANT VGT SUPREME
package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
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
