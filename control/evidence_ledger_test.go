// STATUS: DIAMANT VGT SUPREME

package main

import (
	"os"
	"path/filepath"
	"strings"
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
