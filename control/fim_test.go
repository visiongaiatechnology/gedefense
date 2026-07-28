// STATUS: DIAMANT VGT SUPREME
package main

import (
	"os"
	"path/filepath"
	"testing"
)

func newTestFIM(t *testing.T, roots []string) *FIMEngine {
	t.Helper()
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "storage.key")
	if err := os.WriteFile(keyPath, make([]byte, 32), 0o600); err != nil {
		t.Fatal(err)
	}
	storage, err := NewStorageCipher(keyPath, "fim-test")
	if err != nil {
		t.Fatal(err)
	}
	engine, err := NewFIMEngine(roots, filepath.Join(dir, "fim-baseline.enc"), storage)
	if err != nil {
		t.Fatal(err)
	}
	return engine
}

func TestFIMBaselineDetectsContentAndModeTamper(t *testing.T) {
	watched := filepath.Join(t.TempDir(), "watched.conf")
	if err := os.WriteFile(watched, []byte("trusted\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	engine := newTestFIM(t, []string{watched})
	if status, err := engine.CreateBaseline(); err != nil || status.BaselineCount != 1 {
		t.Fatalf("baseline status=%+v err=%v", status, err)
	}
	if scan, err := engine.Scan(); err != nil || scan.Verified != 1 {
		t.Fatalf("clean scan=%+v err=%v", scan, err)
	}
	if err := os.WriteFile(watched, []byte("tampered\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	scan, err := engine.Scan()
	if err != nil {
		t.Fatal(err)
	}
	if scan.Tampered != 1 || engine.Status().Health != "TAMPERED" {
		t.Fatalf("tamper not detected: %+v status=%+v", scan, engine.Status())
	}
}

func TestFIMRejectsSymlinkAndAuthenticatesBaseline(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	link := filepath.Join(dir, "link")
	if err := os.WriteFile(target, []byte("data"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	engine := newTestFIM(t, []string{link})
	if _, err := engine.CreateBaseline(); err == nil {
		t.Fatal("symlink baseline unexpectedly accepted")
	}

	watched := filepath.Join(t.TempDir(), "watched")
	if err := os.WriteFile(watched, []byte("trusted"), 0o600); err != nil {
		t.Fatal(err)
	}
	engine = newTestFIM(t, []string{watched})
	if _, err := engine.CreateBaseline(); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(engine.baselinePath)
	if err != nil {
		t.Fatal(err)
	}
	raw[len(raw)-1] ^= 1
	if err := os.WriteFile(engine.baselinePath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	reloaded, err := NewFIMEngine([]string{watched}, engine.baselinePath, engine.storage)
	if err != nil {
		t.Fatal(err)
	}
	if reloaded.Status().Health != "QUARANTINED" {
		t.Fatalf("tampered baseline not quarantined: %+v", reloaded.Status())
	}
}

func TestFIMRejectsFilesystemRoot(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "storage.key")
	if err := os.WriteFile(keyPath, make([]byte, 32), 0o600); err != nil {
		t.Fatal(err)
	}
	storage, err := NewStorageCipher(keyPath, "fim-test")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewFIMEngine([]string{string(filepath.Separator)}, filepath.Join(dir, "fim.enc"), storage); err == nil {
		t.Fatal("filesystem-root target unexpectedly accepted")
	}
}
