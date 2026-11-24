// AP-9 / S09 — high-water register and Last-Known-Good shadow corpus: atomic
// persistence, MAC authentication, corruption fail-closed behaviour, rotation
// and ownership/mode checks.
package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func tufTestRegister(epoch uint64, now time.Time) TUFHighWaterRegister {
	return TUFHighWaterRegister{
		Schema:              tufHighWaterSchema,
		Epoch:               epoch,
		SnapshotSHA256:      tufTestDigest("snapshot"),
		ContentSHA256:       tufTestDigest("content"),
		LastKnownGoodSHA256: tufTestDigest("last-known-good"),
		ActivatedAt:         tufTestCanonicalTime(now),
		Reason:              "feed-generation-activated",
	}
}

func tufTestCommitRegister(t *testing.T, dir string, epoch uint64) TUFHighWaterStore {
	t.Helper()
	store := newTUFHighWaterStore(dir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := store.Commit(tufTestRegister(epoch, tufTestNow())); err != nil {
		t.Fatalf("commit register: %v", err)
	}
	return store
}

func TestTufHighWaterStoreRoundTripAndMode(t *testing.T) {
	dir := t.TempDir()
	store := newTUFHighWaterStore(dir)
	register, exists, err := store.Load()
	if err != nil || exists {
		t.Fatalf("fresh store load = %+v exists=%v err=%v", register, exists, err)
	}
	want := tufTestRegister(7, tufTestNow())
	if err := store.Commit(want); err != nil {
		t.Fatalf("commit: %v", err)
	}
	got, exists, err := store.Load()
	if err != nil || !exists {
		t.Fatalf("load after commit: exists=%v err=%v", exists, err)
	}
	if got.Epoch != want.Epoch || got.SnapshotSHA256 != want.SnapshotSHA256 ||
		got.ContentSHA256 != want.ContentSHA256 || got.LastKnownGoodSHA256 != want.LastKnownGoodSHA256 ||
		got.ActivatedAt != want.ActivatedAt || got.Reason != want.Reason || got.MAC == "" {
		t.Fatalf("loaded register = %+v, want %+v", got, want)
	}
	for _, name := range []string{tufHighWaterFile, tufHighWaterKeyFile} {
		path := filepath.Join(dir, name)
		info, err := os.Lstat(path)
		if err != nil {
			t.Fatalf("stat %s: %v", name, err)
		}
		if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
			t.Fatalf("%s mode = %v, want regular 0600", name, info.Mode())
		}
		if stat, ok := info.Sys().(*syscall.Stat_t); ok && int(stat.Uid) != os.Geteuid() {
			t.Fatalf("%s owner uid = %d, want %d", name, stat.Uid, os.Geteuid())
		}
	}
	tmpFiles, err := filepath.Glob(filepath.Join(dir, "*.tmp"))
	if err != nil {
		t.Fatal(err)
	}
	if len(tmpFiles) != 0 {
		t.Fatalf("atomic writer left staging files behind: %v", tmpFiles)
	}
	raw, err := os.ReadFile(filepath.Join(dir, tufHighWaterFile))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.ContainsAny(raw, "\n\r") {
		t.Fatalf("register is not canonical single-line JSON: %q", raw)
	}
}

func TestTufHighWaterStoreRotation(t *testing.T) {
	dir := t.TempDir()
	store := tufTestCommitRegister(t, dir, 3)
	if err := store.Commit(tufTestRegister(9, tufTestNow().Add(time.Hour))); err != nil {
		t.Fatalf("rotation commit: %v", err)
	}
	got, exists, err := store.Load()
	if err != nil || !exists {
		t.Fatalf("rotation load: exists=%v err=%v", exists, err)
	}
	if got.Epoch != 9 {
		t.Fatalf("rotated epoch = %d, want 9", got.Epoch)
	}
}

func TestTufHighWaterStoreCorruptionsFailClosed(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(t *testing.T, dir string)
	}{
		{"tampered-epoch", func(t *testing.T, dir string) {
			path := filepath.Join(dir, tufHighWaterFile)
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			patched := bytes.Replace(raw, []byte(`"epoch":7`), []byte(`"epoch":8`), 1)
			if bytes.Equal(patched, raw) {
				t.Fatal("test did not patch the epoch field")
			}
			if err := os.WriteFile(path, patched, 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{"loosened-mode", func(t *testing.T, dir string) {
			if err := os.Chmod(filepath.Join(dir, tufHighWaterFile), 0o644); err != nil {
				t.Fatal(err)
			}
		}},
		{"missing-key", func(t *testing.T, dir string) {
			if err := os.Remove(filepath.Join(dir, tufHighWaterKeyFile)); err != nil {
				t.Fatal(err)
			}
		}},
		{"missing-register", func(t *testing.T, dir string) {
			if err := os.Remove(filepath.Join(dir, tufHighWaterFile)); err != nil {
				t.Fatal(err)
			}
		}},
		{"invalid-json", func(t *testing.T, dir string) {
			if err := os.WriteFile(filepath.Join(dir, tufHighWaterFile), []byte("not json"), 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{"register-is-directory", func(t *testing.T, dir string) {
			if err := os.Remove(filepath.Join(dir, tufHighWaterFile)); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(filepath.Join(dir, tufHighWaterFile), 0o700); err != nil {
				t.Fatal(err)
			}
		}},
	}
	for _, testCase := range cases {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			dir := t.TempDir()
			tufTestCommitRegister(t, dir, 7)
			testCase.mutate(t, dir)
			_, _, err := newTUFHighWaterStore(dir).Load()
			if err == nil {
				t.Fatalf("%s: corrupt register was accepted", testCase.name)
			}
			if reason := tufErrorReason(err); reason != TUFReasonStateCorrupt {
				t.Fatalf("%s: reason = %q, want %q", testCase.name, reason, TUFReasonStateCorrupt)
			}
		})
	}
}

func TestTufLastKnownGoodRestore(t *testing.T) {
	manager := NewFeedManager(FeedConfig{}, t.TempDir())
	manager.mu.Lock()
	state := manager.feedStates["feodo-c2"]
	state.LastGoodItems = []string{"203.0.113.7/32", "198.51.100.9/32"}
	state.LastGoodCount = 2
	state.LastGoodGen = 4
	state.LastGoodAt = tufTestNow()
	state.ManifestVersion = 3
	state.ManifestVerified = true
	snapshot := manager.snapshotLastKnownGoodLocked()
	state.LastGoodItems = []string{"2001:db8::9/128"}
	state.LastGoodCount = 1
	state.LastGoodGen = 5
	state.ManifestVersion = 4
	state.ManifestVerified = false
	state.LastError = "rejected"
	manager.restoreLastKnownGoodLocked(snapshot)
	restored := manager.feedStates["feodo-c2"]
	manager.mu.Unlock()
	if len(restored.LastGoodItems) != 2 || restored.LastGoodItems[0] != "203.0.113.7/32" ||
		restored.LastGoodCount != 2 || restored.LastGoodGen != 4 || restored.ManifestVersion != 3 ||
		!restored.ManifestVerified || restored.LastError != "" {
		t.Fatalf("last-known-good restore = %+v", restored)
	}
}

func TestTufStatusProjectsPersistedRegister(t *testing.T) {
	stateDir := filepath.Join(t.TempDir(), "state")
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	store := newTUFHighWaterStore(stateDir)
	register := tufTestRegister(5, tufTestNow())
	if err := store.Commit(register); err != nil {
		t.Fatalf("commit register: %v", err)
	}
	keys := make([]string, 0, 3)
	for index := 0; index < 3; index++ {
		publicKey, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		keys = append(keys, base64.StdEncoding.EncodeToString(publicKey))
	}
	manager := NewFeedManager(FeedConfig{RequireSignedManifest: true, TrustedSigningKeys: keys}, stateDir)
	status := manager.TUFStatus()
	if status.Capability != TUFCapabilityAvailable {
		t.Fatalf("capability = %q (%s)", status.Capability, status.Reason)
	}
	if status.Epoch != 5 || status.LastKnownGoodSHA256 != register.LastKnownGoodSHA256 {
		t.Fatalf("startup projection = %+v, want epoch 5 and the persisted LKG", status)
	}
	if status.StateError != "" {
		t.Fatalf("healthy register projected a state error: %s", status.StateError)
	}

	// A corrupt register must be reported at startup and never silently reset.
	if err := os.WriteFile(filepath.Join(stateDir, tufHighWaterFile), []byte("broken"), 0o600); err != nil {
		t.Fatal(err)
	}
	corruptManager := NewFeedManager(FeedConfig{RequireSignedManifest: true, TrustedSigningKeys: keys}, stateDir)
	corruptStatus := corruptManager.TUFStatus()
	if corruptStatus.StateError == "" {
		t.Fatal("corrupt high-water register was not reported")
	}
	if corruptStatus.Epoch != 0 {
		t.Fatalf("corrupt register projected epoch %d, want no silently adopted epoch", corruptStatus.Epoch)
	}
	if !strings.Contains(corruptStatus.StateError, TUFReasonStateCorrupt) {
		t.Fatalf("state error does not carry the stable reason: %q", corruptStatus.StateError)
	}
}
