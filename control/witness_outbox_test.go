package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func isWitnessOutboxFull(err error) bool { return errors.Is(err, errWitnessOutboxFull) }

// POINT 4 / P4-T2: the authenticated outbox contract (docs/POINT4-WITNESS.md §4).
// The outbox is the only survive-a-restart store for an unacknowledged
// checkpoint; a full or corrupt document must fail closed instead of silently
// dropping evidence.

func witnessTestStorageCipher(t *testing.T) *StorageCipher {
	t.Helper()
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "storage.key")
	if err := os.WriteFile(keyPath, make([]byte, 32), 0o600); err != nil {
		t.Fatal(err)
	}
	cipher, err := NewStorageCipher(keyPath, "test-node")
	if err != nil {
		t.Fatal(err)
	}
	return cipher
}

func witnessOutboxCheckpoint(t *testing.T, marker string) WitnessCheckpoint {
	t.Helper()
	ledger, _ := evidenceFixture(t)
	return witnessFixtureCheckpoint(t, ledger, func(checkpoint *WitnessCheckpoint) {
		checkpoint.CheckpointID = strings.Repeat(marker, 16)
	})
}

func witnessOutboxFixture(t *testing.T, maxBytes int64, maxEntries int) (*witnessOutbox, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "witness", "outbox.enc")
	outbox, err := newWitnessOutbox(path, witnessTestStorageCipher(t), maxBytes, maxEntries, func() time.Time {
		return time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC)
	})
	if err != nil {
		t.Fatalf("outbox construction: %v", err)
	}
	return outbox, path
}

func TestWitnessOutboxEnqueueAckPruneAndRestart(t *testing.T) {
	outbox, path := witnessOutboxFixture(t, 4<<20, 1024)
	first, err := outbox.enqueue(witnessOutboxCheckpoint(t, "ab"))
	if err != nil || first != 1 {
		t.Fatalf("first enqueue: seq=%d err=%v", first, err)
	}
	second, err := outbox.enqueue(witnessOutboxCheckpoint(t, "cd"))
	if err != nil || second != 2 {
		t.Fatalf("second enqueue: seq=%d err=%v", second, err)
	}
	if outbox.depth() != 2 || outbox.lastSequence() != 2 {
		t.Fatalf("outbox state depth=%d seq=%d", outbox.depth(), outbox.lastSequence())
	}
	if err := outbox.ack(first); err != nil {
		t.Fatalf("ack: %v", err)
	}
	if outbox.depth() != 1 {
		t.Fatalf("ack did not prune the acknowledged entry: depth=%d", outbox.depth())
	}
	// A restart authenticates the document, keeps the pending entry and continues
	// the local sequence monotonically.
	reloaded, err := newWitnessOutbox(path, outbox.cipher, 4<<20, 1024, time.Now)
	if err != nil {
		t.Fatalf("restart: %v", err)
	}
	if reloaded.depth() != 1 || reloaded.lastSequence() != 2 {
		t.Fatalf("restart lost the pending entry: depth=%d seq=%d", reloaded.depth(), reloaded.lastSequence())
	}
	entry, ok := reloaded.nextDue(time.Now())
	if !ok || entry.LocalSeq != second || entry.Checkpoint.CheckpointID != strings.Repeat("cd", 16) {
		t.Fatalf("restart returned the wrong pending entry: %+v", entry)
	}
	third, err := reloaded.enqueue(witnessOutboxCheckpoint(t, "ef"))
	if err != nil || third != 3 {
		t.Fatalf("enqueue after restart: seq=%d err=%v", third, err)
	}
}

func TestWitnessOutboxBoundsAndFailClosedCondition(t *testing.T) {
	entried, _ := witnessOutboxFixture(t, 4<<20, 1024)
	if err := entried.ack(99); err == nil {
		t.Fatal("acking an unknown entry was accepted")
	}
	if err := entried.recordAttempt(99, 1, time.Now()); err == nil {
		t.Fatal("recording an attempt for an unknown entry was accepted")
	}

	full, _ := witnessOutboxFixture(t, 4<<20, 1)
	if _, err := full.enqueue(witnessOutboxCheckpoint(t, "ab")); err != nil {
		t.Fatalf("first enqueue: %v", err)
	}
	if _, err := full.enqueue(witnessOutboxCheckpoint(t, "cd")); err == nil {
		t.Fatal("the entry bound did not refuse a second checkpoint")
	} else if !isWitnessOutboxFull(err) {
		t.Fatalf("the entry bound failed with the wrong error: %v", err)
	}
	if !full.full() {
		t.Fatal("a full outbox does not report full")
	}

	bytesBound, _ := witnessOutboxFixture(t, 512, 1024)
	if _, err := bytesBound.enqueue(witnessOutboxCheckpoint(t, "ab")); err == nil {
		t.Fatal("the byte bound did not refuse the checkpoint")
	}
}

func TestWitnessOutboxCorruptionFailsClosed(t *testing.T) {
	outbox, path := witnessOutboxFixture(t, 4<<20, 1024)
	if _, err := outbox.enqueue(witnessOutboxCheckpoint(t, "ab")); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// Flip one ciphertext character so the AEAD must refuse the document.
	index := len(raw) / 2
	if raw[index] == 'A' {
		raw[index] = 'B'
	} else {
		raw[index] = 'A'
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	corrupt, err := newWitnessOutbox(path, outbox.cipher, 4<<20, 1024, time.Now)
	if err == nil || corrupt == nil || !corrupt.isCorrupt() {
		t.Fatalf("a tampered outbox was accepted: err=%v", err)
	}
	if _, err := corrupt.enqueue(witnessOutboxCheckpoint(t, "cd")); err == nil {
		t.Fatal("a corrupt outbox accepted a new checkpoint")
	}

	plaintextPath := filepath.Join(t.TempDir(), "witness", "outbox.enc")
	if err := os.MkdirAll(filepath.Dir(plaintextPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(plaintextPath, []byte(`{"schema":"vgt-gedefense-witness-outbox-v1","entries":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := newWitnessOutbox(plaintextPath, outbox.cipher, 4<<20, 1024, time.Now); err == nil {
		t.Fatal("a plaintext outbox document was accepted while a master key is configured")
	}
}

func TestWitnessOutboxSurvivesCrashTempAndPersistsAttempts(t *testing.T) {
	outbox, path := witnessOutboxFixture(t, 4<<20, 1024)
	// A crash leaves a .tmp staging file behind; the authenticated document is the
	// authority and a new write removes the stale staging file.
	if err := os.WriteFile(path+".tmp", []byte("partial"), 0o600); err != nil {
		t.Fatal(err)
	}
	sequence, err := outbox.enqueue(witnessOutboxCheckpoint(t, "ab"))
	if err != nil {
		t.Fatalf("enqueue with a stale temp file: %v", err)
	}
	if _, err := os.Stat(path + ".tmp"); !os.IsNotExist(err) {
		t.Fatal("the stale staging file was left behind")
	}
	next := time.Date(2026, 11, 15, 13, 0, 0, 0, time.UTC)
	if err := outbox.recordAttempt(sequence, 2, next); err != nil {
		t.Fatalf("record attempt: %v", err)
	}
	reloaded, err := newWitnessOutbox(path, outbox.cipher, 4<<20, 1024, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	entry, ok := reloaded.nextDue(time.Now())
	if !ok || entry.Attempts != 2 || !entry.NextAttemptAt.Equal(next) {
		t.Fatalf("the attempt state did not survive the restart: %+v", entry)
	}
	if _, ok := reloaded.nextDue(next.Add(-time.Minute)); ok {
		t.Fatal("an entry was due before its backoff expired")
	}
}
