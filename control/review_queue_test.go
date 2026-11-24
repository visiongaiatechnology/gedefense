// STATUS: DIAMANT VGT SUPREME
package main

// V6.3.0 AP-7: persistent review-queue test corpus.
//
// Covers capacity, TTL, disk-reserve rejection, HMAC/AES-GCM round-trip,
// deduplication, ack/delete persistence, corrupt-store fail-closed behaviour and
// the bounded entry/byte contract.

import (
	"bytes"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func reviewTestIncident(index int) XDRIncident {
	return XDRIncident{
		ID:       "incident-" + string(rune('a'+index)),
		Time:     time.Date(2026, 11, 24, 12, index, 0, 0, time.UTC),
		Severity: "high", Score: 120, ResponseScore: 100,
		PID: 1000 + index, UID: 1000, Process: "process-" + string(rune('a'+index)),
		Executable: "/usr/bin/process-" + string(rune('a'+index)), Parent: "/usr/bin/systemd",
		CommandPreview: "process --flag value",
		RuleIDs:        []string{"XDR.TEMP_EXEC", "KD.LINUX.BPF_LOAD"},
		Categories:     []string{"origin", "kernel"},
		Summary:        "review queue test finding", Decision: "alert", Action: "none",
	}
}

func bindTestReviewQueue(t *testing.T, dir string, clocks ...func() time.Time) *ReviewQueue {
	t.Helper()
	queue := NewReviewQueue()
	// Install a test clock BEFORE binding: bindReviewQueue derives the first
	// maintenance deadline from the queue clock, so injecting the clock
	// afterwards would leave a real-time deadline and make maintenance timing
	// depend on the wall clock (the 2026-11-24 12:00 UTC fixed-clock flake).
	if len(clocks) > 0 && clocks[0] != nil {
		queue.clock = clocks[0]
	}
	if err := queue.bindReviewQueue(reviewQueueBinding{StorageDir: dir, DiskReserve: 1 << 20}); err != nil {
		t.Fatalf("bind review queue: %v", err)
	}
	return queue
}

func reviewQueueFlush(t *testing.T, queue *ReviewQueue, now time.Time) {
	t.Helper()
	if _, _, err := queue.maintain(now.Add(reviewQueueFlushInterval + time.Second)); err != nil {
		t.Fatalf("review queue maintenance flush: %v", err)
	}
}

func TestReviewQueueRoundTripDedupeAndTTL(t *testing.T) {
	dir := t.TempDir()
	now := time.Date(2026, 11, 24, 12, 0, 0, 0, time.UTC)
	queue := bindTestReviewQueue(t, dir, func() time.Time { return now })

	first := reviewTestIncident(0)
	if added, err := queue.EnqueueIncident(first); err != nil || !added {
		t.Fatalf("enqueue first finding: added=%t err=%v", added, err)
	}
	// The same canonical finding must deduplicate, not duplicate.
	if added, err := queue.EnqueueIncident(first); err != nil || added {
		t.Fatalf("dedupe failed: added=%t err=%v", added, err)
	}
	second := reviewTestIncident(1)
	if added, err := queue.EnqueueIncident(second); err != nil || !added {
		t.Fatalf("enqueue second finding: added=%t err=%v", added, err)
	}
	report := queue.Report()
	if report.Entries != 2 || report.Deduped != 1 || report.Bytes <= 0 {
		t.Fatalf("unexpected queue report after enqueue: %+v", report)
	}
	entries := queue.Entries(10)
	if len(entries) != 2 {
		t.Fatalf("expected two review entries, got %d", len(entries))
	}
	for _, entry := range entries {
		if entry.Process != "process-a" {
			continue
		}
		if entry.RepeatCount != 2 {
			t.Fatalf("deduplicated entry lost its repeat count: %+v", entry)
		}
	}

	reviewQueueFlush(t, queue, now)
	reloaded := bindTestReviewQueue(t, dir)
	report = reloaded.Report()
	if report.Entries != 2 || report.Bytes <= 0 {
		t.Fatalf("review queue round-trip lost entries: %+v", report)
	}

	// TTL: after the default 7-day window the entries expire and the expiry is
	// persisted by the maintenance flush.
	expired, flushed, err := reloaded.maintain(now.Add(reviewQueueDefaultTTL + time.Hour))
	if err != nil {
		t.Fatalf("expire review entries: %v", err)
	}
	if expired != 2 || !flushed {
		t.Fatalf("expected both entries to expire and flush, got expired=%d flushed=%t", expired, flushed)
	}
	again := bindTestReviewQueue(t, dir)
	if report := again.Report(); report.Entries != 0 {
		t.Fatalf("expired review entries were restored: %+v", report)
	}
}

func TestReviewQueueCipherEnvelopeHidesFindingContent(t *testing.T) {
	keyDir := t.TempDir()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("random storage key: %v", err)
	}
	keyPath := filepath.Join(keyDir, "storage-master.key")
	if err := os.WriteFile(keyPath, key, 0o600); err != nil {
		t.Fatalf("write storage key: %v", err)
	}
	cipher, err := NewStorageCipher(keyPath, "ap7-test-node")
	if err != nil || cipher == nil {
		t.Fatalf("storage cipher: %v", err)
	}
	dir := t.TempDir()
	queue := NewReviewQueue()
	if err := queue.bindReviewQueue(reviewQueueBinding{StorageDir: dir, Cipher: cipher, DiskReserve: 1 << 20}); err != nil {
		t.Fatalf("bind encrypted review queue: %v", err)
	}
	incident := reviewTestIncident(0)
	incident.Process = "unique-plaintext-process-marker"
	if _, err := queue.EnqueueIncident(incident); err != nil {
		t.Fatalf("enqueue encrypted finding: %v", err)
	}
	now := time.Now().UTC()
	reviewQueueFlush(t, queue, now)
	data, err := os.ReadFile(filepath.Join(dir, reviewQueueStoreFileName))
	if err != nil {
		t.Fatalf("read encrypted review store: %v", err)
	}
	if !bytes.Contains(data, []byte(encryptedStorageSchema)) {
		t.Fatalf("review store is not an AES-GCM envelope: %.80s", data)
	}
	if bytes.Contains(data, []byte("unique-plaintext-process-marker")) ||
		bytes.Contains(data, []byte("XDR.TEMP_EXEC")) {
		t.Fatal("review store leaked finding content in plaintext")
	}
	reloaded := NewReviewQueue()
	if err := reloaded.bindReviewQueue(reviewQueueBinding{StorageDir: dir, Cipher: cipher, DiskReserve: 1 << 20}); err != nil {
		t.Fatalf("reload encrypted review queue: %v", err)
	}
	if report := reloaded.Report(); report.Entries != 1 {
		t.Fatalf("encrypted review queue round-trip failed: %+v", report)
	}
}

func TestReviewQueueCapacityAndDiskReserveRejections(t *testing.T) {
	dir := t.TempDir()
	queue := NewReviewQueue()
	if err := queue.bindReviewQueue(reviewQueueBinding{StorageDir: dir, MaxEntries: 2, DiskReserve: 1 << 20}); err != nil {
		t.Fatalf("bind capped review queue: %v", err)
	}
	for index := 0; index < 2; index++ {
		if _, err := queue.EnqueueIncident(reviewTestIncident(index)); err != nil {
			t.Fatalf("enqueue within capacity: %v", err)
		}
	}
	third := reviewTestIncident(5)
	if added, err := queue.EnqueueIncident(third); err == nil || added {
		t.Fatal("review queue accepted an entry beyond its entry capacity")
	}
	report := queue.Report()
	if report.Entries != 2 || report.Rejected != 1 || !report.Degraded {
		t.Fatalf("capacity rejection was not counted/reported: %+v", report)
	}

	reserveDir := t.TempDir()
	reserveQueue := NewReviewQueue()
	if err := reserveQueue.bindReviewQueue(reviewQueueBinding{StorageDir: reserveDir, DiskReserve: 1 << 62}); err != nil {
		t.Fatalf("bind reserve-limited review queue: %v", err)
	}
	if _, err := reserveQueue.EnqueueIncident(reviewTestIncident(0)); err == nil {
		t.Fatal("review queue accepted an entry below the disk-reserve minimum")
	}
	report = reserveQueue.Report()
	if report.Rejected != 1 || !report.Degraded || report.Entries != 0 {
		t.Fatalf("disk-reserve rejection was not reported: %+v", report)
	}
}

func TestReviewQueueAckAndDeleteArePersisted(t *testing.T) {
	dir := t.TempDir()
	now := time.Now().UTC()
	queue := bindTestReviewQueue(t, dir, func() time.Time { return now })
	incident := reviewTestIncident(0)
	if _, err := queue.EnqueueIncident(incident); err != nil {
		t.Fatalf("enqueue finding: %v", err)
	}
	reviewQueueFlush(t, queue, now)
	entries := queue.Entries(1)
	if len(entries) != 1 {
		t.Fatalf("expected one entry, got %d", len(entries))
	}
	id := entries[0].ID
	if changed, err := queue.Acknowledge(id); err != nil || !changed {
		t.Fatalf("acknowledge entry: changed=%t err=%v", changed, err)
	}
	reloaded := bindTestReviewQueue(t, dir)
	if report := reloaded.Report(); report.Acknowledged != 1 {
		t.Fatalf("acknowledgement was not persisted: %+v", report)
	}
	if changed, err := reloaded.Delete(id); err != nil || !changed {
		t.Fatalf("delete entry: changed=%t err=%v", changed, err)
	}
	final := bindTestReviewQueue(t, dir)
	if report := final.Report(); report.Entries != 0 {
		t.Fatalf("deleted review entry was restored: %+v", report)
	}
	if _, err := final.Acknowledge(strings.Repeat("0", 64)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("unknown review entry acknowledge did not report not-found: %v", err)
	}
}

func TestReviewQueueCorruptStoreFailsClosed(t *testing.T) {
	dir := t.TempDir()
	queue := bindTestReviewQueue(t, dir)
	incident := reviewTestIncident(0)
	if _, err := queue.EnqueueIncident(incident); err != nil {
		t.Fatalf("enqueue finding: %v", err)
	}
	reviewQueueFlush(t, queue, time.Now().UTC())
	storePath := filepath.Join(dir, reviewQueueStoreFileName)
	if err := os.WriteFile(storePath, []byte("{not an authenticated review store"), 0o600); err != nil {
		t.Fatalf("corrupt review store: %v", err)
	}
	corrupted, err := os.ReadFile(storePath)
	if err != nil {
		t.Fatalf("read corrupt store: %v", err)
	}
	reopened := NewReviewQueue()
	if bindErr := reopened.bindReviewQueue(reviewQueueBinding{StorageDir: dir, DiskReserve: 1 << 20}); bindErr == nil {
		t.Fatal("corrupt review store was accepted")
	}
	report := reopened.Report()
	if !report.Corrupt || report.Entries != 0 || !report.Degraded {
		t.Fatalf("corrupt review store did not fail closed: %+v", report)
	}
	if _, enqueueErr := reopened.EnqueueIncident(incident); enqueueErr == nil {
		t.Fatal("corrupt review store accepted a new finding")
	}
	preserved, err := os.ReadFile(storePath)
	if err != nil || !bytes.Equal(preserved, corrupted) {
		t.Fatalf("corrupt review store evidence was overwritten: %v", err)
	}
}

func TestReviewQueueEntryFieldsAreBounded(t *testing.T) {
	dir := t.TempDir()
	queue := bindTestReviewQueue(t, dir)
	incident := reviewTestIncident(0)
	incident.CommandPreview = strings.Repeat("A", 4000)
	incident.Process = strings.Repeat("P", 2000)
	incident.RuleIDs = make([]string, 100)
	for index := range incident.RuleIDs {
		incident.RuleIDs[index] = "RULE." + strings.Repeat("X", 200)
	}
	if _, err := queue.EnqueueIncident(incident); err != nil {
		t.Fatalf("enqueue oversized finding: %v", err)
	}
	entries := queue.Entries(1)
	if len(entries) != 1 {
		t.Fatalf("expected one bounded entry, got %d", len(entries))
	}
	entry := entries[0]
	if len(entry.CommandPreview) > reviewQueueMaxPreviewBytes+3 {
		t.Fatalf("command preview not bounded: %d bytes", len(entry.CommandPreview))
	}
	if len(entry.Process) > 128+3 {
		t.Fatalf("process name not bounded: %d bytes", len(entry.Process))
	}
	if len(entry.RuleIDs) > reviewQueueMaxRules {
		t.Fatalf("rule list not bounded: %d entries", len(entry.RuleIDs))
	}
	if entry.Bytes <= 0 || entry.Bytes > reviewQueueEntryMaxBytes {
		t.Fatalf("entry byte accounting is invalid: %d", entry.Bytes)
	}
	if report := queue.Report(); report.Bytes > report.MaxBytes {
		t.Fatalf("queue byte budget exceeded: %+v", report)
	}
}

func TestReviewQueueFindingHashIsStableAndDiscriminating(t *testing.T) {
	first := reviewTestIncident(0)
	second := first
	second.ID = "another-random-incident-id"
	second.Time = first.Time.Add(37 * time.Minute)
	if reviewFindingHash(first) != reviewFindingHash(second) {
		t.Fatal("finding hash depends on the random incident id or clock")
	}
	discriminating := first
	discriminating.RuleIDs = []string{"XDR.SOMETHING_ELSE"}
	if reviewFindingHash(first) == reviewFindingHash(discriminating) {
		t.Fatal("finding hash ignores the rule set")
	}
	reordered := first
	reordered.RuleIDs = []string{first.RuleIDs[1], first.RuleIDs[0]}
	if reviewFindingHash(first) != reviewFindingHash(reordered) {
		t.Fatal("finding hash depends on rule ordering")
	}
}
