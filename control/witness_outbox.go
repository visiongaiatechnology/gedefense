package main

// POINT 4 / P4-T2: the bounded, authenticated witness outbox
// (docs/POINT4-WITNESS.md §4).
//
// The outbox is the only place an unacknowledged checkpoint survives a restart.
// It is an AEAD document (StorageCipher purpose "witness-outbox", path-bound AAD)
// whose entries carry a monotonic local sequence, the signed checkpoint, the
// attempt counter and the next attempt time. It is bounded by bytes and entries;
// a full or corrupt outbox fails closed: no new checkpoint is created and the
// engine records witness.outbox_full instead of dropping evidence. A restart
// authenticates the document, keeps pending entries and prunes acknowledged ones.

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

const (
	witnessOutboxSchema = "vgt-gedefense-witness-outbox-v1"
	// witnessOutboxPurpose binds the AEAD key and the AAD to this store.
	witnessOutboxPurpose = "witness-outbox"
	// witnessOutboxMaxDocumentBytes caps the plaintext document a restart will
	// decode, independent of the operator byte bound (which bounds the file).
	witnessOutboxMaxDocumentBytes = 128 << 20
)

var errWitnessOutboxFull = errors.New("witness outbox is full")

// witnessOutboxEntry is one encrypted queue entry. State is "pending" while the
// witness has not acknowledged it (acked entries are pruned immediately).
type witnessOutboxEntry struct {
	LocalSeq      uint64            `json:"local_seq"`
	Checkpoint    WitnessCheckpoint `json:"checkpoint"`
	Attempts      int               `json:"attempts"`
	NextAttemptAt time.Time         `json:"next_attempt_at"`
	State         string            `json:"state"`
}

type witnessOutboxDocument struct {
	Schema  string               `json:"schema"`
	Entries []witnessOutboxEntry `json:"entries"`
}

type witnessOutbox struct {
	mu         sync.Mutex
	path       string
	cipher     *StorageCipher
	maxBytes   int64
	maxEntries int
	now        func() time.Time
	sequence   uint64
	entries    []witnessOutboxEntry
	bytes      int64
	corrupt    bool
}

// newWitnessOutbox loads and authenticates the outbox. A missing file is an empty
// outbox; a document that cannot be authenticated is returned as a corrupt,
// fail-closed outbox together with the error, so the engine can still report why
// it refuses to create checkpoints.
func newWitnessOutbox(path string, cipher *StorageCipher, maxBytes int64, maxEntries int, now func() time.Time) (*witnessOutbox, error) {
	if !filepath.IsAbs(path) {
		return nil, errors.New("witness outbox path must be absolute")
	}
	if cipher == nil {
		return nil, errors.New("witness outbox requires the storage cipher")
	}
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	outbox := &witnessOutbox{
		path: path, cipher: cipher, maxBytes: maxBytes, maxEntries: maxEntries, now: now,
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return outbox, fmt.Errorf("witness outbox directory: %w", err)
	}
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return outbox, nil
	}
	if err != nil {
		outbox.corrupt = true
		return outbox, fmt.Errorf("witness outbox is unreadable: %w", err)
	}
	if int64(len(raw)) > maxBytes && maxBytes > 0 {
		// The store is larger than the configured bound. That is not tampering and
		// not a reason to discard entries: report full so no new checkpoint is
		// queued, keep everything that is there.
		outbox.bytes = int64(len(raw))
		outbox.corrupt = true
		return outbox, errWitnessOutboxFull
	}
	if len(raw) == 0 || len(raw) > witnessOutboxMaxDocumentBytes {
		outbox.corrupt = true
		return outbox, errors.New("witness outbox document is empty or oversized")
	}
	plaintext, _, err := cipher.Decrypt(path, witnessOutboxPurpose, raw, nil)
	if err != nil {
		outbox.corrupt = true
		return outbox, fmt.Errorf("witness outbox authentication failed: %w", err)
	}
	if len(plaintext) > witnessOutboxMaxDocumentBytes {
		outbox.corrupt = true
		return outbox, errors.New("witness outbox plaintext is oversized")
	}
	var document witnessOutboxDocument
	decoder := json.NewDecoder(bytes.NewReader(plaintext))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&document); err != nil || document.Schema != witnessOutboxSchema {
		outbox.corrupt = true
		return outbox, errors.New("witness outbox document is malformed")
	}
	entries := make([]witnessOutboxEntry, 0, len(document.Entries))
	var sequence uint64
	for _, entry := range document.Entries {
		if entry.LocalSeq == 0 || entry.LocalSeq <= sequence {
			outbox.corrupt = true
			return outbox, errors.New("witness outbox local sequence is not strictly monotonic")
		}
		if entry.State != "pending" {
			continue
		}
		if err := ValidateWitnessCheckpoint(entry.Checkpoint); err != nil {
			outbox.corrupt = true
			return outbox, errors.New("witness outbox checkpoint is not valid")
		}
		sequence = entry.LocalSeq
		entries = append(entries, entry)
	}
	if len(entries) > maxEntries && maxEntries > 0 {
		outbox.corrupt = true
		return outbox, errors.New("witness outbox exceeds its entry bound")
	}
	outbox.entries = entries
	outbox.sequence = sequence
	outbox.bytes = int64(len(raw))
	return outbox, nil
}

// persistLocked seals and atomically replaces the document. Memory is only
// advanced after the new document is durable, so a failed write loses nothing.
func (o *witnessOutbox) persistLocked(entries []witnessOutboxEntry) error {
	document := witnessOutboxDocument{Schema: witnessOutboxSchema, Entries: entries}
	plaintext, err := json.Marshal(document)
	if err != nil {
		return err
	}
	sealed, err := o.cipher.Encrypt(o.path, witnessOutboxPurpose, 0, plaintext)
	if err != nil {
		return err
	}
	sealed = append(sealed, '\n')
	if o.maxBytes > 0 && int64(len(sealed)) > o.maxBytes {
		return errWitnessOutboxFull
	}
	if err := atomicWriteFile(o.path, sealed, 0o600); err != nil {
		return err
	}
	o.bytes = int64(len(sealed))
	return nil
}

// enqueue appends a signed checkpoint. The checkpoint is durable before it is
// visible in memory; a full outbox refuses instead of dropping evidence.
func (o *witnessOutbox) enqueue(checkpoint WitnessCheckpoint) (uint64, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.corrupt {
		return 0, errWitnessOutboxFull
	}
	if o.maxEntries > 0 && len(o.entries)+1 > o.maxEntries {
		return 0, errWitnessOutboxFull
	}
	next := o.sequence + 1
	entry := witnessOutboxEntry{
		LocalSeq: next, Checkpoint: checkpoint, Attempts: 0,
		NextAttemptAt: o.now(), State: "pending",
	}
	candidate := append(append([]witnessOutboxEntry(nil), o.entries...), entry)
	if err := o.persistLocked(candidate); err != nil {
		return 0, err
	}
	o.entries = candidate
	o.sequence = next
	return next, nil
}

// pending returns a copy of the pending entries in local-sequence order.
func (o *witnessOutbox) pending() []witnessOutboxEntry {
	o.mu.Lock()
	defer o.mu.Unlock()
	out := append([]witnessOutboxEntry(nil), o.entries...)
	sort.Slice(out, func(i, j int) bool { return out[i].LocalSeq < out[j].LocalSeq })
	return out
}

// pendingFirst returns the oldest pending entry.
func (o *witnessOutbox) pendingFirst() (witnessOutboxEntry, bool) {
	o.mu.Lock()
	defer o.mu.Unlock()
	var oldest *witnessOutboxEntry
	for i := range o.entries {
		if oldest == nil || o.entries[i].LocalSeq < oldest.LocalSeq {
			entry := o.entries[i]
			oldest = &entry
		}
	}
	if oldest == nil {
		return witnessOutboxEntry{}, false
	}
	return *oldest, true
}

// nextDue returns the oldest pending entry whose attempt time has arrived.
func (o *witnessOutbox) nextDue(now time.Time) (witnessOutboxEntry, bool) {
	o.mu.Lock()
	defer o.mu.Unlock()
	for _, entry := range o.entries {
		if entry.NextAttemptAt.IsZero() || !entry.NextAttemptAt.After(now) {
			return entry, true
		}
	}
	return witnessOutboxEntry{}, false
}

// replaceCheckpoint updates the checkpoint of one pending entry (a fresh
// challenge requires a fresh signature). The local sequence never changes.
func (o *witnessOutbox) replaceCheckpoint(localSeq uint64, checkpoint WitnessCheckpoint) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	index := -1
	for i := range o.entries {
		if o.entries[i].LocalSeq == localSeq {
			index = i
			break
		}
	}
	if index < 0 {
		return errors.New("witness outbox entry is no longer pending")
	}
	candidate := append([]witnessOutboxEntry(nil), o.entries...)
	candidate[index].Checkpoint = checkpoint
	if err := o.persistLocked(candidate); err != nil {
		return err
	}
	o.entries = candidate
	return nil
}

// recordAttempt persists the attempt counter and the next attempt time. A failed
// write leaves the previous state in force; the checkpoint stays queued.
func (o *witnessOutbox) recordAttempt(localSeq uint64, attempts int, next time.Time) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	index := -1
	for i := range o.entries {
		if o.entries[i].LocalSeq == localSeq {
			index = i
			break
		}
	}
	if index < 0 {
		return errors.New("witness outbox entry is no longer pending")
	}
	candidate := append([]witnessOutboxEntry(nil), o.entries...)
	candidate[index].Attempts = attempts
	candidate[index].NextAttemptAt = next
	if err := o.persistLocked(candidate); err != nil {
		return err
	}
	o.entries = candidate
	return nil
}

// ack removes one acknowledged entry (ack-prune) and persists the new document.
func (o *witnessOutbox) ack(localSeq uint64) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	candidate := make([]witnessOutboxEntry, 0, len(o.entries))
	for _, entry := range o.entries {
		if entry.LocalSeq != localSeq {
			candidate = append(candidate, entry)
		}
	}
	if len(candidate) == len(o.entries) {
		return errors.New("witness outbox entry is no longer pending")
	}
	if err := o.persistLocked(candidate); err != nil {
		return err
	}
	o.entries = candidate
	return nil
}

func (o *witnessOutbox) depth() int {
	o.mu.Lock()
	defer o.mu.Unlock()
	return len(o.entries)
}

func (o *witnessOutbox) storedBytes() int64 {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.bytes
}

func (o *witnessOutbox) full() bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.corrupt {
		return true
	}
	if o.maxEntries > 0 && len(o.entries) >= o.maxEntries {
		return true
	}
	return o.maxBytes > 0 && o.bytes >= o.maxBytes
}

func (o *witnessOutbox) isCorrupt() bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.corrupt
}

func (o *witnessOutbox) lastSequence() uint64 {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.sequence
}

func (o *witnessOutbox) oldestAt() time.Time {
	o.mu.Lock()
	defer o.mu.Unlock()
	var oldest time.Time
	for _, entry := range o.entries {
		createdAt, err := time.Parse(time.RFC3339, entry.Checkpoint.CreatedAt)
		if err != nil {
			continue
		}
		if oldest.IsZero() || createdAt.Before(oldest) {
			oldest = createdAt
		}
	}
	return oldest
}
