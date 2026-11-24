// STATUS: DIAMANT VGT SUPREME
package main

import (
	"errors"
	"os"
	"sort"
	"sync"
	"time"
)

// V6.3.0 AP-7: persistent, encrypted, TTL-bounded review queue.
//
// Replaces the 4,096-entry in-memory ring data loss with an encrypted,
// TTL-bounded, disk-reserve-aware queue for operator review (false-positive
// triage). Entries carry their finding hash and never leak raw secrets: only the
// already-redacted preview fields of the incident are copied, each bounded.
//
// FAIL-CLOSED CONTRACT
//   - a corrupt/oversized/unauthenticated store activates no entry, refuses
//     every overwrite (the file is preserved for forensics) and reports the
//     condition; it is never silently reset;
//   - below the disk-reserve minimum, new entries are rejected with a reported
//     degradation instead of silently disappearing;
//   - capacity is enforced by entries and by bytes; rejected entries are
//     counted and reported.
//
// DURABILITY
//   - incident ingestion only mutates memory and marks the store dirty;
//   - a background flush on the XDR poll cadence (30 s) does temp+fsync+rename;
//   - a burst that dirties 128 entries forces one flush, so the crash window is
//     bounded in entries as well as in time.

// ReviewQueue is the persistent operator review store.
type ReviewQueue struct {
	mu sync.Mutex

	entries map[string]*ReviewEntry

	loaded  bool
	corrupt bool

	storeDir  string
	storePath string
	cipher    *StorageCipher
	hmacKey   []byte
	sequence  uint64

	dirty     bool
	dirtyAdds int
	lastFlush time.Time
	nextFlush time.Time

	ttl         time.Duration
	maxEntries  int
	maxBytes    int
	diskReserve int64

	rejected       uint64
	deduped        uint64
	expired        uint64
	invalidDropped uint64
	degradedReason string

	lastBindAttempt time.Time
	clock           func() time.Time

	diskCheckedAt time.Time
	diskAvailable bool
}

// NewReviewQueue constructs the queue with its bounded default policy. It
// performs no I/O: the store is bound by the engine maintenance tick or by the
// first operator API read.
func NewReviewQueue() *ReviewQueue {
	return &ReviewQueue{
		entries:     make(map[string]*ReviewEntry),
		ttl:         reviewQueueDefaultTTL,
		maxEntries:  reviewQueueDefaultMaxEntries,
		maxBytes:    reviewQueueDefaultMaxBytes,
		diskReserve: reviewQueueDiskReserveBytes,
	}
}

func (q *ReviewQueue) now() time.Time {
	if q != nil && q.clock != nil {
		return q.clock().UTC()
	}
	return time.Now().UTC()
}

func (q *ReviewQueue) ready() bool {
	if q == nil {
		return false
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.loaded && !q.corrupt
}

func (q *ReviewQueue) state() (loaded, corrupt bool, reason string) {
	if q == nil {
		return false, false, "review queue unavailable"
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.loaded, q.corrupt, q.degradedReason
}

func boundedReviewList(values []string, maxEntries, maxBytes int) []string {
	if len(values) == 0 || maxEntries <= 0 {
		return nil
	}
	if len(values) > maxEntries {
		values = values[:maxEntries]
	}
	out := make([]string, 0, len(values))
	for _, value := range values {
		bounded := boundedPermitText(value, maxBytes)
		if bounded != "" {
			out = append(out, bounded)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// EnqueueIncident adds one bounded entry, deduplicated by finding hash. It
// returns whether the entry was newly added. A rejected entry is counted and
// reported; it is never silently dropped.
func (q *ReviewQueue) EnqueueIncident(incident XDRIncident) (bool, error) {
	if q == nil {
		return false, errors.New("review queue is unavailable")
	}
	now := q.now()
	q.mu.Lock()
	defer q.mu.Unlock()
	if !q.loaded || q.corrupt {
		return false, errors.New("review queue is unavailable or corrupt")
	}
	if !q.diskReserveOK(now) {
		q.rejected++
		q.noteReviewDegradedLocked("disk reserve minimum reached; new review entries are rejected")
		return false, errors.New("disk reserve minimum reached")
	}
	hash := reviewFindingHash(incident)
	if hash == "" || !validReviewEntryID(hash) {
		q.rejected++
		q.noteReviewDegradedLocked("finding hash could not be derived")
		return false, errors.New("finding hash could not be derived")
	}
	if existing, ok := q.entries[hash]; ok {
		existing.RepeatCount++
		existing.LastSeen = now
		existing.Bytes = serializedReviewEntrySize(existing)
		q.deduped++
		q.dirty = true
		return false, nil
	}
	entry := reviewEntryFromIncident(incident, hash, now, q.ttl)
	if entry.Bytes <= 0 || entry.Bytes > reviewQueueEntryMaxBytes {
		q.rejected++
		q.noteReviewDegradedLocked("review entry exceeds the per-entry byte bound")
		return false, errors.New("review entry exceeds the per-entry byte bound")
	}
	if len(q.entries) >= q.maxEntries {
		q.rejected++
		q.noteReviewDegradedLocked("review entry capacity reached; new findings are rejected")
		return false, errors.New("review entry capacity reached")
	}
	if q.usedBytesLocked()+entry.Bytes > q.maxBytes {
		q.rejected++
		q.noteReviewDegradedLocked("review byte budget reached; new findings are rejected")
		return false, errors.New("review byte budget reached")
	}
	q.entries[hash] = entry
	q.dirty = true
	q.dirtyAdds++
	if q.dirtyAdds >= reviewQueueForceFlushAdds {
		if err := q.persistReviewQueueLocked(); err != nil {
			q.noteReviewDegradedLocked("review queue flush failed: " + err.Error())
			return true, err
		}
	}
	return true, nil
}

func (q *ReviewQueue) usedBytesLocked() int {
	total := 0
	for _, entry := range q.entries {
		total += entry.Bytes
	}
	return total
}

// maintain expires TTLs and flushes a dirty store on the bounded cadence.
func (q *ReviewQueue) maintain(now time.Time) (expired int, flushed bool, err error) {
	if q == nil {
		return 0, false, nil
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	if !q.loaded || q.corrupt {
		q.nextFlush = now.Add(reviewQueueFlushInterval)
		return 0, false, nil
	}
	for id, entry := range q.entries {
		if !now.Before(entry.ExpiresAt) {
			delete(q.entries, id)
			expired++
		}
	}
	if expired > 0 {
		q.expired += uint64(expired)
		// Persist the expiry with the next flush so a restart cannot resurrect
		// entries whose TTL has already passed.
		q.dirty = true
	}
	if q.dirty && (!now.Before(q.nextFlush) || q.dirtyAdds >= reviewQueueForceFlushAdds) {
		if err := q.persistReviewQueueLocked(); err != nil {
			q.noteReviewDegradedLocked("review queue flush failed: " + err.Error())
			q.nextFlush = now.Add(reviewQueueFlushInterval)
			return expired, false, err
		}
		flushed = true
	}
	if q.nextFlush.IsZero() || !now.Before(q.nextFlush) {
		q.nextFlush = now.Add(reviewQueueFlushInterval)
	}
	return expired, flushed, nil
}

// nextFlushDue returns the next maintenance deadline.
func (q *ReviewQueue) nextFlushDue(now time.Time) time.Time {
	if q == nil {
		return now.Add(reviewQueueFlushInterval)
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.nextFlush.IsZero() {
		return now.Add(reviewQueueFlushInterval)
	}
	if q.nextFlush.Before(now) {
		return now
	}
	return q.nextFlush
}

// Acknowledge marks one entry reviewed and persists the change.
func (q *ReviewQueue) Acknowledge(id string) (bool, error) {
	return q.mutateEntry(id, func(entry *ReviewEntry, now time.Time) (remove bool) {
		if !entry.Acknowledged {
			entry.Acknowledged = true
			acknowledgedAt := now
			entry.AcknowledgedAt = &acknowledgedAt
		}
		return false
	})
}

// Delete removes one entry and persists the change.
func (q *ReviewQueue) Delete(id string) (bool, error) {
	return q.mutateEntry(id, func(entry *ReviewEntry, now time.Time) bool { return true })
}

func (q *ReviewQueue) mutateEntry(id string, mutate func(entry *ReviewEntry, now time.Time) bool) (bool, error) {
	if q == nil || !validReviewEntryID(id) {
		return false, errors.New("review entry identifier is invalid")
	}
	now := q.now()
	q.mu.Lock()
	defer q.mu.Unlock()
	if !q.loaded || q.corrupt {
		return false, errors.New("review queue is unavailable or corrupt")
	}
	current, exists := q.entries[id]
	if !exists {
		return false, os.ErrNotExist
	}
	candidate := make(map[string]*ReviewEntry, len(q.entries))
	for entryID, entry := range q.entries {
		candidate[entryID] = entry
	}
	updated := *current
	remove := mutate(&updated, now)
	updated.Bytes = serializedReviewEntrySize(&updated)
	if remove {
		delete(candidate, id)
	} else {
		candidate[id] = &updated
	}
	previous := q.entries
	q.entries = candidate
	if err := q.persistReviewQueueLocked(); err != nil {
		q.entries = previous
		q.noteReviewDegradedLocked("review queue flush failed: " + err.Error())
		return false, err
	}
	return true, nil
}

// Report returns the bounded queue projection.
func (q *ReviewQueue) Report() ReviewQueueReport {
	report := ReviewQueueReport{
		MaxEntries: reviewQueueDefaultMaxEntries, MaxBytes: reviewQueueDefaultMaxBytes,
		TTLSeconds: int64(reviewQueueDefaultTTL.Seconds()), DiskReserve: reviewQueueDiskReserveBytes,
	}
	if q == nil {
		return report
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	report.Loaded = q.loaded
	report.StorePath = q.storePath
	report.Corrupt = q.corrupt
	report.Degraded = q.corrupt || q.degradedReason != ""
	report.DegradedReason = q.degradedReason
	report.Entries = len(q.entries)
	report.Bytes = q.usedBytesLocked()
	report.MaxEntries = q.maxEntries
	report.MaxBytes = q.maxBytes
	report.TTLSeconds = int64(q.ttl.Seconds())
	report.DiskReserve = q.diskReserve
	report.Rejected = q.rejected
	report.Deduped = q.deduped
	report.Expired = q.expired
	report.InvalidDropped = q.invalidDropped
	for _, entry := range q.entries {
		if entry.Acknowledged {
			report.Acknowledged++
		}
	}
	if !q.lastFlush.IsZero() {
		lastFlush := q.lastFlush
		report.LastFlush = &lastFlush
	}
	return report
}

// Entries returns a newest-first bounded copy of the queue.
func (q *ReviewQueue) Entries(limit int) []ReviewEntry {
	if q == nil {
		return nil
	}
	if limit <= 0 {
		limit = 100
	}
	if limit > reviewQueueDefaultMaxEntries {
		limit = reviewQueueDefaultMaxEntries
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	out := make([]ReviewEntry, 0, len(q.entries))
	for _, entry := range q.entries {
		copied := *entry
		copied.RuleIDs = append([]string(nil), entry.RuleIDs...)
		copied.Categories = append([]string(nil), entry.Categories...)
		if entry.AcknowledgedAt != nil {
			acknowledgedAt := *entry.AcknowledgedAt
			copied.AcknowledgedAt = &acknowledgedAt
		}
		out = append(out, copied)
	}
	sort.Slice(out, func(left, right int) bool {
		if out[left].Time.Equal(out[right].Time) {
			return out[left].ID < out[right].ID
		}
		return out[left].Time.After(out[right].Time)
	})
	if len(out) > limit {
		out = out[:limit]
	}
	return out
}

// ------------------------------------------------------------------ engine glue
