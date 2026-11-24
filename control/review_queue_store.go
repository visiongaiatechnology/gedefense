package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"
)

type reviewQueueHMACEnvelope struct {
	Schema   string `json:"schema"`
	Sequence uint64 `json:"sequence"`
	Payload  string `json:"payload"`
	MAC      string `json:"mac"`
}

var reviewQueueHMACDomain = []byte(reviewQueueHMACDomainString)

// bindReviewQueue binds the queue to its store and loads the persisted entries.
func (q *ReviewQueue) bindReviewQueue(binding reviewQueueBinding) error {
	if q == nil {
		return errors.New("review queue is unavailable")
	}
	if err := ensurePrivateStoreDir(binding.StorageDir); err != nil {
		return err
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	q.lastBindAttempt = q.now()
	q.storeDir = binding.StorageDir
	q.storePath = filepath.Join(binding.StorageDir, reviewQueueStoreFileName)
	q.cipher = binding.Cipher
	if binding.TTL > 0 {
		q.ttl = binding.TTL
	}
	if q.ttl <= 0 {
		q.ttl = reviewQueueDefaultTTL
	}
	if q.ttl > reviewQueueMaxTTL {
		q.ttl = reviewQueueMaxTTL
	}
	q.maxEntries = binding.MaxEntries
	if q.maxEntries <= 0 || q.maxEntries > reviewQueueDefaultMaxEntries {
		q.maxEntries = reviewQueueDefaultMaxEntries
	}
	q.maxBytes = binding.MaxBytes
	if q.maxBytes <= 0 || q.maxBytes > reviewQueueDefaultMaxBytes {
		q.maxBytes = reviewQueueDefaultMaxBytes
	}
	q.diskReserve = binding.DiskReserve
	if q.diskReserve <= 0 {
		q.diskReserve = reviewQueueDiskReserveBytes
	}
	if q.cipher == nil {
		key, err := loadOrCreatePrivateKey(filepath.Join(binding.StorageDir, reviewQueueKeyFileName), permitStoreKeyBytes)
		if err != nil {
			q.corrupt = true
			q.degradedReason = "review queue HMAC key unavailable: " + err.Error()
			return err
		}
		q.hmacKey = key
	} else {
		q.hmacKey = nil
	}
	return q.loadReviewQueueLocked()
}

// noteReviewDegradedLocked records the degraded reason once per transition.
func (q *ReviewQueue) noteReviewDegradedLocked(reason string) {
	q.degradedReason = reason
}

// loadReviewQueueLocked opens and re-validates every persisted entry.
func (q *ReviewQueue) loadReviewQueueLocked() error {
	now := q.now()
	q.entries = make(map[string]*ReviewEntry)
	q.loaded = false
	q.corrupt = false
	q.degradedReason = ""
	q.invalidDropped = 0
	if q.storePath == "" {
		q.corrupt = true
		q.degradedReason = "review queue store path is unavailable"
		return errors.New(q.degradedReason)
	}
	if err := checkPrivateStoreFile(q.storePath, reviewQueueStoreReadBytes); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			q.loaded = true
			q.nextFlush = now.Add(reviewQueueFlushInterval)
			return nil
		}
		q.corrupt = true
		q.degradedReason = "review queue store integrity check failed: " + err.Error()
		return errors.New(q.degradedReason)
	}
	data, err := os.ReadFile(q.storePath)
	if err != nil {
		q.corrupt = true
		q.degradedReason = "review queue store read failed: " + err.Error()
		return errors.New(q.degradedReason)
	}
	var payload []byte
	if q.cipher != nil {
		plaintext, _, openErr := q.cipher.Decrypt(q.storePath, reviewQueuePurpose, data, nil)
		if openErr != nil {
			q.corrupt = true
			q.degradedReason = "review queue authentication failed: " + openErr.Error()
			return errors.New(q.degradedReason)
		}
		payload = plaintext
	} else {
		payload, err = reviewQueueOpenHMAC(q.hmacKey, data)
		if err != nil {
			q.corrupt = true
			q.degradedReason = err.Error()
			return err
		}
	}
	var document reviewQueueStoreDocument
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&document); err != nil {
		q.corrupt = true
		q.degradedReason = "review queue document is malformed"
		return errors.New(q.degradedReason)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		q.corrupt = true
		q.degradedReason = "review queue document contains trailing data"
		return errors.New(q.degradedReason)
	}
	if document.Schema != reviewQueueSchema {
		q.corrupt = true
		q.degradedReason = "review queue document schema is invalid"
		return errors.New(q.degradedReason)
	}
	if document.Sequence > q.sequence {
		q.sequence = document.Sequence
	}
	type loadCandidate struct {
		entry *ReviewEntry
	}
	candidates := make([]loadCandidate, 0, len(document.Entries))
	seen := make(map[string]struct{}, len(document.Entries))
	for _, raw := range document.Entries {
		entry, decodeErr := decodeReviewEntry(raw, now)
		if decodeErr != nil {
			q.invalidDropped++
			continue
		}
		if _, duplicate := seen[entry.ID]; duplicate {
			q.invalidDropped++
			continue
		}
		if !now.Before(entry.ExpiresAt) {
			q.expired++
			continue
		}
		seen[entry.ID] = struct{}{}
		candidates = append(candidates, loadCandidate{entry: entry})
	}
	// Keep the newest bounded window: the store can never grow without bound,
	// even after an operator raised a previous limit.
	sort.Slice(candidates, func(left, right int) bool {
		if candidates[left].entry.FirstSeen.Equal(candidates[right].entry.FirstSeen) {
			return candidates[left].entry.ID < candidates[right].entry.ID
		}
		return candidates[left].entry.FirstSeen.Before(candidates[right].entry.FirstSeen)
	})
	totalBytes := 0
	kept := make([]*ReviewEntry, 0, len(candidates))
	for index := len(candidates) - 1; index >= 0; index-- {
		entry := candidates[index].entry
		if len(kept) >= q.maxEntries {
			q.invalidDropped++
			continue
		}
		if totalBytes+entry.Bytes > q.maxBytes {
			q.invalidDropped++
			continue
		}
		totalBytes += entry.Bytes
		kept = append(kept, entry)
	}
	for _, entry := range kept {
		q.entries[entry.ID] = entry
	}
	q.loaded = true
	q.lastFlush = now
	q.nextFlush = now.Add(reviewQueueFlushInterval)
	return nil
}

// reviewQueueSealHMAC authenticates the payload and sequence number.
func reviewQueueSealHMAC(key []byte, sequence uint64, payload []byte) ([]byte, error) {
	if len(key) != permitStoreKeyBytes {
		return nil, errors.New("review queue HMAC key is invalid")
	}
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(reviewQueueHMACDomain)
	_, _ = mac.Write(sequenceBytes(sequence))
	_, _ = mac.Write(payload)
	envelope := reviewQueueHMACEnvelope{
		Schema:   reviewQueueHMACSchema,
		Sequence: sequence,
		Payload:  base64.RawURLEncoding.EncodeToString(payload),
		MAC:      hex.EncodeToString(mac.Sum(nil)),
	}
	return json.Marshal(envelope)
}

// reviewQueueOpenHMAC authenticates the fallback envelope.
func reviewQueueOpenHMAC(key []byte, data []byte) ([]byte, error) {
	var envelope reviewQueueHMACEnvelope
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&envelope); err != nil {
		return nil, errors.New("review queue envelope is malformed")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, errors.New("review queue envelope contains trailing data")
	}
	if envelope.Schema != reviewQueueHMACSchema {
		return nil, errors.New("review queue envelope schema is invalid")
	}
	payload, err := base64.RawURLEncoding.DecodeString(envelope.Payload)
	if err != nil {
		return nil, errors.New("review queue payload encoding is invalid")
	}
	supplied, err := hex.DecodeString(envelope.MAC)
	if err != nil || len(supplied) != sha256.Size || len(key) != permitStoreKeyBytes {
		return nil, errors.New("review queue MAC is malformed")
	}
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(reviewQueueHMACDomain)
	_, _ = mac.Write(sequenceBytes(envelope.Sequence))
	_, _ = mac.Write(payload)
	if !hmac.Equal(supplied, mac.Sum(nil)) {
		return nil, errors.New("review queue authentication failed")
	}
	return payload, nil
}

// decodeReviewEntry strictly decodes and bounds one persisted entry.
func decodeReviewEntry(raw []byte, now time.Time) (*ReviewEntry, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || len(trimmed) > reviewQueueEntryMaxBytes*2 {
		return nil, errors.New("review entry exceeds its size bound")
	}
	decoder := json.NewDecoder(bytes.NewReader(trimmed))
	decoder.DisallowUnknownFields()
	var entry ReviewEntry
	if err := decoder.Decode(&entry); err != nil {
		return nil, errors.New("review entry is malformed")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, errors.New("review entry contains trailing data")
	}
	if !validReviewEntryID(entry.ID) || entry.FindingHash != entry.ID {
		return nil, errors.New("review entry identifier is invalid")
	}
	if entry.Time.IsZero() || entry.FirstSeen.IsZero() || entry.LastSeen.IsZero() || entry.ExpiresAt.IsZero() {
		return nil, errors.New("review entry time is missing")
	}
	if entry.Score < 0 || entry.Score > 10000 || entry.RepeatCount < 1 || entry.RepeatCount > 1_000_000 {
		return nil, errors.New("review entry counters are invalid")
	}
	if len(entry.RuleIDs) > reviewQueueMaxRules || len(entry.Categories) > reviewQueueMaxCategories {
		return nil, errors.New("review entry list exceeds its bound")
	}
	for _, value := range append(append([]string{}, entry.RuleIDs...), entry.Categories...) {
		if len(value) > 128 {
			return nil, errors.New("review entry list member exceeds its bound")
		}
	}
	for _, value := range []string{
		entry.Severity, entry.Decision, entry.Action, entry.Process, entry.Executable,
		entry.Parent, entry.Remote, entry.CommandPreview, entry.PermitTrustLevel, entry.PermitID,
	} {
		if len(value) > reviewQueueMaxFieldBytes {
			return nil, errors.New("review entry field exceeds its bound")
		}
	}
	entry.Time = entry.Time.UTC()
	entry.FirstSeen = entry.FirstSeen.UTC()
	entry.LastSeen = entry.LastSeen.UTC()
	entry.ExpiresAt = entry.ExpiresAt.UTC()
	entry.Bytes = serializedReviewEntrySize(&entry)
	if entry.Bytes <= 0 || entry.Bytes > reviewQueueEntryMaxBytes {
		return nil, errors.New("review entry serialized size is invalid")
	}
	return &entry, nil
}

// validReviewEntryID requires a lowercase SHA-256 hex finding hash.
func validReviewEntryID(id string) bool {
	if len(id) != sha256.Size*2 {
		return false
	}
	for _, character := range id {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}

// serializedReviewEntrySize computes the canonical size of one entry without
// recursing into the Bytes field itself.
func serializedReviewEntrySize(entry *ReviewEntry) int {
	copyEntry := *entry
	copyEntry.Bytes = 0
	encoded, err := json.Marshal(copyEntry)
	if err != nil {
		return 0
	}
	return len(encoded)
}

// reviewFindingHash derives the stable dedupe hash from the incident's
// canonical finding fields (never from the random incident ID or the clock).
func reviewFindingHash(incident XDRIncident) string {
	rules := append([]string(nil), incident.RuleIDs...)
	sort.Strings(rules)
	categories := append([]string(nil), incident.Categories...)
	sort.Strings(categories)
	canonical := struct {
		RuleIDs        []string `json:"rule_ids"`
		Categories     []string `json:"categories"`
		Severity       string   `json:"severity"`
		Score          int      `json:"score"`
		Decision       string   `json:"decision"`
		Action         string   `json:"action"`
		Process        string   `json:"process"`
		Executable     string   `json:"executable"`
		Parent         string   `json:"parent"`
		Remote         string   `json:"remote"`
		CommandPreview string   `json:"command_preview"`
		CommandSHA256  string   `json:"command_sha256"`
	}{
		RuleIDs: rules, Categories: categories,
		Severity: strings.ToLower(strings.TrimSpace(incident.Severity)), Score: incident.Score,
		Decision: incident.Decision, Action: incident.Action,
		Process: incident.Process, Executable: incident.Executable, Parent: incident.Parent,
		Remote: incident.Remote, CommandPreview: incident.CommandPreview,
		CommandSHA256: incident.CommandSHA256,
	}
	encoded, err := json.Marshal(canonical)
	if err != nil {
		// encoding/json cannot fail on this fixed struct; keep the caller safe.
		encoded = []byte(incident.Summary)
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}

// reviewEntryFromIncident builds the bounded entry from the already-redacted
// incident fields.
func reviewEntryFromIncident(incident XDRIncident, hash string, now time.Time, ttl time.Duration) *ReviewEntry {
	when := incident.Time.UTC()
	if incident.Time.IsZero() {
		when = now
	}
	entry := &ReviewEntry{
		ID: hash, FindingHash: hash, Time: when, FirstSeen: now, LastSeen: now, RepeatCount: 1,
		Severity:       boundedPermitText(strings.ToLower(incident.Severity), 32),
		Score:          incident.Score,
		Decision:       boundedPermitText(incident.Decision, 64),
		Action:         boundedPermitText(incident.Action, 64),
		Process:        boundedPermitText(incident.Process, 128),
		Executable:     boundedPermitText(incident.Executable, 256),
		Parent:         boundedPermitText(incident.Parent, 256),
		Remote:         boundedPermitText(incident.Remote, 128),
		CommandPreview: boundedPermitText(incident.CommandPreview, reviewQueueMaxPreviewBytes),
		RuleIDs:        boundedReviewList(incident.RuleIDs, reviewQueueMaxRules, 96),
		Categories:     boundedReviewList(incident.Categories, reviewQueueMaxCategories, 64),
		ExpiresAt:      now.Add(ttl),
	}
	if incident.Permit != nil {
		entry.PermitTrustLevel = boundedPermitText(incident.Permit.TrustLevel, 32)
		entry.PermitID = boundedPermitText(incident.Permit.PermitID, 64)
	}
	entry.Bytes = serializedReviewEntrySize(entry)
	return entry
}

// diskReserveOK checks the free-space minimum with a short cache so a burst of
// incidents does not statfs once per event.
func (q *ReviewQueue) diskReserveOK(now time.Time) bool {
	if q.diskReserve <= 0 {
		return true
	}
	if !q.diskCheckedAt.IsZero() && now.Sub(q.diskCheckedAt) < 10*time.Second {
		return q.diskAvailable
	}
	var stat syscall.Statfs_t
	available := false
	if err := syscall.Statfs(q.storeDir, &stat); err == nil {
		availableBytes := uint64(stat.Bavail) * uint64(stat.Bsize)
		available = availableBytes >= uint64(q.diskReserve)
	}
	q.diskCheckedAt = now
	q.diskAvailable = available
	return available
}

// persistReviewQueueLocked writes the whole bounded store atomically.
func (q *ReviewQueue) persistReviewQueueLocked() error {
	if q.corrupt {
		return errors.New("review queue is corrupt; refusing to overwrite forensic evidence")
	}
	if q.storePath == "" {
		return errors.New("review queue store path is unavailable")
	}
	now := q.now()
	ids := make([]string, 0, len(q.entries))
	for id := range q.entries {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(left, right int) bool {
		leftEntry, rightEntry := q.entries[ids[left]], q.entries[ids[right]]
		if leftEntry.FirstSeen.Equal(rightEntry.FirstSeen) {
			return leftEntry.ID < rightEntry.ID
		}
		return leftEntry.FirstSeen.Before(rightEntry.FirstSeen)
	})
	rawEntries := make([]json.RawMessage, 0, len(ids))
	for _, id := range ids {
		entry := *q.entries[id]
		entry.Bytes = 0
		encoded, err := json.Marshal(entry)
		if err != nil {
			return fmt.Errorf("review entry serialization: %w", err)
		}
		if len(encoded) > reviewQueueEntryMaxBytes {
			return errors.New("review entry exceeds the serialized byte bound")
		}
		rawEntries = append(rawEntries, encoded)
	}
	sequence := q.sequence + 1
	if sequence == 0 {
		sequence = 1
	}
	document := reviewQueueStoreDocument{Schema: reviewQueueSchema, Sequence: sequence, Entries: rawEntries}
	plaintext, err := json.Marshal(document)
	if err != nil {
		return fmt.Errorf("review queue serialization: %w", err)
	}
	var encrypted []byte
	if q.cipher != nil {
		encrypted, err = q.cipher.Encrypt(q.storePath, reviewQueuePurpose, sequence, plaintext)
		if err != nil {
			return fmt.Errorf("review queue encryption: %w", err)
		}
	} else {
		encrypted, err = reviewQueueSealHMAC(q.hmacKey, sequence, plaintext)
		if err != nil {
			return err
		}
	}
	if err := writePrivateFileAtomic(q.storePath, encrypted); err != nil {
		return err
	}
	q.sequence = sequence
	q.dirty = false
	q.dirtyAdds = 0
	q.lastFlush = now
	q.nextFlush = now.Add(reviewQueueFlushInterval)
	// A successful flush clears a capacity/degradation reason that only
	// described a previous transient condition; corruption is never cleared
	// here (a corrupt queue never reaches this path).
	q.degradedReason = ""
	q.diskCheckedAt = time.Time{}
	return nil
}
