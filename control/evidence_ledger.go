// STATUS: DIAMANT VGT SUPREME

package main

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const (
	evidenceRecordVersion = 1
	evidenceDomain        = "VGT-GEDEFENSE-EVIDENCE-V1\x00"
	evidenceRecentLimit   = 4096
)

type EvidenceRecord struct {
	Version   int       `json:"version"`
	Sequence  uint64    `json:"sequence"`
	ID        string    `json:"id"`
	Time      time.Time `json:"time"`
	Severity  string    `json:"severity"`
	Kind      string    `json:"kind"`
	Source    string    `json:"source"`
	Message   string    `json:"message"`
	Target    string    `json:"target,omitempty"`
	RequestID string    `json:"request_id,omitempty"`
	PrevHash  string    `json:"prev_hash"`
	Hash      string    `json:"hash"`
	Signature string    `json:"signature"`
}

type evidencePayload struct {
	Version   int       `json:"version"`
	Sequence  uint64    `json:"sequence"`
	ID        string    `json:"id"`
	Time      time.Time `json:"time"`
	Severity  string    `json:"severity"`
	Kind      string    `json:"kind"`
	Source    string    `json:"source"`
	Message   string    `json:"message"`
	Target    string    `json:"target,omitempty"`
	RequestID string    `json:"request_id,omitempty"`
	PrevHash  string    `json:"prev_hash"`
}

type evidenceCheckpoint struct {
	Version  int    `json:"version"`
	Sequence uint64 `json:"sequence"`
	HeadHash string `json:"head_hash"`
}

// errEvidenceBudgetExhausted is a capacity condition, not an integrity condition.
//
// The two were previously the same thing: reaching the size budget set integrityErr,
// which quarantines the ledger permanently and - through State.RecordEvidence - reports
// XDR as degraded with "mandatory evidence ledger unavailable". A full ledger is not a
// corrupt ledger, and treating it as one had a second, worse effect: integrityErr is
// sticky, so raising the administrable budget afterwards could not clear it. The
// operator's own retention control became unusable at exactly the moment it was needed.
var errEvidenceBudgetExhausted = errors.New("evidence ledger size budget exhausted")

type EvidenceStatus struct {
	Enabled bool `json:"enabled"`
	Healthy bool `json:"healthy"`
	// Full reports that the retention budget is reached. It is deliberately separate
	// from Healthy: a full ledger is still a valid chain and must not be presented as a
	// damaged one.
	Full        bool   `json:"full,omitempty"`
	Records     uint64 `json:"records"`
	HeadHash    string `json:"head_hash,omitempty"`
	PublicKey   string `json:"public_key,omitempty"`
	Error       string `json:"error,omitempty"`
	MaxBytes    int64  `json:"max_bytes,omitempty"`
	StoredBytes int64  `json:"stored_bytes,omitempty"`
	// VerifyScope names how much of the chain has been verified: "empty", "tail" for the
	// bounded startup check, "partial:n/m" while the incremental watermark catches up, or
	// "full" once the history has been covered end to end. Startup cannot pay for the whole
	// history, so a surface that reports a healthy chain has to be able to say which of these
	// it means instead of implying the strongest one.
	VerifyScope string `json:"verify_scope,omitempty"`
	// FullVerifiedAt is when the whole history was last covered.
	FullVerifiedAt *time.Time `json:"full_verified_at,omitempty"`
}

type EvidenceLedger struct {
	mu           sync.Mutex
	path         string
	headPath     string
	keyPath      string
	publicPath   string
	privateKey   ed25519.PrivateKey
	publicKey    ed25519.PublicKey
	crypto       *StorageCipher
	sequence     uint64
	headHash     string
	expectedSize int64
	maxBytes     int64
	integrityErr error
	// budgetExhausted tracks the capacity condition separately from integrityErr, so a
	// full ledger never quarantines and never has to be cleared by hand.
	budgetExhausted bool
	recent          []EvidenceRecord
	policy          EvidenceFabricSettings
	// verifyScope names how much of the chain this process has actually verified, and
	// fullVerifiedAt records when the whole history was last covered end to end. Startup
	// verifies an authenticated checkpoint plus a bounded tail, so a status surface has to be
	// able to say which of the two happened instead of implying the stronger one.
	verifyScope    string
	fullVerifiedAt *time.Time
	// incrementalChunk bounds one background verification pass. It is a field rather than a
	// constant so a test can exercise the chunking without writing tens of thousands of records.
	incrementalChunk uint64
}

func NewEvidenceLedger(path, keyPath, storageKeyPath, nodeName string, maxBytes int64) (*EvidenceLedger, error) {
	if !filepath.IsAbs(path) || !filepath.IsAbs(keyPath) {
		return nil, errors.New("evidence ledger and signing key paths must be absolute")
	}
	if maxBytes < 1<<20 {
		maxBytes = 64 << 20
	}
	for _, candidate := range []string{path, path + ".head", keyPath, keyPath + ".pub"} {
		if err := os.MkdirAll(filepath.Dir(candidate), 0o700); err != nil {
			return nil, err
		}
		if err := rejectSymlink(candidate); err != nil {
			return nil, err
		}
	}
	storage, err := NewStorageCipher(storageKeyPath, nodeName)
	if err != nil {
		return nil, fmt.Errorf("evidence encryption: %w", err)
	}
	publicKey, privateKey, err := loadOrCreateEvidenceKey(keyPath, storage)
	if err != nil {
		return nil, err
	}
	// Construction must not reject a ledger the running service would accept.
	//
	// The administrable budget is not known yet at this point - the settings document is
	// applied afterwards - so checking against the constructor argument alone refused a
	// ledger that had legitimately grown under a raised policy. The failure was fatal and
	// happened before anything could report it: NewEvidenceLedger returned an error, the
	// caller exited, and the service would not start until the file was cut back by hand.
	// The operator was locked out by the very budget they had been told to raise.
	//
	// The order is deliberate: permissive at construction, strict at runtime, where the
	// effective budget is finally known. A budget that is later lowered is still enforced
	// by the append path against effectiveMaxBytesLocked().
	constructionBudget := maxBytes
	if fallback := defaultIntegrityFabricSettings(Config{}).Evidence.MaxBytes; fallback > constructionBudget {
		constructionBudget = fallback
	}
	// The effective budget starts as this constructor budget, floored the same way.
	//
	// The policy used to be seeded with the compiled-in default alone, and
	// effectiveMaxBytesLocked prefers the policy whenever it is set. A ledger built with
	// the operator's raised budget therefore still enforced 64 MiB: the administration
	// surface reported 256 MiB, the ledger stopped at 64 MiB, and once the file reached it
	// every append failed while Status() still called the ledger healthy. The platform
	// silently stopped recording evidence - the incident log and the forensic ledger both
	// went quiet - and every start logged "evidence ledger size budget exhausted" without
	// naming the disagreement that caused it. The two budgets have to start out equal.
	fabricDefaults := defaultIntegrityFabricSettings(Config{}).Evidence
	fabricDefaults.MaxBytes = constructionBudget
	ledger := &EvidenceLedger{
		path: path, headPath: path + ".head", keyPath: keyPath, publicPath: keyPath + ".pub",
		privateKey: privateKey, publicKey: publicKey, crypto: storage, maxBytes: maxBytes,
		policy:           fabricDefaults,
		recent:           make([]EvidenceRecord, 0, 256),
		incrementalChunk: evidenceIncrementalChunkRecords,
	}
	if err := ledger.writeOrVerifyPublicKey(); err != nil {
		return nil, err
	}
	// A rotation that a crash interrupted is completed before anything is verified. The marker
	// means the sealed segment is already archived and its manifest matches, so only the swap is
	// missing; refusing to start over a half-finished file operation would repeat the failure
	// this change came from.
	if err := finishInterruptedEvidenceRotation(path, ledger.headPath, storage); err != nil {
		ledger.integrityErr = err
		return ledger, nil
	}
	// Startup verifies the authenticated checkpoint and a bounded tail of the chain.
	//
	// The whole history is covered by the incremental watermark pass after readiness, and by
	// the operator on demand. Paying for the history here meant the service could not start at
	// all once the ledger was large - the platform lost its dashboard and its release gate
	// because a forensic log had grown.
	head, sequence, recent, size, scope, verifyErr := verifyEvidenceFilesBounded(path, ledger.headPath, publicKey, storage, constructionBudget, evidenceRecentLimit)
	ledger.headHash = head
	ledger.sequence = sequence
	ledger.recent = recent
	ledger.expectedSize = size
	ledger.integrityErr = verifyErr
	ledger.verifyScope = scope
	if scope == "full" && sequence > 0 && verifyErr == nil {
		// The bounded window covered the whole chain, so coverage is complete and the
		// authenticated watermark may say so. Later passes then only have to cover what is
		// written after this point instead of walking the history again.
		if err := ledger.writeWatermark(evidenceWatermark{Version: evidenceRecordVersion, Sequence: sequence, HeadHash: head}); err != nil {
			ledger.verifyScope = "tail"
		} else {
			now := time.Now().UTC()
			ledger.fullVerifiedAt = &now
		}
	}
	return ledger, nil
}

func loadOrCreateEvidenceKey(path string, storage *StorageCipher) (ed25519.PublicKey, ed25519.PrivateKey, error) {
	data, err := readBoundedPrivateFile(path, 128<<10)
	if err == nil {
		if storage != nil {
			data, _, err = storage.Decrypt(path, "evidence-signing-key", data, nil)
			if err != nil {
				return nil, nil, err
			}
		}
		if len(data) != ed25519.PrivateKeySize {
			return nil, nil, errors.New("evidence signing key has invalid size")
		}
		privateKey := append(ed25519.PrivateKey(nil), data...)
		publicKey := append(ed25519.PublicKey(nil), privateKey.Public().(ed25519.PublicKey)...)
		return publicKey, privateKey, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, nil, err
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	encoded := []byte(privateKey)
	if storage != nil {
		encoded, err = storage.Encrypt(path, "evidence-signing-key", 0, encoded)
		if err != nil {
			return nil, nil, err
		}
		encoded = append(encoded, '\n')
	}
	if err := atomicWriteFile(path, encoded, 0o600); err != nil {
		return nil, nil, err
	}
	return append(ed25519.PublicKey(nil), publicKey...), append(ed25519.PrivateKey(nil), privateKey...), nil
}

func (l *EvidenceLedger) writeOrVerifyPublicKey() error {
	info, err := os.Lstat(l.publicPath)
	if errors.Is(err, os.ErrNotExist) {
		return atomicWriteFile(l.publicPath, l.publicKey, 0o644)
	}
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() != ed25519.PublicKeySize {
		return errors.New("evidence public key must be a regular non-symlink Ed25519 key")
	}
	data, err := os.ReadFile(l.publicPath)
	if err != nil {
		return err
	}
	if !bytes.Equal(data, l.publicKey) {
		return errors.New("evidence public key does not match encrypted private key")
	}
	return nil
}

func evidenceCanonical(record EvidenceRecord) ([]byte, error) {
	payload := evidencePayload{
		Version: record.Version, Sequence: record.Sequence, ID: record.ID, Time: record.Time.UTC(),
		Severity: record.Severity, Kind: record.Kind, Source: record.Source, Message: record.Message,
		Target: record.Target, RequestID: record.RequestID, PrevHash: record.PrevHash,
	}
	return json.Marshal(payload)
}

func evidenceHash(canonical []byte) []byte {
	hash := sha256.New()
	_, _ = hash.Write([]byte(evidenceDomain))
	_, _ = hash.Write(canonical)
	return hash.Sum(nil)
}

func decodeEvidenceRecord(data []byte) (EvidenceRecord, error) {
	var record EvidenceRecord
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&record); err != nil {
		return EvidenceRecord{}, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return EvidenceRecord{}, errors.New("evidence record contains trailing data")
	}
	return record, nil
}

func verifyEvidenceRecord(record EvidenceRecord, sequence uint64, previous string, publicKey ed25519.PublicKey) error {
	if record.Version != evidenceRecordVersion || record.Sequence != sequence || record.ID == "" || record.Time.IsZero() {
		return errors.New("evidence record identity is invalid")
	}
	if record.PrevHash != previous {
		return errors.New("evidence chain predecessor mismatch")
	}
	if err := validateEvidenceText(record); err != nil {
		return err
	}
	canonical, err := evidenceCanonical(record)
	if err != nil {
		return err
	}
	expected := evidenceHash(canonical)
	providedHash, err := hex.DecodeString(record.Hash)
	if err != nil || len(providedHash) != sha256.Size || !bytes.Equal(providedHash, expected) {
		return errors.New("evidence content hash mismatch")
	}
	signature, err := base64.RawURLEncoding.DecodeString(record.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize || !ed25519.Verify(publicKey, expected, signature) {
		return errors.New("evidence signature verification failed")
	}
	return nil
}

func validateEvidenceText(record EvidenceRecord) error {
	for label, value := range map[string]struct {
		text string
		max  int
	}{
		"severity": {record.Severity, 32}, "kind": {record.Kind, 128}, "source": {record.Source, 128},
		"message": {record.Message, 4096}, "target": {record.Target, 1024}, "request_id": {record.RequestID, 256},
	} {
		if value.text == "" && label != "target" && label != "request_id" {
			return fmt.Errorf("evidence %s is required", label)
		}
		if len(value.text) > value.max || bytes.IndexByte([]byte(value.text), 0) >= 0 {
			return fmt.Errorf("evidence %s exceeds its boundary", label)
		}
	}
	return nil
}

// evidenceWalkBounds bound a chain walk.
//
// Verification costs one decryption and one signature check per record, so an unbounded walk
// is O(history) and cannot sit in a startup path or on a timer. Every bound here is stated
// explicitly and every caller has to choose one.
type evidenceWalkBounds struct {
	// From is the first sequence to verify. Records before it are counted but not verified,
	// because an earlier pass already verified them; the authenticated watermark is what makes
	// that statement safe.
	From uint64
	// To is the last sequence to verify. Zero means to the end of the file.
	To uint64
	// PrevHash is the authenticated hash of record From-1, the anchor the first verified
	// record has to link back to.
	PrevHash string
}

// verifyEvidenceChain walks the chain between the bounds and verifies every record inside them.
func verifyEvidenceChain(path string, publicKey ed25519.PublicKey, storage *StorageCipher, maxBytes int64, bounds evidenceWalkBounds) (string, uint64, []EvidenceRecord, int64, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return "", 0, nil, 0, nil
	}
	if err != nil {
		return "", 0, nil, 0, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return "", 0, nil, 0, errors.New("evidence ledger must be a private regular non-symlink file")
	}
	if info.Size() < 0 || info.Size() > maxBytes {
		return "", 0, nil, info.Size(), errors.New("evidence ledger exceeds its size budget")
	}
	file, err := os.Open(path)
	if err != nil {
		return "", 0, nil, info.Size(), err
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 4096), 4<<20)
	previous := bounds.PrevHash
	var sequence uint64
	var lastVerified string
	recent := make([]EvidenceRecord, 0, 256)
	for scanner.Scan() {
		sequence++
		if bounds.To > 0 && sequence > bounds.To {
			// Read one past the bound to detect a ledger that advanced behind the checkpoint.
			sequence--
			break
		}
		if sequence < bounds.From {
			// Counted, not verified: the authenticated watermark covers it.
			continue
		}
		line := append([]byte(nil), scanner.Bytes()...)
		if storage != nil {
			line, _, err = storage.Decrypt(path, "evidence-record", line, &sequence)
			if err != nil {
				return "", 0, nil, info.Size(), fmt.Errorf("evidence line %d decrypt: %w", sequence, err)
			}
		}
		record, err := decodeEvidenceRecord(line)
		if err != nil {
			return "", 0, nil, info.Size(), fmt.Errorf("evidence line %d decode: %w", sequence, err)
		}
		if err := verifyEvidenceRecord(record, sequence, previous, publicKey); err != nil {
			return "", 0, nil, info.Size(), fmt.Errorf("evidence line %d: %w", sequence, err)
		}
		previous = record.Hash
		lastVerified = record.Hash
		recent = append(recent, record)
		if len(recent) > evidenceRecentLimit {
			recent = append([]EvidenceRecord(nil), recent[len(recent)-evidenceRecentLimit:]...)
		}
		if bounds.To > 0 && sequence == bounds.To {
			break
		}
	}
	if err := scanner.Err(); err != nil {
		return "", 0, nil, info.Size(), err
	}
	if bounds.From > sequence+1 {
		return "", sequence, recent, info.Size(), fmt.Errorf("evidence ledger is shorter (%d records) than the verified watermark (%d)", sequence, bounds.From-1)
	}
	if lastVerified == "" {
		lastVerified = bounds.PrevHash
	}
	return lastVerified, sequence, recent, info.Size(), nil
}

// verifyEvidenceFiles walks the entire chain and checks the checkpoint against its end.
//
// It is the operator's and the first-run path, not a startup path: see
// verifyEvidenceFilesBounded for what runs when the service comes up.
func verifyEvidenceFiles(path, headPath string, publicKey ed25519.PublicKey, storage *StorageCipher, maxBytes int64) (string, uint64, []EvidenceRecord, int64, error) {
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		if _, headErr := os.Lstat(headPath); !errors.Is(headErr, os.ErrNotExist) {
			if headErr != nil {
				return "", 0, nil, 0, headErr
			}
			return "", 0, nil, 0, errors.New("evidence checkpoint exists without ledger")
		}
		return "", 0, nil, 0, nil
	}
	head, sequence, recent, size, err := verifyEvidenceChain(path, publicKey, storage, maxBytes, evidenceWalkBounds{From: 1})
	if err != nil {
		return "", 0, nil, size, err
	}
	if err := verifyEvidenceCheckpoint(headPath, sequence, head, storage); err != nil {
		return "", 0, nil, size, err
	}
	return head, sequence, recent, size, nil
}

// readEvidenceCheckpoint returns the authenticated checkpoint that seals the log.
//
// It is the only part of the ledger whose authenticity does not depend on reading the history,
// which is what makes a bounded verification possible at all.
func readEvidenceCheckpoint(path string, storage *StorageCipher) (evidenceCheckpoint, error) {
	data, err := readBoundedPrivateFile(path, 128<<10)
	if err != nil {
		return evidenceCheckpoint{}, err
	}
	if storage != nil {
		data, _, err = storage.Decrypt(path, "evidence-head", data, nil)
		if err != nil {
			return evidenceCheckpoint{}, err
		}
	}
	var checkpoint evidenceCheckpoint
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&checkpoint); err != nil {
		return evidenceCheckpoint{}, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return evidenceCheckpoint{}, errors.New("evidence checkpoint contains trailing data")
	}
	return checkpoint, nil
}

// evidenceLineWindow counts the records in the log and keeps the last limit of the sealed
// prefix. A limit of zero counts only.
//
// Counting is a byte scan without decryption, and it is what makes a bounded start possible: a
// record's sequence number is the line it sits on, and that sequence is bound into the record's
// signature.
func evidenceLineWindow(path string, sealed uint64, limit int) (uint64, [][]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return 0, nil, err
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 4096), 4<<20)
	var lines uint64
	var ring [][]byte
	if limit > 0 {
		ring = make([][]byte, limit)
	}
	for scanner.Scan() {
		raw := scanner.Bytes()
		if len(bytes.TrimSpace(raw)) == 0 {
			continue
		}
		lines++
		if limit <= 0 || lines > sealed {
			continue
		}
		ring[int((lines-1)%uint64(limit))] = append([]byte(nil), raw...)
	}
	if err := scanner.Err(); err != nil {
		return 0, nil, err
	}
	if limit <= 0 {
		return lines, nil, nil
	}
	keep := lines
	if keep > sealed {
		keep = sealed
	}
	if keep > uint64(limit) {
		keep = uint64(limit)
	}
	window := make([][]byte, 0, keep)
	start := sealed - keep
	if lines < sealed {
		start = lines - keep
	}
	for i := uint64(0); i < keep; i++ {
		window = append(window, ring[int((start+i)%uint64(limit))])
	}
	return lines, window, nil
}

// truncateEvidenceTo rewrites the ledger with only its first count records.
//
// It is the recovery for a record that was written but never sealed and does not verify: the
// record is not part of the authenticated chain, and leaving it in place corrupts the chain at
// the next append, because the next record links to the sealed head and not to the orphan.
// The rewrite is a temporary file in the same directory followed by an atomic rename, so an
// interrupted recovery leaves either the old file or the repaired one.
func truncateEvidenceTo(path string, count uint64) error {
	source, err := os.Open(path)
	if err != nil {
		return err
	}
	defer source.Close()
	temp, err := os.CreateTemp(filepath.Dir(path), ".evidence-truncate-*")
	if err != nil {
		return err
	}
	tempName := temp.Name()
	defer func() {
		_ = temp.Close()
		_ = os.Remove(tempName)
	}()
	if err := temp.Chmod(0o600); err != nil {
		return err
	}
	scanner := bufio.NewScanner(source)
	scanner.Buffer(make([]byte, 4096), 4<<20)
	writer := bufio.NewWriterSize(temp, 1<<20)
	var written uint64
	for scanner.Scan() {
		raw := scanner.Bytes()
		if len(bytes.TrimSpace(raw)) == 0 {
			continue
		}
		written++
		if written > count {
			break
		}
		if _, err := writer.Write(append(append([]byte(nil), raw...), '\n')); err != nil {
			return err
		}
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	if err := writer.Flush(); err != nil {
		return err
	}
	if err := temp.Sync(); err != nil {
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	return os.Rename(tempName, path)
}

// readTrailingEvidenceLine returns the last non-empty record of the ledger.
func readTrailingEvidenceLine(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 4096), 4<<20)
	var last []byte
	for scanner.Scan() {
		raw := scanner.Bytes()
		if len(bytes.TrimSpace(raw)) == 0 {
			continue
		}
		last = append([]byte(nil), raw...)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if last == nil {
		return nil, errors.New("evidence ledger has no records")
	}
	return last, nil
}

// recoverUnsealedEvidenceTail adopts or drops the one record that the append path wrote without
// sealing it.
//
// Append writes the record and then the checkpoint, so a crash in between - a power loss, an
// operator's kill, a full disk - leaves the file exactly one record ahead of the checkpoint.
// Both halves of that are unacceptable without recovery: failing the start takes the whole
// platform down because a forensic log was interrupted, and keeping the orphan corrupts the
// chain at the next append.
//
// A well-formed orphan is verified against the sealed head and then sealed, so nothing is lost.
// An orphan that does not verify is removed, because it was never authenticated and a partial
// write is the usual reason it is there.
func recoverUnsealedEvidenceTail(path, headPath string, publicKey ed25519.PublicKey, storage *StorageCipher, checkpoint evidenceCheckpoint) (string, error) {
	raw, err := readTrailingEvidenceLine(path)
	if err != nil {
		return "", err
	}
	sequence := checkpoint.Sequence + 1
	line := raw
	if storage != nil {
		line, _, err = storage.Decrypt(path, "evidence-record", line, &sequence)
		if err != nil {
			line = nil
		}
	}
	if line != nil {
		if record, decodeErr := decodeEvidenceRecord(line); decodeErr == nil {
			if verifyErr := verifyEvidenceRecord(record, sequence, checkpoint.HeadHash, publicKey); verifyErr == nil {
				if err := writeEvidenceCheckpoint(headPath, sequence, record.Hash, storage); err != nil {
					return "", fmt.Errorf("seal the recovered record: %w", err)
				}
				return "adopted", nil
			}
		}
	}
	if err := truncateEvidenceTo(path, checkpoint.Sequence); err != nil {
		return "", fmt.Errorf("remove the unsealed record: %w", err)
	}
	return "dropped", nil
}

// verifyEvidenceFilesBounded verifies the authenticated checkpoint and a bounded tail of the
// log instead of the whole history, and reports which scope it actually verified.
//
// The complete walk decrypts and verifies every record. At 260 MB that cost more than fourteen
// minutes of the control plane's startup - longer than the service manager waits for readiness,
// so the platform could not start at all and the host lost its dashboard and its release gate.
// Verification has to be bounded, and bounding it does not have to give up detection:
//
//   - The checkpoint is authenticated under the node storage key, so its sequence and head
//     hash are trusted rather than derived.
//   - The line count is compared against that sequence in a byte scan with no crypto. It
//     detects truncation and any record appended outside the trusted writer.
//   - The last evidenceRecentLimit records are decrypted, their signatures verified and their
//     linkage checked, and the final one must reproduce the checkpoint's head hash. A record's
//     signature covers its own prev_hash, so the window is anchored to the checkpoint and
//     cannot be rewritten without breaking a signature.
//
// What it does not prove is the history *before* the window. That is what the watermark walk is
// for; it runs after readiness, it is incremental, and VerifyScope reports which of the two has
// happened so that no surface can present a tail verification as a full one.
func verifyEvidenceFilesBounded(path, headPath string, publicKey ed25519.PublicKey, storage *StorageCipher, maxBytes int64, tailLimit int) (string, uint64, []EvidenceRecord, int64, string, error) {
	if tailLimit < 1 {
		tailLimit = evidenceRecentLimit
	}
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		if _, headErr := os.Lstat(headPath); !errors.Is(headErr, os.ErrNotExist) {
			if headErr != nil {
				return "", 0, nil, 0, "", headErr
			}
			return "", 0, nil, 0, "", errors.New("evidence checkpoint exists without ledger")
		}
		return "", 0, nil, 0, "empty", nil
	}
	if err != nil {
		return "", 0, nil, 0, "", err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return "", 0, nil, 0, "", errors.New("evidence ledger must be a private regular non-symlink file")
	}
	if info.Size() < 0 || info.Size() > maxBytes {
		return "", 0, nil, info.Size(), "", errors.New("evidence ledger exceeds its size budget")
	}
	checkpoint, err := readEvidenceCheckpoint(headPath, storage)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) && info.Size() == 0 {
			return "", 0, nil, 0, "empty", nil
		}
		return "", 0, nil, info.Size(), "", err
	}
	if checkpoint.Version != evidenceRecordVersion {
		return "", 0, nil, info.Size(), "", errors.New("evidence checkpoint has an unsupported version")
	}
	if checkpoint.Sequence == 0 {
		if info.Size() != 0 {
			return "", 0, nil, info.Size(), "", errors.New("evidence ledger holds records but its checkpoint seals none")
		}
		return "", 0, nil, 0, "empty", nil
	}
	lines, _, err := evidenceLineWindow(path, 0, 0)
	if err != nil {
		return "", 0, nil, info.Size(), "", err
	}
	if lines == checkpoint.Sequence+1 {
		// The append path writes the record and then the checkpoint, so a crash in between leaves
		// exactly one record that was never sealed. It is recovered here, before verification:
		// refusing to start over an interrupted append takes the whole platform down for a
		// forensic log, and keeping the orphan would corrupt the chain at the next append.
		if _, err := recoverUnsealedEvidenceTail(path, headPath, publicKey, storage, checkpoint); err != nil {
			return "", 0, nil, info.Size(), "", fmt.Errorf("unsealed evidence record: %w", err)
		}
		if stat, statErr := os.Lstat(path); statErr == nil {
			info = stat
		}
		checkpoint, err = readEvidenceCheckpoint(headPath, storage)
		if err != nil {
			return "", 0, nil, info.Size(), "", err
		}
		lines, _, err = evidenceLineWindow(path, 0, 0)
		if err != nil {
			return "", 0, nil, info.Size(), "", err
		}
	}
	if lines != checkpoint.Sequence {
		return "", 0, nil, info.Size(), "", fmt.Errorf("evidence ledger holds %d records but its checkpoint seals %d", lines, checkpoint.Sequence)
	}
	_, window, err := evidenceLineWindow(path, checkpoint.Sequence, tailLimit)
	if err != nil {
		return "", 0, nil, info.Size(), "", err
	}
	start := checkpoint.Sequence - uint64(len(window)) + 1
	previous := ""
	recent := make([]EvidenceRecord, 0, len(window))
	for i, raw := range window {
		sequence := start + uint64(i)
		line := raw
		if storage != nil {
			line, _, err = storage.Decrypt(path, "evidence-record", line, &sequence)
			if err != nil {
				return "", 0, nil, info.Size(), "", fmt.Errorf("evidence line %d decrypt: %w", sequence, err)
			}
		}
		record, err := decodeEvidenceRecord(line)
		if err != nil {
			return "", 0, nil, info.Size(), "", fmt.Errorf("evidence line %d decode: %w", sequence, err)
		}
		// The window's first record has no verified predecessor to compare against. Its own
		// signature still covers its prev_hash, so it cannot be edited either - it is only the
		// link *into* the window that is taken on trust from the authenticated checkpoint.
		expectedPrevious := previous
		if i == 0 {
			expectedPrevious = record.PrevHash
		}
		if err := verifyEvidenceRecord(record, sequence, expectedPrevious, publicKey); err != nil {
			return "", 0, nil, info.Size(), "", fmt.Errorf("evidence line %d: %w", sequence, err)
		}
		previous = record.Hash
		recent = append(recent, record)
	}
	if previous != checkpoint.HeadHash {
		return "", 0, nil, info.Size(), "", errors.New("evidence ledger tail does not reproduce the sealed checkpoint")
	}
	scope := "tail"
	if start == 1 {
		scope = "full"
	}
	return previous, lines, recent, info.Size(), scope, nil
}

func verifyEvidenceCheckpoint(path string, sequence uint64, headHash string, storage *StorageCipher) error {
	data, err := readBoundedPrivateFile(path, 128<<10)
	if errors.Is(err, os.ErrNotExist) {
		if sequence == 0 && headHash == "" {
			return nil
		}
		return errors.New("evidence checkpoint is missing")
	}
	if err != nil {
		return err
	}
	if storage != nil {
		data, _, err = storage.Decrypt(path, "evidence-head", data, nil)
		if err != nil {
			return err
		}
	}
	var checkpoint evidenceCheckpoint
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&checkpoint); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("evidence checkpoint contains trailing data")
	}
	if checkpoint.Version != evidenceRecordVersion || checkpoint.Sequence != sequence || checkpoint.HeadHash != headHash {
		return errors.New("evidence checkpoint does not match verified ledger head")
	}
	return nil
}

func writeEvidenceCheckpoint(path string, sequence uint64, headHash string, storage *StorageCipher) error {
	data, err := json.Marshal(evidenceCheckpoint{Version: evidenceRecordVersion, Sequence: sequence, HeadHash: headHash})
	if err != nil {
		return err
	}
	if storage != nil {
		data, err = storage.Encrypt(path, "evidence-head", sequence, data)
		if err != nil {
			return err
		}
	}
	return atomicWriteFile(path, append(data, '\n'), 0o600)
}

func (l *EvidenceLedger) Append(record EvidenceRecord) (EvidenceRecord, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.integrityErr != nil {
		return EvidenceRecord{}, fmt.Errorf("evidence ledger is quarantined: %w", l.integrityErr)
	}
	if record.ID == "" {
		record.ID = randomID()
	}
	if record.Time.IsZero() {
		record.Time = time.Now().UTC()
	}
	record.Version = evidenceRecordVersion
	record.Sequence = l.sequence + 1
	record.Time = record.Time.UTC()
	record.PrevHash = l.headHash
	record.Hash = ""
	record.Signature = ""
	if err := validateEvidenceText(record); err != nil {
		return EvidenceRecord{}, err
	}
	if err := l.verifyUnchangedLocked(); err != nil {
		l.integrityErr = err
		return EvidenceRecord{}, err
	}
	canonical, err := evidenceCanonical(record)
	if err != nil {
		return EvidenceRecord{}, err
	}
	digest := evidenceHash(canonical)
	record.Hash = hex.EncodeToString(digest)
	record.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(l.privateKey, digest))
	line, err := json.Marshal(record)
	if err != nil {
		return EvidenceRecord{}, err
	}
	if l.crypto != nil {
		line, err = l.crypto.Encrypt(l.path, "evidence-record", record.Sequence, line)
		if err != nil {
			return EvidenceRecord{}, err
		}
	}
	nextSize := l.expectedSize + int64(len(line)+1)
	if nextSize > l.effectiveMaxBytesLocked() {
		// Nothing is written and nothing is quarantined. The record is refused with a
		// condition the caller can tell apart from corruption, and the ledger keeps
		// taking writes as soon as the budget is raised.
		l.budgetExhausted = true
		return EvidenceRecord{}, errEvidenceBudgetExhausted
	}
	l.budgetExhausted = false
	file, err := os.OpenFile(l.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY|noFollowFlag, 0o600)
	if err != nil {
		return EvidenceRecord{}, err
	}
	if _, err = file.Write(append(line, '\n')); err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err != nil {
		return EvidenceRecord{}, err
	}
	if closeErr != nil {
		return EvidenceRecord{}, closeErr
	}
	if err := writeEvidenceCheckpoint(l.headPath, record.Sequence, record.Hash, l.crypto); err != nil {
		l.integrityErr = fmt.Errorf("evidence checkpoint commit failed: %w", err)
		return EvidenceRecord{}, l.integrityErr
	}
	l.sequence = record.Sequence
	l.headHash = record.Hash
	l.expectedSize = nextSize
	l.recent = append(l.recent, record)
	if len(l.recent) > evidenceRecentLimit {
		l.recent = append([]EvidenceRecord(nil), l.recent[len(l.recent)-evidenceRecentLimit:]...)
	}
	return record, nil
}

func (l *EvidenceLedger) verifyUnchangedLocked() error {
	if err := rejectSymlink(l.path); err != nil {
		return err
	}
	if err := verifyEvidenceCheckpoint(l.headPath, l.sequence, l.headHash, l.crypto); err != nil {
		return err
	}
	info, err := os.Lstat(l.path)
	if errors.Is(err, os.ErrNotExist) && l.expectedSize == 0 {
		return nil
	}
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return errors.New("evidence ledger file policy changed")
	}
	if info.Size() != l.expectedSize {
		return errors.New("evidence ledger size changed outside the trusted writer")
	}
	return nil
}

// ApplyPolicy republishes the administrable evidence budget and page bounds. A
// lowered budget takes effect on the next append and never truncates existing
// records: the ledger is append-only by construction.
func (l *EvidenceLedger) ApplyPolicy(settings EvidenceFabricSettings) error {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.policy = settings
	if settings.MaxBytes > 0 {
		l.maxBytes = settings.MaxBytes
	}
	return nil
}

// Policy returns the active evidence policy.
func (l *EvidenceLedger) Policy() EvidenceFabricSettings {
	if l == nil {
		return EvidenceFabricSettings{}
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.policy
}

func (l *EvidenceLedger) effectiveMaxBytesLocked() int64 {
	if l.policy.MaxBytes > 0 {
		return l.policy.MaxBytes
	}
	return l.maxBytes
}

// Verify walks the chain from the beginning and checks the checkpoint against its end.
//
// This is the operator's path (GET /api/v1/evidence/verify) and the fallback for a ledger whose
// watermark is missing. It is deliberately not a startup path: the walk decrypts and verifies
// every record, so its cost is proportional to the whole history, and it holds the ledger lock
// for the duration.
func (l *EvidenceLedger) Verify() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.integrityErr != nil {
		return l.integrityErr
	}
	// The same limit the append path enforces. These two disagreed: Append consulted
	// effectiveMaxBytesLocked(), which prefers the administrable policy, while Verify
	// consulted the constructor value alone. An operator who raised the budget, let the
	// ledger grow past the old bound and then restarted the service had it rejected at
	// boot as "exceeds its size budget" - the ledger they had just been told to enlarge,
	// refused by the process that was told to accept it. One budget, read the same way
	// from both sides.
	head, sequence, _, size, err := verifyEvidenceFiles(l.path, l.headPath, l.publicKey, l.crypto, l.effectiveMaxBytesLocked())
	if err == nil && (head != l.headHash || sequence != l.sequence || size != l.expectedSize) {
		err = errors.New("evidence ledger advanced outside the trusted writer")
	}
	if err != nil {
		l.integrityErr = err
		return err
	}
	if err := l.writeWatermark(evidenceWatermark{Version: evidenceRecordVersion, Sequence: sequence, HeadHash: head}); err != nil {
		l.integrityErr = fmt.Errorf("evidence watermark: %w", err)
		return l.integrityErr
	}
	l.markFullVerifiedLocked()
	return nil
}

// evidenceWatermark records how far the chain has been verified end to end.
//
// It is authenticated under the node storage key, so an attacker without that key cannot move
// it forward, and it is written only after a walk that reached the position it names. That is
// what lets successive passes verify each record exactly once, in order, and still claim
// complete coverage without ever re-reading the history.
type evidenceWatermark struct {
	Version  int    `json:"version"`
	Sequence uint64 `json:"sequence"`
	HeadHash string `json:"head_hash"`
}

// evidenceIncrementalChunkRecords bounds one background pass.
//
// The walk is CPU-bound at roughly six seconds per megabyte on this class of host, so the chunk
// keeps a single pass in the tens of seconds. It runs without the ledger lock, so it competes
// for CPU but never blocks an append.
const evidenceIncrementalChunkRecords = 25000

func (l *EvidenceLedger) watermarkPath() string { return l.path + ".verified" }

// readWatermark returns the last verified position, or an error when there is none.
//
// It needs no lock: it reads only immutable fields of the ledger.
func (l *EvidenceLedger) readWatermark() (evidenceWatermark, error) {
	data, err := readBoundedPrivateFile(l.watermarkPath(), 64<<10)
	if err != nil {
		return evidenceWatermark{}, err
	}
	if l.crypto != nil {
		plaintext, legacy, err := l.crypto.Decrypt(l.watermarkPath(), "evidence-verified", data, nil)
		if err != nil {
			return evidenceWatermark{}, err
		}
		if legacy {
			// An unencrypted watermark is a claim anyone with write access to the state
			// directory can author, and honouring it would let them skip the verification of the
			// entire history by naming a position near its end. The cipher reports legacy
			// plaintext instead of failing, so the refusal has to be explicit: a watermark is
			// either authenticated or it does not count.
			return evidenceWatermark{}, errors.New("evidence watermark is not authenticated")
		}
		data = plaintext
	}
	var mark evidenceWatermark
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&mark); err != nil {
		return evidenceWatermark{}, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return evidenceWatermark{}, errors.New("evidence watermark contains trailing data")
	}
	if mark.Version != evidenceRecordVersion || mark.HeadHash == "" || mark.Sequence == 0 {
		return evidenceWatermark{}, errors.New("evidence watermark is not usable")
	}
	return mark, nil
}

func (l *EvidenceLedger) writeWatermark(mark evidenceWatermark) error {
	data, err := json.Marshal(mark)
	if err != nil {
		return err
	}
	if l.crypto != nil {
		data, err = l.crypto.Encrypt(l.watermarkPath(), "evidence-verified", mark.Sequence, data)
		if err != nil {
			return err
		}
	}
	return atomicWriteFile(l.watermarkPath(), append(data, '\n'), 0o600)
}

func (l *EvidenceLedger) markFullVerifiedLocked() {
	now := time.Now().UTC()
	l.verifyScope = "full"
	l.fullVerifiedAt = &now
}

// recordIntegrity quarantines the ledger with a cause and returns that cause.
func (l *EvidenceLedger) recordIntegrity(err error) error {
	if err == nil {
		return nil
	}
	l.mu.Lock()
	l.integrityErr = err
	l.mu.Unlock()
	return err
}

// VerifyIncremental extends the verified range by one bounded chunk.
//
// Complete verification used to mean re-reading the whole history, on a timer, every fifteen
// minutes. At 260 MB one pass takes minutes, so the timer could never keep up and the pass
// itself became a permanent CPU load. The walk now starts at the authenticated watermark and
// ends at the authenticated checkpoint, so its cost is proportional to what has been written
// since the last pass - milliseconds once it has caught up - while every record is still
// verified exactly once, in order, by one pass or another.
//
// The lock is held only to read the checkpoint and the watermark and to record the result. The
// walk itself runs without it, so the append path is never blocked by verification.
func (l *EvidenceLedger) VerifyIncremental() error {
	l.mu.Lock()
	integrityErr := l.integrityErr
	maxBytes := l.effectiveMaxBytesLocked()
	chunk := l.incrementalChunk
	if chunk == 0 {
		chunk = evidenceIncrementalChunkRecords
	}
	l.mu.Unlock()
	if integrityErr != nil {
		return integrityErr
	}

	checkpoint, err := readEvidenceCheckpoint(l.headPath, l.crypto)
	if err != nil {
		return l.recordIntegrity(fmt.Errorf("evidence checkpoint: %w", err))
	}
	if checkpoint.Version != evidenceRecordVersion {
		return l.recordIntegrity(errors.New("evidence checkpoint has an unsupported version"))
	}

	from := uint64(1)
	prev := ""
	if mark, markErr := l.readWatermark(); markErr == nil {
		from = mark.Sequence + 1
		prev = mark.HeadHash
	}
	if from > checkpoint.Sequence {
		l.mu.Lock()
		l.markFullVerifiedLocked()
		l.mu.Unlock()
		return nil
	}
	to := from + chunk - 1
	if to > checkpoint.Sequence {
		to = checkpoint.Sequence
	}

	head, sequence, _, _, err := verifyEvidenceChain(l.path, l.publicKey, l.crypto, maxBytes,
		evidenceWalkBounds{From: from, To: to, PrevHash: prev})
	if err != nil {
		return l.recordIntegrity(err)
	}
	if sequence != to {
		return l.recordIntegrity(fmt.Errorf("evidence ledger holds %d records, fewer than the verified range ends at", sequence))
	}
	l.mu.Lock()
	if err := l.writeWatermark(evidenceWatermark{Version: evidenceRecordVersion, Sequence: to, HeadHash: head}); err != nil {
		l.mu.Unlock()
		return l.recordIntegrity(fmt.Errorf("evidence watermark: %w", err))
	}
	if to == checkpoint.Sequence {
		l.markFullVerifiedLocked()
	} else {
		// Say exactly how far the chain has been covered instead of implying the whole of it.
		// A watermark that is behind means records exist that no pass has verified yet.
		l.verifyScope = fmt.Sprintf("partial:%d/%d", to, checkpoint.Sequence)
	}
	l.mu.Unlock()
	return nil
}

func (l *EvidenceLedger) Healthy() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.integrityErr
}

func (l *EvidenceLedger) Status() EvidenceStatus {
	l.mu.Lock()
	defer l.mu.Unlock()
	status := EvidenceStatus{
		Enabled: true, Healthy: l.integrityErr == nil, Records: l.sequence,
		HeadHash: l.headHash, PublicKey: hex.EncodeToString(l.publicKey),
		MaxBytes: l.effectiveMaxBytesLocked(), StoredBytes: l.expectedSize,
		VerifyScope: l.verifyScope, FullVerifiedAt: l.fullVerifiedAt,
	}
	// The effective budget is reported, not the compiled-in one: an operator who raised
	// the retention limit needs to see the limit that is actually in force.
	// budgetExhausted is the accurate witness: a refused write does not advance
	// expectedSize, so a size comparison would report "not full" for a ledger that has
	// just refused a record for capacity.
	status.Full = l.integrityErr == nil && l.budgetExhausted
	if l.integrityErr != nil {
		status.Error = "evidence integrity unavailable"
	}
	return status
}

func (l *EvidenceLedger) Recent(limit int) []EvidenceRecord {
	l.mu.Lock()
	defer l.mu.Unlock()
	if limit < 1 {
		limit = 100
	}
	if limit > 500 {
		limit = 500
	}
	if limit > len(l.recent) {
		limit = len(l.recent)
	}
	out := append([]EvidenceRecord(nil), l.recent[len(l.recent)-limit:]...)
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out
}
