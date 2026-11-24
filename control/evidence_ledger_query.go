// STATUS: DIAMANT VGT SUPREME

package main

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

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
	// LedgerEpoch is the persistent rotation generation and PublicKeyFingerprint is the
	// SHA-256 over the Ed25519 public key. Both are additive witness fields: they identify a
	// chain generation and a signing identity without exposing key material or content.
	LedgerEpoch          uint64 `json:"ledger_epoch"`
	PublicKeyFingerprint string `json:"public_key_fingerprint,omitempty"`
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
				if err := writeEvidenceCheckpoint(headPath, sequence, record.Hash, checkpoint.LedgerEpoch, storage); err != nil {
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
		// Strict read: the cipher refuses a plaintext watermark outright. That matters because
		// an unencrypted watermark is a claim anyone with write access to the state directory
		// can author, and honouring it would let them skip the verification of the entire
		// history by naming a position near its end. A refused watermark is treated like a
		// missing one: the pass verifies from the beginning.
		plaintext, _, decryptErr := l.crypto.Decrypt(l.watermarkPath(), "evidence-verified", data, nil)
		if decryptErr != nil {
			return evidenceWatermark{}, decryptErr
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
		LedgerEpoch: l.ledgerEpoch, PublicKeyFingerprint: evidencePublicKeyFingerprint(l.publicKey),
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

// EvidenceCheckpointView is one coherent, durable view of the ledger head as of one lock
// acquisition. It is what an out-of-band witness checkpoint is built from.
type EvidenceCheckpointView struct {
	LedgerEpoch uint64 `json:"ledger_epoch"`
	Sequence    uint64 `json:"sequence"`
	HeadHash    string `json:"head_hash"`
	// Records is the number of records in the live chain. A hash chain numbers its records, so
	// it equals Sequence; it is reported separately because a witness protocol speaks of records.
	Records              uint64 `json:"records"`
	PublicKeyFingerprint string `json:"public_key_fingerprint"`
}

// Checkpoint returns the authenticated ledger head as one atomic, durable view.
//
// Everything a witness needs is read under a single l.mu acquisition, so the epoch, sequence,
// head and record count always belong together. Append commits the .head checkpoint before it
// advances the in-memory head, so the in-memory head is already durable; this method re-verifies
// that the file still seals it instead of trusting that ordering blindly. A ledger whose head
// moved outside the trusted writer, or one that is quarantined, refuses instead of returning a
// head a witness would record as fact.
func (l *EvidenceLedger) Checkpoint() (EvidenceCheckpointView, error) {
	if l == nil {
		return EvidenceCheckpointView{}, errors.New("evidence ledger is not configured")
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.integrityErr != nil {
		return EvidenceCheckpointView{}, fmt.Errorf("evidence ledger is quarantined: %w", l.integrityErr)
	}
	if err := l.verifyUnchangedLocked(); err != nil {
		l.integrityErr = err
		return EvidenceCheckpointView{}, err
	}
	fingerprint := evidencePublicKeyFingerprint(l.publicKey)
	if fingerprint == "" {
		err := errors.New("evidence public key is not available")
		l.integrityErr = err
		return EvidenceCheckpointView{}, err
	}
	return EvidenceCheckpointView{
		LedgerEpoch: l.ledgerEpoch, Sequence: l.sequence, HeadHash: l.headHash,
		Records: l.sequence, PublicKeyFingerprint: fingerprint,
	}, nil
}

// Head is the compact alias for Checkpoint. It exists because a caller that only needs the head
// should not have to know which of the two names is canonical.
func (l *EvidenceLedger) Head() (EvidenceCheckpointView, error) {
	return l.Checkpoint()
}

// PublicKeyFingerprint returns SHA-256 over the Ed25519 public key as 64 lowercase hex chars.
// It identifies the evidence signing key without exporting any key material.
func (l *EvidenceLedger) PublicKeyFingerprint() (string, error) {
	if l == nil {
		return "", errors.New("evidence ledger is not configured")
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	fingerprint := evidencePublicKeyFingerprint(l.publicKey)
	if fingerprint == "" {
		return "", errors.New("evidence public key is not available")
	}
	return fingerprint, nil
}

// WitnessCheckpointSigner returns the callback a witness checkpoint is signed with. The ledger
// stays the only owner of the private key: the callback signs a checkpoint digest and a
// quarantined ledger refuses to sign, so a damaged chain cannot produce witness claims.
func (l *EvidenceLedger) WitnessCheckpointSigner() WitnessCheckpointSigner {
	return func(digest []byte) ([]byte, error) {
		if l == nil {
			return nil, errors.New("evidence ledger is not configured")
		}
		if len(digest) != sha256.Size {
			return nil, errors.New("witness checkpoint digest is not SHA-256 sized")
		}
		l.mu.Lock()
		defer l.mu.Unlock()
		if l.integrityErr != nil {
			return nil, fmt.Errorf("evidence ledger is quarantined: %w", l.integrityErr)
		}
		return ed25519.Sign(l.privateKey, digest), nil
	}
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
