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
)

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
	// SnapshotSize, when positive, bounds the walk to the first SnapshotSize bytes of the
	// ledger. That is the size captured under the ledger lock, so the walk sees exactly the
	// records that existed when the checkpoint and the watermark were read - never a record
	// that an append is still writing. Zero walks the whole file.
	SnapshotSize int64
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
	if bounds.SnapshotSize > 0 && info.Size() < bounds.SnapshotSize {
		// Append only grows the ledger; a file smaller than the captured snapshot was
		// replaced, not appended to. The caller's generation check distinguishes rotation
		// from tampering.
		return "", 0, nil, info.Size(), errors.New("evidence ledger is smaller than the verified snapshot")
	}
	file, err := os.Open(path)
	if err != nil {
		return "", 0, nil, info.Size(), err
	}
	defer file.Close()
	var reader io.Reader = file
	if bounds.SnapshotSize > 0 {
		reader = io.LimitReader(file, bounds.SnapshotSize)
	}
	scanner := bufio.NewScanner(reader)
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
func verifyEvidenceFiles(path, headPath string, publicKey ed25519.PublicKey, storage *StorageCipher, maxBytes int64, ledgerEpoch uint64) (string, uint64, []EvidenceRecord, int64, error) {
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
	if err := verifyEvidenceCheckpoint(headPath, sequence, head, ledgerEpoch, storage); err != nil {
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
		// Strict read: the checkpoint is the authenticated anchor of the entire bounded
		// verification, so a plaintext file with that name may never be treated as one. The
		// cipher returns an error for a document that is not an envelope.
		plain, wasLegacy, decryptErr := storage.Decrypt(path, "evidence-head", data, nil)
		if decryptErr != nil {
			return evidenceCheckpoint{}, decryptErr
		}
		if wasLegacy {
			return evidenceCheckpoint{}, errors.New("evidence checkpoint is not authenticated")
		}
		data = plain
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

func verifyEvidenceCheckpoint(path string, sequence uint64, headHash string, ledgerEpoch uint64, storage *StorageCipher) error {
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
		// Strict read: a plaintext checkpoint is not the authenticated one the ledger wrote.
		plain, wasLegacy, decryptErr := storage.Decrypt(path, "evidence-head", data, nil)
		if decryptErr != nil {
			return decryptErr
		}
		if wasLegacy {
			return errors.New("evidence checkpoint is not authenticated")
		}
		data = plain
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
	if checkpoint.Version != evidenceRecordVersion || checkpoint.Sequence != sequence || checkpoint.HeadHash != headHash || checkpoint.LedgerEpoch != ledgerEpoch {
		return errors.New("evidence checkpoint does not match verified ledger head")
	}
	return nil
}

func writeEvidenceCheckpoint(path string, sequence uint64, headHash string, ledgerEpoch uint64, storage *StorageCipher) error {
	data, err := json.Marshal(evidenceCheckpoint{Version: evidenceRecordVersion, Sequence: sequence, HeadHash: headHash, LedgerEpoch: ledgerEpoch})
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
