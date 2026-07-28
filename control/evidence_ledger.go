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

type EvidenceStatus struct {
	Enabled     bool   `json:"enabled"`
	Healthy     bool   `json:"healthy"`
	Records     uint64 `json:"records"`
	HeadHash    string `json:"head_hash,omitempty"`
	PublicKey   string `json:"public_key,omitempty"`
	Error       string `json:"error,omitempty"`
	MaxBytes    int64  `json:"max_bytes,omitempty"`
	StoredBytes int64  `json:"stored_bytes,omitempty"`
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
	recent       []EvidenceRecord
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
	ledger := &EvidenceLedger{
		path: path, headPath: path + ".head", keyPath: keyPath, publicPath: keyPath + ".pub",
		privateKey: privateKey, publicKey: publicKey, crypto: storage, maxBytes: maxBytes,
		recent: make([]EvidenceRecord, 0, 256),
	}
	if err := ledger.writeOrVerifyPublicKey(); err != nil {
		return nil, err
	}
	head, sequence, recent, size, verifyErr := verifyEvidenceFiles(path, ledger.headPath, publicKey, storage, maxBytes)
	ledger.headHash = head
	ledger.sequence = sequence
	ledger.recent = recent
	ledger.expectedSize = size
	ledger.integrityErr = verifyErr
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

func verifyEvidenceFiles(path, headPath string, publicKey ed25519.PublicKey, storage *StorageCipher, maxBytes int64) (string, uint64, []EvidenceRecord, int64, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		if _, headErr := os.Lstat(headPath); !errors.Is(headErr, os.ErrNotExist) {
			if headErr != nil {
				return "", 0, nil, 0, headErr
			}
			return "", 0, nil, 0, errors.New("evidence checkpoint exists without ledger")
		}
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
	previous := ""
	var sequence uint64
	recent := make([]EvidenceRecord, 0, 256)
	for scanner.Scan() {
		sequence++
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
		recent = append(recent, record)
		if len(recent) > evidenceRecentLimit {
			recent = append([]EvidenceRecord(nil), recent[len(recent)-evidenceRecentLimit:]...)
		}
	}
	if err := scanner.Err(); err != nil {
		return "", 0, nil, info.Size(), err
	}
	if err := verifyEvidenceCheckpoint(headPath, sequence, previous, storage); err != nil {
		return "", 0, nil, info.Size(), err
	}
	return previous, sequence, recent, info.Size(), nil
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
	if nextSize > l.maxBytes {
		l.integrityErr = errors.New("evidence ledger size budget exhausted")
		return EvidenceRecord{}, l.integrityErr
	}
	file, err := os.OpenFile(l.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
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

func (l *EvidenceLedger) Verify() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.integrityErr != nil {
		return l.integrityErr
	}
	head, sequence, _, size, err := verifyEvidenceFiles(l.path, l.headPath, l.publicKey, l.crypto, l.maxBytes)
	if err == nil && (head != l.headHash || sequence != l.sequence || size != l.expectedSize) {
		err = errors.New("evidence ledger advanced outside the trusted writer")
	}
	if err != nil {
		l.integrityErr = err
	}
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
		MaxBytes: l.maxBytes, StoredBytes: l.expectedSize,
	}
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
