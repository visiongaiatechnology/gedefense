package main

import (
	"bufio"
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

const incidentRecordVersion = 2
const incidentDomain = "VGT-GEDEFENSE-INCIDENT-V2\x00"

type incidentRecord struct {
	Version  int         `json:"version"`
	Incident XDRIncident `json:"incident"`
	PrevHash string      `json:"prev_hash"`
	Hash     string      `json:"hash"`
}

type IncidentLogger struct {
	mu           sync.Mutex
	path         string
	headPath     string
	key          []byte
	crypto       *StorageCipher
	prevHash     string
	sequence     uint64
	integrityErr error
	maxBytes     int64
	expectedSize int64
}

func NewIncidentLogger(path, keyPath string, maxOpt ...int64) (*IncidentLogger, error) {
	return NewIncidentLoggerWithStorage(path, keyPath, "", "", maxOpt...)
}

func NewIncidentLoggerWithStorage(path, keyPath, storageKeyPath, nodeName string, maxOpt ...int64) (*IncidentLogger, error) {
	if path == "" || keyPath == "" {
		return nil, errors.New("incident log and key paths are required")
	}
	for _, p := range []string{path, keyPath} {
		if !filepath.IsAbs(p) {
			return nil, errors.New("incident log paths must be absolute")
		}
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			return nil, err
		}
		if err := rejectSymlink(p); err != nil {
			return nil, err
		}
	}
	key, err := loadOrCreateBinaryKey(keyPath)
	if err != nil {
		return nil, err
	}
	storage, err := NewStorageCipher(storageKeyPath, nodeName)
	if err != nil {
		return nil, fmt.Errorf("incident encryption: %w", err)
	}
	maxBytes := int64(64 << 20)
	if len(maxOpt) > 0 && maxOpt[0] > 0 {
		maxBytes = maxOpt[0]
	}
	l := &IncidentLogger{path: path, headPath: path + ".head", key: key, crypto: storage, maxBytes: maxBytes}
	if err := rejectSymlink(l.headPath); err != nil {
		return nil, err
	}
	last, count, legacy, verifyErr := verifyIncidentLogWithStorage(path, key, storage)
	l.prevHash, l.sequence, l.integrityErr = last, count, verifyErr
	if l.integrityErr == nil {
		l.integrityErr = verifyHeadCheckpointWithStorage(l.headPath, l.prevHash, storage)
	}
	if l.integrityErr == nil && legacy && storage != nil {
		if err := migrateIncidentLog(path, l.headPath, key, storage); err != nil {
			l.integrityErr = fmt.Errorf("incident encryption migration: %w", err)
		}
	}
	if st, err := os.Stat(path); err == nil {
		l.expectedSize = st.Size()
		if st.Size() > l.maxBytes {
			l.integrityErr = errors.New("incident log exceeds configured size budget")
		}
	} else if !errors.Is(err, os.ErrNotExist) && l.integrityErr == nil {
		l.integrityErr = err
	}
	return l, nil
}

func rejectSymlink(path string) error {
	st, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if st.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("refusing symbolic link: %s", path)
	}
	return nil
}

func loadOrCreateBinaryKey(path string) ([]byte, error) {
	if !filepath.IsAbs(path) {
		return nil, errors.New("binary authentication key path must be absolute")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	if err := rejectSymlink(path); err != nil {
		return nil, err
	}
	b, err := os.ReadFile(path)
	if err == nil {
		st, statErr := os.Stat(path)
		if statErr != nil {
			return nil, statErr
		}
		if !st.Mode().IsRegular() || st.Mode().Perm()&0o077 != 0 {
			return nil, errors.New("binary authentication key must be a private regular file")
		}
		if len(b) != 32 {
			return nil, errors.New("binary authentication key must contain exactly 32 bytes")
		}
		return append([]byte(nil), b...), nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	b = make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	if err := atomicWriteFile(path, b, 0o600); err != nil {
		return nil, err
	}
	return append([]byte(nil), b...), nil
}

func verifyHeadCheckpoint(path, lastHash string) error {
	return verifyHeadCheckpointWithStorage(path, lastHash, nil)
}

func verifyHeadCheckpointWithStorage(path, lastHash string, storage *StorageCipher) error {
	b, err := readBoundedPrivateFile(path, 64<<10)
	if errors.Is(err, os.ErrNotExist) {
		if lastHash == "" {
			return nil
		}
		return errors.New("incident log head checkpoint is missing")
	}
	if err != nil {
		return err
	}
	if storage != nil {
		b, _, err = storage.Decrypt(path, "incident-head", b, nil)
		if err != nil {
			return err
		}
	}
	got := strings.TrimSpace(string(b))
	if got != lastHash {
		return errors.New("incident log head checkpoint does not match the verified chain")
	}
	return nil
}

func writeHeadCheckpoint(path, hash string) error {
	return writeHeadCheckpointWithStorage(path, hash, nil)
}

func writeHeadCheckpointWithStorage(path, hash string, storage *StorageCipher) error {
	data := []byte(hash + "\n")
	var err error
	if storage != nil {
		data, err = storage.Encrypt(path, "incident-head", 0, data)
		if err != nil {
			return err
		}
		data = append(data, '\n')
	}
	return atomicWriteFile(path, data, 0o600)
}

func deriveHMACSubkey(master []byte, domain string) []byte {
	mac := hmac.New(sha256.New, master)
	_, _ = mac.Write([]byte("VGT-GEDEFENSE-KDF-V1\x00"))
	_, _ = mac.Write([]byte(domain))
	return mac.Sum(nil)
}

func incidentRecordMAC(key []byte, previous string, payload []byte) []byte {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(incidentDomain))
	_, _ = mac.Write([]byte(previous))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write(payload)
	return mac.Sum(nil)
}

func decodeIncidentLine(path string, line []byte, lineNo uint64, storage *StorageCipher) (incidentRecord, bool, error) {
	legacy := false
	plain := append([]byte(nil), line...)
	if storage != nil {
		var err error
		plain, legacy, err = storage.Decrypt(path, "incident-record", line, &lineNo)
		if err != nil {
			return incidentRecord{}, false, err
		}
	}
	var r incidentRecord
	dec := json.NewDecoder(bytes.NewReader(plain))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&r); err != nil {
		return incidentRecord{}, legacy, err
	}
	var trailing any
	if err := dec.Decode(&trailing); !errors.Is(err, io.EOF) {
		return incidentRecord{}, legacy, errors.New("incident record contains trailing data")
	}
	return r, legacy, nil
}

func verifyIncidentLog(path string, key []byte) (string, error) {
	last, _, _, err := verifyIncidentLogWithStorage(path, key, nil)
	return last, err
}

func verifyIncidentLogWithStorage(path string, key []byte, storage *StorageCipher) (string, uint64, bool, error) {
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return "", 0, false, nil
	}
	if err != nil {
		return "", 0, false, err
	}
	defer f.Close()
	if st, err := f.Stat(); err != nil {
		return "", 0, false, err
	} else if st.Mode().Perm()&0o077 != 0 {
		return "", 0, false, errors.New("incident log must not be group/world accessible")
	}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 4096), 4<<20)
	last := ""
	var lineNo uint64
	legacySeen, encryptedSeen := false, false
	for sc.Scan() {
		lineNo++
		r, legacy, err := decodeIncidentLine(path, sc.Bytes(), lineNo, storage)
		if err != nil {
			return "", 0, false, fmt.Errorf("incident log line %d is malformed: %w", lineNo, err)
		}
		legacySeen = legacySeen || legacy
		encryptedSeen = encryptedSeen || !legacy
		if legacySeen && encryptedSeen {
			return "", 0, false, errors.New("incident log mixes plaintext and encrypted records")
		}
		if r.Version != incidentRecordVersion {
			return "", 0, false, fmt.Errorf("incident log line %d has unsupported version", lineNo)
		}
		if r.PrevHash != last {
			return "", 0, false, fmt.Errorf("incident log chain break at line %d", lineNo)
		}
		storedHash := r.Hash
		if len(storedHash) != sha256.Size*2 {
			return "", 0, false, fmt.Errorf("incident log line %d has invalid hash length", lineNo)
		}
		r.Incident.RecordHash = ""
		payload, err := json.Marshal(r.Incident)
		if err != nil {
			return "", 0, false, fmt.Errorf("incident log line %d cannot be canonicalized: %w", lineNo, err)
		}
		expected, err := hex.DecodeString(storedHash)
		if err != nil || !hmac.Equal(expected, incidentRecordMAC(key, last, payload)) {
			return "", 0, false, fmt.Errorf("incident log authentication failed at line %d", lineNo)
		}
		last = storedHash
	}
	if err := sc.Err(); err != nil {
		return "", 0, false, err
	}
	return last, lineNo, legacySeen, nil
}

func migrateIncidentLog(path, headPath string, key []byte, storage *StorageCipher) error {
	if storage == nil {
		return nil
	}
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer f.Close()
	tmp := path + ".encrypting"
	_ = os.Remove(tmp)
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	cleanup := func(e error) error { _ = out.Close(); _ = os.Remove(tmp); return e }
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 4096), 4<<20)
	var sequence uint64
	last := ""
	for sc.Scan() {
		sequence++
		r, _, err := decodeIncidentLine(path, sc.Bytes(), sequence, nil)
		if err != nil {
			return cleanup(err)
		}
		plain, err := json.Marshal(r)
		if err != nil {
			return cleanup(err)
		}
		sealed, err := storage.Encrypt(path, "incident-record", sequence, plain)
		if err != nil {
			return cleanup(err)
		}
		if _, err := out.Write(append(sealed, '\n')); err != nil {
			return cleanup(err)
		}
		last = r.Hash
	}
	if err := sc.Err(); err != nil {
		return cleanup(err)
	}
	if err := out.Sync(); err != nil {
		return cleanup(err)
	}
	if err := out.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return writeHeadCheckpointWithStorage(headPath, last, storage)
}

func (l *IncidentLogger) Healthy() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.integrityErr
}

func (l *IncidentLogger) Verify() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.integrityErr != nil {
		return l.integrityErr
	}
	last, count, _, err := verifyIncidentLogWithStorage(l.path, l.key, l.crypto)
	if err == nil {
		err = verifyHeadCheckpointWithStorage(l.headPath, last, l.crypto)
	}
	if err == nil && (last != l.prevHash || count != l.sequence) {
		err = errors.New("incident log advanced outside the trusted logger")
	}
	if err == nil {
		if st, statErr := os.Stat(l.path); statErr == nil {
			if st.Size() != l.expectedSize {
				err = errors.New("incident log size changed outside the trusted logger")
			}
		} else if !errors.Is(statErr, os.ErrNotExist) || l.expectedSize != 0 {
			err = statErr
		}
	}
	if err != nil {
		l.integrityErr = err
	}
	return err
}

func (l *IncidentLogger) Append(i XDRIncident) (string, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.integrityErr != nil {
		return "", fmt.Errorf("incident log is quarantined: %w", l.integrityErr)
	}
	if err := rejectSymlink(l.path); err != nil {
		l.integrityErr = err
		return "", err
	}
	if err := verifyHeadCheckpointWithStorage(l.headPath, l.prevHash, l.crypto); err != nil {
		l.integrityErr = err
		return "", err
	}
	if st, err := os.Stat(l.path); err == nil {
		if st.Mode().Perm()&0o077 != 0 {
			l.integrityErr = errors.New("incident log must not be group/world accessible")
			return "", l.integrityErr
		}
		if st.Size() != l.expectedSize {
			l.integrityErr = errors.New("incident log size changed outside the trusted logger")
			return "", l.integrityErr
		}
	} else if !errors.Is(err, os.ErrNotExist) || l.expectedSize != 0 {
		l.integrityErr = err
		return "", err
	}
	payload, err := json.Marshal(i)
	if err != nil {
		return "", err
	}
	hash := hex.EncodeToString(incidentRecordMAC(l.key, l.prevHash, payload))
	i.RecordHash = hash
	r := incidentRecord{Version: incidentRecordVersion, Incident: i, PrevHash: l.prevHash, Hash: hash}
	line, err := json.Marshal(r)
	if err != nil {
		return "", err
	}
	nextSequence := l.sequence + 1
	if l.crypto != nil {
		line, err = l.crypto.Encrypt(l.path, "incident-record", nextSequence, line)
		if err != nil {
			return "", err
		}
	}
	nextSize := l.expectedSize + int64(len(line)+1)
	if nextSize > l.maxBytes {
		l.integrityErr = errors.New("incident log size budget exhausted")
		return "", l.integrityErr
	}
	f, err := os.OpenFile(l.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return "", err
	}
	if _, err = fmt.Fprintf(f, "%s\n", line); err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return "", err
	}
	if closeErr != nil {
		return "", closeErr
	}
	if err := writeHeadCheckpointWithStorage(l.headPath, hash, l.crypto); err != nil {
		l.integrityErr = fmt.Errorf("head checkpoint update failed: %w", err)
		return "", l.integrityErr
	}
	l.prevHash = hash
	l.sequence = nextSequence
	l.expectedSize = nextSize
	return hash, nil
}
