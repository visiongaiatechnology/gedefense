package main

import (
	"bytes"
	"crypto/hmac"
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
	"syscall"
)

const permitStoreKeyBytes = 32

// permitStoreTransport is the authenticated store payload. Each permit is kept
// as a raw JSON object so one invalid object is dropped with a counted reason
// instead of invalidating the whole store.
type permitStoreTransport struct {
	Schema   string            `json:"schema"`
	Sequence uint64            `json:"sequence"`
	Permits  []json.RawMessage `json:"permits"`
}

// permitStoreHMACEnvelope is the integrity-only fallback envelope used when no
// storage cipher is configured.
type permitStoreHMACEnvelope struct {
	Schema   string `json:"schema"`
	Sequence uint64 `json:"sequence"`
	Payload  string `json:"payload"`
	MAC      string `json:"mac"`
}

var permitStoreHMACDomain = []byte("VGT-GEDEFENSE-PERMIT-STORE-HMAC-V1\x00")

// checkPrivateStoreFile enforces the regular/non-symlink/private/owned profile
// of an existing store document before it is read.
func checkPrivateStoreFile(path string, max int64) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return errors.New("permit store must be a regular non-symlink file")
	}
	if info.Mode().Perm()&0o077 != 0 {
		return errors.New("permit store must be mode 0600")
	}
	if info.Size() < 0 || info.Size() > max {
		return errors.New("permit store exceeds its size bound")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.New("permit store ownership is unavailable")
	}
	if stat.Uid != 0 && stat.Uid != uint32(os.Geteuid()) {
		return errors.New("permit store is owned by an unrelated account")
	}
	return nil
}

// loadOrCreatePrivateKey loads a fixed-length local key with strict ownership
// and mode checks, creating it with crypto/rand on first use.
func loadOrCreatePrivateKey(path string, length int) ([]byte, error) {
	if length <= 0 || length > 64 {
		return nil, errors.New("permit store key length is invalid")
	}
	if err := ensurePrivateStoreDir(filepath.Dir(path)); err != nil {
		return nil, err
	}
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		key := make([]byte, length)
		if _, err := rand.Read(key); err != nil {
			return nil, errors.New("permit store key random source unavailable")
		}
		if err := writePrivateFileAtomic(path, key); err != nil {
			return nil, err
		}
		return key, nil
	} else if err != nil {
		return nil, fmt.Errorf("permit store key: %w", err)
	}
	if err := checkPrivateStoreFile(path, int64(length+16)); err != nil {
		return nil, fmt.Errorf("permit store key: %w", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("permit store key: %w", err)
	}
	if len(raw) != length {
		return nil, errors.New("permit store key has an unexpected length")
	}
	return append([]byte(nil), raw...), nil
}

// permitStoreSealHMAC authenticates the payload and its sequence number.
func permitStoreSealHMAC(key []byte, sequence uint64, payload []byte) ([]byte, error) {
	if len(key) != permitStoreKeyBytes {
		return nil, errors.New("permit store HMAC key is invalid")
	}
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(permitStoreHMACDomain)
	_, _ = mac.Write(sequenceBytes(sequence))
	_, _ = mac.Write(payload)
	envelope := permitStoreHMACEnvelope{
		Schema:   permitStoreHMACSchema,
		Sequence: sequence,
		Payload:  base64.RawURLEncoding.EncodeToString(payload),
		MAC:      hex.EncodeToString(mac.Sum(nil)),
	}
	return json.Marshal(envelope)
}

// permitStoreOpenHMAC authenticates and decodes the fallback envelope.
func permitStoreOpenHMAC(key []byte, data []byte) (permitStoreTransport, error) {
	var envelope permitStoreHMACEnvelope
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&envelope); err != nil {
		return permitStoreTransport{}, errors.New("permit store envelope is malformed")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return permitStoreTransport{}, errors.New("permit store envelope contains trailing data")
	}
	if envelope.Schema != permitStoreHMACSchema {
		return permitStoreTransport{}, errors.New("permit store envelope schema is invalid")
	}
	payload, err := base64.RawURLEncoding.DecodeString(envelope.Payload)
	if err != nil {
		return permitStoreTransport{}, errors.New("permit store payload encoding is invalid")
	}
	supplied, err := hex.DecodeString(envelope.MAC)
	if err != nil || len(supplied) != sha256.Size {
		return permitStoreTransport{}, errors.New("permit store MAC is malformed")
	}
	if len(key) != permitStoreKeyBytes {
		return permitStoreTransport{}, errors.New("permit store HMAC key is invalid")
	}
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(permitStoreHMACDomain)
	_, _ = mac.Write(sequenceBytes(envelope.Sequence))
	_, _ = mac.Write(payload)
	if !hmac.Equal(supplied, mac.Sum(nil)) {
		return permitStoreTransport{}, errors.New("permit store authentication failed")
	}
	var transport permitStoreTransport
	strict := json.NewDecoder(bytes.NewReader(payload))
	strict.DisallowUnknownFields()
	if err := strict.Decode(&transport); err != nil {
		return permitStoreTransport{}, errors.New("permit store document is malformed")
	}
	var trailingDocument any
	if err := strict.Decode(&trailingDocument); !errors.Is(err, io.EOF) {
		return permitStoreTransport{}, errors.New("permit store document contains trailing data")
	}
	return transport, nil
}

func sequenceBytes(sequence uint64) []byte {
	out := make([]byte, 8)
	for index := 0; index < 8; index++ {
		out[index] = byte(sequence >> (56 - 8*index))
	}
	return out
}

// decodePermitStoreTransport strictly decodes the encrypted/HMAC inner payload.
func decodePermitStoreTransport(payload []byte) (permitStoreTransport, error) {
	var transport permitStoreTransport
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&transport); err != nil {
		return permitStoreTransport{}, errors.New("permit store document is malformed")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return permitStoreTransport{}, errors.New("permit store document contains trailing data")
	}
	if transport.Schema != permitStoreSchema {
		return permitStoreTransport{}, errors.New("permit store document schema is invalid")
	}
	if len(transport.Permits) > permitMaxStorePermits {
		return permitStoreTransport{}, errors.New("permit store document exceeds its entry bound")
	}
	return transport, nil
}
