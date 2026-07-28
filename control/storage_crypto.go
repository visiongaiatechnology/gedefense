package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
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
	"strings"
)

const encryptedStorageSchema = "vgt-gedefense-aes256gcm-v1"

type encryptedStorageEnvelope struct {
	Schema     string `json:"schema"`
	Cipher     string `json:"cipher"`
	Purpose    string `json:"purpose"`
	Sequence   uint64 `json:"sequence,omitempty"`
	AADHash    string `json:"aad_sha256"`
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
}

type StorageCipher struct {
	rootKey  []byte
	nodeName string
}

func NewStorageCipher(keyPath, nodeName string) (*StorageCipher, error) {
	if keyPath == "" {
		return nil, nil
	}
	if !filepath.IsAbs(keyPath) {
		return nil, errors.New("storage key path must be absolute")
	}
	info, err := os.Lstat(keyPath)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("storage key must be a regular non-symlink file")
	}
	mode := info.Mode().Perm()
	if mode&0o007 != 0 || mode&0o020 != 0 || mode&0o010 != 0 {
		return nil, errors.New("storage key must not be world-accessible or group-writable/executable")
	}
	raw, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, err
	}
	if len(raw) != 32 {
		return nil, errors.New("storage key must contain exactly 32 random bytes")
	}
	if strings.TrimSpace(nodeName) == "" {
		nodeName = "unnamed-node"
	}
	return &StorageCipher{rootKey: append([]byte(nil), raw...), nodeName: nodeName}, nil
}

func (c *StorageCipher) purposeKey(purpose string) ([]byte, error) {
	if c == nil {
		return nil, errors.New("storage cipher unavailable")
	}
	if purpose == "" || len(purpose) > 96 {
		return nil, errors.New("invalid encryption purpose")
	}
	mac := hmac.New(sha256.New, c.rootKey)
	mac.Write([]byte("VGT-GEDEFENSE-AES256GCM-KEY-V1\x00"))
	mac.Write([]byte(c.nodeName))
	mac.Write([]byte{0})
	mac.Write([]byte(purpose))
	return mac.Sum(nil), nil
}

func storageAAD(nodeName, purpose, path string, sequence uint64) []byte {
	cleaned := filepath.Clean(path)
	return []byte(fmt.Sprintf("%s\x00node=%s\x00purpose=%s\x00path=%s\x00sequence=%d", encryptedStorageSchema, nodeName, purpose, cleaned, sequence))
}

func (c *StorageCipher) Encrypt(path, purpose string, sequence uint64, plaintext []byte) ([]byte, error) {
	key, err := c.purposeKey(purpose)
	if err != nil {
		return nil, err
	}
	defer clear(key)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	aad := storageAAD(c.nodeName, purpose, path, sequence)
	sealed := gcm.Seal(nil, nonce, plaintext, aad)
	digest := sha256.Sum256(aad)
	envelope := encryptedStorageEnvelope{
		Schema: encryptedStorageSchema, Cipher: "AES-256-GCM", Purpose: purpose, Sequence: sequence,
		AADHash: hex.EncodeToString(digest[:]), Nonce: base64.RawURLEncoding.EncodeToString(nonce),
		Ciphertext: base64.RawURLEncoding.EncodeToString(sealed),
	}
	encoded, err := json.Marshal(envelope)
	if err != nil {
		return nil, err
	}
	return encoded, nil
}

func (c *StorageCipher) Decrypt(path, purpose string, data []byte, expectedSequence *uint64) ([]byte, bool, error) {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		return nil, false, errors.New("encrypted storage document is empty")
	}
	var probe struct {
		Schema string `json:"schema"`
	}
	if json.Unmarshal(trimmed, &probe) != nil || probe.Schema != encryptedStorageSchema {
		return append([]byte(nil), data...), true, nil
	}
	envelope, err := decodeEncryptedStorageEnvelope(trimmed)
	if err != nil {
		return nil, false, err
	}
	if envelope.Schema != encryptedStorageSchema || envelope.Cipher != "AES-256-GCM" || envelope.Purpose != purpose {
		return nil, false, errors.New("encrypted envelope binding mismatch")
	}
	if expectedSequence != nil && envelope.Sequence != *expectedSequence {
		return nil, false, errors.New("encrypted record sequence mismatch")
	}
	nonce, err := base64.RawURLEncoding.DecodeString(envelope.Nonce)
	if err != nil {
		return nil, false, errors.New("encrypted envelope nonce is malformed")
	}
	ciphertext, err := base64.RawURLEncoding.DecodeString(envelope.Ciphertext)
	if err != nil {
		return nil, false, errors.New("encrypted envelope ciphertext is malformed")
	}
	aad := storageAAD(c.nodeName, purpose, path, envelope.Sequence)
	digest := sha256.Sum256(aad)
	provided, err := hex.DecodeString(envelope.AADHash)
	if err != nil || !hmac.Equal(provided, digest[:]) {
		return nil, false, errors.New("encrypted envelope AAD binding mismatch")
	}
	key, err := c.purposeKey(purpose)
	if err != nil {
		return nil, false, err
	}
	defer clear(key)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, false, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, false, err
	}
	if len(nonce) != gcm.NonceSize() || len(ciphertext) < gcm.Overhead() {
		return nil, false, errors.New("encrypted envelope sizes are invalid")
	}
	plaintext, err := gcm.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, false, errors.New("encrypted storage authentication failed")
	}
	return plaintext, false, nil
}

func decodeEncryptedStorageEnvelope(data []byte) (encryptedStorageEnvelope, error) {
	var envelope encryptedStorageEnvelope
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&envelope); err != nil {
		return encryptedStorageEnvelope{}, fmt.Errorf("encrypted envelope: %w", err)
	}
	var trailing any
	if err := dec.Decode(&trailing); !errors.Is(err, io.EOF) {
		return encryptedStorageEnvelope{}, errors.New("encrypted envelope contains trailing data")
	}
	return envelope, nil
}

func readBoundedPrivateFile(path string, max int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("state file must be a regular non-symlink file")
	}
	if info.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("state file must not be group/world accessible")
	}
	if info.Size() < 0 || info.Size() > max {
		return nil, errors.New("state file exceeds configured size bound")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, max+1))
}
