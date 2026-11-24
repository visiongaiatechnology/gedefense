// STATUS: DIAMANT VGT SUPREME
// Local operator signing trust material and verification paths (F-03 / CHAIN-009)
package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const (
	// feedSigningPrivateKeyFile is the default file name of the operator seed
	// inside the directory passed to --init-feed-signing.
	feedSigningPrivateKeyFile = "feed-signing.ed25519"
	// feedSigningPublicKeyFile is the default file name of the pinned public key.
	feedSigningPublicKeyFile = "feed-signing.ed25519.pub"
	// feedSigningSnapshotRawDir is the only sub-directory of feeds.snapshot_dir
	// that the sync is allowed to read raw feed bytes from.
	feedSigningSnapshotRawDir = "raw"
	// feedSigningKeyMaxBytes bounds the private/public key files before reading.
	feedSigningKeyMaxBytes = 4096
)

// feedSigningKeyPair is the parsed operator key pair. The private key is a
// 64-byte ed25519.PrivateKey built from the on-disk 32-byte seed (or accepted
// verbatim when the file already contains the 64-byte private key form).
type feedSigningKeyPair struct {
	private ed25519.PrivateKey
	public  ed25519.PublicKey
}

// validFeedSigningFeedID restricts feed identifiers to the characters that may
// appear in a snapshot file name. The catalog IDs are already DNS-label-like,
// but the snapshot path must not depend on that: a future catalog entry such as
// "../x" must be rejected here instead of becoming a path.
func validFeedSigningFeedID(id string) bool {
	if id == "" || len(id) > 64 || id[0] == '.' {
		return false
	}
	for index := 0; index < len(id); index++ {
		c := id[index]
		switch {
		case c >= 'a' && c <= 'z':
		case c >= 'A' && c <= 'Z':
		case c >= '0' && c <= '9':
		case c == '-' || c == '_' || c == '.':
		default:
			return false
		}
	}
	return true
}

// feedSigningKeyFileMode is the accepted permission mask for a private key: the
// owner must be able to read it, no other user may touch it, and it must not be
// group-writable. 0600 (and 0640 for a root:gedefense deployment) are accepted;
// 0644, 0660 and 0666 are rejected because the operator seed authenticates every
// feed generation the kernel will ever enforce.
func validFeedSigningPrivateKeyMode(mode os.FileMode) bool {
	perm := mode.Perm()
	if perm&0o400 == 0 {
		return false
	}
	if perm&0o007 != 0 {
		return false
	}
	if perm&0o020 != 0 {
		return false
	}
	return true
}

// validFeedSigningPublicKeyMode accepts the world-readable public key while
// still refusing group/world write access. The owner may replace the pinned key
// deliberately (rotation); an unprivileged writer must never be able to.
func validFeedSigningPublicKeyMode(mode os.FileMode) bool {
	perm := mode.Perm()
	if perm&0o400 == 0 {
		return false
	}
	if perm&0o022 != 0 {
		return false
	}
	return true
}

// feedSigningPublicKeyBase64 is the canonical representation accepted by
// feeds.trusted_signing_keys (parsePinnedFeedSigningKeys uses StdEncoding first).
func feedSigningPublicKeyBase64(publicKey ed25519.PublicKey) string {
	return base64.StdEncoding.EncodeToString(publicKey)
}

// feedSigningFingerprint is the short human-readable key identity used in logs.
// It is derived from the public key only and carries no secret.
func feedSigningFingerprint(publicKey ed25519.PublicKey) string {
	if len(publicKey) != ed25519.PublicKeySize {
		return "ed25519:invalid"
	}
	return fmt.Sprintf("ed25519:%x", publicKey[:8])
}

// feedSigningKeyFileBytes returns the key material stored in a key file.
//
// Key material is binary, not text: no TrimSpace/Trim is ever applied to it. A
// randomly generated Ed25519 key may legitimately begin or end with a byte that
// unicode considers whitespace (0x20, 0x09, 0x0a, 0x0d, 0x0b, 0x0c); trimming the
// raw bytes silently shortens a valid 32-byte key (the P3 flaky provisioning
// bug). The only tolerated file decoration is one optional trailing line
// terminator ("\n" or "\r\n"). A file whose size already equals one of the
// accepted raw key sizes is returned verbatim, so a key whose last byte happens
// to be 0x0a/0x0d is never mistaken for a terminated shorter key.
func feedSigningKeyFileBytes(raw []byte, rawSizes ...int) []byte {
	matchesRawSize := func(n int) bool {
		for _, size := range rawSizes {
			if n == size {
				return true
			}
		}
		return false
	}
	if matchesRawSize(len(raw)) {
		return raw
	}
	// If a raw 32/64-byte key ends with 0x0d ('\r') and has a single '\n'
	// terminator appended (length 33/65), only the trailing '\n' is the
	// terminator; stripping "\r\n" first would drop the last key byte.
	if len(raw) > 0 && raw[len(raw)-1] == '\n' && matchesRawSize(len(raw)-1) {
		return raw[:len(raw)-1]
	}
	if len(raw) >= 2 && raw[len(raw)-2] == '\r' && raw[len(raw)-1] == '\n' {
		return raw[:len(raw)-2]
	}
	if len(raw) > 0 && raw[len(raw)-1] == '\n' {
		return raw[:len(raw)-1]
	}
	return raw
}

// loadFeedSigningKeyPair reads and validates the operator private key. The
// accepted shapes are the 32-byte Ed25519 seed (what --init-feed-signing
// writes) and the 64-byte private key, so an operator can migrate an existing
// Ed25519 key without converting it by hand. The bytes are used exactly as
// stored; only one optional trailing newline is stripped.
func loadFeedSigningKeyPair(path string) (*feedSigningKeyPair, error) {
	if !filepath.IsAbs(strings.TrimSpace(path)) {
		return nil, errors.New("feed signing key file must be an absolute path")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("feed signing key file is not readable: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("feed signing key must be a regular non-symlink file")
	}
	if info.Size() <= 0 || info.Size() > feedSigningKeyMaxBytes {
		return nil, errors.New("feed signing key size rejected")
	}
	if !validFeedSigningPrivateKeyMode(info.Mode()) {
		return nil, errors.New("feed signing key must be owner-readable and not group/other accessible (0600 or 0640)")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read feed signing key: %w", err)
	}
	fileSize := len(raw)
	keyBytes := feedSigningKeyFileBytes(raw, ed25519.SeedSize, ed25519.PrivateKeySize)
	switch len(keyBytes) {
	case ed25519.SeedSize:
		privateKey := ed25519.NewKeyFromSeed(keyBytes)
		return &feedSigningKeyPair{private: privateKey, public: privateKey.Public().(ed25519.PublicKey)}, nil
	case ed25519.PrivateKeySize:
		privateKey := ed25519.PrivateKey(append([]byte(nil), keyBytes...))
		return &feedSigningKeyPair{private: privateKey, public: privateKey.Public().(ed25519.PublicKey)}, nil
	default:
		return nil, fmt.Errorf("feed signing key must contain exactly a %d-byte seed or a %d-byte private key (optionally followed by a single newline); got %d bytes", ed25519.SeedSize, ed25519.PrivateKeySize, fileSize)
	}
}

// loadFeedSigningPublicKey reads a pinned public key file (raw 32 bytes or its
// base64 representation) so an operator can verify a deployment without the
// private key being present. The stored bytes are key material, not text: they
// are never trimmed, and only one optional trailing newline is tolerated.
func loadFeedSigningPublicKey(path string) (ed25519.PublicKey, error) {
	if !filepath.IsAbs(strings.TrimSpace(path)) {
		return nil, errors.New("feed public key file must be an absolute path")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("feed public key file is not readable: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("feed public key must be a regular non-symlink file")
	}
	if info.Size() <= 0 || info.Size() > feedSigningKeyMaxBytes {
		return nil, errors.New("feed public key size rejected")
	}
	if !validFeedSigningPublicKeyMode(info.Mode()) {
		return nil, errors.New("feed public key must not be writable")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read feed public key: %w", err)
	}
	fileSize := len(raw)
	// The raw form is the exact 32-byte key as written by --init-feed-signing;
	// binary key bytes are never trimmed or string-converted before this check.
	keyBytes := feedSigningKeyFileBytes(raw, ed25519.PublicKeySize)
	if len(keyBytes) == ed25519.PublicKeySize {
		return ed25519.PublicKey(append([]byte(nil), keyBytes...)), nil
	}
	decoded, decodeErr := base64.StdEncoding.DecodeString(string(keyBytes))
	if decodeErr != nil {
		decoded, decodeErr = base64.RawStdEncoding.DecodeString(string(keyBytes))
	}
	if decodeErr != nil || len(decoded) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("feed public key file must contain exactly a %d-byte raw Ed25519 public key or its base64 encoding (optionally followed by a single newline); got %d bytes", ed25519.PublicKeySize, fileSize)
	}
	return ed25519.PublicKey(decoded), nil
}

// feedSigningSnapshotDir resolves and validates the snapshot root once. The
// directory may not exist yet (first sync); it must be absolute and must not be
// a symlink, so the later EvalSymlinks jail cannot be steered by a link planted
// at the root itself.
func feedSigningSnapshotDir(snapshotDir string) (string, string, error) {
	trimmed := strings.TrimSpace(snapshotDir)
	if trimmed == "" {
		return "", "", errors.New("feeds.snapshot_dir must be configured for local feed signing")
	}
	absDir, err := filepath.Abs(trimmed)
	if err != nil {
		return "", "", fmt.Errorf("resolve feeds.snapshot_dir: %w", err)
	}
	if info, statErr := os.Lstat(absDir); statErr == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return "", "", errors.New("feeds.snapshot_dir must be a real directory, not a symlink")
		}
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return "", "", fmt.Errorf("inspect feeds.snapshot_dir: %w", statErr)
	}
	return absDir, filepath.Join(absDir, feedSigningSnapshotRawDir), nil
}

// resolveFeedSigningSnapshotPath maps a feed identifier to its snapshot path
// and proves the result stays inside the snapshot jail. The identifier is
// validated as a file-name token first; EvalSymlinks then resolves every
// existing component so a symlinked "raw" directory or snapshot file cannot
// redirect the read/write outside feeds.snapshot_dir.
func resolveFeedSigningSnapshotPath(snapshotDir, feedID string) (string, error) {
	if !validFeedSigningFeedID(feedID) {
		return "", fmt.Errorf("feed identifier %q is not a safe snapshot file name", feedID)
	}
	baseDir, rawDir, err := feedSigningSnapshotDir(snapshotDir)
	if err != nil {
		return "", err
	}
	resolvedBase := baseDir
	if resolved, evalErr := filepath.EvalSymlinks(baseDir); evalErr == nil {
		resolvedBase = resolved
	} else if !errors.Is(evalErr, os.ErrNotExist) {
		return "", fmt.Errorf("resolve feeds.snapshot_dir: %w", evalErr)
	}
	resolvedRaw := filepath.Join(resolvedBase, feedSigningSnapshotRawDir)
	if resolved, evalErr := filepath.EvalSymlinks(rawDir); evalErr == nil {
		resolvedRaw = resolved
	} else if !errors.Is(evalErr, os.ErrNotExist) {
		return "", fmt.Errorf("resolve feed snapshot directory: %w", evalErr)
	}
	if resolvedRaw != resolvedBase && !strings.HasPrefix(resolvedRaw, resolvedBase+string(os.PathSeparator)) {
		return "", errors.New("feed snapshot directory escapes feeds.snapshot_dir")
	}
	candidate := filepath.Join(resolvedRaw, feedID)
	if !strings.HasPrefix(candidate, resolvedRaw+string(os.PathSeparator)) {
		return "", errors.New("feed snapshot path escapes feeds.snapshot_dir")
	}
	return candidate, nil
}

// readFeedSnapshot reads a bounded, regular, non-symlink snapshot file. A file
// that is missing, a symlink, larger than the configured download bound or
// empty is rejected: local signing mode never falls back to the network, so a
// missing snapshot is a fail-closed condition, not a licence to download.
func readFeedSnapshot(snapshotDir, feedID string, maxBytes int64) ([]byte, string, error) {
	if maxBytes <= 0 {
		return nil, "", errors.New("feed snapshot size bound is not configured")
	}
	path, err := resolveFeedSigningSnapshotPath(snapshotDir, feedID)
	if err != nil {
		return nil, "", err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, "", NewThreatIntelSecurityException("feed snapshot is missing; feeds fail closed in local signing mode", err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return nil, "", NewThreatIntelSecurityException("feed snapshot must be a regular non-symlink file", nil)
	}
	if info.Size() <= 0 || info.Size() > maxBytes {
		return nil, "", NewThreatIntelSecurityException("feed snapshot size rejected", nil)
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, "", NewThreatIntelSecurityException("feed snapshot read failed", err)
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, maxBytes+1))
	if err != nil {
		return nil, "", NewThreatIntelSecurityException("feed snapshot read failed", err)
	}
	if int64(len(raw)) > maxBytes {
		return nil, "", NewThreatIntelSecurityException("feed snapshot exceeds the bounded size limit", nil)
	}
	return raw, path, nil
}

// verifyFeedSigningManifest is the in-memory twin of readSignedFeedManifest and
// is used by the pipeline self-check and by tests before anything is written.
func verifyFeedSigningManifest(document threatFeedManifestDocument, keys []ed25519.PublicKey) error {
	signature, err := base64.StdEncoding.DecodeString(strings.TrimSpace(document.Signature))
	if err != nil {
		signature, err = base64.RawStdEncoding.DecodeString(strings.TrimSpace(document.Signature))
	}
	if err != nil || len(signature) != ed25519.SignatureSize {
		return errors.New("feed manifest signature encoding rejected")
	}
	message := threatFeedManifestMessageFor(document)
	for _, key := range keys {
		if ed25519.Verify(key, message, signature) {
			return nil
		}
	}
	return errors.New("feed manifest signature verification failed")
}

type feedSigningSelfHealMarker struct {
	Schema    string `json:"schema"`
	PublicKey string `json:"public_key"`
}

// readFeedSigningSelfHealMarker loads and validates a published marker. A
// malformed marker and a marker that names a different key are both hard errors:
// the second is a rotation signal that must be resolved by an explicit pin, not
// silently re-trusted.
func readFeedSigningSelfHealMarker(path, expectedKey string) (feedSigningSelfHealMarker, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return feedSigningSelfHealMarker{}, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return feedSigningSelfHealMarker{}, errors.New("feed signing self-heal marker must be a regular non-symlink file")
	}
	if info.Size() <= 0 || info.Size() > feedSigningKeyMaxBytes {
		return feedSigningSelfHealMarker{}, errors.New("feed signing self-heal marker size rejected")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return feedSigningSelfHealMarker{}, fmt.Errorf("read feed signing self-heal marker: %w", err)
	}
	return validateFeedSigningSelfHealMarker(raw, expectedKey)
}

func validateFeedSigningSelfHealMarker(raw []byte, expectedKey string) (feedSigningSelfHealMarker, error) {
	var marker feedSigningSelfHealMarker
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&marker); err != nil {
		return feedSigningSelfHealMarker{}, errors.New("feed signing self-heal marker is malformed")
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return feedSigningSelfHealMarker{}, errors.New("feed signing self-heal marker is malformed")
	}
	if marker.Schema != "vgt.feed-signing.self-heal/v1" {
		return feedSigningSelfHealMarker{}, errors.New("feed signing self-heal marker is malformed")
	}
	if marker.PublicKey != expectedKey {
		return feedSigningSelfHealMarker{}, errors.New("feed signing self-heal marker does not match the operator key; explicit pin required after rotation")
	}
	return marker, nil
}

// selfHealFeedSigningPin is the narrow bootstrap for the documented operational
// failure: local_signing=true, an operator key exists, but
// feeds.trusted_signing_keys was never provisioned. The explicit opt-in, a
// secure 0600/0640 key file and a stable self-heal marker are required. A
// rotation (new key, old marker) fails closed and requires an operator pin.
func selfHealFeedSigningPin(cfg FeedConfig, stateDir string) (ed25519.PublicKey, bool, error) {
	if !cfg.LocalSigning || !cfg.RequireSignedManifest || len(cfg.TrustedSigningKeys) != 0 {
		return nil, false, nil
	}
	keyFile := strings.TrimSpace(cfg.SigningKeyFile)
	if keyFile == "" {
		return nil, false, errors.New("feeds.local_signing requires feeds.signing_key_file for self-healing")
	}
	key, err := loadFeedSigningKeyPair(keyFile)
	if err != nil {
		return nil, false, err
	}
	markerPath := filepath.Join(stateDir, feedSigningSelfHealMarkerFile)
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return nil, false, fmt.Errorf("prepare feed signing self-heal state: %w", err)
	}
	expectedKey := feedSigningPublicKeyBase64(key.public)
	if info, statErr := os.Lstat(markerPath); statErr == nil {
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return nil, false, errors.New("feed signing self-heal marker must be a regular non-symlink file")
		}
		if _, readErr := readFeedSigningSelfHealMarker(markerPath, expectedKey); readErr != nil {
			return nil, false, readErr
		}
		return key.public, true, nil
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return nil, false, fmt.Errorf("inspect feed signing self-heal marker: %w", statErr)
	}
	if err := writeFeedSigningSelfHealMarker(markerPath, expectedKey); err != nil {
		return nil, false, err
	}
	// Success is only reported after the published marker was read back and
	// validated; an interrupted or stale temporary file cannot produce this state.
	if _, err := readFeedSigningSelfHealMarker(markerPath, expectedKey); err != nil {
		return nil, false, err
	}
	return key.public, true, nil
}

// localSigningKeyState returns a race-free view of the lazily loaded operator
// key. It takes feedSigningMu, never m.mu, so it is safe both from the sync
// pipeline (lock-free) and from the kernel-apply gate (m.mu held).
func (m *FeedManager) localSigningKeyState() (*feedSigningKeyPair, error) {
	m.feedSigningMu.Lock()
	defer m.feedSigningMu.Unlock()
	return m.feedSigningKey, m.feedSigningErr
}

// localSigningKeyPinned proves that the operator key which will sign manifests
// is one of the pinned verification keys. Signing with a key that is not pinned
// would produce a manifest the manager itself refuses, so the pipeline rejects
// the configuration before it writes anything.
func (m *FeedManager) localSigningKeyPinned(policy feedLocalSigningPolicy) error {
	key, err := m.localSigningKeyState()
	if err != nil {
		return err
	}
	if key == nil {
		return errors.New("feed signing key is not loaded")
	}
	for _, pinned := range policy.pinnedKeys {
		if pinned.Equal(key.public) {
			return nil
		}
	}
	return fmt.Errorf("feeds.local_signing key %s is not pinned in feeds.trusted_signing_keys; kernel apply and feed acceptance would fail closed",
		feedSigningFingerprint(key.public))
}

// fetchSourceFromSnapshot is the consumer half of local signing: it reads the
// snapshot bytes instead of the network and runs the exact same verification
// chain (raw digest, parsed indicator digest) against the signed manifest. The
// signed URL stays the configured HTTPS URL, so provenance is unchanged.
func (m *FeedManager) fetchSourceFromSnapshot(src ThreatFeedSource, snapshot *threatIntelSnapshot) ([]string, *threatFeedCertificate, error) {
	if snapshot == nil {
		return nil, nil, NewThreatIntelValidationException("threat intelligence configuration unavailable", nil)
	}
	if _, err := validateFeedSourceURL(src.URL); err != nil {
		return nil, nil, err
	}
	policy := m.localSigningPolicy()
	maxEntries, maxBytes, _ := snapshot.feedBounds(src)
	raw, _, err := readFeedSnapshot(policy.snapshotDir, src.ID, maxBytes)
	if err != nil {
		return nil, nil, err
	}
	// AP-9/S09/R5 interim isolation: a signed snapshot is still untrusted bytes
	// at the parser boundary, so it is shadow-parsed before verification/parsing.
	if shadowErr := tufShadowValidateFeedBytes(raw, maxEntries, maxBytes); shadowErr != nil {
		return nil, nil, shadowErr
	}
	certificate, err := m.verifyFeedArtifact(src, raw)
	if err != nil {
		return nil, nil, err
	}
	if certificate == nil {
		return nil, nil, NewThreatIntelSecurityException("local feed signing is enabled but the signed manifest was not verified", nil)
	}
	items, err := parseFeedRaw(src, raw, "", snapshot.settings.Validation, maxEntries)
	if err != nil {
		return nil, nil, err
	}
	if err := m.verifyFeedItemsDigest(certificate, src, items); err != nil {
		return nil, nil, err
	}
	return items, certificate, nil
}

// localSigningApplyGate is the kernel-apply half of the trust anchor check. It
// runs while the manager write lock is held, so it must not re-enter m.mu; it
// only reads the already-parsed pinned keys and the lazily loaded operator key.
func (m *FeedManager) localSigningApplyGate() error {
	if !m.cfg.LocalSigning {
		return nil
	}
	key, err := m.localSigningKeyState()
	if err != nil {
		return err
	}
	if key == nil {
		return errors.New("feeds.local_signing is enabled but the operator signing key was never loaded")
	}
	for _, pinned := range m.signingKeys {
		if pinned.Equal(key.public) {
			return nil
		}
	}
	return fmt.Errorf("feeds.local_signing key %s is not pinned in feeds.trusted_signing_keys; kernel apply refused",
		feedSigningFingerprint(key.public))
}
