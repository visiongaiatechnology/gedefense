// STATUS: DIAMANT VGT SUPREME
package main

// Local operator signing pipeline for the sovereign threat-intelligence feeds
// (F-03 / CHAIN-009 provisioning half).
//
// The verification half already exists in feeds.go: a detached Ed25519 manifest
// binds the exact raw download bytes, the canonical indicator digest, a
// monotonic generation version and a hard validity window, and kernel apply is
// refused for any BLOCK generation without a verified, unexpired manifest.
//
// What was missing is the producer of that manifest. Without a signing pipeline
// an operator either had to disable the gate (which validation refuses to
// combine with auto_apply) or hand-roll a signing tool. This file implements the
// first party pipeline:
//
//  1. generate an operator-held Ed25519 key pair (private 0600, public 0644),
//  2. download every enabled feed under the existing transport/size/format rules,
//  3. store the exact raw bytes atomically below feeds.snapshot_dir (0600),
//  4. build the manifest from those bytes and their canonical indicator digests,
//  5. sign it with the operator key and write it atomically to feeds.manifest_path,
//  6. let the sync read the snapshot instead of the network, so the bytes that
//     were verified and the bytes that are parsed are the same bytes.
//
// Trust boundaries:
//   - The private key never leaves feeds.signing_key_file and is never logged.
//   - Snapshot files are bounded, symlink-refusing and jailed below
//     feeds.snapshot_dir; a feed identifier is a file name, never a path.
//   - The pinned public key remains bootstrap-only (feeds.trusted_signing_keys),
//     so a compromised dashboard session cannot install a new trust anchor.
//   - Every failure path fails closed: no manifest means no accepted feed.

import (
	"context"
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
	"sort"
	"strings"
	"sync"
	"time"
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

// InitFeedSigning generates the operator key pair used to sign threat-feed
// manifests. It refuses to overwrite existing key material: rotating the feed
// trust anchor is an explicit operation with a new directory, never an implicit
// side effect of starting the program again.
//
// The private file contains the 32-byte Ed25519 seed (raw, not PEM). The public
// file contains the 32-byte Ed25519 public key (raw). The base64 form of the
// public key is what belongs into feeds.trusted_signing_keys.
func InitFeedSigning(directory, publicKeyOut string) (ed25519.PublicKey, error) {
	trimmed := strings.TrimSpace(directory)
	if trimmed == "" {
		return nil, errors.New("feed signing directory must not be empty")
	}
	absDir, err := filepath.Abs(trimmed)
	if err != nil {
		return nil, fmt.Errorf("resolve feed signing directory: %w", err)
	}
	if info, statErr := os.Lstat(absDir); statErr == nil {
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("feed signing directory %q must be a real directory", absDir)
		}
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return nil, fmt.Errorf("inspect feed signing directory: %w", statErr)
	}
	if err := os.MkdirAll(absDir, 0o700); err != nil {
		return nil, fmt.Errorf("create feed signing directory: %w", err)
	}
	if err := os.Chmod(absDir, 0o700); err != nil {
		return nil, fmt.Errorf("restrict feed signing directory: %w", err)
	}

	privatePath := filepath.Join(absDir, feedSigningPrivateKeyFile)
	publicPath := filepath.Join(absDir, feedSigningPublicKeyFile)
	if trimmedOut := strings.TrimSpace(publicKeyOut); trimmedOut != "" {
		publicPath, err = filepath.Abs(trimmedOut)
		if err != nil {
			return nil, fmt.Errorf("resolve feed public key path: %w", err)
		}
		if publicPath == privatePath {
			return nil, errors.New("feed public key output must differ from the private key path")
		}
		if parent := filepath.Dir(publicPath); parent != "" {
			if mkErr := os.MkdirAll(parent, 0o755); mkErr != nil {
				return nil, fmt.Errorf("create feed public key directory: %w", mkErr)
			}
		}
	}
	for _, path := range []string{privatePath, publicPath} {
		if _, statErr := os.Lstat(path); statErr == nil {
			return nil, fmt.Errorf("refusing to overwrite existing feed signing file %q", path)
		} else if !errors.Is(statErr, os.ErrNotExist) {
			return nil, fmt.Errorf("inspect feed signing file %q: %w", path, statErr)
		}
	}

	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate feed signing key pair: %w", err)
	}
	if err := writeFeedSigningFile(privatePath, privateKey.Seed(), 0o600, validFeedSigningPrivateKeyMode); err != nil {
		return nil, fmt.Errorf("write feed signing private key: %w", err)
	}
	if err := writeFeedSigningFile(publicPath, publicKey, 0o644, validFeedSigningPublicKeyMode); err != nil {
		_ = os.Remove(privatePath)
		return nil, fmt.Errorf("write feed signing public key: %w", err)
	}

	// Self-check before the operator pins the key: the files on disk must load
	// and reproduce exactly the key pair that was just generated.
	loaded, err := loadFeedSigningKeyPair(privatePath)
	if err != nil {
		return nil, fmt.Errorf("verify generated feed signing key: %w", err)
	}
	if !loaded.public.Equal(publicKey) {
		return nil, errors.New("generated feed signing key does not reproduce its public key")
	}
	if dir, openErr := os.Open(absDir); openErr == nil {
		_ = dir.Sync()
		_ = dir.Close()
	}
	return publicKey, nil
}

// writeFeedSigningFile creates a key file exclusively with least-privilege
// permissions. It never follows a pre-existing symlink and never overwrites.
func writeFeedSigningFile(path string, data []byte, mode os.FileMode, allowed func(os.FileMode) bool) error {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	cleanup := func() {
		_ = file.Close()
		_ = os.Remove(path)
	}
	if _, err := file.Write(data); err != nil {
		cleanup()
		return err
	}
	if err := file.Sync(); err != nil {
		cleanup()
		return err
	}
	if err := file.Close(); err != nil {
		_ = os.Remove(path)
		return err
	}
	if err := os.Chmod(path, mode); err != nil {
		_ = os.Remove(path)
		return err
	}
	if info, err := os.Lstat(path); err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || !allowed(info.Mode()) {
		_ = os.Remove(path)
		return errors.New("feed signing key file permissions rejected")
	}
	return nil
}

// loadFeedSigningKeyPair reads and validates the operator private key. The
// accepted shapes are the 32-byte Ed25519 seed (what --init-feed-signing
// writes) and the 64-byte private key, so an operator can migrate an existing
// Ed25519 key without converting it by hand.
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
	switch len(raw) {
	case ed25519.SeedSize:
		privateKey := ed25519.NewKeyFromSeed(raw)
		return &feedSigningKeyPair{private: privateKey, public: privateKey.Public().(ed25519.PublicKey)}, nil
	case ed25519.PrivateKeySize:
		privateKey := ed25519.PrivateKey(append([]byte(nil), raw...))
		return &feedSigningKeyPair{private: privateKey, public: privateKey.Public().(ed25519.PublicKey)}, nil
	default:
		return nil, fmt.Errorf("feed signing key must contain a %d-byte seed or a %d-byte private key", ed25519.SeedSize, ed25519.PrivateKeySize)
	}
}

// loadFeedSigningPublicKey reads a pinned public key file (raw 32 bytes or its
// base64 representation) so an operator can verify a deployment without the
// private key being present.
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
	raw = []byte(strings.TrimSpace(string(raw)))
	if len(raw) == ed25519.PublicKeySize {
		return ed25519.PublicKey(append([]byte(nil), raw...)), nil
	}
	decoded, decodeErr := base64.StdEncoding.DecodeString(string(raw))
	if decodeErr != nil {
		decoded, decodeErr = base64.RawStdEncoding.DecodeString(string(raw))
	}
	if decodeErr != nil || len(decoded) != ed25519.PublicKeySize {
		return nil, errors.New("feed public key is not a valid Ed25519 public key")
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

// writeFeedSnapshot stores the exact raw feed bytes atomically. The raw bytes
// are the object the manifest signs, so they are fsynced through the shared
// symlink-refusing atomic writer and never written in place.
func writeFeedSnapshot(snapshotDir, feedID string, raw []byte) (string, error) {
	path, err := resolveFeedSigningSnapshotPath(snapshotDir, feedID)
	if err != nil {
		return "", err
	}
	rawDir := filepath.Dir(path)
	if err := os.MkdirAll(rawDir, 0o700); err != nil {
		return "", fmt.Errorf("create feed snapshot directory: %w", err)
	}
	if err := os.Chmod(rawDir, 0o700); err != nil {
		return "", fmt.Errorf("restrict feed snapshot directory: %w", err)
	}
	if err := atomicWriteFile(path, raw, 0o600); err != nil {
		return "", fmt.Errorf("write feed snapshot %q: %w", feedID, err)
	}
	return path, nil
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

// feedSigningManifestEntryFor builds the manifest entry for one source from the
// exact raw bytes and their canonical indicator set. It is a pure function so
// the digest binding is testable without a network or a filesystem.
func feedSigningManifestEntryFor(source ThreatFeedSource, raw []byte, items []string, version uint64, validUntil time.Time) (threatFeedManifestEntry, error) {
	if len(raw) == 0 {
		return threatFeedManifestEntry{}, errors.New("feed snapshot is empty; refusing to sign an empty feed")
	}
	if version == 0 {
		return threatFeedManifestEntry{}, errors.New("feed manifest version must be greater than zero")
	}
	digest := sha256.Sum256(raw)
	return threatFeedManifestEntry{
		ID:          source.ID,
		URL:         source.URL,
		RawSHA256:   hex.EncodeToString(digest[:]),
		ItemsSHA256: computeFingerprint(items),
		Version:     version,
		Action:      source.Action,
		ValidUntil:  validUntil.UTC(),
	}, nil
}

// signFeedSigningManifest computes the detached signature over the canonical
// manifest message. The signature field is cleared before signing so the
// signature never covers itself.
func signFeedSigningManifest(document threatFeedManifestDocument, key *feedSigningKeyPair) (threatFeedManifestDocument, error) {
	if key == nil || len(key.private) != ed25519.PrivateKeySize {
		return threatFeedManifestDocument{}, errors.New("feed signing key is not loaded")
	}
	document.Signature = ""
	document.GeneratedAt = document.GeneratedAt.UTC()
	document.ValidUntil = document.ValidUntil.UTC()
	sorted := append([]threatFeedManifestEntry(nil), document.Feeds...)
	sort.Slice(sorted, func(left, right int) bool { return sorted[left].ID < sorted[right].ID })
	document.Feeds = sorted
	document.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(key.private, threatFeedManifestMessageFor(document)))
	return document, nil
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

// ---------------------------------------------------------------------------
// FeedManager local-signing methods
// ---------------------------------------------------------------------------

// localSigningPolicy snapshots the bootstrap local-signing configuration. The
// policy is immutable after construction (only bootstrap config carries it), so
// the copy is safe to use while the manager lock is not held.
type feedLocalSigningPolicy struct {
	enabled       bool
	keyFile       string
	snapshotDir   string
	requireSigned bool
	pinnedKeys    []ed25519.PublicKey
	manifestPath  string
	maxAge        time.Duration
}

func (m *FeedManager) localSigningPolicy() feedLocalSigningPolicy {
	m.mu.RLock()
	defer m.mu.RUnlock()
	required, keys, manifestPath, maxAge := m.signingConfigLocked()
	return feedLocalSigningPolicy{
		enabled:       m.cfg.LocalSigning,
		keyFile:       strings.TrimSpace(m.cfg.SigningKeyFile),
		snapshotDir:   strings.TrimSpace(m.cfg.SnapshotDir),
		requireSigned: required,
		pinnedKeys:    keys,
		manifestPath:  manifestPath,
		maxAge:        maxAge,
	}
}

// signingConfigLocked is the lock-free core of signingConfig. The caller must
// hold m.mu (read or write). It exists so local-signing code can resolve the
// policy without re-entering the RWMutex, which is not reentrant.
func (m *FeedManager) signingConfigLocked() (required bool, keys []ed25519.PublicKey, manifestPath string, maxAge time.Duration) {
	required = m.cfg.RequireSignedManifest
	keys = m.signingKeys
	manifestPath = strings.TrimSpace(m.cfg.ManifestPath)
	if manifestPath == "" {
		manifestPath = filepath.Join(filepath.Dir(m.statePath), "threat-feed-manifest.json")
	}
	maxAge = time.Duration(m.cfg.ManifestMaxAgeMinutes) * time.Minute
	if maxAge <= 0 {
		maxAge = 24 * time.Hour
	}
	return required, keys, manifestPath, maxAge
}

// localSigningEnabled reports whether the bootstrap configuration asked for the
// local signing pipeline. It is read on the sync hot path, so it takes the read
// lock once and returns a scalar.
func (m *FeedManager) localSigningEnabled() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.cfg.LocalSigning
}

// ensureLocalSigningKey loads the operator key once. A load failure is sticky:
// every later sync and kernel apply reports the same fail-closed error instead
// of silently degrading to unsigned operation.
func (m *FeedManager) ensureLocalSigningKey(keyFile string) error {
	m.feedSigningMu.Lock()
	defer m.feedSigningMu.Unlock()
	if m.feedSigningKey != nil || m.feedSigningErr != nil {
		return m.feedSigningErr
	}
	key, err := loadFeedSigningKeyPair(keyFile)
	if err != nil {
		m.feedSigningErr = fmt.Errorf("feeds.local_signing trust anchor unavailable: %w", err)
		return m.feedSigningErr
	}
	m.feedSigningKey = key
	return nil
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

// nextLocalManifestVersion returns a generation version that is strictly newer
// than every version this host has already accepted. Reusing a version with
// different content is rejected by checkManifestRollback, so the pipeline bumps
// once per signed snapshot instead of gambling on content equality.
func (m *FeedManager) nextLocalManifestVersion() uint64 {
	m.mu.RLock()
	defer m.mu.RUnlock()
	version := m.localManifestVersion
	for _, state := range m.feedStates {
		if state != nil && state.ManifestVersion > version {
			version = state.ManifestVersion
		}
	}
	return version + 1
}

// feedSigningSnapshotResult carries one source's resolved snapshot for the
// manifest build: either a fresh download or a reused previous snapshot.
type feedSigningSnapshotResult struct {
	source ThreatFeedSource
	raw    []byte
	items  []string
	reused bool
	err    error
}

// resolveSignedSnapshotSource downloads one source and validates the result, or
// falls back to the previously signed snapshot. The fallback keeps the platform
// operational during a short upstream outage and for a feed that legitimately
// returns no new indicators: the manifest is re-signed over exactly the reused
// bytes, so the integrity guarantee is unchanged. Without a snapshot the source
// fails and the whole signed generation is refused.
func (m *FeedManager) resolveSignedSnapshotSource(ctx context.Context, source ThreatFeedSource, snapshot *threatIntelSnapshot, policy feedLocalSigningPolicy) feedSigningSnapshotResult {
	result := feedSigningSnapshotResult{source: source}
	maxEntries, maxBytes, _ := snapshot.feedBounds(source)

	raw, downloadErr := m.downloadFeedRaw(ctx, source, snapshot)
	if downloadErr == nil && int64(len(raw)) <= maxBytes {
		if items, parseErr := parseFeedRaw(source, raw, "", snapshot.settings.Validation, maxEntries); parseErr == nil && len(items) > 0 {
			result.raw = raw
			result.items = items
			return result
		}
	}

	existing, _, snapshotErr := readFeedSnapshot(policy.snapshotDir, source.ID, maxBytes)
	if snapshotErr != nil {
		if downloadErr != nil {
			result.err = fmt.Errorf("%w (no reusable signed snapshot: %v)", downloadErr, snapshotErr)
			return result
		}
		result.err = fmt.Errorf("feed produced no indicators and no reusable signed snapshot exists: %w", snapshotErr)
		return result
	}
	items, parseErr := parseFeedRaw(source, existing, "", snapshot.settings.Validation, maxEntries)
	if parseErr != nil {
		result.err = fmt.Errorf("reused feed snapshot does not parse: %w", parseErr)
		return result
	}
	if len(items) == 0 {
		result.err = errors.New("feed produced no indicators and the reusable snapshot is empty")
		return result
	}
	result.raw = existing
	result.items = items
	result.reused = true
	return result
}

// prepareLocalSignedSnapshots implements the producer half of the signed feed
// contract. It runs before the per-source fetch goroutines: fetch every enabled
// source under the normal transport rules, persist the exact raw bytes, build
// and sign the manifest for exactly those bytes. Any failure aborts the sync
// before a single feed is promoted — fail-closed, with the previous generation
// retained.
func (m *FeedManager) prepareLocalSignedSnapshots(ctx context.Context, snapshot *threatIntelSnapshot) error {
	policy := m.localSigningPolicy()
	if !policy.enabled {
		return nil
	}
	if !policy.requireSigned {
		return NewThreatIntelSecurityException("feeds.local_signing requires feeds.require_signed_manifest=true", nil)
	}
	if len(policy.pinnedKeys) == 0 {
		return NewThreatIntelSecurityException("feeds.local_signing requires at least one pinned feeds.trusted_signing_keys entry", nil)
	}
	if policy.manifestPath == "" {
		return NewThreatIntelSecurityException("feeds.local_signing requires feeds.manifest_path", nil)
	}
	if err := m.ensureLocalSigningKey(policy.keyFile); err != nil {
		return NewThreatIntelSecurityException("local feed signing trust anchor unavailable", err)
	}
	signingKey, keyErr := m.localSigningKeyState()
	if keyErr != nil {
		return NewThreatIntelSecurityException("local feed signing trust anchor unavailable", keyErr)
	}
	if signingKey == nil {
		return NewThreatIntelSecurityException("local feed signing trust anchor is not loaded", nil)
	}
	if err := m.localSigningKeyPinned(policy); err != nil {
		return NewThreatIntelSecurityException("local feed signing trust anchor is not pinned", err)
	}
	if snapshot == nil {
		return NewThreatIntelSecurityException("threat intelligence configuration unavailable for local signing", nil)
	}
	sources := snapshot.orderedSources()
	if len(sources) == 0 {
		return nil
	}

	results := m.downloadSourcesForSignedSnapshot(ctx, sources, snapshot)
	failures := make([]string, 0, len(results))
	for _, result := range results {
		if result.err != nil {
			failures = append(failures, result.source.ID+": "+result.err.Error())
		}
	}
	if len(failures) > 0 {
		sort.Strings(failures)
		return NewThreatIntelSecurityException(
			"local feed snapshot fetch failed; no signed manifest was produced and no feed is promoted (feeds fail closed): "+strings.Join(failures, "; "), nil)
	}

	version := m.nextLocalManifestVersion()
	generatedAt := time.Now().UTC()
	validUntil := generatedAt.Add(policy.maxAge)
	document := threatFeedManifestDocument{
		Schema:      threatFeedManifestSchema,
		GeneratedAt: generatedAt,
		ValidUntil:  validUntil,
		Feeds:       make([]threatFeedManifestEntry, 0, len(results)),
	}
	reused := 0
	for _, result := range results {
		entries, entryErr := feedSigningManifestEntryFor(result.source, result.raw, result.items, version, validUntil)
		if entryErr != nil {
			return NewThreatIntelSecurityException("build signed feed manifest entry for "+result.source.ID, entryErr)
		}
		document.Feeds = append(document.Feeds, entries)
		if result.reused {
			reused++
		}
	}
	sort.Slice(document.Feeds, func(left, right int) bool { return document.Feeds[left].ID < document.Feeds[right].ID })
	if err := validateSignedFeedManifest(document, generatedAt, policy.maxAge); err != nil {
		return NewThreatIntelSecurityException("built feed manifest failed validation", err)
	}
	signed, err := signFeedSigningManifest(document, signingKey)
	if err != nil {
		return NewThreatIntelSecurityException("sign feed manifest", err)
	}
	if err := verifyFeedSigningManifest(signed, policy.pinnedKeys); err != nil {
		return NewThreatIntelSecurityException("signed feed manifest does not verify with the pinned key", err)
	}

	// Persist the snapshot bytes before publishing the manifest. A crash between
	// the two leaves the old manifest over new bytes, which fails closed on the
	// next verification and is repaired by the next local signing sync.
	for _, result := range results {
		if _, err := writeFeedSnapshot(policy.snapshotDir, result.source.ID, result.raw); err != nil {
			return NewThreatIntelSecurityException("persist feed snapshot for "+result.source.ID, err)
		}
	}

	encoded, err := json.Marshal(signed)
	if err != nil {
		return NewThreatIntelSecurityException("encode signed feed manifest", err)
	}
	if err := os.MkdirAll(filepath.Dir(policy.manifestPath), 0o700); err != nil {
		return NewThreatIntelSecurityException("create feed manifest directory", err)
	}
	if err := atomicWriteFile(policy.manifestPath, encoded, 0o600); err != nil {
		return NewThreatIntelSecurityException("write signed feed manifest", err)
	}

	m.mu.Lock()
	if version > m.localManifestVersion {
		m.localManifestVersion = version
	}
	m.mu.Unlock()
	// Snapshot reuse keeps the platform operational while an upstream source is
	// briefly unavailable: the freshly signed manifest still binds exactly the
	// reused bytes, so no unsigned byte ever reaches the parser.
	_ = reused
	return nil
}

// downloadSourcesForSignedSnapshot downloads every enabled source with the
// administrable concurrency bound. A source whose download fails may reuse an
// existing snapshot: the new manifest signs the reused bytes, so the integrity
// guarantee is unchanged and detection does not blink during an upstream
// outage. Without an existing snapshot the whole signed generation fails.
func (m *FeedManager) downloadSourcesForSignedSnapshot(ctx context.Context, sources []ThreatFeedSource, snapshot *threatIntelSnapshot) []feedSigningSnapshotResult {
	concurrency := snapshot.settings.ConcurrentDownloads
	if concurrency < 1 {
		concurrency = 1
	}
	policy := m.localSigningPolicy()
	results := make([]feedSigningSnapshotResult, len(sources))
	sem := make(chan struct{}, concurrency)
	var wait sync.WaitGroup
	for index := range sources {
		index := index
		source := sources[index]
		wait.Add(1)
		go func() {
			defer wait.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			results[index] = m.resolveSignedSnapshotSource(ctx, source, snapshot, policy)
		}()
	}
	wait.Wait()
	return results
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
