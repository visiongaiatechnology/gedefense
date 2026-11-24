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
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

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

// ---------------------------------------------------------------------------
// FeedManager local-signing methods
// ---------------------------------------------------------------------------

// feedSigningSelfHealMarkerFile records the local feed-signing public key that
// this host already trusted through the opt-in local-signing pipeline. It is a
// public-key marker, not a secret. A marker that no longer matches the operator
// key is a rotation/compromise signal and must fail closed instead of silently
// re-pinning a new key.
const feedSigningSelfHealMarkerFile = "feed-signing.self-heal.json"

// feedSigningSelfHealTempPrefix is the reserved prefix of the exclusive
// temporary files the marker writer creates inside the state directory. A
// remnant from an interrupted write carries this prefix, is never mistaken for a
// published marker, and is removed by the next write.
const (
	feedSigningSelfHealTempPattern = ".feed-signing-self-heal-*.tmp"
	feedSigningSelfHealTempPrefix  = ".feed-signing-self-heal-"
)

// removeStaleFeedSigningSelfHealTemps removes remnants of interrupted marker
// writes. A stale temporary file is never a reason to report success: the only
// object that proves the self-heal is a published, validated marker. A symbolic
// link or directory with a matching name is left alone (ReadDir does not follow
// links and the caller only removes regular files).
func removeStaleFeedSigningSelfHealTemps(dir string) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, entry := range entries {
		name := entry.Name()
		if name != feedSigningSelfHealMarkerFile+".tmp" && !strings.HasPrefix(name, feedSigningSelfHealTempPrefix) {
			continue
		}
		candidate := filepath.Join(dir, name)
		if info, infoErr := os.Lstat(candidate); infoErr == nil && info.Mode().IsRegular() {
			_ = os.Remove(candidate)
		}
	}
}

// writeFeedSigningSelfHealMarker publishes the marker atomically:
//
//  1. an exclusive temporary file is created in the destination directory with a
//     random name (os.CreateTemp), so a stale or corrupt ".tmp" left by a crash
//     can never collide with the write and can never be mistaken for success;
//  2. the exact written bytes are re-read and validated against the expected
//     pinned public key before anything is published;
//  3. only then is the temporary file renamed over the marker name.
//
// The previous implementation opened a fixed "<marker>.tmp" with O_EXCL and
// returned success on os.ErrExist. A leftover temporary file therefore made the
// function claim "self-healed" without a marker ever being validated or created.
func writeFeedSigningSelfHealMarker(markerPath, expectedKey string) error {
	dir := filepath.Dir(markerPath)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("prepare feed signing self-heal state: %w", err)
	}
	// A symlink or directory at the final name is refused before the replace; the
	// rename itself replaces the directory entry and never follows it.
	if info, err := os.Lstat(markerPath); err == nil {
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("feed signing self-heal marker must be a regular non-symlink file")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect feed signing self-heal marker: %w", err)
	}

	removeStaleFeedSigningSelfHealTemps(dir)

	payload, err := json.Marshal(feedSigningSelfHealMarker{
		Schema: "vgt.feed-signing.self-heal/v1", PublicKey: expectedKey,
	})
	if err != nil {
		return err
	}
	temp, err := os.CreateTemp(dir, feedSigningSelfHealTempPattern)
	if err != nil {
		return fmt.Errorf("create feed signing self-heal temporary file: %w", err)
	}
	tempPath := temp.Name()
	cleanup := func() {
		_ = temp.Close()
		_ = os.Remove(tempPath)
	}
	if err := temp.Chmod(0o600); err != nil {
		cleanup()
		return fmt.Errorf("restrict feed signing self-heal temporary file: %w", err)
	}
	if _, err := temp.Write(payload); err != nil {
		cleanup()
		return fmt.Errorf("write feed signing self-heal temporary file: %w", err)
	}
	if err := temp.Sync(); err != nil {
		cleanup()
		return fmt.Errorf("flush feed signing self-heal temporary file: %w", err)
	}
	if err := temp.Close(); err != nil {
		_ = os.Remove(tempPath)
		return fmt.Errorf("close feed signing self-heal temporary file: %w", err)
	}

	// Validate the published bytes, not the in-memory intent: a short write or a
	// filesystem defect must surface here, before the marker name resolves to it.
	written, err := os.ReadFile(tempPath)
	if err != nil {
		_ = os.Remove(tempPath)
		return fmt.Errorf("re-read feed signing self-heal temporary file: %w", err)
	}
	if _, err := validateFeedSigningSelfHealMarker(written, expectedKey); err != nil {
		_ = os.Remove(tempPath)
		return err
	}

	// A concurrent writer may have published a marker between the Lstat above and
	// this point. Its content is validated first; a mismatch stays fail-closed.
	if _, statErr := os.Lstat(markerPath); statErr == nil {
		if _, readErr := readFeedSigningSelfHealMarker(markerPath, expectedKey); readErr != nil {
			_ = os.Remove(tempPath)
			return readErr
		}
		_ = os.Remove(tempPath)
		return nil
	} else if !errors.Is(statErr, os.ErrNotExist) {
		_ = os.Remove(tempPath)
		return fmt.Errorf("inspect feed signing self-heal marker: %w", statErr)
	}

	if err := os.Rename(tempPath, markerPath); err != nil {
		_ = os.Remove(tempPath)
		return fmt.Errorf("publish feed signing self-heal marker: %w", err)
	}
	if dirHandle, openErr := os.Open(dir); openErr == nil {
		_ = dirHandle.Sync()
		_ = dirHandle.Close()
	}
	return nil
}

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
		// AP-9/S09/R5 interim isolation: the downloaded bytes are shadow-parsed
		// before they are parsed or signed. A document that fails the bounded
		// shadow parse falls through to the reusable signed snapshot.
		if shadowErr := tufShadowValidateFeedBytes(raw, maxEntries, maxBytes); shadowErr == nil {
			if items, parseErr := parseFeedRaw(source, raw, "", snapshot.settings.Validation, maxEntries); parseErr == nil && len(items) > 0 {
				result.raw = raw
				result.items = items
				return result
			}
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
	if shadowErr := tufShadowValidateFeedBytes(existing, maxEntries, maxBytes); shadowErr != nil {
		result.err = fmt.Errorf("reused feed snapshot rejected by the bounded shadow parser: %w", shadowErr)
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
