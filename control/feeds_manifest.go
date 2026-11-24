// STATUS: DIAMANT VGT SUPREME
// Signed threat-feed manifest (F-03 / CHAIN-009) envelope and verification
package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// ---------------------------------------------------------------------------
// Signed threat-feed manifests (F-03 / CHAIN-009)
//
// The upstream feeds are plain HTTPS documents without a provider signature.
// GeDefense therefore verifies a detached manifest that is provisioned by the
// release/update pipeline and pinned by the operator through
// feeds.trusted_signing_keys. The manifest binds, for every feed:
//
//   - the exact SHA-256 of the raw downloaded bytes (verified BEFORE parsing),
//   - the canonical digest of the parsed indicator set (verified after parsing),
//   - a monotonically increasing version (anti-rollback, persisted),
//   - a hard validity window (TTL: an expired manifest is never applied).
//
// Provisioning requirement (external, documented honestly): this repository
// does not ship a feed-signing private key. The pipeline must generate an
// Ed25519 key pair, publish the manifest for the fetched feed bytes and
// provision only the public key here. Without that provisioning the default
// configuration fails closed: every download is rejected with an explicit
// error and feeds never reach the kernel blocklist.
const (
	threatFeedManifestSchema     = "vgt-threat-feed-manifest/v1"
	maxThreatFeedManifestBytes   = 1 << 20
	threatFeedManifestClockSkew  = 5 * time.Minute
	threatFeedManifestActionList = "BLOCK,CORRELATE_ONLY,ANNOTATE_ONLY"
)

type threatFeedManifestEntry struct {
	ID          string     `json:"id"`
	URL         string     `json:"url"`
	RawSHA256   string     `json:"raw_sha256"`
	ItemsSHA256 string     `json:"items_sha256"`
	Version     uint64     `json:"version"`
	Action      FeedAction `json:"action,omitempty"`
	ValidUntil  time.Time  `json:"valid_until"`
}

type threatFeedManifestDocument struct {
	Schema      string                    `json:"schema"`
	GeneratedAt time.Time                 `json:"generated_at"`
	ValidUntil  time.Time                 `json:"valid_until"`
	Feeds       []threatFeedManifestEntry `json:"feeds"`
	Signature   string                    `json:"signature"`
}

type threatFeedManifestMessage struct {
	Schema      string                    `json:"schema"`
	GeneratedAt string                    `json:"generated_at"`
	ValidUntil  string                    `json:"valid_until"`
	Feeds       []threatFeedManifestEntry `json:"feeds"`
}

type threatFeedCertificate struct {
	Version    uint64
	ValidUntil time.Time
	Entry      threatFeedManifestEntry
}

func parsePinnedFeedSigningKeys(raw []string) ([]ed25519.PublicKey, error) {
	keys := make([]ed25519.PublicKey, 0, len(raw))
	seen := make(map[string]struct{}, len(raw))
	for _, value := range raw {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}
		decoded, err := base64.StdEncoding.DecodeString(trimmed)
		if err != nil {
			decoded, err = base64.RawStdEncoding.DecodeString(trimmed)
		}
		if err != nil || len(decoded) != ed25519.PublicKeySize {
			return nil, errors.New("feed signing key is not a valid Ed25519 public key")
		}
		if _, duplicate := seen[string(decoded)]; duplicate {
			continue
		}
		seen[string(decoded)] = struct{}{}
		keys = append(keys, ed25519.PublicKey(decoded))
	}
	if len(keys) > 8 {
		return nil, errors.New("too many pinned feed signing keys")
	}
	return keys, nil
}

// signingConfig returns the immutable authenticity policy. Called from the
// fetch goroutines, so the mutable manager configuration is read under the lock
// and the pinned keys are treated as immutable.
func (m *FeedManager) signingConfig() (required bool, keys []ed25519.PublicKey, manifestPath string, maxAge time.Duration) {
	m.mu.RLock()
	defer m.mu.RUnlock()
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

func threatFeedManifestMessageFor(document threatFeedManifestDocument) []byte {
	feeds := append([]threatFeedManifestEntry(nil), document.Feeds...)
	sort.Slice(feeds, func(left, right int) bool { return feeds[left].ID < feeds[right].ID })
	message := threatFeedManifestMessage{
		Schema:      document.Schema,
		GeneratedAt: document.GeneratedAt.UTC().Format(time.RFC3339Nano),
		ValidUntil:  document.ValidUntil.UTC().Format(time.RFC3339Nano),
		Feeds:       feeds,
	}
	raw, _ := json.Marshal(message)
	return raw
}

// readFeedManifestRaw reads a bounded, regular, non-symlink manifest file. It is
// the single reader for both the live verification path and the persisted-state
// anchor, so both operate on exactly the same bytes.
func readFeedManifestRaw(manifestPath string) ([]byte, error) {
	info, err := os.Lstat(manifestPath)
	if err != nil {
		return nil, NewThreatIntelSecurityException("signed feed manifest is missing; feeds fail closed until the trust anchor is provisioned", err)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return nil, NewThreatIntelSecurityException("signed feed manifest must be a regular non-symlink file", nil)
	}
	if info.Size() <= 0 || info.Size() > maxThreatFeedManifestBytes {
		return nil, NewThreatIntelSecurityException("signed feed manifest size rejected", nil)
	}
	raw, err := os.ReadFile(manifestPath)
	if err != nil {
		return nil, NewThreatIntelSecurityException("signed feed manifest read failed", err)
	}
	return raw, nil
}

// parseSignedFeedManifestDocument strictly decodes one manifest document. It does
// not authenticate and does not check the clock; callers add exactly the checks
// their use case needs (live acceptance must be fresh, a persisted-state anchor
// must merely have been validly signed).
func parseSignedFeedManifestDocument(raw []byte) (threatFeedManifestDocument, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var document threatFeedManifestDocument
	if err := decoder.Decode(&document); err != nil {
		return threatFeedManifestDocument{}, NewThreatIntelSecurityException("signed feed manifest JSON rejected", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return threatFeedManifestDocument{}, NewThreatIntelSecurityException("signed feed manifest trailing data rejected", nil)
	}
	return document, nil
}

// verifyFeedManifestSignature authenticates the detached manifest signature
// against the pinned keys. It is shared by live verification and the
// persisted-state anchor.
func verifyFeedManifestSignature(document threatFeedManifestDocument, keys []ed25519.PublicKey) error {
	if len(keys) == 0 {
		return NewThreatIntelSecurityException("no pinned feed signing key is configured; signed feed manifests cannot be authenticated", nil)
	}
	signature, err := base64.StdEncoding.DecodeString(strings.TrimSpace(document.Signature))
	if err != nil {
		signature, err = base64.RawStdEncoding.DecodeString(strings.TrimSpace(document.Signature))
	}
	if err != nil || len(signature) != ed25519.SignatureSize {
		return NewThreatIntelSecurityException("signed feed manifest signature encoding rejected", nil)
	}
	message := threatFeedManifestMessageFor(document)
	for _, key := range keys {
		if ed25519.Verify(key, message, signature) {
			return nil
		}
	}
	return NewThreatIntelSecurityException("signed feed manifest signature verification failed", nil)
}

// readSignedFeedManifest loads, strictly decodes and authenticates the detached
// manifest. Any error is a fail-closed rejection: there is no code path that
// continues with a partially trusted manifest.
func (m *FeedManager) readSignedFeedManifest(manifestPath string, keys []ed25519.PublicKey, maxAge time.Duration) (threatFeedManifestDocument, error) {
	raw, err := readFeedManifestRaw(manifestPath)
	if err != nil {
		return threatFeedManifestDocument{}, err
	}
	document, err := parseSignedFeedManifestDocument(raw)
	if err != nil {
		return threatFeedManifestDocument{}, err
	}
	if err := validateSignedFeedManifest(document, time.Now().UTC(), maxAge); err != nil {
		return threatFeedManifestDocument{}, err
	}
	if err := verifyFeedManifestSignature(document, keys); err != nil {
		return threatFeedManifestDocument{}, err
	}
	return document, nil
}

// validateSignedFeedManifestIntegrity checks everything about a manifest that
// does not depend on the current clock. It is used by the persisted-state anchor,
// whose anti-rollback floor must remain verifiable after the manifest's freshness
// window has passed; a stale-but-signed manifest still authenticates history.
func validateSignedFeedManifestIntegrity(document threatFeedManifestDocument) error {
	if document.Schema != threatFeedManifestSchema {
		return NewThreatIntelSecurityException("signed feed manifest schema rejected", nil)
	}
	if document.GeneratedAt.IsZero() || document.ValidUntil.IsZero() {
		return NewThreatIntelSecurityException("signed feed manifest timestamps rejected", nil)
	}
	if document.ValidUntil.Before(document.GeneratedAt) {
		return NewThreatIntelSecurityException("signed feed manifest validity window is inverted", nil)
	}
	if len(document.Feeds) == 0 || len(document.Feeds) > 512 {
		return NewThreatIntelSecurityException("signed feed manifest feed count rejected", nil)
	}
	seen := make(map[string]struct{}, len(document.Feeds))
	validActions := map[FeedAction]struct{}{FeedActionBlock: {}, FeedActionCorrelateOnly: {}, FeedActionAnnotateOnly: {}}
	for _, entry := range document.Feeds {
		if entry.ID == "" || len(entry.ID) > 64 {
			return NewThreatIntelSecurityException("signed feed manifest entry identifier rejected", nil)
		}
		if _, duplicate := seen[entry.ID]; duplicate {
			return NewThreatIntelSecurityException("signed feed manifest entry duplicated", nil)
		}
		seen[entry.ID] = struct{}{}
		if entry.URL == "" || len(entry.URL) > 2048 || !strings.HasPrefix(entry.URL, "https://") {
			return NewThreatIntelSecurityException("signed feed manifest entry URL rejected", nil)
		}
		if len(entry.RawSHA256) != 64 || len(entry.ItemsSHA256) != 64 {
			return NewThreatIntelSecurityException("signed feed manifest entry digest rejected", nil)
		}
		if _, err := hex.DecodeString(entry.RawSHA256); err != nil {
			return NewThreatIntelSecurityException("signed feed manifest entry raw digest rejected", nil)
		}
		if _, err := hex.DecodeString(entry.ItemsSHA256); err != nil {
			return NewThreatIntelSecurityException("signed feed manifest entry items digest rejected", nil)
		}
		if entry.Version == 0 {
			return NewThreatIntelSecurityException("signed feed manifest entry version rejected", nil)
		}
		if entry.Action != "" {
			if _, ok := validActions[entry.Action]; !ok {
				return NewThreatIntelSecurityException("signed feed manifest entry action rejected", nil)
			}
		}
		if entry.ValidUntil.IsZero() {
			return NewThreatIntelSecurityException("signed feed manifest entry validity rejected", nil)
		}
		if entry.ValidUntil.After(document.ValidUntil) {
			return NewThreatIntelSecurityException("signed feed manifest entry validity exceeds the document window", nil)
		}
	}
	return nil
}

func validateSignedFeedManifest(document threatFeedManifestDocument, now time.Time, maxAge time.Duration) error {
	if err := validateSignedFeedManifestIntegrity(document); err != nil {
		return err
	}
	if document.GeneratedAt.After(now.Add(threatFeedManifestClockSkew)) {
		return NewThreatIntelSecurityException("signed feed manifest was issued in the future", nil)
	}
	if !now.Before(document.ValidUntil) {
		return NewThreatIntelSecurityException("signed feed manifest has expired; feeds fail closed until a fresh signed manifest is provisioned", nil)
	}
	if document.ValidUntil.Sub(document.GeneratedAt) > maxAge || now.Sub(document.GeneratedAt) > maxAge {
		return NewThreatIntelSecurityException("signed feed manifest exceeds the configured maximum age", nil)
	}
	for _, entry := range document.Feeds {
		if !entry.ValidUntil.After(now) {
			return NewThreatIntelSecurityException("signed feed manifest entry validity expired", nil)
		}
	}
	return nil
}

// verifyFeedArtifact authenticates the raw download bytes against the signed
// manifest BEFORE the feed is parsed (verify-before-apply).
func (m *FeedManager) verifyFeedArtifact(source ThreatFeedSource, raw []byte) (*threatFeedCertificate, error) {
	required, keys, manifestPath, maxAge := m.signingConfig()
	if !required {
		return nil, nil
	}
	if len(keys) == 0 {
		return nil, NewThreatIntelSecurityException("feed signing trust anchor is not provisioned (no pinned Ed25519 key); feeds fail closed", nil)
	}
	document, err := m.readSignedFeedManifest(manifestPath, keys, maxAge)
	if err != nil {
		return nil, err
	}
	var entry *threatFeedManifestEntry
	for index := range document.Feeds {
		if document.Feeds[index].ID == source.ID {
			entry = &document.Feeds[index]
			break
		}
	}
	if entry == nil {
		return nil, NewThreatIntelSecurityException("signed feed manifest has no entry for "+source.ID+"; feed rejected", nil)
	}
	if entry.URL != source.URL {
		return nil, NewThreatIntelSecurityException("signed feed manifest URL does not match the configured feed URL", nil)
	}
	if entry.Action != "" && entry.Action != source.Action {
		return nil, NewThreatIntelSecurityException("signed feed manifest action does not match the catalog authority", nil)
	}
	digest := sha256.Sum256(raw)
	if !strings.EqualFold(hex.EncodeToString(digest[:]), entry.RawSHA256) {
		return nil, NewThreatIntelSecurityException("feed download does not match the signed manifest raw digest", nil)
	}
	certificate := &threatFeedCertificate{Version: entry.Version, ValidUntil: entry.ValidUntil, Entry: *entry}
	return certificate, nil
}

// verifyFeedItemsDigest binds the canonical parsed indicator set to the signed
// manifest, so a feed whose raw bytes hash correctly but whose normalisation
// would silently change the set is also rejected.
func (m *FeedManager) verifyFeedItemsDigest(certificate *threatFeedCertificate, source ThreatFeedSource, items []string) error {
	if certificate == nil {
		return nil
	}
	if !strings.EqualFold(computeFingerprint(items), certificate.Entry.ItemsSHA256) {
		return NewThreatIntelSecurityException("feed indicator set does not match the signed manifest items digest", nil)
	}
	return nil
}

// checkManifestRollback enforces the persisted monotonic version floor and
// rejects a version that was already seen with different content (replay of an
// older signed generation).
func checkManifestRollback(state *FeedGenerationState, certificate *threatFeedCertificate) error {
	if state == nil || certificate == nil {
		return nil
	}
	if certificate.Version < state.ManifestVersion {
		return NewThreatIntelSecurityException("signed feed manifest rollback rejected: generation version is older than the last accepted version", nil)
	}
	if certificate.Version == state.ManifestVersion && state.LastGoodFingerprint != "" &&
		!strings.EqualFold(state.LastGoodFingerprint, certificate.Entry.ItemsSHA256) {
		return NewThreatIntelSecurityException("signed feed manifest version reuse with different content rejected", nil)
	}
	return nil
}

// verifySignedKernelGenerationsLocked refuses a kernel apply when any feed that
// would contribute BLOCK entries lacks a verified, unexpired signed manifest.
// It intentionally does not delete existing kernel entries: a failed signature
// or TTL gate retains the previous enforcement state instead of releasing it.
func (m *FeedManager) verifySignedKernelGenerationsLocked(settings ThreatIntelFabricSettings) error {
	now := time.Now().UTC()
	for _, feed := range settings.Feeds {
		if !feed.Enabled || FeedAction(feed.Action) != FeedActionBlock {
			continue
		}
		state := m.feedStates[feed.ID]
		if state == nil || len(state.LastGoodItems) == 0 {
			continue
		}
		if !state.ManifestVerified || state.ManifestValidUntil.IsZero() || !now.Before(state.ManifestValidUntil) {
			return NewThreatIntelSecurityException(
				"signed feed manifest is missing or expired for "+feed.ID+"; kernel apply refused (previous enforcement retained)", nil)
		}
		if state.ManifestVersion == 0 {
			return NewThreatIntelSecurityException("feed generation has no signed manifest version; kernel apply refused", nil)
		}
	}
	return nil
}
