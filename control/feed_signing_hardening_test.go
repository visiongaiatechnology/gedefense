// STATUS: DIAMANT VGT SUPREME
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// F-03 / CHAIN-009 — signed feed manifests, verify-before-apply, TTL,
// anti-rollback and fail-closed auto-apply defaults.
// ---------------------------------------------------------------------------

func testFeedSigningKeypair(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return publicKey, privateKey
}

func testFeedSource() ThreatFeedSource {
	return ThreatFeedSource{
		ID: "feodo-c2", Name: "Feodo Tracker C2", URL: "https://feeds.example.test/ipblocklist.txt",
		Action: FeedActionBlock, Format: "lines",
	}
}

func signedFeedManifest(t *testing.T, privateKey ed25519.PrivateKey, generated, validUntil time.Time, entries ...threatFeedManifestEntry) []byte {
	t.Helper()
	document := threatFeedManifestDocument{
		Schema: threatFeedManifestSchema, GeneratedAt: generated, ValidUntil: validUntil, Feeds: entries,
	}
	document.Signature = ""
	signature := ed25519.Sign(privateKey, threatFeedManifestMessageFor(document))
	document.Signature = base64.StdEncoding.EncodeToString(signature)
	raw, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func feedManifestForRaw(source ThreatFeedSource, raw []byte, version uint64, validUntil time.Time) threatFeedManifestEntry {
	items := parsePlainFeedItemsForTest(raw)
	digest := sha256.Sum256(raw)
	return threatFeedManifestEntry{
		ID: source.ID, URL: source.URL, RawSHA256: hex.EncodeToString(digest[:]),
		ItemsSHA256: computeFingerprint(items), Version: version, Action: source.Action, ValidUntil: validUntil,
	}
}

func parsePlainFeedItemsForTest(raw []byte) []string {
	set := map[string]struct{}{}
	for _, line := range strings.Split(string(raw), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		if value, ok := parseThreatToken(trimmed); ok {
			set[value] = struct{}{}
		}
	}
	items := make([]string, 0, len(set))
	for item := range set {
		items = append(items, item)
	}
	return items
}

func newSignedFeedManager(t *testing.T, publicKey ed25519.PublicKey, manifestPath string) *FeedManager {
	t.Helper()
	return NewFeedManager(FeedConfig{
		MaxEntries:            1000,
		RequireSignedManifest: true,
		TrustedSigningKeys:    []string{base64.StdEncoding.EncodeToString(publicKey)},
		ManifestPath:          manifestPath,
		ManifestMaxAgeMinutes: 240,
	}, t.TempDir())
}

func writeFeedManifest(t *testing.T, path string, raw []byte) {
	t.Helper()
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestSignedFeedManifestVerifyBeforeApply(t *testing.T) {
	publicKey, privateKey := testFeedSigningKeypair(t)
	manifestPath := filepath.Join(t.TempDir(), "threat-feed-manifest.json")
	manager := newSignedFeedManager(t, publicKey, manifestPath)
	source := testFeedSource()
	raw := []byte("203.0.113.7\n198.51.100.9\n")
	now := time.Now().UTC()
	entry := feedManifestForRaw(source, raw, 1, now.Add(time.Hour))
	writeFeedManifest(t, manifestPath, signedFeedManifest(t, privateKey, now.Add(-time.Minute), now.Add(time.Hour), entry))

	certificate, err := manager.verifyFeedArtifact(source, raw)
	if err != nil {
		t.Fatalf("valid signed feed generation rejected: %v", err)
	}
	if certificate == nil || certificate.Version != 1 || certificate.ValidUntil.IsZero() {
		t.Fatalf("unexpected certificate: %+v", certificate)
	}
	items := parsePlainFeedItemsForTest(raw)
	if err := manager.verifyFeedItemsDigest(certificate, source, items); err != nil {
		t.Fatalf("valid indicator digest rejected: %v", err)
	}

	// Raw-byte substitution is rejected before parsing.
	substituted := append([]byte(nil), raw...)
	substituted = append(substituted, []byte("1.1.1.1\n")...)
	if _, err := manager.verifyFeedArtifact(source, substituted); err == nil {
		t.Fatal("substituted feed body passed the signed raw digest")
	}
	// Indicator-set substitution with valid raw bytes is rejected after parsing.
	changed := []string{"203.0.113.7/32"}
	if err := manager.verifyFeedItemsDigest(certificate, source, changed); err == nil {
		t.Fatal("changed indicator set passed the signed items digest")
	}
}

func TestSignedFeedManifestNegativeCases(t *testing.T) {
	publicKey, privateKey := testFeedSigningKeypair(t)
	manifestPath := filepath.Join(t.TempDir(), "threat-feed-manifest.json")
	manager := newSignedFeedManager(t, publicKey, manifestPath)
	source := testFeedSource()
	raw := []byte("203.0.113.7\n")
	now := time.Now().UTC()

	// Missing manifest: fail closed.
	if _, err := manager.verifyFeedArtifact(source, raw); err == nil {
		t.Fatal("missing signed manifest was accepted")
	}

	entry := feedManifestForRaw(source, raw, 2, now.Add(time.Hour))
	// Unsigned / tampered signature.
	document := threatFeedManifestDocument{
		Schema: threatFeedManifestSchema, GeneratedAt: now.Add(-time.Minute), ValidUntil: now.Add(time.Hour),
		Feeds: []threatFeedManifestEntry{entry}, Signature: base64.StdEncoding.EncodeToString(make([]byte, ed25519.SignatureSize)),
	}
	tamperedRaw, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	writeFeedManifest(t, manifestPath, tamperedRaw)
	if _, err := manager.verifyFeedArtifact(source, raw); err == nil {
		t.Fatal("tampered manifest signature was accepted")
	}

	// Expired manifest TTL.
	writeFeedManifest(t, manifestPath, signedFeedManifest(t, privateKey, now.Add(-2*time.Hour), now.Add(-time.Hour), entry))
	if _, err := manager.verifyFeedArtifact(source, raw); err == nil {
		t.Fatal("expired signed feed manifest was accepted")
	}
	// Manifest older than the configured maximum age.
	writeFeedManifest(t, manifestPath, signedFeedManifest(t, privateKey, now.Add(-3*time.Hour), now.Add(2*time.Hour), feedManifestForRaw(source, raw, 2, now.Add(2*time.Hour))))
	if _, err := manager.verifyFeedArtifact(source, raw); err == nil {
		t.Fatal("over-age signed feed manifest was accepted")
	}

	// Manifest with the wrong URL / action binds nothing.
	writeFeedManifest(t, manifestPath, signedFeedManifest(t, privateKey, now.Add(-time.Minute), now.Add(time.Hour),
		feedManifestForRaw(ThreatFeedSource{ID: source.ID, URL: "https://other.example.test/x", Action: source.Action}, raw, 2, now.Add(time.Hour))))
	if _, err := manager.verifyFeedArtifact(source, raw); err == nil {
		t.Fatal("manifest for a different feed URL was accepted")
	}

	// Missing trust anchor: fail closed even when the manifest file exists.
	noKeys := NewFeedManager(FeedConfig{MaxEntries: 1000, RequireSignedManifest: true, ManifestPath: manifestPath, ManifestMaxAgeMinutes: 60}, t.TempDir())
	if _, err := noKeys.verifyFeedArtifact(source, raw); err == nil || !strings.Contains(err.Error(), "trust anchor") {
		t.Fatalf("missing trust anchor did not fail closed: %v", err)
	}
}

func TestSignedFeedManifestAntiRollback(t *testing.T) {
	publicKey, privateKey := testFeedSigningKeypair(t)
	manifestPath := filepath.Join(t.TempDir(), "threat-feed-manifest.json")
	manager := newSignedFeedManager(t, publicKey, manifestPath)
	source := testFeedSource()
	raw := []byte("203.0.113.7\n")
	now := time.Now().UTC()
	entry := feedManifestForRaw(source, raw, 1, now.Add(time.Hour))
	writeFeedManifest(t, manifestPath, signedFeedManifest(t, privateKey, now.Add(-time.Minute), now.Add(time.Hour), entry))
	certificate, err := manager.verifyFeedArtifact(source, raw)
	if err != nil {
		t.Fatal(err)
	}
	state := &FeedGenerationState{ID: source.ID, ManifestVersion: 2, LastGoodFingerprint: entry.ItemsSHA256}
	if err := checkManifestRollback(state, certificate); err == nil {
		t.Fatal("manifest rollback to an older version was accepted")
	}
	sameVersionDifferentContent := &FeedGenerationState{ID: source.ID, ManifestVersion: 1, LastGoodFingerprint: strings.Repeat("a", 64)}
	if err := checkManifestRollback(sameVersionDifferentContent, certificate); err == nil {
		t.Fatal("reused manifest version with different content was accepted")
	}
	state.ManifestVersion = 1
	if err := checkManifestRollback(state, certificate); err != nil {
		t.Fatalf("valid re-download at the same version was rejected: %v", err)
	}
}

func TestFeedAuthenticityDefaultsFailClosed(t *testing.T) {
	cfg := defaultConfig()
	if cfg.Feeds.AutoApply {
		t.Fatal("feeds.auto_apply must default to false")
	}
	if !cfg.Feeds.RequireSignedManifest {
		t.Fatal("feeds.require_signed_manifest must default to true")
	}
	if cfg.Feeds.ManifestMaxAgeMinutes <= 0 {
		t.Fatal("feed manifest maximum age must default to a positive bound")
	}
	fabric := defaultThreatIntelFabricSettings(cfg.Feeds, DefaultThreatFeedSources)
	if fabric.Kernel.AutoApply {
		t.Fatal("threat-intelligence kernel auto-apply must default to false")
	}

	// Auto-apply without the signature gate is a configuration error.
	unsigned := defaultConfig()
	unsigned.Feeds.Enabled = true
	unsigned.Feeds.AutoApply = true
	unsigned.Feeds.RequireSignedManifest = false
	if err := validateConfig(&unsigned); err == nil {
		t.Fatal("auto-apply without the signed-manifest gate was accepted")
	}
	// Auto-apply without a pinned trust anchor is a configuration error.
	noKey := defaultConfig()
	noKey.Feeds.Enabled = true
	noKey.Feeds.AutoApply = true
	noKey.Feeds.RequireSignedManifest = true
	if err := validateConfig(&noKey); err == nil {
		t.Fatal("auto-apply without a pinned feed signing key was accepted")
	}
	publicKey, _, keyErr := ed25519.GenerateKey(rand.Reader)
	if keyErr != nil {
		t.Fatal(keyErr)
	}
	// With a pinned key the configuration is accepted.
	signedCfg := defaultConfig()
	signedCfg.Feeds.Enabled = true
	signedCfg.Feeds.AutoApply = true
	signedCfg.Feeds.RequireSignedManifest = true
	signedCfg.Feeds.TrustedSigningKeys = []string{base64.StdEncoding.EncodeToString(publicKey)}
	if err := validateConfig(&signedCfg); err != nil {
		t.Fatalf("signed auto-apply configuration rejected: %v", err)
	}
}

func TestKernelApplyRefusesUnverifiedOrExpiredSignedGeneration(t *testing.T) {
	publicKey, privateKey := testFeedSigningKeypair(t)
	manifestPath := filepath.Join(t.TempDir(), "threat-feed-manifest.json")
	manager := newSignedFeedManager(t, publicKey, manifestPath)
	_ = privateKey
	items := []string{"203.0.113.7/32"}
	manager.mu.Lock()
	manager.feedStates["feodo-c2"] = &FeedGenerationState{
		ID: "feodo-c2", Name: "Feodo Tracker C2", Action: FeedActionBlock,
		LastGoodItems: items, LastGoodCount: 1, LastGoodGen: 1, LastGoodFingerprint: computeFingerprint(items),
		ManifestVerified: false,
	}
	manager.mu.Unlock()
	if _, _, err := manager.ApplyToKernel(nil, nil); err == nil || !strings.Contains(err.Error(), "kernel apply refused") {
		t.Fatalf("unverified signed generation reached the kernel diff: %v", err)
	}

	manager.mu.Lock()
	state := manager.feedStates["feodo-c2"]
	state.ManifestVerified = true
	state.ManifestVersion = 1
	state.ManifestValidUntil = time.Now().UTC().Add(-time.Minute)
	manager.mu.Unlock()
	if _, _, err := manager.ApplyToKernel(nil, nil); err == nil || !strings.Contains(err.Error(), "kernel apply refused") {
		t.Fatalf("expired signed generation reached the kernel diff: %v", err)
	}

	manager.mu.Lock()
	state.ManifestValidUntil = time.Now().UTC().Add(time.Hour)
	manager.mu.Unlock()
	if _, _, err := manager.ApplyToKernel(nil, nil); err != nil {
		t.Fatalf("valid signed generation was refused: %v", err)
	}
}

func TestSharedEgressClassifierRejectsMetadataAndSpecialUse(t *testing.T) {
	forbidden := []string{
		"100.100.100.200", "168.63.129.16", "169.254.169.254", "192.0.0.192",
		"fd00:ec2::254", "127.0.0.1", "::1", "10.1.2.3", "169.254.1.1", "100.64.0.1",
	}
	for _, raw := range forbidden {
		allowed, reason := ClassifyEgressDestination(parseIPForTest(t, raw))
		if allowed || reason == "" {
			t.Fatalf("egress classifier accepted forbidden destination %s (%q)", raw, reason)
		}
	}
	if allowed, _ := ClassifyEgressDestination(parseIPForTest(t, "8.8.8.8")); !allowed {
		t.Fatal("egress classifier rejected public unicast 8.8.8.8")
	}
	for _, rawURL := range []string{
		"https://100.100.100.200/latest/meta-data/",
		"https://168.63.129.16/machine/plugins/",
		"https://192.0.0.192/latest/meta-data/",
		"https://[fd00:ec2::254]/latest/meta-data/",
		"https://127.0.0.1/list.txt",
	} {
		if _, err := validateFeedSourceURL(rawURL); err == nil {
			t.Fatalf("feed URL validator accepted forbidden destination %s", rawURL)
		}
	}
	if _, err := validateFeedSourceURL("https://feeds.example.test/list.txt"); err != nil {
		t.Fatalf("public feed URL rejected: %v", err)
	}
	if !isSensitiveSSRFHost("100.100.100.200") || !isSensitiveSSRFHost("168.63.129.16") {
		t.Fatal("L7 SSRF detector lost the metadata destination classification")
	}
	if !forbiddenFeedIP(parseIPForTest(t, "192.0.0.192")) {
		t.Fatal("feed dialer predicate lost the metadata classification")
	}
}

func parseIPForTest(t *testing.T, raw string) net.IP {
	t.Helper()
	parsed := net.ParseIP(raw)
	if parsed == nil {
		t.Fatalf("invalid test IP %s", raw)
	}
	return parsed
}

func TestThreatIndexIPv4MappedNormalization(t *testing.T) {
	canonical, ok := parseThreatToken("::ffff:203.0.113.7/128")
	if !ok || canonical != "203.0.113.7/32" {
		t.Fatalf("mapped IOC was not normalised: value=%q ok=%v", canonical, ok)
	}
	if _, ok := parseThreatToken("::ffff:203.0.113.7/80"); ok {
		t.Fatal("mapped IOC shorter than /96 was accepted as an inert indicator")
	}
	index := NewThreatIndex()
	index.Replace([]string{"::ffff:203.0.113.7/128"})
	if !index.ContainsString("203.0.113.7") {
		t.Fatal("mapped feed IOC did not match the plain IPv4 event")
	}
	if !index.ContainsString("::ffff:203.0.113.7") {
		t.Fatal("mapped feed IOC did not match the mapped event")
	}
	reverse := NewThreatIndex()
	reverse.Replace([]string{"203.0.113.7/32"})
	if !reverse.ContainsString("::ffff:203.0.113.7") {
		t.Fatal("plain IPv4 feed IOC did not match the mapped event")
	}
}
