// STATUS: DIAMANT VGT SUPREME
package main

// Tests for the local operator signing pipeline (feed_signing.go) and its
// integration into FeedManager sync and kernel apply.
//
// The network is replaced by an in-memory transport so the full producer ->
// snapshot -> manifest -> verifier -> kernel-diff chain runs without leaving the
// process. Tests assert the security properties, not the happy path only:
//   - exact raw-byte and indicator-digest binding,
//   - pinned-key enforcement (unpinned operator key fails closed),
//   - snapshot path jail (identifier traversal, symlinked file, symlinked dir),
//   - key file permissions and overwrite refusal,
//   - TTL expiry and rollback rejection,
//   - kernel-apply refusal for unverified/expired signed generations.

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// feedSigningTestTransport serves canned feed bodies for every HTTPS request
// the pipeline makes, records the requests and can be switched into an outage
// mode that fails deterministically (non-retryable security error) so the
// snapshot-reuse path is exercised without backoff delays.
type feedSigningTestTransport struct {
	mu       sync.Mutex
	requests []string
	failing  bool
	bodies   map[string][]byte
}

func newFeedSigningTestTransport() *feedSigningTestTransport {
	return &feedSigningTestTransport{bodies: make(map[string][]byte)}
}

func (transport *feedSigningTestTransport) setBody(url string, body []byte) {
	transport.mu.Lock()
	defer transport.mu.Unlock()
	transport.bodies[url] = body
}

func (transport *feedSigningTestTransport) setFailing(failing bool) {
	transport.mu.Lock()
	defer transport.mu.Unlock()
	transport.failing = failing
}

func (transport *feedSigningTestTransport) requestCount() int {
	transport.mu.Lock()
	defer transport.mu.Unlock()
	return len(transport.requests)
}

func (transport *feedSigningTestTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	transport.mu.Lock()
	transport.requests = append(transport.requests, req.URL.String())
	failing := transport.failing
	body, known := transport.bodies[req.URL.String()]
	transport.mu.Unlock()
	if failing {
		// A ThreatIntelSecurityException is classified as deterministic, so the
		// retry loop returns immediately and the snapshot-reuse path is taken.
		return nil, NewThreatIntelSecurityException("injected upstream outage", nil)
	}
	if !known {
		body = feedSigningDefaultBody(req.URL.String())
	}
	header := make(http.Header)
	header.Set("Content-Type", "text/plain")
	return &http.Response{
		StatusCode: http.StatusOK,
		Status:     "200 OK",
		Header:     header,
		Body:       io.NopCloser(bytes.NewReader(body)),
		Request:    req,
	}, nil
}

func feedSigningDefaultBody(rawURL string) []byte {
	if strings.HasSuffix(strings.ToLower(rawURL), ".json") {
		return []byte(`["203.0.113.7","198.51.100.9","2001:db8::5"]`)
	}
	return []byte("203.0.113.7\n198.51.100.9\n2001:db8::9\n")
}

type feedSigningTestEnv struct {
	dir          string
	stateDir     string
	keysDir      string
	privatePath  string
	publicKey    ed25519.PublicKey
	snapshotDir  string
	manifestPath string
	manager      *FeedManager
	transport    *feedSigningTestTransport
}

func newFeedSigningTestEnv(t *testing.T, mutate func(*FeedConfig)) *feedSigningTestEnv {
	t.Helper()
	dir := t.TempDir()
	keysDir := filepath.Join(dir, "keys")
	publicKey, err := InitFeedSigning(keysDir, "")
	if err != nil {
		t.Fatalf("init feed signing: %v", err)
	}
	env := &feedSigningTestEnv{
		dir:          dir,
		stateDir:     filepath.Join(dir, "state"),
		keysDir:      keysDir,
		privatePath:  filepath.Join(keysDir, feedSigningPrivateKeyFile),
		publicKey:    publicKey,
		snapshotDir:  filepath.Join(dir, "snapshots"),
		manifestPath: filepath.Join(dir, "threat-feed-manifest.json"),
		transport:    newFeedSigningTestTransport(),
	}
	cfg := FeedConfig{
		Enabled:               true,
		RefreshMinutes:        60,
		MaxDownloadBytes:      1 << 20,
		MaxEntries:            5000,
		RequireSignedManifest: true,
		TrustedSigningKeys:    []string{feedSigningPublicKeyBase64(publicKey)},
		ManifestPath:          env.manifestPath,
		ManifestMaxAgeMinutes: 60,
		LocalSigning:          true,
		SigningKeyFile:        env.privatePath,
		SnapshotDir:           env.snapshotDir,
	}
	if mutate != nil {
		mutate(&cfg)
	}
	env.manager = NewFeedManager(cfg, env.stateDir)
	env.manager.client = &http.Client{Transport: env.transport}
	return env
}

func (env *feedSigningTestEnv) sync(t *testing.T) ([]string, map[string]error) {
	t.Helper()
	items, errs, err := env.manager.SyncWithLock(context.Background(), "test")
	if err != nil {
		t.Fatalf("sync lock failed: %v", err)
	}
	return items, errs
}

func TestLocalFeedSigningPipelineEndToEnd(t *testing.T) {
	env := newFeedSigningTestEnv(t, nil)
	items, errs := env.sync(t)
	if len(errs) != 0 {
		t.Fatalf("local signing sync reported errors: %v", errs)
	}
	if len(items) == 0 {
		t.Fatal("local signing sync produced no block indicators")
	}
	if env.transport.requestCount() == 0 {
		t.Fatal("local signing pipeline did not download any source")
	}

	// 1. The manifest exists, is owner-only and verifies with the pinned key.
	info, err := os.Lstat(env.manifestPath)
	if err != nil {
		t.Fatalf("signed feed manifest missing: %v", err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		t.Fatalf("signed feed manifest must be a 0600 regular file, got %v", info.Mode())
	}
	document, err := env.manager.readSignedFeedManifest(env.manifestPath, []ed25519.PublicKey{env.publicKey}, time.Hour)
	if err != nil {
		t.Fatalf("published feed manifest does not verify: %v", err)
	}
	if document.Schema != threatFeedManifestSchema {
		t.Fatalf("unexpected manifest schema %q", document.Schema)
	}
	if len(document.Feeds) != len(DefaultThreatFeedSources) {
		t.Fatalf("manifest covers %d feeds, want %d", len(document.Feeds), len(DefaultThreatFeedSources))
	}

	// 2. Every manifest entry binds the exact snapshot bytes and the canonical
	//    indicator set that the sync published (raw + items digest binding).
	live := env.manager.live.current()
	for _, entry := range document.Feeds {
		source, known := live.byID[entry.ID]
		if !known {
			t.Fatalf("manifest entry %q has no configured source", entry.ID)
		}
		if entry.URL != source.URL {
			t.Fatalf("manifest entry %q URL %q does not match source URL %q", entry.ID, entry.URL, source.URL)
		}
		maxEntries, maxBytes, _ := live.feedBounds(source)
		raw, _, err := readFeedSnapshot(env.snapshotDir, source.ID, maxBytes)
		if err != nil {
			t.Fatalf("snapshot for %q unreadable: %v", source.ID, err)
		}
		digest := sha256.Sum256(raw)
		if hex.EncodeToString(digest[:]) != entry.RawSHA256 {
			t.Fatalf("manifest raw digest for %q does not bind the snapshot bytes", source.ID)
		}
		parsed, parseErr := parseFeedRaw(source, raw, "", live.settings.Validation, maxEntries)
		if parseErr != nil {
			t.Fatalf("snapshot for %q does not parse: %v", source.ID, parseErr)
		}
		if strings.EqualFold(computeFingerprint(parsed), entry.ItemsSHA256) {
			continue
		}
		t.Fatalf("manifest items digest for %q does not bind the parsed indicators", source.ID)
	}

	// 3. Every feed state is marked as a verified signed generation.
	states := env.manager.SnapshotFeedStates()
	if len(states) == 0 {
		t.Fatal("no feed states after sync")
	}
	for _, state := range states {
		if !state.ManifestVerified || state.ManifestAuthenticity != "SIGNED" {
			t.Fatalf("feed %q is not marked as a verified signed generation: %+v", state.ID, state)
		}
		if state.ManifestVersion != 1 {
			t.Fatalf("feed %q manifest version = %d, want 1", state.ID, state.ManifestVersion)
		}
		if state.ManifestValidUntil.IsZero() {
			t.Fatalf("feed %q has no manifest validity window", state.ID)
		}
	}

	// 4. Kernel apply publishes the block generation and reports machine-visible
	//    status: kernel_apply_status=APPLIED and the added counter.
	added, deleted, err := env.manager.ApplyToKernel(nil, nil)
	if err != nil {
		t.Fatalf("kernel apply of verified signed generation failed: %v", err)
	}
	if added != len(items) || deleted != 0 {
		t.Fatalf("kernel diff = +%d/-%d, want +%d/-0", added, deleted, len(items))
	}
	telemetry := env.manager.Telemetry()
	if telemetry.KernelApplyStatus != kernelApplyApplied {
		t.Fatalf("kernel_apply_status = %q, want %q", telemetry.KernelApplyStatus, kernelApplyApplied)
	}
	if telemetry.LastKernelAdded != len(items) {
		t.Fatalf("last_kernel_added = %d, want %d", telemetry.LastKernelAdded, len(items))
	}
	verifiedFeeds := 0
	for _, feed := range telemetry.Feeds {
		if feed.ManifestVerified {
			verifiedFeeds++
		}
	}
	if verifiedFeeds != len(DefaultThreatFeedSources) {
		t.Fatalf("telemetry exposes %d verified feeds, want %d", verifiedFeeds, len(DefaultThreatFeedSources))
	}

	// 5. A second sync produces a strictly newer signed generation and an empty
	//    kernel diff (anti-churn while the content is unchanged).
	itemsAgain, errsAgain := env.sync(t)
	if len(errsAgain) != 0 {
		t.Fatalf("second local signing sync reported errors: %v", errsAgain)
	}
	if len(itemsAgain) != len(items) {
		t.Fatalf("second sync changed the indicator set: %d -> %d", len(items), len(itemsAgain))
	}
	for _, state := range env.manager.SnapshotFeedStates() {
		if state.ManifestVersion != 2 {
			t.Fatalf("feed %q manifest version = %d after second sync, want 2", state.ID, state.ManifestVersion)
		}
	}
	added, deleted, err = env.manager.ApplyToKernel(nil, nil)
	if err != nil {
		t.Fatalf("second kernel apply failed: %v", err)
	}
	if added != 0 || deleted != 0 {
		t.Fatalf("unchanged generation produced a kernel diff: +%d/-%d", added, deleted)
	}
}

func TestLocalFeedSigningSelfHealsMissingPinAndFailsClosedOnRotation(t *testing.T) {
	// Opt-in local signing with an operator key but no pinned public key is the
	// documented self-heal case: the marker records the key, the sync proceeds.
	env := newFeedSigningTestEnv(t, func(cfg *FeedConfig) {
		cfg.TrustedSigningKeys = nil
	})
	items, errs := env.sync(t)
	if len(errs) != 0 {
		t.Fatalf("self-heal sync reported errors: %v", errs)
	}
	if len(items) == 0 {
		t.Fatal("self-heal sync produced no indicators")
	}
	markerPath := filepath.Join(env.stateDir, feedSigningSelfHealMarkerFile)
	if _, err := os.Lstat(markerPath); err != nil {
		t.Fatalf("feed signing self-heal marker missing: %v", err)
	}
	pins := env.manager.localSigningPolicy().pinnedKeys
	if len(pins) != 1 || !pins[0].Equal(env.publicKey) {
		t.Fatalf("self-healed pin = %v, want the operator key", pins)
	}
	if _, err := env.manager.readSignedFeedManifest(env.manifestPath, pins, time.Hour); err != nil {
		t.Fatalf("self-signed manifest does not verify: %v", err)
	}
	healEnv := env

	// A pinned foreign key remains a hard fail-closed error: self-heal must not
	// override an explicit trust anchor.
	foreignPublic, _, generateErr := ed25519.GenerateKey(rand.Reader)
	if generateErr != nil {
		t.Fatal(generateErr)
	}
	env = newFeedSigningTestEnv(t, func(cfg *FeedConfig) {
		cfg.TrustedSigningKeys = []string{feedSigningPublicKeyBase64(foreignPublic)}
	})
	_, errs = env.sync(t)
	if len(errs) == 0 {
		t.Fatal("local signing with an unpinned operator key was accepted")
	}
	if !strings.Contains(errs["local_signing"].Error(), "not pinned") {
		t.Fatalf("unexpected unpinned-key error: %v", errs["local_signing"])
	}
	if _, statErr := os.Lstat(env.manifestPath); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatal("pipeline wrote a manifest whose signer is not pinned")
	}

	// A rotated operator key with the old self-heal marker must fail closed:
	// rotation requires an explicit pin, not silent re-trust.
	rotatedDir := filepath.Join(healEnv.dir, "rotated-keys")
	if _, initErr := InitFeedSigning(rotatedDir, ""); initErr != nil {
		t.Fatalf("rotate test key: %v", initErr)
	}
	rotatedEnv := &feedSigningTestEnv{
		dir: healEnv.dir, stateDir: healEnv.stateDir,
		privatePath: filepath.Join(rotatedDir, feedSigningPrivateKeyFile),
		snapshotDir: healEnv.snapshotDir, manifestPath: healEnv.manifestPath,
		transport: newFeedSigningTestTransport(),
	}
	rotatedCfg := FeedConfig{
		Enabled: true, RefreshMinutes: 60, MaxDownloadBytes: 1 << 20, MaxEntries: 5000,
		RequireSignedManifest: true, TrustedSigningKeys: nil,
		ManifestPath: rotatedEnv.manifestPath, ManifestMaxAgeMinutes: 60,
		LocalSigning: true, SigningKeyFile: rotatedEnv.privatePath, SnapshotDir: rotatedEnv.snapshotDir,
	}
	rotatedEnv.manager = NewFeedManager(rotatedCfg, rotatedEnv.stateDir)
	rotatedEnv.manager.client = &http.Client{Transport: rotatedEnv.transport}
	_, errs = rotatedEnv.sync(t)
	if len(errs) == 0 {
		t.Fatal("rotated operator key was silently re-pinned by self-heal")
	}
	if !strings.Contains(errs["local_signing"].Error(), "pinned") && !strings.Contains(errs["local_signing"].Error(), "trust anchor") {
		t.Fatalf("unexpected rotation error: %v", errs["local_signing"])
	}
	if rotatedEnv.transport.requestCount() != 0 {
		t.Fatal("rotated key downloaded sources before the trust anchor was verified")
	}
}

func TestLocalFeedSigningBindsSnapshotBytesAndItems(t *testing.T) {
	env := newFeedSigningTestEnv(t, nil)
	if _, errs := env.sync(t); len(errs) != 0 {
		t.Fatalf("sync failed: %v", errs)
	}
	live := env.manager.live.current()
	source, known := live.byID["feodo-c2"]
	if !known {
		t.Fatal("test requires the feodo-c2 source")
	}

	// Tampered snapshot bytes: the raw digest gate rejects them before parsing.
	snapshotPath, err := resolveFeedSigningSnapshotPath(env.snapshotDir, source.ID)
	if err != nil {
		t.Fatal(err)
	}
	original, err := os.ReadFile(snapshotPath)
	if err != nil {
		t.Fatal(err)
	}
	tampered := append(append([]byte(nil), original...), []byte("1.1.1.1\n")...)
	if err := os.WriteFile(snapshotPath, tampered, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := env.manager.fetchSourceFromSnapshot(source, live); err == nil {
		t.Fatal("tampered snapshot bytes passed the signed raw digest")
	}
	// The next local signing sync repairs the snapshot from the network.
	if _, errs := env.sync(t); len(errs) != 0 {
		t.Fatalf("repair sync failed: %v", errs)
	}

	// Correct raw bytes but a different indicator set: the items digest gate
	// rejects the generation even though the raw hash matches.
	raw, _, err := readFeedSnapshot(env.snapshotDir, source.ID, int64(live.settings.MaxDownloadBytesPerFeed))
	if err != nil {
		t.Fatal(err)
	}
	substitutedItems := []string{"198.51.100.9/32"}
	entry, err := feedSigningManifestEntryFor(source, raw, substitutedItems, 99, time.Now().UTC().Add(30*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	document := threatFeedManifestDocument{
		Schema:      threatFeedManifestSchema,
		GeneratedAt: time.Now().UTC().Add(-30 * time.Minute),
		ValidUntil:  time.Now().UTC().Add(30 * time.Minute),
		Feeds:       []threatFeedManifestEntry{entry},
	}
	key, loadErr := loadFeedSigningKeyPair(env.privatePath)
	if loadErr != nil {
		t.Fatal(loadErr)
	}
	signed, signErr := signFeedSigningManifest(document, key)
	if signErr != nil {
		t.Fatal(signErr)
	}
	if err := writeFeedManifestJSON(env.manifestPath, signed); err != nil {
		t.Fatal(err)
	}
	if _, _, err := env.manager.fetchSourceFromSnapshot(source, live); err == nil {
		t.Fatal("substituted indicator set passed the signed items digest")
	}
}

func TestLocalFeedSigningSnapshotJail(t *testing.T) {
	env := newFeedSigningTestEnv(t, nil)
	if _, errs := env.sync(t); len(errs) != 0 {
		t.Fatalf("sync failed: %v", errs)
	}

	for _, invalid := range []string{"", "..", "../feodo-c2", "feodo/c2", "/etc/passwd", ".hidden", "feodo c2", strings.Repeat("a", 65)} {
		if _, err := resolveFeedSigningSnapshotPath(env.snapshotDir, invalid); err == nil {
			t.Fatalf("snapshot path resolver accepted invalid feed identifier %q", invalid)
		}
	}
	if _, err := writeFeedSnapshot(env.snapshotDir, "../escape", []byte("203.0.113.7\n")); err == nil {
		t.Fatal("snapshot writer accepted a traversal identifier")
	}

	// A snapshot file replaced by a symlink is rejected, not followed.
	source := env.manager.live.current().byID["feodo-c2"]
	snapshotPath, err := resolveFeedSigningSnapshotPath(env.snapshotDir, source.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(snapshotPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/etc/passwd", snapshotPath); err != nil {
		t.Fatal(err)
	}
	if _, _, err := readFeedSnapshot(env.snapshotDir, source.ID, 1<<20); err == nil {
		t.Fatal("symlinked snapshot file was followed")
	}
	_ = os.Remove(snapshotPath)

	// A symlinked raw directory must not redirect reads outside the jail.
	base := t.TempDir()
	outside := t.TempDir()
	if err := os.MkdirAll(base, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(base, feedSigningSnapshotRawDir)); err != nil {
		t.Fatal(err)
	}
	if _, err := writeFeedSnapshot(base, "feodo-c2", []byte("203.0.113.7\n")); err == nil {
		t.Fatal("snapshot writer followed a symlinked raw directory")
	}

	// Oversized snapshots are rejected on read.
	oversized := bytes.Repeat([]byte("203.0.113.7\n"), 64)
	if _, err := writeFeedSnapshot(env.snapshotDir, "oversized", oversized); err != nil {
		t.Fatal(err)
	}
	if _, _, err := readFeedSnapshot(env.snapshotDir, "oversized", 16); err == nil {
		t.Fatal("oversized snapshot passed the bounded read")
	}

	// file:// is never a valid configured source, only an internal diagnostic
	// representation of a snapshot read.
	if _, err := validateFeedSourceURL("file:///etc/passwd"); err == nil {
		t.Fatal("file:// URL was accepted as a feed source")
	}
}

func TestInitFeedSigningProvisioning(t *testing.T) {
	dir := t.TempDir()
	keysDir := filepath.Join(dir, "feed-signing")
	publicKey, err := InitFeedSigning(keysDir, "")
	if err != nil {
		t.Fatalf("init feed signing: %v", err)
	}
	privatePath := filepath.Join(keysDir, feedSigningPrivateKeyFile)
	publicPath := filepath.Join(keysDir, feedSigningPublicKeyFile)

	privateInfo, err := os.Stat(privatePath)
	if err != nil {
		t.Fatal(err)
	}
	if privateInfo.Mode().Perm() != 0o600 {
		t.Fatalf("feed signing private key mode = %o, want 0600", privateInfo.Mode().Perm())
	}
	if privateInfo.Size() != ed25519.SeedSize {
		t.Fatalf("feed signing private key size = %d, want the %d-byte seed", privateInfo.Size(), ed25519.SeedSize)
	}
	publicInfo, err := os.Stat(publicPath)
	if err != nil {
		t.Fatal(err)
	}
	if publicInfo.Mode().Perm() != 0o644 {
		t.Fatalf("feed signing public key mode = %o, want 0644", publicInfo.Mode().Perm())
	}
	keysDirInfo, err := os.Stat(keysDir)
	if err != nil {
		t.Fatal(err)
	}
	if keysDirInfo.Mode().Perm() != 0o700 {
		t.Fatalf("feed signing directory mode = %o, want 0700", keysDirInfo.Mode().Perm())
	}

	loaded, err := loadFeedSigningKeyPair(privatePath)
	if err != nil {
		t.Fatalf("load generated key: %v", err)
	}
	if !loaded.public.Equal(publicKey) {
		t.Fatal("generated key pair does not reproduce its public key")
	}
	publicFromFile, err := loadFeedSigningPublicKey(publicPath)
	if err != nil {
		t.Fatalf("load generated public key: %v", err)
	}
	if !publicFromFile.Equal(publicKey) {
		t.Fatal("public key file does not match the generated key")
	}

	// Overwrite refusal: rotation is an explicit new directory, never implicit.
	if _, err := InitFeedSigning(keysDir, ""); err == nil || !strings.Contains(err.Error(), "refusing to overwrite") {
		t.Fatalf("init feed signing did not refuse to overwrite: %v", err)
	}

	// Explicit public key output path (--feed-public-key).
	otherDir := filepath.Join(dir, "other")
	customPublic := filepath.Join(dir, "published", "feed-signing.ed25519.pub")
	if _, err := InitFeedSigning(otherDir, customPublic); err != nil {
		t.Fatalf("init feed signing with explicit public key path: %v", err)
	}
	if info, err := os.Stat(customPublic); err != nil || info.Mode().Perm() != 0o644 {
		t.Fatalf("explicit public key file missing or wrong mode: %v", err)
	}

	// Permission negatives: a group/world accessible private key is refused.
	if err := os.Chmod(privatePath, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadFeedSigningKeyPair(privatePath); err == nil {
		t.Fatal("world-readable feed signing key was accepted")
	}
	if err := os.Chmod(privatePath, 0o660); err != nil {
		t.Fatal(err)
	}
	if _, err := loadFeedSigningKeyPair(privatePath); err == nil {
		t.Fatal("group-writable feed signing key was accepted")
	}
	// A symlink is never followed as key material.
	if err := os.Remove(privatePath); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(privatePath+"-target", privatePath); err != nil {
		t.Fatal(err)
	}
	if _, err := loadFeedSigningKeyPair(privatePath); err == nil {
		t.Fatal("symlinked feed signing key was accepted")
	}
}

func TestFeedLocalSigningConfigValidation(t *testing.T) {
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pinned := feedSigningPublicKeyBase64(publicKey)

	unsigned := defaultConfig()
	unsigned.Feeds.LocalSigning = true
	unsigned.Feeds.RequireSignedManifest = false
	unsigned.Feeds.SigningKeyFile = "/etc/vgt/gedefense/feed-signing/feed-signing.ed25519"
	if err := validateConfig(&unsigned); err == nil {
		t.Fatal("feeds.local_signing without require_signed_manifest was accepted")
	}

	noKeyFile := defaultConfig()
	noKeyFile.Feeds.LocalSigning = true
	noKeyFile.Feeds.SigningKeyFile = ""
	if err := validateConfig(&noKeyFile); err == nil {
		t.Fatal("feeds.local_signing without signing_key_file was accepted")
	}

	relativeKeyFile := defaultConfig()
	relativeKeyFile.Feeds.LocalSigning = true
	relativeKeyFile.Feeds.SigningKeyFile = "feed-signing.ed25519"
	if err := validateConfig(&relativeKeyFile); err == nil {
		t.Fatal("feeds.local_signing with a relative signing_key_file was accepted")
	}

	relativeSnapshots := defaultConfig()
	relativeSnapshots.Feeds.LocalSigning = true
	relativeSnapshots.Feeds.SigningKeyFile = "/etc/vgt/gedefense/feed-signing/feed-signing.ed25519"
	relativeSnapshots.Feeds.SnapshotDir = "feed-snapshots"
	if err := validateConfig(&relativeSnapshots); err == nil {
		t.Fatal("feeds.local_signing with a relative snapshot_dir was accepted")
	}

	valid := defaultConfig()
	valid.Feeds.Enabled = true
	valid.Feeds.LocalSigning = true
	valid.Feeds.RequireSignedManifest = true
	valid.Feeds.AutoApply = true
	valid.Feeds.SigningKeyFile = "/etc/vgt/gedefense/feed-signing/feed-signing.ed25519"
	valid.Feeds.SnapshotDir = "/var/lib/vgt/gedefense/feed-snapshots"
	valid.Feeds.TrustedSigningKeys = []string{pinned}
	if err := validateConfig(&valid); err != nil {
		t.Fatalf("valid local signing configuration rejected: %v", err)
	}

	// The TOML overlay surfaces the three new keys and rejects unknown ones.
	dir := t.TempDir()
	configPath := filepath.Join(dir, "gedefense.toml")
	configText := "[feeds]\n" +
		"local_signing = true\n" +
		"signing_key_file = \"/etc/vgt/gedefense/feed-signing/feed-signing.ed25519\"\n" +
		"snapshot_dir = \"/var/lib/vgt/gedefense/feed-snapshots\"\n"
	if err := os.WriteFile(configPath, []byte(configText), 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, err := loadConfig(configPath)
	if err != nil {
		t.Fatalf("load config with local signing keys: %v", err)
	}
	if !loaded.Feeds.LocalSigning || loaded.Feeds.SigningKeyFile == "" || loaded.Feeds.SnapshotDir == "" {
		t.Fatalf("local signing keys were not loaded from the configuration: %+v", loaded.Feeds)
	}
}

func TestLocalFeedSigningKernelApplyRefusesExpiredOrUnverifiedGeneration(t *testing.T) {
	env := newFeedSigningTestEnv(t, nil)
	if _, errs := env.sync(t); len(errs) != 0 {
		t.Fatalf("sync failed: %v", errs)
	}
	if _, _, err := env.manager.ApplyToKernel(nil, nil); err != nil {
		t.Fatalf("first kernel apply failed: %v", err)
	}

	env.manager.mu.Lock()
	state := env.manager.feedStates["feodo-c2"]
	originalValidUntil := state.ManifestValidUntil
	state.ManifestValidUntil = time.Now().UTC().Add(-time.Minute)
	env.manager.mu.Unlock()
	if _, _, err := env.manager.ApplyToKernel(nil, nil); err == nil || !strings.Contains(err.Error(), "kernel apply refused") {
		t.Fatalf("expired signed generation reached the kernel diff: %v", err)
	}
	status, _, _, _ := env.manager.KernelApplyStatus()
	if status != kernelApplyError {
		t.Fatalf("kernel_apply_status = %q after refusal, want %q", status, kernelApplyError)
	}

	// A generation without a verified manifest is refused as well.
	env.manager.mu.Lock()
	state.ManifestValidUntil = originalValidUntil
	state.ManifestVerified = false
	env.manager.mu.Unlock()
	if _, _, err := env.manager.ApplyToKernel(nil, nil); err == nil || !strings.Contains(err.Error(), "kernel apply refused") {
		t.Fatalf("unverified signed generation reached the kernel diff: %v", err)
	}

	// Restoring the verified state lets the next apply succeed again.
	env.manager.mu.Lock()
	state.ManifestVerified = true
	env.manager.mu.Unlock()
	if _, _, err := env.manager.ApplyToKernel(nil, nil); err != nil {
		t.Fatalf("restored verified generation was refused: %v", err)
	}
}

func TestLocalFeedSigningReusesSnapshotOnUpstreamOutage(t *testing.T) {
	env := newFeedSigningTestEnv(t, nil)
	if _, errs := env.sync(t); len(errs) != 0 {
		t.Fatalf("initial sync failed: %v", errs)
	}
	// No network at all: the pipeline must sign the existing snapshots and stay
	// operational instead of going blind or accepting unsigned bytes.
	env.transport.setFailing(true)
	items, errs := env.sync(t)
	if len(errs) != 0 {
		t.Fatalf("snapshot-reuse sync reported errors: %v", errs)
	}
	if len(items) == 0 {
		t.Fatal("snapshot-reuse sync lost the block generation")
	}
	if err := env.manager.localSigningKeyPinned(env.manager.localSigningPolicy()); err != nil {
		t.Fatalf("trust anchor check failed after reuse: %v", err)
	}
	document, err := env.manager.readSignedFeedManifest(env.manifestPath, []ed25519.PublicKey{env.publicKey}, time.Hour)
	if err != nil {
		t.Fatalf("reused-snapshot manifest does not verify: %v", err)
	}
	if document.Feeds[0].Version != 2 {
		t.Fatalf("reused-snapshot manifest version = %d, want 2", document.Feeds[0].Version)
	}
	if _, _, err := env.manager.ApplyToKernel(nil, nil); err != nil {
		t.Fatalf("kernel apply after snapshot reuse failed: %v", err)
	}
}

func TestFeedSigningManifestTTLAndRollback(t *testing.T) {
	publicKey, privateKey := testFeedSigningKeypair(t)
	now := time.Now().UTC()
	source := testFeedSource()
	raw := []byte("203.0.113.7\n")
	entry := feedManifestForRaw(source, raw, 1, now.Add(time.Hour))
	document := threatFeedManifestDocument{
		Schema:      threatFeedManifestSchema,
		GeneratedAt: now.Add(-2 * time.Hour),
		ValidUntil:  now.Add(-time.Hour),
		Feeds:       []threatFeedManifestEntry{entry},
	}
	signed := signTestFeedManifest(t, privateKey, document)
	if err := verifyFeedSigningManifest(signed, []ed25519.PublicKey{publicKey}); err != nil {
		t.Fatalf("signed manifest self-check failed: %v", err)
	}
	if err := validateSignedFeedManifest(signed, now, time.Hour); err == nil {
		t.Fatal("expired signed manifest passed validation")
	}

	overAge := threatFeedManifestDocument{
		Schema:      threatFeedManifestSchema,
		GeneratedAt: now.Add(-4 * time.Hour),
		ValidUntil:  now.Add(2 * time.Hour),
		Feeds:       []threatFeedManifestEntry{feedManifestForRaw(source, raw, 1, now.Add(2*time.Hour))},
	}
	if err := validateSignedFeedManifest(overAge, now, time.Hour); err == nil {
		t.Fatal("over-age signed manifest passed validation")
	}

	// Anti-rollback: an older version and a reused version with different
	// content are both refused by the persisted floor.
	certificate := &threatFeedCertificate{Version: 1, ValidUntil: now.Add(time.Hour), Entry: entry}
	if err := checkManifestRollback(&FeedGenerationState{ManifestVersion: 2}, certificate); err == nil {
		t.Fatal("older signed generation passed the anti-rollback floor")
	}
	reused := &FeedGenerationState{ManifestVersion: 1, LastGoodFingerprint: strings.Repeat("a", 64)}
	if err := checkManifestRollback(reused, certificate); err == nil {
		t.Fatal("reused manifest version with different content passed the anti-rollback floor")
	}
	matching := &FeedGenerationState{ManifestVersion: 1, LastGoodFingerprint: entry.ItemsSHA256}
	if err := checkManifestRollback(matching, certificate); err != nil {
		t.Fatalf("valid re-download at the same version was refused: %v", err)
	}
}

// signTestFeedManifest signs a manifest with a raw private key and returns the
// fully populated document (signature included).
func signTestFeedManifest(t *testing.T, privateKey ed25519.PrivateKey, document threatFeedManifestDocument) threatFeedManifestDocument {
	t.Helper()
	document.Signature = ""
	document.GeneratedAt = document.GeneratedAt.UTC()
	document.ValidUntil = document.ValidUntil.UTC()
	document.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, threatFeedManifestMessageFor(document)))
	return document
}

// writeFeedManifestJSON writes a manifest document through the production
// atomic writer, so tests exercise the same on-disk shape the manager reads.
func writeFeedManifestJSON(path string, document threatFeedManifestDocument) error {
	encoded, err := json.Marshal(document)
	if err != nil {
		return err
	}
	return atomicWriteFile(path, encoded, 0o600)
}
