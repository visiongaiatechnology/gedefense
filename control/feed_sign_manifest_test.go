// STATUS: DIAMANT VGT SUPREME

package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

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

// writeFeedSigningTestKeyFile writes exact key-file bytes, independent of
// InitFeedSigning, so a test controls the raw material and the file mode.
func writeFeedSigningTestKeyFile(t *testing.T, path string, raw []byte, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, raw, mode); err != nil {
		t.Fatal(err)
	}
	// WriteFile keeps an existing file's mode; chmod makes the test independent
	// of the process umask and of the previous write.
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

// TestFeedSigningKeyFileBytesAreNotTrimmed is the regression test for the P3
// provisioning flake: loadFeedSigningPublicKey ran strings.TrimSpace over the
// raw 32 key bytes. A randomly generated Ed25519 key starting or ending with a
// whitespace byte was shortened to 31 bytes and rejected, which failed
// TestInitFeedSigningProvisioning in 11/200 runs.
func TestFeedSigningKeyFileBytesAreNotTrimmed(t *testing.T) {
	dir := t.TempDir()
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publicPath := filepath.Join(dir, "feed-signing.ed25519.pub")
	privatePath := filepath.Join(dir, "feed-signing.ed25519")
	// Every byte unicode.IsSpace strips from a Go string, plus NUL (which is key
	// material like any other byte and also must never be reinterpreted).
	edgeBytes := []byte{0x20, 0x09, 0x0a, 0x0d, 0x0b, 0x0c, 0x00}

	// (a) 32 raw key bytes stay 32 raw key bytes, even when an edge byte is one
	// TrimSpace would have removed. 0x0a/0x0d are included: a key ending in a
	// newline byte is a valid key, not a newline-terminated 31-byte key.
	for _, edge := range edgeBytes {
		for _, index := range []int{0, ed25519.PublicKeySize - 2, ed25519.PublicKeySize - 1} {
			edited := append([]byte(nil), publicKey...)
			edited[index] = edge
			writeFeedSigningTestKeyFile(t, publicPath, edited, 0o644)
			loaded, loadErr := loadFeedSigningPublicKey(publicPath)
			if loadErr != nil {
				t.Fatalf("public key with edge byte 0x%02x at index %d rejected: %v", edge, index, loadErr)
			}
			if !loaded.Equal(ed25519.PublicKey(edited)) {
				t.Fatalf("public key with edge byte 0x%02x at index %d was altered", edge, index)
			}
		}
	}
	// A key whose final two bytes are exactly "\r\n" is a 32-byte key, not a
	// terminated 30-byte key.
	crlfKey := append([]byte(nil), publicKey...)
	crlfKey[ed25519.PublicKeySize-2], crlfKey[ed25519.PublicKeySize-1] = '\r', '\n'
	writeFeedSigningTestKeyFile(t, publicPath, crlfKey, 0o644)
	if loaded, loadErr := loadFeedSigningPublicKey(publicPath); loadErr != nil || !loaded.Equal(ed25519.PublicKey(crlfKey)) {
		t.Fatalf("32-byte public key ending in CRLF was not accepted verbatim: %v", loadErr)
	}

	// (b) Exactly one optional trailing file terminator is tolerated for the raw
	// form and for the documented base64 form.
	for _, terminator := range [][]byte{{'\n'}, {'\r', '\n'}} {
		rawForm := append(append([]byte(nil), publicKey...), terminator...)
		writeFeedSigningTestKeyFile(t, publicPath, rawForm, 0o644)
		if loaded, loadErr := loadFeedSigningPublicKey(publicPath); loadErr != nil || !loaded.Equal(publicKey) {
			t.Fatalf("newline-terminated raw public key rejected: %v", loadErr)
		}
		base64Form := append([]byte(feedSigningPublicKeyBase64(publicKey)), terminator...)
		writeFeedSigningTestKeyFile(t, publicPath, base64Form, 0o644)
		if loaded, loadErr := loadFeedSigningPublicKey(publicPath); loadErr != nil || !loaded.Equal(publicKey) {
			t.Fatalf("newline-terminated base64 public key rejected: %v", loadErr)
		}
	}

	// (c) 31/33-byte key material is rejected with an error that names the
	// required size: a truncated or padded key is never quietly accepted.
	for _, rejected := range [][]byte{
		publicKey[:ed25519.PublicKeySize-1],
		append(append([]byte(nil), publicKey...), 0xAB),
		append(append([]byte(nil), publicKey...), 0xAB, 0xCD),
	} {
		writeFeedSigningTestKeyFile(t, publicPath, rejected, 0o644)
		_, loadErr := loadFeedSigningPublicKey(publicPath)
		if loadErr == nil {
			t.Fatalf("%d-byte public key file was accepted", len(rejected))
		}
		if !strings.Contains(loadErr.Error(), "32-byte") {
			t.Fatalf("public key size error is not clear: %v", loadErr)
		}
	}

	// The operator key loader follows the same rule: binary seed/key bytes are
	// used verbatim (only one optional trailing newline is stripped).
	seed := privateKey.Seed()
	for _, edge := range edgeBytes {
		edited := append([]byte(nil), seed...)
		edited[0], edited[ed25519.SeedSize-1] = edge, edge
		writeFeedSigningTestKeyFile(t, privatePath, edited, 0o600)
		loaded, loadErr := loadFeedSigningKeyPair(privatePath)
		if loadErr != nil {
			t.Fatalf("private seed with edge bytes 0x%02x rejected: %v", edge, loadErr)
		}
		want := ed25519.NewKeyFromSeed(edited)
		if !loaded.private.Equal(want) || !loaded.public.Equal(want.Public().(ed25519.PublicKey)) {
			t.Fatalf("private seed with edge bytes 0x%02x was altered", edge)
		}
	}
	// Also test deterministic trailing-0x0d/0x0a seeds with both "\n" and "\r\n"
	// terminators so a random key ending in '\r' never gets corrupted by "\r\n" stripping.
	crSeed := append([]byte(nil), seed...)
	crSeed[ed25519.SeedSize-1] = '\r'
	crPriv := ed25519.NewKeyFromSeed(crSeed)
	for _, keyMaterial := range [][]byte{seed, privateKey, crSeed, crPriv} {
		want := ed25519.PrivateKey(append([]byte(nil), keyMaterial...))
		if len(keyMaterial) == ed25519.SeedSize {
			want = ed25519.NewKeyFromSeed(keyMaterial)
		}
		for _, terminator := range [][]byte{{'\n'}, {'\r', '\n'}} {
			rawForm := append(append([]byte(nil), keyMaterial...), terminator...)
			writeFeedSigningTestKeyFile(t, privatePath, rawForm, 0o600)
			loaded, loadErr := loadFeedSigningKeyPair(privatePath)
			if loadErr != nil {
				t.Fatalf("%d-byte private key material with terminator rejected: %v", len(keyMaterial), loadErr)
			}
			if !loaded.private.Equal(want) || !loaded.public.Equal(want.Public().(ed25519.PublicKey)) {
				t.Fatalf("%d-byte private key material with terminator was altered", len(keyMaterial))
			}
		}
	}
	for _, rejected := range [][]byte{
		seed[:ed25519.SeedSize-1],
		append(append([]byte(nil), seed...), 0xAB),
		privateKey[:ed25519.PrivateKeySize-1],
		append(append([]byte(nil), privateKey...), 0xAB),
	} {
		writeFeedSigningTestKeyFile(t, privatePath, rejected, 0o600)
		_, loadErr := loadFeedSigningKeyPair(privatePath)
		if loadErr == nil {
			t.Fatalf("%d-byte private key file was accepted", len(rejected))
		}
		if !strings.Contains(loadErr.Error(), "32-byte seed") {
			t.Fatalf("private key size error is not clear: %v", loadErr)
		}
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

func TestFeedSigningSelfHealMarkerIgnoresStaleTempFiles(t *testing.T) {
	dir := t.TempDir()
	keysDir := filepath.Join(dir, "keys")
	publicKey, err := InitFeedSigning(keysDir, "")
	if err != nil {
		t.Fatalf("init feed signing: %v", err)
	}
	stateDir := filepath.Join(dir, "state")
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	markerPath := filepath.Join(stateDir, feedSigningSelfHealMarkerFile)

	// The historical implementation opened markerPath+".tmp" with O_EXCL and
	// reported success when that open returned os.ErrExist. Plant exactly the
	// remnants an interrupted write leaves behind: the fixed legacy name and a
	// partial CreateTemp file with the reserved prefix.
	legacyStale := markerPath + ".tmp"
	if err := os.WriteFile(legacyStale, []byte("{not-json"), 0o600); err != nil {
		t.Fatal(err)
	}
	prefixedStale := filepath.Join(stateDir, feedSigningSelfHealTempPrefix+"interrupted.tmp")
	if err := os.WriteFile(prefixedStale, []byte("garbage"), 0o600); err != nil {
		t.Fatal(err)
	}
	unrelated := filepath.Join(stateDir, "unrelated.file")
	if err := os.WriteFile(unrelated, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg := FeedConfig{
		LocalSigning: true, RequireSignedManifest: true,
		SigningKeyFile: filepath.Join(keysDir, feedSigningPrivateKeyFile),
	}
	healed, ok, healErr := selfHealFeedSigningPin(cfg, stateDir)
	if healErr != nil || !ok {
		t.Fatalf("self-heal with stale temp files failed: ok=%v err=%v", ok, healErr)
	}
	if !healed.Equal(publicKey) {
		t.Fatal("self-healed key is not the operator key")
	}
	// Success must mean a validated marker exists, not merely that a leftover
	// temporary file was encountered.
	if _, markerErr := readFeedSigningSelfHealMarker(markerPath, feedSigningPublicKeyBase64(publicKey)); markerErr != nil {
		t.Fatalf("self-heal reported success without a valid marker: %v", markerErr)
	}
	for _, stale := range []string{legacyStale, prefixedStale} {
		if _, statErr := os.Lstat(stale); !os.IsNotExist(statErr) {
			t.Fatalf("stale temporary file %q was not cleaned up", stale)
		}
	}
	if _, statErr := os.Lstat(unrelated); statErr != nil {
		t.Fatalf("cleanup removed an unrelated state file: %v", statErr)
	}

	// The published marker is stable: a second call is idempotent.
	secondKey, secondOK, secondErr := selfHealFeedSigningPin(cfg, stateDir)
	if secondErr != nil || !secondOK || !secondKey.Equal(publicKey) {
		t.Fatalf("second self-heal not idempotent: ok=%v err=%v", secondOK, secondErr)
	}

	// A corrupt marker is a hard fail-closed condition, never a re-create.
	if err := os.WriteFile(markerPath, []byte("{corrupt"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, corruptErr := selfHealFeedSigningPin(cfg, stateDir); corruptErr == nil {
		t.Fatal("corrupt self-heal marker was silently replaced")
	}

	// A marker for a different operator key is a rotation signal, not a licence
	// to re-pin.
	foreignPublic, _, generateErr := ed25519.GenerateKey(rand.Reader)
	if generateErr != nil {
		t.Fatal(generateErr)
	}
	foreignMarker := feedSigningSelfHealMarker{
		Schema: "vgt.feed-signing.self-heal/v1", PublicKey: feedSigningPublicKeyBase64(foreignPublic),
	}
	foreignRaw, marshalErr := json.Marshal(foreignMarker)
	if marshalErr != nil {
		t.Fatal(marshalErr)
	}
	if err := os.WriteFile(markerPath, foreignRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, rotationErr := selfHealFeedSigningPin(cfg, stateDir); rotationErr == nil || !strings.Contains(rotationErr.Error(), "explicit pin required") {
		t.Fatalf("rotated self-heal marker did not fail closed: %v", rotationErr)
	}
}
