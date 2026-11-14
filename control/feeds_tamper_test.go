// STATUS: DIAMANT VGT SUPREME
package main

// FIND-023 regression corpus: the persisted threat-intelligence state carries the
// anti-rollback floor (ManifestVersion) and the last-known-good indicator sets, so
// it must never be adopted unless it is authenticated. These tests prove that
//   - a correctly signed / manifest-anchored state is adopted across a restart,
//   - a manipulated ManifestVersion or indicator set is refused with an event,
//   - an unsigned legacy document is quarantined instead of silently adopted
//     whenever a feed authenticity model is configured,
//   - a deployment without an authenticity model keeps the documented legacy
//     migration (plaintext is all that mode ever had).

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type threatIntelStateTestEnv struct {
	dir          string
	stateDir     string
	keysDir      string
	privatePath  string
	publicKey    ed25519.PublicKey
	manifestPath string
}

func newThreatIntelStateTestEnv(t *testing.T) *threatIntelStateTestEnv {
	t.Helper()
	dir := t.TempDir()
	keysDir := filepath.Join(dir, "keys")
	publicKey, err := InitFeedSigning(keysDir, "")
	if err != nil {
		t.Fatalf("init feed signing: %v", err)
	}
	return &threatIntelStateTestEnv{
		dir: dir, stateDir: filepath.Join(dir, "state"), keysDir: keysDir,
		privatePath:  filepath.Join(keysDir, feedSigningPrivateKeyFile),
		publicKey:    publicKey,
		manifestPath: filepath.Join(dir, "threat-feed-manifest.json"),
	}
}

// localSigningFeedConfig is the deployment mode in which the operator key is on
// the host: the state can be signed with it.
func (env *threatIntelStateTestEnv) localSigningFeedConfig() FeedConfig {
	return FeedConfig{
		MaxEntries:            1000,
		RequireSignedManifest: true,
		TrustedSigningKeys:    []string{feedSigningPublicKeyBase64(env.publicKey)},
		ManifestPath:          env.manifestPath,
		ManifestMaxAgeMinutes: 240,
		LocalSigning:          true,
		SigningKeyFile:        env.privatePath,
		SnapshotDir:           filepath.Join(env.dir, "snapshots"),
	}
}

func quarantineEntries(t *testing.T, stateDir string) []string {
	t.Helper()
	matches, err := filepath.Glob(filepath.Join(stateDir, "threat-intel-state.json"+threatIntelStateQuarantineSuffix+"*"))
	if err != nil {
		t.Fatal(err)
	}
	return matches
}

func feedStateSnapshot(t *testing.T, manager *FeedManager, id string) FeedGenerationState {
	t.Helper()
	manager.mu.RLock()
	defer manager.mu.RUnlock()
	state, ok := manager.feedStates[id]
	if !ok {
		t.Fatalf("feed %s is not tracked by the manager", id)
	}
	return *state
}

// tamperThreatIntelStateEnvelope rewrites one field of an envelope payload
// without touching the signature or the embedded manifest anchor, which is
// exactly the attacker model of FIND-023.
func tamperThreatIntelStateEnvelope(t *testing.T, statePath string, mutate func(payload map[string]any)) {
	t.Helper()
	raw, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatal(err)
	}
	var envelope map[string]any
	if err := json.Unmarshal(raw, &envelope); err != nil {
		t.Fatal(err)
	}
	encodedPayload, ok := envelope["payload"].(string)
	if !ok {
		t.Fatalf("state envelope has no payload: %s", string(raw))
	}
	payloadRaw, err := base64.StdEncoding.DecodeString(encodedPayload)
	if err != nil {
		t.Fatal(err)
	}
	var payload map[string]any
	if err := json.Unmarshal(payloadRaw, &payload); err != nil {
		t.Fatal(err)
	}
	mutate(payload)
	mutatedPayload, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	envelope["payload"] = base64.StdEncoding.EncodeToString(mutatedPayload)
	mutatedEnvelope, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(statePath, mutatedEnvelope, 0o600); err != nil {
		t.Fatal(err)
	}
}

func payloadFeed(t *testing.T, payload map[string]any, id string) map[string]any {
	t.Helper()
	feeds, ok := payload["feeds"].(map[string]any)
	if !ok {
		t.Fatalf("payload has no feeds map: %v", payload["feeds"])
	}
	feed, ok := feeds[id].(map[string]any)
	if !ok {
		t.Fatalf("payload has no feed %s: %v", id, feeds)
	}
	return feed
}

func hasStateIntegrityEvent(events []threatIntelStateIntegrityEvent, kind string) bool {
	for _, event := range events {
		if event.Kind == kind {
			return true
		}
	}
	return false
}

func saveFeedState(t *testing.T, manager *FeedManager, id string, mutate func(*FeedGenerationState)) {
	t.Helper()
	manager.mu.Lock()
	state, ok := manager.feedStates[id]
	if !ok {
		manager.mu.Unlock()
		t.Fatalf("feed %s is not tracked by the manager", id)
	}
	mutate(state)
	manager.mu.Unlock()

	manager.mu.Lock()
	err := manager.savePersistentStateLocked()
	manager.mu.Unlock()
	if err != nil {
		t.Fatalf("save persisted state: %v", err)
	}
}

func TestPersistentStateSignedAdoptedAndTamperRefused(t *testing.T) {
	env := newThreatIntelStateTestEnv(t)
	cfg := env.localSigningFeedConfig()
	manager := NewFeedManager(cfg, env.stateDir)
	statePath := manager.statePath

	lastGoodAt := time.Now().UTC().Truncate(time.Second)
	saveFeedState(t, manager, "feodo-c2", func(state *FeedGenerationState) {
		state.LastGoodItems = []string{"203.0.113.7/32"}
		state.LastGoodCount = 1
		state.LastGoodFingerprint = computeFingerprint(state.LastGoodItems)
		state.LastGoodAt = lastGoodAt
		state.LastAttemptAt = lastGoodAt
		state.ManifestVersion = 42
		state.ManifestValidUntil = lastGoodAt.Add(time.Hour)
		state.ManifestVerified = true
		state.ManifestAuthenticity = "SIGNED"
	})

	raw, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), threatIntelStateEnvelopeSchema) || !strings.Contains(string(raw), threatIntelStateModeSigned) {
		t.Fatalf("persisted state is not a signed envelope: %s", string(raw))
	}

	// 1. The authenticated state is adopted across a restart.
	reloaded := NewFeedManager(cfg, env.stateDir)
	if integrityErr, events := reloaded.PersistentStateIntegrity(); integrityErr != "" || !hasStateIntegrityEvent(events, "state.loaded") {
		t.Fatalf("signed state was not adopted: err=%q events=%+v", integrityErr, events)
	}
	adopted := feedStateSnapshot(t, reloaded, "feodo-c2")
	if adopted.ManifestVersion != 42 || len(adopted.LastGoodItems) != 1 || adopted.LastGoodItems[0] != "203.0.113.7/32" {
		t.Fatalf("signed state values not adopted: %+v", adopted)
	}
	if !adopted.ManifestVerified || adopted.ManifestAuthenticity != "SIGNED" {
		t.Fatalf("signed projection not adopted: %+v", adopted)
	}

	// 2. A manipulated anti-rollback floor (downgrade) breaks the signature: the
	//    whole document is untrusted, quarantined and never adopted.
	tamperThreatIntelStateEnvelope(t, statePath, func(payload map[string]any) {
		payloadFeed(t, payload, "feodo-c2")["manifest_version"] = 1
	})
	tampered := NewFeedManager(cfg, env.stateDir)
	integrityErr, events := tampered.PersistentStateIntegrity()
	if integrityErr == "" || !hasStateIntegrityEvent(events, "state.untrusted") {
		t.Fatalf("tampered signed state was not refused: err=%q events=%+v", integrityErr, events)
	}
	if state := feedStateSnapshot(t, tampered, "feodo-c2"); state.ManifestVersion != 0 || len(state.LastGoodItems) != 0 {
		t.Fatalf("tampered anti-rollback state was adopted: %+v", state)
	}
	if _, statErr := os.Lstat(statePath); !os.IsNotExist(statErr) {
		t.Fatal("untrusted state file was not quarantined")
	}
	if matches := quarantineEntries(t, env.stateDir); len(matches) != 1 {
		t.Fatalf("expected exactly one quarantined state file, got %v", matches)
	}
}

func writeAnchoredFeedManifest(t *testing.T, env *threatIntelStateTestEnv, privateKey ed25519.PrivateKey, version uint64) (threatFeedManifestEntry, []string) {
	t.Helper()
	now := time.Now().UTC()
	rawFeed := []byte("203.0.113.7\n198.51.100.9\n")
	items := parsePlainFeedItemsForTest(rawFeed)
	entry := feedManifestForRaw(testFeedSource(), rawFeed, version, now.Add(time.Hour))
	writeFeedManifest(t, env.manifestPath, signedFeedManifest(t, privateKey, now.Add(-time.Minute), now.Add(time.Hour), entry))
	return entry, items
}

func (env *threatIntelStateTestEnv) manifestAnchorFeedConfig() FeedConfig {
	return FeedConfig{
		MaxEntries:            1000,
		RequireSignedManifest: true,
		TrustedSigningKeys:    []string{base64.StdEncoding.EncodeToString(env.publicKey)},
		ManifestPath:          env.manifestPath,
		ManifestMaxAgeMinutes: 240,
	}
}

// seedAnchoredState builds a manager whose persisted feed projection matches the
// signed manifest, saves it and returns the manager and its entry.
func seedAnchoredState(t *testing.T, env *threatIntelStateTestEnv, version uint64) (*FeedManager, threatFeedManifestEntry, []string) {
	t.Helper()
	keyPair, err := loadFeedSigningKeyPair(env.privatePath)
	if err != nil {
		t.Fatalf("load operator key: %v", err)
	}
	entry, items := writeAnchoredFeedManifest(t, env, keyPair.private, version)
	cfg := env.manifestAnchorFeedConfig()
	manager := NewFeedManager(cfg, env.stateDir)
	saveFeedState(t, manager, entry.ID, func(state *FeedGenerationState) {
		state.LastGoodItems = append([]string(nil), items...)
		state.LastGoodCount = len(items)
		state.LastGoodFingerprint = entry.ItemsSHA256
		state.LastGoodAt = time.Now().UTC().Truncate(time.Second)
		state.ManifestVersion = entry.Version
		state.ManifestValidUntil = entry.ValidUntil
		state.ManifestVerified = true
		state.ManifestAuthenticity = "SIGNED"
	})
	return manager, entry, items
}

func TestPersistentStateManifestAnchorAdoptedAndTamperRefused(t *testing.T) {
	env := newThreatIntelStateTestEnv(t)
	cfg := env.manifestAnchorFeedConfig()

	// 1. A state bound to a validly signed manifest is adopted.
	manager, entry, items := seedAnchoredState(t, env, 7)
	if manager.statePath == "" {
		t.Fatal("manager has no state path")
	}
	reloaded := NewFeedManager(cfg, env.stateDir)
	if integrityErr, events := reloaded.PersistentStateIntegrity(); integrityErr != "" || !hasStateIntegrityEvent(events, "state.loaded") {
		t.Fatalf("manifest-anchored state was not adopted: err=%q events=%+v", integrityErr, events)
	}
	adopted := feedStateSnapshot(t, reloaded, entry.ID)
	if adopted.ManifestVersion != entry.Version || len(adopted.LastGoodItems) != len(items) {
		t.Fatalf("anchored state values not adopted: %+v", adopted)
	}

	// 2. A lowered anti-rollback floor is not authenticated by the embedded
	//    manifest: only the affected projection is refused, and the refusal is
	//    recorded as an integrity event.
	tamperThreatIntelStateEnvelope(t, manager.statePath, func(payload map[string]any) {
		payloadFeed(t, payload, entry.ID)["manifest_version"] = 1
	})
	tampered := NewFeedManager(cfg, env.stateDir)
	_, events := tampered.PersistentStateIntegrity()
	if !hasStateIntegrityEvent(events, "state.feed_projection_refused") {
		t.Fatalf("lowered ManifestVersion was not refused: events=%+v", events)
	}
	if state := feedStateSnapshot(t, tampered, entry.ID); state.ManifestVersion != 0 || len(state.LastGoodItems) != 0 {
		t.Fatalf("tampered anti-rollback floor was adopted: %+v", state)
	}
	if matches := quarantineEntries(t, env.stateDir); len(matches) != 0 {
		t.Fatalf("authenticated envelope should not be quarantined: %v", matches)
	}

	// 3. A substituted indicator set is refused as well (the manifest binds the
	//    exact canonical item digest).
	env2 := newThreatIntelStateTestEnv(t)
	manager2, entry2, _ := seedAnchoredState(t, env2, 9)
	tamperThreatIntelStateEnvelope(t, manager2.statePath, func(payload map[string]any) {
		feed := payloadFeed(t, payload, entry2.ID)
		feed["last_good_items"] = []string{"6.6.6.6/32"}
		feed["last_good_fingerprint"] = computeFingerprint([]string{"6.6.6.6/32"})
	})
	tampered2 := NewFeedManager(env2.manifestAnchorFeedConfig(), env2.stateDir)
	_, events2 := tampered2.PersistentStateIntegrity()
	if !hasStateIntegrityEvent(events2, "state.feed_projection_refused") {
		t.Fatalf("substituted indicator set was not refused: events=%+v", events2)
	}
	if state := feedStateSnapshot(t, tampered2, entry2.ID); len(state.LastGoodItems) != 0 {
		t.Fatalf("substituted indicator set was adopted: %+v", state)
	}
}

func TestPersistentStateUnsignedLegacyDocumentIsQuarantined(t *testing.T) {
	publicKey, _ := testFeedSigningKeypair(t)
	dir := t.TempDir()
	stateDir := filepath.Join(dir, "state")
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	statePath := filepath.Join(stateDir, "threat-intel-state.json")
	lastGoodAt := time.Now().UTC().Truncate(time.Second)
	legacy := map[string]any{
		"schema":                  threatIntelStateSchema,
		"overall_status":          "OK",
		"last_successful_sync_at": lastGoodAt.Format(time.RFC3339),
		"generation":              uint64(99),
		"feeds": map[string]any{
			"feodo-c2": map[string]any{
				"id": "feodo-c2", "action": "BLOCK",
				"last_good_items": []string{"203.0.113.7/32"}, "last_good_count": 1,
				"manifest_version": uint64(77), "manifest_verified": true,
				"manifest_authenticity": "SIGNED",
			},
		},
	}
	raw, err := json.Marshal(legacy)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(statePath, raw, 0o600); err != nil {
		t.Fatal(err)
	}

	cfg := FeedConfig{
		MaxEntries:            1000,
		RequireSignedManifest: true,
		TrustedSigningKeys:    []string{base64.StdEncoding.EncodeToString(publicKey)},
		ManifestPath:          filepath.Join(dir, "threat-feed-manifest.json"),
		ManifestMaxAgeMinutes: 240,
	}
	manager := NewFeedManager(cfg, stateDir)
	integrityErr, events := manager.PersistentStateIntegrity()
	if integrityErr == "" || !hasStateIntegrityEvent(events, "state.untrusted") {
		t.Fatalf("unsigned legacy state was not refused: err=%q events=%+v", integrityErr, events)
	}
	state := feedStateSnapshot(t, manager, "feodo-c2")
	if state.ManifestVersion != 0 || len(state.LastGoodItems) != 0 {
		t.Fatalf("unsigned state floor/items were adopted: %+v", state)
	}
	if manager.Generation() != 0 {
		t.Fatalf("unsigned generation counter was adopted: %d", manager.Generation())
	}
	if _, statErr := os.Lstat(statePath); !os.IsNotExist(statErr) {
		t.Fatal("unsigned state file was not quarantined")
	}
	if matches := quarantineEntries(t, stateDir); len(matches) != 1 {
		t.Fatalf("expected the unsigned file to be quarantined once, got %v", matches)
	}
}

func TestPersistentStateUnauthenticatedPipelineKeepsLegacyMigration(t *testing.T) {
	dir := t.TempDir()
	statePath := filepath.Join(dir, "threat-intel-state.json")
	doc := `{
		"schema": "vgt-gedefense-threat-intel-state-v1",
		"last_successful_sync_at": "2026-10-01T12:00:00Z",
		"generation": 42,
		"fingerprint": "abc12345",
		"feeds": {"feodo-c2": {"id": "feodo-c2", "action": "BLOCK", "last_good_items": ["203.0.113.1/32"], "last_good_count": 1}}
	}`
	if err := os.WriteFile(statePath, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	// No manifest gate, no pinned key, no local signing: the whole pipeline is
	// explicitly unauthenticated, so the documented legacy document is migrated.
	manager := NewFeedManager(FeedConfig{MaxEntries: 1000}, dir)
	if manager.Generation() != 42 {
		t.Fatalf("legacy unauthenticated state was not migrated: generation=%d", manager.Generation())
	}
	if integrityErr, events := manager.PersistentStateIntegrity(); integrityErr != "" || !hasStateIntegrityEvent(events, "state.loaded_unauthenticated") {
		t.Fatalf("unauthenticated migration not recorded: err=%q events=%+v", integrityErr, events)
	}
	if matches := quarantineEntries(t, dir); len(matches) != 0 {
		t.Fatalf("unauthenticated pipeline must not quarantine its own legacy file: %v", matches)
	}
}

func TestPersistentStatePersistenceRefusedWithoutAuthenticatedFormat(t *testing.T) {
	// A manifest gate is configured but no trust anchor is provisioned: the
	// manager may not write an unsigned state file, because that file would be
	// exactly the downgrade the integrity check exists for.
	dir := t.TempDir()
	manager := NewFeedManager(FeedConfig{
		MaxEntries:            1000,
		RequireSignedManifest: true,
		ManifestPath:          filepath.Join(dir, "threat-feed-manifest.json"),
		ManifestMaxAgeMinutes: 240,
	}, dir)

	manager.mu.Lock()
	saveErr := manager.savePersistentStateLocked()
	manager.mu.Unlock()
	if saveErr == nil {
		t.Fatal("unsigned state was persisted although a feed authenticity model is configured")
	}
	if _, statErr := os.Lstat(manager.statePath); !os.IsNotExist(statErr) {
		t.Fatal("refused save still created a state file")
	}
	integrityErr, events := manager.PersistentStateIntegrity()
	if integrityErr == "" || !hasStateIntegrityEvent(events, "state.persist_refused") {
		t.Fatalf("persistence refusal not recorded: err=%q events=%+v", integrityErr, events)
	}
}
