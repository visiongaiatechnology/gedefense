// AP-9 / S09 — integration corpus at the feeds boundary: a poisoned update
// that is *validly* 2-of-3 signed (and covered by a valid legacy manifest) must
// not be activated, the previous Last-Known-Good must stay active and the
// high-water epoch must not advance. All of this runs against the existing
// in-memory feed test harness, no network.
package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const tufIntegrationFeodoURL = "https://feodotracker.abuse.ch/downloads/ipblocklist.txt"

type tufIntegrationEnv struct {
	dir          string
	stateDir     string
	manifestPath string
	manager      *FeedManager
	transport    *feedSigningTestTransport
	roles        *tufTestRoles
}

func newTufIntegrationEnv(t *testing.T) *tufIntegrationEnv {
	t.Helper()
	dir := t.TempDir()
	roles := newTufTestRoles(t)
	env := &tufIntegrationEnv{
		dir:          dir,
		stateDir:     filepath.Join(dir, "state"),
		manifestPath: filepath.Join(dir, "threat-feed-manifest.json"),
		transport:    newFeedSigningTestTransport(),
		roles:        roles,
	}
	cfg := FeedConfig{
		Enabled:               true,
		RefreshMinutes:        60,
		MaxDownloadBytes:      1 << 20,
		MaxEntries:            5000,
		RequireSignedManifest: true,
		TrustedSigningKeys: []string{
			base64.StdEncoding.EncodeToString(roles.public[0]),
			base64.StdEncoding.EncodeToString(roles.public[1]),
			base64.StdEncoding.EncodeToString(roles.public[2]),
		},
		ManifestPath:          env.manifestPath,
		ManifestMaxAgeMinutes: 60,
	}
	env.manager = NewFeedManager(cfg, env.stateDir)
	env.manager.client = &http.Client{Transport: env.transport}
	return env
}

func (env *tufIntegrationEnv) bodyFor(source ThreatFeedSource) []byte {
	env.transport.mu.Lock()
	defer env.transport.mu.Unlock()
	if body, known := env.transport.bodies[source.URL]; known {
		return body
	}
	return feedSigningDefaultBody(source.URL)
}

// publishFeedManifest writes a valid detached legacy manifest (single pinned
// signature, the pre-existing F-03 gate) for the current transport bodies.
func (env *tufIntegrationEnv) publishFeedManifest(t *testing.T, version uint64) threatFeedManifestDocument {
	t.Helper()
	snapshot := env.manager.live.current()
	generatedAt := time.Now().UTC()
	document := threatFeedManifestDocument{
		Schema:      threatFeedManifestSchema,
		GeneratedAt: generatedAt.Add(-time.Minute),
		ValidUntil:  generatedAt.Add(30 * time.Minute),
	}
	for _, source := range snapshot.orderedSources() {
		raw := env.bodyFor(source)
		maxEntries, _, _ := snapshot.feedBounds(source)
		items, err := parseFeedRaw(source, raw, "", snapshot.settings.Validation, maxEntries)
		if err != nil {
			t.Fatalf("test harness could not parse %s: %v", source.ID, err)
		}
		digest := sha256.Sum256(raw)
		document.Feeds = append(document.Feeds, threatFeedManifestEntry{
			ID: source.ID, URL: source.URL,
			RawSHA256: hex.EncodeToString(digest[:]), ItemsSHA256: computeFingerprint(items),
			Version: version, Action: source.Action, ValidUntil: generatedAt.Add(20 * time.Minute),
		})
	}
	key := &feedSigningKeyPair{private: env.roles.private[0], public: env.roles.public[0]}
	signed, err := signFeedSigningManifest(document, key)
	if err != nil {
		t.Fatalf("sign legacy feed manifest: %v", err)
	}
	raw, err := json.Marshal(signed)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(env.manifestPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(env.manifestPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return signed
}

// publishThresholdEnvelope writes a TUF 2-of-3 envelope over the canonical
// content digest of the given legacy manifest.
func (env *tufIntegrationEnv) publishThresholdEnvelope(t *testing.T, epoch uint64, document threatFeedManifestDocument, signatureRoles ...string) {
	t.Helper()
	spec := tufTestEnvelopeSpec{
		Epoch:         epoch,
		ContentDigest: tufFeedManifestContentDigest(document),
		Now:           time.Now().UTC(),
		Roles:         signatureRoles,
	}
	raw, err := json.Marshal(env.roles.envelope(t, spec))
	if err != nil {
		t.Fatal(err)
	}
	path := tufManifestEnvelopePath(env.manifestPath)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
}

func (env *tufIntegrationEnv) sync(t *testing.T) map[string]error {
	t.Helper()
	_, errs, err := env.manager.SyncWithLock(context.Background(), "tuf-integration")
	if err != nil {
		t.Fatalf("sync lock: %v", err)
	}
	return errs
}

func (env *tufIntegrationEnv) feedState(t *testing.T, id string) FeedGenerationState {
	t.Helper()
	env.manager.mu.RLock()
	defer env.manager.mu.RUnlock()
	state := env.manager.feedStates[id]
	if state == nil {
		t.Fatalf("feed %s is not tracked", id)
	}
	cloned := *state
	cloned.LastGoodItems = append([]string(nil), state.LastGoodItems...)
	return cloned
}

func (env *tufIntegrationEnv) highWater(t *testing.T) TUFHighWaterRegister {
	t.Helper()
	register, exists, err := newTUFHighWaterStore(env.stateDir).Load()
	if err != nil {
		t.Fatalf("load high-water register: %v", err)
	}
	if !exists {
		t.Fatal("high-water register does not exist after a successful activation")
	}
	return register
}

func TestTufFeedBoundaryRejectsPoisonedValidlySignedUpdate(t *testing.T) {
	env := newTufIntegrationEnv(t)

	// Legitimate generation: 3-of-3 source set promoted, epoch 1 committed.
	manifestV1 := env.publishFeedManifest(t, 1)
	env.publishThresholdEnvelope(t, 1, manifestV1, tufRoleContent, tufRoleSnapshot)
	if errs := env.sync(t); len(errs) != 0 {
		t.Fatalf("legitimate sync reported errors: %v", errs)
	}
	status := env.manager.TUFStatus()
	if status.Capability != TUFCapabilityAvailable || status.Epoch != 1 || status.BlockedUpdates != 0 {
		t.Fatalf("post-activation status = %+v", status)
	}
	original := env.feedState(t, "feodo-c2")
	if len(original.LastGoodItems) != 3 || original.ManifestVersion != 1 || original.ManifestAuthenticity != "SIGNED" {
		t.Fatalf("initial feodo-c2 generation = %+v", original)
	}
	register := env.highWater(t)
	if register.Epoch != 1 || register.LastKnownGoodSHA256 == "" {
		t.Fatalf("high-water register after activation = %+v", register)
	}
	if len(env.manager.SnapshotFeedStates()) == 0 {
		t.Fatal("legitimate activation projected no feed states")
	}

	// Poisoned but validly signed evolution: the feed deletes 2 of its 3 active
	// protection entries. Legacy manifest, threshold envelope and epoch are all
	// valid, so only the local semantic guard can stop it.
	var securityEvents []Event
	env.manager.SetTUFEventSink(func(event Event) { securityEvents = append(securityEvents, event) })
	env.transport.setBody(tufIntegrationFeodoURL, []byte("203.0.113.7\n"))
	manifestV2 := env.publishFeedManifest(t, 2)
	env.publishThresholdEnvelope(t, 2, manifestV2, tufRoleContent, tufRoleSnapshot)
	errs := env.sync(t)
	poisonErr, rejected := errs[tufIntegrationFeodoURL]
	if !rejected {
		t.Fatalf("poisoned feed generation was not rejected: %v", errs)
	}
	if reason := tufErrorReason(poisonErr); reason != TUFReasonDiffBudget {
		t.Fatalf("poisoned feed rejection reason = %q (%v), want %q", reason, poisonErr, TUFReasonDiffBudget)
	}
	blocked := env.feedState(t, "feodo-c2")
	if len(blocked.LastGoodItems) != len(original.LastGoodItems) || blocked.ManifestVersion != 1 {
		t.Fatalf("poisoned generation replaced the last-known-good: %+v", blocked)
	}
	if blocked.LastError == "" || blocked.LastGoodGen != original.LastGoodGen {
		t.Fatalf("poisoned feed state not preserved: %+v", blocked)
	}
	register = env.highWater(t)
	if register.Epoch != 1 {
		t.Fatalf("high-water epoch advanced on a rejected generation: %+v", register)
	}
	status = env.manager.TUFStatus()
	if status.BlockedUpdates < 1 || status.LastBlockedReason != TUFReasonDiffBudget {
		t.Fatalf("blocked projection after poisoning = %+v", status)
	}
	blockedEvent := false
	for _, event := range securityEvents {
		if event.Kind == "feed.poisoning_blocked" && event.Target == "feodo-c2" &&
			strings.Contains(event.Message, TUFReasonDiffBudget) {
			blockedEvent = true
		}
	}
	if !blockedEvent {
		t.Fatalf("no bounded poisoning state event was recorded for the rejected feed: %v", securityEvents)
	}
	composed, _, _ := func() ([]string, []string, []string) {
		env.manager.mu.RLock()
		defer env.manager.mu.RUnlock()
		return env.manager.composeGenerationsLocked(env.manager.live.activeSettings())
	}()
	if len(composed) == 0 {
		t.Fatal("previous last-known-good block entries were dropped on rejection")
	}

	// Under-signed evolution (1-of-3) is refused before activation as well.
	manifestV3 := env.publishFeedManifest(t, 3)
	env.publishThresholdEnvelope(t, 3, manifestV3, tufRoleContent)
	errs = env.sync(t)
	if len(errs) != len(env.manager.live.current().sources) {
		t.Fatalf("under-signed envelope did not block every feed: %v", errs)
	}
	for url, err := range errs {
		if reason := tufErrorReason(err); reason != TUFReasonSignatureThreshold {
			t.Fatalf("under-signed rejection for %s = %q (%v)", url, reason, err)
		}
	}
	register = env.highWater(t)
	if register.Epoch != 1 {
		t.Fatalf("high-water epoch advanced after an under-signed generation: %+v", register)
	}
	after := env.feedState(t, "feodo-c2")
	if len(after.LastGoodItems) != len(original.LastGoodItems) {
		t.Fatalf("under-signed generation changed the last-known-good: %+v", after)
	}
	if status = env.manager.TUFStatus(); status.LastBlockedReason != TUFReasonSignatureThreshold {
		t.Fatalf("last blocked reason after under-signed generation = %q", status.LastBlockedReason)
	}
}

func TestTufFeedBoundaryCorruptHighWaterFailsClosed(t *testing.T) {
	env := newTufIntegrationEnv(t)
	manifest := env.publishFeedManifest(t, 1)
	env.publishThresholdEnvelope(t, 1, manifest, tufRoleContent, tufRoleSnapshot)

	// A register/key pair that fails authentication must block activation
	// instead of restarting the epoch at zero.
	if err := os.MkdirAll(env.stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	keyBytes := make([]byte, 32)
	if _, err := rand.Read(keyBytes); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(env.stateDir, tufHighWaterKeyFile), keyBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(env.stateDir, tufHighWaterFile), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	errs := env.sync(t)
	if len(errs) != len(env.manager.live.current().sources) {
		t.Fatalf("corrupt register did not block every feed: %v", errs)
	}
	for _, err := range errs {
		if reason := tufErrorReason(err); reason != TUFReasonStateCorrupt {
			t.Fatalf("corrupt-register rejection reason = %q (%v)", reason, err)
		}
	}
	state := env.feedState(t, "feodo-c2")
	if len(state.LastGoodItems) != 0 || state.ManifestVersion != 0 {
		t.Fatalf("corrupt register still activated a generation: %+v", state)
	}
	if status := env.manager.TUFStatus(); status.StateError == "" {
		t.Fatal("corrupt register was not reported in the status projection")
	}

	// After the operator repairs the register, the same envelope activates.
	if err := os.Remove(filepath.Join(env.stateDir, tufHighWaterFile)); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(env.stateDir, tufHighWaterKeyFile)); err != nil {
		t.Fatal(err)
	}
	if errs := env.sync(t); len(errs) != 0 {
		t.Fatalf("repaired high-water register did not allow activation: %v", errs)
	}
	if register := env.highWater(t); register.Epoch != 1 {
		t.Fatalf("repaired activation register = %+v", register)
	}
}

func TestTufFeedBoundaryCapabilityUnavailableIsHonest(t *testing.T) {
	// The pre-existing single-key local-signing deployment has no role-separated
	// key set. The capability must be reported unavailable, the semantic guard
	// must still run, and the legacy signed-manifest pipeline must be unchanged.
	env := newFeedSigningTestEnv(t, nil)
	status := env.manager.TUFStatus()
	if status.Capability != TUFCapabilityUnavailable || status.Reason == "" {
		t.Fatalf("single-key capability projection = %+v", status)
	}
	if status.R5Isolation != TUFR5IsolationShadow || status.R5HelperIsolation != TUFR5HelperPending {
		t.Fatalf("R5 projection = %+v", status)
	}
	items, errs := env.sync(t)
	if len(errs) != 0 || len(items) == 0 {
		t.Fatalf("legacy signed-manifest pipeline regressed: %v", errs)
	}
	if status := env.manager.TUFStatus(); status.Epoch != 0 {
		t.Fatalf("TUF epoch advanced without a threshold envelope: %+v", status)
	}
}

func TestTufFeedBoundaryEnvelopeSchemaIsBounded(t *testing.T) {
	env := newTufIntegrationEnv(t)
	if !strings.Contains(tufEnvelopeSchema, "vgt-gedefense-tuf-manifest") {
		t.Fatalf("envelope schema token changed: %q", tufEnvelopeSchema)
	}
	// The envelope must live next to feeds.manifest_path (documented contract).
	expected := filepath.Join(filepath.Dir(env.manifestPath), "tuf-feed-manifest.json")
	if got := tufManifestEnvelopePath(env.manifestPath); got != expected {
		t.Fatalf("envelope path = %q, want %q", got, expected)
	}
}
