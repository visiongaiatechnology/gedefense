// STATUS: DIAMANT VGT SUPREME
package main

import (
	"encoding/hex"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func threatIntelFixture(t *testing.T) (*APIServer, *SettingsStore, *FeedManager) {
	t.Helper()
	cfg, state, policy, release := betaReleaseFixture(t)
	cfg.Feeds.Enabled = true
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "runtime.key")
	if err := os.WriteFile(keyPath, make([]byte, 32), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg.Runtime.StorageKeyFile = ""
	settings, err := NewSettingsStore(filepath.Join(dir, "runtime.json"), keyPath, cfg)
	if err != nil {
		t.Fatal(err)
	}
	release.settings = settings
	feeds := NewFeedManager(cfg.Feeds, dir)
	if err := feeds.applyThreatIntelSettings(effectiveThreatIntelSettings(settings.Get()), settings.Get().Revision); err != nil {
		t.Fatal(err)
	}
	server := NewAPIServer(cfg, state, nil, feeds, policy, nil, release, settings, fabricTestToken)
	server.AttachFeeds(feeds)
	return server, settings, feeds
}

func threatIntelPayload(t *testing.T, settings *SettingsStore, mutate func(fabric *ThreatIntelFabricSettings)) []byte {
	t.Helper()
	current := settings.Get()
	fabric := defaultThreatIntelFabricSettings(FeedConfig{}, DefaultThreatFeedSources)
	if current.ThreatIntel != nil {
		fabric = cloneThreatIntelFabricSettings(*current.ThreatIntel)
	}
	fabric.Enabled = current.FeedsEnabled
	fabric.AutoSync = current.AutoFeedSync
	mutate(&fabric)
	payload, err := json.Marshal(map[string]any{"expected_revision": current.Revision, "settings": fabric})
	if err != nil {
		t.Fatal(err)
	}
	return payload
}

func TestFabricThreatIntelHotRevisionReachesLiveFeedManager(t *testing.T) {
	server, settings, feeds := threatIntelFixture(t)

	payload := threatIntelPayload(t, settings, func(fabric *ThreatIntelFabricSettings) {
		fabric.RefreshMinutes = 60
		fabric.ConcurrentDownloads = 6
		fabric.Retry.Attempts = 3
		for index := range fabric.Feeds {
			if fabric.Feeds[index].ID == "cins-badguys" {
				fabric.Feeds[index].Action = "BLOCK"
				fabric.Feeds[index].Priority = 1
			}
		}
	})
	preview := fabricRequest(t, server, http.MethodPost, "/api/v1/settings/threat_intel/preview", payload)
	if preview.Code != http.StatusOK {
		t.Fatalf("preview status=%d body=%s", preview.Code, preview.Body.String())
	}
	var parsed FabricSettingsPreview
	if err := json.Unmarshal(preview.Body.Bytes(), &parsed); err != nil {
		t.Fatal(err)
	}
	if !parsed.Valid || parsed.RequiresRestart {
		t.Fatalf("hot revision flagged unexpectedly: %+v", parsed)
	}

	apply := fabricRequest(t, server, http.MethodPut, "/api/v1/settings/threat_intel", payload)
	if apply.Code != http.StatusOK {
		t.Fatalf("apply status=%d body=%s", apply.Code, apply.Body.String())
	}
	view := decodeFabricView(t, apply.Body.Bytes())
	if view.ApplyState != "applied" {
		t.Fatalf("hot revision reported apply state %q", view.ApplyState)
	}

	live := feeds.LiveSettings()
	if live.RefreshMinutes != 60 || live.ConcurrentDownloads != 6 || live.Retry.Attempts != 3 {
		t.Fatalf("live manager did not adopt the revision: %+v", live)
	}

	// A feed whose action changed must be reclassified immediately, not on the
	// next download.
	feeds.mu.Lock()
	feeds.feedStates["cins-badguys"].LastGoodItems = []string{"203.0.113.50/32"}
	feeds.feedStates["cins-badguys"].LastGoodCount = 1
	feeds.mu.Unlock()
	block, _, _ := feeds.composeGenerationsLocked(feeds.LiveSettings())
	if !containsString(block, "203.0.113.50/32") {
		t.Fatalf("action change did not reach the block generation: %v", block)
	}
}

func TestFabricThreatIntelRejectsUnsafeConfiguration(t *testing.T) {
	server, settings, _ := threatIntelFixture(t)
	cases := []struct {
		name   string
		mutate func(fabric *ThreatIntelFabricSettings)
	}{
		{"plaintext feed url", func(fabric *ThreatIntelFabricSettings) { fabric.Feeds[0].URL = "http://feeds.example.test/list.txt" }},
		{"non standard port", func(fabric *ThreatIntelFabricSettings) {
			fabric.Feeds[0].URL = "https://feeds.example.test:8443/list.txt"
		}},
		{"loopback feed host", func(fabric *ThreatIntelFabricSettings) { fabric.Feeds[0].URL = "https://127.0.0.1/list.txt" }},
		{"duplicate feed id", func(fabric *ThreatIntelFabricSettings) { fabric.Feeds[1].ID = fabric.Feeds[0].ID }},
		{"duplicate feed url", func(fabric *ThreatIntelFabricSettings) { fabric.Feeds[1].URL = fabric.Feeds[0].URL }},
		{"invalid feed id", func(fabric *ThreatIntelFabricSettings) { fabric.Feeds[0].ID = "feed id with spaces" }},
		{"unknown action", func(fabric *ThreatIntelFabricSettings) { fabric.Feeds[0].Action = "DROP" }},
		{"unknown format", func(fabric *ThreatIntelFabricSettings) { fabric.Feeds[0].Format = "csv" }},
		{"both families disabled", func(fabric *ThreatIntelFabricSettings) {
			fabric.Validation.IPv4Enabled = false
			fabric.Validation.IPv6Enabled = false
		}},
		{"ambiguous generation policy", func(fabric *ThreatIntelFabricSettings) { fabric.Validation.GenerationPolicy = "sometimes" }},
		{"auto sync without enablement", func(fabric *ThreatIntelFabricSettings) { fabric.Enabled = false; fabric.AutoSync = true }},
		{"stale critical below warning", func(fabric *ThreatIntelFabricSettings) {
			fabric.StaleWarningMinutes = 600
			fabric.StaleCriticalMinutes = 60
		}},
		{"refresh interval below floor", func(fabric *ThreatIntelFabricSettings) { fabric.RefreshMinutes = 1 }},
		{"concurrency above ceiling", func(fabric *ThreatIntelFabricSettings) { fabric.ConcurrentDownloads = 64 }},
		{"content type policy required but empty", func(fabric *ThreatIntelFabricSettings) {
			fabric.Transport.RequireContentType = true
			fabric.Transport.AllowedContentTypes = nil
		}},
		{"host allowlist entry carries a scheme", func(fabric *ThreatIntelFabricSettings) {
			fabric.Transport.AllowedHosts = []string{"https://feeds.example.test"}
		}},
		{"retry attempts above ceiling", func(fabric *ThreatIntelFabricSettings) { fabric.Retry.Attempts = 12 }},
		{"feed list emptied while enabled", func(fabric *ThreatIntelFabricSettings) { fabric.Feeds = nil }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			payload := threatIntelPayload(t, settings, tc.mutate)
			rec := fabricRequest(t, server, http.MethodPost, "/api/v1/settings/threat_intel/preview", payload)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("unsafe configuration accepted: %d %s", rec.Code, rec.Body.String())
			}
			if settings.Get().Revision != 1 {
				t.Fatal("rejected preview mutated runtime settings")
			}
		})
	}
}

func TestFabricThreatIntelCompositionIsDeterministicAndPriorityOrdered(t *testing.T) {
	_, settings, feeds := threatIntelFixture(t)
	fabric := effectiveThreatIntelSettings(settings.Get())
	fabric.Enabled = true
	fabric.MaxTotalEntries = 1
	fabric.Feeds = []ThreatFeedSourceSettings{
		{ID: "low-trust", Name: "Low trust", Enabled: true, URL: "https://low.example.test/list.txt", Format: "lines", Action: "BLOCK", Priority: 20, TrustWeight: 10},
		{ID: "high-trust", Name: "High trust", Enabled: true, URL: "https://high.example.test/list.txt", Format: "lines", Action: "BLOCK", Priority: 10, TrustWeight: 900},
	}
	if err := feeds.applyThreatIntelSettings(fabric, 2); err != nil {
		t.Fatal(err)
	}
	feeds.mu.Lock()
	feeds.feedStates["low-trust"] = &FeedGenerationState{ID: "low-trust", Action: FeedActionBlock, LastGoodItems: []string{"198.51.100.1/32"}}
	feeds.feedStates["high-trust"] = &FeedGenerationState{ID: "high-trust", Action: FeedActionBlock, LastGoodItems: []string{"203.0.113.1/32"}}
	feeds.mu.Unlock()

	for attempt := 0; attempt < 24; attempt++ {
		block, _, _ := feeds.composeGenerationsLocked(feeds.LiveSettings())
		if len(block) != 1 || block[0] != "203.0.113.1/32" {
			t.Fatalf("priority order or global budget not honoured on attempt %d: %v", attempt, block)
		}
	}

	// Trust weight breaks a priority tie.
	fabric.Feeds[0].Priority = 10
	if err := feeds.applyThreatIntelSettings(fabric, 3); err != nil {
		t.Fatal(err)
	}
	block, _, _ := feeds.composeGenerationsLocked(feeds.LiveSettings())
	if len(block) != 1 || block[0] != "203.0.113.1/32" {
		t.Fatalf("trust weight did not break the priority tie: %v", block)
	}
}

func TestThreatIntelValidationPolicyRejectsCorruptDownloads(t *testing.T) {
	policy := ThreatIntelValidationSettings{IPv4Enabled: true, IPv6Enabled: true, MalformedEntryPermille: 250, GenerationPolicy: "bump"}

	// A feed that is mostly garbage must be refused so the active generation is
	// preserved.
	stats := threatFeedStats{}
	set := map[string]struct{}{}
	for _, line := range []string{"203.0.113.1", "not-an-address", "' OR 1=1 --", "\x00\x01", "198.51.100.7"} {
		value, kind := classifyThreatLine(line, policy)
		switch kind {
		case threatLineAccepted:
			stats.Candidates++
			stats.Accepted++
			set[value] = struct{}{}
		case threatLineMalformed:
			stats.Candidates++
			stats.Malformed++
		}
	}
	if _, err := finalizeThreatFeed(set, stats, policy); err == nil {
		t.Fatal("a corrupt download was accepted despite the malformed entry limit")
	}

	// A clean feed passes and is deduplicated.
	stats = threatFeedStats{}
	set = map[string]struct{}{}
	for _, line := range []string{"203.0.113.1", "# comment", "", "203.0.113.1", "198.51.100.7"} {
		if value, kind := classifyThreatLine(line, policy); kind == threatLineAccepted {
			stats.Candidates++
			stats.Accepted++
			set[value] = struct{}{}
		}
	}
	items, err := finalizeThreatFeed(set, stats, policy)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 2 {
		t.Fatalf("clean feed items=%v", items)
	}

	// Address-family filtering is not counted as corruption.
	ipv4Only := policy
	ipv4Only.IPv6Enabled = false
	if _, kind := classifyThreatLine("2001:db8::1", ipv4Only); kind != threatLineFiltered {
		t.Fatalf("IPv6 entry was not filtered when the family is disabled: %v", kind)
	}
	bothOff := policy
	bothOff.IPv4Enabled = false
	bothOff.IPv6Enabled = false
	if _, kind := classifyThreatLine("203.0.113.9", bothOff); kind != threatLineFiltered {
		t.Fatalf("IPv4 entry survived with both families disabled: %v", kind)
	}

	// The anti-poisoning filter remains unconditional regardless of policy.
	if _, kind := classifyThreatLine("127.0.0.1", policy); kind != threatLineMalformed {
		t.Fatal("loopback indicator was accepted despite the unconditional anti-poisoning filter")
	}
	if _, kind := classifyThreatLine("169.254.169.254", policy); kind != threatLineMalformed {
		t.Fatal("cloud metadata address was accepted despite the unconditional anti-poisoning filter")
	}
}

func TestThreatIntelRetryClassificationAndTransportPolicy(t *testing.T) {
	if threatFeedRetryable(nil) {
		t.Fatal("a successful attempt was classified as retryable")
	}
	if !threatFeedRetryable(newFeedTransientError("feed request failed", nil)) {
		t.Fatal("a network fault was not classified as retryable")
	}
	if threatFeedRetryable(NewThreatIntelSecurityException("feed host resolved to a forbidden network", nil)) {
		t.Fatal("a security rejection must never be retried")
	}
	if threatFeedRetryable(NewThreatIntelValidationException("feed returned HTTP 404", nil)) {
		t.Fatal("a deterministic HTTP rejection must never be retried")
	}

	fabric := defaultThreatIntelFabricSettings(FeedConfig{}, DefaultThreatFeedSources)
	fabric.Transport.AllowedHosts = []string{"feeds.example.test"}
	fabric.Transport.RequireContentType = true
	fabric.Transport.AllowedContentTypes = []string{"text/plain", "application/json"}
	snapshot := buildThreatIntelSnapshot(fabric, 1)

	if !snapshot.hostAllowed("feeds.example.test") {
		t.Fatal("allowlisted host was rejected")
	}
	if snapshot.hostAllowed("evil.example.test") {
		t.Fatal("host outside the allowlist was accepted")
	}
	if !snapshot.contentAllowed("text/plain; charset=utf-8") {
		t.Fatal("text/plain with parameters was rejected")
	}
	if snapshot.contentAllowed("text/html") {
		t.Fatal("content type outside the policy was accepted")
	}
	if snapshot.contentAllowed("") {
		t.Fatal("missing content type was accepted while the policy requires it")
	}
	empty := buildThreatIntelSnapshot(defaultThreatIntelFabricSettings(FeedConfig{}, DefaultThreatFeedSources), 0)
	if !empty.hostAllowed("anything.example.test") {
		t.Fatal("an empty host allowlist must mean any public host")
	}
	if !empty.contentAllowed("") {
		t.Fatal("a missing content type must be tolerated when the policy does not require it")
	}
}

func TestThreatIntelGenerationPolicyKeepsIdenticalDownloadsStable(t *testing.T) {
	items := []string{"203.0.113.1/32", "203.0.113.2/32"}
	digest := computeFingerprint(items)
	state := &FeedGenerationState{ID: "feodo-c2", Action: FeedActionBlock, LastGoodItems: items, LastGoodGen: 1, LastGoodFingerprint: digest}

	stable := ThreatIntelValidationSettings{IPv4Enabled: true, IPv6Enabled: true, GenerationPolicy: "stable"}
	if shouldAdvanceGeneration(state, digest, stable) {
		t.Fatal("identical re-download advanced the generation under the stable policy")
	}
	if !shouldAdvanceGeneration(state, computeFingerprint([]string{"203.0.113.9/32"}), stable) {
		t.Fatal("changed content did not advance the generation under the stable policy")
	}
	fresh := &FeedGenerationState{ID: "feodo-c2", Action: FeedActionBlock, LastGoodFingerprint: digest}
	if !shouldAdvanceGeneration(fresh, digest, stable) {
		t.Fatal("a first download must always establish a generation")
	}

	bump := ThreatIntelValidationSettings{IPv4Enabled: true, IPv6Enabled: true, GenerationPolicy: "bump"}
	if !shouldAdvanceGeneration(state, digest, bump) {
		t.Fatal("identical re-download did not advance the generation under the bump policy")
	}
	if !shouldAdvanceGeneration(nil, digest, bump) {
		t.Fatal("a missing generation state must advance")
	}
}

func TestThreatIntelKernelDiffBudgetRefusesOversizedDiff(t *testing.T) {
	_, settings, feeds := threatIntelFixture(t)
	fabric := effectiveThreatIntelSettings(settings.Get())
	fabric.Enabled = true
	fabric.Kernel.MaximumDiffPerSync = 1
	if err := feeds.applyThreatIntelSettings(fabric, 2); err != nil {
		t.Fatal(err)
	}
	feeds.mu.Lock()
	feeds.feedStates["feodo-c2"].LastGoodItems = []string{"203.0.113.1/32", "203.0.113.2/32", "203.0.113.3/32"}
	feeds.feedStates["feodo-c2"].LastGoodCount = 3
	feeds.mu.Unlock()

	if _, _, err := feeds.ApplyToKernel(nil, nil); err == nil {
		t.Fatal("a kernel diff above the configured budget was applied")
	}
	if feeds.Generation() != 0 {
		t.Fatalf("generation advanced despite a refused diff: %d", feeds.Generation())
	}
	if status, _, _, _ := feeds.KernelApplyStatus(); status != kernelApplyError {
		t.Fatalf("refused diff reported kernel status %q", status)
	}

	fabric.Kernel.MaximumDiffPerSync = 0
	if err := feeds.applyThreatIntelSettings(fabric, 3); err != nil {
		t.Fatal(err)
	}
	if _, _, err := feeds.ApplyToKernel(nil, nil); err != nil {
		t.Fatalf("diff within the disabled budget was refused: %v", err)
	}
}

// TestThreatIntelDocumentWithoutNamespaceStillAuthenticates guards the
// migration path for a settings document written before the Threat
// Intelligence namespace existed.
func TestThreatIntelDocumentWithoutNamespaceStillAuthenticates(t *testing.T) {
	cfg := defaultConfig()
	cfg.Feeds.Enabled = true
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "runtime.key")
	if err := os.WriteFile(keyPath, make([]byte, 32), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg.Runtime.StorageKeyFile = ""
	path := filepath.Join(dir, "runtime.json")
	seeded, err := NewSettingsStore(path, keyPath, cfg)
	if err != nil {
		t.Fatal(err)
	}

	legacy := seeded.Get()
	legacy.FabricVersion = 3
	legacy.ThreatIntel = nil
	legacy.FeedsEnabled = true
	legacy.AutoFeedSync = true
	legacy.Kinetic.VelocityLimit = 777
	mac, err := seeded.mac(legacy)
	if err != nil {
		t.Fatal(err)
	}
	document := runtimeSettingsEnvelope{Schema: runtimeSettingsSchema, Settings: legacy, MAC: hex.EncodeToString(mac)}
	data, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(data, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}

	reloaded, err := NewSettingsStore(path, keyPath, cfg)
	if err != nil {
		t.Fatalf("a pre-Threat-Intelligence settings document was rejected: %v", err)
	}
	upgraded := reloaded.Get()
	if upgraded.FabricVersion != fabricSettingsVersion {
		t.Fatalf("schema version not upgraded: %d", upgraded.FabricVersion)
	}
	if upgraded.ThreatIntel == nil {
		t.Fatal("Threat Intelligence namespace was not seeded during the upgrade")
	}
	if !upgraded.ThreatIntel.Enabled || !upgraded.ThreatIntel.AutoSync {
		t.Fatalf("existing operator enablement was not preserved: %+v", upgraded.ThreatIntel)
	}
	if upgraded.Kinetic.VelocityLimit != 777 {
		t.Fatal("existing operator tuning was lost during the upgrade")
	}
	if len(upgraded.ThreatIntel.Feeds) != len(DefaultThreatFeedSources) {
		t.Fatalf("feed catalogue was not seeded: %d sources", len(upgraded.ThreatIntel.Feeds))
	}
}

func TestFabricThreatIntelSchemaRegistryCoversEveryAdvertisedKey(t *testing.T) {
	server, settings, _ := threatIntelFixture(t)
	rec := fabricRequest(t, server, http.MethodGet, "/api/v1/settings/schema", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("schema status=%d body=%s", rec.Code, rec.Body.String())
	}
	var schema struct {
		Modules  []string                `json:"modules"`
		Settings []FabricSettingMetadata `json:"settings"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &schema); err != nil {
		t.Fatal(err)
	}
	if !containsString(schema.Modules, "threat_intel") {
		t.Fatalf("schema does not advertise the Threat Intelligence module: %v", schema.Modules)
	}
	registered := map[string]FabricSettingMetadata{}
	for _, meta := range schema.Settings {
		if meta.Module == "threat_intel" {
			registered[meta.Key] = meta
		}
	}
	if len(registered) == 0 {
		t.Fatal("schema carries no Threat Intelligence settings")
	}

	payload, err := json.Marshal(effectiveThreatIntelSettings(settings.Get()))
	if err != nil {
		t.Fatal(err)
	}
	var flat map[string]any
	if err := json.Unmarshal(payload, &flat); err != nil {
		t.Fatal(err)
	}
	// The snapshot mixes two shapes: most threat intelligence bounds are flat keys,
	// while transport, validation and retry are nested objects. The schema reflects
	// that - flat keys are registered verbatim, nested ones as "group.leaf". The walk
	// therefore handles both, and the earlier version handled neither correctly: it
	// compared top-level keys against schema keys, which could not hold for the
	// nested namespaces. It was only ever compiled, never run.
	checked := 0
	for key, raw := range flat {
		if key == "feeds" {
			// Feed definitions are a list of records, not a settings namespace.
			continue
		}
		nested, isObject := raw.(map[string]any)
		if !isObject {
			if _, ok := registered[key]; !ok {
				t.Fatalf("administrable key %q has no schema metadata", key)
			}
			checked++
			continue
		}
		if len(nested) == 0 {
			t.Fatalf("namespace %q is empty in the module snapshot", key)
		}
		for leaf := range nested {
			documented := key + "." + leaf
			if _, ok := registered[documented]; !ok {
				t.Fatalf("administrable key %q has no schema metadata", documented)
			}
			checked++
		}
	}
	if checked == 0 {
		t.Fatal("no threat intelligence setting was walked; the assertion is vacuous")
	}
}

func TestThreatIntelFeedStatusIsTimeAware(t *testing.T) {
	settings := defaultThreatIntelFabricSettings(FeedConfig{}, DefaultThreatFeedSources)
	settings.StaleWarningMinutes = 60
	settings.StaleCriticalMinutes = 120
	now := time.Now().UTC()
	state := &FeedGenerationState{ID: "feeds", LastAttemptAt: now, LastGoodAt: now, LastGoodGen: 1}
	if got := computeFeedStatus(state, settings); got != "OK" {
		t.Fatalf("fresh feed reported %q", got)
	}
	state.LastGoodAt = now.Add(-90 * time.Minute)
	if got := computeFeedStatus(state, settings); got != "STALE" {
		t.Fatalf("aged feed reported %q", got)
	}
	state.LastGoodAt = now.Add(-180 * time.Minute)
	if got := computeFeedStatus(state, settings); got != "CRITICAL" {
		t.Fatalf("very old feed reported %q", got)
	}
	if got := computeFeedStatus(nil, settings); got != "NEVER_SYNCED" {
		t.Fatalf("unknown feed reported %q", got)
	}
}

func TestThreatIntelApplyEndpointPublishesStagedGeneration(t *testing.T) {
	server, settings, feeds := threatIntelFixture(t)
	fabric := effectiveThreatIntelSettings(settings.Get())
	fabric.Enabled = true
	fabric.Kernel.AutoApply = false
	if err := feeds.applyThreatIntelSettings(fabric, 2); err != nil {
		t.Fatal(err)
	}
	feeds.mu.Lock()
	feeds.feedStates["feodo-c2"].LastGoodItems = []string{"203.0.113.11/32"}
	feeds.feedStates["feodo-c2"].LastGoodCount = 1
	feeds.mu.Unlock()

	rec := fabricRequest(t, server, http.MethodPost, "/api/v1/feeds/apply", []byte("{}"))
	if rec.Code != http.StatusOK {
		t.Fatalf("explicit publication failed: %d %s", rec.Code, rec.Body.String())
	}
	if feeds.Generation() != 1 {
		t.Fatalf("explicit publication did not publish a generation: %d", feeds.Generation())
	}
	if !strings.Contains(rec.Body.String(), "kernel_apply_status") {
		t.Fatalf("publication response lacks the kernel status: %s", rec.Body.String())
	}
}
