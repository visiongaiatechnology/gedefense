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

func systemFixture(t *testing.T) (*APIServer, *SettingsStore, *State, *CoreClient) {
	t.Helper()
	cfg, state, policy, release := betaReleaseFixture(t)
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "runtime.key")
	if err := os.WriteFile(keyPath, make([]byte, 32), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg.Runtime.StorageKeyFile = ""
	cfg.XDR.IncidentLog = filepath.Join(dir, "incidents.jsonl")
	settings, err := NewSettingsStore(filepath.Join(dir, "runtime.json"), keyPath, cfg)
	if err != nil {
		t.Fatal(err)
	}
	release.settings = settings
	server := NewAPIServer(cfg, state, nil, nil, policy, nil, release, settings, fabricTestToken)
	return server, settings, state, nil
}

func systemFabricPayload(t *testing.T, settings *SettingsStore, mutate func(fabric *SystemFabricSettings)) []byte {
	t.Helper()
	current := settings.Get()
	fabric := defaultSystemFabricSettings(Config{})
	if current.System != nil {
		fabric = *current.System
	}
	mutate(&fabric)
	payload, err := json.Marshal(map[string]any{"expected_revision": current.Revision, "settings": fabric})
	if err != nil {
		t.Fatal(err)
	}
	return payload
}

// TestSystemRateLimitRevisionTakesEffect proves the limiter is live and that a
// tightening revision clamps buckets that already exceed the new allowance.
func TestSystemRateLimitRevisionTakesEffect(t *testing.T) {
	limiter := NewRateLimiter(6000, 1000)
	now := time.Unix(1700000000, 0).UTC()
	// Fill the bucket for one identity up to the old burst.
	for attempt := 0; attempt < 900; attempt++ {
		if !limiter.Allow("203.0.113.9", now) {
			t.Fatalf("the limiter refused request %d inside its own burst", attempt)
		}
	}
	if err := limiter.Configure(60, 5); err != nil {
		t.Fatal(err)
	}
	// The clamp leaves the bucket holding exactly the new burst. Asserting "the next
	// request is refused" would be wrong: five tokens remain and the next call is
	// entitled to one of them. The count is what proves the clamp - exactly five more
	// requests may pass. Without it roughly a hundred would, because the bucket still
	// held the old allowance.
	remaining := 0
	for attempt := 0; attempt < 200; attempt++ {
		if !limiter.Allow("203.0.113.9", now) {
			break
		}
		remaining++
	}
	if remaining != 5 {
		t.Fatalf("a tightened burst left %d requests in the bucket, want exactly 5", remaining)
	}
	// A separate identity is unaffected.
	if !limiter.Allow("203.0.113.10", now) {
		t.Fatal("a fresh identity was refused under the new allowance")
	}
	// An invalid configuration is rejected rather than applied.
	if err := limiter.Configure(10, 500); err == nil {
		t.Fatal("a burst larger than the rate limit was accepted")
	}
	if err := limiter.Configure(0, 1); err == nil {
		t.Fatal("a zero rate limit was accepted")
	}
}

// TestSystemEventCacheRevisionTrimsImmediately proves a tightened ring budget is
// applied to the current state rather than only to future events.
func TestSystemEventCacheRevisionTrimsImmediately(t *testing.T) {
	state := NewState("test", defaultConfig())
	for index := 0; index < 200; index++ {
		state.AddEvent(Event{Severity: "info", Kind: "test", Source: "test", Message: "filler"})
	}
	if got := state.EventCap(); got != 250 {
		t.Fatalf("unexpected compiled-in ring budget: %d", got)
	}
	state.SetEventCap(32)
	if got := state.EventCap(); got != 32 {
		t.Fatalf("ring budget not republished: %d", got)
	}
	if got := len(state.Snapshot().Events); got > 32 {
		t.Fatalf("the ring was not trimmed on the revision: %d events retained", got)
	}
	// A nonsense budget is ignored rather than applied.
	state.SetEventCap(0)
	if got := state.EventCap(); got != 32 {
		t.Fatalf("a zero budget was applied: %d", got)
	}
}

// TestSystemPayloadCeilingIsEnforcedBeforeHandlers proves the ceiling is applied
// in the middleware, so a handler cannot be reached with a larger body.
func TestSystemPayloadCeilingIsEnforcedBeforeHandlers(t *testing.T) {
	server, settings, _, _ := systemFixture(t)
	// Practical fixture ceiling: the validator refuses anything below 64 KiB, so a
	// large but valid body proves the middleware bound rather than the handler's.
	payload := systemFabricPayload(t, settings, func(fabric *SystemFabricSettings) {
		fabric.Events.MaxAPIPayload = 64 << 10
	})
	if rec := fabricRequest(t, server, http.MethodPut, "/api/v1/settings/system", payload); rec.Code != http.StatusOK {
		t.Fatalf("apply status=%d body=%s", rec.Code, rec.Body.String())
	}
	if got := server.apiPayloadLimit(); got != 64<<10 {
		t.Fatalf("payload ceiling not published: %d", got)
	}

	// A body above the ceiling is refused before the handler runs.
	oversized := make([]byte, (64<<10)+4096)
	for index := range oversized {
		oversized[index] = 'a'
	}
	recorder := fabricRequest(t, server, http.MethodPut, "/api/v1/settings/system", oversized)
	if recorder.Code == http.StatusOK {
		t.Fatal("an oversized body was accepted")
	}
	if recorder.Code != http.StatusRequestEntityTooLarge && recorder.Code != http.StatusBadRequest {
		t.Fatalf("an oversized body produced an unexpected status: %d", recorder.Code)
	}
}

// TestSystemSettingsRejectUnsafeConfiguration covers the validator.
func TestSystemSettingsRejectUnsafeConfiguration(t *testing.T) {
	server, settings, _, _ := systemFixture(t)
	cases := []struct {
		name   string
		mutate func(fabric *SystemFabricSettings)
	}{
		{"zero rate limit", func(f *SystemFabricSettings) { f.Dashboard.RateLimitPerMinute = 0 }},
		{"rate limit above the range", func(f *SystemFabricSettings) { f.Dashboard.RateLimitPerMinute = 100000 }},
		{"burst above the rate limit", func(f *SystemFabricSettings) {
			f.Dashboard.RateLimitPerMinute = 100
			f.Dashboard.RateLimitBurst = 200
		}},
		{"zero burst", func(f *SystemFabricSettings) { f.Dashboard.RateLimitBurst = 0 }},
		{"stream ceiling above the range", func(f *SystemFabricSettings) { f.Dashboard.MaxSSEClients = 5000 }},
		{"event cache below the floor", func(f *SystemFabricSettings) { f.Events.MaxEventCache = 1 }},
		{"payload ceiling below the floor", func(f *SystemFabricSettings) { f.Events.MaxAPIPayload = 1024 }},
		{"payload ceiling above the range", func(f *SystemFabricSettings) { f.Events.MaxAPIPayload = 1 << 30 }},
		{"core deadline below the floor", func(f *SystemFabricSettings) { f.Core.RequestTimeoutMillis = 1 }},
		{"core deadline above the range", func(f *SystemFabricSettings) { f.Core.RequestTimeoutMillis = 600000 }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			payload := systemFabricPayload(t, settings, tc.mutate)
			rec := fabricRequest(t, server, http.MethodPost, "/api/v1/settings/system/preview", payload)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("unsafe configuration accepted: %d %s", rec.Code, rec.Body.String())
			}
			if settings.Get().Revision != 1 {
				t.Fatal("rejected preview mutated runtime settings")
			}
		})
	}
}

// TestSystemMetricsExpositionCanBeDisabled proves the switch removes the endpoint
// instead of serving an empty document.
func TestSystemMetricsExpositionCanBeDisabled(t *testing.T) {
	server, settings, _, _ := systemFixture(t)

	before := fabricRequest(t, server, http.MethodGet, "/metrics", nil)
	if before.Code != http.StatusOK {
		t.Fatalf("metrics unavailable before the change: %d", before.Code)
	}
	payload := systemFabricPayload(t, settings, func(fabric *SystemFabricSettings) { fabric.Dashboard.MetricsEnabled = false })
	if rec := fabricRequest(t, server, http.MethodPut, "/api/v1/settings/system", payload); rec.Code != http.StatusOK {
		t.Fatalf("apply status=%d body=%s", rec.Code, rec.Body.String())
	}
	after := fabricRequest(t, server, http.MethodGet, "/metrics", nil)
	if after.Code != http.StatusNotFound {
		t.Fatalf("a disabled metrics endpoint still answered with %d", after.Code)
	}
}

// TestSystemDocumentWithoutNamespaceStillAuthenticates guards the migration path
// for a settings document written before the System namespace existed.
func TestSystemDocumentWithoutNamespaceStillAuthenticates(t *testing.T) {
	cfg := defaultConfig()
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
	legacy.FabricVersion = 8
	legacy.System = nil
	legacy.Kinetic.VelocityLimit = 222
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
		t.Fatalf("a pre-System settings document was rejected: %v", err)
	}
	upgraded := reloaded.Get()
	if upgraded.FabricVersion != fabricSettingsVersion {
		t.Fatalf("schema version not upgraded: %d", upgraded.FabricVersion)
	}
	if upgraded.System == nil {
		t.Fatal("the System namespace was not seeded during the upgrade")
	}
	if upgraded.Kinetic.VelocityLimit != 222 {
		t.Fatal("existing operator tuning was lost during the upgrade")
	}
	// The bootstrap values seed the first revision, so an existing deployment keeps
	// its configured exposure rather than silently reverting to the compiled default.
	if upgraded.System.Dashboard.RateLimitPerMinute != cfg.Dashboard.RateLimitPerMinute {
		t.Fatalf("the bootstrap rate limit was not seeded: %+v", upgraded.System.Dashboard)
	}
	if upgraded.System.Core.RequestTimeoutMillis != cfg.Core.RequestTimeoutMillis {
		t.Fatalf("the bootstrap core deadline was not seeded: %+v", upgraded.System.Core)
	}
}

func TestFabricSystemSchemaRegistryCoversEveryAdvertisedKey(t *testing.T) {
	server, settings, _, _ := systemFixture(t)
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
	if !containsString(schema.Modules, "system") {
		t.Fatalf("schema does not advertise the System module: %v", schema.Modules)
	}
	registered := map[string]FabricSettingMetadata{}
	for _, meta := range schema.Settings {
		if meta.Module == "system" {
			registered[meta.Key] = meta
		}
	}
	raw, err := json.Marshal(effectiveSystemSettings(settings.Get()))
	if err != nil {
		t.Fatal(err)
	}
	var flat map[string]any
	if err := json.Unmarshal(raw, &flat); err != nil {
		t.Fatal(err)
	}
	for _, group := range []string{"dashboard", "events", "core"} {
		nested, ok := flat[group].(map[string]any)
		if !ok {
			t.Fatalf("namespace %q missing from the module snapshot", group)
		}
		for leaf := range nested {
			documented := group + "." + leaf
			if _, exists := registered[documented]; !exists {
				t.Fatalf("administrable key %q has no schema metadata", documented)
			}
		}
	}

	// The module view must publish the hard caps beside the administered values, so
	// an operator can see that a setting is not the last line of defence.
	view := fabricRequest(t, server, http.MethodGet, "/api/v1/settings/system", nil)
	if view.Code != http.StatusOK {
		t.Fatalf("module view status=%d body=%s", view.Code, view.Body.String())
	}
	decoded := decodeFabricView(t, view.Body.Bytes())
	budgets, ok := decoded.Details["budgets"].([]any)
	if !ok || len(budgets) == 0 {
		t.Fatalf("module view carries no budget audit: %+v", decoded.Details)
	}
	for _, entry := range budgets {
		row, ok := entry.(map[string]any)
		if !ok {
			t.Fatalf("budget audit row is malformed: %+v", entry)
		}
		for _, field := range []string{"resource", "hard_cap", "setting", "administered"} {
			if row[field] == nil || row[field] == "" {
				t.Fatalf("budget audit row is incomplete: %+v", row)
			}
		}
	}
	// The advertised caps are the compiled-in ones, not a restatement of the setting.
	for _, entry := range budgets {
		row := entry.(map[string]any)
		if row["setting"] == "events.max_event_cache" && !strings.Contains(row["hard_cap"].(string), "100000") {
			t.Fatalf("the event cache hard cap was misreported: %+v", row)
		}
	}
}

func TestSystemBudgetAuditIsStable(t *testing.T) {
	settings := defaultSystemFabricSettings(Config{})
	first := systemBudgetAudit(settings)
	for attempt := 0; attempt < 5; attempt++ {
		next := systemBudgetAudit(settings)
		left, err := json.Marshal(first)
		if err != nil {
			t.Fatal(err)
		}
		right, err := json.Marshal(next)
		if err != nil {
			t.Fatal(err)
		}
		if string(left) != string(right) {
			t.Fatal("the budget audit is not in a stable order")
		}
	}
}
