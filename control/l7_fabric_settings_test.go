// STATUS: DIAMANT VGT SUPREME
package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// l7FabricFixture builds a control plane whose Application Defense engine is
// already attached, so the Fabric module can be exercised end to end: persisted
// revision -> preview -> apply -> live engine.
func l7FabricFixture(t *testing.T) (*APIServer, *SettingsStore, *ReleaseController, *L7Engine) {
	t.Helper()
	cfg, state, policy, release := betaReleaseFixture(t)
	cfg.L7.Enabled = true
	cfg.L7.Mode = "observe"
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
	server := NewAPIServer(cfg, state, nil, nil, policy, nil, release, settings, fabricTestToken)
	engine, err := NewL7Engine(cfg.L7, nil, release)
	if err != nil {
		t.Fatal(err)
	}
	server.AttachL7(engine)
	return server, settings, release, engine
}

func l7MutationPayload(t *testing.T, settings *SettingsStore, mutate func(fabric *L7FabricSettings)) []byte {
	t.Helper()
	current := settings.Get()
	if current.L7 == nil {
		t.Fatal("fixture has no Application Defense namespace")
	}
	fabric := cloneL7FabricSettings(*current.L7)
	mutate(&fabric)
	payload, err := json.Marshal(map[string]any{"expected_revision": current.Revision, "settings": fabric})
	if err != nil {
		t.Fatal(err)
	}
	return payload
}

func decodeFabricView(t *testing.T, body []byte) FabricModuleView {
	t.Helper()
	var view FabricModuleView
	if err := json.Unmarshal(body, &view); err != nil {
		t.Fatalf("decode module view: %v (%s)", err, body)
	}
	return view
}

func TestFabricL7HotRevisionReachesLiveSnapshot(t *testing.T) {
	server, settings, _, engine := l7FabricFixture(t)

	payload := l7MutationPayload(t, settings, func(fabric *L7FabricSettings) {
		fabric.AlertScore = 55
		fabric.MaxURIBytes = 4096
		fabric.SensitivePaths = append(fabric.SensitivePaths, "/admin/secret")
	})
	preview := fabricRequest(t, server, http.MethodPost, "/api/v1/settings/l7/preview", payload)
	if preview.Code != http.StatusOK {
		t.Fatalf("preview status=%d body=%s", preview.Code, preview.Body.String())
	}
	var parsed FabricSettingsPreview
	if err := json.Unmarshal(preview.Body.Bytes(), &parsed); err != nil {
		t.Fatal(err)
	}
	if !parsed.Valid || parsed.RequiresRestart {
		t.Fatalf("hot revision flagged as restart class: %+v", parsed)
	}
	classes := map[string]string{}
	for _, diff := range parsed.Diff {
		classes[diff.Key] = diff.ApplyClass
	}
	if classes["alert_score"] != FabricApplyHot || classes["max_uri_bytes"] != FabricApplyHot || classes["sensitive_paths"] != FabricApplyHot {
		t.Fatalf("hot keys misclassified: %+v", classes)
	}

	apply := fabricRequest(t, server, http.MethodPut, "/api/v1/settings/l7", payload)
	if apply.Code != http.StatusOK {
		t.Fatalf("apply status=%d body=%s", apply.Code, apply.Body.String())
	}
	view := decodeFabricView(t, apply.Body.Bytes())
	if view.ApplyState != "applied" {
		t.Fatalf("hot revision reported apply state %q", view.ApplyState)
	}
	live := engine.live.config()
	if live.AlertScore != 55 || live.MaxURIBytes != 4096 {
		t.Fatalf("live snapshot did not adopt the revision: alert=%d uri=%d", live.AlertScore, live.MaxURIBytes)
	}
	if !engine.live.current().sensitivePath("/admin/secret/token") {
		t.Fatal("newly configured sensitive path is not enforced live")
	}

	// The reduced URI budget must be enforced on the very next inspection.
	if _, err := engine.Inspect(context.Background(), l7Request("/"+strings.Repeat("a", 5000))); err == nil {
		t.Fatal("reduced URI budget was not enforced by the live engine")
	}
}

func TestFabricL7RestartClassIsPersistedButNotSilentlyActivated(t *testing.T) {
	server, settings, release, engine := l7FabricFixture(t)
	before := engine.LiveSettings().MaxConcurrent

	payload := l7MutationPayload(t, settings, func(fabric *L7FabricSettings) {
		fabric.MaxConcurrent = before + 4
	})
	preview := fabricRequest(t, server, http.MethodPost, "/api/v1/settings/l7/preview", payload)
	if preview.Code != http.StatusOK {
		t.Fatalf("preview status=%d body=%s", preview.Code, preview.Body.String())
	}
	var parsed FabricSettingsPreview
	if err := json.Unmarshal(preview.Body.Bytes(), &parsed); err != nil {
		t.Fatal(err)
	}
	if !parsed.RequiresRestart {
		t.Fatalf("concurrency change was not marked restart-required: %+v", parsed)
	}
	found := false
	for _, diff := range parsed.Diff {
		if diff.Key == "max_concurrent" && diff.ApplyClass == FabricApplyRestart {
			found = true
		}
	}
	if !found {
		t.Fatalf("restart-class diff missing: %+v", parsed.Diff)
	}

	apply := fabricRequest(t, server, http.MethodPut, "/api/v1/settings/l7", payload)
	if apply.Code != http.StatusOK {
		t.Fatalf("apply status=%d body=%s", apply.Code, apply.Body.String())
	}
	view := decodeFabricView(t, apply.Body.Bytes())
	if view.ApplyState != "restart_required" {
		t.Fatalf("restart-class revision reported %q", view.ApplyState)
	}
	if got := engine.LiveSettings().MaxConcurrent; got != before {
		t.Fatalf("restart-class value activated silently: live=%d want=%d", got, before)
	}
	if persisted := settings.Get().L7; persisted == nil || persisted.MaxConcurrent != before+4 {
		t.Fatalf("restart-class value was not persisted: %+v", persisted)
	}

	server.state.SetSensorCoverage(SensorCoverage{Name: "xdp_ingress", Layer: LayerIngressNetwork, Status: CoverageOnline, Required: true})
	if _, err := release.Transition(ReleasePhaseCanary, "PROMOTE:CANARY", "exercise L7 restart-class phase gate"); err != nil {
		t.Fatal(err)
	}
	blocked := l7MutationPayload(t, settings, func(fabric *L7FabricSettings) {
		fabric.MaxConcurrent = before + 8
	})
	if rec := fabricRequest(t, server, http.MethodPut, "/api/v1/settings/l7", blocked); rec.Code != http.StatusConflict {
		t.Fatalf("restart-class change outside Observe/Degraded accepted: %d %s", rec.Code, rec.Body.String())
	}
}

func TestFabricL7RuleRegistrySuppressesDetection(t *testing.T) {
	server, settings, _, engine := l7FabricFixture(t)
	request := l7Request("/search?q=%3Cscript%3Ealert(1)%3C/script%3E")

	baseline, err := engine.Inspect(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if !findingByID(baseline.Findings, "L7.XSS.SCRIPT_TAG") {
		t.Fatalf("fixture did not detect the baseline XSS signature: %+v", baseline.Findings)
	}

	payload := l7MutationPayload(t, settings, func(fabric *L7FabricSettings) {
		fabric.Rules = []L7RuleOverride{{ID: "L7.XSS.SCRIPT_TAG", Enabled: false, Score: 90, Confidence: 96}}
	})
	if rec := fabricRequest(t, server, http.MethodPut, "/api/v1/settings/l7", payload); rec.Code != http.StatusOK {
		t.Fatalf("rule override apply failed: %d %s", rec.Code, rec.Body.String())
	}
	suppressed, err := engine.Inspect(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if findingByID(suppressed.Findings, "L7.XSS.SCRIPT_TAG") {
		t.Fatalf("disabled rule still produced a finding: %+v", suppressed.Findings)
	}

	unknown := l7MutationPayload(t, settings, func(fabric *L7FabricSettings) {
		fabric.Rules = []L7RuleOverride{{ID: "L7.OPERATOR.INVENTED", Enabled: true, Score: 90, Confidence: 90}}
	})
	if rec := fabricRequest(t, server, http.MethodPost, "/api/v1/settings/l7/preview", unknown); rec.Code != http.StatusBadRequest {
		t.Fatalf("unknown rule id accepted: %d %s", rec.Code, rec.Body.String())
	}

	outOfRange := l7MutationPayload(t, settings, func(fabric *L7FabricSettings) {
		fabric.Rules = []L7RuleOverride{{ID: "L7.XSS.SCRIPT_TAG", Enabled: true, Score: 400, Confidence: 96}}
	})
	if rec := fabricRequest(t, server, http.MethodPost, "/api/v1/settings/l7/preview", outOfRange); rec.Code != http.StatusBadRequest {
		t.Fatalf("out-of-range rule score accepted: %d %s", rec.Code, rec.Body.String())
	}
}

func TestFabricL7AlertOnlyRulesCannotAuthoriseABlock(t *testing.T) {
	settings := defaultConfig().L7
	fabric := defaultL7FabricSettings(settings)
	fabric.Rules = []L7RuleOverride{{ID: "L7.XSS.SCRIPT_TAG", Enabled: true, Score: 200, Confidence: 99, AlertOnly: true}}
	snapshot := buildL7RuntimeSnapshot(fabric, 7)

	findings := []L7Finding{newL7Finding("L7.XSS.SCRIPT_TAG", "xss", "high", 90, 96, "query.q", "<script>", "fixture")}
	kept, blockable := snapshot.applyRuleOverrides(findings)
	if len(kept) != 1 || kept[0].Score != 200 || kept[0].Confidence != 99 {
		t.Fatalf("score/confidence override not applied: %+v", kept)
	}
	if len(blockable) != 0 {
		t.Fatalf("alert-only rule remained block-eligible: %+v", blockable)
	}

	fabric.Rules = nil
	plain := buildL7RuntimeSnapshot(fabric, 8)
	kept, blockable = plain.applyRuleOverrides(findings)
	if len(kept) != 1 || len(blockable) != 1 {
		t.Fatalf("empty registry must preserve the historical behaviour: kept=%d blockable=%d", len(kept), len(blockable))
	}

	// A family override covers every runtime-generated identifier below it.
	fabric.Rules = []L7RuleOverride{{ID: "L7.RATE_LIMIT", Enabled: false, Score: 95, Confidence: 99}}
	family := buildL7RuntimeSnapshot(fabric, 9)
	_, blockable = family.applyRuleOverrides([]L7Finding{newL7Finding("L7.RATE_LIMIT.SENSITIVE_ROUTE_GLOBAL", "rate-limit", "high", 95, 99, "request", "x", "fixture")})
	if len(blockable) != 0 {
		t.Fatal("family override did not cover the generated rate-limit identifier")
	}
}

func TestFabricL7RejectsUnsafeCombinations(t *testing.T) {
	server, settings, _, _ := l7FabricFixture(t)
	cases := []struct {
		name   string
		mutate func(fabric *L7FabricSettings)
	}{
		{"scores inverted", func(fabric *L7FabricSettings) { fabric.AlertScore = fabric.BlockScore }},
		{"upload exceeds body", func(fabric *L7FabricSettings) { fabric.MaxUploadBytes = fabric.MaxBodyBytes + 1 }},
		{"inspection budget too small", func(fabric *L7FabricSettings) { fabric.MaxInspectionBytes = 1 << 20 }},
		{"inline without engine", func(fabric *L7FabricSettings) { fabric.Enabled = false; fabric.InlineEnabled = true }},
		{"inline upstream off-host", func(fabric *L7FabricSettings) {
			fabric.InlineEnabled = true
			fabric.InlineUpstream = "http://10.1.2.3:8080"
		}},
		{"relative JA3 path", func(fabric *L7FabricSettings) { fabric.TLSJA3File = "fingerprints.json" }},
		{"unclean sensitive path", func(fabric *L7FabricSettings) { fabric.SensitivePaths = []string{"/admin?x=1"} }},
		{"peer credentials without identity", func(fabric *L7FabricSettings) {
			fabric.RequirePeerCredentials = true
			fabric.AllowedPeerUIDs = nil
			fabric.AllowedPeerGIDs = nil
		}},
		{"unknown fingerprint behaviour", func(fabric *L7FabricSettings) { fabric.TLSUnknownFingerprint = "block" }},
		{"aggregate memory budget", func(fabric *L7FabricSettings) {
			fabric.MaxEnvelopeBytes = 32 << 20
			fabric.MaxBodyBytes = 16 << 20
			fabric.MaxInspectionBytes = 64 << 20
			fabric.InlineMaxResponseBytes = 16 << 20
			fabric.MaxConcurrent = 512
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			payload := l7MutationPayload(t, settings, tc.mutate)
			rec := fabricRequest(t, server, http.MethodPost, "/api/v1/settings/l7/preview", payload)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("unsafe configuration accepted: %d %s", rec.Code, rec.Body.String())
			}
			if server.cfg.L7.Mode != settings.Get().L7.Mode {
				t.Fatal("rejected preview mutated the runtime configuration")
			}
		})
	}
}

// TestFabricL7DocumentWithoutNamespaceStillAuthenticates guards the migration
// path for an installation whose encrypted settings document was written before
// the Application Defense namespace existed. Such a document must still
// authenticate and must be upgraded in place rather than rejected.
func TestFabricL7DocumentWithoutNamespaceStillAuthenticates(t *testing.T) {
	cfg := defaultConfig()
	cfg.L7.Enabled = true
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
	legacy.FabricVersion = 2
	legacy.L7 = nil
	legacy.Kinetic.VelocityLimit = 4242
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
		t.Fatalf("a pre-L7 settings document was rejected: %v", err)
	}
	upgraded := reloaded.Get()
	if upgraded.FabricVersion != fabricSettingsVersion {
		t.Fatalf("schema version not upgraded: %d", upgraded.FabricVersion)
	}
	if upgraded.L7 == nil {
		t.Fatal("Application Defense namespace was not seeded during the upgrade")
	}
	if upgraded.L7.Socket != cfg.L7.Socket || upgraded.L7.MaxURIBytes != cfg.L7.MaxURIBytes {
		t.Fatalf("namespace was not seeded from the bootstrap configuration: %+v", upgraded.L7)
	}
	if upgraded.Kinetic.VelocityLimit != 4242 {
		t.Fatalf("existing operator tuning was lost during the upgrade: %d", upgraded.Kinetic.VelocityLimit)
	}
}

func TestFabricL7ModuleViewExposesEffectiveAndComputedTruth(t *testing.T) {
	server, _, _, _ := l7FabricFixture(t)
	rec := fabricRequest(t, server, http.MethodGet, "/api/v1/settings/l7", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	view := decodeFabricView(t, rec.Body.Bytes())
	if view.ApplyState != "applied" {
		t.Fatalf("attached engine reported apply state %q", view.ApplyState)
	}
	budget, ok := view.Details["memory_budget"].(map[string]any)
	if !ok {
		t.Fatalf("module view is missing the computed memory budget: %+v", view.Details)
	}
	perInspection, _ := budget["per_inspection_bytes"].(float64)
	aggregate, _ := budget["aggregate_bytes"].(float64)
	persisted := *(server.settings.Get().L7)
	if perInspection <= 0 || aggregate != perInspection*float64(persisted.MaxConcurrent) {
		t.Fatalf("memory budget is inconsistent with the request limits: %+v", budget)
	}
	rules, ok := view.Details["rule_registry"].([]any)
	if !ok || len(rules) == 0 {
		t.Fatalf("module view is missing the rule catalogue: %+v", view.Details)
	}
	if _, ok := view.Details["tls_fingerprints"]; !ok {
		t.Fatal("module view is missing the TLS fingerprint status")
	}
}

func TestFabricL7SchemaRegistryCoversEveryAdvertisedKey(t *testing.T) {
	server, settings, _, _ := l7FabricFixture(t)

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
	if !containsString(schema.Modules, "l7") {
		t.Fatalf("schema does not advertise the Application Defense module: %v", schema.Modules)
	}
	registered := map[string]FabricSettingMetadata{}
	for _, meta := range schema.Settings {
		if meta.Module == "l7" {
			registered[meta.Key] = meta
		}
	}
	if len(registered) == 0 {
		t.Fatal("schema carries no Application Defense settings")
	}

	// Every administrable key of the persisted namespace must be documented,
	// and every documented key must classify with its registered risk/class.
	persisted := settings.Get().L7
	payload, err := json.Marshal(persisted)
	if err != nil {
		t.Fatal(err)
	}
	var flat map[string]any
	if err := json.Unmarshal(payload, &flat); err != nil {
		t.Fatal(err)
	}
	for key := range flat {
		if key == "rules" {
			continue
		}
		meta, ok := registered[key]
		if !ok {
			t.Fatalf("administrable key %q has no schema metadata", key)
		}
		risk, class := settingRisk("l7", key)
		if risk != meta.Risk || class != meta.ApplyClass {
			t.Fatalf("key %q classifies as %s/%s but is registered as %s/%s", key, risk, class, meta.Risk, meta.ApplyClass)
		}
	}
	if len(fabricModuleRestartClass("l7")) == 0 {
		t.Fatal("the registry declares no restart-class Application Defense setting")
	}
	for _, key := range fabricModuleRestartClass("l7") {
		if !containsString(l7RestartClassKeys, key) {
			t.Fatalf("registry restart key %q is not handled by the runtime restart detector", key)
		}
	}
	for _, key := range l7RestartClassKeys {
		if _, ok := registered[key]; !ok {
			t.Fatalf("runtime restart key %q is not documented in the schema registry", key)
		}
	}
}
