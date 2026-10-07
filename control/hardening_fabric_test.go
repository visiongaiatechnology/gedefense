// STATUS: DIAMANT VGT SUPREME
package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"testing"
)

func hardeningFixture(t *testing.T) (*APIServer, *SettingsStore) {
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
	return server, settings
}

func hardeningPayload(t *testing.T, settings *SettingsStore, mutate func(fabric *HardeningFabricSettings)) []byte {
	t.Helper()
	current := settings.Get()
	fabric := defaultHardeningFabricSettings(Config{}, "")
	if current.Hardening != nil {
		fabric = cloneHardeningFabricSettings(*current.Hardening)
	}
	mutate(&fabric)
	payload, err := json.Marshal(map[string]any{"expected_revision": current.Revision, "settings": fabric})
	if err != nil {
		t.Fatal(err)
	}
	return payload
}

func TestFabricHardeningHotRevisionReachesHostSecurityEngines(t *testing.T) {
	server, settings := hardeningFixture(t)
	dir := t.TempDir()

	payload := hardeningPayload(t, settings, func(fabric *HardeningFabricSettings) {
		fabric.RASP.TrustedDebuggers = []string{"gdb", "strace"}
		fabric.RASP.ContainmentEnabled = false
		fabric.RASP.AlertOnly = true
		fabric.Deception.Canaries = []CanarySettings{
			{Path: filepath.Join(dir, "decoy.env"), Type: string(CanaryDotEnv), Enabled: true, OwnerUID: 1000, FileMode: 0o600},
		}
		fabric.Deception.AllowedRoots = []string{dir}
		fabric.Deception.ContainmentLevel = deceptionContainmentObserve
		fabric.Airlock.QuarantineDirectory = filepath.Join(dir, "vault")
		fabric.Airlock.PolyglotDetection = false
		fabric.Airlock.ExecutableUploadPolicy = airlockExecPolicyReport
		fabric.Airlock.AutoQuarantine = true
	})
	preview := fabricRequest(t, server, http.MethodPost, "/api/v1/settings/hardening/preview", payload)
	if preview.Code != http.StatusOK {
		t.Fatalf("preview status=%d body=%s", preview.Code, preview.Body.String())
	}
	var parsed FabricSettingsPreview
	if err := json.Unmarshal(preview.Body.Bytes(), &parsed); err != nil {
		t.Fatal(err)
	}
	if !parsed.Valid || parsed.RequiresRestart {
		t.Fatalf("host security revision flagged unexpectedly: %+v", parsed)
	}

	apply := fabricRequest(t, server, http.MethodPut, "/api/v1/settings/hardening", payload)
	if apply.Code != http.StatusOK {
		t.Fatalf("apply status=%d body=%s", apply.Code, apply.Body.String())
	}

	// Distribution onto the engines is exercised through the same choke point the
	// XDR engine uses.
	live := effectiveHardeningSettings(settings.Get())
	morpheus := NewMorpheusRASP("", nil, nil)
	airlock, err := NewAirlockInspector(filepath.Join(dir, "vault"), 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	deception, err := NewDeceptionEngine(bytes.Repeat([]byte{7}, 32), nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := applyHardeningPolicy(live, morpheus, airlock, deception); err != nil {
		t.Fatal(err)
	}

	// RASP: a trusted debugger is exempt and containment is off.
	if event, err := morpheus.InspectProcess(ProcessSample{PID: 4242, Comm: "gdb", Cmdline: "gdb -p 1"}); event != nil || err != nil {
		t.Fatalf("trusted debugger was not exempt: event=%v err=%v", event, err)
	}
	if event, err := morpheus.InspectProcess(ProcessSample{PID: 4243, Comm: "frida", Cmdline: "frida -p 1 -- /usr/bin/vault"}); event == nil || err != nil {
		t.Fatalf("alert-only RASP did not report without containing: event=%v err=%v", event, err)
	}

	// Deception: the administrable grid replaced the built-in decoys.
	inventory := deception.ListCanaries()
	if len(inventory) != 1 || inventory[0].Path != filepath.Join(dir, "decoy.env") {
		t.Fatalf("canary grid was not reconciled: %+v", inventory)
	}
	if inventory[0].Type != string(CanaryDotEnv) {
		t.Fatalf("canary type not applied: %+v", inventory[0])
	}

	// Airlock: polyglot detection is off, so a polyglot body is no longer refused
	// for that reason, and a disguised executable is reported rather than refused.
	polyglot := []byte("GIF89a" + string([]byte{0x00}) + "<?php system($_GET['x']); ?>")
	result, err := airlock.InspectBytes("image.gif", polyglot)
	if err != nil || result == nil || !result.IsClean {
		t.Fatalf("polyglot detection stayed active after being disabled: result=%+v err=%v", result, err)
	}
	disguised := append([]byte{0x7F, 'E', 'L', 'F'}, bytes.Repeat([]byte{0x00}, 32)...)
	execResult, execErr := airlock.InspectBytes("invoice.pdf", disguised)
	if execErr == nil || execResult == nil {
		t.Fatal("disguised executable was not reported at all")
	}
	if execResult.RiskScore != airlockReportOnlyScore {
		t.Fatalf("report-only policy did not cap the escalation score: %d", execResult.RiskScore)
	}
	if execResult.QuarantinePath == "" {
		t.Fatal("automatic quarantine did not stage the refused object")
	}
	if _, statErr := os.Stat(execResult.QuarantinePath); statErr != nil {
		t.Fatalf("staged quarantine object is missing: %v", statErr)
	}
}

func TestFabricHardeningRejectsUnsafeConfiguration(t *testing.T) {
	server, settings := hardeningFixture(t)
	cases := []struct {
		name   string
		mutate func(fabric *HardeningFabricSettings)
	}{
		{"unknown required domain", func(f *HardeningFabricSettings) { f.Posture.RequiredDomains = []string{"kernel", "invented-domain"} }},
		{"thresholds out of order", func(f *HardeningFabricSettings) { f.Posture.StrongThreshold = 95 }},
		{"scan interval below floor", func(f *HardeningFabricSettings) { f.Posture.ScanIntervalSeconds = 5 }},
		{"sysctl profile references an unknown control", func(f *HardeningFabricSettings) {
			f.Sysctl.Profiles = []SysctlProfileSettings{{Name: "custom", Controls: []string{"kernel.invented"}}}
		}},
		{"sysctl profile selects nothing", func(f *HardeningFabricSettings) {
			f.Sysctl.Profiles = []SysctlProfileSettings{{Name: "custom", Controls: nil}}
			f.Sysctl.DefaultProfile = ""
		}},
		{"sysctl default profile undefined", func(f *HardeningFabricSettings) { f.Sysctl.DefaultProfile = "does-not-exist" }},
		{"duplicate sysctl profile", func(f *HardeningFabricSettings) {
			f.Sysctl.Profiles = []SysctlProfileSettings{
				{Name: "dup", Controls: []string{"kernel.aslr"}},
				{Name: "dup", Controls: []string{"kernel.kptr"}},
			}
			f.Sysctl.DefaultProfile = ""
		}},
		{"canary outside every root", func(f *HardeningFabricSettings) {
			f.Deception.AllowedRoots = []string{"/srv"}
		}},
		{"canary relative path", func(f *HardeningFabricSettings) {
			f.Deception.Canaries = []CanarySettings{{Path: "tmp/decoy", Type: string(CanaryDotEnv), Enabled: true, FileMode: 0o600}}
		}},
		{"canary file mode unset", func(f *HardeningFabricSettings) {
			f.Deception.Canaries = []CanarySettings{{Path: "/tmp/decoy", Type: string(CanaryDotEnv), Enabled: true, FileMode: 0}}
		}},
		{"canary type unknown", func(f *HardeningFabricSettings) {
			f.Deception.Canaries = []CanarySettings{{Path: "/tmp/decoy", Type: "MAGIC", Enabled: true, FileMode: 0o600}}
		}},
		{"duplicate canary path", func(f *HardeningFabricSettings) {
			f.Deception.Canaries = []CanarySettings{
				{Path: "/tmp/decoy", Type: string(CanaryDotEnv), Enabled: true, FileMode: 0o600},
				{Path: "/tmp/decoy", Type: string(CanarySSHKey), Enabled: true, FileMode: 0o600},
			}
		}},
		{"deception enabled without canaries", func(f *HardeningFabricSettings) {
			f.Deception.Enabled = true
			f.Deception.Canaries = nil
		}},
		{"unknown containment level", func(f *HardeningFabricSettings) { f.Deception.ContainmentLevel = "nuke" }},
		{"unclean allowed root", func(f *HardeningFabricSettings) { f.Deception.AllowedRoots = []string{"/srv/../etc"} }},
		{"rasp alert-only with containment", func(f *HardeningFabricSettings) {
			f.RASP.AlertOnly = true
			f.RASP.ContainmentEnabled = true
		}},
		{"rasp protected name with a path", func(f *HardeningFabricSettings) { f.RASP.ProtectedNames = []string{"/usr/bin/vault"} }},
		{"airlock quarantine at root", func(f *HardeningFabricSettings) { f.Airlock.QuarantineDirectory = "/" }},
		{"airlock enabled without a vault", func(f *HardeningFabricSettings) { f.Airlock.QuarantineDirectory = "" }},
		{"airlock size out of bounds", func(f *HardeningFabricSettings) { f.Airlock.MaxFileSizeBytes = 1 }},
		{"unknown mime action", func(f *HardeningFabricSettings) { f.Airlock.MimeMismatchAction = "block" }},
		{"unknown executable policy", func(f *HardeningFabricSettings) { f.Airlock.ExecutableUploadPolicy = "quarantine" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			payload := hardeningPayload(t, settings, tc.mutate)
			rec := fabricRequest(t, server, http.MethodPost, "/api/v1/settings/hardening/preview", payload)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("unsafe configuration accepted: %d %s", rec.Code, rec.Body.String())
			}
			if settings.Get().Revision != 1 {
				t.Fatal("rejected preview mutated runtime settings")
			}
		})
	}
}

// TestHardeningSysctlDefaultsMatchTheBuiltInProfiles proves the administrable
// profile model is behaviour-preserving: the derived key sets must equal the
// compiled-in ones exactly.
func TestHardeningSysctlDefaultsMatchTheBuiltInProfiles(t *testing.T) {
	defaults := defaultHardeningFabricSettings(Config{}, "").Sysctl
	derived, err := buildSysctlProfiles(defaults.Profiles)
	if err != nil {
		t.Fatal(err)
	}
	applier := NewSysctlTransactionApplier(nil)
	builtIn, _, _ := applier.profileSet()

	if len(derived) != len(builtIn) {
		t.Fatalf("profile count changed: derived=%d built-in=%d", len(derived), len(builtIn))
	}
	// The compiled-in profiles are a documented shape: 13 kernel keys for the
	// balanced server profile and 15 for the strict workstation profile.
	if got := len(derived["linux-server-balanced"].Values); got != 13 {
		t.Fatalf("balanced profile key count=%d want=13", got)
	}
	if got := len(derived["astraeaos-workstation-strict"].Values); got != 15 {
		t.Fatalf("strict profile key count=%d want=15", got)
	}
	for name, profile := range builtIn {
		other, ok := derived[name]
		if !ok {
			t.Fatalf("derived profile set is missing %q", name)
		}
		if len(profile.Values) != len(other.Values) {
			t.Fatalf("profile %q key count changed: built-in=%d derived=%d", name, len(profile.Values), len(other.Values))
		}
		for key, value := range profile.Values {
			if other.Values[key] != value {
				t.Fatalf("profile %q key %s changed: built-in=%q derived=%q", name, key, value, other.Values[key])
			}
		}
	}
}

func TestHardeningSysctlAdHocPolicyIsEnforced(t *testing.T) {
	applier := NewSysctlTransactionApplier(nil)
	settings := defaultHardeningFabricSettings(Config{}, "").Sysctl
	settings.AllowAdHocControls = false
	if err := applier.UpdateProfiles(settings); err != nil {
		t.Fatal(err)
	}
	profiles, defaultProfile, allowAdHoc := applier.profileSet()
	if _, err := decodeSysctlProfileRequest([]byte(`{"controls":["kernel.aslr"]}`), profiles, defaultProfile, allowAdHoc); err == nil {
		t.Fatal("ad-hoc control selection was accepted while disabled by policy")
	}
	// A named profile still works, and an empty request falls back to the default.
	if _, err := decodeSysctlProfileRequest([]byte(`{"profile":"linux-server-balanced"}`), profiles, defaultProfile, allowAdHoc); err != nil {
		t.Fatalf("named profile was rejected: %v", err)
	}
	profile, err := decodeSysctlProfileRequest([]byte(`{}`), profiles, defaultProfile, allowAdHoc)
	if err != nil {
		t.Fatalf("default profile fallback failed: %v", err)
	}
	if profile.Name != defaultProfile {
		t.Fatalf("fallback returned %q instead of %q", profile.Name, defaultProfile)
	}
	// The vocabulary stays closed even with ad-hoc selection enabled.
	settings.AllowAdHocControls = true
	if err := applier.UpdateProfiles(settings); err != nil {
		t.Fatal(err)
	}
	profiles, defaultProfile, allowAdHoc = applier.profileSet()
	if _, err := decodeSysctlProfileRequest([]byte(`{"controls":["kernel.not-allowlisted"]}`), profiles, defaultProfile, allowAdHoc); err == nil {
		t.Fatal("a control outside the closed vocabulary was accepted")
	}
}

// TestHardeningPostureAssessmentCannotBeSilenced verifies that a required domain
// with no measurable control is reported UNAVAILABLE, so removing a domain from
// the required list cannot turn an unmeasurable posture green.
func TestHardeningPostureAssessmentCannotBeSilenced(t *testing.T) {
	settings := HardeningPostureSettings{
		HardenedThreshold: 90, StrongThreshold: 75, BasicThreshold: 50,
		RequiredDomains: []string{"kernel", "network", "integrity"},
	}
	posture := HardeningPosture{
		Score: 80, Level: "STRONG",
		Domains: []HardeningDomain{
			{ID: "kernel", Title: "Kernel", Score: 95, Protected: 5, Total: 5},
			{ID: "network", Title: "Network", Score: 40, Protected: 1, Total: 3},
		},
	}
	findings := assessHardeningPosture(posture, settings)
	byDomain := map[string]HardeningDomainFinding{}
	for _, finding := range findings {
		byDomain[finding.Domain] = finding
	}
	if byDomain["kernel"].State != "PROTECTED" {
		t.Fatalf("healthy domain misreported: %+v", byDomain["kernel"])
	}
	if byDomain["network"].State != "CRITICAL" {
		t.Fatalf("below-basic domain misreported: %+v", byDomain["network"])
	}
	if byDomain["integrity"].State != "UNAVAILABLE" {
		t.Fatalf("domain with no measurable control was not reported unavailable: %+v", byDomain["integrity"])
	}

	// Removing the unmeasurable domain from the required list removes the finding
	// but cannot make it pass: the domain is simply no longer asserted.
	settings.RequiredDomains = []string{"kernel", "network"}
	shrunk := assessHardeningPosture(posture, settings)
	if len(shrunk) != 2 {
		t.Fatalf("required-domain list was not honoured: %+v", shrunk)
	}
}

func TestHardeningDeceptionPolicyReconcilesGrid(t *testing.T) {
	dir := t.TempDir()
	engine, err := NewDeceptionEngine(bytes.Repeat([]byte{9}, 32), nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	settings := defaultHardeningFabricSettings(Config{}, "").Deception
	settings.AllowedRoots = []string{dir}
	settings.Canaries = []CanarySettings{
		{Path: filepath.Join(dir, "a.env"), Type: string(CanaryDotEnv), Enabled: true, OwnerUID: 1000, FileMode: 0o600},
		{Path: filepath.Join(dir, "b.key"), Type: string(CanarySSHKey), Enabled: true, OwnerUID: 0, FileMode: 0o600},
	}
	registered, removed, err := engine.ApplyPolicy(settings)
	if err != nil {
		t.Fatal(err)
	}
	if registered != 2 || removed != 0 {
		t.Fatalf("first reconciliation registered=%d removed=%d", registered, removed)
	}
	if inventory := engine.ListCanaries(); len(inventory) != 2 {
		t.Fatalf("inventory=%+v", inventory)
	}

	// A type change re-enrols the decoy so its signed token matches.
	settings.Canaries[0].Type = string(CanaryCloudCred)
	registered, removed, err = engine.ApplyPolicy(settings)
	if err != nil {
		t.Fatal(err)
	}
	if registered != 1 || removed != 0 {
		t.Fatalf("type change did not re-enrol: registered=%d removed=%d", registered, removed)
	}
	inventory := engine.ListCanaries()
	if inventory[0].Path != filepath.Join(dir, "a.env") || inventory[0].Type != string(CanaryCloudCred) {
		t.Fatalf("re-enrolment did not update the token: %+v", inventory[0])
	}

	// Dropping a decoy removes it from the grid.
	settings.Canaries = settings.Canaries[1:]
	_, removed, err = engine.ApplyPolicy(settings)
	if err != nil {
		t.Fatal(err)
	}
	if removed != 1 {
		t.Fatalf("removal count=%d", removed)
	}
	if inventory := engine.ListCanaries(); len(inventory) != 1 {
		t.Fatalf("grid not pruned: %+v", inventory)
	}
	if err := engine.UnregisterCanary("/nowhere"); err == nil {
		t.Fatal("unregistering an unknown decoy succeeded")
	}
}

func TestHardeningRASPPolicyExemptsOnlyNamedTools(t *testing.T) {
	rasp := NewMorpheusRASP("", nil, nil)
	rasp.ApplyPolicy(HardeningRASPSettings{
		Enabled: true, ProtectedNames: []string{"vault"}, TrustedDebuggers: []string{"gdb"}, ContainmentEnabled: true,
	})
	if event, err := rasp.InspectProcess(ProcessSample{PID: 10, Comm: "gdb", Cmdline: "gdb -p 1 -- /etc/vault"}); event != nil || err != nil {
		t.Fatalf("trusted debugger was not exempt: %+v %v", event, err)
	}
	if _, err := rasp.InspectProcess(ProcessSample{PID: 11, Comm: "frida", Cmdline: "frida -- /etc/vault"}); err == nil {
		t.Fatal("an untrusted scraper was not contained")
	}

	// Disabling the data path stops all RASP participation.
	rasp.ApplyPolicy(HardeningRASPSettings{Enabled: false})
	if event, err := rasp.InspectProcess(ProcessSample{PID: 12, Comm: "frida", Cmdline: "frida -- /etc/vault"}); event != nil || err != nil {
		t.Fatalf("disabled RASP still evaluated: %+v %v", event, err)
	}
}

// TestHardeningDocumentWithoutNamespaceStillAuthenticates guards the migration
// path for a settings document written before the Host Security namespace
// existed.
func TestHardeningDocumentWithoutNamespaceStillAuthenticates(t *testing.T) {
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
	legacy.FabricVersion = 4
	legacy.Hardening = nil
	legacy.Kinetic.VelocityLimit = 321
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
		t.Fatalf("a pre-Host-Security settings document was rejected: %v", err)
	}
	upgraded := reloaded.Get()
	if upgraded.FabricVersion != fabricSettingsVersion {
		t.Fatalf("schema version not upgraded: %d", upgraded.FabricVersion)
	}
	if upgraded.Hardening == nil {
		t.Fatal("Host Security namespace was not seeded during the upgrade")
	}
	if upgraded.Kinetic.VelocityLimit != 321 {
		t.Fatal("existing operator tuning was lost during the upgrade")
	}
	if upgraded.Hardening.Airlock.MaxFileSizeBytes != 100<<20 {
		t.Fatalf("airlock default was not seeded: %d", upgraded.Hardening.Airlock.MaxFileSizeBytes)
	}
}

func TestFabricHardeningSchemaRegistryCoversEveryAdvertisedKey(t *testing.T) {
	server, settings := hardeningFixture(t)
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
	if !containsString(schema.Modules, "hardening") {
		t.Fatalf("schema does not advertise the Host Security module: %v", schema.Modules)
	}
	registered := map[string]FabricSettingMetadata{}
	for _, meta := range schema.Settings {
		if meta.Module == "hardening" {
			registered[meta.Key] = meta
		}
	}
	if len(registered) == 0 {
		t.Fatal("schema carries no Host Security settings")
	}

	payload, err := json.Marshal(effectiveHardeningSettings(settings.Get()))
	if err != nil {
		t.Fatal(err)
	}
	var flat map[string]any
	if err := json.Unmarshal(payload, &flat); err != nil {
		t.Fatal(err)
	}
	// Every leaf key of the namespace must be documented.
	for _, group := range []string{"posture", "sysctl", "rasp", "deception", "airlock"} {
		raw, ok := flat[group]
		if !ok {
			t.Fatalf("namespace %q missing from the module snapshot", group)
		}
		nested, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		for leaf := range nested {
			documented := group + "." + leaf
			if _, exists := registered[documented]; !exists {
				t.Fatalf("administrable key %q has no schema metadata", documented)
			}
		}
	}

	// The module view must carry the posture assessment and the closed control
	// vocabulary so the dashboard never has to invent either.
	view := fabricRequest(t, server, http.MethodGet, "/api/v1/settings/hardening", nil)
	if view.Code != http.StatusOK {
		t.Fatalf("module view status=%d body=%s", view.Code, view.Body.String())
	}
	decoded := decodeFabricView(t, view.Body.Bytes())
	if _, ok := decoded.Details["posture"]; !ok {
		t.Fatalf("module view is missing the posture assessment: %+v", decoded.Details)
	}
	controls, ok := decoded.Details["sysctl_controls"].([]any)
	if !ok || len(controls) != len(sysctlControlDefinitions) {
		t.Fatalf("module view does not publish the closed control vocabulary: %+v", decoded.Details["sysctl_controls"])
	}
}
