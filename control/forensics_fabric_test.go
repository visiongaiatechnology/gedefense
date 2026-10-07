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

func forensicsFixture(t *testing.T) (*APIServer, *SettingsStore) {
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

func forensicsFabricPayload(t *testing.T, settings *SettingsStore, mutate func(fabric *ForensicsFabricSettings)) []byte {
	t.Helper()
	current := settings.Get()
	fabric := defaultForensicsFabricSettings()
	if current.Forensics != nil {
		fabric = cloneForensicsFabricSettings(*current.Forensics)
	}
	mutate(&fabric)
	payload, err := json.Marshal(map[string]any{"expected_revision": current.Revision, "settings": fabric})
	if err != nil {
		t.Fatal(err)
	}
	return payload
}

// TestForensicsQuarantinePolicyOnlyRestricts proves the central invariant: a
// Fabric revision can add restrictions but can never remove the compiled-in
// boundary that protects the host and the control plane itself.
func TestForensicsQuarantinePolicyOnlyRestricts(t *testing.T) {
	builtin := quarantinePolicy{}
	for _, path := range []string{
		"/proc/self/mem", "/sys/kernel/security/lockdown", "/dev/sda",
		"/etc/vgt/gedefense/policy.key", "/var/lib/vgt/gedefense/evidence.jsonl",
		"/opt/vgt/gedefense/core", "/etc/shadow",
	} {
		if !builtin.pathForbidden(path) {
			t.Fatalf("the compiled-in denylist does not cover %s", path)
		}
	}
	if builtin.pathForbidden("/home/operator/suspicious.bin") {
		t.Fatal("an ordinary path is denied by the compiled-in rules")
	}

	// An operator allowlist narrows what may be quarantined.
	narrow := quarantinePolicy{allowed: []string{"/var/tmp"}}
	if !narrow.pathOutsideAllowedRoots("/home/operator/suspicious.bin") {
		t.Fatal("a path outside the allowlist was permitted")
	}
	if narrow.pathOutsideAllowedRoots("/var/tmp/payload.bin") {
		t.Fatal("a path inside the allowlist was refused")
	}
	// Prefix safety: a sibling directory sharing a textual prefix is not inside.
	if !narrow.pathOutsideAllowedRoots("/var/tmp-evil/payload.bin") {
		t.Fatal("a sibling of the allowlist root was treated as inside it")
	}
	// An added denial restricts further.
	extra := quarantinePolicy{extra: []string{"/home/operator"}}
	if !extra.pathForbidden("/home/operator/.ssh/id_ed25519") {
		t.Fatal("an administered extra denial was not applied")
	}
	// Even with a permissive-looking allowlist, the built-in rules still hold.
	mixed := quarantinePolicy{allowed: []string{"/proc"}}
	if !mixed.pathForbidden("/proc/self/mem") {
		t.Fatal("an allowlist removed the compiled-in denial")
	}
}

func TestForensicsRejectsContradictoryQuarantineRoots(t *testing.T) {
	server, settings := forensicsFixture(t)
	cases := []struct {
		name   string
		mutate func(fabric *ForensicsFabricSettings)
	}{
		{"allowlist inside a built-in denial", func(f *ForensicsFabricSettings) {
			f.Quarantine.AllowedRoots = []string{"/var/lib/vgt/gedefense/tmp"}
		}},
		{"allowlist equal to a built-in denial", func(f *ForensicsFabricSettings) {
			f.Quarantine.AllowedRoots = []string{"/run"}
		}},
		{"allowlist containing an added denial", func(f *ForensicsFabricSettings) {
			f.Quarantine.AllowedRoots = []string{"/home/operator"}
			f.Quarantine.ExtraForbidden = []string{"/home/operator"}
		}},
		{"allowlist at the filesystem root", func(f *ForensicsFabricSettings) {
			f.Quarantine.AllowedRoots = []string{"/"}
		}},
		{"unclean allowed root", func(f *ForensicsFabricSettings) {
			f.Quarantine.AllowedRoots = []string{"/home/../etc"}
		}},
		{"restore mode widens access", func(f *ForensicsFabricSettings) { f.Quarantine.RestoreFileMode = 0o644 }},
		{"case budget zero", func(f *ForensicsFabricSettings) { f.Cases.MaxCases = 0 }},
		{"correlation window zero", func(f *ForensicsFabricSettings) { f.Cases.CorrelationWindowMins = 0 }},
		{"creation score above the range", func(f *ForensicsFabricSettings) { f.Cases.MinimumIncidentScore = 300 }},
		{"export boundary too small", func(f *ForensicsFabricSettings) { f.Export.MaxExportBytes = 1024 }},
		{"auto-close beyond the range", func(f *ForensicsFabricSettings) { f.Cases.AutoCloseAfterHours = 99999 }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			payload := forensicsFabricPayload(t, settings, tc.mutate)
			rec := fabricRequest(t, server, http.MethodPost, "/api/v1/settings/forensics/preview", payload)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("unsafe configuration accepted: %d %s", rec.Code, rec.Body.String())
			}
			if settings.Get().Revision != 1 {
				t.Fatal("rejected preview mutated runtime settings")
			}
		})
	}
}

// TestForensicsCasePolicyGatesCreation covers the two switches that decide
// whether a case exists at all.
func TestForensicsCasePolicyGatesCreation(t *testing.T) {
	engine := &CaseEngine{}
	engine.ApplyPolicy(defaultForensicsFabricSettings().Cases)
	policy := engine.policySnapshot()
	if !policy.autoCreate || policy.minimumScore != 150 {
		t.Fatalf("defaults were not published: %+v", policy)
	}

	// A zero-valued revision must not be able to remove a bound.
	engine.ApplyPolicy(ForensicsCasesSettings{})
	guarded := engine.policySnapshot()
	if guarded.maxCases != 4096 || guarded.maxEvidence != 256 || guarded.maxObservations != 256 {
		t.Fatalf("a partial revision removed a budget: %+v", guarded)
	}
	if guarded.listMaxLimit != 500 || guarded.correlationMins != 60 {
		t.Fatalf("a partial revision removed a limit: %+v", guarded)
	}
}

// TestForensicsCorrelationWindowSplitsRecurrences proves the window bounds case
// accumulation instead of letting one target grow a case forever.
func TestForensicsCorrelationWindowSplitsRecurrences(t *testing.T) {
	now := time.Unix(1700000000, 0).UTC()
	policy := defaultForensicsFabricSettings().Cases.policy()
	record := SecurityCase{Status: "open", UpdatedAt: now.Add(-30 * time.Minute)}

	recent := XDRIncident{Time: now}
	if correlationExpired(record, recent, now, policy) {
		t.Fatal("an incident inside the window was treated as a new case")
	}
	late := XDRIncident{Time: now.Add(31 * time.Minute)}
	if !correlationExpired(record, late, now, policy) {
		t.Fatal("an incident outside the window did not start a new case")
	}
	// A wide window admits both.
	wide := policy
	wide.correlationMins = 1440
	if correlationExpired(record, late, now, wide) {
		t.Fatal("a widened window did not admit the later incident")
	}
}

func TestForensicsAutoCloseIsOptIn(t *testing.T) {
	now := time.Unix(1700000000, 0).UTC()
	policy := defaultForensicsFabricSettings().Cases.policy()
	record := SecurityCase{Status: "open", UpdatedAt: now.Add(-100 * time.Hour)}

	if autoCloseCandidate(record, now, policy) {
		t.Fatal("the default closed a case without being asked to")
	}
	policy.autoCloseHours = 72
	if !autoCloseCandidate(record, now, policy) {
		t.Fatal("a configured age did not select the idle case")
	}
	// A case an operator moved out of open is never touched.
	policy.autoCloseHours = 1
	record.Status = "resolved"
	if autoCloseCandidate(record, now, policy) {
		t.Fatal("the sweep touched a case that is not open")
	}
	record.Status = "open"
	record.UpdatedAt = now.Add(-30 * time.Minute)
	if autoCloseCandidate(record, now, policy) {
		t.Fatal("the sweep selected a case inside the inactivity window")
	}
}

// TestForensicsRedactionCoversInternalAddressesOnly proves the redaction is
// precise: it removes internal addressing and keeps the public indicators the
// export exists for.
func TestForensicsRedactionCoversInternalAddressesOnly(t *testing.T) {
	input := `{"target":"10.1.2.3","peer":"192.168.4.5","loop":"127.0.0.1",` +
		`"link":"fe80::1","cgnat":"100.64.9.9","public":"203.0.113.7","v6":"2001:db8::1"}`
	output := redactInternalIPs(input)

	for _, internal := range []string{"10.1.2.3", "192.168.4.5", "127.0.0.1", "fe80::1", "100.64.9.9"} {
		if strings.Contains(output, internal) {
			t.Errorf("internal address %s survived redaction: %s", internal, output)
		}
	}
	for _, public := range []string{"203.0.113.7", "2001:db8::1"} {
		if !strings.Contains(output, public) {
			t.Errorf("public indicator %s was removed: %s", public, output)
		}
	}
	// The token is stable, so two occurrences of one host stay correlated.
	repeated := redactInternalIPs(`{"a":"10.1.2.3","b":"10.1.2.3"}`)
	if strings.Count(repeated, "internal-") != 2 {
		t.Fatalf("repeated address was not tokenised consistently: %s", repeated)
	}
	first := redactInternalIPs(`"10.1.2.3"`)
	second := redactInternalIPs(`"10.1.2.3"`)
	if first != second {
		t.Fatal("the token is not deterministic across calls")
	}
	// A longer literal containing an address-shaped substring is left alone.
	untouched := redactInternalIPs(`{"v":"1.2.3.4.5"}`)
	if strings.Contains(untouched, "internal-") {
		t.Fatalf("a non-address literal was rewritten: %s", untouched)
	}
}

// TestForensicsExportShapingIsHonest covers the section switches, the boundary
// and the signing contract.
func TestForensicsExportShapingIsHonest(t *testing.T) {
	snapshot := Snapshot{
		Version: "4.2", NodeName: "node-a",
		Events:    []Event{{ID: "e1", Message: "blocked 10.0.0.9"}},
		Incidents: []XDRIncident{{ID: "i1"}},
	}

	full := defaultForensicsFabricSettings().Export
	shaped, err := shapeForensicsSnapshot(snapshot, full, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(shaped.Events) != 1 || shaped.NodeName != "node-a" {
		t.Fatal("a fully inclusive export dropped content")
	}

	// Section switches remove exactly their section.
	reduced := full
	reduced.IncludeRawRecords = false
	reduced.IncludeSystemMeta = false
	shaped, err = shapeForensicsSnapshot(snapshot, reduced, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(shaped.Events) != 0 || len(shaped.Incidents) != 0 {
		t.Fatal("raw records survived an exclusion")
	}
	if shaped.NodeName != "" || shaped.Version != "" {
		t.Fatal("system metadata survived an exclusion")
	}
	if shaped.NodeMode != snapshot.NodeMode {
		t.Fatal("an unrelated field was cleared")
	}

	// A required signature that cannot be produced refuses the export.
	if _, err := shapeForensicsSnapshot(snapshot, full, false); err == nil {
		t.Fatal("an unsigned export was produced while signatures are required")
	}
	unsigned := full
	unsigned.SigningRequired = false
	if _, err := shapeForensicsSnapshot(snapshot, unsigned, false); err != nil {
		t.Fatalf("an explicitly unsigned export was refused: %v", err)
	}

	// The boundary is enforced on the shaped document.
	tiny := full
	tiny.MaxExportBytes = 64 << 10
	large := snapshot
	large.Events = make([]Event, 0, 4000)
	for index := 0; index < 4000; index++ {
		large.Events = append(large.Events, Event{ID: strings.Repeat("a", 64), Message: strings.Repeat("b", 64)})
	}
	if _, err := shapeForensicsSnapshot(large, tiny, true); err == nil {
		t.Fatal("an oversized export was produced")
	}
}

// TestForensicsExportRouteHonoursPolicy proves the shaping is on the served path,
// not only in the helper.
func TestForensicsExportRouteHonoursPolicy(t *testing.T) {
	server, settings := forensicsFixture(t)

	// Redaction on: the served document must not contain the internal address.
	payload := forensicsFabricPayload(t, settings, func(f *ForensicsFabricSettings) { f.Export.RedactInternalIPs = true })
	if rec := fabricRequest(t, server, http.MethodPut, "/api/v1/settings/forensics", payload); rec.Code != http.StatusOK {
		t.Fatalf("apply status=%d body=%s", rec.Code, rec.Body.String())
	}
	exported := surfaceRequest(t, server, http.MethodGet, "/api/v1/forensics/export", nil)
	if exported.Code != http.StatusOK {
		t.Fatalf("export status=%d body=%s", exported.Code, exported.Body.String())
	}
	if got := exported.Header().Get("X-Gedefense-Signature"); got != "ed25519" {
		t.Fatalf("signed export did not announce its signature: %q", got)
	}
	if strings.Contains(exported.Body.String(), "127.0.0.1") {
		t.Fatal("a loopback address survived into the signed export")
	}

	// Signing waived: the response says so explicitly.
	payload = forensicsFabricPayload(t, settings, func(f *ForensicsFabricSettings) { f.Export.SigningRequired = false })
	if rec := fabricRequest(t, server, http.MethodPut, "/api/v1/settings/forensics", payload); rec.Code != http.StatusOK {
		t.Fatalf("apply status=%d body=%s", rec.Code, rec.Body.String())
	}
	unsigned := surfaceRequest(t, server, http.MethodGet, "/api/v1/forensics/export", nil)
	if unsigned.Code != http.StatusOK {
		t.Fatalf("unsigned export status=%d", unsigned.Code)
	}
	if got := unsigned.Header().Get("X-Gedefense-Signature"); got != "none" {
		t.Fatalf("unsigned export did not announce itself: %q", got)
	}
	var payloadBody struct {
		Signed bool `json:"signed"`
	}
	if err := json.Unmarshal(unsigned.Body.Bytes(), &payloadBody); err != nil {
		t.Fatal(err)
	}
	if payloadBody.Signed {
		t.Fatal("an unsigned export claimed to be signed")
	}
}

// TestForensicsDocumentWithoutNamespaceStillAuthenticates guards the migration
// path for a settings document written before the Forensics namespace existed.
func TestForensicsDocumentWithoutNamespaceStillAuthenticates(t *testing.T) {
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
	legacy.FabricVersion = 7
	legacy.Forensics = nil
	legacy.Kinetic.VelocityLimit = 111
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
		t.Fatalf("a pre-Forensics settings document was rejected: %v", err)
	}
	upgraded := reloaded.Get()
	if upgraded.FabricVersion != fabricSettingsVersion {
		t.Fatalf("schema version not upgraded: %d", upgraded.FabricVersion)
	}
	if upgraded.Forensics == nil {
		t.Fatal("the Forensics namespace was not seeded during the upgrade")
	}
	if upgraded.Kinetic.VelocityLimit != 111 {
		t.Fatal("existing operator tuning was lost during the upgrade")
	}
	if !upgraded.Forensics.Cases.AutoCreate || upgraded.Forensics.Cases.MinimumIncidentScore != 150 {
		t.Fatalf("case defaults were not seeded: %+v", upgraded.Forensics.Cases)
	}
	if len(upgraded.Forensics.Quarantine.ExtraForbidden) != 0 {
		t.Fatal("the upgrade added an unrequested denial")
	}
}

func TestFabricForensicsSchemaRegistryCoversEveryAdvertisedKey(t *testing.T) {
	server, settings := forensicsFixture(t)
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
	if !containsString(schema.Modules, "forensics") {
		t.Fatalf("schema does not advertise the Forensics module: %v", schema.Modules)
	}
	registered := map[string]FabricSettingMetadata{}
	for _, meta := range schema.Settings {
		if meta.Module == "forensics" {
			registered[meta.Key] = meta
		}
	}
	raw, err := json.Marshal(effectiveForensicsSettings(settings.Get()))
	if err != nil {
		t.Fatal(err)
	}
	var flat map[string]any
	if err := json.Unmarshal(raw, &flat); err != nil {
		t.Fatal(err)
	}
	for _, group := range []string{"cases", "export", "quarantine"} {
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
	// The module view must publish the immutable denylist, so the dashboard never
	// renders an allowlist without showing what can never be allowed.
	view := fabricRequest(t, server, http.MethodGet, "/api/v1/settings/forensics", nil)
	if view.Code != http.StatusOK {
		t.Fatalf("module view status=%d body=%s", view.Code, view.Body.String())
	}
	decoded := decodeFabricView(t, view.Body.Bytes())
	quarantine, ok := decoded.Details["quarantine"].(map[string]any)
	if !ok {
		t.Fatalf("module view carries no quarantine detail: %+v", decoded.Details)
	}
	builtin, ok := quarantine["builtin_forbidden"].([]any)
	if !ok || len(builtin) != len(quarantineBuiltinForbidden) {
		t.Fatalf("the immutable denylist is not published: %+v", quarantine)
	}
}
