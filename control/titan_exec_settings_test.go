// STATUS: DIAMANT VGT SUPREME
package main

// POINT 1 / P1-T2 tests: Titan exec-gate settings namespace, its v14 migration,
// reject-not-repair validation, the Fabric Settings module surface and the honest
// apply-state mapping.

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func titanExecSettingsFixture() TitanExecFabricSettings {
	return TitanExecFabricSettings{
		Enabled:       true,
		Mode:          TitanExecModeObserve,
		ExecRoots:     []string{"/usr/local/bin", "/opt/app/bin"},
		AllowPaths:    []string{"/opt/app/lib/helper"},
		DevRoots:      []string{"/home/developer/src"},
		JitCgroups:    []uint64{200},
		StrictCgroups: []uint64{100},
		MaxEntries:    4096,
		MaxScopes:     64,
		RequireCtime:  true,
	}
}

func TestTitanExecSettingsDefaultsKeepUpgradeBehaviour(t *testing.T) {
	cfg := defaultConfig()
	defaults := defaultRuntimeSettings(cfg)
	if defaults.TitanExec == nil {
		t.Fatal("a fresh settings document carries no TitanExec namespace")
	}
	if defaults.TitanExec.Enabled || defaults.TitanExec.Mode != TitanExecModeOff {
		t.Fatalf("the TitanExec default must not change kernel behaviour: %+v", *defaults.TitanExec)
	}
	if len(defaults.TitanExec.ExecRoots) != 0 || len(defaults.TitanExec.AllowPaths) != 0 ||
		len(defaults.TitanExec.DevRoots) != 0 || len(defaults.TitanExec.JitCgroups) != 0 || len(defaults.TitanExec.StrictCgroups) != 0 {
		t.Fatalf("the TitanExec default carries rules: %+v", *defaults.TitanExec)
	}
	if defaults.TitanExec.MaxEntries != titanExecDefaultMaxEntries || defaults.TitanExec.MaxScopes != titanExecDefaultMaxScopes {
		t.Fatalf("the TitanExec default bounds are wrong: %+v", *defaults.TitanExec)
	}
	if defaults.TitanExec.RequireCtime {
		t.Fatal("the TitanExec default enables the ctime re-check")
	}
	if err := validateRuntimeSettings(&defaults); err != nil {
		t.Fatalf("default runtime settings are invalid: %v", err)
	}

	// The real upgrade path ships from a v13 document: the namespace is seeded and
	// the migration note names it, because the operator sees new fields appear.
	legacy := defaultRuntimeSettings(cfg)
	legacy.FabricVersion = 13
	legacy.TitanExec = nil
	legacy.Migrations = nil
	if !upgradeRuntimeSettings(&legacy, defaults) {
		t.Fatal("a v13 document was not upgraded")
	}
	if legacy.TitanExec == nil || legacy.TitanExec.Enabled || legacy.TitanExec.Mode != TitanExecModeOff {
		t.Fatalf("upgrade did not seed the disabled namespace: %+v", legacy.TitanExec)
	}
	if legacy.FabricVersion != fabricSettingsVersion {
		t.Fatalf("document stayed at version %d", legacy.FabricVersion)
	}
	if len(legacy.Migrations) != 1 {
		t.Fatalf("a v13 upgrade must record exactly the new namespace, got %v", legacy.Migrations)
	}
	note := legacy.Migrations[0]
	if !strings.Contains(note, "titan_exec namespace") || !strings.Contains(note, "enabled=false") || !strings.Contains(note, "mode=off") {
		t.Fatalf("the migration did not record the new namespace honestly: %q", note)
	}

	// A v12 document receives the StyX namespace with a note, but the TitanExec seed
	// must stay silent for it (the established additive-module contract).
	v12 := defaultRuntimeSettings(cfg)
	v12.FabricVersion = 12
	v12.TitanExec = nil
	v12.Styx = nil
	v12.Migrations = nil
	if !upgradeRuntimeSettings(&v12, defaults) {
		t.Fatal("a v12 document was not upgraded")
	}
	if v12.TitanExec == nil || v12.TitanExec.Enabled {
		t.Fatalf("v12 upgrade did not seed the disabled TitanExec namespace: %+v", v12.TitanExec)
	}
	if joined := strings.Join(v12.Migrations, " "); strings.Contains(joined, "titan_exec namespace") {
		t.Fatalf("a pre-v13 document accumulated a TitanExec migration note: %v", v12.Migrations)
	}

	// Ancient documents receive several namespaces at once and no notes at all.
	ancient := RuntimeSettings{FabricVersion: 9}
	if !upgradeRuntimeSettings(&ancient, defaults) {
		t.Fatal("an ancient document was not upgraded")
	}
	if ancient.TitanExec == nil || ancient.TitanExec.Enabled || ancient.TitanExec.Mode != TitanExecModeOff {
		t.Fatalf("ancient upgrade did not seed the disabled namespace: %+v", ancient.TitanExec)
	}
	if len(ancient.Migrations) != 0 {
		t.Fatalf("ancient upgrade invented migration notes: %v", ancient.Migrations)
	}
}

// A document persisted before the namespace existed must still serialise without the
// field, otherwise its MAC stops authenticating on upgrade.
func TestTitanExecSettingsJSONStaysCompatibleWithExistingDocuments(t *testing.T) {
	legacy := RuntimeSettings{FabricVersion: 13}
	encoded, err := json.Marshal(legacy)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "titan_exec") {
		t.Fatalf("a nil TitanExec namespace was serialised: %s", encoded)
	}
	withNamespace := defaultRuntimeSettings(defaultConfig())
	encoded, err = json.Marshal(withNamespace)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(encoded), `"titan_exec"`) {
		t.Fatalf("the TitanExec namespace is not covered by the document: %s", encoded)
	}
}

func TestTitanExecFabricSettingsCloneIsDeep(t *testing.T) {
	settings := defaultRuntimeSettings(defaultConfig())
	fixture := titanExecSettingsFixture()
	settings.TitanExec = &fixture
	clone := cloneRuntimeSettings(settings)
	clone.TitanExec.ExecRoots[0] = "/tmp/other"
	clone.TitanExec.AllowPaths[0] = "/tmp/other"
	clone.TitanExec.DevRoots[0] = "/tmp/other"
	clone.TitanExec.JitCgroups[0] = 999
	clone.TitanExec.StrictCgroups[0] = 999
	if settings.TitanExec.ExecRoots[0] != "/usr/local/bin" || settings.TitanExec.AllowPaths[0] != "/opt/app/lib/helper" ||
		settings.TitanExec.DevRoots[0] != "/home/developer/src" || settings.TitanExec.JitCgroups[0] != 200 ||
		settings.TitanExec.StrictCgroups[0] != 100 {
		t.Fatal("cloneRuntimeSettings shared TitanExec slices with the source document")
	}
}

func TestTitanExecFabricSettingsValidationRejectsHostileInput(t *testing.T) {
	valid := titanExecSettingsFixture()
	cases := map[string]func(*TitanExecFabricSettings){
		"bad-mode":          func(s *TitanExecFabricSettings) { s.Mode = "blocked" },
		"off-with-rules":    func(s *TitanExecFabricSettings) { s.Mode = TitanExecModeOff },
		"strict-no-sources": func(s *TitanExecFabricSettings) { s.Mode = TitanExecModeStrict; s.ExecRoots = nil; s.AllowPaths = nil },
		"relative-path":     func(s *TitanExecFabricSettings) { s.ExecRoots = []string{"usr/bin"} },
		"non-canonical":     func(s *TitanExecFabricSettings) { s.ExecRoots = []string{"/usr/../usr/bin"} },
		"trailing-slash":    func(s *TitanExecFabricSettings) { s.AllowPaths = []string{"/usr/bin/"} },
		"path-with-space":   func(s *TitanExecFabricSettings) { s.AllowPaths = []string{"/opt/my app/bin"} },
		"path-with-nul":     func(s *TitanExecFabricSettings) { s.AllowPaths = []string{"/opt/app\x00bin"} },
		"path-with-control": func(s *TitanExecFabricSettings) { s.DevRoots = []string{"/home/dev\x1f/src"} },
		"path-too-long": func(s *TitanExecFabricSettings) {
			s.ExecRoots = []string{"/" + strings.Repeat("a", titanExecMaxPathBytes)}
		},
		"duplicate-path":   func(s *TitanExecFabricSettings) { s.ExecRoots = []string{"/usr/bin", "/usr/bin"} },
		"zero-cgroup":      func(s *TitanExecFabricSettings) { s.JitCgroups = []uint64{0} },
		"duplicate-cgroup": func(s *TitanExecFabricSettings) { s.StrictCgroups = []uint64{7, 7} },
		"scopes-over-bound": func(s *TitanExecFabricSettings) {
			s.MaxScopes = 1
			s.JitCgroups = []uint64{7}
			s.StrictCgroups = []uint64{9}
		},
		"zero-max-entries": func(s *TitanExecFabricSettings) { s.MaxEntries = 0 },
		"max-entries-cap":  func(s *TitanExecFabricSettings) { s.MaxEntries = titanExecMaxPolicyEntries + 1 },
		"zero-max-scopes":  func(s *TitanExecFabricSettings) { s.MaxScopes = 0 },
		"max-scopes-cap":   func(s *TitanExecFabricSettings) { s.MaxScopes = titanExecMaxPolicyScopes + 1 },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			candidate := cloneTitanExecFabricSettings(valid)
			mutate(&candidate)
			if err := validateTitanExecFabricSettings(&candidate); err == nil {
				t.Fatalf("hostile TitanExec settings were accepted: %+v", candidate)
			}
		})
	}
	tooManyRoots := cloneTitanExecFabricSettings(valid)
	tooManyRoots.ExecRoots = make([]string, titanExecMaxExecRoots+1)
	for index := range tooManyRoots.ExecRoots {
		tooManyRoots.ExecRoots[index] = "/opt/root" + string(rune('a'+index%26)) + "/" + strings.Repeat("x", index%8)
	}
	if err := validateTitanExecFabricSettings(&tooManyRoots); err == nil {
		t.Fatal("exec root cap was not enforced")
	}
}

func TestTitanExecFabricSettingsValidationCanonicalises(t *testing.T) {
	settings := TitanExecFabricSettings{
		Enabled:       true,
		Mode:          " STRICT ",
		ExecRoots:     []string{"/usr/local/bin", "/usr/bin"},
		AllowPaths:    []string{"/opt/app/bin/tool"},
		DevRoots:      []string{"/home/dev/src"},
		JitCgroups:    []uint64{300, 100},
		StrictCgroups: []uint64{200, 100},
		MaxEntries:    1024,
		MaxScopes:     32,
		RequireCtime:  true,
	}
	if err := validateTitanExecFabricSettings(&settings); err != nil {
		t.Fatal(err)
	}
	if settings.Mode != TitanExecModeStrict {
		t.Fatalf("mode was not normalised: %q", settings.Mode)
	}
	if len(settings.ExecRoots) != 2 || settings.ExecRoots[0] != "/usr/bin" || settings.ExecRoots[1] != "/usr/local/bin" {
		t.Fatalf("exec roots were not sorted: %v", settings.ExecRoots)
	}
	if len(settings.JitCgroups) != 2 || settings.JitCgroups[0] != 100 || settings.JitCgroups[1] != 300 {
		t.Fatalf("JIT cgroups were not sorted: %v", settings.JitCgroups)
	}
	if !settings.RequireCtime || titanExecGlobalFlags(settings) != titanExecGlobalFlagRequireCtime {
		t.Fatal("require_ctime was not projected onto the global flags")
	}
}

// A disabled namespace may carry a draft (nothing is claimed), but an enabled
// namespace with mode=off and rules is the inert policy §7.1 forbids.
func TestTitanExecFabricSettingsRejectsInertModeOffPolicy(t *testing.T) {
	enabled := titanExecSettingsFixture()
	enabled.Mode = TitanExecModeOff
	err := validateTitanExecFabricSettings(&enabled)
	if err == nil || !strings.Contains(err.Error(), "mode=off") {
		t.Fatalf("inert mode=off policy was not refused visibly: %v", err)
	}
	draft := titanExecSettingsFixture()
	draft.Mode = TitanExecModeOff
	draft.Enabled = false
	if err := validateTitanExecFabricSettings(&draft); err != nil {
		t.Fatalf("disabled draft settings were rejected: %v", err)
	}
	clean := TitanExecFabricSettings{Enabled: true, Mode: TitanExecModeOff, MaxEntries: 8192, MaxScopes: 256}
	if err := validateTitanExecFabricSettings(&clean); err != nil {
		t.Fatalf("clean off settings were rejected: %v", err)
	}
	if _, planErr := compileTitanExecPolicyPlan(nil, enabled, titanExecPlanDeps{}); planErr == nil {
		t.Fatal("plan compiler (sync path) accepted an inert mode=off policy")
	}
}

func TestTitanExecEffectiveSettingsResolveDisabledAndBounds(t *testing.T) {
	disabled := defaultRuntimeSettings(defaultConfig())
	if got := effectiveTitanExecFabricSettings(disabled); got.Enabled || got.Mode != TitanExecModeOff {
		t.Fatalf("default namespace is not effective off: %+v", got)
	}
	draft := titanExecSettingsFixture()
	draft.Enabled = false
	container := defaultRuntimeSettings(defaultConfig())
	container.TitanExec = &draft
	if got := effectiveTitanExecFabricSettings(container); got.Mode != TitanExecModeOff {
		t.Fatalf("disabled namespace did not resolve to mode off: %+v", got)
	}
	// Defensive bounds: a hand-built struct must never reach the plan compiler with a
	// zero or oversized bound.
	zero := defaultRuntimeSettings(defaultConfig())
	empty := TitanExecFabricSettings{Enabled: true, Mode: TitanExecModeObserve}
	zero.TitanExec = &empty
	if got := effectiveTitanExecFabricSettings(zero); got.MaxEntries != titanExecDefaultMaxEntries || got.MaxScopes != titanExecDefaultMaxScopes {
		t.Fatalf("zero bounds were not guarded: %+v", got)
	}
}

func TestTitanExecModuleApplyStateIsHonest(t *testing.T) {
	settings := defaultRuntimeSettings(defaultConfig())
	enabledFixture := titanExecSettingsFixture()
	disabledFixture := defaultTitanExecFabricSettings()
	settings.TitanExec = &disabledFixture
	if got := titanExecModuleApplyState(settings, titanExecUnavailableStatus(), false); got != "applied" {
		t.Fatalf("disabled unwired module reports %q, want applied", got)
	}
	settings.TitanExec = &enabledFixture
	if got := titanExecModuleApplyState(settings, titanExecUnavailableStatus(), false); got != "engine_unavailable" {
		t.Fatalf("enabled unwired module reports %q, want engine_unavailable", got)
	}
	applied := TitanExecSyncStatus{State: TitanExecSyncStateApplied, Enabled: true, Mode: TitanExecModeObserve}
	if got := titanExecModuleApplyState(settings, applied, true); got != "applied" {
		t.Fatalf("matched applied status reports %q", got)
	}
	mismatched := applied
	mismatched.Mode = TitanExecModeOff
	if got := titanExecModuleApplyState(settings, mismatched, true); got != "reload_pending" {
		t.Fatalf("stale mode reports %q, want reload_pending", got)
	}
	for _, state := range []string{TitanExecSyncStateCapabilityMissing, TitanExecSyncStateInactive, TitanExecSyncStateUnavailable} {
		sync := TitanExecSyncStatus{State: state, Enabled: true, Mode: TitanExecModeObserve}
		if got := titanExecModuleApplyState(settings, sync, true); got != "engine_unavailable" {
			t.Fatalf("state %q reports %q, want engine_unavailable", state, got)
		}
	}
	if got := titanExecModuleApplyState(settings, TitanExecSyncStatus{State: TitanExecSyncStateFailed}, true); got != "reload_pending" {
		t.Fatalf("failed sync reports %q, want reload_pending", got)
	}
	if got := titanExecModuleApplyState(settings, TitanExecSyncStatus{State: TitanExecSyncStatePending}, true); got != "reload_pending" {
		t.Fatalf("pending sync reports %q, want reload_pending", got)
	}
}

// TestTitanExecFabricModuleSurface pins the settings module wiring: the schema
// publishes the module, the snapshot round-trips and validation rejects hostile
// values before persistence.
func TestTitanExecFabricModuleSurface(t *testing.T) {
	server, store, _ := settingsAPIFixture(t)
	current := store.Get()
	if current.TitanExec == nil {
		t.Fatal("the settings document has no TitanExec namespace")
	}
	snapshot, err := fabricModuleSnapshot(current, "titan_exec")
	if err != nil {
		t.Fatalf("module snapshot: %v", err)
	}
	if !strings.Contains(string(mustJSON(t, snapshot)), `"max_entries":8192`) {
		t.Fatalf("snapshot does not expose the namespace: %s", mustJSON(t, snapshot))
	}
	rec := fabricRequest(t, server, http.MethodGet, "/api/v1/settings/titan_exec", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("module GET returned %d: %s", rec.Code, rec.Body.String())
	}
	var view FabricModuleView
	if err := json.Unmarshal(rec.Body.Bytes(), &view); err != nil {
		t.Fatal(err)
	}
	if view.Module != "titan_exec" || view.ApplyState != "applied" {
		t.Fatalf("default module view is wrong: %+v", view)
	}

	invalid := titanExecSettingsFixture()
	invalid.ExecRoots = []string{"relative/bin"}
	payload := mustJSON(t, map[string]any{"expected_revision": current.Revision, "settings": invalid})
	if rec := fabricRequest(t, server, http.MethodPut, "/api/v1/settings/titan_exec", payload); rec.Code != http.StatusBadRequest {
		t.Fatalf("invalid TitanExec module apply returned %d: %s", rec.Code, rec.Body.String())
	}
	valid := titanExecSettingsFixture()
	payload = mustJSON(t, map[string]any{"expected_revision": current.Revision, "settings": valid})
	if rec := fabricRequest(t, server, http.MethodPut, "/api/v1/settings/titan_exec", payload); rec.Code != http.StatusOK {
		t.Fatalf("valid TitanExec module apply returned %d: %s", rec.Code, rec.Body.String())
	}
	updated := store.Get()
	if updated.TitanExec == nil || updated.TitanExec.Mode != TitanExecModeObserve || len(updated.TitanExec.ExecRoots) != 2 {
		t.Fatalf("TitanExec settings were not persisted: %+v", updated.TitanExec)
	}

	rec = fabricRequest(t, server, http.MethodGet, "/api/v1/settings/schema", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("schema endpoint returned %d", rec.Code)
	}
	var schemaPayload struct {
		Modules  []string                `json:"modules"`
		Settings []FabricSettingMetadata `json:"settings"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &schemaPayload); err != nil {
		t.Fatal(err)
	}
	advertised := false
	for _, module := range schemaPayload.Modules {
		if module == "titan_exec" {
			advertised = true
		}
	}
	if !advertised {
		t.Fatal("the schema endpoint does not publish the titan_exec module")
	}
	keys := map[string]bool{}
	for _, meta := range schemaPayload.Settings {
		if meta.Module != "titan_exec" {
			continue
		}
		if meta.Risk == "" || meta.ApplyClass == "" || meta.Description == "" || meta.Type == "" {
			t.Fatalf("titan_exec setting %q has incomplete metadata: %+v", meta.Key, meta)
		}
		keys[meta.Key] = true
	}
	for _, want := range []string{"enabled", "mode", "exec_roots", "allow_paths", "dev_roots", "jit_cgroups", "strict_cgroups", "max_entries", "max_scopes", "require_ctime"} {
		if !keys[want] {
			t.Fatalf("titan_exec schema is missing %q", want)
		}
	}
}

func mustJSON(t *testing.T, value any) []byte {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}
