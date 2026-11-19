package main

// GeDefense 6.1.0 Fabric Settings namespace tests. The pure-package tests cover
// the algorithms; these lock the persisted contract: defaults validate, a v17
// document receives exactly the five new namespaces with inert defaults and one
// migration record each, an existing v18 namespace is never overwritten, and the
// snapshot/decode path round-trips for every new module.

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestV61DefaultNamespacesAreValidAndInert(t *testing.T) {
	cfg := defaultConfig()
	settings := defaultRuntimeSettings(cfg)
	if err := validateRuntimeSettings(&settings); err != nil {
		t.Fatalf("default 6.1.0 namespaces are invalid: %v", err)
	}
	if settings.FabricVersion != 18 {
		t.Fatalf("fabric settings version = %d, want 18", settings.FabricVersion)
	}
	for name, present := range map[string]bool{
		"web_exposure": settings.WebExposure != nil,
		"worker_guard": settings.WorkerGuard != nil,
		"tls_sensor":   settings.TLSSensor != nil,
		"lpe_guard":    settings.LPEGuard != nil,
		"edge_proxy":   settings.EdgeProxy != nil,
	} {
		if !present {
			t.Fatalf("default runtime settings carry no %s namespace", name)
		}
	}
	if !settings.WebExposure.Enabled || !settings.WebExposure.ProbeLoopbackALPN {
		t.Fatalf("web exposure default is not the read-only sensor: %+v", settings.WebExposure)
	}
	if settings.WorkerGuard.Enabled || settings.TLSSensor.Enabled || settings.LPEGuard.Enabled || settings.EdgeProxy.Enabled {
		t.Fatal("a 6.1.0 enforcement namespace defaults to enabled")
	}
	if !settings.TLSSensor.AlertOnly {
		t.Fatal("tls sensor is not alert-only by default")
	}
	for module := range map[string]bool{"web_exposure": true, "worker_guard": true, "tls_sensor": true, "lpe_guard": true, "edge_proxy": true} {
		if _, ok := fabricModuleName(module); !ok {
			t.Fatalf("fabricModuleName rejects %q", module)
		}
		if _, err := fabricModuleSnapshot(settings, module); err != nil {
			t.Fatalf("module %q has no snapshot: %v", module, err)
		}
	}
}

func TestV61MigrationSeedsFiveNamespacesFromV17(t *testing.T) {
	defaults := defaultRuntimeSettings(defaultConfig())
	legacy := defaults
	legacy.FabricVersion = 17
	// A v17 document knows only the pre-6.1.0 namespaces.
	legacy.WebExposure = nil
	legacy.WorkerGuard = nil
	legacy.TLSSensor = nil
	legacy.LPEGuard = nil
	legacy.EdgeProxy = nil
	legacy.Migrations = nil
	if upgraded := upgradeRuntimeSettings(&legacy, defaults); !upgraded {
		t.Fatal("a v17 document was not upgraded")
	}
	if legacy.FabricVersion != fabricSettingsVersion {
		t.Fatalf("schema version = %d, want %d", legacy.FabricVersion, fabricSettingsVersion)
	}
	if legacy.WebExposure == nil || legacy.WorkerGuard == nil || legacy.TLSSensor == nil || legacy.LPEGuard == nil || legacy.EdgeProxy == nil {
		t.Fatalf("v18 upgrade did not seed every namespace: %+v", legacy)
	}
	if legacy.WorkerGuard.Enabled || legacy.TLSSensor.Enabled || legacy.LPEGuard.Enabled || legacy.EdgeProxy.Enabled {
		t.Fatal("v18 upgrade seeded an enforcement namespace enabled")
	}
	if err := validateRuntimeSettings(&legacy); err != nil {
		t.Fatalf("upgraded document is invalid: %v", err)
	}
	named := strings.Join(legacy.Migrations, "\n")
	for _, namespace := range []string{"web_exposure", "worker_guard", "tls_sensor", "lpe_guard", "edge_proxy"} {
		if !strings.Contains(named, namespace+" namespace added") {
			t.Fatalf("the v18 upgrade did not record the %s namespace: %q", namespace, legacy.Migrations)
		}
	}
	if len(legacy.Migrations) != 5 {
		t.Fatalf("v17->v18 recorded %d migrations, want 5: %v", len(legacy.Migrations), legacy.Migrations)
	}
}

func TestV61MigrationNeverOverwritesOperatorValues(t *testing.T) {
	defaults := defaultRuntimeSettings(defaultConfig())
	legacy := defaultRuntimeSettings(defaultConfig())
	legacy.FabricVersion = 17
	custom := WorkerGuardFabricSettings{
		Enabled: true, Comms: []string{"php-fpm"}, UIDs: []uint32{33},
		ExcludeUnits: []string{"master"}, StormThreshold: 7, StormWindowSeconds: 120,
		CorrelatePeers: false, StrictExec: false, StrictMmap: false, AutoApplyStrict: false,
	}
	legacy.WorkerGuard = &custom
	legacy.WebExposure = nil
	legacy.TLSSensor = nil
	legacy.LPEGuard = nil
	legacy.EdgeProxy = nil
	if upgraded := upgradeRuntimeSettings(&legacy, defaults); !upgraded {
		t.Fatal("a v17 document was not upgraded")
	}
	if legacy.WorkerGuard == nil || !legacy.WorkerGuard.Enabled || legacy.WorkerGuard.StormThreshold != 7 {
		t.Fatalf("an existing namespace was overwritten by the upgrade: %+v", legacy.WorkerGuard)
	}
	// A current document accumulates no migration note.
	current := defaultRuntimeSettings(defaultConfig())
	current.Migrations = nil
	if upgraded := upgradeRuntimeSettings(&current, defaults); upgraded {
		t.Fatal("a current v18 document was upgraded again")
	}
	if len(current.Migrations) != 0 {
		t.Fatalf("a current document accumulated migration notes: %v", current.Migrations)
	}
}

func TestV61NamespaceValidationBounds(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		mutate func(*RuntimeSettings)
		reject bool
	}{
		{"web scan interval below minimum", func(s *RuntimeSettings) { s.WebExposure.ScanIntervalSeconds = 1 }, true},
		{"web max servers above maximum", func(s *RuntimeSettings) { s.WebExposure.MaxServers = 1024 }, true},
		{"web relative config root", func(s *RuntimeSettings) { s.WebExposure.ConfigRoots = []string{"etc/nginx"} }, true},
		{"web extra advisories malformed", func(s *RuntimeSettings) { s.WebExposure.ExtraAdvisoriesJSON = json.RawMessage(`{"id":"x"}`) }, true},
		{"worker storm threshold below minimum", func(s *RuntimeSettings) { s.WorkerGuard.StormThreshold = 1 }, true},
		{"worker strict without enable", func(s *RuntimeSettings) { s.WorkerGuard.StrictExec = true }, true},
		{"worker auto apply without strict", func(s *RuntimeSettings) { s.WorkerGuard.Enabled = true; s.WorkerGuard.AutoApplyStrict = true }, true},
		{"worker comm too long", func(s *RuntimeSettings) { s.WorkerGuard.Comms = []string{"this-comm-is-way-too-long"} }, true},
		{"tls empty ports", func(s *RuntimeSettings) { s.TLSSensor.Ports = []uint16{} }, true},
		{"tls payload below minimum", func(s *RuntimeSettings) { s.TLSSensor.MaxPayloadBytes = 16 }, true},
		{"tls threshold above maximum", func(s *RuntimeSettings) { s.TLSSensor.RxThresholdBytes = 9 << 30 }, true},
		{"lpe bad backend cidr", func(s *RuntimeSettings) { s.LPEGuard.StyxBackendCIDRs = []string{"banana"} }, true},
		{"lpe styx profile without enable", func(s *RuntimeSettings) { s.LPEGuard.StyxProfile = true }, true},
		{"edge public listen", func(s *RuntimeSettings) { s.EdgeProxy.Listen = "0.0.0.0:8443" }, true},
		{"edge https upstream", func(s *RuntimeSettings) { s.EdgeProxy.Upstream = "https://127.0.0.1:8080" }, true},
		{"edge missing upstream port", func(s *RuntimeSettings) { s.EdgeProxy.Upstream = "http://127.0.0.1" }, true},
		{"edge cert without key", func(s *RuntimeSettings) { s.EdgeProxy.CertFile = "/etc/ssl/edge.pem" }, true},
		{"edge unknown method", func(s *RuntimeSettings) { s.EdgeProxy.AllowedMethods = []string{"TRACE"} }, true},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			settings := defaultRuntimeSettings(defaultConfig())
			tc.mutate(&settings)
			err := validateRuntimeSettings(&settings)
			if gotReject := err != nil; gotReject != tc.reject {
				t.Fatalf("validation reject=%t err=%v", gotReject, err)
			}
		})
	}
	if err := validateRuntimeSettings(ptr(defaultRuntimeSettings(defaultConfig()))); err != nil {
		t.Fatalf("untouched defaults are invalid: %v", err)
	}
}

func TestV61NamespaceSnapshotDecodeRoundTrip(t *testing.T) {
	defaults := defaultRuntimeSettings(defaultConfig())
	for _, module := range []string{"web_exposure", "worker_guard", "tls_sensor", "lpe_guard", "edge_proxy"} {
		snapshot, err := fabricModuleSnapshot(defaults, module)
		if err != nil {
			t.Fatalf("%s snapshot: %v", module, err)
		}
		raw, err := json.Marshal(snapshot)
		if err != nil {
			t.Fatalf("%s marshal: %v", module, err)
		}
		next := cloneRuntimeSettings(defaults)
		if err := decodeModuleSettings(raw, module, &next); err != nil {
			t.Fatalf("%s decode: %v", module, err)
		}
		if err := validateRuntimeSettings(&next); err != nil {
			t.Fatalf("%s decoded document is invalid: %v", module, err)
		}
		again, err := fabricModuleSnapshot(next, module)
		if err != nil {
			t.Fatalf("%s second snapshot: %v", module, err)
		}
		first, _ := json.Marshal(snapshot)
		second, _ := json.Marshal(again)
		if string(first) != string(second) {
			t.Fatalf("%s round trip changed the namespace:\nfirst=%s\nsecond=%s", module, first, second)
		}
	}
}

// TestV61ApplyStateIsHonestWithoutEngines locks the fail-honest rule: an enabled
// module without an engine reports engine_unavailable, never "applied"; a
// deliberately disabled namespace reports "disabled" even without an engine.
func TestV61ApplyStateIsHonestWithoutEngines(t *testing.T) {
	settings := defaultRuntimeSettings(defaultConfig())
	server := &APIServer{}
	cases := map[string]string{
		"web_exposure": "engine_unavailable", // enabled read-only default
		"worker_guard": "disabled",
		"tls_sensor":   "disabled",
		"lpe_guard":    "disabled",
		"edge_proxy":   "disabled",
	}
	for module, want := range cases {
		state, handled := server.v61ModuleApplyState(settings, module)
		if !handled {
			t.Fatalf("%s is not handled by the 6.1.0 apply-state layer", module)
		}
		if state != want {
			t.Fatalf("%s without an engine = %q, want %q", module, state, want)
		}
	}
	// A disabled namespace is "disabled" even with an engine attached.
	disabled := settings
	disabled.WebExposure = &WebExposureFabricSettings{ExtraAdvisoriesJSON: json.RawMessage(`[]`)}
	server.v61 = &V61Engines{webExposure: NewWebExposureEngine(nil, nil)}
	if state, _ := server.v61ModuleApplyState(disabled, "web_exposure"); state != "disabled" {
		t.Fatalf("disabled web_exposure apply state = %q", state)
	}
}

func TestV61EdgeProxyApplyStateToleratesDisabledAndEnabled(t *testing.T) {
	settings := defaultRuntimeSettings(defaultConfig())
	server := &APIServer{}
	if state, handled := server.v61ModuleApplyState(settings, "edge_proxy"); !handled || state != "disabled" {
		t.Fatalf("edge proxy default = %q/%t", state, handled)
	}
	enabled := defaultRuntimeSettings(defaultConfig())
	enabled.EdgeProxy.Enabled = true
	// The Module E runtime hook is implemented by control/edge_proxy.go. A bare
	// test server has no listener and no settings store, so the answer must stay
	// inside the honest vocabulary and must never claim the listener is applied.
	state, handled := server.v61ModuleApplyState(enabled, "edge_proxy")
	if !handled {
		t.Fatal("edge_proxy is not handled by the 6.1.0 apply-state layer")
	}
	switch state {
	case "disabled", "engine_unavailable", "reload_pending":
	default:
		t.Fatalf("bare server claimed edge proxy state %q", state)
	}
}

func ptr(settings RuntimeSettings) *RuntimeSettings { return &settings }
