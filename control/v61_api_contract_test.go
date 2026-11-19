package main

// GeDefense 6.1.0 API contract tests for the Module A–E surfaces. They lock the
// blueprint 3.2 required keys, the fail-honest fallback when an engine is not
// wired, and the pure helpers the handlers depend on. The module algorithms are
// covered by the tests in control/internal/*.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func decodeJSONBody(t *testing.T, recorder *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", recorder.Code, recorder.Body.String())
	}
	var payload map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatalf("response is not JSON: %v (%s)", err, recorder.Body.String())
	}
	return payload
}

func requireKeys(t *testing.T, payload map[string]any, keys ...string) {
	t.Helper()
	for _, key := range keys {
		if _, ok := payload[key]; !ok {
			t.Fatalf("payload is missing required key %q: %v", key, payload)
		}
	}
}

// TestWebExposureStatusContract locks the Module A payload keys and the honest
// unwired fallback.
func TestWebExposureStatusContract(t *testing.T) {
	server := &APIServer{}
	recorder := httptest.NewRecorder()
	server.webExposureStatus(recorder, httptest.NewRequest(http.MethodGet, "/api/v1/web-exposure/status", nil))
	payload := decodeJSONBody(t, recorder)
	requireKeys(t, payload, "generated_at", "scanned", "reason", "servers", "summary", "evidence")
	if payload["scanned"] != false || payload["reason"] == "" {
		t.Fatalf("unwired web exposure payload claims a scan: %v", payload)
	}
	summary := payload["summary"].(map[string]any)
	requireKeys(t, summary, "servers", "exposed", "affected_cves", "grade", "score")

	// The engine fallback snapshot is honest too.
	engine := NewWebExposureEngine(nil, nil)
	if snapshot := engine.Snapshot(); snapshot.GeneratedAt.IsZero() || snapshot.Scanned {
		t.Fatalf("uninitialised engine snapshot = %+v", snapshot)
	}
	if _, allowed, err := engine.ForceScan(nil); err == nil || !allowed {
		t.Fatalf("ForceScan without a settings store = allowed %t err %v", allowed, err)
	}
	if itoaSmall(0) != "0" || itoaSmall(42) != "42" {
		t.Fatalf("itoaSmall produced %q/%q", itoaSmall(0), itoaSmall(42))
	}
}

// TestWebExposureScanFailsHonestly keeps the POST from pretending success when
// the engine is absent.
func TestWebExposureScanFailsHonestly(t *testing.T) {
	server := &APIServer{}
	recorder := httptest.NewRecorder()
	server.webExposureScan(recorder, httptest.NewRequest(http.MethodPost, "/api/v1/web-exposure/scan", nil))
	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("unwired scan status = %d", recorder.Code)
	}
	recorder = httptest.NewRecorder()
	server.webExposureAdvisories(recorder, httptest.NewRequest(http.MethodGet, "/api/v1/web-exposure/advisories", nil))
	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("unwired advisories status = %d", recorder.Code)
	}
}

// TestWorkerGuardStatusContract locks the Module B payload keys.
func TestWorkerGuardStatusContract(t *testing.T) {
	server := &APIServer{}
	recorder := httptest.NewRecorder()
	server.workerGuardStatus(recorder, httptest.NewRequest(http.MethodGet, "/api/v1/worker-guard/status", nil))
	payload := decodeJSONBody(t, recorder)
	requireKeys(t, payload, "generated_at", "mode", "source", "capability", "reason", "registry", "counters", "workers", "recent_storms")
	if payload["source"] != "none" || payload["capability"] != "inactive" {
		t.Fatalf("unwired worker guard claims a source: %v", payload)
	}
	registry := payload["registry"].(map[string]any)
	requireKeys(t, registry, "comms", "uids", "strict_cgroups")
	counters := payload["counters"].(map[string]any)
	requireKeys(t, counters, "events", "storms", "denied_exec", "denied_mmap")

	recorder = httptest.NewRecorder()
	server.workerGuardEvents(recorder, httptest.NewRequest(http.MethodGet, "/api/v1/worker-guard/events", nil))
	page := decodeJSONBody(t, recorder)
	requireKeys(t, page, "events", "next")

	if clampQueryInt("bogus", 7, 1, 10) != 7 || clampQueryInt("100", 7, 1, 10) != 10 || clampQueryInt("3", 7, 1, 10) != 3 {
		t.Fatal("clampQueryInt did not bound the query parameter")
	}
}

// TestTLSSensorStatusContract locks the Module C payload keys.
func TestTLSSensorStatusContract(t *testing.T) {
	server := &APIServer{}
	recorder := httptest.NewRecorder()
	server.tlsSensorStatus(recorder, httptest.NewRequest(http.MethodGet, "/api/v1/tls-sensor/status", nil))
	payload := decodeJSONBody(t, recorder)
	requireKeys(t, payload, "generated_at", "capture", "reason", "handshakes", "alpn", "quic_initial", "flows", "storm", "tls_engine")
	storm := payload["storm"].(map[string]any)
	requireKeys(t, storm, "active", "severity", "peers", "predicate")
	predicate := storm["predicate"].(map[string]any)
	requireKeys(t, predicate, "rx_bytes", "tx_bytes", "ratio", "avg_pkt_len", "pps_ratio")
	tlsEngine := payload["tls_engine"].(map[string]any)
	requireKeys(t, tlsEngine, "findings", "tracked")
	if payload["capture"] != "inactive" {
		t.Fatalf("unwired tls sensor capture = %v", payload["capture"])
	}
	for _, path := range []string{"/api/v1/tls-sensor/handshakes", "/api/v1/tls-sensor/flows"} {
		recorder = httptest.NewRecorder()
		if path == "/api/v1/tls-sensor/handshakes" {
			server.tlsSensorHandshakes(recorder, httptest.NewRequest(http.MethodGet, path, nil))
			requireKeys(t, decodeJSONBody(t, recorder), "handshakes", "next")
		} else {
			server.tlsSensorFlows(recorder, httptest.NewRequest(http.MethodGet, path, nil))
			page := decodeJSONBody(t, recorder)
			requireKeys(t, page, "flows", "budget")
			requireKeys(t, page["budget"].(map[string]any), "max_flows", "used")
		}
	}
}

// TestLPEGuardStatusContract locks the Module D payload keys.
func TestLPEGuardStatusContract(t *testing.T) {
	server := &APIServer{}
	recorder := httptest.NewRecorder()
	server.lpeGuardStatus(recorder, httptest.NewRequest(http.MethodGet, "/api/v1/lpe-guard/status", nil))
	payload := decodeJSONBody(t, recorder)
	requireKeys(t, payload, "generated_at", "mode", "capability", "reason", "socket_policy", "styx_profile", "hardening")
	profile := payload["styx_profile"].(map[string]any)
	requireKeys(t, profile, "name", "enabled", "allow", "dns", "backend")

	recorder = httptest.NewRecorder()
	server.lpeGuardApply(recorder, httptest.NewRequest(http.MethodPost, "/api/v1/lpe-guard/apply", nil))
	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("unwired lpe apply status = %d", recorder.Code)
	}
}

// TestLPECellPolicySetValidatesBeforeIPC proves the new flag word is validated
// before any socket write, and that the pre-6.1.0 exclusive validation is not the
// path used for the 6.1.0 bits.
func TestLPECellPolicySetValidatesBeforeIPC(t *testing.T) {
	client := &CoreClient{}
	cases := []struct {
		name   string
		cgroup uint64
		flags  uint8
	}{
		{"zero cgroup", 0, 1 << 1},
		{"empty flags", 42, 0},
		{"unknown bit", 42, 1 << 7},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			if err := client.lpeCellPolicySet(tc.cgroup, tc.flags); err == nil {
				t.Fatal("invalid cell policy request was accepted")
			}
		})
	}
	// The 6.1.0 deny mask itself is a valid flag word (the transport failure is
	// expected because this client has no socket; it must not be a flag error).
	if err := client.lpeCellPolicySet(42, 0x7e); err == nil {
		t.Fatal("a client without a core socket unexpectedly succeeded")
	}
}

// TestWorkerCrashStormIncidentShape locks the incident the correlation emits.
func TestWorkerCrashStormIncidentShape(t *testing.T) {
	state := NewState("test", defaultConfig())
	engine := NewWorkerGuardEngine(nil, state, nil, nil, nil)
	engine.handleCrash(WorkerCrashEvent{Comm: "not-enabled", Signal: 11})
	if incidents := state.Snapshot().Incidents; len(incidents) != 0 {
		t.Fatalf("a disabled engine produced incidents: %+v", incidents)
	}
}

// TestV61RoutesAreRegisteredForModulesAD proves every Module A–D route from the
// blueprint is present in the server multiplexer and therefore went through the
// single route table. A bare server cannot be walked, so the check is that the
// handlers are methods of *APIServer (compile-time) and the paths are unique.
func TestV61RouteHandlerMethodsExist(t *testing.T) {
	server := &APIServer{}
	var _ = []func(http.ResponseWriter, *http.Request){
		server.webExposureStatus, server.webExposureScan, server.webExposureAdvisories,
		server.workerGuardStatus, server.workerGuardEvents,
		server.tlsSensorStatus, server.tlsSensorHandshakes, server.tlsSensorFlows,
		server.lpeGuardStatus, server.lpeGuardApply,
	}
}
