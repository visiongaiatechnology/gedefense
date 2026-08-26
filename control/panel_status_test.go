// STATUS: DIAMANT VGT SUPREME
package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func newPanelStatusServer() (*APIServer, *State) {
	cfg := defaultConfig()
	state := NewState("test", cfg)
	return NewAPIServer(
		cfg,
		state,
		nil,
		nil,
		nil,
		nil,
		nil,
		nil,
		"0123456789abcdef0123456789abcdef",
	), state
}

func callLocalHealth(t *testing.T, server *APIServer, path string) *httptest.ResponseRecorder {
	t.Helper()
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "http://127.0.0.1"+path, nil)
	request.RemoteAddr = "127.0.0.1:43120"
	server.http.Handler.ServeHTTP(recorder, request)
	return recorder
}

func decodeHealthPayload(t *testing.T, recorder *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var payload map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode health payload: %v", err)
	}
	return payload
}

func TestBootHealthRequiresAuthenticatedCore(t *testing.T) {
	server, state := newPanelStatusServer()
	offline := callLocalHealth(t, server, "/bootz")
	if offline.Code != http.StatusServiceUnavailable {
		t.Fatalf("offline boot health status=%d", offline.Code)
	}

	state.SetCore(true, "native")
	online := callLocalHealth(t, server, "/bootz")
	if online.Code != http.StatusOK {
		t.Fatalf("online boot health status=%d", online.Code)
	}
	if ok, _ := decodeHealthPayload(t, online)["ok"].(bool); !ok {
		t.Fatal("online boot health did not report ok")
	}
}

func TestPanelStatusTurnsRedForUnacknowledgedFinding(t *testing.T) {
	server, state := newPanelStatusServer()
	state.SetCore(true, "native")

	safe := decodeHealthPayload(t, callLocalHealth(t, server, "/panelz"))
	if safe["state"] != "safe" {
		t.Fatalf("healthy panel state=%v", safe["state"])
	}

	state.AddIncident(XDRIncident{Severity: "high", Summary: "test finding"})
	state.AddIncident(XDRIncident{Severity: "high", Summary: "duplicate observation"})
	alert := decodeHealthPayload(t, callLocalHealth(t, server, "/panelz"))
	if alert["state"] != "alert" {
		t.Fatalf("finding panel state=%v", alert["state"])
	}
	if alert["open_findings"] != float64(1) {
		t.Fatalf("open findings=%v", alert["open_findings"])
	}
}

func TestPanelAndBootHealthRejectNonLoopbackClients(t *testing.T) {
	server, _ := newPanelStatusServer()
	for _, path := range []string{"/bootz", "/panelz"} {
		recorder := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodGet, "http://127.0.0.1"+path, nil)
		request.RemoteAddr = "192.0.2.45:43120"
		server.http.Handler.ServeHTTP(recorder, request)
		if recorder.Code != http.StatusNotFound {
			t.Fatalf("%s exposed to non-loopback client: %d", path, recorder.Code)
		}
	}
}
