package main

// POINT 2 / P2-T3 API tests: authentication, replay guard, strict JSON, base64
// bounds, the confirm-gated burn and the untrusted export download. The handlers
// are exercised through the real ServeMux (s.auth included).

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func newParserCellAPIFixture(t *testing.T, enabled bool) (*APIServer, *SettingsStore, *parserCellFakeHelper, *ParserCellManager) {
	t.Helper()
	server, store, _ := settingsAPIFixture(t)
	if enabled {
		current := store.Get()
		cells := defaultParserCellsFabricSettings()
		cells.Enabled = true
		current.ParserCells = &cells
		if _, err := store.Update(current); err != nil {
			t.Fatalf("enable parser cells for the API fixture: %v", err)
		}
	}
	helper := newParserCellFakeHelper(t)
	manager := NewParserCellManager(helper.cfg, server.state, store, nil, nil)
	client, err := newParserCellClient(helper.cfg)
	if err != nil {
		t.Fatalf("parser cell API client: %v", err)
	}
	manager.client = client
	manager.clientErr = nil
	manager.now = func() time.Time { return time.Now() }
	if err := server.state.AttachParserCells(manager); err != nil {
		t.Fatalf("attach parser cell manager: %v", err)
	}
	return server, store, helper, manager
}

func decodeParserCellJSON(t *testing.T, raw []byte, target any) {
	t.Helper()
	if err := json.Unmarshal(raw, target); err != nil {
		t.Fatalf("decode parser cell payload: %v (body=%s)", err, raw)
	}
}

func parserCellManualRequest(t *testing.T, server *APIServer, method, path, contentType, requestID string, body []byte) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, "http://127.0.0.1"+path, bytes.NewReader(body))
	req.Host = "127.0.0.1"
	req.Header.Set("Authorization", "Bearer "+fabricTestToken)
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	if requestID != "" {
		req.Header.Set("X-VGT-Request-ID", requestID)
	}
	rec := httptest.NewRecorder()
	server.http.Handler.ServeHTTP(rec, req)
	return rec
}

func TestParserCellsAPIStatusAndAuth(t *testing.T) {
	// Without any manager the surface is honest and inert.
	server, _, _ := settingsAPIFixture(t)
	rec := fabricRequest(t, server, http.MethodGet, "/api/v1/parser-cells/status", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status without manager returned %d", rec.Code)
	}
	var status ParserCellsStatus
	decodeParserCellJSON(t, rec.Body.Bytes(), &status)
	if status.Enabled || status.Available || status.Helper != "disabled" {
		t.Fatalf("status without manager is not inert: %+v", status)
	}
	rec = fabricRequest(t, server, http.MethodGet, "/api/v1/parser-cells", nil)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"cells":[]`) {
		t.Fatalf("list without manager is not empty: %d %s", rec.Code, rec.Body.String())
	}
	rec = fabricRequest(t, server, http.MethodPost, "/api/v1/parser-cells/inputs", []byte(`{"data_base64":"eA=="}`))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("staging without manager returned %d: %s", rec.Code, rec.Body.String())
	}
	// Authentication and the replay guard come from s.auth.
	if rec := fabricRequestWithoutAuth(t, server, "/api/v1/parser-cells/status"); rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated status returned %d", rec.Code)
	}
	body := []byte(`{"data_base64":"eA=="}`)
	first := parserCellManualRequest(t, server, http.MethodPost, "/api/v1/parser-cells/inputs", "application/json", "", body)
	if first.Code != http.StatusConflict {
		t.Fatalf("mutation without X-VGT-Request-ID returned %d", first.Code)
	}
}

func TestParserCellsAPIDefaultOffContactsNoHelper(t *testing.T) {
	server, _, helper, _ := newParserCellAPIFixture(t, false)
	rec := fabricRequest(t, server, http.MethodGet, "/api/v1/parser-cells/status", nil)
	var status ParserCellsStatus
	decodeParserCellJSON(t, rec.Body.Bytes(), &status)
	if status.Enabled {
		t.Fatalf("disabled namespace reported enabled: %+v", status)
	}
	rec = fabricRequest(t, server, http.MethodPost, "/api/v1/parser-cells/inputs", []byte(`{"data_base64":"eA=="}`))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("staging while disabled returned %d: %s", rec.Code, rec.Body.String())
	}
	if requests := helper.requestCount(); requests != 0 {
		t.Fatalf("disabled namespace contacted the helper %d times", requests)
	}
}

func TestParserCellsAPIStrictInputBounds(t *testing.T) {
	server, store, _, manager := newParserCellAPIFixture(t, true)
	valid := base64.StdEncoding.EncodeToString([]byte("parser document"))
	rec := fabricRequest(t, server, http.MethodPost, "/api/v1/parser-cells/inputs", []byte(`{"data_base64":"`+valid+`"}`))
	if rec.Code != http.StatusCreated {
		t.Fatalf("valid staging returned %d: %s", rec.Code, rec.Body.String())
	}
	var input ParserCellInput
	decodeParserCellJSON(t, rec.Body.Bytes(), &input)
	if len(input.Token) != 32 || len(input.SHA256) != 64 || input.Size != 15 {
		t.Fatalf("staging answer is wrong: %+v", input)
	}
	for name, body := range map[string]string{
		"invalid-base64": `{"data_base64":"%%%not-base64%%%"}`,
		"empty":          `{"data_base64":""}`,
		"unknown-field":  `{"data_base64":"eA==","path":"/etc/shadow"}`,
		"not-json":       `not json`,
	} {
		rec := fabricRequest(t, server, http.MethodPost, "/api/v1/parser-cells/inputs", []byte(body))
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("%s returned %d: %s", name, rec.Code, rec.Body.String())
		}
	}
	if rec := parserCellManualRequest(t, server, http.MethodPost, "/api/v1/parser-cells/inputs", "text/plain", randomID(), []byte(`{"data_base64":"eA=="}`)); rec.Code != http.StatusBadRequest {
		t.Fatalf("non-JSON content type returned %d", rec.Code)
	}
	// Tighten the administrable bound and prove the API refuses above it.
	current := store.Get()
	cells := *current.ParserCells
	cells.MaxInputBytes = 1024
	current.ParserCells = &cells
	if _, err := store.Update(current); err != nil {
		t.Fatal(err)
	}
	manager.Configure(store.Get())
	oversized := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte("X"), 2048))
	if rec := fabricRequest(t, server, http.MethodPost, "/api/v1/parser-cells/inputs", []byte(`{"data_base64":"`+oversized+`"}`)); rec.Code != http.StatusBadRequest {
		t.Fatalf("oversized input returned %d: %s", rec.Code, rec.Body.String())
	}
}

func TestParserCellsAPIReplayGuardRejectsSecondRequest(t *testing.T) {
	server, _, _, _ := newParserCellAPIFixture(t, true)
	body := []byte(`{"data_base64":"` + base64.StdEncoding.EncodeToString([]byte("doc")) + `"}`)
	requestID := strings.Repeat("r", 32)
	first := parserCellManualRequest(t, server, http.MethodPost, "/api/v1/parser-cells/inputs", "application/json", requestID, body)
	if first.Code != http.StatusCreated {
		t.Fatalf("first replay-checked request returned %d: %s", first.Code, first.Body.String())
	}
	second := parserCellManualRequest(t, server, http.MethodPost, "/api/v1/parser-cells/inputs", "application/json", requestID, body)
	if second.Code != http.StatusConflict {
		t.Fatalf("replayed request id was accepted: %d %s", second.Code, second.Body.String())
	}
}

func TestParserCellsAPILifecycleBurnAndExport(t *testing.T) {
	server, _, helper, _ := newParserCellAPIFixture(t, true)
	helper.set(func(h *parserCellFakeHelper) { h.export = []byte("untrusted parser export") })
	inputBody := `{"data_base64":"` + base64.StdEncoding.EncodeToString([]byte("parser document")) + `"}`
	rec := fabricRequest(t, server, http.MethodPost, "/api/v1/parser-cells/inputs", []byte(inputBody))
	if rec.Code != http.StatusCreated {
		t.Fatalf("staging returned %d: %s", rec.Code, rec.Body.String())
	}
	var input ParserCellInput
	decodeParserCellJSON(t, rec.Body.Bytes(), &input)
	openBody, _ := json.Marshal(map[string]any{"profile": "pdf-viewer", "input_token": input.Token,
		"sha256": input.SHA256, "size": input.Size, "ttl_seconds": 60})
	rec = fabricRequest(t, server, http.MethodPost, "/api/v1/parser-cells/open", openBody)
	if rec.Code != http.StatusCreated {
		t.Fatalf("open returned %d: %s", rec.Code, rec.Body.String())
	}
	var runtime ParserCellRuntime
	decodeParserCellJSON(t, rec.Body.Bytes(), &runtime)
	if runtime.State != parserCellStateIsolated || !runtime.Sandbox || !runtime.NetNS {
		t.Fatalf("open answer is not an attested cell: %+v", runtime)
	}
	// A wrong staged digest is refused before the helper is contacted.
	badOpen, _ := json.Marshal(map[string]any{"profile": "pdf-viewer", "input_token": input.Token,
		"sha256": strings.Repeat("0", 64), "size": input.Size})
	if rec := fabricRequest(t, server, http.MethodPost, "/api/v1/parser-cells/open", badOpen); rec.Code != http.StatusBadRequest {
		t.Fatalf("open with a wrong digest returned %d: %s", rec.Code, rec.Body.String())
	}
	// Freeze/unfreeze require a strict JSON object body.
	if rec := fabricRequest(t, server, http.MethodPost, "/api/v1/parser-cells/"+runtime.UUID+"/freeze", []byte(`{"path":"x"}`)); rec.Code != http.StatusBadRequest {
		t.Fatalf("freeze with unknown JSON field returned %d", rec.Code)
	}
	if rec := fabricRequest(t, server, http.MethodPost, "/api/v1/parser-cells/"+runtime.UUID+"/freeze", []byte(`{}`)); rec.Code != http.StatusOK {
		t.Fatalf("freeze returned %d: %s", rec.Code, rec.Body.String())
	}
	if rec := fabricRequest(t, server, http.MethodPost, "/api/v1/parser-cells/"+runtime.UUID+"/unfreeze", []byte(`{}`)); rec.Code != http.StatusOK {
		t.Fatalf("unfreeze returned %d: %s", rec.Code, rec.Body.String())
	}
	// The burn needs the exact confirm phrase for this cell.
	wrongConfirm, _ := json.Marshal(map[string]string{"confirm": "BURN " + strings.Repeat("0", 32)})
	if rec := fabricRequest(t, server, http.MethodPost, "/api/v1/parser-cells/"+runtime.UUID+"/burn", wrongConfirm); rec.Code != http.StatusBadRequest {
		t.Fatalf("burn with a wrong confirm phrase returned %d", rec.Code)
	}
	confirm, _ := json.Marshal(map[string]string{"confirm": "BURN " + runtime.UUID})
	rec = fabricRequest(t, server, http.MethodPost, "/api/v1/parser-cells/"+runtime.UUID+"/burn", confirm)
	if rec.Code != http.StatusOK {
		t.Fatalf("burn returned %d: %s", rec.Code, rec.Body.String())
	}
	var burned ParserCellRuntime
	decodeParserCellJSON(t, rec.Body.Bytes(), &burned)
	if burned.State != parserCellStateBurned || !burned.Terminal {
		t.Fatalf("burn did not report a terminal cell: %+v", burned)
	}
	if rec := fabricRequest(t, server, http.MethodPost, "/api/v1/parser-cells/"+runtime.UUID+"/burn", confirm); rec.Code != http.StatusOK {
		t.Fatalf("idempotent burn returned %d: %s", rec.Code, rec.Body.String())
	}
	// Export metadata and the bounded untrusted download.
	rec = fabricRequest(t, server, http.MethodGet, "/api/v1/parser-cells/"+runtime.UUID+"/export", nil)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"export"`) {
		t.Fatalf("export metadata returned %d: %s", rec.Code, rec.Body.String())
	}
	rec = fabricRequest(t, server, http.MethodGet, "/api/v1/parser-cells/"+runtime.UUID+"/export?download=1", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("export download returned %d: %s", rec.Code, rec.Body.String())
	}
	if got := rec.Body.Bytes(); !bytes.Equal(got, []byte("untrusted parser export")) {
		t.Fatalf("export download bytes are wrong: %q", got)
	}
	if rec.Header().Get("Content-Type") != "application/octet-stream" ||
		!strings.Contains(rec.Header().Get("Content-Disposition"), "attachment") ||
		rec.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("export download headers do not mark untrusted evidence: %v", rec.Header())
	}
	if rec := fabricRequest(t, server, http.MethodGet, "/api/v1/parser-cells/"+strings.Repeat("0", 32)+"/export", nil); rec.Code != http.StatusNotFound {
		t.Fatalf("export of an unknown cell returned %d", rec.Code)
	}
	if rec := fabricRequest(t, server, http.MethodGet, "/api/v1/parser-cells?limit=999", nil); rec.Code != http.StatusBadRequest {
		t.Fatalf("invalid list limit returned %d", rec.Code)
	}
	if rec := fabricRequest(t, server, http.MethodGet, "/api/v1/parser-cells?limit=1", nil); rec.Code != http.StatusOK {
		t.Fatalf("bounded list returned %d", rec.Code)
	}
}

func TestParserCellsAPIInputBodyLimitIsRouteScoped(t *testing.T) {
	server, _, _, _ := newParserCellAPIFixture(t, true)
	// 8 MiB decoded (the documented hard maximum) must pass the route's own 12 MiB
	// base64 body bound although the global mutation ceiling is 1 MiB.
	document := bytes.Repeat([]byte("D"), 8<<20)
	payload, _ := json.Marshal(map[string]string{"data_base64": base64.StdEncoding.EncodeToString(document)})
	rec := fabricRequest(t, server, http.MethodPost, "/api/v1/parser-cells/inputs", payload)
	if rec.Code != http.StatusCreated {
		t.Fatalf("8 MiB document was blocked: %d %s", rec.Code, rec.Body.String())
	}
	var input ParserCellInput
	decodeParserCellJSON(t, rec.Body.Bytes(), &input)
	if input.Size != int64(len(document)) {
		t.Fatalf("staged document size is %d, want %d", input.Size, len(document))
	}
	// Decoded above MaxInputBytes but within the body bound: refused as input-invalid.
	tooBig := bytes.Repeat([]byte("D"), (8<<20)+3)
	payload, _ = json.Marshal(map[string]string{"data_base64": base64.StdEncoding.EncodeToString(tooBig)})
	if rec := fabricRequest(t, server, http.MethodPost, "/api/v1/parser-cells/inputs", payload); rec.Code != http.StatusBadRequest {
		t.Fatalf("decoded input above MaxInputBytes returned %d", rec.Code)
	}
	// Base64 body above the route's 12 MiB bound: 413, not a silent truncation.
	huge, _ := json.Marshal(map[string]string{"data_base64": base64.StdEncoding.EncodeToString(bytes.Repeat([]byte("D"), 9<<20))})
	if int64(len(huge)) <= parserCellInputBodyLimit {
		t.Fatalf("test body %d does not exceed the %d body bound", len(huge), parserCellInputBodyLimit)
	}
	if rec := fabricRequest(t, server, http.MethodPost, "/api/v1/parser-cells/inputs", huge); rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized body returned %d: %s", rec.Code, rec.Body.String())
	}
	// Every other mutating route keeps the global 1 MiB ceiling unchanged.
	burnBody := append([]byte(`{"confirm":"BURN `+strings.Repeat("0", 32)+`"}`), bytes.Repeat([]byte(" "), 2<<20)...)
	if rec := fabricRequest(t, server, http.MethodPost, "/api/v1/parser-cells/"+strings.Repeat("0", 32)+"/burn", burnBody); rec.Code != http.StatusBadRequest {
		t.Fatalf("non-exempt mutation route lost the global body ceiling: %d", rec.Code)
	}
}

func TestParserCellsAPIHelperMissingIs503(t *testing.T) {
	server, store, _ := settingsAPIFixture(t)
	current := store.Get()
	cells := defaultParserCellsFabricSettings()
	cells.Enabled = true
	current.ParserCells = &cells
	if _, err := store.Update(current); err != nil {
		t.Fatal(err)
	}
	missing := filepath.Join(t.TempDir(), "absent")
	manager := NewParserCellManager(ParserCellsConfig{Socket: missing, AuthKeyFile: missing,
		InputDir: filepath.Join(t.TempDir(), "in"), ImportsDir: filepath.Join(t.TempDir(), "out"),
		RequestTimeoutMillis: 500, PeerUID: -1},
		server.state, store, nil, nil)
	manager.Configure(store.Get())
	if err := server.state.AttachParserCells(manager); err != nil {
		t.Fatal(err)
	}
	rec := fabricRequest(t, server, http.MethodPost, "/api/v1/parser-cells/inputs", []byte(`{"data_base64":"eA=="}`))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("helper-missing staging returned %d: %s", rec.Code, rec.Body.String())
	}
	var payload map[string]string
	decodeParserCellJSON(t, rec.Body.Bytes(), &payload)
	if payload["code"] != "capability-missing" {
		t.Fatalf("helper-missing error code is %q, want capability-missing", payload["code"])
	}
	rec = fabricRequest(t, server, http.MethodGet, "/api/v1/parser-cells/status", nil)
	var status ParserCellsStatus
	decodeParserCellJSON(t, rec.Body.Bytes(), &status)
	if !status.Enabled || status.Available || status.Helper != "unavailable" {
		t.Fatalf("missing helper status is dishonest: %+v", status)
	}
}
