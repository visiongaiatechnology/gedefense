package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestBootTrustEndpointRequiresAuthenticationAndMarksEvidenceOnly(t *testing.T) {
	cfg := defaultConfig()
	server := NewAPIServer(cfg, NewState("test", cfg), nil, nil, nil, nil, nil, nil, "0123456789abcdef0123456789abcdef")
	server.bootTrust = newBootTrustCollectorForTest(t.TempDir(), true, func() time.Time {
		return time.Date(2026, 7, 28, 15, 0, 0, 0, time.UTC)
	})

	unauthorized := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "http://127.0.0.1/api/v1/boot-trust", nil)
	request.Host = "127.0.0.1"
	server.http.Handler.ServeHTTP(unauthorized, request)
	if unauthorized.Code != http.StatusUnauthorized {
		t.Fatalf("boot trust endpoint returned %d without auth", unauthorized.Code)
	}

	authorized := httptest.NewRecorder()
	request = httptest.NewRequest(http.MethodGet, "http://127.0.0.1/api/v1/boot-trust", nil)
	request.Host = "127.0.0.1"
	request.Header.Set("Authorization", "Bearer 0123456789abcdef0123456789abcdef")
	server.http.Handler.ServeHTTP(authorized, request)
	if authorized.Code != http.StatusOK {
		t.Fatalf("authenticated boot trust endpoint returned %d", authorized.Code)
	}
	var report BootTrustReport
	if err := json.Unmarshal(authorized.Body.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	if report.ClaimLevel != "evidence-only" {
		t.Fatalf("unsafe boot trust claim level: %q", report.ClaimLevel)
	}
}

func TestMutationIntentIsCommittedBeforeHandlerAndFailureClosesGate(t *testing.T) {
	cfg := defaultConfig()
	state := NewState("test", cfg)
	ledger, path := evidenceFixture(t)
	if err := state.AttachEvidenceLedger(ledger); err != nil {
		t.Fatal(err)
	}
	server := NewAPIServer(cfg, state, nil, nil, nil, nil, nil, nil, "0123456789abcdef0123456789abcdef")
	calls := 0
	handler := server.auth(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		w.WriteHeader(http.StatusNoContent)
	})

	request := func(id string) int {
		recorder := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "http://127.0.0.1/api/v1/test-mutation", nil)
		req.Host = "127.0.0.1"
		req.Header.Set("Authorization", "Bearer 0123456789abcdef0123456789abcdef")
		req.Header.Set("X-VGT-Request-ID", id)
		handler(recorder, req)
		return recorder.Code
	}
	if code := request("request_1111111111111111"); code != http.StatusNoContent {
		t.Fatalf("authenticated mutation returned %d", code)
	}
	records := ledger.Recent(10)
	if calls != 1 || len(records) != 1 || records[0].Kind != "operator.mutation.intent" {
		t.Fatalf("mutation ran without durable intent: calls=%d records=%+v", calls, records)
	}
	file, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.WriteString("external-tamper\n"); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if code := request("request_2222222222222222"); code != http.StatusServiceUnavailable {
		t.Fatalf("tampered evidence gate returned %d", code)
	}
	if calls != 1 {
		t.Fatal("mutation handler executed after evidence integrity failure")
	}
}

func TestStatusRequiresBearerAuthentication(t *testing.T) {
	cfg := defaultConfig()
	state := NewState("test", cfg)
	server := NewAPIServer(cfg, state, nil, nil, nil, nil, nil, nil, "0123456789abcdef0123456789abcdef")

	unauthorized := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1/api/v1/status", nil)
	req.Host = "127.0.0.1"
	server.http.Handler.ServeHTTP(unauthorized, req)
	if unauthorized.Code != http.StatusUnauthorized {
		t.Fatalf("sensitive status endpoint returned %d without auth", unauthorized.Code)
	}

	authorized := httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "http://127.0.0.1/api/v1/status", nil)
	req.Host = "127.0.0.1"
	req.Header.Set("Authorization", "Bearer 0123456789abcdef0123456789abcdef")
	server.http.Handler.ServeHTTP(authorized, req)
	if authorized.Code != http.StatusOK {
		t.Fatalf("authenticated status endpoint returned %d", authorized.Code)
	}
	for _, header := range []string{"Content-Security-Policy", "X-Frame-Options", "X-Content-Type-Options", "Cross-Origin-Opener-Policy"} {
		if authorized.Header().Get(header) == "" {
			t.Fatalf("security header %s missing", header)
		}
	}
}

func TestAuthenticatedMutationRequiresUniqueRequestID(t *testing.T) {
	cfg := defaultConfig()
	state := NewState("test", cfg)
	server := NewAPIServer(cfg, state, nil, nil, nil, nil, nil, nil, "0123456789abcdef0123456789abcdef")
	handler := server.auth(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })

	request := func(id string) int {
		recorder := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "http://127.0.0.1/test", nil)
		req.Host = "127.0.0.1"
		req.Header.Set("Authorization", "Bearer 0123456789abcdef0123456789abcdef")
		req.Header.Set("X-VGT-Request-ID", id)
		handler(recorder, req)
		return recorder.Code
	}
	id := "request_0123456789abcdef"
	if code := request(id); code != http.StatusNoContent {
		t.Fatalf("first request returned %d", code)
	}
	if code := request(id); code != http.StatusConflict {
		t.Fatalf("replayed request returned %d", code)
	}
	if code := request("short"); code != http.StatusConflict {
		t.Fatalf("malformed request id returned %d", code)
	}
}

func TestTransactionAPIRequiresPreviewAndExactConfirmation(t *testing.T) {
	cfg := defaultConfig()
	state := NewState("test", cfg)
	ledger, _ := evidenceFixture(t)
	if err := state.AttachEvidenceLedger(ledger); err != nil {
		t.Fatal(err)
	}
	applier := &memoryTransactionApplier{value: "before"}
	engine, _, _ := newTestTransactionEngine(t, applier, state.RecordEvidence)
	if err := state.AttachTransactions(engine); err != nil {
		t.Fatal(err)
	}
	server := NewAPIServer(
		cfg, state, nil, nil, nil, nil, nil, nil,
		"0123456789abcdef0123456789abcdef",
	)
	request := func(path, requestID string, body []byte) *httptest.ResponseRecorder {
		recorder := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "http://127.0.0.1"+path, bytes.NewReader(body))
		req.Host = "127.0.0.1"
		req.Header.Set("Authorization", "Bearer 0123456789abcdef0123456789abcdef")
		req.Header.Set("X-VGT-Request-ID", requestID)
		req.Header.Set("Content-Type", "application/json")
		server.http.Handler.ServeHTTP(recorder, req)
		return recorder
	}
	previewResponse := request(
		"/api/v1/transactions/preview",
		"request_transaction_preview_0001",
		[]byte(`{"type":"test.memory","summary":"Change memory value","reason":"API regression","payload":{"value":"after"}}`),
	)
	if previewResponse.Code != http.StatusCreated {
		t.Fatalf("preview returned %d: %s", previewResponse.Code, previewResponse.Body.String())
	}
	var preview TransactionView
	if err := json.Unmarshal(previewResponse.Body.Bytes(), &preview); err != nil {
		t.Fatal(err)
	}
	rejected := request(
		"/api/v1/transactions/"+preview.ID+"/apply",
		"request_transaction_apply_bad_0002",
		[]byte(`{"confirmation":"APPLY wrong"}`),
	)
	if rejected.Code != http.StatusConflict || applier.value != "before" {
		t.Fatalf("invalid confirmation mutated state: code=%d value=%s", rejected.Code, applier.value)
	}
	applied := request(
		"/api/v1/transactions/"+preview.ID+"/apply",
		"request_transaction_apply_ok_0003",
		[]byte(`{"confirmation":"APPLY `+preview.ID+`"}`),
	)
	if applied.Code != http.StatusOK || applier.value != "after" {
		t.Fatalf("confirmed apply failed: code=%d value=%s body=%s", applied.Code, applier.value, applied.Body.String())
	}
	kinds := make(map[string]bool)
	for _, record := range ledger.Recent(20) {
		kinds[record.Kind] = true
	}
	for _, required := range []string{
		"operator.mutation.intent", "transaction.apply.intent", "transaction.applied",
	} {
		if !kinds[required] {
			t.Fatalf("transaction evidence missing %s: %+v", required, ledger.Recent(20))
		}
	}
}

func TestBoundedGuardsFailClosedAtCapacity(t *testing.T) {
	limiter := NewRateLimiter(6000, 10)
	limiter.maxVisitors = 2
	now := time.Now()
	if !limiter.Allow("one", now) || !limiter.Allow("two", now) || limiter.Allow("three", now) {
		t.Fatal("rate limiter visitor cap did not fail closed")
	}
	guard := NewReplayGuard(time.Hour)
	guard.maxEntries = 2
	if !guard.Claim("request_0000000000000001", now) || !guard.Claim("request_0000000000000002", now) || guard.Claim("request_0000000000000003", now) {
		t.Fatal("replay guard capacity did not fail closed")
	}
}

func TestEmbeddedAssetsHonorETag(t *testing.T) {
	cfg := defaultConfig()
	server := NewAPIServer(cfg, NewState("test", cfg), nil, nil, nil, nil, nil, nil, "0123456789abcdef0123456789abcdef")

	first := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1/assets/app.js", nil)
	req.Host = "127.0.0.1"
	server.http.Handler.ServeHTTP(first, req)
	if first.Code != http.StatusOK || first.Header().Get("ETag") == "" {
		t.Fatalf("first asset response code=%d etag=%q", first.Code, first.Header().Get("ETag"))
	}

	second := httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "http://127.0.0.1/assets/app.js", nil)
	req.Host = "127.0.0.1"
	req.Header.Set("If-None-Match", first.Header().Get("ETag"))
	server.http.Handler.ServeHTTP(second, req)
	if second.Code != http.StatusNotModified {
		t.Fatalf("conditional asset response=%d want=%d", second.Code, http.StatusNotModified)
	}
}

func TestTLSMaterialRejectsUnsafeFiles(t *testing.T) {
	dir := t.TempDir()
	cert := filepath.Join(dir, "server.crt")
	key := filepath.Join(dir, "server.key")
	if err := os.WriteFile(cert, []byte("certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(key, []byte("private-key"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := validateTLSMaterial(cert, key); err != nil {
		t.Fatalf("secure TLS material rejected: %v", err)
	}

	if err := os.Chmod(key, 0o640); err != nil {
		t.Fatal(err)
	}
	if err := validateTLSMaterial(cert, key); err == nil {
		t.Fatal("group-readable private key accepted")
	}
	if err := os.Chmod(key, 0o600); err != nil {
		t.Fatal(err)
	}

	certLink := filepath.Join(dir, "server-link.crt")
	if err := os.Symlink(cert, certLink); err != nil {
		t.Fatal(err)
	}
	if err := validateTLSMaterial(certLink, key); err == nil {
		t.Fatal("symlinked TLS certificate accepted")
	}

	if err := os.Chmod(cert, 0o620); err != nil {
		t.Fatal(err)
	}
	if err := validateTLSMaterial(cert, key); err == nil {
		t.Fatal("group-writable TLS certificate accepted")
	}
}

func TestBeta5SecurityHeadersAndI18nAssetAllowlist(t *testing.T) {
	cfg := defaultConfig()
	server := NewAPIServer(cfg, NewState("test", cfg), nil, nil, nil, nil, nil, nil, "0123456789abcdef0123456789abcdef")

	recorder := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1/assets/i18n.js", nil)
	req.Host = "127.0.0.1"
	server.http.Handler.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusOK {
		t.Fatalf("i18n asset status=%d", recorder.Code)
	}
	if recorder.Header().Get("Content-Type") != "text/javascript; charset=utf-8" {
		t.Fatalf("content-type=%q", recorder.Header().Get("Content-Type"))
	}
	for _, header := range []string{
		"Content-Security-Policy", "Origin-Agent-Cluster", "X-Permitted-Cross-Domain-Policies",
		"Cross-Origin-Embedder-Policy", "Cross-Origin-Opener-Policy", "Cross-Origin-Resource-Policy",
	} {
		if recorder.Header().Get(header) == "" {
			t.Fatalf("security header %s missing", header)
		}
	}

	recorder = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "http://127.0.0.1/assets/%2e%2e%2fetc%2fpasswd", nil)
	req.Host = "127.0.0.1"
	server.http.Handler.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("path traversal asset status=%d", recorder.Code)
	}

	recorder = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "http://127.0.0.1/assets/unknown.js", nil)
	req.Host = "127.0.0.1"
	server.http.Handler.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("unknown asset status=%d", recorder.Code)
	}
}

func TestBackendOriginAndBearerChecksCannotBeBypassed(t *testing.T) {
	cfg := defaultConfig()
	server := NewAPIServer(cfg, NewState("test", cfg), nil, nil, nil, nil, nil, nil, "0123456789abcdef0123456789abcdef")

	cases := []struct {
		name   string
		origin string
		token  string
		want   int
	}{
		{name: "missing bearer", want: http.StatusUnauthorized},
		{name: "wrong bearer", token: "wrong", want: http.StatusUnauthorized},
		{name: "foreign origin", origin: "https://attacker.invalid", token: "0123456789abcdef0123456789abcdef", want: http.StatusForbidden},
		{name: "internal gateway request", token: "0123456789abcdef0123456789abcdef", want: http.StatusOK},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1/api/v1/status", nil)
			req.Host = "127.0.0.1"
			if tc.origin != "" {
				req.Header.Set("Origin", tc.origin)
			}
			if tc.token != "" {
				req.Header.Set("Authorization", "Bearer "+tc.token)
			}
			server.http.Handler.ServeHTTP(recorder, req)
			if recorder.Code != tc.want {
				t.Fatalf("status=%d want=%d", recorder.Code, tc.want)
			}
		})
	}
}
