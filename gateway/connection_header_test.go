package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

// FIND-005 (VGT-AUDIT-2026-11-19): a client that lists an attested header in
// its Connection header must not be able to make net/http's ReverseProxy strip
// the Authorization or gateway-session header after the Director set them.
func TestProxyDirectorStripsConnectionNominatedHeaders(t *testing.T) {
	backend, _ := url.Parse("http://127.0.0.1:9844")
	g := &gateway{backend: backend, backendToken: "0123456789abcdef0123456789abcdef"}
	p := g.newProxy()
	req := httptest.NewRequest(http.MethodGet, "https://203.0.113.10:9843/api/v1/test", nil)
	req.Header.Set("Connection", "X-Gedefense-Gateway-Session, Authorization, X-VGT-Gateway")
	req.Header.Set("Authorization", "Bearer browser-value")
	req.Header.Set("X-Gedefense-Gateway-Session", "attacker-controlled")
	req.Header.Set("X-VGT-Gateway", "attacker-controlled")
	p.Director(req)
	if got := req.Header.Get("Connection"); got != "" {
		t.Fatalf("Connection leaked to backend: %q", got)
	}
	if got := req.Header.Get("Authorization"); got != "Bearer 0123456789abcdef0123456789abcdef" {
		t.Fatalf("attested Authorization was stripped: %q", got)
	}
	if got := req.Header.Get("X-VGT-Gateway"); got != "direct-access-v2" {
		t.Fatalf("attested gateway header was stripped: %q", got)
	}
	if got := req.Header.Get("X-Gedefense-Gateway-Session"); got != "" {
		t.Fatalf("client session header leaked: %q", got)
	}
}

// Full proxy path: the backend must receive the attested Authorization even
// when the client nominates it in Connection.
func TestProxyServeHTTPKeepsAttestedAuthorizationUnderConnectionAttack(t *testing.T) {
	seen := make(chan http.Header, 1)
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen <- r.Header.Clone()
		w.WriteHeader(http.StatusNoContent)
	}))
	defer backend.Close()
	backendURL, err := url.Parse(backend.URL)
	if err != nil {
		t.Fatal(err)
	}
	const token = "0123456789abcdef0123456789abcdef"
	g := &gateway{backend: backendURL, backendToken: token}
	proxy := g.newProxy()

	req := httptest.NewRequest(http.MethodGet, "https://203.0.113.10:9843/api/v1/status", nil)
	req.Header.Set("Connection", "Authorization, X-Gedefense-Gateway-Session")
	req.Header.Set("Authorization", "Bearer browser-value")
	req.Header.Set("X-Gedefense-Gateway-Session", "attacker-controlled")
	recorder := httptest.NewRecorder()
	proxy.ServeHTTP(recorder, req)
	if recorder.Code != http.StatusNoContent {
		body, _ := io.ReadAll(recorder.Result().Body)
		t.Fatalf("proxy status=%d body=%s", recorder.Code, body)
	}
	headers := <-seen
	if got := headers.Get("Authorization"); got != "Bearer "+token {
		t.Fatalf("backend authorization=%q, want attested bearer", got)
	}
	if got := headers.Get("X-Gedefense-Gateway-Session"); got != "" {
		t.Fatalf("backend received client session header: %q", got)
	}
	if got := headers.Get("Connection"); got != "" {
		t.Fatalf("backend received Connection: %q", got)
	}
}
