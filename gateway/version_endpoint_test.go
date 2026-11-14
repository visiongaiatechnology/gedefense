// STATUS: DIAMANT VGT SUPREME
package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestUnauthenticatedVersionSurfaceDoesNotDiscloseTheBuild pins FIND-012. An anonymous
// request must not be answered with the exact build version, and there must be no
// version surface that answers 200 without a server-side session. Liveness stays the
// only anonymous health answer and carries no build metadata.
func TestUnauthenticatedVersionSurfaceDoesNotDiscloseTheBuild(t *testing.T) {
	g := &gateway{
		publicHost:   "127.0.0.1:9843",
		publicOrigin: "https://127.0.0.1:9843",
		sessionKey:   []byte(strings.Repeat("k", 32)),
		limiter:      newLimiter(),
	}
	front := httptest.NewTLSServer(g.security(g.routes()))
	defer front.Close()
	g.publicHost = mustURL(t, front.URL).Host
	g.publicOrigin = front.URL
	client := front.Client()
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

	productVersion := strings.TrimSuffix(version, "-access")
	// The retired anonymous build path is answered as a plain 404: no 200, no version,
	// and no redirect that would confirm a live version surface.
	resp, err := client.Get(front.URL + "/gateway/version")
	if err != nil {
		t.Fatalf("GET /gateway/version: %v", err)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	_ = resp.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("anonymous GET /gateway/version answered %d, want 404", resp.StatusCode)
	}
	if strings.Contains(string(body), productVersion) || strings.Contains(string(body), version) {
		t.Fatalf("anonymous GET /gateway/version disclosed the build version: %q", body)
	}

	// Any other unknown path must not become a version surface either.
	for _, path := range []string{"/version", "/gateway/version/"} {
		resp, err := client.Get(front.URL + path)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		_ = resp.Body.Close()
		if err != nil {
			t.Fatalf("read %s response: %v", path, err)
		}
		if resp.StatusCode == http.StatusOK {
			t.Fatalf("anonymous GET %s answered 200", path)
		}
		if strings.Contains(string(body), productVersion) || strings.Contains(string(body), version) {
			t.Fatalf("anonymous GET %s disclosed the build version: %q", path, body)
		}
	}

	// Liveness remains reachable without a session, but it must stay minimal.
	resp, err = client.Get(front.URL + "/gateway/livez")
	if err != nil {
		t.Fatal(err)
	}
	body, err = io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	_ = resp.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("livez status=%d", resp.StatusCode)
	}
	if strings.TrimSpace(string(body)) != `{"ok":true}` {
		t.Fatalf("livez payload=%q, want {\"ok\":true}", body)
	}
	if strings.Contains(string(body), productVersion) || strings.Contains(string(body), version) {
		t.Fatalf("livez disclosed the build version: %q", body)
	}
}
