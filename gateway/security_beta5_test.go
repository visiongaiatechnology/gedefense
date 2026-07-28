package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSameOriginRequiredFailsClosed(t *testing.T) {
	g := &gateway{publicHost: "203.0.113.10:9843", publicOrigin: "https://203.0.113.10:9843"}
	for _, origin := range []string{"", "null", "http://203.0.113.10:9843", "https://attacker.invalid"} {
		req := httptest.NewRequest(http.MethodPost, "https://203.0.113.10:9843/api/v1/settings", nil)
		if origin != "" {
			req.Header.Set("Origin", origin)
		}
		if g.sameOriginRequired(req) {
			t.Fatalf("unsafe origin %q accepted", origin)
		}
	}
	req := httptest.NewRequest(http.MethodPost, "https://203.0.113.10:9843/api/v1/settings", nil)
	req.Header.Set("Origin", "https://203.0.113.10:9843")
	if !g.sameOriginRequired(req) {
		t.Fatal("exact HTTPS origin rejected")
	}
}

func TestLoginRejectsMismatchedOriginEvenWithoutCrossSiteFetchMetadata(t *testing.T) {
	_, backend, front, client := testGateway(t)
	defer backend.Close()
	defer front.Close()
	resp, err := client.Get(front.URL + "/login")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	csrf := extractCSRF(t, string(body))
	form := url.Values{"csrf": {csrf}, "password": {"correct horse battery staple"}}
	req, _ := http.NewRequest(http.MethodPost, front.URL+"/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "https://attacker.invalid")
	req.Header.Set("Sec-Fetch-Site", "none")
	resp, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status=%d", resp.StatusCode)
	}
}

func TestLoginCSRFTokenIsMandatoryAndBoundToCookie(t *testing.T) {
	_, backend, front, client := testGateway(t)
	defer backend.Close()
	defer front.Close()
	resp, err := client.Get(front.URL + "/login")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	csrf := extractCSRF(t, string(body))
	for _, supplied := range []string{"", csrf + "tampered"} {
		form := url.Values{"csrf": {supplied}, "password": {"correct horse battery staple"}}
		req, _ := http.NewRequest(http.MethodPost, front.URL+"/login", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Origin", front.URL)
		resp, err = client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("csrf=%q status=%d", supplied, resp.StatusCode)
		}
	}
}

func TestAuthenticatedMutationRequiresExactOrigin(t *testing.T) {
	g, backend, front, client := testGateway(t)
	defer backend.Close()
	defer front.Close()
	value, err := g.issueSession(time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(front.URL)
	client.Jar.SetCookies(u, []*http.Cookie{{Name: cookieName, Value: value, Path: "/", Secure: true}})

	for _, origin := range []string{"", "null", "https://attacker.invalid"} {
		req, _ := http.NewRequest(http.MethodPost, front.URL+"/api/v1/settings", strings.NewReader(`{}`))
		if origin != "" {
			req.Header.Set("Origin", origin)
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("origin=%q status=%d", origin, resp.StatusCode)
		}
	}

	req, _ := http.NewRequest(http.MethodPost, front.URL+"/api/v1/settings", strings.NewReader(`{}`))
	req.Header.Set("Origin", front.URL)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("same-origin status=%d body=%q", resp.StatusCode, body)
	}
}

func TestForgedAndExpiredSessionCookiesAreRejected(t *testing.T) {
	key := []byte(strings.Repeat("k", 32))
	g := &gateway{sessionKey: key}
	valid, err := g.issueSession(time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	cases := []string{"garbage", valid + "x"}
	for _, value := range cases {
		req := httptest.NewRequest(http.MethodGet, "https://example.test/", nil)
		req.AddCookie(&http.Cookie{Name: cookieName, Value: value})
		if g.validSession(req) {
			t.Fatalf("forged cookie accepted: %q", value)
		}
	}
	expired, err := g.issueSession(time.Now().Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "https://example.test/", nil)
	req.AddCookie(&http.Cookie{Name: cookieName, Value: expired})
	if g.validSession(req) {
		t.Fatal("expired cookie accepted")
	}
}

func TestGatewaySecurityHeadersAndHostAllowlist(t *testing.T) {
	g := &gateway{publicHost: "203.0.113.10:9843"}
	h := g.security(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	req := httptest.NewRequest(http.MethodGet, "https://203.0.113.10:9843/", nil)
	req.Host = "203.0.113.10:9843"
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusNoContent {
		t.Fatalf("status=%d", rr.Code)
	}
	for _, header := range []string{
		"Strict-Transport-Security", "X-Content-Type-Options", "X-Frame-Options", "Referrer-Policy",
		"Permissions-Policy", "Cross-Origin-Opener-Policy", "Cross-Origin-Resource-Policy",
		"Origin-Agent-Cluster", "X-Permitted-Cross-Domain-Policies",
	} {
		if rr.Header().Get(header) == "" {
			t.Fatalf("missing header %s", header)
		}
	}
	bad := httptest.NewRequest(http.MethodGet, "https://attacker.invalid/", nil)
	bad.Host = "attacker.invalid"
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, bad)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("host allowlist status=%d", rr.Code)
	}
}

func TestArgon2PasswordRecordRoundTripAndFilePolicy(t *testing.T) {
	password := []byte("a long and unique operator password")
	record, err := createArgon2PasswordRecord(password)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(record, "v2$argon2id$v=19$m=65536,t=3,p=1$") {
		t.Fatalf("unexpected record %q", record)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "access-password")
	if err := os.WriteFile(path, []byte(record+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, err := loadPasswordRecord(path)
	if err != nil {
		t.Fatal(err)
	}
	if !verifyPassword(password, loaded) || verifyPassword([]byte("wrong password"), loaded) {
		t.Fatal("Argon2id password verification policy failed")
	}
	if err := os.Chmod(path, 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := loadPasswordRecord(path); err == nil {
		t.Fatal("group-readable password record accepted")
	}
}

func TestBrandedLoginHasVersionLanguagesSupportAndNonceCSP(t *testing.T) {
	g := &gateway{publicHost: "203.0.113.10:9843", sessionKey: []byte(strings.Repeat("s", 32))}
	for _, tc := range []struct {
		lang string
		text string
	}{
		{lang: "de", text: "Operator-Zugang"},
		{lang: "en", text: "Operator access"},
		{lang: "ru", text: "Доступ оператора"},
	} {
		req := httptest.NewRequest(http.MethodGet, "https://203.0.113.10:9843/login?lang="+tc.lang, nil)
		req.Host = "203.0.113.10:9843"
		rr := httptest.NewRecorder()
		g.loginPage(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("lang=%s status=%d", tc.lang, rr.Code)
		}
		body := rr.Body.String()
		for _, expected := range []string{
			"GeDefense", "VisionGaiaTechnology", "1.0.0-beta.5", tc.text,
			"paypal.me/dergoldenelotus", "bc1q3ue5gq822tddmkdrek79adlkm36fatat3lz0dm",
			"0xD37DEfb09e07bD775EaaE9ccDaFE3a5b2348Fe85",
		} {
			if !strings.Contains(body, expected) {
				t.Fatalf("lang=%s missing %q", tc.lang, expected)
			}
		}
		csp := rr.Header().Get("Content-Security-Policy")
		if !strings.Contains(csp, "style-src 'nonce-") || !strings.Contains(csp, "default-src 'none'") {
			t.Fatalf("lang=%s CSP=%q", tc.lang, csp)
		}
	}
}
