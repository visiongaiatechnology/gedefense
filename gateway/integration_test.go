package main

import (
	"crypto/sha256"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func testGateway(t *testing.T) (*gateway, *httptest.Server, *httptest.Server, *http.Client) {
	t.Helper()
	backendToken := strings.Repeat("a", 40)
	var backend *httptest.Server
	backend = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != strings.TrimPrefix(backend.URL, "http://") {
			http.Error(w, "invalid host", http.StatusBadRequest)
			return
		}
		if r.Header.Get("Origin") != "" || r.Header.Get("Referer") != "" || r.Header.Get("Cookie") != "" || r.Header.Get("X-Forwarded-For") != "" || r.Header.Get("Forwarded") != "" {
			http.Error(w, "origin rejected", http.StatusForbidden)
			return
		}
		if r.Header.Get("Authorization") != "Bearer "+backendToken {
			http.Error(w, "authorization required", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"ok":true}`)
	}))
	backendURL, err := url.Parse(backend.URL)
	if err != nil {
		t.Fatal(err)
	}
	salt := []byte("0123456789abcdef")
	password := []byte("correct horse battery staple")
	digest := pbkdf2SHA256(password, salt, 300000, 32)
	key := sha256.Sum256([]byte("session-test-key"))
	g := &gateway{
		backend:      backendURL,
		password:     passwordRecord{algorithm: "pbkdf2-sha256", iterations: 300000, salt: salt, digest: digest},
		sessionKey:   key[:],
		backendToken: backendToken,
		limiter:      newLimiter(),
	}
	g.proxy = g.newProxy()
	mux := http.NewServeMux()
	mux.HandleFunc("GET /gateway/livez", g.livez)
	mux.HandleFunc("GET /login", g.loginPage)
	mux.HandleFunc("POST /login", g.login)
	mux.HandleFunc("POST /logout", g.logout)
	mux.HandleFunc("/", g.protectedProxy)
	front := httptest.NewTLSServer(g.security(mux))
	frontURL, err := url.Parse(front.URL)
	if err != nil {
		t.Fatal(err)
	}
	g.publicHost = frontURL.Host
	g.publicOrigin = front.URL
	jar, _ := cookiejar.New(nil)
	client := front.Client()
	client.Jar = jar
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse }
	return g, backend, front, client
}

func extractCSRF(t *testing.T, body string) string {
	t.Helper()
	prefix := `name="csrf" value="`
	start := strings.Index(body, prefix)
	if start < 0 {
		t.Fatalf("csrf not found in %q", body)
	}
	start += len(prefix)
	end := strings.Index(body[start:], `"`)
	if end < 0 {
		t.Fatal("unterminated csrf")
	}
	return body[start : start+end]
}

func TestFullLoginAndProxyWithOpaqueOrigin(t *testing.T) {
	g, backend, front, client := testGateway(t)
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
	req.Header.Set("Origin", "null")
	req.Header.Set("Sec-Fetch-Site", "none")
	resp, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/?lang=de" {
		t.Fatalf("login status=%d location=%q", resp.StatusCode, resp.Header.Get("Location"))
	}
	resp.Body.Close()

	u, _ := url.Parse(front.URL)
	cookies := client.Jar.Cookies(u)
	found := false
	for _, c := range cookies {
		if c.Name == cookieName && c.Value != "" {
			found = true
		}
	}
	if !found {
		t.Fatalf("session cookie missing: %#v", cookies)
	}

	statusReq, _ := http.NewRequest(http.MethodGet, front.URL+"/api/v1/status", nil)
	statusReq.Header.Set("X-Forwarded-For", "198.51.100.9")
	statusReq.Header.Set("Forwarded", "for=198.51.100.9")
	resp, err = client.Do(statusReq)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("proxy status=%d body=%q", resp.StatusCode, b)
	}
	if g.validSession(resp.Request) {
		// Response request is the outgoing client request and carries the cookie;
		// this branch simply ensures the validator remains callable in integration.
	}
}

func TestCrossSiteLoginRejected(t *testing.T) {
	_, backend, front, client := testGateway(t)
	defer backend.Close()
	defer front.Close()
	resp, _ := client.Get(front.URL + "/login")
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	csrf := extractCSRF(t, string(body))
	form := url.Values{"csrf": {csrf}, "password": {"correct horse battery staple"}}
	req, _ := http.NewRequest(http.MethodPost, front.URL+"/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "https://attacker.invalid")
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status=%d", resp.StatusCode)
	}
}
