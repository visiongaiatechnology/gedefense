package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func readBody(t *testing.T, response *http.Response) string {
	t.Helper()
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

func mustURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	parsed, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}

func TestSessionRegistryRejectsExpiredIdleAndRevokedSessions(t *testing.T) {
	registry := newSessionRegistry()
	now := time.Unix(1_800_000_000, 0)
	registry.now = func() time.Time { return now }

	session, err := registry.create(now.Add(sessionAbsoluteLifetime))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := registry.validate(session.id); !ok {
		t.Fatal("fresh session was rejected")
	}
	// Idle timeout: no request for longer than the idle window.
	now = now.Add(sessionIdleTimeout + time.Minute)
	if _, ok := registry.validate(session.id); ok {
		t.Fatal("idle session was accepted")
	}
	// Absolute timeout: periodic activity does not extend it.
	now = time.Unix(1_800_000_000, 0)
	absolute, err := registry.create(now.Add(sessionAbsoluteLifetime))
	if err != nil {
		t.Fatal(err)
	}
	for step := 0; step < 2; step++ {
		now = now.Add(30 * time.Minute)
		if _, ok := registry.validate(absolute.id); !ok {
			t.Fatalf("active session was rejected at step %d", step)
		}
	}
	now = now.Add(sessionAbsoluteLifetime)
	if _, ok := registry.validate(absolute.id); ok {
		t.Fatal("session outlived its absolute lifetime")
	}
	// Revocation is immediate.
	now = time.Unix(1_800_000_000, 0)
	revoked, err := registry.create(now.Add(sessionAbsoluteLifetime))
	if err != nil {
		t.Fatal(err)
	}
	registry.revoke(revoked)
	if _, ok := registry.validate(revoked.id); ok {
		t.Fatal("revoked session was accepted")
	}
}

func TestSessionRotationKeepsGraceAndRevokesPrevious(t *testing.T) {
	registry := newSessionRegistry()
	now := time.Unix(1_800_000_000, 0)
	registry.now = func() time.Time { return now }
	session, err := registry.create(now.Add(sessionAbsoluteLifetime))
	if err != nil {
		t.Fatal(err)
	}
	oldID := session.id
	rotated, err := registry.rotate(session)
	if err != nil {
		t.Fatal(err)
	}
	if rotated.id == oldID {
		t.Fatal("rotation did not change the session id")
	}
	if _, ok := registry.validate(rotated.id); !ok {
		t.Fatal("rotated session id was rejected")
	}
	now = now.Add(sessionRotationGrace + time.Second)
	if _, ok := registry.validate(oldID); ok {
		t.Fatal("previous session id outlived the rotation grace window")
	}
}

func TestLoginLimiterAdmitsNewIdentitiesWhenFull(t *testing.T) {
	limiter := newLimiter()
	limiter.maxEntries = 2
	now := time.Now()
	limiter.fail("198.51.100.1", now)
	limiter.fail("198.51.100.2", now)
	// A flooded failure map must not lock innocent addresses out (G-WEB-04).
	if !limiter.allow("198.51.100.3", now) {
		t.Fatal("a new address was refused because the failure map was full")
	}
	if pressure := limiter.pressure(now); pressure != 2 {
		t.Fatalf("failure pressure=%d, want 2", pressure)
	}
}

func TestLogoutRevokesTheServerSideSession(t *testing.T) {
	_, backend, front, client := testGateway(t)
	defer backend.Close()
	defer front.Close()
	// Sign in.
	resp, err := client.Get(front.URL + "/login")
	if err != nil {
		t.Fatal(err)
	}
	body := readBody(t, resp)
	csrf := extractCSRF(t, body)
	form := "csrf=" + csrf + "&password=correct+horse+battery+staple"
	loginReq, _ := http.NewRequest(http.MethodPost, front.URL+"/login", strings.NewReader(form))
	loginReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	loginReq.Header.Set("Origin", "null")
	loginReq.Header.Set("Sec-Fetch-Site", "none")
	loginResp, err := client.Do(loginReq)
	if err != nil {
		t.Fatal(err)
	}
	_ = loginResp.Body.Close()
	if loginResp.StatusCode != http.StatusSeeOther {
		t.Fatalf("login status=%d", loginResp.StatusCode)
	}
	cookies := client.Jar.Cookies(mustURL(t, front.URL))
	var sessionCookie *http.Cookie
	for _, cookie := range cookies {
		if cookie.Name == cookieName {
			sessionCookie = cookie
		}
	}
	if sessionCookie == nil {
		t.Fatal("no session cookie issued")
	}
	// Confirm the session works before logout.
	statusReq, _ := http.NewRequest(http.MethodGet, front.URL+"/api/v1/status", nil)
	statusResp, err := client.Do(statusReq)
	if err != nil {
		t.Fatal(err)
	}
	_ = statusResp.Body.Close()
	if statusResp.StatusCode != http.StatusOK {
		t.Fatalf("authenticated proxy status=%d", statusResp.StatusCode)
	}
	// Logout must revoke the record, not only clear the browser cookie.
	logoutReq, _ := http.NewRequest(http.MethodPost, front.URL+"/logout", nil)
	logoutReq.Header.Set("Origin", front.URL)
	logoutResp, err := client.Do(logoutReq)
	if err != nil {
		t.Fatal(err)
	}
	_ = logoutResp.Body.Close()
	if logoutResp.StatusCode != http.StatusSeeOther {
		t.Fatalf("logout status=%d", logoutResp.StatusCode)
	}
	// Replay the captured cookie from a fresh client: it must be invalid.
	replay := &http.Client{Transport: client.Transport, CheckRedirect: func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse }}
	replayReq, _ := http.NewRequest(http.MethodGet, front.URL+"/api/v1/status", nil)
	replayReq.AddCookie(sessionCookie)
	replayResp, err := replay.Do(replayReq)
	if err != nil {
		t.Fatal(err)
	}
	defer replayResp.Body.Close()
	if replayResp.StatusCode == http.StatusOK {
		t.Fatal("a logged-out session cookie still authenticated after logout")
	}
}

func TestProxyCarriesAttestedSessionIdentity(t *testing.T) {
	backendToken := strings.Repeat("b", 40)
	var seen []string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, r.Header.Get(gatewaySessionHeaderName))
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()
	backendURL := mustURL(t, backend.URL)
	key := sha256.Sum256([]byte("session-attestation-key"))
	g := &gateway{backend: backendURL, sessionKey: key[:], backendToken: backendToken, limiter: newLimiter()}
	g.proxy = g.newProxy()
	g.ensureSessions()
	if _, err := g.sessions.create(time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/", g.protectedProxy)
	front := httptest.NewTLSServer(g.security(mux))
	defer front.Close()
	frontURL := mustURL(t, front.URL)
	g.publicHost = frontURL.Host
	g.publicOrigin = front.URL
	session, err := g.sessions.create(time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	client := front.Client()
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse }
	req, _ := http.NewRequest(http.MethodGet, front.URL+"/api/v1/status", nil)
	req.AddCookie(g.sessionCookie(session))
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("proxy status=%d", resp.StatusCode)
	}
	if len(seen) != 1 {
		t.Fatalf("backend saw %d requests", len(seen))
	}
	parts := strings.Split(seen[0], ".")
	if len(parts) != 2 {
		t.Fatalf("attested session header malformed: %q", seen[0])
	}
	mac := hmac.New(sha256.New, []byte(backendToken))
	mac.Write([]byte("VGT-GEDEFENSE-GATEWAY-SESSION\x00"))
	mac.Write([]byte(parts[0]))
	if !hmac.Equal([]byte(parts[1]), []byte(hex.EncodeToString(mac.Sum(nil)))) {
		t.Fatal("attested session binding does not verify with the backend credential")
	}
}

func TestGatewayLivezDoesNotDiscloseVersion(t *testing.T) {
	g := &gateway{}
	rec := httptest.NewRecorder()
	g.livez(rec, httptest.NewRequest(http.MethodGet, "/gateway/livez", nil))
	var payload map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if _, ok := payload["version"]; ok {
		t.Fatal("livez discloses the build version")
	}
	if payload["ok"] != true {
		t.Fatal("livez does not report ok")
	}
}
