// STATUS: DIAMANT VGT SUPREME
package main

// V6.3.0 AP-9 (R6): the gateway-side step-up and role-claim regression suite. It is
// fully in-process: an httptest TLS listener and a recording mock backend.

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	// rbacGatewayBackendToken is both the operator token the control plane knows and
	// the backend credential the gateway presents; the claim MAC is keyed on it.
	rbacGatewayBackendToken = "0123456789abcdef0123456789abcdef"
	// rbacGatewayClaimVector is the pinned cross-component claim MAC. The control
	// plane's verifier and this gateway producer must both reproduce it byte for
	// byte: HMAC-SHA256(key, domain + "critical|password|1700000000|abcdef...") with
	// key = rbacGatewayBackendToken.
	rbacGatewayClaimVector = "4ac29c78b0f3bc6fde1a802d90bccd02b7b689b8b58b28df0e670ec1aa7680df"
)

type rbacGatewayBackendCall struct {
	method string
	path   string
	header http.Header
}

type rbacGatewayFixture struct {
	g            *gateway
	backend      *httptest.Server
	front        *httptest.Server
	client       *http.Client
	backendToken string

	mu    sync.Mutex
	calls []rbacGatewayBackendCall
}

func newRBACGatewayFixture(t *testing.T) *rbacGatewayFixture {
	t.Helper()
	fixture := &rbacGatewayFixture{backendToken: rbacGatewayBackendToken}
	fixture.backend = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fixture.mu.Lock()
		fixture.calls = append(fixture.calls, rbacGatewayBackendCall{method: r.Method, path: r.URL.Path, header: r.Header.Clone()})
		fixture.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"ok":true}`)
	}))
	backendURL, err := url.Parse(fixture.backend.URL)
	if err != nil {
		t.Fatalf("backend url: %v", err)
	}
	salt := []byte("0123456789abcdef")
	password := []byte("correct horse battery staple")
	digest := pbkdf2SHA256(password, salt, 300000, 32)
	sessionKey := sha256.Sum256([]byte("rbac-stepup-test-key"))
	g := &gateway{
		backend:      backendURL,
		password:     passwordRecord{algorithm: "pbkdf2-sha256", iterations: 300000, salt: salt, digest: digest},
		sessionKey:   sessionKey[:],
		backendToken: rbacGatewayBackendToken,
		limiter:      newLimiter(),
	}
	g.proxy = g.newProxy()
	mux := http.NewServeMux()
	mux.HandleFunc("POST /gateway/step-up", g.stepUpRoute)
	mux.HandleFunc("/", g.protectedProxy)
	fixture.front = httptest.NewTLSServer(g.security(mux))
	frontURL := mustURL(t, fixture.front.URL)
	g.publicHost = frontURL.Host
	g.publicOrigin = fixture.front.URL
	fixture.g = g
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatalf("cookie jar: %v", err)
	}
	fixture.client = fixture.front.Client()
	fixture.client.Jar = jar
	fixture.client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return fixture
}

func (f *rbacGatewayFixture) close() {
	f.front.Close()
	f.backend.Close()
}

func (f *rbacGatewayFixture) grantSession(t *testing.T) {
	t.Helper()
	f.grantSessionFor(t, f.client)
}

func (f *rbacGatewayFixture) grantSessionFor(t *testing.T, client *http.Client) {
	t.Helper()
	value, err := f.g.issueSession(time.Now().Add(time.Hour))
	if err != nil {
		t.Fatalf("issue session: %v", err)
	}
	frontURL := mustURL(t, f.front.URL)
	client.Jar.SetCookies(frontURL, []*http.Cookie{{Name: cookieName, Value: value, Path: "/", Secure: true}})
}

func (f *rbacGatewayFixture) do(t *testing.T, client *http.Client, method, path string, body []byte, headers map[string]string) (int, []byte) {
	t.Helper()
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, f.front.URL+path, reader)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	req.Header.Set("Origin", f.front.URL)
	for name, value := range headers {
		req.Header.Set(name, value)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		t.Fatalf("%s %s body: %v", method, path, err)
	}
	return resp.StatusCode, data
}

func (f *rbacGatewayFixture) backendCalls() []rbacGatewayBackendCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	copied := make([]rbacGatewayBackendCall, len(f.calls))
	copy(copied, f.calls)
	return copied
}

func (f *rbacGatewayFixture) stepUpProof(t *testing.T) string {
	t.Helper()
	status, body := f.do(t, f.client, http.MethodPost, "/gateway/step-up",
		[]byte(`{"password":"correct horse battery staple"}`), nil)
	if status != http.StatusOK {
		t.Fatalf("step-up status=%d body=%q", status, body)
	}
	var payload struct {
		Proof     string `json:"step_up_proof"`
		Purpose   string `json:"purpose"`
		ExpiresAt string `json:"expires_at"`
		TTL       int    `json:"ttl_seconds"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		t.Fatalf("step-up answer: %v (%q)", err, body)
	}
	if payload.Proof == "" || payload.Purpose != gatewayCriticalRole || payload.TTL <= 0 ||
		payload.TTL > int(gatewayStepUpProofTTL/time.Second) || payload.ExpiresAt == "" {
		t.Fatalf("step-up answer violates the contract: %+v", payload)
	}
	for _, secret := range []string{"correct horse battery staple", rbacGatewayBackendToken, cookieName} {
		if strings.Contains(string(body), secret) {
			t.Fatalf("the step-up answer leaked secret material %q", secret)
		}
	}
	return payload.Proof
}

// TestRBACGatewayCriticalRouteMatcher pins the gateway's critical-action list. It
// mirrors the control plane classifier; the paths are the AP-7 destructive
// surface and the two lists must be kept in sync (docs/V6.3.0-RBAC.md).
func TestRBACGatewayCriticalRouteMatcher(t *testing.T) {
	critical := []struct{ method, path string }{
		{http.MethodPost, "/api/v1/quarantine/prune"},
		{http.MethodPost, "/api/v1/xdr/review/0123456789abcdef/ack"},
		{http.MethodDelete, "/api/v1/xdr/review/0123456789abcdef"},
	}
	for _, route := range critical {
		if !gatewayCriticalRoute(route.method, route.path) {
			t.Fatalf("%s %s is not classified as critical", route.method, route.path)
		}
	}
	nonCritical := []struct{ method, path string }{
		{http.MethodGet, "/api/v1/quarantine/prune"},
		{http.MethodPost, "/api/v1/quarantine/preview"},
		{http.MethodPost, "/api/v1/xdr/review/0123456789abcdef"},
		{http.MethodDelete, "/api/v1/blocks/0123456789abcdef"},
		{http.MethodPost, "/api/v1/settings/system/preview"},
		{http.MethodPost, "/api/v1/xdr/review//ack"},
		{http.MethodPost, "/api/v1/xdr/review/a/b/ack"},
	}
	for _, route := range nonCritical {
		if gatewayCriticalRoute(route.method, route.path) {
			t.Fatalf("%s %s was classified as critical", route.method, route.path)
		}
	}
}

// TestRBACGatewayClaimMACContractVector pins the exact bytes the control plane
// verifies. If either side changes its domain separator, field order or encoding,
// this fails and the two components would silently stop trusting each other.
func TestRBACGatewayClaimMACContractVector(t *testing.T) {
	got := hex.EncodeToString(gatewayCriticalClaimMAC(
		rbacGatewayBackendToken, gatewayCriticalRole, gatewayStepUpMethodPassword,
		1700000000, "abcdef0123456789abcdef0123456789"))
	if got != rbacGatewayClaimVector {
		t.Fatalf("the gateway claim MAC contract drifted: %s != %s", got, rbacGatewayClaimVector)
	}
}

// TestRBACGatewayPasswordStepUpFlow is the end-to-end browser flow: session +
// password re-entry -> one-time proof -> one MACed critical request.
func TestRBACGatewayPasswordStepUpFlow(t *testing.T) {
	fixture := newRBACGatewayFixture(t)
	defer fixture.close()
	fixture.grantSession(t)
	proof := fixture.stepUpProof(t)

	before := len(fixture.backendCalls())
	status, body := fixture.do(t, fixture.client, http.MethodPost, "/api/v1/quarantine/prune", []byte(`{}`),
		map[string]string{gatewayStepUpProofHeader: proof})
	if status != http.StatusOK {
		t.Fatalf("the critical request failed: status=%d body=%q", status, body)
	}
	calls := fixture.backendCalls()
	if len(calls) != before+1 {
		t.Fatalf("the critical request did not reach the backend: %d", len(calls))
	}
	forwarded := calls[len(calls)-1].header
	if forwarded.Get(gatewayRoleHeader) != gatewayCriticalRole {
		t.Fatalf("the forwarded role claim is %q", forwarded.Get(gatewayRoleHeader))
	}
	if forwarded.Get(gatewayStepUpProofHeader) != "" {
		t.Fatal("the one-time proof was forwarded to the control plane")
	}
	role := forwarded.Get(gatewayRoleHeader)
	stepUp := forwarded.Get(gatewayStepUpHeader)
	tsValue := forwarded.Get(gatewayClaimTsHeader)
	macValue := forwarded.Get(gatewayClaimMACHeader)
	method, nonce, ok := strings.Cut(stepUp, ":")
	if !ok || method != gatewayStepUpMethodPassword || len(nonce) != 2*gatewayStepUpProofTokenBytes {
		t.Fatalf("the forwarded step-up claim has an unexpected shape: %q", stepUp)
	}
	timestamp, err := parseGatewayTestUnix(tsValue)
	if err != nil {
		t.Fatalf("claim timestamp %q: %v", tsValue, err)
	}
	if skew := time.Now().Unix() - timestamp; skew > 5 || -skew > 5 {
		t.Fatalf("claim timestamp is not fresh: %d", skew)
	}
	wantMAC := hex.EncodeToString(gatewayCriticalClaimMAC(rbacGatewayBackendToken, role, method, timestamp, nonce))
	if !hmac.Equal([]byte(macValue), []byte(wantMAC)) {
		t.Fatalf("the forwarded claim MAC does not match the contract: %s != %s", macValue, wantMAC)
	}

	// The proof is single use: a replay is refused and never reaches the backend.
	before = len(fixture.backendCalls())
	status, _ = fixture.do(t, fixture.client, http.MethodPost, "/api/v1/quarantine/prune", []byte(`{}`),
		map[string]string{gatewayStepUpProofHeader: proof})
	if status != http.StatusForbidden {
		t.Fatalf("a replayed step-up proof returned %d", status)
	}
	if len(fixture.backendCalls()) != before {
		t.Fatal("a replayed proof reached the control plane")
	}

	// A proof is only accepted for a critical action; elsewhere it is refused
	// instead of being silently consumed.
	fresh := fixture.stepUpProof(t)
	status, _ = fixture.do(t, fixture.client, http.MethodGet, "/api/v1/status", nil,
		map[string]string{gatewayStepUpProofHeader: fresh})
	if status != http.StatusBadRequest {
		t.Fatalf("a step-up proof on a non-critical route returned %d", status)
	}
}

func parseGatewayTestUnix(value string) (int64, error) {
	var parsed int64
	if value == "" {
		return 0, io.ErrUnexpectedEOF
	}
	for index := 0; index < len(value); index++ {
		if value[index] < '0' || value[index] > '9' {
			return 0, io.ErrUnexpectedEOF
		}
		parsed = parsed*10 + int64(value[index]-'0')
	}
	return parsed, nil
}

// TestRBACGatewayForgedClaimHeadersAreStripped proves a browser cannot inject the
// role claim: the proxy always drops the inbound claim headers and only re-adds a
// claim it produced from a verified one-time proof.
func TestRBACGatewayForgedClaimHeadersAreStripped(t *testing.T) {
	fixture := newRBACGatewayFixture(t)
	defer fixture.close()
	fixture.grantSession(t)
	forged := map[string]string{
		gatewayRoleHeader:     gatewayCriticalRole,
		gatewayStepUpHeader:   "password:" + strings.Repeat("ab", gatewayStepUpProofTokenBytes),
		gatewayClaimTsHeader:  formatGatewayUnix(time.Now().Unix()),
		gatewayClaimMACHeader: strings.Repeat("aa", 32),
	}
	status, _ := fixture.do(t, fixture.client, http.MethodPost, "/api/v1/quarantine/prune", []byte(`{}`), forged)
	if status != http.StatusOK {
		t.Fatalf("the forced request failed before the header check: %d", status)
	}
	calls := fixture.backendCalls()
	if len(calls) != 1 {
		t.Fatalf("unexpected backend call count: %d", len(calls))
	}
	forwarded := calls[0].header
	for _, header := range []string{gatewayRoleHeader, gatewayStepUpHeader, gatewayClaimTsHeader, gatewayClaimMACHeader, gatewayStepUpProofHeader} {
		if forwarded.Get(header) != "" {
			t.Fatalf("the client-controlled %s header reached the control plane: %q", header, forwarded.Get(header))
		}
	}
}

// TestRBACGatewayStepUpRequiresSessionAndOrigin proves the step-up endpoint cannot
// be reached anonymously or cross-origin, and never discloses the build.
func TestRBACGatewayStepUpRequiresSessionAndOrigin(t *testing.T) {
	fixture := newRBACGatewayFixture(t)
	defer fixture.close()
	status, body := fixture.do(t, fixture.client, http.MethodPost, "/gateway/step-up",
		[]byte(`{"password":"correct horse battery staple"}`), nil)
	if status != http.StatusUnauthorized {
		t.Fatalf("an anonymous step-up returned %d", status)
	}
	if strings.Contains(string(body), strings.TrimSuffix(version, "-access")) || strings.Contains(string(body), version) {
		t.Fatalf("the anonymous step-up disclosed the build: %q", body)
	}
	fixture.grantSession(t)
	// A cross-origin request is refused before the password is read.
	req, err := http.NewRequest(http.MethodPost, fixture.front.URL+"/gateway/step-up",
		bytes.NewReader([]byte(`{"password":"correct horse battery staple"}`)))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Origin", "https://attacker.invalid")
	resp, err := fixture.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("a cross-origin step-up returned %d", resp.StatusCode)
	}
}

// TestRBACGatewayStepUpLockout proves the fixed-window brute-force bound and that a
// correct password is admitted again after the window expires.
func TestRBACGatewayStepUpLockout(t *testing.T) {
	current := time.Now()
	fixture := newRBACGatewayFixture(t)
	defer fixture.close()
	fixture.g.ensureStepUp()
	fixture.g.stepUp = newStepUpAuthority(func() time.Time { return current })
	fixture.grantSession(t)
	fixture.g.stepUp.now = func() time.Time { return current }
	for attempt := 0; attempt < gatewayStepUpFailureLimit; attempt++ {
		status, _ := fixture.do(t, fixture.client, http.MethodPost, "/gateway/step-up",
			[]byte(`{"password":"definitely the wrong password"}`), nil)
		if status != http.StatusUnauthorized {
			t.Fatalf("wrong password %d returned %d", attempt, status)
		}
	}
	status, _ := fixture.do(t, fixture.client, http.MethodPost, "/gateway/step-up",
		[]byte(`{"password":"definitely the wrong password"}`), nil)
	if status != http.StatusTooManyRequests {
		t.Fatalf("the source was not locked out: %d", status)
	}
	// A correct password does not bypass an engaged lockout; it is bounded time.
	status, _ = fixture.do(t, fixture.client, http.MethodPost, "/gateway/step-up",
		[]byte(`{"password":"correct horse battery staple"}`), nil)
	if status != http.StatusTooManyRequests {
		t.Fatalf("a locked source was admitted with the correct password: %d", status)
	}
	current = current.Add(gatewayStepUpLockoutDuration + time.Second)
	status, body := fixture.do(t, fixture.client, http.MethodPost, "/gateway/step-up",
		[]byte(`{"password":"correct horse battery staple"}`), nil)
	if status != http.StatusOK {
		t.Fatalf("the source was not admitted after the lockout expired: %d %q", status, body)
	}
}

// TestRBACGatewayStepUpProofIsSessionBound proves a proof cannot be moved to
// another operator session.
func TestRBACGatewayStepUpProofIsSessionBound(t *testing.T) {
	fixture := newRBACGatewayFixture(t)
	defer fixture.close()
	fixture.grantSession(t)
	proof := fixture.stepUpProof(t)

	// A second, independently authenticated browser gets its own session.
	secondClient := fixture.front.Client()
	secondJar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	secondClient.Jar = secondJar
	secondClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	fixture.grantSessionFor(t, secondClient)
	status, _ := fixture.do(t, secondClient, http.MethodPost, "/api/v1/quarantine/prune", []byte(`{}`),
		map[string]string{gatewayStepUpProofHeader: proof})
	if status != http.StatusForbidden {
		t.Fatalf("a step-up proof was accepted by another session: %d", status)
	}
}

// TestRBACGatewayStepUpAuthorityIsBounded proves the one-time proof table and the
// per-source failure table are bounded.
func TestRBACGatewayStepUpAuthorityIsBounded(t *testing.T) {
	current := time.Now()
	authority := newStepUpAuthority(func() time.Time { return current })
	authority.maxEntries = 2
	first, _, err := authority.issue("session-a")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := authority.issue("session-a"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := authority.issue("session-a"); err != nil {
		t.Fatal(err)
	}
	authority.mu.Lock()
	proofs := len(authority.proofs)
	authority.mu.Unlock()
	if proofs > authority.maxEntries {
		t.Fatalf("the proof table grew past its bound: %d", proofs)
	}
	// The evicted proof is refused; that is the documented bounded-cache
	// trade-off (a proof storm cannot grow memory without bound).
	if authority.consume("session-a", first) {
		t.Fatal("an evicted proof was still accepted")
	}
	authority.maxSources = 3
	for index := 0; index < 32; index++ {
		authority.fail("source-" + formatGatewayInt(int64(index)))
	}
	authority.mu.Lock()
	sources := len(authority.failures)
	authority.mu.Unlock()
	if sources > authority.maxSources {
		t.Fatalf("the failure table grew past its bound: %d", sources)
	}
}

// TestLoginLockoutAfterRepeatedPasswordFailures proves the pre-existing sign-in
// brute-force bound still holds (the step-up path has its own guard).
func TestLoginLockoutAfterRepeatedPasswordFailures(t *testing.T) {
	_, backend, front, client := testGateway(t)
	defer backend.Close()
	defer front.Close()
	resp, err := client.Get(front.URL + "/login")
	if err != nil {
		t.Fatal(err)
	}
	csrf := extractCSRF(t, readBody(t, resp))
	for attempt := 0; attempt < 5; attempt++ {
		form := url.Values{"csrf": {csrf}, "password": {"definitely the wrong password"}}
		req, err := http.NewRequest(http.MethodPost, front.URL+"/login", strings.NewReader(form.Encode()))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Origin", front.URL)
		response, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
	}
	form := url.Values{"csrf": {csrf}, "password": {"correct horse battery staple"}}
	req, err := http.NewRequest(http.MethodPost, front.URL+"/login", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", front.URL)
	response, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusTooManyRequests || response.Header.Get("Retry-After") == "" {
		t.Fatalf("the sign-in source was not locked out: status=%d retry=%q", response.StatusCode, response.Header.Get("Retry-After"))
	}
}
