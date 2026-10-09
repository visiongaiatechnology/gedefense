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

		// The property that matters is that no session is granted. This used to be
		// asserted as a 403, which was a weaker statement: it checked the status a
		// rejection happened to carry rather than whether the request authenticated.
		// A stale form is now sent back to a fresh one instead of refused outright, and
		// that must not - and does not - let it through.
		for _, cookie := range resp.Cookies() {
			if cookie.Name == cookieName && cookie.Value != "" {
				t.Fatalf("csrf=%q was granted a session", supplied)
			}
		}
		if resp.StatusCode == http.StatusSeeOther && resp.Header.Get("Location") == "/" {
			t.Fatalf("csrf=%q was treated as a successful sign-in", supplied)
		}
		if resp.StatusCode != http.StatusForbidden && resp.StatusCode != http.StatusSeeOther {
			t.Fatalf("csrf=%q status=%d", supplied, resp.StatusCode)
		}
	}
}

// TestStaleSignInPageIsSentBackToAFreshOne covers the failure that had no way out.
//
// An operator who opened the sign-in page, was called away and came back found their
// password refused with a bare "request rejected" - no cause, no remedy, and no hint that
// reloading would have fixed it. The token no longer expires inside a working day, and a
// form that is stale anyway now lands on a page that says so.
func TestStaleSignInPageIsSentBackToAFreshOne(t *testing.T) {
	_, backend, front, client := testGateway(t)
	defer backend.Close()
	defer front.Close()

	form := url.Values{"csrf": {"a-token-that-was-never-issued"}, "password": {"correct horse battery staple"}}
	req, _ := http.NewRequest(http.MethodPost, front.URL+"/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", front.URL)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("a stale form was not redirected to a fresh page: status=%d", resp.StatusCode)
	}
	if location := resp.Header.Get("Location"); !strings.HasPrefix(location, "/login?lang=") {
		t.Fatalf("a stale form was sent to %q", location)
	}
	// The reason rides a one-shot cookie rather than the URL, so that reloading the page
	// cannot repeat a refusal that has already been explained.
	noticed := false
	for _, c := range resp.Cookies() {
		if c.Name == noticeCookieName && c.Value == noticeStale {
			noticed = true
		}
	}
	if !noticed {
		t.Fatalf("a stale form was not told why it was refused: cookies=%v", resp.Cookies())
	}
	for _, cookie := range resp.Cookies() {
		if cookie.Name == cookieName && cookie.Value != "" {
			t.Fatal("a stale form was granted a session")
		}
	}

	// The page it lands on says what happened, in the language of the request.
	for _, lang := range []string{"de", "en", "ru", "zh-CN"} {
		document := renderLoginWithState(t, lang, true, false, true)
		if !strings.Contains(document, copyForLanguage(lang).Stale) {
			t.Fatalf("lang=%s does not render the stale explanation", lang)
		}
		if strings.Contains(document, copyForLanguage(lang).Failed) {
			t.Fatalf("lang=%s shows the wrong-password message for a stale form", lang)
		}
	}
}

// TestFurtherRequestsForTheSignInPageDoNotInvalidateTheOpenForm covers the failure that
// survived the first repair and that reloading could never clear.
//
// The sign-in page carries its own language links. Browsers prefetch and prerender them,
// and every request for the page used to mint a fresh token and overwrite the cookie. The
// form on screen then held a token the cookie no longer matched, so submitting it was
// refused as stale while the page in front of the operator looked perfectly current - and
// the reload that followed re-rendered the form and re-armed the same race. A second tab,
// a back/forward restore and a third-party <img> pointing at this endpoint all did it too.
//
// The contract is now: the token a browser is given stays valid for that browser until it
// expires, however many times the page is fetched.
func TestFurtherRequestsForTheSignInPageDoNotInvalidateTheOpenForm(t *testing.T) {
	_, backend, front, client := testGateway(t)
	defer backend.Close()
	defer front.Close()

	// The form the operator is looking at, and keeps looking at.
	rendered := fetchLoginForm(t, client, front.URL+"/login")

	// What the page does to itself. Each of these used to replace the token.
	prefetched := []string{"/login?lang=en", "/login?lang=ru", "/login?lang=de", "/login"}
	for _, path := range prefetched {
		if again := fetchLoginForm(t, client, front.URL+path); again != rendered {
			t.Fatalf("GET %s replaced the token the open form carries: %q became %q", path, rendered, again)
		}
	}

	// The operator submits the form that was on screen the whole time, with the correct
	// password: the sign-in has to be honoured, not merely refused politely.
	form := url.Values{"csrf": {rendered}, "password": {"correct horse battery staple"}}
	req, _ := http.NewRequest(http.MethodPost, front.URL+"/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "null")
	req.Header.Set("Sec-Fetch-Site", "none")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/?lang=de" {
		t.Fatalf("a form rendered before %d further page views was refused: status=%d location=%q",
			len(prefetched), resp.StatusCode, resp.Header.Get("Location"))
	}
	u, _ := url.Parse(front.URL)
	granted := false
	for _, c := range client.Jar.Cookies(u) {
		if c.Name == cookieName && c.Value != "" {
			granted = true
		}
	}
	if !granted {
		t.Fatal("the sign-in was accepted but no session was issued")
	}
}

func fetchLoginForm(t *testing.T, client *http.Client, target string) string {
	t.Helper()
	return extractCSRF(t, fetchLoginBody(t, client, target))
}

func fetchLoginBody(t *testing.T, client *http.Client, target string) string {
	t.Helper()
	resp, err := client.Get(target)
	if err != nil {
		t.Fatalf("GET %s: %v", target, err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s status=%d", target, resp.StatusCode)
	}
	return string(body)
}

// TestTheRefusalReasonIsShownOnceAndNotOnReload covers what made a correct repair look
// broken to the operator.
//
// The reason for a refusal travelled in the query string, so it became a property of the
// address rather than of what had happened: reloading the page - or returning to it from
// history - repeated "this sign-in page had expired" over a form that had just been issued
// and was perfectly valid. The only way to make the page stop saying it was to edit the
// URL. The reason now rides a one-shot cookie that the page consumes, so it is shown once
// and every later load states the current truth.
func TestTheRefusalReasonIsShownOnceAndNotOnReload(t *testing.T) {
	_, backend, front, client := testGateway(t)
	defer backend.Close()
	defer front.Close()

	form := url.Values{"csrf": {"a-token-that-was-never-issued"}, "password": {"correct horse battery staple"}}
	req, _ := http.NewRequest(http.MethodPost, front.URL+"/login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", front.URL)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	explained := copyForLanguage("de").Stale
	if body := fetchLoginBody(t, client, front.URL+"/login?lang=de"); !strings.Contains(body, explained) {
		t.Fatal("the page that followed the refusal did not say why it happened")
	}
	for reload := 1; reload <= 3; reload++ {
		if body := fetchLoginBody(t, client, front.URL+"/login?lang=de"); strings.Contains(body, explained) {
			t.Fatalf("reload %d repeated a refusal that had already been explained", reload)
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
	// Loopback identities on the gateway port must also be permitted
	for _, loopbackHost := range []string{"127.0.0.1:9843", "localhost:9843", "[::1]:9843"} {
		lbReq := httptest.NewRequest(http.MethodGet, "https://"+loopbackHost+"/", nil)
		lbReq.Host = loopbackHost
		rr = httptest.NewRecorder()
		h.ServeHTTP(rr, lbReq)
		if rr.Code != http.StatusNoContent {
			t.Fatalf("loopback host %q rejected, status=%d", loopbackHost, rr.Code)
		}
	}

	for _, badHost := range []string{
		"attacker.invalid",
		"attacker.invalid:9843",
		"127.0.0.1:8080",
		"localhost:8080",
		"192.168.1.50:9843",
	} {
		bad := httptest.NewRequest(http.MethodGet, "https://"+badHost+"/", nil)
		bad.Host = badHost
		rr = httptest.NewRecorder()
		h.ServeHTTP(rr, bad)
		if rr.Code != http.StatusBadRequest {
			t.Fatalf("host allowlist accepted unsafe host %q, status=%d", badHost, rr.Code)
		}
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
		{lang: "zh-CN", text: "操作员访问"},
	} {
		req := httptest.NewRequest(http.MethodGet, "https://203.0.113.10:9843/login?lang="+tc.lang, nil)
		req.Host = "203.0.113.10:9843"
		rr := httptest.NewRecorder()
		g.loginPage(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("lang=%s status=%d", tc.lang, rr.Code)
		}
		body := rr.Body.String()
		// The expected version is read from the same constant the page renders. Written as a
		// literal it made this test fail for the one reason that is not a defect: the release
		// version changed.
		productVersion := strings.TrimSuffix(version, "-access")
		for _, expected := range []string{
			"GeDefense", "VisionGaiaTechnology", productVersion, tc.text,
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
