package edgeproxy

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func validConfig() Config {
	cfg := DefaultConfig()
	cfg.Enabled = true
	cfg.CertFile = "/etc/gedefense/edge/fullchain.pem"
	cfg.KeyFile = "/etc/gedefense/edge/privkey.pem"
	return cfg
}

func TestConfigRequiresLoopbackListenerAndSafeUpstream(t *testing.T) {
	cfg := validConfig()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("default config rejected: %v", err)
	}
	exposed := cfg
	exposed.Listen = "0.0.0.0:8443"
	if err := exposed.Validate(); err == nil {
		t.Fatal("a public listen address must be rejected")
	}
	remote := cfg
	remote.Upstream = "http://203.0.113.5:8080"
	if err := remote.Validate(); err == nil {
		t.Fatal("a non-loopback upstream must be rejected")
	}
	traversal := cfg
	traversal.Upstream = "unix:///run/../etc/shadow"
	if err := traversal.Validate(); err == nil {
		t.Fatal("a traversing unix socket path must be rejected")
	}
	missingCert := cfg
	missingCert.CertFile = ""
	if err := missingCert.Validate(); err == nil {
		t.Fatal("enabled without a certificate must be rejected")
	}
	disabled := cfg
	disabled.Enabled = false
	disabled.CertFile, disabled.KeyFile = "", ""
	if err := disabled.Validate(); err != nil {
		t.Fatalf("disabled config without certificate rejected: %v", err)
	}
}

func TestConfigNormalizeBounds(t *testing.T) {
	cfg := validConfig()
	cfg.AllowedMethods = []string{"get", "GET", " post ", ""}
	cfg.MinTLSVersion = "tls1.2"
	normalized := cfg.Normalize()
	if normalized.MinTLSVersion != "TLS1.2" {
		t.Fatalf("min TLS = %q", normalized.MinTLSVersion)
	}
	if strings.Join(normalized.AllowedMethods, ",") != "GET,POST" {
		t.Fatalf("methods = %v", normalized.AllowedMethods)
	}
	if err := normalized.Validate(); err != nil {
		t.Fatalf("normalized config rejected: %v", err)
	}
}

func request(t *testing.T, method, target string) *http.Request {
	t.Helper()
	parsed, err := url.Parse(target)
	if err != nil {
		t.Fatalf("parse target: %v", err)
	}
	r := &http.Request{
		Method: method,
		URL:    parsed,
		Host:   "example.org",
		Header: http.Header{},
		Proto:  "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1,
		ContentLength: 0,
		RemoteAddr:    "203.0.113.9:44321",
	}
	return r
}

func allowedSet(cfg Config) map[string]bool {
	out := make(map[string]bool, len(cfg.AllowedMethods))
	for _, method := range cfg.AllowedMethods {
		out[method] = true
	}
	return out
}

func TestInspectRequestAllowsNormalTraffic(t *testing.T) {
	cfg := validConfig()
	allowed := allowedSet(cfg)
	for _, target := range []string{"/", "/index.php?p=1", "/wp-admin/", "/a/b/c?x=%20y", "/v1..2/file"} {
		if verdict := InspectRequest(request(t, "GET", target), cfg, allowed); verdict.Blocked {
			t.Fatalf("%s blocked: %s", target, verdict.Reason)
		}
	}
}

func TestInspectRequestBlocksTraversalSegmentsOnly(t *testing.T) {
	cfg := validConfig()
	allowed := allowedSet(cfg)
	for _, target := range []string{"/a/../b", "/..", "/%2e%2e/x"} {
		if verdict := InspectRequest(request(t, "GET", target), cfg, allowed); !verdict.Blocked || verdict.Reason != "path_traversal" {
			t.Fatalf("%s verdict = %+v, want path_traversal", target, verdict)
		}
	}
	// A double dot inside a file name is not a traversal and must stay usable:
	// blocking it would be a denial of legitimate traffic.
	if verdict := InspectRequest(request(t, "GET", "/v1..2/file"), cfg, allowed); verdict.Blocked {
		t.Fatalf("legitimate name blocked: %s", verdict.Reason)
	}
}

func TestInspectRequestBlocksStructuralAttacks(t *testing.T) {
	cfg := validConfig()
	allowed := allowedSet(cfg)
	cases := []struct {
		method string
		target string
		reason string
	}{
		{"TRACE", "/", "method_not_allowed"},
		{"GET", "/../../etc/passwd", "path_traversal"},
		{"GET", "/%2e%2e/%2e%2e/etc/passwd", "path_traversal"},
		{"GET", "/a%00b", "control_byte_in_target"},
		{"GET", "/ok?q=%00", "nul_in_query"},
		{"GET", "/" + strings.Repeat("a", 4000), "request_target_too_long"},
	}
	for _, c := range cases {
		verdict := InspectRequest(request(t, c.method, c.target), cfg, allowed)
		if !verdict.Blocked || verdict.Reason != c.reason {
			t.Fatalf("%s %s: got %+v want reason %s", c.method, c.target, verdict, c.reason)
		}
	}
}

func TestInspectRequestEnforcesBodyAndHeaderBudgets(t *testing.T) {
	cfg := validConfig()
	allowed := allowedSet(cfg)
	big := request(t, "POST", "/upload")
	big.ContentLength = cfg.MaxBodyBytes + 1
	if verdict := InspectRequest(big, cfg, allowed); verdict.Reason != "body_too_large" {
		t.Fatalf("large body verdict = %+v", verdict)
	}
	safe := request(t, "GET", "/")
	safe.ContentLength = 1
	if verdict := InspectRequest(safe, cfg, allowed); verdict.Reason != "body_on_safe_method" {
		t.Fatalf("GET body verdict = %+v", verdict)
	}
	many := request(t, "GET", "/")
	for index := 0; index < 70; index++ {
		many.Header.Set(fmt.Sprintf("X-Probe-%02d", index), "1")
	}
	if verdict := InspectRequest(many, cfg, allowed); verdict.Reason != "too_many_headers" {
		t.Fatalf("header count verdict = %+v", verdict)
	}
}

func TestInspectRequestRejectsAmbiguousFraming(t *testing.T) {
	cfg := validConfig()
	allowed := allowedSet(cfg)
	smuggled := request(t, "POST", "/")
	smuggled.Header.Set("Transfer-Encoding", "chunked")
	smuggled.ContentLength = 12
	if verdict := InspectRequest(smuggled, cfg, allowed); verdict.Reason != "ambiguous_body_framing" {
		t.Fatalf("smuggling verdict = %+v", verdict)
	}
}

func TestLimiterAllowsBurstThenDenies(t *testing.T) {
	l := newLimiter(60, 8) // 1/s, burst 60
	allowed := 0
	for index := 0; index < 80; index++ {
		if l.allow("198.51.100.7") {
			allowed++
		}
	}
	if allowed == 0 || allowed >= 80 {
		t.Fatalf("limiter allowed %d of 80", allowed)
	}
	if !l.allow("198.51.100.8") {
		t.Fatal("a different peer must have its own budget")
	}
}

func TestLimiterTableIsBounded(t *testing.T) {
	l := newLimiter(60, 4)
	for index := 0; index < 64; index++ {
		l.allow("peer-" + strings.Repeat("x", index))
	}
	if len(l.peers) > 4 {
		t.Fatalf("limiter table grew to %d", len(l.peers))
	}
}

func TestDisabledManagerStaysStopped(t *testing.T) {
	manager := NewManager()
	cfg := DefaultConfig()
	cfg.Enabled = false
	if err := manager.Sync(cfg); err != nil {
		t.Fatalf("sync disabled: %v", err)
	}
	status := manager.Status()
	if status.State != StateStopped || status.Enabled {
		t.Fatalf("status = %+v", status)
	}
}

func TestClientPeerStripsPort(t *testing.T) {
	if got := clientPeer("203.0.113.9:44321"); got != "203.0.113.9" {
		t.Fatalf("peer = %q", got)
	}
	if got := clientPeer("[2001:db8::1]:443"); got != "2001:db8::1" {
		t.Fatalf("peer = %q", got)
	}
}

// TestEdgeRewriteStripsSpoofedForwardingHeaders is FIND-006: a client-supplied
// X-Forwarded-For (or RFC 7239 Forwarded) must never reach the upstream. The
// upstream may only see the peer address the proxy derived from the connection.
func TestEdgeRewriteStripsSpoofedForwardingHeaders(t *testing.T) {
	seen := make(chan http.Header, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen <- r.Header.Clone()
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()

	cfg := validConfig()
	cfg.Upstream = upstream.URL
	proxy, err := buildProxy(cfg)
	if err != nil {
		t.Fatalf("build proxy: %v", err)
	}
	inbound := request(t, "GET", "/")
	inbound.Header.Set("X-Forwarded-For", "203.0.113.66")
	inbound.Header.Set("X-Real-IP", "203.0.113.66")
	inbound.Header.Set("Forwarded", "for=203.0.113.66;proto=https")
	recorder := httptest.NewRecorder()
	proxy.ServeHTTP(recorder, inbound)
	if recorder.Code != http.StatusNoContent {
		t.Fatalf("upstream status = %d body=%s", recorder.Code, recorder.Body.String())
	}
	headers := <-seen
	if got := headers.Values("X-Forwarded-For"); len(got) != 1 || got[0] != "203.0.113.9" {
		t.Fatalf("upstream X-Forwarded-For = %v, want only the peer address 203.0.113.9", got)
	}
	if got := headers.Get("X-Real-IP"); got != "" {
		t.Fatalf("upstream X-Real-IP = %q, want the spoofed header removed", got)
	}
	if got := headers.Get("Forwarded"); got != "" {
		t.Fatalf("upstream Forwarded = %q, want the spoofed header removed", got)
	}
}
