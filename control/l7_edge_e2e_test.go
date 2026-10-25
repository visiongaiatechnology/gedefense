//go:build linux

// STATUS: DIAMANT VGT SUPREME
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// End-to-end tests for the inline edge as a first-class L7 producer.
//
// Unlike the engine-level tests, these tests run a real Unix-socket HTTP server
// (the inline edge), a real TCP upstream (httptest) and a real client that dials
// the Unix socket. They are Linux-only because the peer-credential path depends on
// SO_PEERCRED, which is the security boundary the edge enforces in production.

type l7InlineProducerUpstream struct {
	hits        atomic.Int64
	mu          sync.Mutex
	lastHeaders http.Header
	lastURI     string
	lastHost    string
}

func (u *l7InlineProducerUpstream) header(name string) string {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.lastHeaders == nil {
		return ""
	}
	return u.lastHeaders.Get(name)
}

func newL7InlineProducerFixture(t *testing.T, mode string, mutate func(*L7Config), respond func(http.ResponseWriter, *http.Request)) (*L7EdgeService, *L7Engine, *http.Client, *l7InlineProducerUpstream, *L7Config) {
	t.Helper()

	upstreamState := &l7InlineProducerUpstream{}
	upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamState.hits.Add(1)
		upstreamState.mu.Lock()
		upstreamState.lastHeaders = r.Header.Clone()
		upstreamState.lastURI = r.URL.RequestURI()
		upstreamState.lastHost = r.Host
		upstreamState.mu.Unlock()
		if respond != nil {
			respond(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = io.WriteString(w, "ok")
	}))
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	upstream.Listener = listener
	upstream.Start()
	t.Cleanup(upstream.Close)

	cfg := l7TestConfig()
	cfg.Mode = mode
	cfg.InlineEnabled = true
	cfg.InlineSocket = filepath.Join(t.TempDir(), "edge.sock")
	cfg.InlineUpstream = "http://" + upstream.Listener.Addr().String()
	cfg.InlineMaxResponseBytes = 64 << 10
	if mutate != nil {
		mutate(&cfg)
	}

	engine, err := NewL7Engine(cfg, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	state := NewState("test", Config{L7: cfg, XDR: defaultConfig().XDR, Release: defaultConfig().Release})
	service, err := NewL7EdgeService(cfg, engine, state)
	if err != nil {
		t.Fatal(err)
	}
	if err := service.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = service.Shutdown(ctx)
	})

	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			DisableKeepAlives: true,
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "unix", cfg.InlineSocket)
			},
		},
	}
	return service, engine, client, upstreamState, &cfg
}

func l7InlineProducerRequest(t *testing.T, method, uri string, body []byte, headers map[string]string) *http.Request {
	t.Helper()
	request, err := http.NewRequest(method, "http://unix"+uri, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	request.Host = "example.test"
	request.Header.Set(l7EdgeClientIPHeader, "203.0.113.50")
	request.Header.Set(l7EdgeSchemeHeader, "https")
	for name, value := range headers {
		request.Header.Set(name, value)
	}
	return request
}

func l7InlineProducerDo(t *testing.T, client *http.Client, request *http.Request) (int, []byte) {
	t.Helper()
	response, err := client.Do(request)
	if err != nil {
		t.Fatalf("inline edge request failed: %v", err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("reading inline edge response failed: %v", err)
	}
	return response.StatusCode, body
}

func l7InlineProducerStatus(t *testing.T, service *L7EdgeService) map[string]any {
	t.Helper()
	// Snapshot derives coverage from the counters, and serialization applies the
	// attachment verdict, so this is exactly what an operator's status API serves.
	return l7StatusWire(t, service.state.Snapshot().L7)
}

// TestL7InlineEdgeEndToEndBenignTraffic proves the full chain: client -> Unix socket
// -> inline edge -> real TCP upstream. The benign request must reach the upstream and
// the status must report the inline edge as an attached, verified producer.
func TestL7InlineEdgeEndToEndBenignTraffic(t *testing.T) {
	service, _, client, upstream, _ := newL7InlineProducerFixture(t, "block", nil, nil)

	status, body := l7InlineProducerDo(t, client, l7InlineProducerRequest(t, http.MethodGet, "/health", nil, nil))
	if status != http.StatusOK || string(body) != "ok" {
		t.Fatalf("benign request did not traverse the edge: status=%d body=%q", status, body)
	}
	if upstream.hits.Load() != 1 {
		t.Fatalf("upstream was contacted %d time(s) for one request", upstream.hits.Load())
	}
	if got := upstream.lastURI; got != "/health" {
		t.Fatalf("upstream saw URI %q", got)
	}
	if host := upstream.lastHost; host != "example.test" {
		t.Fatalf("upstream Host was not preserved: %q", host)
	}

	view := l7InlineProducerStatus(t, service)
	if got := l7WireUint(t, view, "inline_requests_total"); got != 1 {
		t.Fatalf("inline_requests_total=%d after one request", got)
	}
	if got := l7WireUint(t, view, "requests_total"); got != 1 {
		t.Fatalf("requests_total must aggregate the inline request, got %d", got)
	}
	for _, field := range []string{"producer_attached", "inline_producer_attached", "traffic_path_attached", "traffic_path_verified"} {
		if !l7WireBool(t, view, field) {
			t.Fatalf("status field %q is false after verified inline traffic: %v", field, view)
		}
	}
	reason, _ := view["inline_attachment_reason"].(string)
	if !strings.Contains(reason, "inspected") {
		t.Fatalf("attachment reason does not name verified traffic: %q", reason)
	}
	if _, ok := view["inline_last_request_at"]; !ok {
		t.Fatal("status is missing inline_last_request_at after inline traffic")
	}
}

// TestL7InlineEdgeBlocksPayloadsBeforeUpstream covers the acceptance criterion: real
// payloads over the real socket are blocked by the L7 engine and never reach the
// upstream. The path-traversal case is the LFI form (stream wrapper + traversal), which
// is what crosses the configured block threshold at the default policy.
func TestL7InlineEdgeBlocksPayloadsBeforeUpstream(t *testing.T) {
	service, engine, client, upstream, _ := newL7InlineProducerFixture(t, "block", nil, nil)
	engine.canBlock = func() bool { return true }

	cases := []struct {
		name string
		uri  string
	}{
		{
			name: "sqli_union",
			uri:  "/?q=%2555NION%2520SELECT%2520password%2520FROM%2520users--",
		},
		{
			name: "xss_script",
			uri:  "/?x=%3Cscript%3Ealert(1)%3C/script%3E",
		},
		{
			name: "path_traversal_lfi",
			uri:  "/?file=php://filter/convert.base64-encode/resource=../../etc/passwd",
		},
		{
			name: "command_injection",
			uri:  "/?cmd=;%20curl%20http://127.0.0.1/x",
		},
	}

	before := l7InlineProducerStatus(t, service)
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			hitsBefore := upstream.hits.Load()
			status, _ := l7InlineProducerDo(t, client, l7InlineProducerRequest(t, http.MethodGet, test.uri, nil, nil))
			if status < 400 || status >= 500 {
				t.Fatalf("payload was not blocked: status=%d uri=%s", status, test.uri)
			}
			if got := upstream.hits.Load(); got != hitsBefore {
				t.Fatalf("blocked payload reached the upstream (%d -> %d)", hitsBefore, got)
			}
		})
	}

	after := l7InlineProducerStatus(t, service)
	if l7WireUint(t, after, "inline_blocked_total") <= l7WireUint(t, before, "inline_blocked_total") {
		t.Fatal("inline_blocked_total did not move for blocked payloads")
	}
	if l7WireUint(t, after, "blocked_total") <= l7WireUint(t, before, "blocked_total") {
		t.Fatal("blocked_total did not aggregate the inline blocks")
	}
	if l7WireUint(t, after, "inline_findings_total") <= l7WireUint(t, before, "inline_findings_total") {
		t.Fatal("inline_findings_total did not move for detected payloads")
	}
	if !l7WireBool(t, after, "inline_producer_attached") {
		t.Fatal("the inline edge stopped being an attached producer after blocking traffic")
	}
}

// TestL7InlineEdgeStillDetectsBelowBlockThreshold is the counter-case for coverage: a
// traversal payload whose score stays below the block threshold must still be counted
// as a finding. Either outcome (forwarded or blocked) is acceptable; silently passing
// without a finding is not.
func TestL7InlineEdgeStillDetectsBelowBlockThreshold(t *testing.T) {
	service, engine, client, _, _ := newL7InlineProducerFixture(t, "block", nil, nil)
	engine.canBlock = func() bool { return true }

	before := l7InlineProducerStatus(t, service)
	_, _ = l7InlineProducerDo(t, client, l7InlineProducerRequest(t, http.MethodGet, "/?file=../../etc/passwd", nil, nil))
	after := l7InlineProducerStatus(t, service)
	if l7WireUint(t, after, "inline_findings_total") <= l7WireUint(t, before, "inline_findings_total") {
		t.Fatal("a traversal payload did not produce an L7 finding")
	}
}

// TestL7InlineEdgeInspectsResponseAndPreservesBody covers response inspection through
// the real proxy path: the upstream body must arrive byte-identical and the response
// counters must move.
func TestL7InlineEdgeInspectsResponseAndPreservesBody(t *testing.T) {
	const leak = "SQLSTATE[42000]: syntax error near secret_table"
	service, _, client, _, _ := newL7InlineProducerFixture(t, "block", nil, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = io.WriteString(w, leak)
	})

	status, body := l7InlineProducerDo(t, client, l7InlineProducerRequest(t, http.MethodGet, "/failure", nil, nil))
	if status != http.StatusInternalServerError {
		t.Fatalf("response status changed in transit: %d", status)
	}
	if string(body) != leak {
		t.Fatalf("response body changed during inspection: %q", body)
	}
	view := l7InlineProducerStatus(t, service)
	if got := l7WireUint(t, view, "responses_inspected_total"); got != 1 {
		t.Fatalf("responses_inspected_total=%d after one response", got)
	}
	if l7WireUint(t, view, "response_findings_total") == 0 {
		t.Fatal("the error-leak response produced no finding")
	}
	if l7WireUint(t, view, "findings_total") == 0 {
		t.Fatal("findings_total does not aggregate the inline response findings")
	}
}

// TestL7InlineEdgePeerCredentialPolicy covers the peer-credential path end to end: the
// same-UID client is authorized, a foreign identity is refused before inspection, and
// the reserved self-test path works without a permanent producer policy entry.
func TestL7InlineEdgePeerCredentialPolicy(t *testing.T) {
	t.Run("authorized_same_identity", func(t *testing.T) {
		_, _, client, upstream, _ := newL7InlineProducerFixture(t, "block", nil, nil)
		status, _ := l7InlineProducerDo(t, client, l7InlineProducerRequest(t, http.MethodGet, "/peer", nil, nil))
		if status != http.StatusOK {
			t.Fatalf("same-UID peer was refused: %d", status)
		}
		if upstream.hits.Load() != 1 {
			t.Fatalf("authorized request did not reach the upstream: %d", upstream.hits.Load())
		}
	})

	t.Run("foreign_identity_refused", func(t *testing.T) {
		service, _, client, upstream, _ := newL7InlineProducerFixture(t, "block", func(cfg *L7Config) {
			cfg.AllowedPeerUIDs = []uint32{uint32(os.Getuid()) + 1}
			cfg.AllowedPeerGIDs = nil
			cfg.SocketGroup = ""
		}, nil)
		status, _ := l7InlineProducerDo(t, client, l7InlineProducerRequest(t, http.MethodGet, "/peer", nil, nil))
		if status != http.StatusForbidden {
			t.Fatalf("foreign peer identity was not refused: %d", status)
		}
		if upstream.hits.Load() != 0 {
			t.Fatalf("refused peer reached the upstream %d time(s)", upstream.hits.Load())
		}
		view := l7InlineProducerStatus(t, service)
		if got := l7WireUint(t, view, "inline_requests_total"); got != 0 {
			t.Fatalf("a refused peer moved the inspection counter: %d", got)
		}
	})

	t.Run("reserved_self_test_path", func(t *testing.T) {
		service, _, client, upstream, _ := newL7InlineProducerFixture(t, "block", func(cfg *L7Config) {
			// No permanent producer policy: the self-test must still be able to prove
			// the path, because it runs from the control process's own identity.
			cfg.AllowedPeerUIDs = nil
			cfg.AllowedPeerGIDs = nil
			cfg.SocketGroup = ""
		}, nil)
		request := l7InlineProducerRequest(t, http.MethodGet, l7SelfTestPath, nil, map[string]string{
			"X-Gedefense-Self-Test": "1",
		})
		status, _ := l7InlineProducerDo(t, client, request)
		if status != http.StatusOK {
			t.Fatalf("the reserved self-test path was refused: %d", status)
		}
		if upstream.hits.Load() != 1 {
			t.Fatalf("the self-test request was not forwarded: %d", upstream.hits.Load())
		}
		view := l7InlineProducerStatus(t, service)
		if !l7WireBool(t, view, "inline_producer_attached") {
			t.Fatal("the self-test did not establish the inline producer")
		}
	})
}

// TestL7InlineEdgeHardensForwardingHeaders covers the proxy trust boundary: hop-local
// and Connection-nominated headers must not be forwarded, spoofed X-Forwarded-* values
// are replaced by the peer-attested identity, and internal proxy metadata never leaks.
func TestL7InlineEdgeHardensForwardingHeaders(t *testing.T) {
	_, _, client, upstream, _ := newL7InlineProducerFixture(t, "block", nil, nil)

	request := l7InlineProducerRequest(t, http.MethodGet, "/headers", nil, map[string]string{
		"Connection":        "X-Leak-Header",
		"X-Leak-Header":     "secret",
		"X-Forwarded-For":   "10.0.0.1",
		"X-Forwarded-Proto": "http",
		"X-Real-Ip":         "10.1.1.1",
	})
	status, _ := l7InlineProducerDo(t, client, request)
	if status != http.StatusOK {
		t.Fatalf("header-hardening request failed: %d", status)
	}
	if got := upstream.header("X-Leak-Header"); got != "" {
		t.Fatalf("Connection-nominated header reached the upstream: %q", got)
	}
	if got := upstream.header("Connection"); got != "" {
		t.Fatalf("hop-by-hop Connection header reached the upstream: %q", got)
	}
	if got := upstream.header(l7EdgeClientIPHeader); got != "" {
		t.Fatalf("internal client-ip metadata leaked upstream: %q", got)
	}
	if got := upstream.header(l7EdgeSchemeHeader); got != "" {
		t.Fatalf("internal scheme metadata leaked upstream: %q", got)
	}
	if got := upstream.header("X-Forwarded-For"); got != "203.0.113.50" {
		t.Fatalf("spoofed X-Forwarded-For survived: %q", got)
	}
	if got := upstream.header("X-Forwarded-Proto"); got != "https" {
		t.Fatalf("spoofed X-Forwarded-Proto survived: %q", got)
	}
}

// TestL7InlineEdgeEnforcesLimitsBeforeUpstream covers the resource boundaries: a body
// over the configured limit and a header block over the configured limit are refused
// before the upstream is contacted.
func TestL7InlineEdgeEnforcesLimitsBeforeUpstream(t *testing.T) {
	t.Run("oversized_body", func(t *testing.T) {
		_, _, client, upstream, cfg := newL7InlineProducerFixture(t, "block", func(cfg *L7Config) {
			cfg.MaxBodyBytes = 1024
		}, nil)
		body := bytes.Repeat([]byte{'A'}, cfg.MaxBodyBytes+1)
		status, _ := l7InlineProducerDo(t, client, l7InlineProducerRequest(t, http.MethodPost, "/upload", body, map[string]string{
			"Content-Type": "text/plain",
		}))
		if status != http.StatusRequestEntityTooLarge {
			t.Fatalf("oversized body was not refused with 413: %d", status)
		}
		if upstream.hits.Load() != 0 {
			t.Fatalf("oversized body reached the upstream %d time(s)", upstream.hits.Load())
		}
	})

	t.Run("oversized_header_block", func(t *testing.T) {
		_, _, client, upstream, _ := newL7InlineProducerFixture(t, "block", func(cfg *L7Config) {
			// Deliberately tiny so the request header block alone is over budget.
			cfg.MaxHeaderBytes = 512
		}, nil)
		request := l7InlineProducerRequest(t, http.MethodGet, "/headers", nil, map[string]string{
			"X-Padding": strings.Repeat("p", 2048),
		})
		response, err := client.Do(request)
		if err == nil {
			_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
			_ = response.Body.Close()
			if response.StatusCode != http.StatusRequestHeaderFieldsTooLarge {
				t.Fatalf("oversized header block was not refused with 431: %d", response.StatusCode)
			}
		}
		if upstream.hits.Load() != 0 {
			t.Fatalf("oversized header request reached the upstream %d time(s)", upstream.hits.Load())
		}
	})
}

// TestL7InlineProducerStatusSurvivesLaterPublisher is the regression test for the live
// defect: after inline traffic established the producer, the self-test evidence writer
// updated the shared status. That later writer must not erase the attachment verdict.
func TestL7InlineProducerStatusSurvivesLaterPublisher(t *testing.T) {
	service, _, client, _, _ := newL7InlineProducerFixture(t, "block", nil, nil)
	if status, _ := l7InlineProducerDo(t, client, l7InlineProducerRequest(t, http.MethodGet, "/health", nil, nil)); status != http.StatusOK {
		t.Fatalf("benign request failed: %d", status)
	}

	now := time.Now().UTC()
	service.state.UpdateL7Status(func(status *L7Status) {
		// Exactly what recordSelfTestEvidence writes after the probe.
		status.SelfTestOutcome = "PASS"
		status.SelfTestAt = &now
	})

	view := l7InlineProducerStatus(t, service)
	if !l7WireBool(t, view, "producer_attached") {
		t.Fatal("a later status writer erased the inline producer attachment")
	}
	if !l7WireBool(t, view, "inline_producer_attached") {
		t.Fatal("a later status writer erased the inline producer verification")
	}
	if got := l7WireUint(t, view, "requests_total"); got == 0 {
		t.Fatal("a later status writer erased the aggregated inline request count")
	}
}

// TestL7InlineStatusJSONIsValid guards the wire format itself: the derived status must
// stay valid JSON with the documented field names.
func TestL7InlineStatusJSONIsValid(t *testing.T) {
	service, _, client, _, _ := newL7InlineProducerFixture(t, "block", nil, nil)
	if status, _ := l7InlineProducerDo(t, client, l7InlineProducerRequest(t, http.MethodGet, "/health", nil, nil)); status != http.StatusOK {
		t.Fatalf("benign request failed: %d", status)
	}
	raw, err := json.Marshal(service.state.Snapshot().L7)
	if err != nil {
		t.Fatalf("status JSON marshal failed: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("status JSON is not valid: %v", err)
	}
	for _, required := range []string{
		"requests_total", "findings_total", "blocked_total", "rate_limited_total",
		"inline_requests_total", "inline_blocked_total", "inline_findings_total",
		"producer_attached", "inline_producer_attached", "inline_attachment_reason",
		"traffic_path_attached", "traffic_path_verified",
	} {
		if _, ok := decoded[required]; !ok {
			t.Fatalf("status JSON is missing the required field %q", required)
		}
	}
}
