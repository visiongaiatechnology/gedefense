// STATUS: DIAMANT VGT SUPREME
package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func newL7EdgeFixture(t *testing.T, handler http.Handler, mode string) (*L7EdgeService, *L7Engine, *http.Client, *atomic.Int64) {
	t.Helper()
	var hits atomic.Int64
	upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		handler.ServeHTTP(w, r)
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
	cfg.SocketGroup = ""
	cfg.RequirePeerCredentials = false
	cfg.InlineMaxResponseBytes = 64 << 10
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
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", cfg.InlineSocket)
	}}
	client := &http.Client{Transport: transport, Timeout: 3 * time.Second}
	return service, engine, client, &hits
}

func newL7EdgeRequest(t *testing.T, method, target string, body []byte) *http.Request {
	t.Helper()
	req, err := http.NewRequest(method, "http://unix"+target, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Host = "example.test"
	req.Header.Set(l7EdgeClientIPHeader, "198.51.100.44")
	req.Header.Set(l7EdgeSchemeHeader, "https")
	return req
}

func TestL7EdgeForwardsAllowedRequestAndStripsInternalMetadata(t *testing.T) {
	var observedClientHeader string
	var observedSchemeHeader string
	var observedBody string
	var observedForwardedFor string
	var observedForwardedProto string
	service, _, client, hits := newL7EdgeFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		observedClientHeader = r.Header.Get(l7EdgeClientIPHeader)
		observedSchemeHeader = r.Header.Get(l7EdgeSchemeHeader)
		observedForwardedFor = r.Header.Get("X-Forwarded-For")
		observedForwardedProto = r.Header.Get("X-Forwarded-Proto")
		data, _ := io.ReadAll(r.Body)
		observedBody = string(data)
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, "ok")
	}), "observe")

	req := newL7EdgeRequest(t, http.MethodPost, "/submit?value=hello", []byte("plain-body"))
	req.Header.Set("Content-Type", "text/plain")
	req.Header.Set("X-Forwarded-For", "10.0.0.1")
	req.Header.Set("X-Forwarded-Proto", "http")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK || hits.Load() != 1 {
		t.Fatalf("unexpected forwarding result status=%d hits=%d", resp.StatusCode, hits.Load())
	}
	if observedClientHeader != "" || observedSchemeHeader != "" {
		t.Fatalf("internal proxy metadata leaked upstream: client=%q scheme=%q", observedClientHeader, observedSchemeHeader)
	}
	if observedBody != "plain-body" {
		t.Fatalf("request body changed in transit: %q", observedBody)
	}
	if observedForwardedFor != "198.51.100.44" || observedForwardedProto != "https" {
		t.Fatalf("untrusted forwarding headers survived: for=%q proto=%q", observedForwardedFor, observedForwardedProto)
	}
	if status := service.state.L7Status(); !status.InlineHealthy || status.InlineRequestsTotal != 1 {
		t.Fatalf("unexpected inline status: %#v", status)
	}
}

func TestL7EdgeBlocksBeforeUpstreamWhenReleaseGateAllows(t *testing.T) {
	_, engine, client, hits := newL7EdgeFixture(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}), "block")
	engine.canBlock = func() bool { return true }
	req := newL7EdgeRequest(t, http.MethodGet, "/?q=%2555NION%2520SELECT%2520password%2520FROM%2520users--", nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected block, got %d", resp.StatusCode)
	}
	if hits.Load() != 0 {
		t.Fatalf("blocked request reached upstream %d time(s)", hits.Load())
	}
}

func TestL7EdgeInspectsGzipBodyWithoutChangingUpstreamPayload(t *testing.T) {
	_, engine, client, hits := newL7EdgeFixture(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}), "block")
	engine.canBlock = func() bool { return true }
	var compressed bytes.Buffer
	zw := gzip.NewWriter(&compressed)
	_, _ = zw.Write([]byte(`{"value":"<script>alert(1)</script>"}`))
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	req := newL7EdgeRequest(t, http.MethodPost, "/api", compressed.Bytes())
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Content-Encoding", "gzip")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden || hits.Load() != 0 {
		t.Fatalf("gzip inspection bypass: status=%d hits=%d", resp.StatusCode, hits.Load())
	}
}

func TestL7EdgeRejectsUnsupportedRequestEncoding(t *testing.T) {
	_, _, client, hits := newL7EdgeFixture(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}), "observe")
	req := newL7EdgeRequest(t, http.MethodPost, "/api", []byte("opaque"))
	req.Header.Set("Content-Encoding", "br")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnsupportedMediaType || hits.Load() != 0 {
		t.Fatalf("unsupported encoding was forwarded: status=%d hits=%d", resp.StatusCode, hits.Load())
	}
}

func TestL7EdgeObservesResponseLeakWithoutCorruptingBody(t *testing.T) {
	service, _, client, _ := newL7EdgeFixture(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = io.WriteString(w, "SQLSTATE[42000]: syntax error near secret_table")
	}), "observe")
	req := newL7EdgeRequest(t, http.MethodGet, "/failure", nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "SQLSTATE[42000]: syntax error near secret_table" {
		t.Fatalf("response body changed during inspection: %q", data)
	}
	status := service.state.L7Status()
	if status.ResponsesInspectedTotal != 1 || status.ResponseFindingsTotal == 0 {
		t.Fatalf("response inspection metrics missing: %#v", status)
	}
}

func TestL7EdgeInspectsCompressedResponseAndPreservesWireBody(t *testing.T) {
	var expected bytes.Buffer
	zw := gzip.NewWriter(&expected)
	_, _ = zw.Write([]byte("SQLSTATE[42000]: compressed database failure"))
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	wire := append([]byte(nil), expected.Bytes()...)
	service, _, client, _ := newL7EdgeFixture(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Set("Content-Length", fmt.Sprintf("%d", len(wire)))
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write(wire)
	}), "observe")
	client.Transport.(*http.Transport).DisableCompression = true
	req := newL7EdgeRequest(t, http.MethodGet, "/compressed-failure", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, wire) {
		t.Fatal("compressed response changed during inspection")
	}
	status := service.state.L7Status()
	if status.ResponsesInspectedTotal != 1 || status.ResponseFindingsTotal == 0 {
		t.Fatalf("compressed response was not inspected: %#v", status)
	}
}

func TestValidateL7InlineUpstreamRejectsNonLoopbackAndCredentials(t *testing.T) {
	for _, value := range []string{
		"https://127.0.0.1:8080",
		"http://example.com:8080",
		"http://user:pass@127.0.0.1:8080",
		"http://127.0.0.1",
		"http://127.0.0.1:8080/app",
	} {
		if err := validateL7InlineUpstream(value); err == nil {
			t.Fatalf("expected upstream %q to be rejected", value)
		}
	}
	if err := validateL7InlineUpstream("http://127.0.0.1:8080"); err != nil {
		t.Fatalf("valid loopback upstream rejected: %v", err)
	}
	if err := validateL7InlineUpstream("unix:///run/example/app.sock"); err != nil {
		t.Fatalf("valid unix upstream rejected: %v", err)
	}
}

func TestL7EdgeRejectsOversizedBodyBeforeUpstream(t *testing.T) {
	_, _, client, hits := newL7EdgeFixture(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}), "observe")
	cfg := defaultConfig().L7
	body := bytes.Repeat([]byte{'A'}, cfg.MaxBodyBytes+1)
	req := newL7EdgeRequest(t, http.MethodPost, "/upload", body)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected 413 for oversized body, got %d", resp.StatusCode)
	}
	if hits.Load() != 0 {
		t.Fatalf("oversized request reached upstream %d time(s)", hits.Load())
	}
}

func TestL7EdgeUpstreamFailureDoesNotMisreportSecurityHealth(t *testing.T) {
	probe, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := probe.Addr().String()
	_ = probe.Close()

	cfg := l7TestConfig()
	cfg.InlineEnabled = true
	cfg.InlineSocket = filepath.Join(t.TempDir(), "edge.sock")
	cfg.InlineUpstream = "http://" + address
	cfg.SocketGroup = ""
	cfg.RequirePeerCredentials = false
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
	client := &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", cfg.InlineSocket)
	}}, Timeout: 3 * time.Second}

	resp, err := client.Do(newL7EdgeRequest(t, http.MethodGet, "/", nil))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("expected upstream 502, got %d", resp.StatusCode)
	}
	status := state.L7Status()
	if !status.InlineHealthy {
		t.Fatalf("upstream outage incorrectly degraded security listener health: %#v", status)
	}
	if status.InlineUpstreamErrorsTotal != 1 || status.InlineLastError == "" {
		t.Fatalf("upstream diagnostics missing: %#v", status)
	}
}
