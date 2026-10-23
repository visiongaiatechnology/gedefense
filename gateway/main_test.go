package main

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func TestHardenedTLSConfigPrioritizesPostQuantumWithClassicalFallback(t *testing.T) {
	want := []tls.CurveID{
		tls.SecP384r1MLKEM1024,
		tls.X25519MLKEM768,
		tls.X25519,
		tls.CurveP384,
	}
	for _, loopback := range []bool{true, false} {
		config := hardenedTLSConfig(loopback)
		if config.MinVersion != tls.VersionTLS13 {
			t.Fatalf("minimum TLS version=%x", config.MinVersion)
		}
		if len(config.CurvePreferences) != len(want) {
			t.Fatalf("loopback=%v curve count=%d", loopback, len(config.CurvePreferences))
		}
		for i := range want {
			if config.CurvePreferences[i] != want[i] {
				t.Fatalf("loopback=%v curve[%d]=%v want %v", loopback, i, config.CurvePreferences[i], want[i])
			}
		}
	}
}

func TestProxyDirectorStripsPublicOriginAndRewritesHost(t *testing.T) {
	backend, _ := url.Parse("http://127.0.0.1:9844")
	g := &gateway{backend: backend, backendToken: "0123456789abcdef0123456789abcdef"}
	p := g.newProxy()
	req := httptest.NewRequest(http.MethodPost, "https://203.0.113.10:9843/api/v1/test", nil)
	req.Host = "203.0.113.10:9843"
	req.Header.Set("Origin", "https://203.0.113.10:9843")
	req.Header.Set("Referer", "https://203.0.113.10:9843/")
	req.Header.Set("Cookie", "secret=yes")
	req.Header.Set("Authorization", "Bearer browser-value")
	req.Header.Set("X-Forwarded-For", "198.51.100.90")
	req.Header.Set("Forwarded", "for=198.51.100.90")
	p.Director(req)
	if req.Host != "127.0.0.1:9844" {
		t.Fatalf("host=%q", req.Host)
	}
	for _, h := range []string{"Origin", "Referer", "Cookie", "Forwarded", "X-Forwarded-For"} {
		if req.Header.Get(h) != "" {
			t.Fatalf("%s leaked: %q", h, req.Header.Get(h))
		}
	}
	if got := req.Header.Get("Authorization"); got != "Bearer 0123456789abcdef0123456789abcdef" {
		t.Fatalf("authorization=%q", got)
	}
}

func TestSameOrigin(t *testing.T) {
	g := &gateway{publicHost: "203.0.113.10:9843", publicOrigin: "https://203.0.113.10:9843"}
	req := httptest.NewRequest(http.MethodPost, "https://203.0.113.10:9843/login", nil)
	req.Header.Set("Origin", "https://203.0.113.10:9843")
	if !g.sameOrigin(req) {
		t.Fatal("valid origin rejected")
	}
	req.Header.Set("Origin", "http://203.0.113.10:9843")
	if g.sameOrigin(req) {
		t.Fatal("insecure origin accepted")
	}
}
