package main

import (
	"net"
	"testing"
)

func TestParseThreatLine(t *testing.T) {
	if got, ok := parseThreatLine("203.0.113.4 ; test"); !ok || got != "203.0.113.4/32" {
		t.Fatalf("got %q %v", got, ok)
	}
	if _, ok := parseThreatLine("127.0.0.1"); ok {
		t.Fatal("loopback accepted")
	}
	if _, ok := parseThreatLine("garbage"); ok {
		t.Fatal("garbage accepted")
	}
}

func TestThreatIndexUsesPrefixMatches(t *testing.T) {
	index := NewThreatIndex()
	index.Replace([]string{
		"203.0.113.0/24",
		"198.51.100.7/32",
		"2001:db8:abcd::/48",
		"2001:db8:ffff::7/128",
	})
	for _, address := range []string{"203.0.113.9", "198.51.100.7", "2001:db8:abcd:12::1", "2001:db8:ffff::7"} {
		if !index.ContainsString(address) {
			t.Fatalf("expected prefix match for %s", address)
		}
	}
	for _, address := range []string{"203.0.114.9", "198.51.100.8", "2001:db8:abce::1", "2001:db8:ffff::8"} {
		if index.ContainsString(address) {
			t.Fatalf("unexpected prefix match for %s", address)
		}
	}
	if got := index.Count(); got != 4 {
		t.Fatalf("count=%d want=4", got)
	}

	index.Replace([]string{"192.0.2.0/24"})
	if index.ContainsString("203.0.113.9") || !index.ContainsString("192.0.2.5") {
		t.Fatal("atomic index replacement retained stale prefixes")
	}
}

func TestValidateFeedSourceURLRejectsSSRFNetworks(t *testing.T) {
	bad := []string{
		"http://example.com/feed.txt",
		"https://localhost/feed.txt",
		"https://127.0.0.1/feed.txt",
		"https://169.254.169.254/latest/meta-data/",
		"https://10.0.0.1/feed.txt",
		"https://[::1]/feed.txt",
		"https://example.com:8443/feed.txt",
		"https://user:pass@example.com/feed.txt",
	}
	for _, raw := range bad {
		if _, err := validateFeedSourceURL(raw); err == nil {
			t.Fatalf("expected SSRF URL rejection for %q", raw)
		}
	}
	if _, err := validateFeedSourceURL("https://example.com/feed.txt"); err != nil {
		t.Fatalf("public HTTPS feed rejected: %v", err)
	}
}

func TestForbiddenFeedIP(t *testing.T) {
	for _, raw := range []string{"127.0.0.1", "10.1.2.3", "169.254.169.254", "::1", "fe80::1"} {
		if !forbiddenFeedIP(net.ParseIP(raw)) {
			t.Fatalf("expected forbidden feed IP: %s", raw)
		}
	}
	if forbiddenFeedIP(net.ParseIP("1.1.1.1")) {
		t.Fatal("public resolver IP was rejected")
	}
}
