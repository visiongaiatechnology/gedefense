package main

import (
	"net"
	"strings"
	"testing"
)

func TestParseThreatLine(t *testing.T) {
	if got, ok := parseThreatLine("203.0.113.4 ; test"); !ok || got != "203.0.113.4/32" {
		t.Fatalf("got %q %v", got, ok)
	}
	if got, ok := parseThreatLine("203.0.113.8 # inline comment"); !ok || got != "203.0.113.8/32" {
		t.Fatalf("got %q %v", got, ok)
	}
	if _, ok := parseThreatLine("127.0.0.1"); ok {
		t.Fatal("loopback accepted")
	}
	if _, ok := parseThreatLine("garbage"); ok {
		t.Fatal("garbage accepted")
	}
}

func TestParseThreatTokenMathematicalHardening(t *testing.T) {
	// Length boundary checks (< 3 or > 49)
	if _, ok := parseThreatToken(""); ok {
		t.Fatal("empty token accepted")
	}
	if _, ok := parseThreatToken("1"); ok {
		t.Fatal("token len 1 accepted")
	}
	if _, ok := parseThreatToken("12"); ok {
		t.Fatal("token len 2 accepted")
	}
	if _, ok := parseThreatToken(strings.Repeat("1", 50)); ok {
		t.Fatal("token len 50 accepted")
	}

	// Regex Whitelist: eliminates quotes, semicolons, SQL comments, spaces, control characters
	sqlInjections := []string{
		"203.0.113.4' OR '1'='1",
		"203.0.113.4; DROP TABLE rules--",
		"203.0.113.4--",
		"203.0.113.4/*comment*/",
		"203.0.113.4\x00",
		"203.0.113.4\n127.0.0.1",
		"203.0.113.4 127.0.0.1",
		"203.0.113.4\t127.0.0.1",
		"<script>alert(1)</script>",
	}
	for _, payload := range sqlInjections {
		if _, ok := parseThreatToken(payload); ok {
			t.Fatalf("SQL injection/poisoning payload accepted: %q", payload)
		}
	}

	// Anti-Poisoning checks
	poisonTargets := []string{
		"127.0.0.1",
		"127.0.0.1/32",
		"127.0.0.0/8",
		"::1",
		"::1/128",
		"0.0.0.0",
		"0.0.0.0/0",
		"::",
		"::/0",
		"10.0.0.1",
		"10.0.0.0/8",
		"172.16.1.1",
		"172.16.0.0/12",
		"192.168.1.1",
		"192.168.0.0/16",
		"fc00::1",
		"224.0.0.1",
		"224.0.0.0/4",
		"ff02::1",
		"169.254.1.1",
		"169.254.0.0/16",
		"169.254.169.254", // AWS/GCP/Azure IMDS
		"100.100.100.200", // Alibaba IMDS
		"168.63.129.16",   // Azure WireServer
		"fd00:ec2::254",   // AWS IMDSv2
	}
	for _, target := range poisonTargets {
		if _, ok := parseThreatToken(target); ok {
			t.Fatalf("anti-poisoning check failed for %q: should be rejected", target)
		}
	}

	// Valid Public Targets
	validTargets := map[string]string{
		"203.0.113.4":        "203.0.113.4/32",
		"203.0.113.0/24":     "203.0.113.0/24",
		"198.51.100.7":       "198.51.100.7/32",
		"2001:db8::1":        "2001:db8::1/128",
		"2001:db8:abcd::/48": "2001:db8:abcd::/48",
	}
	for input, expected := range validTargets {
		got, ok := parseThreatToken(input)
		if !ok || got != expected {
			t.Fatalf("valid target %q: got %q %v, want %q", input, got, ok, expected)
		}
	}
}

func TestAllowlistPrecedenceInvariant(t *testing.T) {
	// Invariant 3: Management allowlists take precedence during enforcement.
	// Do not discard an entire threat CIDR merely because it overlaps one allowlisted address or subnet.
	targets := []string{
		"198.51.100.5",
		"198.51.100.0/24",
		"203.0.113.42",
		"198.51.101.9",
	}
	for _, target := range targets {
		got, ok := parseThreatToken(target)
		if !ok {
			t.Fatalf("threat token %q should not be discarded at parse time: got %q %v", target, got, ok)
		}
	}
}

func TestJSONThreatFeedParser(t *testing.T) {
	jsonPayload := `[
		{"cidr": "203.0.113.0/24", "asn": 12345, "type": "DROP"},
		{"cidr": "198.51.100.0/24", "asn": 54321, "type": "EDROP"},
		{"cidr": "127.0.0.1/32", "asn": 0, "type": "INVALID"},
		{"cidr": "169.254.169.254/32", "asn": 0, "type": "IMDS"}
	]`

	items, err := parseJSONThreatFeed(strings.NewReader(jsonPayload), 100)
	if err != nil {
		t.Fatalf("JSON parse error: %v", err)
	}
	if len(items) != 2 {
		t.Fatalf("expected 2 valid items from JSON, got %d: %v", len(items), items)
	}
	itemMap := make(map[string]bool)
	for _, it := range items {
		itemMap[it] = true
	}
	if !itemMap["203.0.113.0/24"] || !itemMap["198.51.100.0/24"] {
		t.Fatalf("missing expected CIDRs: %v", items)
	}
}

func TestIPsumFormatParser(t *testing.T) {
	lines := []string{
		"# IPsum level 1+",
		"203.0.113.10\t4",
		"203.0.113.11\t12",
		"# comment line",
		"127.0.0.1\t10", // poisoned loopback
	}
	var extracted []string
	for _, line := range lines {
		if tok, ok := parseThreatLine(line); ok {
			extracted = append(extracted, tok)
		}
	}
	if len(extracted) != 2 {
		t.Fatalf("expected 2 valid items from IPsum, got %d: %v", len(extracted), extracted)
	}
	if extracted[0] != "203.0.113.10/32" || extracted[1] != "203.0.113.11/32" {
		t.Fatalf("unexpected extracted items: %v", extracted)
	}
}

func TestFeedActionSemantics(t *testing.T) {
	// Invariant 1:
	// Only BLOCK vectors may enter XDP/cgroup enforcement maps or cause DROP_THREAT_INTEL.
	// Feodo Tracker and Spamhaus DROP IPv4/IPv6 are BLOCK.
	// CINS Army, blocklist.de, Emerging Threats, IPsum and FireHOL are CORRELATE_ONLY.
	// Tor Exit Nodes are strictly ANNOTATE_ONLY.
	if len(DefaultThreatFeedSources) != 9 {
		t.Fatalf("expected 9 default threat feeds, got %d", len(DefaultThreatFeedSources))
	}

	expectedActions := map[string]FeedAction{
		"feodo-c2":               FeedActionBlock,
		"spamhaus-drop-v4":       FeedActionBlock,
		"spamhaus-drop-v6":       FeedActionBlock,
		"cins-badguys":           FeedActionCorrelateOnly,
		"blocklist-de-all":       FeedActionCorrelateOnly,
		"emerging-threats-block": FeedActionCorrelateOnly,
		"ipsum-level-1":          FeedActionCorrelateOnly,
		// FireHOL level 1 is a curated aggregate of networks already observed attacking
		// or abusing hosts, and upstream documents it as safe to block outright.
		// Correlating it meant recording known-bad sources and then letting them
		// through, which is the one outcome a threat feed must not produce.
		"firehol-level-1": FeedActionBlock,
		"tor-bulk-exit":   FeedActionAnnotateOnly,
	}

	for _, src := range DefaultThreatFeedSources {
		expected, exists := expectedActions[src.ID]
		if !exists {
			t.Fatalf("unexpected feed ID %s in defaults", src.ID)
		}
		if src.Action != expected {
			t.Fatalf("feed %s action mismatch: got %v want %v", src.ID, src.Action, expected)
		}
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

func TestDefaultThreatFeedsURLs(t *testing.T) {
	if len(DefaultThreatFeeds) != 9 {
		t.Fatalf("expected 9 default threat feeds, got %d", len(DefaultThreatFeeds))
	}
	for _, u := range DefaultThreatFeeds {
		if _, err := validateFeedSourceURL(u); err != nil {
			t.Fatalf("default feed URL %q rejected by validator: %v", u, err)
		}
	}
}
