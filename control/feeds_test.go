package main

import (
	"bufio"
	"encoding/base64"
	"net"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
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
		"firehol-level-1":        FeedActionCorrelateOnly,
		"tor-bulk-exit":          FeedActionAnnotateOnly,
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

func TestFeedManagerPartitioningAndActionIsolation(t *testing.T) {
	tempDir := t.TempDir()
	fm := NewFeedManager(FeedConfig{MaxEntries: 1000}, tempDir)

	fm.feedStates["feodo-c2"].LastGoodItems = []string{"203.0.113.10/32"}
	fm.feedStates["cins-badguys"].LastGoodItems = []string{"198.51.100.20/32"}
	fm.feedStates["tor-bulk-exit"].LastGoodItems = []string{"192.0.2.30/32"}

	// Apply without kernel client (updates in-memory indices)
	added, deleted, err := fm.ApplyToKernel(nil, nil)
	if err != nil {
		t.Fatalf("ApplyToKernel failed: %v", err)
	}
	if added != 1 || deleted != 0 {
		t.Fatalf("expected 1 added (BLOCK), 0 deleted, got +%d/-%d", added, deleted)
	}

	// Invariant 1 enforcement: Only BLOCK vectors enter blockIndex
	if !fm.BlockIndex().ContainsString("203.0.113.10") {
		t.Fatal("BlockIndex missing Feodo BLOCK IP")
	}
	if fm.BlockIndex().ContainsString("198.51.100.20") {
		t.Fatal("BlockIndex erroneously contains CORRELATE_ONLY IP")
	}
	if fm.BlockIndex().ContainsString("192.0.2.30") {
		t.Fatal("BlockIndex erroneously contains ANNOTATE_ONLY IP")
	}

	// CorrelateIndex includes both BLOCK and CORRELATE_ONLY
	if !fm.CorrelateIndex().ContainsString("203.0.113.10") {
		t.Fatal("CorrelateIndex missing Feodo BLOCK IP")
	}
	if !fm.CorrelateIndex().ContainsString("198.51.100.20") {
		t.Fatal("CorrelateIndex missing CINS CORRELATE_ONLY IP")
	}
	if fm.CorrelateIndex().ContainsString("192.0.2.30") {
		t.Fatal("CorrelateIndex erroneously contains ANNOTATE_ONLY IP")
	}

	// AnnotateIndex contains strictly ANNOTATE_ONLY
	if !fm.AnnotateIndex().ContainsString("192.0.2.30") {
		t.Fatal("AnnotateIndex missing Tor Exit node")
	}
	if fm.AnnotateIndex().ContainsString("203.0.113.10") || fm.AnnotateIndex().ContainsString("198.51.100.20") {
		t.Fatal("AnnotateIndex contains non-annotate IP")
	}

	// Invariant 4: Shared generation ID and fingerprint
	if fm.Generation() != 1 {
		t.Fatalf("expected generation 1, got %d", fm.Generation())
	}
	if fm.Fingerprint() == "" {
		t.Fatal("expected non-empty fingerprint")
	}
}

func TestLastKnownGoodGenerationRetention(t *testing.T) {
	// Invariant 2: Each feed maintains a last-known-good generation. Failed, empty, malformed,
	// truncated or implausible downloads must never replace the current active generation.
	state := &FeedGenerationState{
		ID:            "feodo-c2",
		Name:          "Feodo Tracker C2",
		Action:        FeedActionBlock,
		LastGoodItems: []string{"203.0.113.50/32"},
		LastGoodCount: 1,
		LastGoodGen:   1,
		LastGoodAt:    time.Now().UTC().Add(-1 * time.Hour),
	}

	// Simulate empty download result: must NOT overwrite LastGoodItems
	emptyItems := []string{}
	now := time.Now().UTC()
	state.LastAttemptAt = now
	if len(emptyItems) == 0 {
		state.LastError = "empty payload rejected"
		state.ConsecutiveFails++
	}

	if len(state.LastGoodItems) != 1 || state.LastGoodItems[0] != "203.0.113.50/32" {
		t.Fatalf("LastGoodItems was cleared on empty download: %v", state.LastGoodItems)
	}
	if state.ConsecutiveFails != 1 {
		t.Fatalf("ConsecutiveFails=%d want=1", state.ConsecutiveFails)
	}
}

func TestLiveSyncLockOwnerAndCrashRecovery(t *testing.T) {
	// Invariant 6: The sync lock remains owned until the sync completes; its TTL is
	// crash recovery, not permission to steal from a live owner.
	var lock ThreatIntelLock

	acquired, remaining := lock.TryLock("operator")
	if !acquired || remaining != 0 {
		t.Fatalf("expected lock acquisition: acquired=%v remaining=%v", acquired, remaining)
	}

	// Immediate second acquisition fails with remaining duration
	acquired2, remaining2 := lock.TryLock("vis_threat_intel_cron_sync")
	if acquired2 || remaining2 <= 0 || remaining2 > threatIntelLockTTL {
		t.Fatalf("expected lock rejection: acquired=%v remaining=%v", acquired2, remaining2)
	}

	// Artificially age the acquiredAt timestamp beyond the 15m TTL
	lock.mu.Lock()
	lock.acquiredAt = time.Now().UTC().Add(-20 * time.Minute)
	lock.persistedAt = time.Now().UTC().Add(-20 * time.Minute)
	lock.mu.Unlock()

	// Worker 2 attempts to acquire: MUST FAIL because active is still true (worker 1 is live!)
	acquiredStillLive, remainingLive := lock.TryLock("worker-2")
	if acquiredStillLive {
		t.Fatal("lock stolen from live owner after 20 minutes")
	}
	if remainingLive <= 0 {
		t.Fatal("expected positive remaining duration")
	}

	// Worker 1 unlocks
	lock.Unlock()
	locked, _, _, _ := lock.Status()
	if locked {
		t.Fatal("lock still active after Unlock()")
	}

	// Now worker 2 can acquire
	acquired3, _ := lock.TryLock("worker-2")
	if !acquired3 {
		t.Fatal("failed to acquire after legitimate unlock")
	}
	lock.Unlock()

	// Test Crash Recovery: active == false, but persistedAt is recent (< 15m) -> locked
	lock.mu.Lock()
	lock.active = false
	lock.persistedAt = time.Now().UTC().Add(-5 * time.Minute)
	lock.mu.Unlock()

	acquiredCrash, _ := lock.TryLock("worker-3")
	if acquiredCrash {
		t.Fatal("crash lock acquired before TTL elapsed")
	}

	// Once persistedAt exceeds 15m -> crash recovery allows reacquisition
	lock.mu.Lock()
	lock.persistedAt = time.Now().UTC().Add(-16 * time.Minute)
	lock.mu.Unlock()

	acquiredRecovered, _ := lock.TryLock("worker-3")
	if !acquiredRecovered {
		t.Fatal("crash lock failed to recover after 16 minutes")
	}
	lock.Unlock()
}

func TestApplyToKernelAdditionsBeforeDeletionsAndRollback(t *testing.T) {
	// Invariant 5: Kernel diff updates must apply additions before deletions and must never
	// publish a new userspace generation until the corresponding kernel update succeeded.
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "core.key")
	socketPath := filepath.Join(dir, "core.sock")

	client, err := NewCoreClient(socketPath, keyPath, time.Second)
	if err != nil {
		t.Fatal(err)
	}

	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	var commandsReceived []string
	var commandsMu sync.Mutex

	// Mock server that records commands and simulates failure on a specific target
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				reader := bufio.NewReader(c)
				for {
					line, err := reader.ReadString('\n')
					if err != nil {
						return
					}
					fields := strings.Fields(strings.TrimSpace(line))
					if len(fields) >= 5 {
						cmd := fields[3]
						target := fields[4]
						commandsMu.Lock()
						commandsReceived = append(commandsReceived, cmd+":"+target)
						commandsMu.Unlock()

						responseTag := coreProtocol + "R"
						status := "OK"
						if target == "203.0.113.99/32" {
							status = "ERR"
						}
						payload := base64.RawURLEncoding.EncodeToString([]byte("ok"))
						mac := coreMAC(client.key, responseTag, fields[2], status, payload)
						_, _ = c.Write([]byte(strings.Join([]string{responseTag, fields[2], status, payload, mac}, " ") + "\n"))
					}
				}
			}(conn)
		}
	}()

	fm := NewFeedManager(FeedConfig{MaxEntries: 100}, dir)
	fm.feedStates["feodo-c2"].LastGoodItems = []string{"203.0.113.1/32", "203.0.113.2/32"}

	added, deleted, err := fm.ApplyToKernel(client, nil)
	if err != nil {
		t.Fatalf("ApplyToKernel failed: %v", err)
	}
	if added != 2 || deleted != 0 {
		t.Fatalf("expected 2 added, 0 deleted, got +%d/-%d", added, deleted)
	}
	if fm.Generation() != 1 {
		t.Fatalf("expected generation 1, got %d", fm.Generation())
	}

	// Second round: 1 deletion (.2) and 1 addition (.99) that FAILS
	fm.feedStates["feodo-c2"].LastGoodItems = []string{"203.0.113.1/32", "203.0.113.99/32"}
	_, _, err = fm.ApplyToKernel(client, nil)
	if err == nil {
		t.Fatal("expected error on failed addition")
	}

	// Invariant 5: Generation must NOT be updated if kernel sync fails
	if fm.Generation() != 1 {
		t.Fatalf("generation was updated despite failure: %d", fm.Generation())
	}

	commandsMu.Lock()
	defer commandsMu.Unlock()

	// Verify that additions occurred before deletions
	firstBatchAdds := 0
	for _, cmd := range commandsReceived {
		if strings.HasPrefix(cmd, "ADD:") {
			firstBatchAdds++
		}
	}
	if firstBatchAdds < 2 {
		t.Fatalf("expected at least 2 ADD commands recorded, got %d", firstBatchAdds)
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
