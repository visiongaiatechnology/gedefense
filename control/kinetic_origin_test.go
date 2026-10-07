// STATUS: DIAMANT VGT SUPREME
package main

import (
	"net"
	"testing"
)

// TestFireholLevelOneIsEnforcedAsBlock pins the operator requirement: the FireHOL
// level 1 list contains networks already observed attacking, so correlating it would
// mean recording known-bad sources and letting them through.
func TestFireholLevelOneIsEnforcedAsBlock(t *testing.T) {
	var found bool
	for _, source := range DefaultThreatFeedSources {
		if source.ID != "firehol-level-1" {
			continue
		}
		found = true
		if source.Action != FeedActionBlock {
			t.Fatalf("firehol-level-1 action = %v, want BLOCK", source.Action)
		}
	}
	if !found {
		t.Fatal("the FireHOL level 1 feed is gone from the defaults")
	}
}

// TestBlockedSourcesIncludeFeedEnforcement covers the display defect behind "1152
// hits, 0 blocked". Feed BLOCK prefixes are pushed straight into kernel maps and never
// enter the management block ledger, so a source list built only from the ledger
// reported zero blocked while the kernel was dropping that exact address. Enforcement
// has two paths and both must be visible.
func TestBlockedSourcesIncludeFeedEnforcement(t *testing.T) {
	index := NewThreatIndex()
	// Replace takes the canonical CIDR form the feed parser produces: a bare address is
	// normalised to /32 or /128 before it reaches the index. Passing a bare address
	// here would be silently skipped, which is why the parser is the contract.
	index.Replace([]string{"203.0.113.77/32", "198.51.100.0/24"})

	engine := NewKineticEngine(defaultConfig().Kinetic, nil, NewKineticRuleRegistry(), nil)
	engine.SetThreatIntel(index, nil, nil)

	// A feed-blocked address must be reported as blocked even though nothing was ever
	// written to the management ledger.
	if !engine.sourceBlockedWithFeeds(net.ParseIP("203.0.113.77"), map[string]bool{}, nil) {
		t.Fatal("a feed-blocked address was not reported as blocked")
	}
	// A prefix membership counts the same way.
	if !engine.sourceBlockedWithFeeds(net.ParseIP("198.51.100.42"), map[string]bool{}, nil) {
		t.Fatal("an address inside a feed-blocked prefix was not reported as blocked")
	}
	// An address in neither path is not blocked, so the counter cannot simply always
	// return true.
	if engine.sourceBlockedWithFeeds(net.ParseIP("192.0.2.10"), map[string]bool{}, nil) {
		t.Fatal("an address in no block set was reported as blocked")
	}
	// The management ledger keeps working alongside the feed index.
	if !engine.sourceBlockedWithFeeds(net.ParseIP("192.0.2.10"), map[string]bool{"192.0.2.10": true}, nil) {
		t.Fatal("a management-blocked address was not reported as blocked")
	}
	// A nil index must not panic: feeds may not have synced yet.
	empty := NewKineticEngine(defaultConfig().Kinetic, nil, NewKineticRuleRegistry(), nil)
	if empty.sourceBlockedWithFeeds(net.ParseIP("203.0.113.1"), map[string]bool{}, nil) {
		t.Fatal("an engine without a threat index reported a block")
	}
}

// TestKineticOriginIsHonestAboutWhatItCannotResolve proves the origin never invents a
// position. A host whose only addresses are private cannot be geolocated, and the
// result must say so rather than place the marker somewhere on earth.
func TestKineticOriginIsHonestAboutWhatItCannotResolve(t *testing.T) {
	server := &APIServer{}
	origin := server.resolveKineticOrigin()

	if origin.Known {
		// A resolved origin must be a real coordinate on earth.
		if origin.Latitude < -90 || origin.Latitude > 90 || origin.Longitude < -180 || origin.Longitude > 180 {
			t.Fatalf("resolved origin has an impossible coordinate: %+v", origin)
		}
		if origin.IP == "" {
			t.Fatal("a resolved origin must name the address it resolved")
		}
	} else if origin.Reason == "" {
		// An unresolved origin must state why, otherwise the interface shows nothing
		// and the operator cannot tell a NAT host from a broken lookup.
		t.Fatal("an unresolved origin must carry a reason")
	}
	if note := describeOrigin(origin); note == "" {
		t.Fatal("the origin note must never be empty")
	}
}

// TestPrivateAddressClassificationMatchesTheRedactor proves the map and the forensics
// redaction agree on what counts as internal, so the two cannot drift apart.
func TestPrivateAddressClassificationMatchesTheRedactor(t *testing.T) {
	internal := []string{"10.0.0.1", "172.16.5.4", "192.168.1.1", "127.0.0.1", "100.64.0.1", "169.254.1.1"}
	for _, raw := range internal {
		if !isPrivateAddress(net.ParseIP(raw)) {
			t.Errorf("%s was not classified as internal", raw)
		}
	}
	public := []string{"8.8.8.8", "1.1.1.1", "203.0.113.5", "2606:4700:4700::1111"}
	for _, raw := range public {
		if isPrivateAddress(net.ParseIP(raw)) {
			t.Errorf("%s was classified as internal", raw)
		}
	}
}
