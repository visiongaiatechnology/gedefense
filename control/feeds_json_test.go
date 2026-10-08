// STATUS: DIAMANT VGT SUPREME
package main

import (
	"strings"
	"testing"
)

// TestJSONFeedIgnoresMetadataStrings covers the feed that was rejected as corrupt.
//
// Spamhaus publishes one prefix per object alongside its labels:
//
//	{"cidr":"1.10.16.0/20","sblid":"SBL256894","rir":"apnic"}
//
// Every string in the document was counted as a candidate, so five labels were scored as
// malformed for every address. The feed was rejected at 833 per mille against a limit of
// 250, the last-known-good generation was preserved, and the operator saw a CRITICAL feed
// whose contents were entirely valid.
func TestJSONFeedIgnoresMetadataStrings(t *testing.T) {
	const document = `{"cidr":"1.10.16.0/20","sblid":"SBL256894","rir":"apnic"}
{"cidr":"1.10.32.0/19","sblid":"SBL256895","rir":"apnic"}
{"cidr":"2001:db8::/32","sblid":"SBL256896","rir":"ripencc"}
`
	set := map[string]struct{}{}
	stats := threatFeedStats{}
	policy := ThreatIntelValidationSettings{IPv4Enabled: true, IPv6Enabled: true, GenerationPolicy: "bump"}

	if err := collectJSONThreatEntries(strings.NewReader(document), 1000, policy, set, &stats); err != nil {
		t.Fatalf("a healthy feed was rejected: %v", err)
	}
	if stats.Malformed != 0 {
		t.Fatalf("labels were counted as malformed entries: %d", stats.Malformed)
	}
	if stats.Accepted != 3 {
		t.Fatalf("expected the three prefixes, accepted %d (candidates %d)", stats.Accepted, stats.Candidates)
	}
	if len(set) != 3 {
		t.Fatalf("expected three entries in the set, got %d", len(set))
	}
	if _, ok := set["1.10.16.0/20"]; !ok {
		t.Fatal("the prefix was not collected")
	}
	// The guard itself must still pass on this feed.
	if _, err := finalizeThreatFeed(set, stats, policy); err != nil {
		t.Fatalf("the validation policy still rejects the feed: %v", err)
	}
}

// TestJSONFeedStillRejectsAddressShapedGarbage is the counter-case. Skipping labels must
// not become a way for a corrupt feed to pass: a value that is address-shaped and invalid
// is still a malformed entry, and enough of them still trip the integrity guard.
func TestJSONFeedStillRejectsAddressShapedGarbage(t *testing.T) {
	var builder strings.Builder
	for i := 0; i < 100; i++ {
		builder.WriteString(`{"cidr":"999.999.999.999/33","sblid":"x"}` + "\n")
	}
	set := map[string]struct{}{}
	stats := threatFeedStats{}
	policy := ThreatIntelValidationSettings{IPv4Enabled: true, IPv6Enabled: true, GenerationPolicy: "bump"}

	if err := collectJSONThreatEntries(strings.NewReader(builder.String()), 1000, policy, set, &stats); err != nil {
		t.Fatalf("collection failed: %v", err)
	}
	if stats.Malformed == 0 {
		t.Fatal("address-shaped garbage was not counted as malformed")
	}
	strict := ThreatIntelValidationSettings{
		IPv4Enabled: true, IPv6Enabled: true, GenerationPolicy: "bump",
		MalformedEntryPermille: 250, MinimumValidEntryPermille: 500,
	}
	if _, err := finalizeThreatFeed(set, stats, strict); err == nil {
		t.Fatal("a feed of address-shaped garbage was accepted")
	}
}

// TestJSONFeedOfPureNoiseIsAFailure closes the hole that skipping could open. A document
// that carried content and yielded no address at all is a broken feed, not an empty one.
func TestJSONFeedOfPureNoiseIsAFailure(t *testing.T) {
	const document = `{"note":"this feed moved to another url","contact":"abuse@example.invalid"}
`
	set := map[string]struct{}{}
	stats := threatFeedStats{}
	policy := ThreatIntelValidationSettings{IPv4Enabled: true, IPv6Enabled: true, GenerationPolicy: "bump"}

	err := collectJSONThreatEntries(strings.NewReader(document), 1000, policy, set, &stats)
	if err == nil {
		t.Fatal("a document with content but no address was accepted as an empty feed")
	}
	if !strings.Contains(err.Error(), "none of them was a network address") {
		t.Fatalf("the failure does not say what was wrong: %v", err)
	}
}

// TestCouldBeNetworkToken pins the classifier the fix depends on.
func TestCouldBeNetworkToken(t *testing.T) {
	for _, value := range []string{"1.10.16.0/20", "2001:db8::/32", "::1", "10.0.0.1", "fe80::1/64", "0.0.0.0/0"} {
		if !couldBeNetworkToken(value) {
			t.Errorf("%q should be treated as a possible address", value)
		}
	}
	for _, value := range []string{"apnic", "SBL256894", "ripencc", "not an address", "hello world", "1.10.16.0/20 extra", "Ünicode"} {
		if couldBeNetworkToken(value) {
			t.Errorf("%q should be treated as metadata", value)
		}
	}
}
