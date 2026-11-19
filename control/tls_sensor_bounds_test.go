package main

import (
	"fmt"
	"strings"
	"testing"
)

// FIND-002 (VGT-AUDIT-2026-11-19): untrusted ClientHello data must not grow the
// ALPN counter map or the tracked-peer set without a bound.
func TestBoundedALPNRejectsHostileValues(t *testing.T) {
	protocols := []string{
		"h2", "http/1.1", "h2", "", strings.Repeat("a", tlsSensorMaxALPNBytes+1),
		"bad\x00value", "ok", "h3", "spdy/3", "quic", "http/1.0", "x", "y", "z",
	}
	bounded := boundedALPN(protocols, tlsSensorMaxALPNPerHello, tlsSensorMaxALPNBytes)
	if len(bounded) > tlsSensorMaxALPNPerHello {
		t.Fatalf("per-handshake ALPN list grew to %d", len(bounded))
	}
	for _, value := range bounded {
		if value == "" || len(value) > tlsSensorMaxALPNBytes || !printableASCII(value) {
			t.Fatalf("hostile ALPN value survived: %q", value)
		}
	}
	seen := map[string]bool{}
	for _, value := range bounded {
		if seen[value] {
			t.Fatalf("duplicate ALPN value %q", value)
		}
		seen[value] = true
	}
	if len(boundedALPN(nil, 8, 32)) != 0 {
		t.Fatal("nil ALPN input produced entries")
	}
}

func TestALPNCounterMapIsBoundedAndAggregatesTheRest(t *testing.T) {
	engine := NewTLSSensorEngine(nil, nil, nil)
	protocols := make([]string, 0, 1000)
	for index := 0; index < 1000; index++ {
		protocols = append(protocols, fmt.Sprintf("proto-%04d", index))
	}
	engine.accountALPNLocked(protocols)
	if len(engine.alpnCounts) > tlsSensorMaxALPNKeys {
		t.Fatalf("ALPN map grew to %d keys (max %d)", len(engine.alpnCounts), tlsSensorMaxALPNKeys)
	}
	if engine.alpnCounts[tlsSensorALPNOther] == 0 {
		t.Fatal("overflow protocols were not aggregated into the (other) bucket")
	}
	// A known key still increments rather than creating a new key.
	known := protocols[0]
	before := engine.alpnCounts[known]
	engine.accountALPNLocked([]string{known})
	if engine.alpnCounts[known] != before+1 {
		t.Fatalf("known ALPN counter did not increment: %d -> %d", before, engine.alpnCounts[known])
	}
}

func TestTrackedPeerSetIsBounded(t *testing.T) {
	engine := NewTLSSensorEngine(nil, nil, nil)
	for index := 0; index < tlsSensorMaxTrackedPeers+500; index++ {
		engine.trackPeerLocked(fmt.Sprintf("198.51.%d.%d", (index/256)%256, index%256))
	}
	if len(engine.trackedPeers) != tlsSensorMaxTrackedPeers {
		t.Fatalf("tracked peers = %d, want the %d cap", len(engine.trackedPeers), tlsSensorMaxTrackedPeers)
	}
	// An already tracked peer remains tracked; the cap does not evict silently.
	first := "198.51.0.0"
	if _, ok := engine.trackedPeers[first]; !ok {
		t.Fatal("already tracked peer was evicted")
	}
}
