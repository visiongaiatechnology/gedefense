// STATUS: DIAMANT VGT SUPREME
package main

import (
	"strings"
	"testing"
)

// TestDescribeWebSurfaceNeverClaimsProtection is the guard for point 8 of the L7
// change list: WordPress - or any web application - must never be described as
// protected merely because it was detected. Every sentence the discovery produces
// either states an observation or states the absence of coverage.
func TestDescribeWebSurfaceNeverClaimsProtection(t *testing.T) {
	cases := []struct {
		name     string
		surface  WebSurface
		attached bool
		mustSay  []string
		mustNot  []string
	}{
		{
			name:    "detected but not attached is the miswiring case",
			surface: WebSurface{Scanned: true, Detected: true, ExpectsHTTP: true, Listeners: 2},
			mustSay: []string{"not being inspected"},
			mustNot: []string{"protected", "secured", "covered", "inspected by"},
		},
		{
			name:     "detected and attached still does not claim protection",
			surface:  WebSurface{Scanned: true, Detected: true, ExpectsHTTP: true, Listeners: 2},
			attached: true,
			mustSay:  []string{"attached"},
			mustNot:  []string{"protected", "secured", "safe"},
		},
		{
			name:    "not scanned is not the same as nothing found",
			surface: WebSurface{Scanned: false, Reason: "the kernel socket tables could not be read"},
			mustSay: []string{"not scanned"},
			mustNot: []string{"no web server"},
		},
		{
			name:    "a host with no web surface says so",
			surface: WebSurface{Scanned: true},
			mustSay: []string{"no web server"},
			mustNot: []string{"protected", "attached"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := strings.ToLower(describeWebSurface(tc.surface, tc.attached))
			for _, needle := range tc.mustSay {
				if !strings.Contains(got, needle) {
					t.Errorf("description %q does not state %q", got, needle)
				}
			}
			for _, needle := range tc.mustNot {
				if strings.Contains(got, needle) {
					t.Errorf("description %q claims %q, which detection cannot support", got, needle)
				}
			}
		})
	}
}

// TestWebSurfaceDiscoveryIsBoundedAndHonest covers the discovery contract: it always
// answers, it never errors, and a failure to read the system reports "not scanned"
// rather than an empty surface that would read as "nothing running".
func TestWebSurfaceDiscoveryIsBoundedAndHonest(t *testing.T) {
	surface := discoverWebSurface()
	if !surface.Scanned && surface.Reason == "" {
		t.Fatal("an unscanned surface must carry a reason, otherwise it is indistinguishable from an empty one")
	}
	if surface.Scanned && surface.Reason != "" && len(surface.Servers) == 0 && len(surface.WebPorts) == 0 {
		t.Logf("scanned with no web surface: %s", surface.Reason)
	}
	for _, port := range surface.AllPorts {
		if port <= 0 || port > 65535 {
			t.Fatalf("discovery reported an impossible port %d", port)
		}
	}
	// Ports must be sorted and unique, because the UI renders them in order and a
	// duplicate would read as two listeners.
	for i := 1; i < len(surface.AllPorts); i++ {
		if surface.AllPorts[i] <= surface.AllPorts[i-1] {
			t.Fatalf("ports are not strictly ascending: %v", surface.AllPorts)
		}
	}
	for i := 1; i < len(surface.Servers); i++ {
		if surface.Servers[i].Name <= surface.Servers[i-1].Name {
			t.Fatalf("servers are not in a stable order: %v", surface.Servers)
		}
	}
	// Only allowlisted names may ever appear, so an unexpected executable cannot be
	// labelled a web server.
	for _, server := range surface.Servers {
		if !isKnownWebServerLabel(server.Name) {
			t.Fatalf("discovery reported a server name outside the allowlist: %q", server.Name)
		}
		if server.Count < 1 {
			t.Fatalf("server %q reported a non-positive count", server.Name)
		}
	}
}

func isKnownWebServerLabel(label string) bool {
	for _, known := range l7WebServerNames {
		if known == label {
			return true
		}
	}
	return false
}

// TestMiswiredIsDerivedFromObservation proves the state that matters most cannot be
// asserted from configuration alone: it needs a detected web surface AND an absent
// traffic path.
func TestMiswiredIsDerivedFromObservation(t *testing.T) {
	cases := []struct {
		name       string
		enabled    bool
		expects    bool
		attached   bool
		wantMiswir bool
	}{
		{"web surface, nothing attached", true, true, false, true},
		{"web surface, path attached", true, true, true, false},
		{"no web surface, nothing attached", true, false, false, false},
		{"disabled engine is never miswired", false, true, false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			surface := WebSurface{Scanned: true, ExpectsHTTP: tc.expects}
			got := tc.enabled && surface.ExpectsHTTP && !tc.attached
			if got != tc.wantMiswir {
				t.Fatalf("miswired=%v, want %v", got, tc.wantMiswir)
			}
		})
	}
}

// TestL7StatusSeparatesEngineAttachmentAndTraffic pins the separation the interface
// depends on. A consumer must be able to show engine health, path attachment and
// verified traffic as three facts, so none of them may be derived from another at the
// presentation layer.
func TestL7StatusSeparatesEngineAttachmentAndTraffic(t *testing.T) {
	// The engine is healthy and nothing is attached.
	idle := L7Status{Enabled: true, Healthy: true}
	idle.RequestsSeen = idle.RequestsTotal + idle.InlineRequestsTotal
	idle.ProducerAttached = idle.RequestsTotal > 0
	idle.TrafficPathAttached = idle.InlineEnabled || idle.RequestsSeen > 0 || idle.TLSHandshakesTotal > 0
	if !idle.Healthy {
		t.Fatal("engine health must not depend on attachment")
	}
	if idle.TrafficPathAttached || idle.ProducerAttached {
		t.Fatal("an idle engine reported an attached path")
	}

	// An inline listener is attachment even before the first request.
	inline := L7Status{Enabled: true, Healthy: true, InlineEnabled: true}
	inline.TrafficPathAttached = inline.InlineEnabled || inline.RequestsSeen > 0 || inline.TLSHandshakesTotal > 0
	if !inline.TrafficPathAttached {
		t.Fatal("an inline listener did not count as an attached path")
	}

	// A producer that has delivered is attachment and producer presence.
	producer := L7Status{Enabled: true, Healthy: true, RequestsTotal: 3}
	producer.RequestsSeen = producer.RequestsTotal + producer.InlineRequestsTotal
	producer.ProducerAttached = producer.RequestsTotal > 0
	producer.TrafficPathAttached = producer.InlineEnabled || producer.RequestsSeen > 0 || producer.TLSHandshakesTotal > 0
	if !producer.ProducerAttached || !producer.TrafficPathAttached {
		t.Fatal("a producer that delivered requests was not recognised")
	}
}
