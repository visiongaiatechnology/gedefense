// STATUS: DIAMANT VGT SUPREME
package main

import (
	"testing"
	"time"
)

// The inline publisher is the single place that folds the inline edge's own atomics into
// the shared L7 status. These tests drive it directly, without sockets, so the
// aggregation and attachment arithmetic is executable on any platform the package builds
// on (the suite is Linux-only because the package uses Linux facilities elsewhere).
func newL7InlinePublisherFixture(t *testing.T) (*L7EdgeService, *State) {
	t.Helper()
	cfg := l7TestConfig()
	cfg.InlineEnabled = true
	cfg.InlineSocket = "/run/vgt-gedefense-l7/edge.sock"
	state := NewState("test", Config{L7: cfg, XDR: defaultConfig().XDR, Release: defaultConfig().Release})
	// The inspection service publishes its own view at start-up. Simulate a host where
	// the socket producer already delivered traffic before the inline edge started.
	state.UpdateL7Status(func(status *L7Status) {
		status.Enabled = true
		status.Healthy = true
		status.Coverage = "TRAFFIC_ACTIVE"
		status.RequestsTotal = 7
		status.FindingsTotal = 2
		status.BlockedTotal = 1
	})
	service := &L7EdgeService{cfg: cfg, state: state, errors: make(chan error, 1)}
	return service, state
}

func TestL7InlinePublisherAggregatesInlineAndSocketTraffic(t *testing.T) {
	service, state := newL7InlinePublisherFixture(t)
	service.requests.Store(16)
	service.blocked.Store(3)
	service.findings.Store(5)
	service.responseFindings.Store(4)
	service.responsesInspected.Store(16)
	service.lastRequestUnix.Store(time.Now().UTC().UnixNano())

	service.publishStatus(true)

	status := state.L7Status()
	if status.InlineRequestsTotal != 16 {
		t.Fatalf("inline_requests_total=%d", status.InlineRequestsTotal)
	}
	if status.RequestsTotal != 23 {
		t.Fatalf("requests_total must aggregate socket and inline traffic: %d", status.RequestsTotal)
	}
	if status.BlockedTotal != 4 {
		t.Fatalf("blocked_total must aggregate socket and inline blocks: %d", status.BlockedTotal)
	}
	if status.FindingsTotal != 11 {
		t.Fatalf("findings_total must aggregate socket, inline and response findings: %d", status.FindingsTotal)
	}
	if status.InlineFindingsTotal != 5 {
		t.Fatalf("inline_findings_total=%d", status.InlineFindingsTotal)
	}
	if !status.InlineProducerAttached || !status.ProducerAttached {
		t.Fatalf("verified inline traffic was not attached as producer: %#v", status)
	}
	if !status.TrafficPathAttached || !status.TrafficPathVerified {
		t.Fatalf("traffic path flags are wrong after verified inline traffic: %#v", status)
	}
	if status.InlineLastRequestAt == nil {
		t.Fatal("inline_last_request_at was not recorded")
	}
	if status.LastInspection == nil || status.LastProducerSeen == nil {
		t.Fatal("last_inspection/last_producer_seen were not derived from the inline request")
	}

	view := l7StatusWire(t, state.Snapshot().L7)
	if got := l7WireUint(t, view, "requests_total"); got != 23 {
		t.Fatalf("wire requests_total=%d", got)
	}
	if got := l7WireUint(t, view, "blocked_total"); got != 4 {
		t.Fatalf("wire blocked_total=%d", got)
	}
	if got := l7WireUint(t, view, "findings_total"); got != 11 {
		t.Fatalf("wire findings_total=%d", got)
	}
	if !l7WireBool(t, view, "producer_attached") || !l7WireBool(t, view, "inline_producer_attached") {
		t.Fatalf("wire attachment verdict is wrong: %v", view)
	}
}

// TestL7InlinePublisherIdempotentAcrossRepeatedPublishes proves repeated publishes do not
// accumulate counters twice. The inline edge publishes once per request and once per
// inspected response, so this is the common case.
func TestL7InlinePublisherIdempotentAcrossRepeatedPublishes(t *testing.T) {
	service, state := newL7InlinePublisherFixture(t)
	service.requests.Store(16)
	service.blocked.Store(3)
	service.findings.Store(5)
	service.responseFindings.Store(4)

	for i := 0; i < 3; i++ {
		service.publishStatus(true)
	}
	status := state.L7Status()
	if status.RequestsTotal != 23 || status.BlockedTotal != 4 || status.FindingsTotal != 11 {
		t.Fatalf("repeated publishes accumulated totals: %#v", status)
	}
}

// TestL7InlinePublisherUnhealthyClearsAttachment covers the failure mode: after an error
// the path must stop claiming a verified inline producer, while socket-producer traffic
// (if any) still keeps the overall producer flag true.
func TestL7InlinePublisherUnhealthyClearsAttachment(t *testing.T) {
	service, state := newL7InlinePublisherFixture(t)
	service.requests.Store(16)
	service.publishStatus(true)
	service.publishStatus(false)

	status := state.L7Status()
	if status.InlineHealthy {
		t.Fatal("publishing an unhealthy listener left inline_healthy=true")
	}
	if status.InlineProducerAttached {
		t.Fatalf("unhealthy inline listener still counts as a producer: %#v", status)
	}
	// The socket producer has 7 requests, so the overall producer verdict stays true;
	// the inline verdict must be false and the reason must name the unhealthy state.
	if !status.ProducerAttached {
		t.Fatalf("socket-producer traffic lost its producer verdict: %#v", status)
	}
	view := l7StatusWire(t, state.Snapshot().L7)
	if l7WireBool(t, view, "inline_producer_attached") {
		t.Fatal("wire status still reports an inline producer after a listener failure")
	}
}

// TestL7InlinePublisherAwaitingFirstRequest keeps the "attached but not producer" state
// stable: a freshly started listener publishes once before any request arrives.
func TestL7InlinePublisherAwaitingFirstRequest(t *testing.T) {
	cfg := l7TestConfig()
	cfg.InlineEnabled = true
	cfg.InlineSocket = "/run/vgt-gedefense-l7/edge.sock"
	state := NewState("test", Config{L7: cfg, XDR: defaultConfig().XDR, Release: defaultConfig().Release})
	service := &L7EdgeService{cfg: cfg, state: state, errors: make(chan error, 1)}

	service.publishStatus(true)

	status := state.L7Status()
	if !status.InlineHealthy || status.InlineRequestsTotal != 0 {
		t.Fatalf("fresh listener status is wrong: %#v", status)
	}
	if !status.TrafficPathAttached {
		t.Fatal("a healthy bound listener is an attached path")
	}
	if status.InlineProducerAttached || status.ProducerAttached {
		t.Fatalf("a silent listener was reported as producer: %#v", status)
	}
	view := l7StatusWire(t, state.Snapshot().L7)
	if l7WireBool(t, view, "traffic_path_verified") {
		t.Fatal("an idle inline listener was reported as a verified path")
	}
	reason, _ := view["inline_attachment_reason"].(string)
	if reason == "" {
		t.Fatal("the attachment reason is empty")
	}
}
