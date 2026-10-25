// STATUS: DIAMANT VGT SUPREME
package main

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// l7StatusWire marshals a status exactly as the API serves it and decodes it back into
// a map, so the assertions below test the wire contract a consumer sees rather than the
// in-memory struct a publisher happened to write.
func l7StatusWire(t *testing.T, status L7Status) map[string]any {
	t.Helper()
	raw, err := json.Marshal(status)
	if err != nil {
		t.Fatalf("status cannot be serialized: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("serialized status is not valid JSON: %v", err)
	}
	return decoded
}

func l7WireBool(t *testing.T, view map[string]any, key string) bool {
	t.Helper()
	value, ok := view[key]
	if !ok {
		t.Fatalf("status JSON is missing %q: %v", key, view)
	}
	flag, ok := value.(bool)
	if !ok {
		t.Fatalf("status field %q is not a boolean: %T", key, value)
	}
	return flag
}

func l7WireUint(t *testing.T, view map[string]any, key string) uint64 {
	t.Helper()
	value, ok := view[key]
	if !ok {
		t.Fatalf("status JSON is missing %q: %v", key, view)
	}
	number, ok := value.(float64)
	if !ok || number < 0 {
		t.Fatalf("status field %q is not a non-negative number: %T %v", key, value, value)
	}
	return uint64(number)
}

// TestL7InlineProducerIsFirstClass covers the production gap this task exists for: a
// host that inspects all of its traffic through the inline edge reported
// producer_attached=false because that flag was derived from the socket-producer counter
// alone. Verified inline traffic has to count as an attached producer.
func TestL7InlineProducerIsFirstClass(t *testing.T) {
	last := time.Now().UTC()
	status := L7Status{
		Enabled:                 true,
		Healthy:                 true,
		InlineEnabled:           true,
		InlineHealthy:           true,
		InlineSocket:            "/run/vgt-gedefense-l7/edge.sock",
		InlineRequestsTotal:     16,
		InlineBlockedTotal:      3,
		InlineFindingsTotal:     5,
		InlineLastRequestAt:     &last,
		ResponsesInspectedTotal: 16,
		ResponseFindingsTotal:   4,
		Coverage:                "TRAFFIC_ACTIVE",
		TrafficPathVerified:     true,
	}

	view := l7StatusWire(t, status)
	if !l7WireBool(t, view, "producer_attached") {
		t.Fatal("verified inline traffic did not count as an attached producer")
	}
	if !l7WireBool(t, view, "inline_producer_attached") {
		t.Fatal("the inline producer flag is false for a healthy listener with inspected traffic")
	}
	if !l7WireBool(t, view, "traffic_path_attached") {
		t.Fatal("an attached inline path was reported as unattached")
	}
	if !l7WireBool(t, view, "traffic_path_verified") {
		t.Fatal("the verified-path flag did not follow the coverage verdict")
	}
	if got := l7WireUint(t, view, "requests_total"); got != 16 {
		t.Fatalf("requests_total must aggregate inline traffic, got %d", got)
	}
	if got := l7WireUint(t, view, "blocked_total"); got != 3 {
		t.Fatalf("blocked_total must aggregate inline traffic, got %d", got)
	}
	if got := l7WireUint(t, view, "findings_total"); got != 9 {
		t.Fatalf("findings_total must aggregate inline request and response findings, got %d", got)
	}
	reason, _ := view["inline_attachment_reason"].(string)
	if !strings.Contains(reason, "inspected") {
		t.Fatalf("the attachment reason does not name verified traffic: %q", reason)
	}
}

// TestL7InlineListenerWithoutTrafficIsAttachedNotProducer is the counter-case: binding
// the socket is not inspecting traffic. The path is attached, but it is not a producer
// and it is not verified.
func TestL7InlineListenerWithoutTrafficIsAttachedNotProducer(t *testing.T) {
	status := L7Status{
		Enabled:             true,
		Healthy:             true,
		InlineEnabled:       true,
		InlineHealthy:       true,
		Coverage:            "HEALTHY_AWAITING_TRAFFIC",
		TrafficPathAttached: true,
	}
	view := l7StatusWire(t, status)
	if l7WireBool(t, view, "producer_attached") {
		t.Fatal("a silent inline listener was reported as an attached producer")
	}
	if l7WireBool(t, view, "inline_producer_attached") {
		t.Fatal("a silent inline listener was reported as a verified producer")
	}
	if !l7WireBool(t, view, "traffic_path_attached") {
		t.Fatal("a healthy bound listener is an attached path")
	}
	if l7WireBool(t, view, "traffic_path_verified") {
		t.Fatal("an idle inline listener must not be reported as a verified path")
	}
	if got := l7WireUint(t, view, "requests_total"); got != 0 {
		t.Fatalf("idle status reported %d requests", got)
	}
	reason, _ := view["inline_attachment_reason"].(string)
	if !strings.Contains(reason, "awaiting") {
		t.Fatalf("the attachment reason does not name the awaiting state: %q", reason)
	}
}

// TestL7InlineUnhealthyIsNeitherAttachedNorVerified covers the stale-verdict defect: a
// listener that inspected requests and then failed must not keep claiming a verified
// path or an attached producer just because old counters are non-zero.
func TestL7InlineUnhealthyIsNeitherAttachedNorVerified(t *testing.T) {
	status := L7Status{
		Enabled:             true,
		Healthy:             true,
		InlineEnabled:       true,
		InlineHealthy:       false,
		InlineRequestsTotal: 4,
		InlineBlockedTotal:  1,
		// The flags below are exactly what a publisher that wrote before the failure
		// would have left behind.
		Coverage:            "TRAFFIC_ACTIVE",
		TrafficPathAttached: true,
		TrafficPathVerified: true,
	}
	view := l7StatusWire(t, status)
	if l7WireBool(t, view, "inline_producer_attached") {
		t.Fatal("an unhealthy inline listener was reported as a verified producer")
	}
	if l7WireBool(t, view, "producer_attached") {
		t.Fatal("an unhealthy inline listener was reported as an attached producer")
	}
	if l7WireBool(t, view, "traffic_path_attached") {
		t.Fatal("an unhealthy inline listener was reported as an attached path")
	}
	if l7WireBool(t, view, "traffic_path_verified") {
		t.Fatal("a stale verified flag survived an unhealthy inline listener")
	}
	reason, _ := view["inline_attachment_reason"].(string)
	if !strings.Contains(reason, "not healthy") {
		t.Fatalf("the attachment reason does not name the unhealthy state: %q", reason)
	}
}

// TestL7SocketProducerStillReportsAttachment guarantees the change does not regress the
// envelope-producer deployment: a producer-only host must still be reported as attached.
func TestL7SocketProducerStillReportsAttachment(t *testing.T) {
	status := L7Status{
		Enabled:       true,
		Healthy:       true,
		RequestsTotal: 7,
		FindingsTotal: 2,
		Coverage:      "TRAFFIC_ACTIVE",
	}
	view := l7StatusWire(t, status)
	if !l7WireBool(t, view, "producer_attached") {
		t.Fatal("socket-producer traffic no longer counts as an attached producer")
	}
	if l7WireBool(t, view, "inline_producer_attached") {
		t.Fatal("the inline producer flag is set without an inline listener")
	}
	if got := l7WireUint(t, view, "requests_total"); got != 7 {
		t.Fatalf("socket-producer requests_total changed: %d", got)
	}
	if got := l7WireUint(t, view, "findings_total"); got != 2 {
		t.Fatalf("socket-producer findings_total changed: %d", got)
	}
}

// TestL7AggregatedCountersAreIdempotent proves the aggregation does not double count
// when a status has already folded inline traffic into the totals. This is the shape the
// inline publisher writes, and the JSON derivation runs on top of it.
func TestL7AggregatedCountersAreIdempotent(t *testing.T) {
	status := L7Status{
		Enabled:               true,
		Healthy:               true,
		InlineEnabled:         true,
		InlineHealthy:         true,
		InlineRequestsTotal:   16,
		InlineBlockedTotal:    3,
		InlineFindingsTotal:   5,
		ResponseFindingsTotal: 4,
		// Already aggregated by the edge publisher: 7 socket + 16 inline, 2 socket +
		// 3 inline blocked, 1 socket + 5 inline + 4 response findings.
		RequestsTotal:       23,
		BlockedTotal:        5,
		FindingsTotal:       10,
		Coverage:            "TRAFFIC_ACTIVE",
		TrafficPathVerified: true,
	}
	view := l7StatusWire(t, status)
	if got := l7WireUint(t, view, "requests_total"); got != 23 {
		t.Fatalf("aggregated requests_total was double counted: %d", got)
	}
	if got := l7WireUint(t, view, "blocked_total"); got != 5 {
		t.Fatalf("aggregated blocked_total was double counted: %d", got)
	}
	if got := l7WireUint(t, view, "findings_total"); got != 10 {
		t.Fatalf("aggregated findings_total was double counted: %d", got)
	}
	if !l7WireBool(t, view, "producer_attached") {
		t.Fatal("mixed socket and inline traffic lost its producer attachment")
	}
}

// TestL7RawCountersAreAggregated proves the opposite direction: when the socket
// publisher wrote last and the status still carries raw producer counters, the wire
// format must present the aggregate including inline traffic.
func TestL7RawCountersAreAggregated(t *testing.T) {
	status := L7Status{
		Enabled:             true,
		Healthy:             true,
		InlineEnabled:       true,
		InlineHealthy:       true,
		InlineRequestsTotal: 16,
		InlineBlockedTotal:  3,
		InlineFindingsTotal: 5,
		RequestsTotal:       7,
		BlockedTotal:        2,
		FindingsTotal:       1,
	}
	view := l7StatusWire(t, status)
	if got := l7WireUint(t, view, "requests_total"); got != 23 {
		t.Fatalf("raw producer count was not aggregated with inline traffic: %d", got)
	}
	if got := l7WireUint(t, view, "blocked_total"); got != 5 {
		t.Fatalf("raw producer blocked count was not aggregated: %d", got)
	}
	if got := l7WireUint(t, view, "findings_total"); got != 6 {
		t.Fatalf("raw producer findings were not aggregated: %d", got)
	}
}

// TestL7AttachmentFlagsAreDerivedFromCounters pins the pure derivation used by the
// publisher, independent of JSON serialization.
func TestL7AttachmentFlagsAreDerivedFromCounters(t *testing.T) {
	cases := []struct {
		name     string
		status   L7Status
		inline   bool
		producer bool
		attached bool
	}{
		{
			name:     "inline_verified",
			status:   L7Status{InlineEnabled: true, InlineHealthy: true, InlineRequestsTotal: 2},
			inline:   true,
			producer: true,
			attached: true,
		},
		{
			name:     "inline_awaiting",
			status:   L7Status{InlineEnabled: true, InlineHealthy: true},
			inline:   false,
			producer: false,
			attached: true,
		},
		{
			name:     "inline_unhealthy",
			status:   L7Status{InlineEnabled: true, InlineRequestsTotal: 2},
			inline:   false,
			producer: false,
			attached: false,
		},
		{
			name:     "socket_producer",
			status:   L7Status{RequestsTotal: 3},
			inline:   false,
			producer: true,
			attached: true,
		},
		{
			name:     "tls_telemetry",
			status:   L7Status{TLSHandshakesTotal: 1},
			inline:   false,
			producer: false,
			attached: true,
		},
		{
			name:     "disabled",
			status:   L7Status{},
			inline:   false,
			producer: false,
			attached: false,
		},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			inline, producer, attached := l7AttachmentFlags(test.status)
			if inline != test.inline || producer != test.producer || attached != test.attached {
				t.Fatalf("flags mismatch: inline=%v producer=%v attached=%v, want %v/%v/%v",
					inline, producer, attached, test.inline, test.producer, test.attached)
			}
			clone := test.status
			clone.applyAttachmentSemantics()
			if clone.InlineProducerAttached != test.inline || clone.ProducerAttached != test.producer || clone.TrafficPathAttached != test.attached {
				t.Fatalf("applyAttachmentSemantics mismatch: %#v", clone)
			}
			if clone.InlineAttachmentReason == "" {
				t.Fatal("the attachment reason is empty")
			}
		})
	}
}

// TestL7HopByHopHeadersAreStripped pins the header list the edge removes before
// forwarding. The proxy must never forward hop-local fields or Connection-nominated
// fields, which can be used to smuggle state past the origin in a different form than
// the inspection layer saw it.
func TestL7HopByHopHeadersAreStripped(t *testing.T) {
	headers := l7HopByHopHeaders([]string{"X-Leak-Header, X-Other-Leak", ""})
	index := make(map[string]bool, len(headers))
	for _, header := range headers {
		index[strings.ToLower(header)] = true
	}
	for _, required := range []string{
		"connection", "proxy-connection", "keep-alive", "proxy-authenticate",
		"proxy-authorization", "te", "trailer", "transfer-encoding", "upgrade",
		"x-leak-header", "x-other-leak",
	} {
		if !index[required] {
			t.Fatalf("hop-by-hop/strip list is missing %q: %v", required, headers)
		}
	}
}
