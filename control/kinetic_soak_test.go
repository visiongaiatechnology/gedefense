package main

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// B14 deterministic stress gate. This is not a substitute for the mandatory
// target-host 24h soak, but it proves hostile network-prefix cardinality cannot
// grow the in-memory aggregation maps without a hard bound between sweeps.
func TestB14AggregateMapsBoundedUnderAdversarialCardinality(t *testing.T) {
	cfg := defaultConfig()
	cfg.Kinetic.MaxTrackingIPs = 32
	cfg.Kinetic.IPThreshold = 1 << 20
	cfg.Kinetic.RangeThreshold = 1 << 20
	cfg.Kinetic.IPv6SubThreshold = 1 << 20
	cfg.Kinetic.WideRangeThreshold = 1 << 20

	state := NewState("4.1.0", cfg)
	eng := NewKineticEngine(cfg.Kinetic, state, NewKineticRuleRegistry(), nil)
	now := time.Now().UTC()

	// More unique IPv4 /24s and /16s than their internal capacities.
	for i := 0; i < 1200; i++ {
		ip := net.IPv4(23, byte(i%250), byte((i/250)%250), byte((i%200)+1))
		eng.IngestPacket(IngressPacket{
			Family: 4, Protocol: 6, SrcIP: ip, DstIP: net.ParseIP("192.0.2.10"),
			DstPort: 443, TCPFlags: 0x02, Bytes: 1200,
			Timestamp: now.Add(time.Duration(i) * time.Millisecond),
		})
	}

	// More unique IPv6 /64s than their internal capacity.
	for i := 0; i < 600; i++ {
		ip := net.ParseIP(fmt.Sprintf("2001:db8:%x:%x::1", i/256, i%256))
		if ip == nil {
			t.Fatalf("failed to construct IPv6 test address %d", i)
		}
		eng.IngestPacket(IngressPacket{
			Family: 6, Protocol: 6, SrcIP: ip, DstIP: net.ParseIP("2001:db8:ffff::10"),
			DstPort: 443, TCPFlags: 0x02, Bytes: 1200,
			Timestamp: now.Add(2*time.Second + time.Duration(i)*time.Millisecond),
		})
	}

	if got := len(eng.ipBuckets); got > cfg.Kinetic.MaxTrackingIPs {
		t.Fatalf("IP tracker exceeded bound: got=%d max=%d", got, cfg.Kinetic.MaxTrackingIPs)
	}
	if got := len(eng.subnetV4Buckets); got > eng.maxSubnetBuckets {
		t.Fatalf("IPv4 subnet tracker exceeded bound: got=%d max=%d", got, eng.maxSubnetBuckets)
	}
	if got := len(eng.subnetV6Buckets); got > eng.maxSubnetBuckets {
		t.Fatalf("IPv6 subnet tracker exceeded bound: got=%d max=%d", got, eng.maxSubnetBuckets)
	}
	if got := len(eng.wideV4Buckets); got > eng.maxWideBuckets {
		t.Fatalf("wide IPv4 tracker exceeded bound: got=%d max=%d", got, eng.maxWideBuckets)
	}

	telemetry := eng.SnapshotTelemetry()
	if telemetry.AggregateEvictionsTotal == 0 {
		t.Fatal("expected aggregate eviction telemetry under adversarial prefix cardinality")
	}
	if telemetry.TrackingEvictionsTotal == 0 {
		t.Fatal("expected source eviction telemetry under adversarial source cardinality")
	}
}

func TestB14TrafficHistoryAgesOutBeyond24Hours(t *testing.T) {
	cfg := defaultConfig()
	cfg.Kinetic.IPThreshold = 1 << 20
	state := NewState("4.1.0", cfg)
	eng := NewKineticEngine(cfg.Kinetic, state, NewKineticRuleRegistry(), nil)

	base := time.Now().UTC().Truncate(time.Minute)
	source := net.ParseIP("198.51.100.77")
	for hour := 0; hour < 30; hour++ {
		eng.IngestPacket(IngressPacket{
			Family: 4, Protocol: 6, SrcIP: source, DstIP: net.ParseIP("192.0.2.10"),
			DstPort: 443, TCPFlags: 0x10, Packets: 1, Bytes: 500,
			Timestamp: base.Add(time.Duration(hour) * time.Hour),
		})
	}

	now := base.Add(30 * time.Hour)
	spec, ok := parseKineticWindow("24h")
	if !ok {
		t.Fatal("24h window parser unavailable")
	}
	window := eng.TrafficWindow(spec, now)
	if window.Hits > 24 {
		t.Fatalf("24h bounded history retained stale samples: hits=%d", window.Hits)
	}
}

func TestB14MetricsExposeKineticPressureAndResponseTruth(t *testing.T) {
	cfg := defaultConfig()
	state := NewState("4.1.0", cfg)
	state.UpdateKineticTelemetry(func(k *KineticTelemetry) {
		k.HitsTotal = 1234
		k.ActiveTrackingIPs = 17
		k.TrackingDropsTotal = 2
		k.TrackingEvictionsTotal = 3
		k.AggregateEvictionsTotal = 4
		k.KernelRingDrops = 5
		k.KernelTrackInsertFailures = 6
		k.BansEnforcedTotal = 7
		k.BansExpiredTotal = 8
		k.ResponseAppliedTotal = 9
		k.ResponseSuppressedTotal = 10
		k.ResponseFailedTotal = 11
	})
	server := NewAPIServer(cfg, state, nil, nil, nil, nil, nil, nil, "0123456789abcdef0123456789abcdef")
	req := httptest.NewRequest("GET", "http://127.0.0.1:9844/metrics", nil)
	req.RemoteAddr = "127.0.0.1:4242"
	rr := httptest.NewRecorder()
	server.metrics(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("metrics status=%d body=%s", rr.Code, rr.Body.String())
	}
	body := rr.Body.String()
	expected := []string{
		"gedefense_kinetic_hits_total 1234",
		"gedefense_kinetic_active_tracking_ips 17",
		"gedefense_kinetic_tracking_drops_total 2",
		"gedefense_kinetic_tracking_evictions_total 3",
		"gedefense_kinetic_aggregate_evictions_total 4",
		"gedefense_kinetic_kernel_ring_drops_total 5",
		"gedefense_kinetic_kernel_track_insert_failures_total 6",
		"gedefense_kinetic_bans_enforced_total 7",
		"gedefense_kinetic_bans_expired_total 8",
		"gedefense_kinetic_response_applied_total 9",
		"gedefense_kinetic_response_suppressed_total 10",
		"gedefense_kinetic_response_failed_total 11",
	}
	for _, line := range expected {
		if !strings.Contains(body, line) {
			t.Fatalf("missing Kinetic metric %q in:\n%s", line, body)
		}
	}
}
