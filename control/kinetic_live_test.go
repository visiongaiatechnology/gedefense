package main

import (
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func ingestWindowSample(t *testing.T, eng *KineticEngine, ip string, at time.Time, port uint16) {
	t.Helper()
	parsed := net.ParseIP(ip)
	if parsed == nil {
		t.Fatalf("invalid test IP %q", ip)
	}
	eng.IngestPacket(IngressPacket{
		Family: 4, Protocol: 17, SrcIP: parsed, DstIP: net.ParseIP("198.51.100.1"),
		DstPort: port, Bytes: 64, Timestamp: at,
	})
}

func TestKineticTrafficWindowsAreServerSideAndBounded(t *testing.T) {
	eng, _ := newTestKineticEngine(t)
	now := time.Now().UTC().Truncate(time.Second)
	eng.startedAt = now.Add(-25 * time.Hour)

	for _, at := range []time.Time{
		now.Add(-20 * time.Minute),
		now.Add(-10 * time.Minute),
		now.Add(-3 * time.Minute),
		now.Add(-30 * time.Second),
	} {
		ingestWindowSample(t, eng, "203.0.113.91", at, 443)
	}

	cases := []struct {
		name string
		want uint64
	}{
		{"live", 1},
		{"1m", 1},
		{"5m", 2},
		{"15m", 3},
		{"1h", 4},
		{"24h", 4},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			spec, ok := parseKineticWindow(tc.name)
			if !ok {
				t.Fatalf("window %s unexpectedly rejected", tc.name)
			}
			got := eng.TrafficWindow(spec, now)
			if got.Hits != tc.want {
				t.Fatalf("window %s hits=%d want=%d", tc.name, got.Hits, tc.want)
			}
			if !got.HistoryComplete {
				t.Fatalf("window %s should have complete global history after 25h runtime", tc.name)
			}
		})
	}
}

func TestKineticSourceWindowCountersAndCIDRBlockMatch(t *testing.T) {
	eng, state := newTestKineticEngine(t)
	now := time.Now().UTC().Truncate(time.Second)
	eng.startedAt = now.Add(-time.Hour)

	for _, at := range []time.Time{now.Add(-12 * time.Minute), now.Add(-3 * time.Minute), now.Add(-20 * time.Second)} {
		ingestWindowSample(t, eng, "203.0.113.44", at, 22)
	}
	if _, err := state.AddBlock("203.0.113.0/24", "test subnet containment", "test", time.Hour, true, 100); err != nil {
		t.Fatal(err)
	}

	spec, _ := parseKineticWindow("5m")
	sources := eng.SourceSnapshotForWindow(10, spec, now)
	if len(sources) != 1 {
		t.Fatalf("sources=%d want=1: %#v", len(sources), sources)
	}
	if sources[0].WindowHits != 2 {
		t.Fatalf("5m window hits=%d want=2", sources[0].WindowHits)
	}
	if !sources[0].Blocked || sources[0].State != "BLOCKED" {
		t.Fatalf("CIDR block not reflected in source state: %#v", sources[0])
	}
}

func TestKineticLiveAPIContractAndBounds(t *testing.T) {
	cfg := defaultConfig()
	state := NewState("test", cfg)
	server := NewAPIServer(cfg, state, nil, nil, nil, nil, nil, nil, "0123456789abcdef0123456789abcdef")
	now := time.Now().UTC()
	server.kinetic.startedAt = now.Add(-time.Hour)

	// Active sources: more than requested response limit.
	for i := 1; i <= 40; i++ {
		ip := net.IPv4(203, 0, 113, byte(i))
		server.kinetic.IngestPacket(IngressPacket{Family: 4, Protocol: 17, SrcIP: ip, DstIP: net.ParseIP("198.51.100.1"), DstPort: 443, Bytes: 64, Timestamp: now.Add(-10 * time.Second)})
	}
	// Event pressure: force the bounded queue past capacity to prove the API
	// cannot serialize an unbounded history.
	for i := 0; i < 400; i++ {
		server.kinetic.eventQueue.Push(KineticEvent{ID: generateEventID(), Time: now.Add(-time.Duration(i%20) * time.Second), RuleID: "NET.INGRESS.TEST", Port: 443, Action: "warn"})
	}

	req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1/api/v1/kinetic/live?window=5m&limit=25&state=all", nil)
	req.Host = "127.0.0.1"
	req.Header.Set("Authorization", "Bearer 0123456789abcdef0123456789abcdef")
	rec := httptest.NewRecorder()
	server.http.Handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("live endpoint status=%d body=%s", rec.Code, rec.Body.String())
	}

	var payload kineticLiveResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Window != "5m" || payload.WindowSeconds != 300 || payload.StateFilter != "all" {
		t.Fatalf("window contract mismatch: %#v", payload)
	}
	if len(payload.Sources) > 25 || len(payload.Events) > 25 {
		t.Fatalf("bounded API exceeded requested limits: sources=%d events=%d", len(payload.Sources), len(payload.Events))
	}
	if payload.Bounds.EventCapacity != 250 || payload.Bounds.EventDropsTotal == 0 || !payload.Bounds.Bounded {
		t.Fatalf("event buffer bounds not surfaced: %#v", payload.Bounds)
	}
	if payload.Traffic.Hits != 40 {
		t.Fatalf("window traffic hits=%d want=40", payload.Traffic.Hits)
	}
}

func TestKineticLiveAPIRejectsInvalidWindowStateAndLimit(t *testing.T) {
	cfg := defaultConfig()
	server := NewAPIServer(cfg, NewState("test", cfg), nil, nil, nil, nil, nil, nil, "0123456789abcdef0123456789abcdef")
	for _, path := range []string{
		"/api/v1/kinetic/live?window=forever",
		"/api/v1/kinetic/live?window=5m&state=evil",
		"/api/v1/kinetic/live?window=5m&limit=9999",
	} {
		req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1"+path, nil)
		req.Host = "127.0.0.1"
		req.Header.Set("Authorization", "Bearer 0123456789abcdef0123456789abcdef")
		rec := httptest.NewRecorder()
		server.http.Handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("%s status=%d want=400 body=%s", path, rec.Code, rec.Body.String())
		}
	}
}

func TestKinetic24hSourceHistoryTruthfullyMarksPartialRetention(t *testing.T) {
	cfg := defaultConfig()
	state := NewState("test", cfg)
	server := NewAPIServer(cfg, state, nil, nil, nil, nil, nil, nil, "0123456789abcdef0123456789abcdef")
	server.kinetic.startedAt = time.Now().UTC().Add(-48 * time.Hour)

	req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1/api/v1/kinetic/live?window=24h", nil)
	req.Host = "127.0.0.1"
	req.Header.Set("Authorization", "Bearer 0123456789abcdef0123456789abcdef")
	rec := httptest.NewRecorder()
	server.http.Handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var payload kineticLiveResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Bounds.SourceHistoryComplete {
		t.Fatal("24h source history must not claim completeness with 1h source retention")
	}
	if payload.Traffic.BucketResolution != "60s" {
		t.Fatalf("24h traffic bucket resolution=%q want 60s", payload.Traffic.BucketResolution)
	}
}

func TestKineticLiveReportsTotalActiveBlocksIndependentOfSourceLimit(t *testing.T) {
	cfg := defaultConfig()
	state := NewState("test", cfg)
	server := NewAPIServer(cfg, state, nil, nil, nil, nil, nil, nil, "0123456789abcdef0123456789abcdef")
	now := time.Now().UTC()
	server.kinetic.startedAt = now.Add(-time.Hour)

	for i := 1; i <= 20; i++ {
		ip := net.IPv4(8, 8, 8, byte(i))
		server.kinetic.IngestPacket(IngressPacket{Family: 4, Protocol: 6, TCPFlags: 0x02, SrcIP: ip, DstIP: net.ParseIP("1.1.1.1"), DstPort: 22, Bytes: 64, Timestamp: now.Add(-10 * time.Second)})
	}
	for _, target := range []string{"8.8.8.1/32", "8.8.8.0/24", "2001:4860::1/128"} {
		if _, err := state.AddBlock(target, "test", "operator", time.Hour, true, 100); err != nil {
			t.Fatal(err)
		}
	}

	req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1/api/v1/kinetic/live?window=5m&limit=1", nil)
	req.Host = "127.0.0.1"
	req.Header.Set("Authorization", "Bearer 0123456789abcdef0123456789abcdef")
	rec := httptest.NewRecorder()
	server.http.Handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var payload kineticLiveResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.ActiveBlocks != 3 {
		t.Fatalf("active_blocks=%d want=3", payload.ActiveBlocks)
	}
	if len(payload.Sources) != 1 {
		t.Fatalf("source limit not honored: %d", len(payload.Sources))
	}
}

func TestKineticLiveGeoDoesNotPinSpecialUseSources(t *testing.T) {
	cfg := defaultConfig()
	state := NewState("test", cfg)
	server := NewAPIServer(cfg, state, nil, nil, nil, nil, nil, nil, "0123456789abcdef0123456789abcdef")
	server.geo = NewGeoResolver(writeGeoFixture(t, "network,country_code,country_name,latitude,longitude\n0.0.0.0/0,US,United States,37.751,-97.822\n::/0,US,United States,37.751,-97.822\n"))
	now := time.Now().UTC()
	server.kinetic.startedAt = now.Add(-time.Hour)

	for _, raw := range []string{"192.0.2.44", "2001:db8::44"} {
		ip := net.ParseIP(raw)
		family := uint8(4)
		if ip.To4() == nil {
			family = 6
		}
		server.kinetic.IngestPacket(IngressPacket{Family: family, Protocol: 6, TCPFlags: 0x02, SrcIP: ip, DstIP: net.ParseIP("1.1.1.1"), DstPort: 22, Bytes: 64, Timestamp: now.Add(-5 * time.Second)})
	}

	req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1/api/v1/kinetic/live?window=5m&limit=10", nil)
	req.Host = "127.0.0.1"
	req.Header.Set("Authorization", "Bearer 0123456789abcdef0123456789abcdef")
	rec := httptest.NewRecorder()
	server.http.Handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var payload kineticLiveResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if len(payload.Countries) != 0 {
		t.Fatalf("special-use sources produced country aggregates: %#v", payload.Countries)
	}
	for _, src := range payload.Sources {
		if src.CountryCode != "" || src.Latitude != nil || src.Longitude != nil {
			t.Fatalf("special-use source was geolocated: %#v", src)
		}
	}
}
