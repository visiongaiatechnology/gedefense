package main

import (
	"net"
	"testing"
	"time"
)

func newTestKineticEngine(t *testing.T) (*KineticEngine, *State) {
	t.Helper()
	cfg := defaultConfig()
	state := NewState("4.1.0", cfg)
	rules := NewKineticRuleRegistry()
	eng := NewKineticEngine(cfg.Kinetic, state, rules, []string{"192.0.2.10/32", "198.51.100.0/24"})
	return eng, state
}

func TestKineticSingleIPRateTrigger(t *testing.T) {
	eng, _ := newTestKineticEngine(t)
	srcIP := net.ParseIP("203.0.113.50")
	now := time.Now().UTC().Truncate(time.Minute)

	var events []KineticEvent
	// Send 34 packets across different seconds but within one minute to avoid
	// velocity while exercising the explicit 1-minute IP-rate window.
	for i := 0; i < 34; i++ {
		secTime := now.Add(time.Duration(i) * time.Second)
		evts := eng.IngestPacket(IngressPacket{
			Family:    4,
			Protocol:  17,
			SrcIP:     srcIP,
			DstIP:     net.ParseIP("198.51.100.1"),
			DstPort:   443,
			Bytes:     64,
			Timestamp: secTime,
		})
		if len(evts) > 0 {
			events = append(events, evts...)
		}
	}
	if len(events) != 0 {
		t.Fatalf("expected 0 events before reaching IPThreshold (35), got %d", len(events))
	}

	// 35th packet triggers NET.INGRESS.IP_RATE
	evts := eng.IngestPacket(IngressPacket{
		Family:    4,
		Protocol:  17,
		SrcIP:     srcIP,
		DstIP:     net.ParseIP("198.51.100.1"),
		DstPort:   443,
		Bytes:     64,
		Timestamp: now.Add(34 * time.Second),
	})

	found := false
	for _, e := range evts {
		if e.RuleID == "NET.INGRESS.IP_RATE" && e.SourceIP == "203.0.113.50" {
			found = true
			if e.Hits != 35 {
				t.Fatalf("expected 35 hits in event, got %d", e.Hits)
			}
		}
	}
	if !found {
		t.Fatalf("expected NET.INGRESS.IP_RATE trigger on 35th packet, got: %+v", evts)
	}
}

func TestKineticVelocityBurstTrigger(t *testing.T) {
	eng, _ := newTestKineticEngine(t)
	srcIP := net.ParseIP("203.0.113.99")
	now := time.Now().UTC()

	var triggeredEvent *KineticEvent
	// Send packets rapidly within the same second
	for i := 1; i <= 15; i++ {
		evts := eng.IngestPacket(IngressPacket{
			Family:    4,
			Protocol:  6,
			SrcIP:     srcIP,
			DstIP:     net.ParseIP("198.51.100.1"),
			DstPort:   443,
			TCPFlags:  0x02, // SYN without ACK: connection-attempt velocity
			Bytes:     64,
			Timestamp: now,
		})
		for _, e := range evts {
			if e.RuleID == "NET.INGRESS.IP_VELOCITY" {
				triggeredEvent = &e
				break
			}
		}
	}

	if triggeredEvent == nil {
		t.Fatalf("expected NET.INGRESS.IP_VELOCITY event at velocity limit 15/s")
	}
	if triggeredEvent.RatePerSec != 15 {
		t.Fatalf("expected rate per sec 15, got %f", triggeredEvent.RatePerSec)
	}
}

func TestKineticSubnetV4Aggregation(t *testing.T) {
	eng, _ := newTestKineticEngine(t)
	now := time.Now().UTC()

	// Simulate distributed botnet across 203.0.113.0/24 with 3 IPs
	ips := []string{"203.0.113.10", "203.0.113.20", "203.0.113.30"}
	var subnetTriggered bool

	for i := 0; i < 46; i++ {
		ip := net.ParseIP(ips[i%len(ips)])
		secTime := now.Add(time.Duration(i*2) * time.Second)
		evts := eng.IngestPacket(IngressPacket{
			Family:    4,
			Protocol:  17,
			SrcIP:     ip,
			DstIP:     net.ParseIP("198.51.100.1"),
			DstPort:   443,
			Bytes:     64,
			Timestamp: secTime,
		})
		for _, e := range evts {
			if e.RuleID == "NET.INGRESS.SUBNET_V4" {
				subnetTriggered = true
				if e.Subnet != "203.0.113.0/24" {
					t.Fatalf("expected subnet 203.0.113.0/24, got %s", e.Subnet)
				}
				if got := kineticContributorCount(e); got < 2 {
					t.Fatalf("expected multi-source evidence metadata, got %d contributors", got)
				}
				break
			}
		}
		if subnetTriggered {
			break
		}
	}

	if !subnetTriggered {
		t.Fatalf("expected NET.INGRESS.SUBNET_V4 trigger after 45 aggregated hits across /24")
	}
}

func TestKineticSubnetV6Aggregation(t *testing.T) {
	eng, _ := newTestKineticEngine(t)
	now := time.Now().UTC()

	// Coordinated flood from 2001:db8:abcd:0012::/64
	v6IPs := []string{
		"2001:db8:abcd:12::1",
		"2001:db8:abcd:12::2",
		"2001:db8:abcd:12::3",
	}

	var v6SubnetTriggered bool
	for i := 0; i < 56; i++ {
		ip := net.ParseIP(v6IPs[i%len(v6IPs)])
		secTime := now.Add(time.Duration(i*2) * time.Second)
		evts := eng.IngestPacket(IngressPacket{
			Family:    6,
			Protocol:  17,
			SrcIP:     ip,
			DstIP:     net.ParseIP("2001:db8::1"),
			DstPort:   443,
			Bytes:     64,
			Timestamp: secTime,
		})
		for _, e := range evts {
			if e.RuleID == "NET.INGRESS.SUBNET_V6" {
				v6SubnetTriggered = true
				if got := kineticContributorCount(e); got < 2 {
					t.Fatalf("expected IPv6 multi-source evidence metadata, got %d contributors", got)
				}
				break
			}
		}
		if v6SubnetTriggered {
			break
		}
	}

	if !v6SubnetTriggered {
		t.Fatalf("expected NET.INGRESS.SUBNET_V6 trigger after 55 hits in IPv6 /64")
	}
}

func TestKineticPortscanDetection(t *testing.T) {
	eng, _ := newTestKineticEngine(t)
	srcIP := net.ParseIP("203.0.113.77")
	now := time.Now().UTC()

	ports := []uint16{80, 443, 8080, 8443, 9000}
	var scanDetected bool

	for _, p := range ports {
		evts := eng.IngestPacket(IngressPacket{
			Family:    4,
			Protocol:  6,
			SrcIP:     srcIP,
			DstIP:     net.ParseIP("198.51.100.1"),
			DstPort:   p,
			TCPFlags:  0x02, // SYN
			Bytes:     60,
			Timestamp: now,
		})
		for _, e := range evts {
			if e.RuleID == "NET.INGRESS.PORT_SCAN" {
				scanDetected = true
				break
			}
		}
	}

	if !scanDetected {
		t.Fatalf("expected NET.INGRESS.PORT_SCAN trigger after probing 5 distinct ports")
	}
}

func TestKineticManagementAllowlistImmunity(t *testing.T) {
	eng, _ := newTestKineticEngine(t)
	// 192.0.2.10 was in allowlist
	allowlistedIP := net.ParseIP("192.0.2.10")
	now := time.Now().UTC()

	for i := 0; i < 100; i++ {
		evts := eng.IngestPacket(IngressPacket{
			Family:    4,
			Protocol:  6,
			SrcIP:     allowlistedIP,
			DstIP:     net.ParseIP("198.51.100.1"),
			DstPort:   22,
			TCPFlags:  0x02,
			Bytes:     64,
			Timestamp: now,
		})
		if len(evts) > 0 {
			t.Fatalf("allowlisted IP triggered kinetic events: %+v", evts)
		}
	}
}

func TestKineticMalformedTCPFlags(t *testing.T) {
	eng, _ := newTestKineticEngine(t)
	srcIP := net.ParseIP("203.0.113.88")
	now := time.Now().UTC()

	var malformedTriggered bool
	for i := 0; i < 3; i++ {
		evts := eng.IngestPacket(IngressPacket{
			Family:    4,
			Protocol:  6,
			SrcIP:     srcIP,
			DstIP:     net.ParseIP("198.51.100.1"),
			DstPort:   80,
			TCPFlags:  0x00, // NULL scan
			Bytes:     60,
			Timestamp: now,
		})
		for _, e := range evts {
			if e.RuleID == "NET.INGRESS.MALFORMED_TCP" {
				malformedTriggered = true
				break
			}
		}
	}

	if !malformedTriggered {
		t.Fatalf("expected NET.INGRESS.MALFORMED_TCP trigger on repeated NULL flags")
	}
}

func TestKineticSweepAndEviction(t *testing.T) {
	eng, state := newTestKineticEngine(t)
	srcIP := net.ParseIP("203.0.113.111")
	now := time.Now().UTC()

	eng.IngestPacket(IngressPacket{
		Family:    4,
		Protocol:  6,
		SrcIP:     srcIP,
		DstIP:     net.ParseIP("198.51.100.1"),
		DstPort:   80,
		TCPFlags:  0x10,
		Bytes:     64,
		Timestamp: now,
	})

	if snap := state.Snapshot(); snap.Kinetic.ActiveTrackingIPs != 1 {
		t.Fatalf("expected 1 active tracking IP, got %d", snap.Kinetic.ActiveTrackingIPs)
	}

	// Low-and-slow detection needs source history beyond one minute. A 65s
	// pause must therefore not destroy the bucket.
	eng.Sweep(now.Add(65 * time.Second))
	if snap := state.Snapshot(); snap.Kinetic.ActiveTrackingIPs != 1 {
		t.Fatalf("expected source history to survive 65s for low-and-slow detection, got %d", snap.Kinetic.ActiveTrackingIPs)
	}

	// One hour of inactivity is the bounded retention limit.
	eng.Sweep(now.Add(time.Hour + time.Second))
	if snap := state.Snapshot(); snap.Kinetic.ActiveTrackingIPs != 0 {
		t.Fatalf("expected 0 active tracking IPs after >1h idle, got %d", snap.Kinetic.ActiveTrackingIPs)
	}
}

func TestKineticAggregatedTCPFlagsDoNotInflateVelocity(t *testing.T) {
	eng, _ := newTestKineticEngine(t)
	now := time.Now().UTC()

	// Models a previous-window aggregate accidentally carrying the next packet's
	// SYN flag. Aggregate counters say these 14 packets contained no SYN attempts
	// and 14 ACKs, so the flag must not turn the whole batch into 14 SYNs.
	events := eng.IngestPacket(IngressPacket{
		Family:    4,
		Protocol:  6,
		SrcIP:     net.ParseIP("203.0.113.140"),
		DstIP:     net.ParseIP("198.51.100.1"),
		DstPort:   443,
		TCPFlags:  0x02,
		Packets:   14,
		SYNCount:  0,
		ACKCount:  14,
		Bytes:     14 * 64,
		Timestamp: now,
	})
	for _, event := range events {
		if event.RuleID == "NET.INGRESS.IP_VELOCITY" || event.RuleID == "NET.INGRESS.SYN_FLOOD" {
			t.Fatalf("aggregate trigger flags produced false connection signal: %+v", event)
		}
	}

	sources := eng.SourceSnapshot(10)
	if len(sources) != 1 {
		t.Fatalf("expected one tracked source, got %d", len(sources))
	}
	if sources[0].RatePerSec != 0 || sources[0].SYNs != 0 || sources[0].ACKs != 14 {
		t.Fatalf("unexpected aggregate counters: %+v", sources[0])
	}
}

func TestKineticNeutralCarryoverUsesExactCounters(t *testing.T) {
	eng, _ := newTestKineticEngine(t)
	now := time.Now().UTC()

	// Protocol 0 is the kernel producer's metadata-neutral carry-over marker.
	// Exact SYN/ACK deltas still need to survive while destination/port context
	// stays intentionally unspecified.
	eng.IngestPacket(IngressPacket{
		Family:    6,
		Protocol:  0,
		SrcIP:     net.ParseIP("2001:db8:abcd:42::99"),
		Packets:   10,
		SYNCount:  3,
		ACKCount:  7,
		Bytes:     1280,
		Timestamp: now,
	})

	sources := eng.SourceSnapshot(10)
	if len(sources) != 1 {
		t.Fatalf("expected one tracked source, got %d", len(sources))
	}
	got := sources[0]
	if got.Hits != 10 || got.RatePerSec != 3 || got.SYNs != 3 || got.ACKs != 7 {
		t.Fatalf("neutral carry-over lost exact counters: %+v", got)
	}
	if len(got.Ports) != 0 {
		t.Fatalf("neutral carry-over must not invent destination ports: %+v", got.Ports)
	}
}

func TestKineticKernelWindowEpochPreventsIPCBatchVelocityMerge(t *testing.T) {
	eng, _ := newTestKineticEngine(t)
	now := time.Now().UTC()
	src := net.ParseIP("203.0.113.201")

	for _, epoch := range []uint64{1000, 1001} {
		events := eng.IngestPacket(IngressPacket{
			Family: 4, Protocol: 6, SrcIP: src, DstIP: net.ParseIP("198.51.100.1"), DstPort: 443,
			Packets: 10, SYNCount: 10, AttemptCount: 10, Bytes: 640, WindowEpoch: epoch, Timestamp: now,
		})
		for _, event := range events {
			if event.RuleID == "NET.INGRESS.IP_VELOCITY" {
				t.Fatalf("separate kernel seconds were merged into a false velocity burst: %+v", event)
			}
		}
	}

	sources := eng.SourceSnapshot(10)
	if len(sources) != 1 || sources[0].RatePerSec != 10 {
		t.Fatalf("expected current kernel-second velocity of 10, got %+v", sources)
	}
}

func TestKineticIPRateDoesNotAccumulateAcrossMinuteBoundary(t *testing.T) {
	eng, _ := newTestKineticEngine(t)
	now := time.Now().UTC().Truncate(time.Minute)
	src := net.ParseIP("203.0.113.202")

	// 34 hits near the end of one minute, then 34 in the next minute. Lifetime
	// hits exceed the legacy threshold, but neither current rate window does.
	for minute := 0; minute < 2; minute++ {
		base := now.Add(time.Duration(minute) * time.Minute)
		for i := 0; i < 34; i++ {
			events := eng.IngestPacket(IngressPacket{
				Family: 4, Protocol: 17, SrcIP: src, DstIP: net.ParseIP("198.51.100.1"), DstPort: 443,
				Bytes: 64, Timestamp: base.Add(time.Duration(i) * time.Second),
			})
			for _, event := range events {
				if event.RuleID == "NET.INGRESS.IP_RATE" {
					t.Fatalf("lifetime traffic incorrectly triggered one-minute IP rate: %+v", event)
				}
			}
		}
	}
}

func TestKineticSYNFloodUsesCurrentMinuteHandshakeBalance(t *testing.T) {
	eng, _ := newTestKineticEngine(t)
	now := time.Now().UTC().Truncate(time.Minute)
	src := net.ParseIP("203.0.113.203")

	var found bool
	for i := 0; i < 25; i++ {
		events := eng.IngestPacket(IngressPacket{
			Family: 4, Protocol: 6, SrcIP: src, DstIP: net.ParseIP("198.51.100.1"), DstPort: 443,
			TCPFlags: 0x02, Bytes: 64, Timestamp: now.Add(time.Duration(i) * time.Second),
		})
		for _, event := range events {
			if event.RuleID == "NET.INGRESS.SYN_FLOOD" {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("expected SYN flood after 25 SYN attempts without matching ACKs in one minute")
	}

	balanced, _ := newTestKineticEngine(t)
	balancedEvents := balanced.IngestPacket(IngressPacket{
		Family: 4, Protocol: 6, SrcIP: net.ParseIP("203.0.113.204"), DstIP: net.ParseIP("198.51.100.1"), DstPort: 443,
		Packets: 60, SYNCount: 30, ACKCount: 30, AttemptCount: 30, Bytes: 3840, WindowEpoch: 5000, Timestamp: now,
	})
	for _, event := range balancedEvents {
		if event.RuleID == "NET.INGRESS.SYN_FLOOD" {
			t.Fatalf("balanced handshake traffic produced false SYN flood: %+v", event)
		}
	}
}

func TestKineticLowSlowScanSurvivesMinuteIdleHistory(t *testing.T) {
	eng, _ := newTestKineticEngine(t)
	now := time.Now().UTC()
	src := net.ParseIP("203.0.113.205")
	ports := []uint16{10001, 10002, 10003, 10004, 10005}

	var found bool
	for i, port := range ports {
		events := eng.IngestPacket(IngressPacket{
			Family: 4, Protocol: 6, SrcIP: src, DstIP: net.ParseIP("198.51.100.1"), DstPort: port,
			TCPFlags: 0x02, Bytes: 60, Timestamp: now.Add(time.Duration(i) * 20 * time.Second),
		})
		if i > 0 {
			eng.Sweep(now.Add(time.Duration(i)*20*time.Second - time.Second))
		}
		for _, event := range events {
			if event.RuleID == "NET.INGRESS.LOW_SLOW_SCAN" {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("expected low-and-slow scan to survive >60s source history and trigger")
	}
}

func TestKineticSubnetWindowsDoNotAccumulateForever(t *testing.T) {
	t.Run("ipv4-24", func(t *testing.T) {
		eng, _ := newTestKineticEngine(t)
		now := time.Now().UTC()
		ips := []net.IP{net.ParseIP("203.0.113.10"), net.ParseIP("203.0.113.20")}
		for i := 0; i < 44; i++ {
			eng.IngestPacket(IngressPacket{
				Family: 4, Protocol: 17, SrcIP: ips[i%2], DstIP: net.ParseIP("198.51.100.1"), DstPort: 443,
				Bytes: 64, Timestamp: now.Add(time.Duration(i) * time.Second),
			})
		}
		events := eng.IngestPacket(IngressPacket{
			Family: 4, Protocol: 17, SrcIP: ips[0], DstIP: net.ParseIP("198.51.100.1"), DstPort: 443,
			Bytes: 64, Timestamp: now.Add(5*time.Minute + time.Second),
		})
		for _, event := range events {
			if event.RuleID == "NET.INGRESS.SUBNET_V4" {
				t.Fatalf("/24 aggregation crossed a stale five-minute window: %+v", event)
			}
		}
	})

	t.Run("ipv6-64", func(t *testing.T) {
		eng, _ := newTestKineticEngine(t)
		now := time.Now().UTC()
		ips := []net.IP{net.ParseIP("2001:db8:feed:1::10"), net.ParseIP("2001:db8:feed:1::20")}
		for i := 0; i < 54; i++ {
			eng.IngestPacket(IngressPacket{
				Family: 6, Protocol: 17, SrcIP: ips[i%2], DstIP: net.ParseIP("2001:db8::1"), DstPort: 443,
				Bytes: 64, Timestamp: now.Add(time.Duration(i) * time.Second),
			})
		}
		events := eng.IngestPacket(IngressPacket{
			Family: 6, Protocol: 17, SrcIP: ips[0], DstIP: net.ParseIP("2001:db8::1"), DstPort: 443,
			Bytes: 64, Timestamp: now.Add(5*time.Minute + time.Second),
		})
		for _, event := range events {
			if event.RuleID == "NET.INGRESS.SUBNET_V6" {
				t.Fatalf("/64 aggregation crossed a stale five-minute window: %+v", event)
			}
		}
	})
}

func TestKineticHighVolumeEstablishedTCPDataDoesNotCountAsAttackAttempts(t *testing.T) {
	eng, _ := newTestKineticEngine(t)
	now := time.Now().UTC().Truncate(time.Minute)
	src := net.ParseIP("203.0.113.210")

	events := eng.IngestPacket(IngressPacket{
		Family: 4, Protocol: 6, SrcIP: src, DstIP: net.ParseIP("198.51.100.1"), DstPort: 443,
		TCPFlags: 0x10, Packets: 200, ACKCount: 200, Bytes: 256000, WindowEpoch: uint64(now.Unix()), Timestamp: now,
	})
	for _, event := range events {
		switch event.RuleID {
		case "NET.INGRESS.IP_RATE", "NET.INGRESS.IP_VELOCITY", "NET.INGRESS.SYN_FLOOD", "NET.INGRESS.SUBNET_V4":
			t.Fatalf("established TCP data/ACK traffic produced an aggressive ingress event: %+v", event)
		}
	}

	sources := eng.SourceSnapshot(10)
	if len(sources) != 1 {
		t.Fatalf("expected one tracked source, got %+v", sources)
	}
	if sources[0].Hits != 200 || sources[0].Attempts != 0 || sources[0].Attempts1m != 0 {
		t.Fatalf("raw packet visibility must remain while attack-attempt counters stay zero: %+v", sources[0])
	}
}

func TestKineticWideV4IsCampaignOnlyAndNeverDirectBlock(t *testing.T) {
	eng, _ := newTestKineticEngine(t)
	now := time.Now().UTC().Truncate(time.Minute)
	ips := []net.IP{
		net.ParseIP("203.0.1.10"),
		net.ParseIP("203.0.2.10"),
		net.ParseIP("203.0.3.10"),
		net.ParseIP("203.0.4.10"),
	}

	var wide *KineticEvent
	for i := 0; i < 80 && wide == nil; i++ {
		events := eng.IngestPacket(IngressPacket{
			Family: 4, Protocol: 17, SrcIP: ips[i%len(ips)], DstIP: net.ParseIP("198.51.100.1"), DstPort: 443,
			Bytes: 64, Timestamp: now.Add(time.Duration(i) * time.Second),
		})
		for j := range events {
			if events[j].RuleID == "NET.INGRESS.WIDE_V4" {
				copy := events[j]
				wide = &copy
				break
			}
		}
	}
	if wide == nil {
		t.Fatal("expected /16 campaign correlation after distributed activity across four /24s")
	}
	if wide.Subnet != "203.0.0.0/16" || wide.Action != "warn" {
		t.Fatalf("wide /16 correlation must remain non-destructive: %+v", *wide)
	}
	def, ok := eng.rules.Get("NET.INGRESS.WIDE_V4")
	if !ok || def.ContainEligible || def.BlockEligible {
		t.Fatalf("wide /16 rule unexpectedly permits containment/blocking: %+v", def)
	}
}

func TestKineticRuntimeDisableStopsDetection(t *testing.T) {
	eng, _ := newTestKineticEngine(t)
	cfg := defaultConfig()
	runtime := defaultRuntimeSettings(cfg).Kinetic
	runtime.Enabled = false
	eng.UpdateConfig(runtime)
	events := eng.IngestPacket(IngressPacket{
		Family: 4, Protocol: 6, TCPFlags: 0x02, AttemptCount: 100,
		SrcIP: net.ParseIP("203.0.113.211"), DstIP: net.ParseIP("198.51.100.1"), DstPort: 22,
		Packets: 100, SYNCount: 100, Bytes: 6400, Timestamp: time.Now().UTC(),
	})
	if len(events) != 0 {
		t.Fatalf("disabled Kinetic engine emitted events: %+v", events)
	}
}

func TestKineticRuntimeSYNThresholdIsHotReloaded(t *testing.T) {
	eng, _ := newTestKineticEngine(t)
	cfg := defaultConfig()
	runtime := defaultRuntimeSettings(cfg).Kinetic
	runtime.SYNThreshold = 4
	runtime.SYNAckRatio = 2
	eng.UpdateConfig(runtime)
	now := time.Now().UTC().Truncate(time.Second)
	events := eng.IngestPacket(IngressPacket{
		Family: 4, Protocol: 6, TCPFlags: 0x02, AttemptCount: 4,
		SrcIP: net.ParseIP("203.0.113.212"), DstIP: net.ParseIP("198.51.100.1"), DstPort: 443,
		Packets: 4, SYNCount: 4, ACKCount: 0, Bytes: 256, Timestamp: now,
	})
	found := false
	for _, event := range events {
		if event.RuleID == "NET.INGRESS.SYN_FLOOD" {
			found = true
		}
	}
	if !found {
		t.Fatalf("hot-reloaded SYN threshold did not trigger: %+v", events)
	}
}
