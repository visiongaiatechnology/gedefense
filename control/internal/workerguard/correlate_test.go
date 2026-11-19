package workerguard

import (
	"testing"
	"time"
)

func testEvent(at time.Time, comm string, uid uint32, signal int) CrashEvent {
	return CrashEvent{At: at, PID: 42, Comm: comm, UID: uid, Signal: signal, ExitCode: 139, Source: SourceNetlink}
}

// TestCorrelatorStormThreshold covers the exact threshold boundary: below the
// threshold only audit events are produced, at the threshold one critical storm.
func TestCorrelatorStormThreshold(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC)
	correlator := NewCorrelator(Config{Threshold: 3, WindowSeconds: 60, Now: func() time.Time { return now }})
	for index := 1; index <= 2; index++ {
		outcome := correlator.Observe(testEvent(now.Add(time.Duration(index)*time.Second), "php-fpm", 33, SignalSEGV))
		if !outcome.Audit {
			t.Fatalf("crash %d produced no audit event", index)
		}
		if outcome.Storm != nil {
			t.Fatalf("crash %d below the threshold produced a storm", index)
		}
	}
	outcome := correlator.Observe(testEvent(now.Add(3*time.Second), "php-fpm", 33, SignalSEGV))
	if outcome.Storm == nil {
		t.Fatal("the third crash in the window did not produce a storm")
	}
	if outcome.Storm.Severity != "critical" || outcome.Storm.Crashes != 3 {
		t.Fatalf("storm = %+v", outcome.Storm)
	}
	if outcome.Severity != "critical" {
		t.Fatalf("storm severity = %q", outcome.Severity)
	}
	if counters := correlator.CounterSnapshot(); counters.Events != 3 || counters.Storms != 1 {
		t.Fatalf("counters = %+v", counters)
	}
}

// TestCorrelatorWindowExpiry proves the window is rolling: three crashes spread
// wider than the window never form a storm.
func TestCorrelatorWindowExpiry(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC)
	correlator := NewCorrelator(Config{Threshold: 3, WindowSeconds: 60, Now: func() time.Time { return now }})
	correlator.Observe(testEvent(now, "nginx", 33, SignalSEGV))
	correlator.Observe(testEvent(now.Add(31*time.Second), "nginx", 33, SignalSEGV))
	correlator.Observe(testEvent(now.Add(62*time.Second), "nginx", 33, SignalSEGV))
	if storms := correlator.RecentStorms(10); len(storms) != 0 {
		t.Fatalf("crashes spread beyond the window formed a storm: %+v", storms)
	}
}

// TestCorrelatorDedupesStormWithinWindow proves one storm opens exactly one
// critical incident inside the window, while the crashes keep auditing.
func TestCorrelatorDedupesStormWithinWindow(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC)
	correlator := NewCorrelator(Config{Threshold: 3, WindowSeconds: 60, Now: func() time.Time { return now }})
	for index := 0; index < 6; index++ {
		outcome := correlator.Observe(testEvent(now.Add(time.Duration(index)*time.Second), "nginx", 33, SignalSEGV))
		wantStorm := index == 2
		if (outcome.Storm != nil) != wantStorm {
			t.Fatalf("crash %d storm=%t, want %t", index, outcome.Storm != nil, wantStorm)
		}
		if !outcome.Audit {
			t.Fatalf("crash %d lost its audit event", index)
		}
	}
}

// TestCorrelatorIsolatesCommsAndUIDs locks the comm+uid key: two different
// workers cannot be merged into one storm.
func TestCorrelatorIsolatesCommsAndUIDs(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC)
	correlator := NewCorrelator(Config{Threshold: 3, WindowSeconds: 60, Now: func() time.Time { return now }})
	correlator.Observe(testEvent(now, "nginx", 33, SignalSEGV))
	correlator.Observe(testEvent(now, "nginx", 34, SignalSEGV))
	correlator.Observe(testEvent(now, "php-fpm", 33, SignalSEGV))
	if storms := correlator.RecentStorms(10); len(storms) != 0 {
		t.Fatalf("crashes of different comm/uid keys formed a storm: %+v", storms)
	}
}

// TestFatalSignalFilter proves clean exits and panel reload signals never enter
// the correlation window.
func TestFatalSignalFilter(t *testing.T) {
	t.Parallel()
	cases := []struct {
		signal int
		want   bool
	}{
		{SignalSEGV, true}, {SignalBUS, true}, {SignalILL, true}, {SignalABRT, true}, {SignalFPE, true},
		{15, false}, {9, false}, {0, false}, {2, false},
	}
	for _, tc := range cases {
		if got := IsFatalSignal(tc.signal); got != tc.want {
			t.Fatalf("IsFatalSignal(%d) = %t, want %t", tc.signal, got, tc.want)
		}
	}
	if signal, ok := WaitStatusSignal(139); !ok || signal != 11 {
		t.Fatalf("wait status 139 = %d/%t, want 11/true", signal, ok)
	}
	if _, ok := WaitStatusSignal(0); ok {
		t.Fatal("clean exit was classified as a signal death")
	}
	now := time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC)
	correlator := NewCorrelator(Config{Threshold: 2, WindowSeconds: 60, Now: func() time.Time { return now }})
	if outcome := correlator.Observe(testEvent(now, "nginx", 33, 15)); outcome.Audit || outcome.Storm != nil {
		t.Fatal("SIGTERM entered the worker correlation window")
	}
}

// TestControlUnitDenylist proves a strict scope can never include a master or
// control unit, including an operator-supplied exclusion.
func TestControlUnitDenylist(t *testing.T) {
	t.Parallel()
	registry := Registry{Comms: []string{"nginx", "php-fpm", "systemd"}, ExcludeUnits: []string{"master", "control", "panel-reload"}}
	cases := []struct {
		comm string
		want bool
	}{
		{"systemd", true},
		{"nginx: master", true},
		{"php-fpm: master", true},
		{"panel-reload", true},
		{"nginx", false},
		{"php-fpm", false},
	}
	for _, tc := range cases {
		if got := IsControlUnit(tc.comm, registry.ExcludeUnits); got != tc.want {
			t.Fatalf("IsControlUnit(%q) = %t, want %t", tc.comm, got, tc.want)
		}
	}
	if _, ok := ClassifyWorker(100, "systemd", 0, "/system.slice/systemd.service", 5, registry, true); ok {
		t.Fatal("a control unit was classified as a strict worker")
	}
	if _, ok := ClassifyWorker(101, "php-fpm: master", 0, "/system.slice/php.service", 6, registry, true); ok {
		t.Fatal("a php-fpm master was classified as a strict worker")
	}
	worker, ok := ClassifyWorker(102, "php-fpm", 33, "/system.slice/php.service", 7, registry, true)
	if !ok || !worker.Strict || worker.CgroupID != 7 {
		t.Fatalf("worker = %+v ok=%t", worker, ok)
	}
}

// TestCgroupPathParsing covers the unified hierarchy only.
func TestCgroupPathParsing(t *testing.T) {
	t.Parallel()
	path, err := ParseCgroupPath("0::/system.slice/nginx.service\n")
	if err != nil || path != "/system.slice/nginx.service" {
		t.Fatalf("parse = %q err=%v", path, err)
	}
	if _, err := ParseCgroupPath("12:memory:/legacy\n1:name=systemd:/legacy\n"); err == nil {
		t.Fatal("a cgroup v1-only process was accepted")
	}
	if _, err := ParseCgroupPath("0::relative\n"); err == nil {
		t.Fatal("a relative cgroup path was accepted")
	}
}

// TestCorrelatePeersOrdering locks the peer attachment used for the TLS
// correlation without letting one storm grow unbounded.
func TestCorrelatePeersOrdering(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC)
	correlator := NewCorrelator(Config{Threshold: 2, WindowSeconds: 60, CorrelatePeers: true, Now: func() time.Time { return now }})
	event := testEvent(now, "nginx", 33, SignalSEGV)
	event.Peer = "203.0.113.7"
	correlator.Observe(testEvent(now, "nginx", 33, SignalSEGV))
	outcome := correlator.Observe(event)
	if outcome.Storm == nil || len(outcome.Storm.Peers) != 1 || outcome.Storm.Peers[0] != "203.0.113.7" {
		t.Fatalf("storm peers = %+v", outcome.Storm)
	}
	for index := 0; index < 20; index++ {
		correlator.AddStormPeer("nginx", "198.51.100."+string(rune('a'+index)))
	}
	storms := correlator.RecentStorms(1)
	if len(storms) != 1 || len(storms[0].Peers) > MaxPeersPerStorm {
		t.Fatalf("peer list grew unbounded: %+v", storms)
	}
}
