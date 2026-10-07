package main

import "testing"

func TestParseCoreIngressHealth(t *testing.T) {
	got, err := parseCoreIngressHealth("42:3:7")
	if err != nil {
		t.Fatal(err)
	}
	if got.EventsEmitted != 42 || got.RingDrops != 3 || got.TrackInsertFailures != 7 {
		t.Fatalf("unexpected health counters: %+v", got)
	}
	for _, invalid := range []string{"", "1:2", "1:2:3:4", "x:2:3", "1:-1:3"} {
		if _, err := parseCoreIngressHealth(invalid); err == nil {
			t.Fatalf("expected invalid health payload %q to fail", invalid)
		}
	}
}

func TestEvaluateKineticSensorHealthRequiresVerifiedHealth(t *testing.T) {
	status, selfTest, _ := evaluateKineticSensorHealth(0, 0, nil, nil)
	if status != CoverageOffline || selfTest != "unverified" {
		t.Fatalf("empty event polls must not prove producer health: status=%s self_test=%s", status, selfTest)
	}

	zero := &CoreIngressHealth{}
	status, selfTest, _ = evaluateKineticSensorHealth(0, 0, nil, zero)
	if status != CoverageOnline || selfTest != "pass" {
		t.Fatalf("readable kernel health maps should verify an idle producer: status=%s self_test=%s", status, selfTest)
	}
}

func TestEvaluateKineticSensorHealthDetectsPressureAndFailures(t *testing.T) {
	previous := &CoreIngressHealth{EventsEmitted: 100, RingDrops: 2, TrackInsertFailures: 1}
	current := &CoreIngressHealth{EventsEmitted: 140, RingDrops: 3, TrackInsertFailures: 1}
	status, selfTest, _ := evaluateKineticSensorHealth(0, 0, previous, current)
	if status != CoverageDegraded || selfTest != "degraded" {
		t.Fatalf("new ring pressure must degrade sensor: status=%s self_test=%s", status, selfTest)
	}

	status, selfTest, _ = evaluateKineticSensorHealth(1, 0, current, current)
	if status != CoverageDegraded || selfTest != "degraded" {
		t.Fatalf("transient event drain failure must degrade sensor: status=%s self_test=%s", status, selfTest)
	}

	status, selfTest, _ = evaluateKineticSensorHealth(kineticOfflineAfterFails, 0, current, current)
	if status != CoverageOffline || selfTest != "failed" {
		t.Fatalf("repeated event drain failures must take sensor offline: status=%s self_test=%s", status, selfTest)
	}
}
