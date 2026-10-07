package main

import (
	"strings"
	"testing"
)

// TestParseCoreIngressHealth pins the wire format of the kernel health response.
//
// The response carried exactly three counters until the enforcement mode was added as a
// fourth field. Both widths are accepted, because a control plane and a core are upgraded
// independently and a version mismatch must not read as a broken kernel. The earlier
// expectation that "1:2:3:4" fails was correct for the old contract and is wrong for the
// new one, so it is replaced rather than deleted: the case now proves that the extra
// field is understood.
func TestParseCoreIngressHealth(t *testing.T) {
	got, err := parseCoreIngressHealth("42:3:7")
	if err != nil {
		t.Fatal(err)
	}
	if got.EventsEmitted != 42 || got.RingDrops != 3 || got.TrackInsertFailures != 7 {
		t.Fatalf("unexpected health counters: %+v", got)
	}
	// A three-field response comes from a core older than the mode. It must parse, and
	// the mode must read as unknown rather than being invented.
	if got.Mode != "" {
		t.Fatalf("a core that reported no mode produced %q", got.Mode)
	}

	// The current format: four fields, the last naming the hook.
	withMode, err := parseCoreIngressHealth("42:3:7:native")
	if err != nil {
		t.Fatalf("the four-field response was rejected: %v", err)
	}
	if withMode.Mode != "NATIVE_XDP" {
		t.Fatalf("native XDP parsed as %q", withMode.Mode)
	}
	if withMode.EventsEmitted != 42 || withMode.RingDrops != 3 || withMode.TrackInsertFailures != 7 {
		t.Fatalf("the counters were lost when the mode was present: %+v", withMode)
	}

	// Every mode the core can report maps onto the interface vocabulary.
	for raw, want := range map[string]string{
		"native":     "NATIVE_XDP",
		"generic":    "GENERIC_XDP",
		"tc-ingress": "TC_INGRESS",
		"tc":         "TC_INGRESS",
		"NATIVE":     "NATIVE_XDP",
	} {
		parsed, err := parseCoreIngressHealth("1:0:0:" + raw)
		if err != nil {
			t.Fatalf("mode %q was rejected: %v", raw, err)
		}
		if parsed.Mode != want {
			t.Errorf("mode %q parsed as %q, want %q", raw, parsed.Mode, want)
		}
	}

	// A mode this build does not know is preserved rather than dropped: an operator
	// should see what the core said, not "unknown".
	future, err := parseCoreIngressHealth("1:0:0:af-xdp")
	if err != nil {
		t.Fatalf("an unrecognised mode was rejected outright: %v", err)
	}
	if future.Mode != "AF-XDP" {
		t.Fatalf("an unrecognised mode was rewritten to %q", future.Mode)
	}

	// Genuinely malformed payloads still fail.
	for _, invalid := range []string{"", "1:2", "1:2:3:4:5", "x:2:3", "1:-1:3"} {
		if _, err := parseCoreIngressHealth(invalid); err == nil {
			t.Fatalf("expected invalid health payload %q to fail", invalid)
		}
	}
}

// TestKineticCoverageReasonNamesTheEnforcementHook is the point of the whole change.
//
// "verified kernel ingress producer" was reported identically whether the kernel was
// dropping in the driver path, in the generic path, or only at the traffic-control layer.
// Those are not the same statement about a host and they do not perform the same under
// load, so the reason has to name which one is live.
func TestKineticCoverageReasonNamesTheEnforcementHook(t *testing.T) {
	for mode, want := range map[string]string{
		"NATIVE_XDP":  "native XDP",
		"GENERIC_XDP": "generic XDP",
		"TC_INGRESS":  "TC ingress",
		"":            "unreported",
	} {
		current := &CoreIngressHealth{EventsEmitted: 10, Mode: mode}
		status, selfTest, reason := evaluateKineticSensorHealth(0, 0, nil, current)
		if status != CoverageOnline || selfTest != "pass" {
			t.Fatalf("mode %q did not verify an active producer: %s/%s", mode, status, selfTest)
		}
		if !strings.Contains(reason, want) {
			t.Errorf("mode %q produced reason %q, which does not name %q", mode, reason, want)
		}
	}

	// An unreported hook must not be described as if it were native. Saying nothing about
	// the mode is honest; assuming the best one is not.
	current := &CoreIngressHealth{EventsEmitted: 10, Mode: ""}
	_, _, reason := evaluateKineticSensorHealth(0, 0, nil, current)
	if strings.Contains(reason, "native") {
		t.Fatalf("an unreported hook was described as native: %q", reason)
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
