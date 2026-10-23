// STATUS: DIAMANT VGT SUPREME
package main

import (
	"strings"
	"testing"
	"time"
)

// TestCoverageVerdictIsDerivedAndCannotGoStale covers the defect found on a live host.
//
// Two components publish into the same L7Status. The inspection service recomputed the
// coverage verdict on its own events; the inline edge set InlineHealthy when a request or
// a self-test proved the path. The edge's events are not the service's, so the verdict was
// computed once at startup - against the initial InlineHealthy, which is false whenever the
// inline listener is enabled - and then never again.
//
// The host was found reporting INLINE_DEGRADED next to inline_healthy = true on the same
// screen, with a passing self-test recorded minutes earlier. The verdict was a stored copy
// of a past computation, and nothing recomputed it.
func TestCoverageVerdictIsDerivedAndCannotGoStale(t *testing.T) {
	cfg := defaultConfig()
	cfg.L7.Enabled = true
	cfg.L7.InlineEnabled = true
	state := NewState("test", cfg)

	// The state the host was in: the verdict stored while the path was still unproven.
	state.UpdateL7Status(func(status *L7Status) {
		status.Enabled = true
		status.Healthy = true
		status.InlineEnabled = true
		status.InlineHealthy = false
		status.Coverage = "INLINE_DEGRADED"
		status.CoverageReason = "inline L7 listener is degraded"
	})
	if got := state.Snapshot().L7.Coverage; got != "INLINE_DEGRADED" {
		t.Fatalf("the fixture did not establish the stale verdict: %s", got)
	}

	// The edge proves the path afterwards. Only InlineHealthy changes; nothing calls the
	// inspection service's publisher, which is exactly what happened in production.
	past := time.Now().UTC().Add(-time.Minute)
	state.UpdateL7Status(func(status *L7Status) {
		status.InlineHealthy = true
		status.SelfTestOutcome = "PASS"
		status.SelfTestAt = &past
		status.InlineRequestsTotal = 2
	})

	after := state.Snapshot().L7
	if after.Coverage == "INLINE_DEGRADED" {
		t.Fatal("the verdict still says degraded while the path is proven working")
	}
	if after.Coverage != "TRAFFIC_ACTIVE" {
		t.Fatalf("a proven path reported %q", after.Coverage)
	}
	if !after.TrafficPathVerified {
		t.Fatal("the verified-path flag did not follow the verdict")
	}
	// The reason has to follow too, or the screen explains a verdict it no longer holds.
	if strings.Contains(after.CoverageReason, "degraded") {
		t.Fatalf("the reason describes the old verdict: %q", after.CoverageReason)
	}
}

// TestDerivedVerdictStillDegradesWhenThePathIsUnproven is the counter-case. The derivation
// must not have become a way to report a healthy path regardless; a genuinely cleared flag
// with no recent measurement still degrades.
func TestDerivedVerdictStillDegradesWhenThePathIsUnproven(t *testing.T) {
	cfg := defaultConfig()
	cfg.L7.Enabled = true
	cfg.L7.InlineEnabled = true
	state := NewState("test", cfg)

	state.UpdateL7Status(func(status *L7Status) {
		status.Enabled = true
		status.Healthy = true
		status.InlineEnabled = true
		status.InlineHealthy = false
		status.Coverage = "TRAFFIC_ACTIVE" // a stale optimistic verdict
	})

	if got := state.Snapshot().L7.Coverage; got != "INLINE_DEGRADED" {
		t.Fatalf("an unproven path reported %q", got)
	}

	// A self-test that failed is not evidence either.
	failed := time.Now().UTC().Add(-time.Minute)
	state.UpdateL7Status(func(status *L7Status) {
		status.SelfTestOutcome = "FAIL"
		status.SelfTestAt = &failed
	})
	if got := state.Snapshot().L7.Coverage; got != "INLINE_DEGRADED" {
		t.Fatalf("a failed self-test cleared the degradation: %q", got)
	}
}

// TestCoverageReasonIsAPureFunctionOfTheVerdict keeps the two derivations from drifting.
func TestCoverageReasonIsAPureFunctionOfTheVerdict(t *testing.T) {
	seen := map[string]bool{}
	for _, verdict := range []string{
		"OFFLINE", "INLINE_DEGRADED", "NO_TRAFFIC_WARNING", "TLS_NOT_IN_PATH",
		"READY_NOT_ATTACHED", "HEALTHY_AWAITING_TRAFFIC", "TRAFFIC_ACTIVE", "DISABLED",
	} {
		reason := describeL7Coverage(verdict)
		if strings.TrimSpace(reason) == "" {
			t.Errorf("verdict %q has no reason", verdict)
		}
		if seen[reason] {
			t.Errorf("verdict %q reuses a reason another verdict already has: %q", verdict, reason)
		}
		seen[reason] = true
	}
}

// TestKineticSensorEntryFollowsTheL7Verdict covers the second stale copy, one level up.
//
// The L7 sensor entry is what Kinetic summarises the platform from, and it was written
// only by the inspection service”s publisher. The inline edge changes the L7 verdict
// without ever calling that publisher, so the entry kept whatever it recorded last. A
// host was found serving coverage "HEALTHY_AWAITING_TRAFFIC" from the L7 status while the
// Kinetic summary in the same response still read "inline L7 listener is degraded".
func TestKineticSensorEntryFollowsTheL7Verdict(t *testing.T) {
	cfg := defaultConfig()
	cfg.L7.Enabled = true
	cfg.L7.InlineEnabled = true
	state := NewState("test", cfg)

	// The state the host was in: an entry written while the verdict was still degraded.
	state.SetSensorCoverage(SensorCoverage{
		Name: "l7_application", Layer: LayerApplicationL7,
		Status: CoverageDegraded, Required: true, SelfTest: "failed",
		CoverageReason: "inline L7 listener is degraded",
		LastError:      "inline L7 listener is degraded",
	})
	// The kernel ingress sensor is online on the host; without it here the overall verdict
	// would be offline for an unrelated reason and the assertion would prove nothing.
	state.SetSensorCoverage(SensorCoverage{
		Name: "xdp_ingress", Layer: LayerIngressNetwork,
		Status: CoverageOnline, Required: true, SelfTest: "pass",
		CoverageReason: "verified kernel ingress producer via native XDP in the driver path",
	})
	state.UpdateL7Status(func(status *L7Status) {
		status.Enabled = true
		status.Healthy = true
		status.InlineEnabled = true
		status.InlineHealthy = false
		status.CoverageRequired = true
	})

	before := state.Snapshot()
	if before.Kinetic.Coverage.OverallStatus != CoverageDegraded {
		t.Fatalf("the fixture did not establish a degraded platform: %s", before.Kinetic.Coverage.OverallStatus)
	}

	// The edge proves the path. Only InlineHealthy and the traffic counters change, which
	// is exactly what happens on a live host.
	past := time.Now().UTC().Add(-time.Minute)
	state.UpdateL7Status(func(status *L7Status) {
		status.InlineHealthy = true
		status.SelfTestOutcome = "PASS"
		status.SelfTestAt = &past
		status.InlineRequestsTotal = 4
		status.LastInspection = &past
	})

	after := state.Snapshot()
	sensor, ok := after.Kinetic.Coverage.Sensors["l7_application"]
	if !ok {
		t.Fatal("the L7 sensor entry disappeared from the summary")
	}
	if sensor.Status == CoverageDegraded {
		t.Fatalf("Kinetic still degrades the platform on a stale L7 sentence: %s", sensor.CoverageReason)
	}
	if strings.Contains(sensor.CoverageReason, "inline L7 listener is degraded") {
		t.Fatalf("the sensor entry is still serving the old reason: %q", sensor.CoverageReason)
	}
	// The two must agree, because they are served in one response.
	if after.L7.Coverage == "INLINE_DEGRADED" {
		t.Fatalf("the L7 verdict itself did not follow: %s", after.L7.Coverage)
	}
	if after.Kinetic.Coverage.OverallStatus == CoverageDegraded {
		t.Fatalf("the platform is still degraded: %s", after.Kinetic.Coverage.Summary)
	}
}

// TestL7SensorEntryStillDegradesAnIdleRequiredPath is the counter-case. The derivation
// must not have become a way to report a healthy sensor regardless: an attached path that
// is required and silent is a real fault and has to keep saying so.
func TestL7SensorEntryStillDegradesAnIdleRequiredPath(t *testing.T) {
	cfg := defaultConfig()
	cfg.L7.Enabled = true
	cfg.L7.InlineEnabled = true
	state := NewState("test", cfg)

	state.UpdateL7Status(func(status *L7Status) {
		status.Enabled = true
		status.Healthy = true
		status.InlineEnabled = true
		status.InlineHealthy = true
		status.CoverageRequired = true
	})

	sensor := deriveL7SensorCoverage(state.Snapshot().L7, true)
	if sensor.Status != CoverageDegraded {
		t.Fatalf("an attached, required and silent path reported %q", sensor.Status)
	}
	if sensor.SelfTest != "awaiting-traffic" {
		t.Fatalf("the self-test state does not name the situation: %q", sensor.SelfTest)
	}
	if !sensor.Required {
		t.Fatal("the entry stopped being mandatory")
	}

	// An engine that is switched off is disabled, not degraded.
	state.UpdateL7Status(func(status *L7Status) { status.Enabled = false })
	if got := deriveL7SensorCoverage(state.Snapshot().L7, true); got.Status != CoverageDisabled {
		t.Fatalf("a disabled engine reported %q", got.Status)
	}

	// An unhealthy service is offline, not degraded.
	state.UpdateL7Status(func(status *L7Status) { status.Enabled = true })
	if got := deriveL7SensorCoverage(state.Snapshot().L7, false); got.Status != CoverageOffline {
		t.Fatalf("an offline service reported %q", got.Status)
	}
}

// TestTopLevelCoverageCarriesTheDerivedVerdict covers the third copy of the same verdict.
//
// Snapshot builds its top-level Coverage from the stored Kinetic summary before any
// derivation runs, and the derivation then updated only the Kinetic field. The platform
// served a corrected summary and a stale overall verdict in one response, and the
// interface reads the overall one. On a live host this showed as a sidebar reporting the
// platform degraded while the sensor list beside it said every sensor was online.
func TestTopLevelCoverageCarriesTheDerivedVerdict(t *testing.T) {
	cfg := defaultConfig()
	cfg.L7.Enabled = true
	cfg.L7.InlineEnabled = true
	state := NewState("test", cfg)

	// A stored summary that disagrees with the fields it was derived from.
	state.SetSensorCoverage(SensorCoverage{
		Name: "l7_application", Layer: LayerApplicationL7,
		Status: CoverageDegraded, Required: true, SelfTest: "failed",
		CoverageReason: "inline L7 listener is degraded",
		LastError:      "inline L7 listener is degraded",
	})
	state.SetSensorCoverage(SensorCoverage{
		Name: "xdp_ingress", Layer: LayerIngressNetwork,
		Status: CoverageOnline, Required: true, SelfTest: "pass",
		CoverageReason: "verified kernel ingress producer via native XDP in the driver path",
	})
	state.UpdateL7Status(func(status *L7Status) {
		status.Enabled = true
		status.Healthy = true
		status.InlineEnabled = true
		status.InlineHealthy = false
		status.CoverageRequired = true
	})

	if state.Snapshot().Coverage.OverallStatus != CoverageDegraded {
		t.Fatal("the fixture did not establish a degraded stored summary")
	}

	// The edge proves the path.
	past := time.Now().UTC().Add(-time.Minute)
	state.UpdateL7Status(func(status *L7Status) {
		status.InlineHealthy = true
		status.SelfTestOutcome = "PASS"
		status.SelfTestAt = &past
		status.InlineRequestsTotal = 4
		status.LastInspection = &past
	})

	snap := state.Snapshot()
	// Both names must carry the same summary, and it must be the derived one.
	if snap.Coverage.OverallStatus != snap.Kinetic.Coverage.OverallStatus {
		t.Fatalf("the two coverage fields disagree: top-level %s, kinetic %s",
			snap.Coverage.OverallStatus, snap.Kinetic.Coverage.OverallStatus)
	}
	if snap.Coverage.OverallStatus == CoverageDegraded {
		t.Fatalf("the overall verdict is still degraded: %s", snap.Coverage.Summary)
	}
	if !snap.Coverage.Nominal {
		t.Fatalf("the platform is not nominal: %s", snap.Coverage.Summary)
	}
}
