package main

import (
	"strings"
	"testing"
	"time"
)

// TestTheCoverageSummaryNamesAreDeterministic covers the contract the function states.
//
// EvaluateCoverage says it determines the status deterministically, but it joined the
// sensor names in map iteration order, so the same state produced a differently ordered
// sentence on every refresh. The names are now sorted before they are joined.
func TestTheCoverageSummaryNamesAreDeterministic(t *testing.T) {
	sensors := map[string]SensorCoverage{
		"zulu_sensor":  {Name: "zulu_sensor", Status: CoverageDegraded, Required: true},
		"alpha_sensor": {Name: "alpha_sensor", Status: CoverageDegraded, Required: true},
		"mid_sensor":   {Name: "mid_sensor", Status: CoverageDegraded, Required: true},
		// A sensor that is not mandatory must not be named at all.
		"optional_sensor": {Name: "optional_sensor", Status: CoverageDegraded, Required: false},
	}
	want := "Mandatory sensors degraded: alpha_sensor, mid_sensor, zulu_sensor"
	first := EvaluateCoverage(sensors)
	if first.Summary != want {
		t.Fatalf("summary=%q, want %q", first.Summary, want)
	}
	if first.OverallStatus != CoverageDegraded || first.Nominal {
		t.Fatalf("status=%s nominal=%v", first.OverallStatus, first.Nominal)
	}
	for i := 0; i < 50; i++ {
		if got := EvaluateCoverage(sensors).Summary; got != want {
			t.Fatalf("the summary changed between runs: %q then %q", want, got)
		}
	}
}

// TestAnOfflineSensorOutranksADegradedOne keeps the precedence the two panels rely on.
func TestAnOfflineSensorOutranksADegradedOne(t *testing.T) {
	got := EvaluateCoverage(map[string]SensorCoverage{
		"degraded_one": {Name: "degraded_one", Status: CoverageDegraded, Required: true},
		"offline_one":  {Name: "offline_one", Status: CoverageOffline, Required: true},
	})
	if got.OverallStatus != CoverageOffline {
		t.Fatalf("an offline mandatory sensor did not outrank a degraded one: %s", got.OverallStatus)
	}
	if !strings.Contains(got.Summary, "offline_one") {
		t.Fatalf("the summary does not name the offline sensor: %q", got.Summary)
	}
}

// TestARequiredPathWithoutVerifiedTrafficStaysAGap pins a decision that looks like a false
// alarm and is not one.
//
// The Kinetic page announced "Mandatory sensors degraded: l7_application" while the
// Application Defense page described the same path as healthy and attached. The tempting
// reading is that the sensor verdict is wrong. It is not: an operator who declares L7
// mandatory has declared that no verified request through the path is a gap, and the release
// gate refuses the promotion from Canary to Enforce on exactly that condition
// (release_test.go derives the same state and proves it is a gap).
//
// The traffic counters live in memory, so a restart resets them and the gap reappears until
// one request has been verified. Softening that was tried and reverted, because it removed
// the gate. What was actually wrong is covered by the two tests below: the sentence shown
// beside the verdict belonged to a different sensor, and the inspected-request count
// ignored the inline listener that had served every one of them.
func TestARequiredPathWithoutVerifiedTrafficStaysAGap(t *testing.T) {
	status := L7Status{
		Enabled: true, Healthy: true, InlineEnabled: true, InlineHealthy: true,
		CoverageRequired: true,
		Coverage:         "HEALTHY_AWAITING_TRAFFIC",
		CoverageReason:   describeL7Coverage("HEALTHY_AWAITING_TRAFFIC"),
	}

	gap := deriveL7SensorCoverage(status, true)
	if gap.Status != CoverageDegraded || !gap.Required {
		t.Fatalf("a mandatory path with no verified traffic reported %s required=%v; the release gate depends on this being a gap",
			gap.Status, gap.Required)
	}
	if gap.CoverageReason == "" {
		t.Fatal("the gap has no reason to show the operator")
	}
	if summary := EvaluateCoverage(map[string]SensorCoverage{"l7_application": gap}); summary.Nominal {
		t.Fatal("a mandatory L7 gap did not make the platform non-nominal")
	}

	// One verified request through the path closes it, which is what the operator sees on a
	// working installation.
	status.Coverage = "TRAFFIC_ACTIVE"
	status.CoverageReason = describeL7Coverage("TRAFFIC_ACTIVE")
	if cov := deriveL7SensorCoverage(status, true); cov.Status != CoverageOnline {
		t.Fatalf("a verified path reported %s", cov.Status)
	}
}

// TestADegradedInlineListenerNamesWhatItReported closes the last way this panel could
// withhold the truth.
//
// "inline L7 listener is degraded" is a verdict, not an explanation. The service also
// records what it reported, and that text survives only for the lifetime of the process,
// so an operator who went looking after the fact found a degradation and no cause. The
// sentence now carries the report when there is one and stays the verdict alone when there
// is not; the verdict itself, which the release gate reads, is not touched.
func TestADegradedInlineListenerNamesWhatItReported(t *testing.T) {
	verdict := describeL7Coverage("INLINE_DEGRADED")
	status := L7Status{
		Enabled: true, Healthy: true, InlineEnabled: true, InlineHealthy: false,
		CoverageRequired: true,
		Coverage:         "INLINE_DEGRADED",
		CoverageReason:   verdict,
		InlineLastError:  "l7 inline accept: too many open files",
	}

	reported := deriveL7SensorCoverage(status, true)
	if reported.Status != CoverageDegraded || !reported.Required {
		t.Fatalf("status=%s required=%v", reported.Status, reported.Required)
	}
	if !strings.Contains(reported.CoverageReason, verdict) {
		t.Fatalf("the verdict sentence was replaced instead of augmented: %q", reported.CoverageReason)
	}
	if !strings.Contains(reported.CoverageReason, "too many open files") {
		t.Fatalf("the listener's own report is withheld: %q", reported.CoverageReason)
	}

	// With nothing recorded, nothing is invented.
	status.InlineLastError = ""
	quiet := deriveL7SensorCoverage(status, true)
	if quiet.CoverageReason != verdict {
		t.Fatalf("an absent report changed the sentence: %q", quiet.CoverageReason)
	}
	if quiet.Status != reported.Status {
		t.Fatalf("the addition changed the verdict: %s then %s", reported.Status, quiet.Status)
	}
	if summary := EvaluateCoverage(map[string]SensorCoverage{"l7_application": quiet}); summary.Nominal {
		t.Fatal("a degraded inline listener stopped degrading the platform")
	}
}

// TestTheKineticLiveCoverageIsDerivedNotStored is the contradiction an operator reported
// three times: one screen said the platform was nominal and another said a mandatory sensor
// was degraded, in the same second, from the same process.
//
// /api/v1/status re-derived the coverage. /api/v1/kinetic/live - the endpoint the Kinetic
// page actually reads - served the stored copy, which records whichever component wrote into
// it last. Both now take it from one derivation.
func TestTheKineticLiveCoverageIsDerivedNotStored(t *testing.T) {
	cfg := defaultConfig()
	cfg.L7.Enabled = true
	cfg.L7.InlineEnabled = true
	state := NewState("test", cfg)

	// What the publisher stored while the inline path had not yet been verified. The live
	// accessor used to answer with exactly this, however old it was.
	stale := EvaluateCoverage(map[string]SensorCoverage{
		"l7_application": {Name: "l7_application", Layer: LayerApplicationL7, Status: CoverageDegraded,
			Required: true, CoverageReason: describeL7Coverage("INLINE_DEGRADED")},
		"xdp_ingress": {Name: "xdp_ingress", Layer: LayerIngressNetwork, Status: CoverageOnline, Required: true},
	})
	if stale.Nominal {
		t.Fatal("the fixture did not store a degraded verdict")
	}
	state.UpdateKineticTelemetry(func(telemetry *KineticTelemetry) { telemetry.Coverage = stale })

	// The ingress sensor is online on the host. Without it the overall verdict would be
	// offline for an unrelated reason and the assertion below would prove nothing.
	state.SetSensorCoverage(SensorCoverage{Name: "xdp_ingress", Layer: LayerIngressNetwork,
		Status: CoverageOnline, Required: true, SelfTest: "pass",
		CoverageReason: "verified kernel ingress producer via native XDP in the driver path"})

	// The published fields say the path is verified end to end.
	verified := time.Now().UTC()
	state.UpdateL7Status(func(status *L7Status) {
		status.Enabled = true
		status.Healthy = true
		status.InlineEnabled = true
		status.InlineHealthy = true
		status.InlineRequestsTotal = 174
		status.LastInspection = &verified
		status.CoverageRequired = true
	})

	live := state.KineticTelemetry().Coverage
	if live.OverallStatus != CoverageOnline || !live.Nominal {
		t.Fatalf("the live telemetry served the stored verdict: %s / %s", live.OverallStatus, live.Summary)
	}
	snapshot := state.Snapshot().Kinetic.Coverage
	if live.Summary != snapshot.Summary {
		t.Fatalf("the two endpoints disagree: %q against %q", live.Summary, snapshot.Summary)
	}
	if entry := live.Sensors["l7_application"]; entry.Status != CoverageOnline {
		t.Fatalf("the L7 entry is still the stored one: %s", entry.CoverageReason)
	}
}

// TestTheKineticCoverageReasonBelongsToTheNamedSensor covers the contradiction an operator
// saw: the Kinetic page announced "Mandatory sensors degraded: l7_application" and then
// explained it with the healthy ingress producer's sentence.
//
// The reason line was bound to one sensor name, so the panel named whichever sensor was not
// nominal and described a different one. It has to be derived from the sensor the summary
// named, and the fallback has to be a translated key rather than a German literal.
func TestTheKineticCoverageReasonBelongsToTheNamedSensor(t *testing.T) {
	asset, err := webAssets.ReadFile("web/kinetic.js")
	if err != nil {
		t.Fatal(err)
	}
	source := string(asset)

	if strings.Contains(source, "sensors?.xdp_ingress") || strings.Contains(source, `sensors?.['xdp_ingress']`) {
		t.Fatal("kinetic.js still explains the coverage summary with one fixed sensor")
	}
	if !strings.Contains(source, "function coverageReason(") {
		t.Fatal("kinetic.js no longer derives the reason from the sensor that is not nominal")
	}
	for _, want := range []string{"sensor.coverage_reason", "sensor.last_error", "kinetic.coverage.noReason", "required === true"} {
		if !strings.Contains(source, want) {
			t.Fatalf("the coverage reason no longer honours %q", want)
		}
	}
}

// TestTheInspectedRequestCountIncludesTheInlineListener covers the second contradiction:
// the Application Defense panel reported "0 geprüfte Requests" directly beneath its own
// "TRAFFIC AKTIV" badge, because it displayed one of the two counters the verdict is
// computed from while the inline listener had served 174 requests.
func TestTheInspectedRequestCountIncludesTheInlineListener(t *testing.T) {
	asset, err := webAssets.ReadFile("web/l7.js")
	if err != nil {
		t.Fatal(err)
	}
	source := string(asset)
	if !strings.Contains(source, "Number(l7.requests_total || 0) + Number(l7.inline_requests_total || 0)") {
		t.Fatal("the inspected-request count still ignores one of the two counters the coverage verdict uses")
	}
	if strings.Count(source, "inspected.toLocaleString(locale())") < 2 {
		t.Fatal("the inline counter reaches the panel but not every place that shows inspected requests")
	}
}
