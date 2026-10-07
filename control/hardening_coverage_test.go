// STATUS: DIAMANT VGT SUPREME
package main

import (
	"strings"
	"testing"
	"time"
)

// TestHardeningPostureCapsItselfWhenEvidenceIsThin covers the over-claim the audit found.
//
// An unmeasurable check is excluded from both the numerator and the denominator of the
// score, which is the right treatment - a host should not be penalised for a control it
// will not let us read. The consequence was unnoticed: a host where almost nothing is
// readable computes its score from the handful of checks that are, and two passing
// checks produced a score of 100 and the level HARDENED. The level is a claim about the
// host, so it needs enough of the host to be observable to support it.
func TestHardeningPostureCapsItselfWhenEvidenceIsThin(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	thresholds := defaultHardeningThresholds()

	// Two measurable, both protected, everything else unreadable.
	thin := []HardeningCheck{
		{ID: "kernel.aslr", Domain: "kernel", Weight: 10, State: hardeningStateProtected},
		{ID: "kernel.kptr", Domain: "kernel", Weight: 8, State: hardeningStateProtected},
	}
	for index := 0; index < 20; index++ {
		thin = append(thin, HardeningCheck{
			ID: "unreadable." + string(rune('a'+index)), Domain: "kernel",
			Weight: 10, State: hardeningStateUnavailable,
		})
	}
	posture := summarizeHardening(now, thin, thresholds)

	if posture.Score != 100 {
		t.Fatalf("the score should still describe the checks that could be read: %d", posture.Score)
	}
	if posture.Level == "HARDENED" || posture.Level == "STRONG" {
		t.Fatalf("a posture measured from 2 of 22 controls claimed %q", posture.Level)
	}
	if posture.CoverageSufficient {
		t.Fatal("thin evidence was reported as sufficient")
	}
	if posture.CoverageNote == "" {
		t.Fatal("a capped level must state why it was capped")
	}
	if posture.MeasuredChecks != 2 || posture.UnavailableChecks != 20 || posture.TotalChecks != 22 {
		t.Fatalf("coverage counts are wrong: measured=%d unavailable=%d total=%d",
			posture.MeasuredChecks, posture.UnavailableChecks, posture.TotalChecks)
	}

	// The counter-case: with the catalogue mostly measurable, a strong result stands.
	full := make([]HardeningCheck, 0, 22)
	weight := 0
	for index := 0; index < 22; index++ {
		full = append(full, HardeningCheck{
			ID: "check." + string(rune('a'+index)), Domain: "kernel",
			Weight: 4, State: hardeningStateProtected,
		})
		weight += 4
	}
	strong := summarizeHardening(now, full, thresholds)
	if !strong.CoverageSufficient {
		t.Fatal("a fully measurable catalogue was reported as insufficient evidence")
	}
	if strong.Level != "HARDENED" {
		t.Fatalf("a fully protected, fully measurable host reported %q", strong.Level)
	}
	if strong.Score != 100 {
		t.Fatalf("a fully protected host scored %d", strong.Score)
	}
	if weight < hardeningMinimumEvidenceWeight {
		t.Logf("note: the full catalogue weighs %d, below the evidence floor of %d", weight, hardeningMinimumEvidenceWeight)
	}

	// A host with nothing measurable at all must not be presented as hardened.
	blind := make([]HardeningCheck, 0, 8)
	for index := 0; index < 8; index++ {
		blind = append(blind, HardeningCheck{
			ID: "blind." + string(rune('a'+index)), Domain: "kernel",
			Weight: 10, State: hardeningStateUnavailable,
		})
	}
	unknown := summarizeHardening(now, blind, thresholds)
	if unknown.Level == "HARDENED" || unknown.Score > 0 {
		t.Fatalf("a host with no measurable control reported level=%q score=%d", unknown.Level, unknown.Score)
	}
	if unknown.CoverageSufficient {
		t.Fatal("no measurable control was reported as sufficient evidence")
	}
}

// TestHardeningCollectorReadsLiveSysctlValues proves the suite reports measured kernel
// state rather than a static expectation. The collector resolves its paths against the
// real root, so on Linux these reads succeed and the evidence string carries the value
// that is actually in force.
func TestHardeningCollectorReadsLiveSysctlValues(t *testing.T) {
	collector := NewHardeningCollector()
	value, err := collector.regularText("proc/sys/kernel/randomize_va_space", 64)
	if err != nil {
		t.Skipf("procfs is not readable in this environment: %v", err)
	}
	if strings.TrimSpace(value) == "" {
		t.Fatal("the ASLR control read an empty value")
	}
	// The value must be the kernel's, not a default the collector assumed.
	if value != "0" && value != "1" && value != "2" {
		t.Fatalf("randomize_va_space reported %q, which is not a kernel value", value)
	}

	// And the check built from it must carry that value as its evidence, so an operator
	// can see what was measured rather than only whether it passed.
	check := collector.integerCheck("kernel.aslr", "kernel", "Address Space Layout Randomization",
		"proc/sys/kernel/randomize_va_space", 2, 10, true, "Set kernel.randomize_va_space=2")
	if check.State == hardeningStateUnavailable {
		t.Fatalf("the ASLR check reported unavailable although the value was readable: %+v", check)
	}
	if !strings.Contains(check.Evidence, "live value") {
		t.Fatalf("the check does not publish the value it measured: %q", check.Evidence)
	}
}

// TestHardeningSwitchesAreAllSelectable pins the interaction contract for the control
// list. The preflight button verifies a selection; it does not apply one. Disabling the
// controls that were already PROTECTED made ten switches inert on a hardened host for
// no security reason, which is what the operator saw.
func TestHardeningSwitchesAreAllSelectable(t *testing.T) {
	source := embeddedWebFile(t, "app.js")

	start := strings.Index(source, "function renderHardeningSwitches(checks)")
	if start < 0 {
		t.Fatal("the hardening switch renderer is gone")
	}
	end := strings.Index(source[start:], "\n}")
	if end < 0 {
		t.Fatal("the hardening switch renderer is unterminated")
	}
	body := source[start : start+end]

	// Every administrable control must render a control element. A disabled attribute
	// driven by the measured state is what made them inert.
	if strings.Contains(body, "input.disabled") {
		t.Fatal("the hardening switch is disabled by its measured state again")
	}
	// The control must be reachable: either the wrapper is a label or the input carries
	// an explicit wiring. The primitive used here is a label.
	if !strings.Contains(body, "document.createElement('label')") {
		t.Fatal("the hardening switch is no longer wrapped in a label, so a click on the visible track does nothing")
	}
	// The primitive the Fabric Settings workbench uses, so both surfaces share one
	// interaction and one appearance.
	for _, required := range []string{"settings-switch", "settings-switch-track", "settings-switch-state"} {
		if !strings.Contains(body, required) {
			t.Fatalf("the hardening switch no longer uses the shared primitive: %s missing", required)
		}
	}
	// A control that cannot be administrated at runtime must state that in words.
	if !strings.Contains(body, "hardening.notRuntimeAdministrable") {
		t.Fatal("a non-administrable control no longer explains why it has no switch")
	}
}
