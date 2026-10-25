package main

import "testing"

// F-HOTFIX-5 regression: the release controller owns the XDR mode. The XDR
// engine's periodic sensor-status refresh must never downgrade an enforced
// release back to observe in the operator-visible state.
func TestReleaseXDRModeSurvivesSensorStatusRefresh(t *testing.T) {
	cfg := Config{}
	cfg.XDR.QueueCapacity = 16
	state := NewState("hotfix", cfg)

	state.SetModes("enforce", "enforce")
	state.SetXDRStatus(XDRStatus{
		Enabled: true, Mode: "observe", Sensor: "fanotify-exec+procfs-fallback",
		QueueCapacity: cfg.XDR.QueueCapacity,
	})

	if _, mode := state.Modes(); mode != "enforce" {
		t.Fatalf("sensor refresh downgraded the release mode: %q", mode)
	}
	if snap := state.Snapshot(); snap.XDR.Mode != "enforce" {
		t.Fatalf("operator snapshot reports %q instead of enforce", snap.XDR.Mode)
	}

	// A deliberate release fail-safe still lowers automatic response.
	state.SetModes("enforce", "observe")
	if _, mode := state.Modes(); mode != "observe" {
		t.Fatalf("release-controlled downgrade was not honoured: %q", mode)
	}
}
