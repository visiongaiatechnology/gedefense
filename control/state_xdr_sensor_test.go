// STATUS: DIAMANT VGT SUPREME
package main

import "testing"

// TestASettingsRefreshDoesNotClobberTheSensorLabel is the defect that produced a false
// HANDLUNGSBEDARF in the integrity view.
//
// The engine composes the sensor label from the individual sensors and publishes it through
// SetXDRStatus. The status tick then called SetXDREnabled, which overwrote the same field with a
// coarse "procfs+network-bounded" - so the precise label never reached the interface, the malware
// card derived "not verified" from it, and the integrity badge reported action required while the
// Rust core was running with on_access=fanotify-exec. Only the operator's switch may name the
// disabled state, and it must never replace a report it did not make.
func TestASettingsRefreshDoesNotClobberTheSensorLabel(t *testing.T) {
	state := NewState("test-node", defaultConfig())
	precise := "fanotify-exec+bpf-lsm-cell+ebpf-exec+cgroup-egress+procfs-fallback"
	state.SetXDRStatus(XDRStatus{Enabled: true, Mode: "enforce", Sensor: precise})

	state.SetXDREnabled(true, true)

	if got := state.xdr.Sensor; got != precise {
		t.Fatalf("the enablement switch overwrote the sensor label: %q", got)
	}
	if !state.xdr.Enabled {
		t.Fatal("the enablement switch did not publish the enabled state")
	}
}

// TestADisabledSwitchNamesItsOwnState keeps the one statement only this function can make.
func TestADisabledSwitchNamesItsOwnState(t *testing.T) {
	state := NewState("test-node", defaultConfig())
	state.SetXDRStatus(XDRStatus{Enabled: true, Mode: "enforce", Sensor: "fanotify-exec+ebpf-exec+procfs-fallback"})

	state.SetXDREnabled(false, true)

	if got := state.xdr.Sensor; got != "disabled-by-operator" {
		t.Fatalf("a disabled platform must say so: %q", got)
	}
}

// TestTheFallbackLabelIsSetOnlyWhenNothingPreciseWasReported covers the first tick after startup:
// the field still says "initializing", and the coarse label is the honest placeholder until the
// engine reports the sensors it actually has.
func TestTheFallbackLabelIsSetOnlyWhenNothingPreciseWasReported(t *testing.T) {
	networked := NewState("test-node", defaultConfig())
	networked.SetXDREnabled(true, true)
	if got := networked.xdr.Sensor; got != "procfs+network-bounded" {
		t.Fatalf("the networked fallback label was not set: %q", got)
	}

	bounded := NewState("test-node", defaultConfig())
	bounded.SetXDREnabled(true, false)
	if got := bounded.xdr.Sensor; got != "procfs-bounded" {
		t.Fatalf("the bounded fallback label was not set: %q", got)
	}
}
