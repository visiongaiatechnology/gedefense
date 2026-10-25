package main

import "testing"

func protectionFixture() Snapshot {
	snap := Snapshot{Enforcement: "enforce", CoreConnected: true, CoreMode: "native"}
	snap.Release = ReleaseStatus{Phase: ReleasePhaseEnforce, KernelPolicyState: "verified-enforce"}
	snap.XDR = XDRStatus{Enabled: true, Mode: "enforce"}
	snap.Settings.Kinetic.Enabled = true
	snap.Settings.Kinetic.EnforcementMode = "block"
	snap.Coverage = SystemCoverage{Nominal: true, OverallStatus: CoverageOnline}
	snap.L7 = L7Status{Enabled: true, Mode: "block"}
	snap.Evidence = EvidenceStatus{Enabled: true, Healthy: true, VerifyScope: "full"}
	return snap
}

func TestProtectionStatusRequiresEveryLayer(t *testing.T) {
	if got := deriveProtectionStatus(protectionFixture(), "enforce"); !got.Effective || got.Level != "full" {
		t.Fatalf("full fixture is not effective: %+v", got)
	}
	// The reported regression: release enforce while the XDR layer is still observe.
	snap := protectionFixture()
	snap.XDR.Mode = "observe"
	got := deriveProtectionStatus(snap, "observe")
	if got.Effective || got.Level == "full" {
		t.Fatalf("observe XDR was reported as full protection: %+v", got)
	}
	found := false
	for _, gap := range got.Gaps {
		if gap == "xdr_observe" {
			found = true
		}
	}
	if !found {
		t.Fatalf("xdr_observe gap missing: %+v", got.Gaps)
	}
	// Core disconnected must also invalidate the claim.
	snap = protectionFixture()
	snap.CoreConnected = false
	if got := deriveProtectionStatus(snap, "enforce"); got.Effective {
		t.Fatalf("disconnected core was reported as full protection: %+v", got)
	}
}
