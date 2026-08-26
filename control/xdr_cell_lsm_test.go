// STATUS: DIAMANT VGT SUPREME
package main

import (
	"strings"
	"testing"
	"time"
)

func TestDesiredCellLSMPoliciesAreAuthenticatedAndFailClosed(t *testing.T) {
	now := time.Now().UTC()
	cell := func(uuid string, cgroupID uint64, class, state, network string) GaiaCell {
		return GaiaCell{
			Version: 1, UUID: uuid, Label: "test", Profile: "default", Class: class,
			CgroupPath: "/sys/fs/cgroup/gaia-cells.slice/gaia-cell-" + uuid + ".service",
			CgroupID:   cgroupID, PolicyDigest: strings.Repeat("a", 64), Generation: 1,
			State: state, NetworkState: network, ObservedAt: now,
		}
	}
	status := GaiaCellsStatus{
		Enabled: true, Healthy: true, Availability: "online",
		Cells: []GaiaCell{
			cell("00000000-0000-4000-8000-000000000001", 101, "application", "running", "none"),
			cell("00000000-0000-4000-8000-000000000002", 102, "application", "running", "normal"),
			cell("00000000-0000-4000-8000-000000000003", 103, "vault", "frozen", "none"),
			cell("00000000-0000-4000-8000-000000000004", 104, "microvm", "stopped", "none"),
		},
	}
	desired, err := desiredCellLSMPolicies(status)
	if err != nil {
		t.Fatalf("derive Cell LSM policies: %v", err)
	}
	if len(desired) != 2 || desired[101] != cellLSMDenyNonUnixSocket || desired[103] != cellLSMDenyNonUnixSocket {
		t.Fatalf("unexpected desired Cell LSM policy set: %#v", desired)
	}
	status.Healthy = false
	status.Availability = "runtime_unavailable"
	if _, err := desiredCellLSMPolicies(status); err == nil {
		t.Fatal("accepted unauthenticated or unhealthy Gaia Cells inventory")
	}
}

func TestDesiredCellLSMPoliciesAllowDisabledGenericIntegration(t *testing.T) {
	desired, err := desiredCellLSMPolicies(GaiaCellsStatus{Enabled: false})
	if err != nil || len(desired) != 0 {
		t.Fatalf("disabled generic Gaia Cells integration must be neutral: %#v %v", desired, err)
	}
}
