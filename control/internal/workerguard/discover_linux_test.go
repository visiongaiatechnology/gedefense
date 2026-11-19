//go:build linux

package workerguard

import "testing"

// TestScanProcessesLiveWalkIsBoundedAndHonest runs the two-pass /proc walk on
// the live host with a registry that cannot match the test binary. It proves the
// walk is bounded, never panics and keeps its result fields initialized; the
// master-cgroup exclusion decision itself is covered by
// TestSharedMasterCgroupIsExcluded without needing a real systemd service.
func TestScanProcessesLiveWalkIsBoundedAndHonest(t *testing.T) {
	t.Parallel()
	result, reason := ScanProcesses(Registry{Comms: []string{"gedefense-no-such-worker"}}, true, 64)
	if reason != "" {
		t.Fatalf("live /proc walk failed: %s", reason)
	}
	if result.Workers == nil || result.Skipped == nil {
		t.Fatalf("scan result fields are not initialized: %+v", result)
	}
	if len(result.Workers) != 0 {
		t.Fatalf("scan invented workers for an unmatched registry: %+v", result.Workers)
	}
	for _, skip := range result.Skipped {
		if skip.Reason == "" || skip.CgroupID == 0 {
			t.Fatalf("skip record is incomplete: %+v", skip)
		}
	}
}
