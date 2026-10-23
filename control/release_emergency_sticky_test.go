// STATUS: DIAMANT VGT SUPREME
// SPDX-FileCopyrightText: 2026 VisionGaia Technology
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestAnUnreadableEmergencyMarkerCountsAsAnActiveStop closes a fail-open path that the audit found:
// refreshLocked used to treat *any* os.Stat error as "no emergency stop". An unreadable marker - a
// changed permission, an I/O error, a broken mount - therefore cleared an operator's emergency stop
// instead of holding it. The only error that may clear it is a missing file.
//
// A path containing a NUL byte makes os.Stat fail with EINVAL deterministically, which is exactly the
// class of error the guard has to survive - and it needs no root, no permissions and no damaged
// filesystem to reproduce.
// A *file* used as a directory makes os.Stat fail with ENOTDIR - a deterministic error that is
// explicitly not "does not exist". That distinction is the whole point: ENOENT may clear the stop,
// every other error may not. The test asserts the error class first, so it can never pass for the
// wrong reason.
func TestAnUnreadableEmergencyMarkerCountsAsAnActiveStop(t *testing.T) {
	blocker := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(blocker, "EMERGENCY_STOP")
	_, statErr := os.Stat(marker)
	if statErr == nil {
		t.Fatal("the fixture path must not exist")
	}
	if os.IsNotExist(statErr) {
		t.Fatalf("the chosen error class is ENOENT, which legitimately clears the stop: %v", statErr)
	}

	cfg, state, policy, _ := betaReleaseFixture(t)
	cfg.Release.EmergencyStopFile = marker
	release := NewReleaseController(cfg, state, &releaseCoreStub{}, policy, nil)

	status := release.Status()
	if !status.EmergencyStop {
		t.Fatal("an emergency marker that cannot be read was treated as absent; the stop would be silently cleared")
	}
	if !strings.Contains(status.Detail, "cannot be verified") {
		t.Fatalf("the operator is not told why the stop is held: %q", status.Detail)
	}
	if status.Ready {
		t.Fatal("a platform holding an unverifiable emergency stop must not report itself ready")
	}
}
