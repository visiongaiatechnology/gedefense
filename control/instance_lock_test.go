// STATUS: PLATIN
// SPDX-FileCopyrightText: 2026 VisionGaia Technology
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"path/filepath"
	"testing"
)

// TestControlPlaneInstanceLockIsExclusive is G-STATE-08: two control planes pointed at the
// same state directory must not both open the revision-bound stores.
func TestControlPlaneInstanceLockIsExclusive(t *testing.T) {
	stateFile := filepath.Join(t.TempDir(), "policy.json")
	first, err := acquireInstanceLock(stateFile)
	if err != nil {
		t.Fatalf("first instance lock: %v", err)
	}
	if _, err := acquireInstanceLock(stateFile); err == nil {
		t.Fatal("a second control-plane instance acquired the same state directory")
	}
	if err := first.Release(); err != nil {
		t.Fatalf("release: %v", err)
	}
	second, err := acquireInstanceLock(stateFile)
	if err != nil {
		t.Fatalf("lock was not released: %v", err)
	}
	if err := second.Release(); err != nil {
		t.Fatalf("second release: %v", err)
	}
}
