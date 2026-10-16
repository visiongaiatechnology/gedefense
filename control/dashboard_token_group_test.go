// STATUS: DIAMANT VGT SUPREME
// SPDX-FileCopyrightText: 2026 VisionGaia Technology
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
)

// TestDashboardTokenGroupIsExplicitAndNeverWorldReadable pins the three properties that make the
// gateway identity split safe to switch on - and safe to leave switched off.
//
// The group is configured, never detected. An earlier attempt derived it from the presence of an
// account, which made the runtime behaviour and the whole test suite depend on the user table of the
// machine: green on a host with the account, red without it. A suite that fails for reasons outside
// the code is a suite people learn to ignore, so the trigger is an explicit value with an empty
// default.
func TestDashboardTokenGroupIsExplicitAndNeverWorldReadable(t *testing.T) {
	dir := t.TempDir()

	// 1. Empty group: nothing changes. The token stays owner-only and keeps working, which is what
	//    every installation that has not migrated relies on.
	ownerOnly := filepath.Join(dir, "owner-only.token")
	if _, err := loadOrCreateToken(ownerOnly); err != nil {
		t.Fatal(err)
	}
	if err := adoptDashboardToken(ownerOnly, ""); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(ownerOnly)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("an empty group changed the mode to %o, want 0600", info.Mode().Perm())
	}
	if _, err := readDashboardToken(ownerOnly); err != nil {
		t.Fatalf("an owner-only token was rejected: %v", err)
	}

	// 2. Configured owner: the token becomes that account's property with mode 0600, which is what the
	//    gateway demands ("file permissions must be 0600 or stricter") and what the control plane keeps
	//    working against through cap_dac_override and cap_chown. The owner is asserted, not just the
	//    mode: a token that is 0600 but still belongs to the control plane would fail at the gateway.
	grouped := filepath.Join(dir, "owned.token")
	if _, err := loadOrCreateToken(grouped); err != nil {
		t.Fatal(err)
	}
	account, lookupErr := user.Lookup("gedefense")
	if lookupErr != nil {
		t.Skipf("the platform account is not present on this host: %v", lookupErr)
	}
	if err := adoptDashboardToken(grouped, account.Username); err != nil {
		t.Skipf("cannot take ownership as this user (expected outside root): %v", err)
	}
	groupedInfo, err := os.Stat(grouped)
	if err != nil {
		t.Fatal(err)
	}
	if groupedInfo.Mode().Perm() != 0o600 {
		t.Fatalf("a configured owner produced mode %o, want 0600", groupedInfo.Mode().Perm())
	}
	owner, ok := groupedInfo.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatal("cannot read the file ownership")
	}
	wantUID, convErr := strconv.Atoi(account.Uid)
	if convErr != nil {
		t.Fatal(convErr)
	}
	if int(owner.Uid) != wantUID {
		t.Fatalf("token belongs to uid %d, want %d - the gateway would refuse it", owner.Uid, wantUID)
	}
	if _, err := readDashboardToken(grouped); err != nil {
		t.Fatalf("an owner-only token was rejected: %v", err)
	}

	// 3. World access is never acceptable, whatever else is configured. This is the property the whole
	//    exercise exists to protect: the dashboard credential must not be readable by a service that
	//    has no business holding it.
	for _, mode := range []os.FileMode{0o644, 0o604, 0o606, 0o666} {
		if err := os.Chmod(grouped, mode); err != nil {
			t.Fatal(err)
		}
		if _, err := readDashboardToken(grouped); err == nil {
			t.Fatalf("a token with mode %o was accepted", mode)
		}
	}

	// 4. A missing account is a configuration error the operator sees, not something the platform
	//    silently ignores - a token nobody can read takes the dashboard offline.
	if err := os.Chmod(grouped, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := adoptDashboardToken(grouped, "definitely-not-a-user-vgt"); err == nil {
		t.Fatal("an unknown account was accepted instead of reported")
	}
}
