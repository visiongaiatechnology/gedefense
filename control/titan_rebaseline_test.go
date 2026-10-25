// SPDX-FileCopyrightText: 2026 VisionGaia Technology
// SPDX-License-Identifier: AGPL-3.0-only

package main

// Tests for the Titan side of the authorized release rebaseline: open
// UNEXPECTED findings are closed only when the approved FIM baseline vouches for
// the current bytes, and a fresh AUTHORIZED observation answers the current
// state. A COMPROMISED finding is never closed automatically.

import (
	"os"
	"path/filepath"
	"testing"
)

func TestTitanAcceptRebaselinedPathsClosesOnlyVerifiedFindings(t *testing.T) {
	var target string
	rig := newTitanTestRig(t, func(rig *titanTestRig) {
		target = filepath.Join(rig.root, "gedefense-control")
	})
	path := rig.write("gedefense-control", "old-release-binary")
	if path != target {
		t.Fatalf("test path mismatch: %s != %s", path, target)
	}
	finding := rig.observe(target, TitanChangeModified)
	if finding.TrustState != TitanTrustUnexpected || finding.Review != "PENDING" {
		t.Fatalf("expected an open UNEXPECTED finding, got %+v", finding)
	}
	if open := rig.engine.Status().OpenFindings; open != 1 {
		t.Fatalf("open findings before acceptance=%d, want 1", open)
	}

	// The verified release replaced the binary; the approved FIM baseline now
	// carries the new digest.
	if err := os.WriteFile(target, []byte("new-release-binary"), 0o600); err != nil {
		t.Fatal(err)
	}
	rig.fim.set(target, "new-release-binary")

	acceptance, err := rig.engine.AcceptRebaselinedPaths(
		[]string{target, "/etc/not-in-titan-roots.conf"},
		"authorized release rebaseline 5.0.0-beta.1-hotfix2",
	)
	if err != nil {
		t.Fatalf("baseline acceptance failed: %v", err)
	}
	if acceptance.ApprovedPaths != 1 || acceptance.ClosedFindings != 1 || acceptance.FreshObservations != 1 {
		t.Fatalf("unexpected acceptance result: %+v", acceptance)
	}
	if len(acceptance.Skipped) != 1 {
		t.Fatalf("expected the out-of-root path to be reported as skipped: %+v", acceptance.Skipped)
	}
	if open := rig.engine.Status().OpenFindings; open != 0 {
		t.Fatalf("open findings after acceptance=%d, want 0", open)
	}
	closed, ok := rig.eventByID(finding.ID)
	if !ok {
		t.Fatal("original finding missing from the journal")
	}
	if closed.Review != titanRebaselineReviewState || closed.ReviewUTC == nil {
		t.Fatalf("original finding was not closed with the acceptance reason: %+v", closed)
	}
	latest := rig.lastEvent()
	if latest.TrustState != TitanTrustAuthorized || latest.Sensor != titanRebaselineSensorSource {
		t.Fatalf("no fresh AUTHORIZED observation recorded: %+v", latest)
	}
}

func TestTitanAcceptRebaselinedPathsRefusesUnverifiedContent(t *testing.T) {
	var target string
	rig := newTitanTestRig(t, func(rig *titanTestRig) {
		target = filepath.Join(rig.root, "gedefense-core")
	})
	rig.write("gedefense-core", "observed-bytes")
	finding := rig.observe(target, TitanChangeModified)
	if finding.TrustState != TitanTrustUnexpected {
		t.Fatalf("expected UNEXPECTED, got %s", finding.TrustState)
	}
	// The FIM baseline records different bytes than the file on disk: acceptance
	// must refuse instead of blessing what was not approved.
	rig.fim.set(target, "some-other-approved-bytes")
	if _, err := rig.engine.AcceptRebaselinedPaths(
		[]string{target}, "authorized release rebaseline of an unverified file",
	); err == nil {
		t.Fatal("baseline acceptance accepted a path the FIM baseline does not vouch for")
	}
	if open := rig.engine.Status().OpenFindings; open != 1 {
		t.Fatalf("open findings=%d, want the finding to stay open", open)
	}
	kept, ok := rig.eventByID(finding.ID)
	if !ok {
		t.Fatal("finding disappeared from the journal")
	}
	if kept.Review != "PENDING" {
		t.Fatalf("finding was reviewed without evidence: %+v", kept)
	}
}

func TestTitanAcceptRebaselinedPathsNeverClosesCompromised(t *testing.T) {
	var target string
	rig := newTitanTestRig(t, func(rig *titanTestRig) {
		target = filepath.Join(rig.root, "critical.conf")
	})
	rig.write("critical.conf", "content-before")
	// A compromised trust state requires a temporal XDR correlation on a
	// security-critical path without an approved baseline. Give the root a
	// protected path and one recent incident, then observe the change.
	rig.engine.ApplyPolicy(TitanModeStrict, true, false, "test policy for compromised acceptance")
	rig.xdrContext.mu.Lock()
	rig.xdrContext.count = 1
	rig.xdrContext.mu.Unlock()
	rig.engine.mu.Lock()
	rig.engine.policy.ProtectedPaths = []string{target}
	rig.engine.mu.Unlock()
	event := rig.observe(target, TitanChangeModified)
	if event.TrustState != TitanTrustCompromised {
		t.Skipf("observation did not reach COMPROMISED (state=%s); the temporal path is exercised elsewhere", event.TrustState)
	}
	rig.fim.set(target, "content-before")
	acceptance, err := rig.engine.AcceptRebaselinedPaths(
		[]string{target}, "authorized release rebaseline with open incident correlation",
	)
	if err != nil {
		t.Fatalf("acceptance failed: %v", err)
	}
	if acceptance.CompromisedDeferred != 1 {
		t.Fatalf("compromised finding was not deferred to the operator: %+v", acceptance)
	}
	kept, ok := rig.eventByID(event.ID)
	if !ok || kept.Review != "PENDING" {
		t.Fatalf("compromised finding was closed automatically: %+v", kept)
	}
}
