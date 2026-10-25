// SPDX-FileCopyrightText: 2026 VisionGaia Technology
// SPDX-License-Identifier: AGPL-3.0-only

package main

// Tests for the authorized release rebaseline. They exercise the merge logic
// with a re-rooted release tree so the production constant never has to exist on
// the test host.

import (
	"os"
	"path/filepath"
	"testing"
)

func newRebaselineTestFIM(t *testing.T, roots []string) *FIMEngine {
	t.Helper()
	engine := newTestFIM(t, roots)
	return engine
}

func verifiedRebaselineAuth() FIMRebaselineAuthorization {
	return FIMRebaselineAuthorization{
		Phase: ReleasePhaseEnforce, FailSafeVerified: true,
		KernelPolicyState: "verified-enforce", ReleaseVersion: "5.0.0-beta.1",
	}
}

func TestFIMReleaseRebaselineAcceptsOnlyReleaseScope(t *testing.T) {
	dir := t.TempDir()
	releaseRoot := filepath.Join(dir, "current")
	if err := os.MkdirAll(filepath.Join(releaseRoot, "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(dir, "etc", "gedefense.toml")
	if err := os.MkdirAll(filepath.Dir(configPath), 0o755); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(dir, "outside.conf")
	for path, content := range map[string]string{
		filepath.Join(releaseRoot, "bin", "gedefense-control"): "old-release-binary",
		configPath: "feed.mode = \"correlation-only\"\n",
		outside:    "must not be rebaselined\n",
	} {
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	engine := newRebaselineTestFIM(t, []string{releaseRoot, configPath, outside})
	engine.releaseRoot = releaseRoot
	engine.releaseConfigPaths = []string{configPath}
	if _, err := engine.CreateBaseline(); err != nil {
		t.Fatal(err)
	}
	if status := engine.Status(); status.Health != "PENDING" && status.Health != "VERIFIED" {
		t.Fatalf("unexpected initial status: %+v", status)
	}

	// The verified update replaces the release binary and the deployed config.
	if err := os.WriteFile(filepath.Join(releaseRoot, "bin", "gedefense-control"), []byte("new-release-binary"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, []byte("feed.mode = \"signed\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(releaseRoot, "bin", "gedefense-new"), []byte("added-binary"), 0o700); err != nil {
		t.Fatal(err)
	}

	// An unverified release state is refused before anything is written.
	unverified := verifiedRebaselineAuth()
	unverified.FailSafeVerified = false
	if _, err := engine.RebaselineRelease(unverified, "deployment of the verified release"); err == nil {
		t.Fatal("rebaseline accepted an unverified release state")
	}

	result, err := engine.RebaselineRelease(verifiedRebaselineAuth(), "deployment of the verified release 5.0.0-beta.1-hotfix2")
	if err != nil {
		t.Fatalf("release rebaseline failed: %v", err)
	}
	if len(result.Accepted) != 3 {
		t.Fatalf("expected three accepted transitions, got %+v", result.Accepted)
	}
	if result.Status.Health != "VERIFIED" {
		t.Fatalf("FIM health after rebaseline=%s, want VERIFIED (status=%+v)", result.Status.Health, result.Status)
	}
	if result.Preserved != 1 {
		t.Fatalf("preserved non-release records=%d, want 1", result.Preserved)
	}
	if result.RemainingDeviations != 0 {
		t.Fatalf("remaining deviations=%d, want 0", result.RemainingDeviations)
	}
	oldDigests := make(map[string]string, len(result.Accepted))
	for _, change := range result.Accepted {
		oldDigests[change.Path] = change.PreviousSHA256
	}
	if oldDigests[configPath] == "" {
		t.Fatal("audit record does not carry the previous digest of the replaced config")
	}
	if summary := result.AuditSummary(); summary == "" {
		t.Fatal("audit summary is empty")
	}

	// The out-of-scope file was not touched by the merge: a deviation there
	// still reports TAMPERED.
	if err := os.WriteFile(outside, []byte("tampered after rebaseline\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if status := engine.Status(); status.Health != "TAMPERED" {
		if _, scanErr := engine.Scan(); scanErr != nil {
			t.Fatal(scanErr)
		}
		if status = engine.Status(); status.Health != "TAMPERED" {
			t.Fatalf("out-of-scope deviation not reported: %+v", status)
		}
	}
}

func TestFIMReleaseRebaselineRefusesScopeAbuse(t *testing.T) {
	dir := t.TempDir()
	releaseRoot := filepath.Join(dir, "current")
	if err := os.MkdirAll(releaseRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	watched := filepath.Join(dir, "watched.conf")
	if err := os.WriteFile(watched, []byte("v1"), 0o600); err != nil {
		t.Fatal(err)
	}
	engine := newRebaselineTestFIM(t, []string{releaseRoot, watched})
	engine.releaseRoot = releaseRoot
	engine.releaseConfigPaths = nil
	if _, err := engine.CreateBaseline(); err != nil {
		t.Fatal(err)
	}
	if _, err := engine.RebaselineRelease(verifiedRebaselineAuth(), "short"); err == nil {
		t.Fatal("rebaseline accepted a reason below the minimum length")
	}
	if err := os.WriteFile(watched, []byte("v2"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := engine.RebaselineRelease(verifiedRebaselineAuth(), "attempt to bless a file outside the release scope"); err == nil {
		t.Fatal("rebaseline accepted a deviation outside the release scope")
	}
	if status := engine.Status(); status.Health != "TAMPERED" {
		if _, scanErr := engine.Scan(); scanErr == nil {
			if status = engine.Status(); status.Health != "TAMPERED" {
				t.Fatalf("out-of-scope tamper was accepted: %+v", status)
			}
		}
	}
}

func TestFIMRebaselinePathInScopeIsExact(t *testing.T) {
	root := "/opt/vgt/gedefense/current"
	configs := []string{"/etc/vgt/gedefense/gedefense.toml"}
	cases := []struct {
		path string
		want bool
	}{
		{root + "/bin/gedefense-control", true},
		{root + "/libexec/gedefense-core", true},
		{"/etc/vgt/gedefense/gedefense.toml", true},
		{"/etc/vgt/gedefense/other.toml", false},
		{"/opt/vgt/gedefense/current2/bin/x", false},
		{"/opt/vgt/gedefense/releases/old/bin/x", false},
		{"/etc/passwd", false},
	}
	for _, testCase := range cases {
		if got := fimRebaselinePathInScope(testCase.path, root, configs); got != testCase.want {
			t.Fatalf("scope(%s)=%t, want %t", testCase.path, got, testCase.want)
		}
	}
}
