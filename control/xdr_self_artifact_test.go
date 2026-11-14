// STATUS: DIAMANT VGT SUPREME
package main

import (
	"os"
	"path/filepath"
	"testing"
)

// TestProductArtifactsAreRecognised pins the classifier the response depends on.
func TestProductArtifactsAreRecognised(t *testing.T) {
	for _, exe := range productArtifactPaths() {
		if !isProductArtifact(exe) {
			t.Errorf("%s was not recognised as this product's own", exe)
		}
	}
	for _, exe := range []string{
		"/usr/bin/bash", "/usr/sbin/nginx", "/opt/somewhere/else/gedefense-control",
		"/opt/vgt/gedefense/current/bin/not-gedefense", "", "/",
	} {
		if isProductArtifact(exe) {
			t.Errorf("%q was mistaken for this product's own binary", exe)
		}
	}
}

// TestProductArtifactRootFollowsTheEnvironment keeps the classifier and the preflight on
// one root. Two independent copies of the same path is how they drift apart.
func TestProductArtifactRootFollowsTheEnvironment(t *testing.T) {
	previous, had := os.LookupEnv("VGT_RELEASE_ROOT")
	t.Cleanup(func() {
		if had {
			_ = os.Setenv("VGT_RELEASE_ROOT", previous)
			return
		}
		_ = os.Unsetenv("VGT_RELEASE_ROOT")
	})

	_ = os.Unsetenv("VGT_RELEASE_ROOT")
	if got := productArtifactRoot(); got != "/opt/vgt/gedefense/current" {
		t.Fatalf("default root is %q", got)
	}
	_ = os.Setenv("VGT_RELEASE_ROOT", "/srv/gedefense")
	if got := productArtifactRoot(); got != "/srv/gedefense" {
		t.Fatalf("override ignored: %q", got)
	}
	// The derived paths have to follow, or an installation outside the default prefix
	// would not recognise its own binaries.
	if !isProductArtifact("/srv/gedefense/bin/gedefense-access") {
		t.Fatal("an overridden root did not recognise its own binary")
	}
}

// TestOwnArtifactMismatchIsNotDowngraded is the FIND-025 regression test at the comparison
// level.
//
// A mismatch on one of the product's own components used to be marked AlertOnly, which removed
// the finding from the response score and - through the matching branch in xdr.go - from every
// degradation. The comparison no longer decides that: it reports a full finding, and the update
// path turns it into XDR.SELF_TAMPER plus a release-blocking degradation unless a verified
// signed update window covers the exact new bytes. Terminating the product's own already-running
// process is still not a response, so kill eligibility stays off.
func TestOwnArtifactMismatchIsNotDowngraded(t *testing.T) {
	dir := t.TempDir()
	own := filepath.Join(dir, "gedefense-control")
	if err := os.WriteFile(own, []byte("the deployed bytes"), 0o700); err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	t.Setenv("VGT_RELEASE_ROOT", root)
	if err := os.MkdirAll(filepath.Join(root, "bin"), 0o700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(root, "bin", "gedefense-control")
	if err := os.WriteFile(target, []byte("the deployed bytes"), 0o700); err != nil {
		t.Fatal(err)
	}

	baseline := &XDRBaseline{compiled: map[string]compiledBaseline{
		resolveBaselinePath(target): {
			profile: BaselineProfile{Executable: target, SHA256: "0000000000000000000000000000000000000000000000000000000000000000"},
		},
	}}
	matches := baseline.Evaluate(ProcessSample{Exe: target, PID: 1}, nil)
	if len(matches) != 1 {
		t.Fatalf("expected one finding, got %d", len(matches))
	}
	match := matches[0]
	if match.ID != "BASELINE.HASH_MISMATCH" {
		t.Fatalf("unexpected rule %q", match.ID)
	}
	// Detection is untouched: same score, same category, same words.
	if match.Score != 120 || match.Category != "integrity" {
		t.Fatalf("the finding was weakened: score=%d category=%s", match.Score, match.Category)
	}
	if match.AlertOnly {
		t.Fatal("a mismatch on the product's own component was downgraded to alert-only")
	}
	if match.KillEligible {
		t.Fatal("a mismatch on the product's own component became kill-eligible")
	}

	// The mismatch is attributable: the engine can tell which approved digest the bytes diverge
	// from, which is what the signed update window comparison needs.
	expected, observed, mismatch := baseline.ProductArtifactMismatch(target)
	if !mismatch {
		t.Fatal("the engine did not classify the own-component digest mismatch")
	}
	if expected != "0000000000000000000000000000000000000000000000000000000000000000" || len(observed) != 64 {
		t.Fatalf("the mismatch evidence is incomplete: expected=%q observed=%q", expected, observed)
	}
	// A path outside the product's own set is never routed through the update-window logic.
	if _, _, mismatch := baseline.ProductArtifactMismatch("/usr/bin/bash"); mismatch {
		t.Fatal("a foreign binary was classified as a product artifact")
	}
}

// TestForeignBinaryStillCarriesTheFullResponse is the counter-case, and the property that
// keeps this from being a general weakening of tamper detection.
func TestForeignBinaryStillCarriesTheFullResponse(t *testing.T) {
	dir := t.TempDir()
	foreign := filepath.Join(dir, "customer-daemon")
	if err := os.WriteFile(foreign, []byte("the deployed bytes"), 0o700); err != nil {
		t.Fatal(err)
	}
	baseline := &XDRBaseline{compiled: map[string]compiledBaseline{
		resolveBaselinePath(foreign): {
			profile: BaselineProfile{Executable: foreign, SHA256: "0000000000000000000000000000000000000000000000000000000000000000"},
		},
	}}
	matches := baseline.Evaluate(ProcessSample{Exe: foreign, PID: 1}, nil)
	if len(matches) != 1 {
		t.Fatalf("expected one finding, got %d", len(matches))
	}
	if matches[0].AlertOnly {
		t.Fatal("a third-party binary was exempted from the response")
	}
	if !matches[0].KillEligible {
		t.Fatal("a third-party binary lost kill eligibility")
	}
}

// TestAlertOnlyRemovesTheFindingFromTheResponseScore proves the flag does what the fix
// assumes it does, rather than assuming the plumbing.
func TestAlertOnlyRemovesTheFindingFromTheResponseScore(t *testing.T) {
	alerting := combineMatches([]RuleMatch{{
		ID: "BASELINE.HASH_MISMATCH", Category: "integrity", Score: 120, AlertOnly: true,
	}})
	if alerting.Score != 120 {
		t.Fatalf("the detection score was reduced: %d", alerting.Score)
	}
	if alerting.ResponseScore != 0 {
		t.Fatalf("an alert-only finding still drives a response: %d", alerting.ResponseScore)
	}
	acting := combineMatches([]RuleMatch{{
		ID: "BASELINE.HASH_MISMATCH", Category: "integrity", Score: 120,
	}})
	if acting.ResponseScore != 120 {
		t.Fatalf("a normal finding lost its response score: %d", acting.ResponseScore)
	}
}
