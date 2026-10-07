// STATUS: DIAMANT VGT SUPREME
package main

import (
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// ---------------------------------------------------------------- path jail

// TestOpenBeneathRefusesASymlinkedParentComponent covers the gap that a check on
// the parent plus O_EXCL on the final component leaves open. O_EXCL guarantees
// only that the last component is new; the directories above it are resolved by
// the kernel at open time, so a substituted parent redirects the write while the
// exclusive create still succeeds.
func TestOpenBeneathRefusesASymlinkedParentComponent(t *testing.T) {
	root := t.TempDir()
	inside := filepath.Join(root, "inside")
	if err := os.MkdirAll(inside, 0o700); err != nil {
		t.Fatal(err)
	}
	outside := t.TempDir()

	// A legitimate write lands inside the jail.
	file, err := openBeneath(root, "inside/decoy.env", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatalf("a legitimate jailed write failed: %v", err)
	}
	if _, err := file.Write([]byte("payload")); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if content, err := os.ReadFile(filepath.Join(inside, "decoy.env")); err != nil || string(content) != "payload" {
		t.Fatalf("the jailed write did not land: %q %v", content, err)
	}

	// A symlinked intermediate directory must be refused, not followed. This is the
	// case the previous check-then-open could not see.
	linked := filepath.Join(root, "redirect")
	if err := os.Symlink(outside, linked); err != nil {
		t.Skipf("symlinks are unavailable: %v", err)
	}
	if file, err := openBeneath(root, "redirect/escaped.env", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600); err == nil {
		_ = file.Close()
		t.Fatal("a symlinked parent component was followed")
	}
	if _, err := os.Stat(filepath.Join(outside, "escaped.env")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("the write escaped the jail through a symlinked parent")
	}

	// A symlinked final component is refused as well.
	target := filepath.Join(outside, "victim")
	if err := os.WriteFile(target, []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(root, "link.env")); err != nil {
		t.Fatal(err)
	}
	if file, err := openBeneath(root, "link.env", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600); err == nil {
		_ = file.Close()
		t.Fatal("a symlinked final component was followed")
	}
	if content, err := os.ReadFile(target); err != nil || string(content) != "original" {
		t.Fatalf("the link target was modified: %q %v", content, err)
	}
}

// TestOpenBeneathRejectsEscapingNames proves a name that is not a plain relative
// path never reaches the walk.
func TestOpenBeneathRejectsEscapingNames(t *testing.T) {
	root := t.TempDir()
	for _, name := range []string{
		"", ".", "..", "../outside", "inside/../../outside", "/etc/shadow",
		"inside/./file", "in\x00side",
	} {
		if file, err := openBeneath(root, name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600); err == nil {
			_ = file.Close()
			t.Errorf("name %q was accepted by the jail", name)
		}
	}
}

// TestRemoveAndRenameStayInsideTheJail covers the two companion operations: a
// removal or a replace must not be redirectable either.
func TestRemoveAndRenameStayInsideTheJail(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	outsideFile := filepath.Join(outside, "keep")
	if err := os.WriteFile(outsideFile, []byte("outside"), 0o600); err != nil {
		t.Fatal(err)
	}

	// Build a real file inside the jail, then replace it.
	file, err := openBeneath(root, "staging.tmp", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.Write([]byte("new decoy")); err != nil {
		_ = file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if err := renameBeneath(root, "staging.tmp", "decoy.env"); err != nil {
		t.Fatalf("a jailed rename failed: %v", err)
	}
	if content, err := os.ReadFile(filepath.Join(root, "decoy.env")); err != nil || string(content) != "new decoy" {
		t.Fatalf("the jailed rename did not land: %q %v", content, err)
	}
	if _, err := os.Lstat(filepath.Join(root, "staging.tmp")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("the staging file survived the rename")
	}

	// A rename across directories is refused: it could move a file out of its jail.
	if err := renameBeneath(root, "decoy.env", "nested/decoy.env"); err == nil {
		t.Fatal("a cross-directory jail rename was accepted")
	}
	// Escaping names are refused.
	if err := renameBeneath(root, "../outside", "decoy.env"); err == nil {
		t.Fatal("an escaping rename source was accepted")
	}
	if err := removeBeneath(root, "../outside/keep"); err == nil {
		t.Fatal("an escaping removal was accepted")
	}
	if _, err := os.Stat(outsideFile); err != nil {
		t.Fatalf("an outside file was removed through the jail: %v", err)
	}

	// A removal through a symlinked directory cannot reach outside either.
	if err := os.Symlink(outside, filepath.Join(root, "redirect")); err != nil {
		t.Skipf("symlinks are unavailable: %v", err)
	}
	if err := removeBeneath(root, "redirect/keep"); err == nil {
		t.Fatal("a removal followed a symlinked directory")
	}
	if _, err := os.Stat(outsideFile); err != nil {
		t.Fatalf("the outside file was removed through a symlinked directory: %v", err)
	}

	// A legitimate removal still works, and a missing file reports the real error.
	if err := removeBeneath(root, "decoy.env"); err != nil {
		t.Fatalf("a legitimate jailed removal failed: %v", err)
	}
	if err := removeBeneath(root, "decoy.env"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a missing file did not report not-exist: %v", err)
	}
}

// TestCanaryDeploymentSurvivesTheJailRewrite proves the security change did not
// break the feature: the decoy still appears, still has the right mode, and the
// staging file is gone.
func TestCanaryDeploymentSurvivesTheJailRewrite(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "decoy.env")
	if err := DeployCanaryFile(target, CanaryDotEnv); err != nil {
		t.Fatalf("a legitimate deployment failed: %v", err)
	}
	info, err := os.Lstat(target)
	if err != nil {
		t.Fatal(err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		t.Fatalf("deployed decoy has unexpected mode %v", info.Mode())
	}
	content, err := os.ReadFile(target)
	if err != nil || len(content) == 0 {
		t.Fatalf("the deployed decoy is empty: %v", err)
	}
	if _, err := os.Lstat(target + ".tmp"); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("the staging file was left behind")
	}
	// A second deployment leaves the existing decoy untouched.
	if err := DeployCanaryFile(target, CanarySSHKey); err != nil {
		t.Fatalf("a repeat deployment failed: %v", err)
	}
	again, err := os.ReadFile(target)
	if err != nil || string(again) != string(content) {
		t.Fatal("a repeat deployment rewrote an existing decoy")
	}
}

// TestCanaryDeploymentRefusesASymlinkedDirectory proves a link placed where the
// decoy directory should be cannot redirect the deployment.
func TestCanaryDeploymentRefusesASymlinkedDirectory(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	linkedDir := filepath.Join(root, "decoys")
	if err := os.Symlink(outside, linkedDir); err != nil {
		t.Skipf("symlinks are unavailable: %v", err)
	}
	if err := DeployCanaryFile(filepath.Join(linkedDir, "decoy.env"), CanaryDotEnv); err == nil {
		t.Fatal("a symlinked canary directory was accepted")
	}
	if _, err := os.Stat(filepath.Join(outside, "decoy.env")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("the decoy was written outside the intended directory")
	}
}

// ------------------------------------------------------------ id contract

// TestIdentifiersAreCorrelationOnly guards the boundary between a correlation
// identifier and a capability: no route that carries an identifier may rely on it
// for authority, and every such route must be behind the token check.
func TestIdentifiersAreCorrelationOnly(t *testing.T) {
	source := moduleSource(t, "server.go")
	routePattern := regexp.MustCompile(`mux\.HandleFunc\("([A-Z]+ [^"]+)"\s*,\s*([^)]*)\)`)
	// The asset route is the single documented exception. It carries a name, not an
	// identifier the caller chooses freely, and it is constrained by an explicit
	// allowlist - a stronger control here than a token, because the dashboard needs
	// its own assets before any token exists. Any other unauthenticated
	// identifier-carrying route is a defect.
	const assetRoute = "GET /assets/{name...}"
	matched := 0
	exceptions := []string{}
	for _, match := range routePattern.FindAllStringSubmatch(source, -1) {
		route := match[1]
		handler := match[2]
		if !strings.Contains(route, "{") {
			continue
		}
		matched++
		if strings.Contains(handler, "s.auth(") {
			continue
		}
		exceptions = append(exceptions, route)
	}
	if matched == 0 {
		t.Fatal("no identifier-carrying route was found; the scan looks wrong")
	}
	if len(exceptions) != 1 || exceptions[0] != assetRoute {
		t.Fatalf("identifier-carrying routes without the token check changed: %v", exceptions)
	}
	// The exception is only acceptable because the name is allowlisted, so that
	// property is asserted rather than assumed.
	asset := moduleSource(t, "server.go")
	if !strings.Contains(asset, "resolveWebAsset(") {
		t.Fatal("the asset route no longer validates its name against the allowlist")
	}
}

// TestIdentifiersAreNotSecretLength pins the entropy boundary as an explicit
// decision rather than an accident: the identifier is 64 bits because it is a
// correlation handle, and a future feature that needs an unguessable value must
// not reuse it.
func TestIdentifiersAreNotSecretLength(t *testing.T) {
	id := randomID()
	if len(id) != 16 {
		t.Fatalf("identifier width changed to %d characters", len(id))
	}
	// The documented boundary is stated where the value is produced, so a reader
	// of the code sees it without having to find this test.
	declaration := moduleSource(t, "state.go")
	for _, required := range []string{
		"Entropy boundary", "not secrets", "must never become one", "128",
	} {
		if !strings.Contains(declaration, required) {
			t.Errorf("the identifier contract no longer states %q", required)
		}
	}
}

// TestDeliberateActionGuardsAreNotCapabilities proves the confirmation phrase is
// derived from the identifier, which is what makes it an intent guard rather than
// an authority check. If this ever stops being true, the constant-time comparison
// becomes load-bearing and the identifier's entropy becomes a security property.
func TestDeliberateActionGuardsAreNotCapabilities(t *testing.T) {
	source := moduleSource(t, "transactions.go")
	if !strings.Contains(source, `expectedConfirmation := "APPLY " + record.ID`) {
		t.Fatal("the apply confirmation is no longer derived from the identifier; review whether it became a capability")
	}
	if !strings.Contains(source, `expectedConfirmation := "REVERSE " + record.ID`) {
		t.Fatal("the reverse confirmation is no longer derived from the identifier; review whether it became a capability")
	}
	if !strings.Contains(source, "deliberate-action guard") {
		t.Error("the confirmation's nature is no longer documented at the check")
	}
}

// TestAtomicWriterStatesItsScope proves the shared atomic writer documents what it
// does and does not cover, so its guarantee is not read as broader than it is.
func TestAtomicWriterStatesItsScope(t *testing.T) {
	source := moduleSource(t, "policy.go")
	if !strings.Contains(source, "Scope of the symlink guarantee") {
		t.Fatal("the atomic writer no longer states the scope of its symlink guarantee")
	}
	if !strings.Contains(source, "are NOT covered here") {
		t.Fatal("the atomic writer no longer states the part of the path it does not cover")
	}
	if !strings.Contains(source, "openBeneath") {
		t.Fatal("the atomic writer no longer points at the primitive that covers the rest")
	}
}
