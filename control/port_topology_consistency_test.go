// STATUS: DIAMANT VGT SUPREME
package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// G-RUST-06 / CHAIN-005: the shipped port topology is one contract.
//
//   - public access front end: 127.0.0.1:9843 / 0.0.0.0:9843
//   - internal control backend: 127.0.0.1:9844
//
// The control-plane default used to listen on 9843, colliding with the packaged
// access front end on package installs. This test pins the canonical values and
// cross-checks the shipped configuration and packaging sources that are present
// in the checkout.
func TestShippedPortTopologyIsConsistent(t *testing.T) {
	if got := defaultConfig().Dashboard.Listen; got != canonicalDashboardInternalListen {
		t.Fatalf("control dashboard default listen=%q, want %q", got, canonicalDashboardInternalListen)
	}
	if canonicalAccessBackendTarget != "http://127.0.0.1:9844" {
		t.Fatalf("canonical access backend target is inconsistent: %q", canonicalAccessBackendTarget)
	}
	if canonicalAccessPublicPort != "9843" {
		t.Fatalf("canonical public access port=%q", canonicalAccessPublicPort)
	}

	repoRoot := ".."
	assertFileContains(t, filepath.Join(repoRoot, "gedefense.toml"),
		`listen = "127.0.0.1:9844"`)
	assertFileContains(t, filepath.Join(repoRoot, "packaging", "systemd", "gedefense-access.service.in"),
		"--backend=http://127.0.0.1:9844")
	assertFileContains(t, filepath.Join(repoRoot, "integration", "astraeaos", "astraeaos-profile.toml"),
		`listen = "127.0.0.1:9844"`)
	assertFileContains(t, filepath.Join(repoRoot, "integration", "astraeaos", "gedefense-access-astraeaos.conf"),
		"--listen=127.0.0.1:9843")
	assertFileContains(t, filepath.Join(repoRoot, "integration", "astraeaos", "gedefense-access-astraeaos.conf"),
		"--backend=http://127.0.0.1:9844")
}

func assertFileContains(t *testing.T, path, needle string) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			t.Skipf("shipped file %s is not present in this checkout (%v)", path, err)
		}
		t.Fatalf("read %s: %v", path, err)
	}
	if !strings.Contains(string(raw), needle) {
		t.Fatalf("%s does not contain %q", path, needle)
	}
}
