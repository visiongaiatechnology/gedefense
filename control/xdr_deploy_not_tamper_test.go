// STATUS: DIAMANT VGT SUPREME
package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestAReplacedGeDefenseComponentIsADeploymentNotAnIntrusion covers the defect an operator
// reported as "it considers itself critical".
//
// The protected set contains the platform's own executables, and a deployment replaces them
// while the service runs. That was reported as self-tampering, which degrades XDR - and a
// degraded XDR blocks every promotion and pauses the automatic response until somebody restarts
// the control plane. Shipping a fix therefore switched part of the protection off, silently, and
// the panel said the platform had attacked itself.
//
// The change still has to be visible: it is recorded as a high-severity incident and as an event,
// it simply no longer counts as an attack.
func TestAReplacedGeDefenseComponentIsADeploymentNotAnIntrusion(t *testing.T) {
	root := t.TempDir()
	libexec := filepath.Join(root, "libexec")
	if err := os.MkdirAll(libexec, 0o755); err != nil {
		t.Fatal(err)
	}
	core := filepath.Join(libexec, "gedefense-core")
	if err := os.WriteFile(core, []byte("release-v1"), 0o755); err != nil {
		t.Fatal(err)
	}
	// The artifact root is configurable, so the test does not need the production tree.
	t.Setenv("VGT_RELEASE_ROOT", root)

	cfg := defaultConfig()
	state := NewState("test-node", cfg)
	engine := &XDREngine{cfg: cfg, state: state, degradeCauses: map[string]string{}}
	engine.protected = map[string]protectedObject{
		core: {path: core, digest: "stale-digest", mode: 0o755, size: 10},
	}

	// A deployment replaces the component.
	if err := os.WriteFile(core, []byte("release-v2"), 0o755); err != nil {
		t.Fatal(err)
	}
	engine.checkProtected()

	if degraded, reason := engine.degradedState(); degraded {
		t.Fatalf("replacing a GeDefense component degraded XDR: %s", reason)
	}
	recorded := false
	for _, incident := range state.Snapshot().Incidents {
		if strings.Contains(incident.Summary, "protected object changed") {
			recorded = true
			if incident.Severity != "high" || incident.Action != "none" {
				t.Fatalf("the deployment was recorded as an active response: %+v", incident)
			}
		}
	}
	if !recorded {
		t.Fatal("the deployment left no record for the operator")
	}
}

// TestAReplacedThirdPartyObjectStillDegradesXDR is the counter-case. Nothing legitimate rewrites
// a third-party object, so the full response stays.
func TestAReplacedThirdPartyObjectStillDegradesXDR(t *testing.T) {
	dir := t.TempDir()
	other := filepath.Join(dir, "third-party-object")
	if err := os.WriteFile(other, []byte("v1"), 0o755); err != nil {
		t.Fatal(err)
	}
	cfg := defaultConfig()
	state := NewState("test-node", cfg)
	engine := &XDREngine{cfg: cfg, state: state, degradeCauses: map[string]string{}}
	engine.protected = map[string]protectedObject{
		other: {path: other, digest: "stale-digest", mode: 0o755, size: 2},
	}
	if err := os.WriteFile(other, []byte("v2"), 0o755); err != nil {
		t.Fatal(err)
	}
	engine.checkProtected()
	if degraded, _ := engine.degradedState(); !degraded {
		t.Fatal("a changed third-party object no longer degrades XDR")
	}
}
