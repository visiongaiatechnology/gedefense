// STATUS: DIAMANT VGT SUPREME
package main

import (
	"os"
	"path/filepath"
	"testing"
)

// TestAReplacedThirdPartyObjectStillDegradesXDR is the counter-case for own-component handling:
// nothing legitimate rewrites a third-party object, so a changed one keeps the full fail-closed
// response. Own components are covered by xdr_update_window_test.go: an unauthorized replacement
// is also non-rebaselineable, while only a verified signed update window may replace them.
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
