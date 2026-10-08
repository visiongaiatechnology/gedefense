package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// protectedFixture builds the layout the product is installed with: one release directory
// and a "current" symlink pointing at it, so the same file is reachable under two names.
func protectedFixture(t *testing.T) (engine *XDREngine, state *State, stable, versioned string) {
	t.Helper()
	dir := t.TempDir()
	cfg := defaultConfig()
	state = NewState("test", cfg)
	engine = &XDREngine{
		cfg:           cfg,
		state:         state,
		selfPID:       -1,
		dedupe:        map[string]time.Time{},
		protected:     map[string]protectedObject{},
		degradeCauses: map[string]string{},
	}
	release := filepath.Join(dir, "releases", "4.2.1", "bin")
	if err := os.MkdirAll(release, 0o755); err != nil {
		t.Fatal(err)
	}
	versioned = filepath.Join(release, "gedefense-access")
	if err := os.WriteFile(versioned, []byte("release one"), 0o755); err != nil {
		t.Fatal(err)
	}
	current := filepath.Join(dir, "current")
	if err := os.Symlink(filepath.Join(dir, "releases", "4.2.1"), current); err != nil {
		t.Fatal(err)
	}
	stable = filepath.Join(current, "bin", "gedefense-access")
	return engine, state, stable, versioned
}

// TestOneReplacedProtectedObjectIsReportedOnce covers what an operator saw after a
// legitimate update: the platform declared itself tampered with, twice for one file, and
// then kept declaring it.
func TestOneReplacedProtectedObjectIsReportedOnce(t *testing.T) {
	engine, state, stable, versioned := protectedFixture(t)
	engine.captureProtected([]string{stable, versioned})
	if len(engine.protected) != 2 {
		t.Fatalf("both routes to the file should be watched, got %d", len(engine.protected))
	}

	before := state.Snapshot().XDR.IncidentsTotal

	// One file is replaced. It is reachable through two protected paths.
	if err := os.WriteFile(versioned, []byte("release two"), 0o755); err != nil {
		t.Fatal(err)
	}
	engine.checkProtected()

	after := state.Snapshot().XDR.IncidentsTotal
	if after != before+1 {
		t.Fatalf("one replaced object produced %d incidents, want exactly 1", after-before)
	}
	if degraded, _ := engine.degradedState(); !degraded {
		t.Fatal("a changed protected object did not degrade XDR")
	}

	// The object keeps not matching. That is a state, not a repeating event. The time-based
	// anomaly dedupe is expired on every pass, because that is the timer the old behaviour
	// waited on: five minutes after the first report it announced the same unchanged fact
	// again, and again every five minutes after that. Expiring it here makes this a test of
	// the tamper state rather than a test of a timer that has not run out yet.
	for pass := 0; pass < 3; pass++ {
		engine.mu.Lock()
		engine.dedupe = map[string]time.Time{}
		engine.mu.Unlock()
		engine.checkProtected()
	}
	if again := state.Snapshot().XDR.IncidentsTotal; again != after {
		t.Fatalf("an unremediated change was announced again: %d -> %d incidents", after, again)
	}

	// A further modification is a new fact and has to be reported.
	if err := os.WriteFile(versioned, []byte("release three"), 0o755); err != nil {
		t.Fatal(err)
	}
	engine.checkProtected()
	if third := state.Snapshot().XDR.IncidentsTotal; third != after+1 {
		t.Fatalf("a second modification was not reported: %d -> %d incidents", after, third)
	}

	// A permission change alone is also a change of the protected state.
	if err := os.Chmod(versioned, 0o700); err != nil {
		t.Fatal(err)
	}
	engine.checkProtected()
	if fourth := state.Snapshot().XDR.IncidentsTotal; fourth != after+2 {
		t.Fatalf("a permission change was not reported: %d -> %d incidents", after+1, fourth)
	}
}

// TestTheDegradedReasonNamesEveryObjectThatChanged checks that the reason an operator is
// shown is not silently reduced to whichever object happened to be checked last.
func TestTheDegradedReasonNamesEveryObjectThatChanged(t *testing.T) {
	engine, _, stable, versioned := protectedFixture(t)
	engine.captureProtected([]string{stable, versioned})

	if err := os.WriteFile(versioned, []byte("changed"), 0o755); err != nil {
		t.Fatal(err)
	}
	other := filepath.Join(filepath.Dir(stable), "gedefense-core")
	if err := os.WriteFile(other, []byte("core"), 0o755); err != nil {
		t.Fatal(err)
	}
	engine.captureProtected([]string{other})
	if err := os.WriteFile(other, []byte("core changed"), 0o755); err != nil {
		t.Fatal(err)
	}

	engine.checkProtected()

	degraded, reason := engine.degradedState()
	if !degraded {
		t.Fatal("two changed protected objects did not degrade XDR")
	}
	for _, want := range []string{"gedefense-access", "gedefense-core"} {
		if !strings.Contains(reason, want) {
			t.Fatalf("the reason does not name %s: %q", want, reason)
		}
	}
}

func TestResolvedIdentityCollapsesRoutesToTheSameFile(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "releases", "4.2.1", "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(dir, "releases", "4.2.1", "bin", "gedefense-access")
	if err := os.WriteFile(target, []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(dir, "releases", "4.2.1"), filepath.Join(dir, "current")); err != nil {
		t.Fatal(err)
	}
	stable := filepath.Join(dir, "current", "bin", "gedefense-access")
	if resolvedIdentity(stable) != resolvedIdentity(target) {
		t.Fatalf("two routes to one file resolved differently: %q and %q",
			resolvedIdentity(stable), resolvedIdentity(target))
	}

	// A path that cannot be resolved is still reported as itself rather than dropped, or
	// a disappeared object would be reported under an empty identity.
	missing := filepath.Join(dir, "gone")
	if got := resolvedIdentity(missing); got != missing {
		t.Fatalf("an unresolvable path became %q", got)
	}
}
