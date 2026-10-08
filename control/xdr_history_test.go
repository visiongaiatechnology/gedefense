// STATUS: DIAMANT VGT SUPREME
package main

import (
	"path/filepath"
	"testing"
	"time"
)

// incidentLoggerFixture builds a logger over a temporary log.
type incidentFixture struct {
	logger  *IncidentLogger
	logPath string
	keyPath string
}

func incidentLoggerFixture(t *testing.T) incidentFixture {
	t.Helper()
	dir := t.TempDir()
	logPath := filepath.Join(dir, "incidents.jsonl")
	keyPath := filepath.Join(dir, "incidents.key")
	logger, err := NewIncidentLogger(logPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	return incidentFixture{logger: logger, logPath: logPath, keyPath: keyPath}
}

// TestIncidentHistoryIsReadableAfterARestart covers the gap that made the forensic view
// report zero.
//
// The logger could write and verify but not read. The engine's incident list lives in
// memory, so it began empty on every start while the log on disk held every incident the
// host had ever recorded - 220 of them in the case that surfaced this. The operator's
// view said nothing had ever happened, next to a file that said otherwise.
func TestIncidentHistoryIsReadableAfterARestart(t *testing.T) {
	fixture := incidentLoggerFixture(t)
	logger := fixture.logger

	written := []string{"RELEASE.FAIL_SAFE", "XDR.CONTAIN", "NET.INGRESS.PORT_SCAN"}
	for i, rule := range written {
		_, err := logger.Append(XDRIncident{
			ID: randomID(), Time: time.Now().UTC().Add(time.Duration(i) * time.Second),
			Severity: "high", RuleIDs: []string{rule},
			Summary: "incident " + rule, Decision: "alert", Action: "none", Outcome: "observed",
		})
		if err != nil {
			t.Fatal(err)
		}
	}

	// A second logger over the same file is what a restart looks like.
	restarted, err := NewIncidentLogger(fixture.logPath, fixture.keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := restarted.Verify(); err != nil {
		t.Fatalf("the log did not verify: %v", err)
	}
	recent, err := restarted.ReadRecent(10)
	if err != nil {
		t.Fatalf("the history could not be read: %v", err)
	}
	if len(recent) != len(written) {
		t.Fatalf("expected %d incidents, read %d", len(written), len(recent))
	}
	// Oldest first, so the list reads in the order things happened.
	for i, rule := range written {
		if len(recent[i].RuleIDs) == 0 || recent[i].RuleIDs[0] != rule {
			t.Fatalf("position %d is %v, expected %s", i, recent[i].RuleIDs, rule)
		}
	}
}

// TestIncidentHistoryReadIsBounded proves the limit is the memory cost, not the file. An
// installation that has been running for years must not load its whole log to show a view
// that displays a few dozen rows.
func TestIncidentHistoryReadIsBounded(t *testing.T) {
	fixture := incidentLoggerFixture(t)
	logger := fixture.logger
	for i := 0; i < 12; i++ {
		if _, err := logger.Append(XDRIncident{
			ID: randomID(), Time: time.Now().UTC(), Severity: "info",
			Summary: "row", Decision: "alert",
		}); err != nil {
			t.Fatal(err)
		}
	}
	recent, err := logger.ReadRecent(5)
	if err != nil {
		t.Fatal(err)
	}
	if len(recent) != 5 {
		t.Fatalf("expected the last 5, got %d", len(recent))
	}
	// It must be the LAST five, not the first five.
	all, err := logger.ReadRecent(12)
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 12 {
		t.Fatalf("expected 12, got %d", len(all))
	}
	for i := range recent {
		if recent[i].ID != all[len(all)-len(recent)+i].ID {
			t.Fatalf("ReadRecent returned the wrong slice at position %d", i)
		}
	}

	// Zero and negative limits are answered, not guessed at.
	for _, limit := range []int{0, -1} {
		got, err := logger.ReadRecent(limit)
		if err != nil || got != nil {
			t.Fatalf("limit %d produced %v, %v", limit, got, err)
		}
	}
}

// TestRestoredIncidentsDoNotInflateTotals is the property that keeps a restart from
// corrupting what the platform reports about itself. Restoring history is not observing
// new events, and the totals must not move.
func TestRestoredIncidentsDoNotInflateTotals(t *testing.T) {
	cfg := defaultConfig()
	state := NewState("test", cfg)

	before := state.Snapshot().XDR
	state.RestoreIncidents([]XDRIncident{
		{ID: "restored-1", Time: time.Now().UTC(), Severity: "critical", Summary: "from an earlier run"},
		{ID: "restored-2", Time: time.Now().UTC(), Severity: "high", Summary: "from an earlier run"},
	})
	after := state.Snapshot()

	if len(after.Incidents) != 2 {
		t.Fatalf("the history was not restored: %d incidents", len(after.Incidents))
	}
	if after.XDR.IncidentsTotal != before.IncidentsTotal {
		t.Fatalf("restoring history changed the incident total: %d -> %d", before.IncidentsTotal, after.XDR.IncidentsTotal)
	}
	if after.XDR.ActionsTotal != before.ActionsTotal {
		t.Fatalf("restoring history changed the action total: %d -> %d", before.ActionsTotal, after.XDR.ActionsTotal)
	}

	// A newly observed incident still counts.
	state.AddIncident(XDRIncident{ID: "live-1", Time: time.Now().UTC(), Severity: "high", Action: "contain"})
	final := state.Snapshot()
	if final.XDR.IncidentsTotal != before.IncidentsTotal+1 {
		t.Fatalf("a live incident was not counted: %d", final.XDR.IncidentsTotal)
	}
	if final.XDR.ActionsTotal != before.ActionsTotal+1 {
		t.Fatalf("a live action was not counted: %d", final.XDR.ActionsTotal)
	}
}

// TestRestoringTwiceDoesNotDuplicate keeps startup and a later reload from doubling the
// list, which would make the forensic view report the same event twice.
func TestRestoringTwiceDoesNotDuplicate(t *testing.T) {
	cfg := defaultConfig()
	state := NewState("test", cfg)

	history := []XDRIncident{
		{ID: "a", Time: time.Now().UTC(), Severity: "high"},
		{ID: "b", Time: time.Now().UTC(), Severity: "high"},
	}
	state.RestoreIncidents(history)
	state.RestoreIncidents(history)
	if got := len(state.Snapshot().Incidents); got != 2 {
		t.Fatalf("restoring twice produced %d incidents", got)
	}

	// An entry without an identity cannot be deduplicated, so it is refused rather than
	// silently added twice.
	state.RestoreIncidents([]XDRIncident{{Time: time.Now().UTC()}})
	if got := len(state.Snapshot().Incidents); got != 2 {
		t.Fatalf("an identified-less record was admitted: %d", got)
	}
}
