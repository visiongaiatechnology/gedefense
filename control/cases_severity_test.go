// STATUS: DIAMANT VGT SUPREME
package main

import "testing"

// The display form is what Morpheus RASP, the StyX egress/beacon engines and the
// deception engine actually emit. Before the boundary normalisation these incidents
// were dropped by the case gate while state.go recorded a successful ingest, so the
// highest-scored detections of the product never reached the case store.
func TestCaseEngineIngestsDisplayFormSeverity(t *testing.T) {
	engine, _, _ := newTestCaseEngine(t, func(EvidenceRecord) error { return nil })

	if err := engine.IngestIncident(testCaseIncident("incident-upper", "CRITICAL")); err != nil {
		t.Fatalf("uppercase severity must be ingested, got %v", err)
	}
	status := engine.Status(10)
	if status.Count != 1 {
		t.Fatalf("expected exactly 1 case, got %d", status.Count)
	}
	if got := status.Cases[0].Severity; got != "critical" {
		t.Fatalf("case severity = %q, want %q", got, "critical")
	}
	if got := status.Cases[0].Confidence; got != "high" {
		t.Fatalf("case confidence = %q, want %q", got, "high")
	}
	if !status.Healthy {
		t.Fatalf("case store reported unhealthy: %s", status.Error)
	}
}

// Trim plus lower-case must cover the whole producer surface, not one spelling.
func TestCaseEngineAcceptsMixedCaseProducerSeverities(t *testing.T) {
	for _, severity := range []string{"CRITICAL", "Critical", " critical ", "HIGH", "High"} {
		engine, _, _ := newTestCaseEngine(t, func(EvidenceRecord) error { return nil })
		if err := engine.IngestIncident(testCaseIncident("incident-"+severity, severity)); err != nil {
			t.Fatalf("severity %q: unexpected error %v", severity, err)
		}
		if got := engine.Status(10).Count; got != 1 {
			t.Fatalf("severity %q: expected 1 case, got %d", severity, got)
		}
	}
}

// "info" and "low" are legitimate observation-only levels: no case and no error. An
// error here would feed noteCaseHistoryFailure and degrade the platform for an
// incident that is correctly not a case.
func TestCaseEngineKeepsObservationSeveritiesCased(t *testing.T) {
	for _, severity := range []string{"info", "low", "INFO", "Low"} {
		engine, _, _ := newTestCaseEngine(t, func(EvidenceRecord) error { return nil })
		if err := engine.IngestIncident(testCaseIncident("incident-"+severity, severity)); err != nil {
			t.Fatalf("severity %q must not be an error, got %v", severity, err)
		}
		if got := engine.Status(10).Count; got != 0 {
			t.Fatalf("severity %q: expected 0 cases, got %d", severity, got)
		}
	}
}

// A value outside the closed vocabulary is a producer bug. It must be reported so
// noteCaseHistoryFailure can surface it, instead of the store claiming success.
func TestCaseEngineRejectsUnknownSeverity(t *testing.T) {
	engine, _, _ := newTestCaseEngine(t, func(EvidenceRecord) error { return nil })
	if err := engine.IngestIncident(testCaseIncident("incident-unknown", "catastrophic")); err == nil {
		t.Fatal("an unknown severity must be reported, got nil")
	}
	if got := engine.Status(10).Count; got != 0 {
		t.Fatalf("expected 0 cases, got %d", got)
	}
}

// The state is the single boundary every incident passes: appendIncident and the two
// direct AddIncident callers. It must normalise before the fingerprint, the case
// engine and the dashboard snapshot see the value.
func TestStateAddIncidentNormalisesDisplaySeverity(t *testing.T) {
	state := NewState("test", defaultConfig())
	engine, _, _ := newTestCaseEngine(t, func(EvidenceRecord) error { return nil })
	if err := state.AttachCases(engine); err != nil {
		t.Fatal(err)
	}

	state.AddIncident(testCaseIncident("incident-state-upper", "CRITICAL"))

	snapshot := state.Snapshot()
	if len(snapshot.Incidents) != 1 {
		t.Fatalf("expected 1 incident in the snapshot, got %d", len(snapshot.Incidents))
	}
	if got := snapshot.Incidents[0].Severity; got != "critical" {
		t.Fatalf("snapshot severity = %q, want %q", got, "critical")
	}

	status := engine.Status(10)
	if status.Count != 1 {
		t.Fatalf("expected 1 case from a display-form severity, got %d", status.Count)
	}
	if got := status.Cases[0].Severity; got != "critical" {
		t.Fatalf("case severity = %q, want %q", got, "critical")
	}
}
