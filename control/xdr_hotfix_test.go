package main

import (
	"strings"
	"testing"
	"time"
)

// F-HOTFIX-3 regression: a contain decision must never fall through to an
// untracked SIGSTOP when the reversible response engine is unavailable.
func TestContainRefusesUntrackedFreezeWithoutResponseEngine(t *testing.T) {
	cfg := Config{}
	cfg.XDR.DedupeSeconds = 120
	state := NewState("test", cfg)
	state.SetModes("enforce", "contain")
	engine := &XDREngine{
		cfg:    cfg,
		state:  state,
		dedupe: make(map[string]time.Time),
		core:   &CoreClient{},
	}
	incident := XDRIncident{
		ID: "inc-hotfix", Time: time.Now().UTC(), PID: 4242, StartTicks: 7,
		Decision: "contain", Score: 95, ResponseScore: 95,
		RuleIDs: []string{"XDR.HOTFIX_TEST"},
	}
	action, outcome := engine.respond(incident)
	if strings.Contains(outcome, "privileged broker") || strings.Contains(outcome, "process frozen") {
		t.Fatalf("untracked freeze reached the privileged core: action=%q outcome=%q", action, outcome)
	}
	if !strings.Contains(outcome, "refused") {
		t.Fatalf("expected an explicit refusal without a response engine: action=%q outcome=%q", action, outcome)
	}
}
