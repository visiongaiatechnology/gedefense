// STATUS: DIAMANT VGT SUPREME
package main

import (
	"errors"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
)

// TestEvidenceGateDoesNotSealItsOwnExits covers the deadlock the operator hit.
//
// The evidence gate refuses every operator mutation while the ledger is unavailable, so
// that no action is accepted without an audit record. That is the right default and it
// stays true everywhere else. But it also refused the endpoints that are the way out of
// the condition: raising the ledger budget is a settings mutation, so a full ledger
// blocked the only interface-level remedy, and the self-test was refused too - which
// meant the operator saw an evidence failure reported as a traffic-path failure.
func TestEvidenceGateDoesNotSealItsOwnExits(t *testing.T) {
	exempt := []string{
		"/api/v1/release/emergency-stop",
		"/api/v1/l7/selftest",
		"/api/v1/settings/integrity",
	}
	for _, path := range exempt {
		if !evidenceGateExempt(path) {
			t.Errorf("%s is gated behind the condition it exists to resolve", path)
		}
	}

	// Everything else stays gated. The audit guarantee must not have been widened by
	// accident while adding the exits.
	gated := []string{
		"/api/v1/settings/kinetic",
		"/api/v1/settings/system",
		"/api/v1/settings/forensics",
		"/api/v1/release/transition",
		"/api/v1/blocks",
		"/api/v1/transactions",
		"/api/v1/settings/import/apply",
		"",
	}
	for _, path := range gated {
		if evidenceGateExempt(path) {
			t.Errorf("%s was exempted from the evidence gate; the audit guarantee is now wider than intended", path)
		}
	}
}

// TestSelfTestSurvivesAnUnavailableEvidenceLedger proves the exemption works end to end
// through the auth middleware, not only in the predicate.
func TestSelfTestSurvivesAnUnavailableEvidenceLedger(t *testing.T) {
	server, state := evidenceGateFixture(t)

	// A gated mutation must be refused, so the gate is demonstrably still active.
	gated := fabricRequest(t, server, http.MethodPost, "/api/v1/settings/system/preview", []byte(`{}`))
	if gated.Code != http.StatusServiceUnavailable {
		t.Fatalf("a gated endpoint answered %d while the evidence ledger was unavailable; the gate is not active", gated.Code)
	}

	// The condition must still hold immediately before the probe, otherwise the probe
	// would prove nothing about running under it.
	if state.EvidenceHealthy() == nil {
		t.Fatal("the unavailable-ledger condition did not survive the gated request")
	}

	// The self-test must reach its handler and answer with a result document rather than
	// a gate refusal. This is the property under test: a diagnostic stays runnable while
	// the platform is degraded.
	probe := fabricRequest(t, server, http.MethodPost, "/api/v1/l7/selftest", []byte(`{}`))
	if probe.Code == http.StatusServiceUnavailable {
		t.Fatalf("the self-test was refused by the evidence gate: %s", probe.Body.String())
	}
	if probe.Code != http.StatusOK {
		t.Fatalf("the self-test answered %d: %s", probe.Code, probe.Body.String())
	}
	if body := strings.TrimSpace(probe.Body.String()); !strings.HasPrefix(body, "{") {
		t.Fatalf("the self-test did not return a result document: %s", body)
	}
}

// evidenceGateFixture builds a server whose evidence ledger reports itself unavailable,
// with an L7 service attached so the self-test route reaches its real handler.
func evidenceGateFixture(t *testing.T) (*APIServer, *State) {
	t.Helper()
	cfg := defaultConfig()
	state := NewState("test", cfg)

	l7cfg := cfg.L7
	l7cfg.Enabled = true
	l7cfg.InlineEnabled = false
	l7cfg.Socket = ""
	l7cfg.InlineSocket = ""
	engine, err := NewL7Engine(l7cfg, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	service, err := NewL7Service(l7cfg, engine, state)
	if err != nil {
		t.Fatal(err)
	}

	// The gate only engages when a ledger is attached, so the fixture has to attach a
	// real one. Without it the whole block is skipped and the test would pass while
	// proving nothing.
	dir := t.TempDir()
	ledger, err := NewEvidenceLedger(
		filepath.Join(dir, "evidence.jsonl"),
		filepath.Join(dir, "evidence.ed25519"),
		"", "test-node", 4<<20,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := state.AttachEvidenceLedger(ledger); err != nil {
		t.Fatal(err)
	}

	server := NewAPIServer(cfg, state, nil, nil, nil, nil, nil, nil, fabricTestToken)
	server.AttachL7Service(service)

	// Establish the condition the gate reads. The field is unexported and the test lives
	// in the same package, so it is set under the lock it is documented to be read under
	// rather than through production code added only for a test.
	state.mu.Lock()
	state.evidenceErr = errEvidenceBudgetExhausted
	state.mu.Unlock()
	return server, state
}

// TestSelfTestRefusalIsNotReportedAsATrafficVerdict pins the client-side distinction.
// A refusal by the platform carries its own outcome, so the operator is not sent looking
// at the traffic path for a problem that lives in the evidence ledger.
func TestSelfTestRefusalIsNotReportedAsATrafficVerdict(t *testing.T) {
	source := embeddedWebFile(t, "l7-integration.js")

	start := strings.Index(source, "async function runSelfTest()")
	if start < 0 {
		t.Fatal("the self-test runner is gone")
	}
	end := strings.Index(source[start:], "\n}")
	if end < 0 {
		t.Fatal("the self-test runner is unterminated")
	}
	body := source[start : start+end]

	if !strings.Contains(body, "'BLOCKED'") {
		t.Fatal("a platform refusal no longer has its own outcome, so it is reported as a path verdict")
	}
	if !strings.Contains(body, "status === 503") {
		t.Fatal("the runner no longer distinguishes a gate refusal from a path failure")
	}
	if !strings.Contains(body, "l7.integration.selfTestBlocked") {
		t.Fatal("a blocked self-test no longer states that it says nothing about the traffic path")
	}
	// The traffic-path hint belongs to a real FAIL and nowhere else.
	if !strings.Contains(source, "if (outcome === 'FAIL') {") {
		t.Fatal("the traffic-path hint is attached to outcomes it does not describe")
	}
	// The blocked message must be present in every catalogue, otherwise a non-German
	// operator reads a raw key.
	catalogue := embeddedWebFile(t, "i18n.js")
	if count := strings.Count(catalogue, `"l7.integration.selfTestBlocked"`); count != 4 {
		t.Fatalf("the blocked-self-test message exists in %d of 4 catalogues", count)
	}
}

// TestEvidenceGateNamesTheConditionItIsRefusing proves the two causes are told apart.
// They were reported with one string, which left an operator whose ledger was merely
// full with every mutation refused and no indication that the remedy was a setting they
// own - the state the platform was actually found in.
func TestEvidenceGateNamesTheConditionItIsRefusing(t *testing.T) {
	server, state := evidenceGateFixture(t)

	gated := fabricRequest(t, server, http.MethodPost, "/api/v1/settings/system/preview", []byte(`{}`))
	if gated.Code != http.StatusServiceUnavailable {
		t.Fatalf("the gate did not refuse: %d", gated.Code)
	}
	body := gated.Body.String()
	if !strings.Contains(body, "retention budget reached") {
		t.Fatalf("a full ledger was not named as a capacity condition: %s", body)
	}
	if strings.Contains(body, "unavailable") {
		t.Fatalf("a full ledger was still reported as unavailable: %s", body)
	}

	// The counter-case: a genuine integrity failure keeps its own wording and must not
	// be softened into a capacity message, because raising a budget does not fix it.
	state.mu.Lock()
	state.evidenceErr = errors.New("evidence chain verification failed")
	state.mu.Unlock()

	corrupt := fabricRequest(t, server, http.MethodPost, "/api/v1/settings/system/preview", []byte(`{}`))
	if corrupt.Code != http.StatusServiceUnavailable {
		t.Fatalf("a corrupt ledger did not close the gate: %d", corrupt.Code)
	}
	if !strings.Contains(corrupt.Body.String(), "unavailable") {
		t.Fatalf("a corrupt ledger was reported as something else: %s", corrupt.Body.String())
	}
	if strings.Contains(corrupt.Body.String(), "retention budget") {
		t.Fatalf("a corrupt ledger was reported as a capacity condition: %s", corrupt.Body.String())
	}
}
