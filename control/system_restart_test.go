// STATUS: DIAMANT VGT SUPREME
package main

import (
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

// restartFixture builds a server, forces the rate limiter into a known state and swaps
// the exit seam for an observer, so a restart can be exercised without ending the test
// process.
func restartFixture(t *testing.T) (*APIServer, *State, *int32Recorder) {
	t.Helper()
	cfg := defaultConfig()
	state := NewState("test", cfg)

	dir := t.TempDir()
	ledger, err := NewEvidenceLedger(
		dir+"/evidence.jsonl", dir+"/evidence.ed25519", "", "test-node", 4<<20)
	if err != nil {
		t.Fatal(err)
	}
	if err := state.AttachEvidenceLedger(ledger); err != nil {
		t.Fatal(err)
	}

	server := NewAPIServer(cfg, state, nil, nil, nil, nil, nil, nil, fabricTestToken)

	// Each test gets a fresh limiter: the production one is a process-wide singleton and
	// would make the tests order-dependent.
	systemRestartLimiterOnce = sync.Once{}
	systemRestartLimiter = nil

	recorder := &int32Recorder{}
	previousExit := systemRestartExit
	systemRestartExit = recorder.record
	t.Cleanup(func() { systemRestartExit = previousExit })
	return server, state, recorder
}

// waitForExit blocks until a pending restart has fired.
//
// An accepted restart spawns a goroutine that exits after systemRestartDelay. A test that
// returns without waiting leaves that goroutine alive past t.Cleanup, which restores the
// real os.Exit - and the goroutine then ends the test process. Every test that provokes an
// accepted restart must drain it before returning.
func waitForExit(t *testing.T, recorder *int32Recorder) {
	t.Helper()
	deadline := time.Now().Add(5 * systemRestartDelay)
	for recorder.count() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("the pending restart never exited")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// int32Recorder counts exits across goroutines.
type int32Recorder struct {
	mu    sync.Mutex
	calls []int
}

func (r *int32Recorder) record(code int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, code)
}

func (r *int32Recorder) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.calls)
}

// TestRestartRefusesWhenNothingWouldRestartIt is the decisive property.
//
// The mechanism is a clean self-exit that the supervisor undoes. Without a supervisor the
// same exit stops the control plane and leaves it stopped, so the request must be refused
// rather than obeyed. An operator told "restarting" who then finds the dashboard gone has
// been misled exactly when the product needed to be truthful.
func TestRestartRefusesWhenNothingWouldRestartIt(t *testing.T) {
	server, _, recorder := restartFixture(t)
	t.Setenv("INVOCATION_ID", "") // no supervisor

	response := fabricRequest(t, server, http.MethodPost, "/api/v1/system/restart",
		[]byte(`{"reason":"applying the persisted L7 transport change"}`))
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("an unsupervised restart answered %d, want 503", response.Code)
	}
	if !strings.Contains(response.Body.String(), "restart unavailable") {
		t.Fatalf("the refusal does not name the condition: %s", response.Body.String())
	}
	if recorder.count() != 0 {
		t.Fatal("the process exited even though nothing would have restarted it")
	}
}

// TestRestartRequiresAJustification proves the audited action cannot be triggered without
// stating why, and that the recorded text is printable.
func TestRestartRequiresAJustification(t *testing.T) {
	server, _, recorder := restartFixture(t)
	t.Setenv("INVOCATION_ID", "test-invocation")

	for name, body := range map[string]string{
		"empty":     `{}`,
		"too short": `{"reason":"x"}`,
		"control characters": func() string {
			encoded, _ := json.Marshal(map[string]string{"reason": "apply\x07the\x00change"})
			return string(encoded)
		}(),
		"oversized": func() string {
			encoded, _ := json.Marshal(map[string]string{"reason": strings.Repeat("a", systemRestartMaxReason+1)})
			return string(encoded)
		}(),
		"unknown field": `{"reason":"a valid enough reason","extra":true}`,
	} {
		response := fabricRequest(t, server, http.MethodPost, "/api/v1/system/restart", []byte(body))
		if response.Code != http.StatusBadRequest {
			t.Errorf("%s: answered %d, want 400", name, response.Code)
		}
	}
	if recorder.count() != 0 {
		t.Fatal("the process exited on an unjustified request")
	}
}

// TestRestartIsRefusedWhileProtectionIsEnforcing applies the same rule the restart-class
// settings already obey: the control plane is not restarted underneath an active
// protection phase.
func TestRestartIsRefusedWhileProtectionIsEnforcing(t *testing.T) {
	server, state, recorder := restartFixture(t)
	t.Setenv("INVOCATION_ID", "test-invocation")

	state.mu.Lock()
	state.release.Phase = "enforce"
	state.mu.Unlock()

	response := fabricRequest(t, server, http.MethodPost, "/api/v1/system/restart",
		[]byte(`{"reason":"applying the persisted L7 transport change"}`))
	if response.Code != http.StatusConflict {
		t.Fatalf("a restart during enforce answered %d, want 409", response.Code)
	}
	if recorder.count() != 0 {
		t.Fatal("the process exited while protection was enforcing")
	}
}

// TestRestartIsAcceptedUnderASupervisorInObserve is the path the operator asked for: an
// internal restart that works, acknowledges before the socket closes, is evidenced, and
// then exits cleanly so the supervisor brings the persisted revision live.
func TestRestartIsAcceptedUnderASupervisorInObserve(t *testing.T) {
	server, state, recorder := restartFixture(t)
	t.Setenv("INVOCATION_ID", "test-invocation")

	reason := "applying the persisted L7 transport change"
	response := fabricRequest(t, server, http.MethodPost, "/api/v1/system/restart",
		[]byte(`{"reason":"`+reason+`"}`))
	if response.Code != http.StatusAccepted {
		t.Fatalf("a supervised restart answered %d, want 202: %s", response.Code, response.Body.String())
	}

	// The acknowledgement has to be a real document: it is the only thing the operator
	// sees before the connection drops.
	var result SystemRestartResult
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
		t.Fatalf("the acknowledgement is not readable: %v", err)
	}
	if !result.Accepted {
		t.Fatal("the acknowledgement does not report acceptance")
	}
	if result.PendingMilliseconds <= 0 {
		t.Fatal("the acknowledgement does not say how long the operator has")
	}
	if result.Detail == "" {
		t.Fatal("the acknowledgement does not explain what is happening")
	}

	// The intent is in the ledger before the process leaves.
	ledger := state.EvidenceLedger()
	if ledger == nil {
		t.Fatal("the fixture lost its ledger")
	}
	found := false
	for _, record := range ledger.Recent(50) {
		if record.Kind != "system.restart.requested" {
			continue
		}
		found = true
		if !strings.Contains(record.Target, reason) {
			t.Errorf("the evidence record does not carry the reason: %q", record.Target)
		}
	}
	if !found {
		t.Fatal("the restart was not recorded in the evidence ledger")
	}

	// And the exit follows. It is delayed on purpose so the response is delivered first.
	waitForExit(t, recorder)
}

// TestRestartIsRateLimited proves the endpoint cannot be used to hold the control plane
// down by restarting it in a loop.
func TestRestartIsRateLimited(t *testing.T) {
	server, _, recorder := restartFixture(t)
	t.Setenv("INVOCATION_ID", "test-invocation")

	body := []byte(`{"reason":"applying the persisted L7 transport change"}`)
	first := fabricRequest(t, server, http.MethodPost, "/api/v1/system/restart", body)
	if first.Code != http.StatusAccepted {
		t.Fatalf("the first restart answered %d, want 202", first.Code)
	}
	second := fabricRequest(t, server, http.MethodPost, "/api/v1/system/restart", body)
	if second.Code != http.StatusTooManyRequests {
		t.Fatalf("the second restart answered %d, want 429", second.Code)
	}
	if second.Header().Get("Retry-After") == "" {
		t.Fatal("a rate-limited restart does not say when to retry")
	}
	// The first request was accepted, so its exit is still pending. Drain it before the
	// cleanup restores the real os.Exit.
	waitForExit(t, recorder)
}

// TestRestartIsGatedByTheEvidenceLedger proves the restart is an ordinary operator
// mutation: with the ledger unavailable it is refused before it can exit the process.
func TestRestartIsGatedByTheEvidenceLedger(t *testing.T) {
	server, state, recorder := restartFixture(t)
	t.Setenv("INVOCATION_ID", "test-invocation")

	state.mu.Lock()
	state.evidenceErr = errEvidenceBudgetExhausted
	state.mu.Unlock()

	response := fabricRequest(t, server, http.MethodPost, "/api/v1/system/restart",
		[]byte(`{"reason":"applying the persisted L7 transport change"}`))
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("a restart answered %d while the evidence gate was closed, want 503", response.Code)
	}
	if recorder.count() != 0 {
		t.Fatal("the process exited although the restart could not be recorded")
	}
}

// TestSupervisorDetectionReadsTheEnvironment pins the predicate itself. It is the one
// check standing between an operator action and a stopped product.
func TestSupervisorDetectionReadsTheEnvironment(t *testing.T) {
	t.Setenv("INVOCATION_ID", "")
	if supervisedBySystemd() {
		t.Fatal("an unset INVOCATION_ID was reported as supervised")
	}
	t.Setenv("INVOCATION_ID", "   ")
	if supervisedBySystemd() {
		t.Fatal("a blank INVOCATION_ID was reported as supervised")
	}
	t.Setenv("INVOCATION_ID", "8f4a2c1e9b7d4f0a")
	if !supervisedBySystemd() {
		t.Fatal("a set INVOCATION_ID was not reported as supervised")
	}
}
