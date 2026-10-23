// STATUS: DIAMANT VGT SUPREME
// SPDX-FileCopyrightText: 2026 VisionGaia Technology
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type titanAPIFixture struct {
	rig    *titanTestRig
	state  *State
	server *APIServer
}

const titanAPIToken = "titan-test-operator-token"

func newTitanAPIFixture(t *testing.T, mutate func(*titanTestRig)) *titanAPIFixture {
	t.Helper()
	rig := newTitanTestRig(t, mutate)
	state := NewState(titanTestVersion, Config{})
	if err := state.AttachTitan(rig.engine); err != nil {
		t.Fatalf("attach Titan: %v", err)
	}
	server := &APIServer{
		state:   state,
		token:   titanAPIToken,
		replay:  NewReplayGuard(time.Minute),
		limiter: NewRateLimiter(1000, 1000),
	}
	return &titanAPIFixture{rig: rig, state: state, server: server}
}

func (f *titanAPIFixture) do(handler http.HandlerFunc, method, target, body, token, requestID string) *httptest.ResponseRecorder {
	var reader *strings.Reader
	if body == "" {
		reader = strings.NewReader("")
	} else {
		reader = strings.NewReader(body)
	}
	request := httptest.NewRequest(method, target, reader)
	request.Header.Set("Content-Type", "application/json")
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	if requestID != "" {
		request.Header.Set("X-VGT-Request-ID", requestID)
	}
	recorder := httptest.NewRecorder()
	f.server.auth(handler)(recorder, request)
	return recorder
}

func (f *titanAPIFixture) doReview(target, body, token, requestID string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(http.MethodPost, target, strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("X-VGT-Request-ID", requestID)
	// The endpoint identifier is a path value in the real mux; httptest needs it
	// set explicitly for the handler to read.
	parts := strings.Split(strings.TrimRight(target, "/"), "/")
	request.SetPathValue("id", parts[len(parts)-2])
	recorder := httptest.NewRecorder()
	f.server.auth(f.server.titanReview)(recorder, request)
	return recorder
}

func TestTitanAPIAuthentication(t *testing.T) {
	fixture := newTitanAPIFixture(t, nil)
	unauthorized := fixture.do(fixture.server.titanStatus, http.MethodGet, "/api/v1/titan/status", "", "", "")
	if unauthorized.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated status = %d, want 401", unauthorized.Code)
	}
	wrong := fixture.do(fixture.server.titanStatus, http.MethodGet, "/api/v1/titan/status", "", "wrong-token", "")
	if wrong.Code != http.StatusUnauthorized {
		t.Fatalf("wrong token status = %d, want 401", wrong.Code)
	}
	authorized := fixture.do(fixture.server.titanStatus, http.MethodGet, "/api/v1/titan/status", "", titanAPIToken, "")
	if authorized.Code != http.StatusOK {
		t.Fatalf("authenticated status = %d: %s", authorized.Code, authorized.Body.String())
	}
}

func TestTitanAPIStatusAndEventsShapes(t *testing.T) {
	fixture := newTitanAPIFixture(t, nil)
	event := fixture.rig.observe(fixture.rig.write("api.bin", "payload"), TitanChangeCreated)
	statusRecorder := fixture.do(fixture.server.titanStatus, http.MethodGet, "/api/v1/titan/status", "", titanAPIToken, "")
	if statusRecorder.Code != http.StatusOK {
		t.Fatalf("status = %d", statusRecorder.Code)
	}
	var status map[string]json.RawMessage
	if err := json.Unmarshal(statusRecorder.Body.Bytes(), &status); err != nil {
		t.Fatalf("status decode: %v", err)
	}
	for _, key := range []string{"version", "mode", "armed", "auto_contain", "trust", "correlation", "events_total", "open_findings", "quarantine_count", "sensor", "updated_utc"} {
		if _, exists := status[key]; !exists {
			t.Fatalf("status response missing %q", key)
		}
	}

	eventsRecorder := fixture.do(fixture.server.titanEvents, http.MethodGet, "/api/v1/titan/events?limit=1", "", titanAPIToken, "")
	if eventsRecorder.Code != http.StatusOK {
		t.Fatalf("events = %d: %s", eventsRecorder.Code, eventsRecorder.Body.String())
	}
	var page struct {
		Events     []map[string]json.RawMessage `json:"events"`
		NextBefore string                       `json:"next_before"`
	}
	if err := json.Unmarshal(eventsRecorder.Body.Bytes(), &page); err != nil {
		t.Fatalf("events decode: %v", err)
	}
	if len(page.Events) != 1 {
		t.Fatalf("events count = %d, want 1", len(page.Events))
	}
	for _, key := range []string{"id", "observed_utc", "path", "change_type", "trust_state", "authorization_reason", "response", "correlation_quality", "severity", "sensor", "sha256", "size"} {
		if _, exists := page.Events[0][key]; !exists {
			t.Fatalf("event JSON missing %q", key)
		}
	}
	if got := string(page.Events[0]["id"]); !strings.Contains(got, event.ID) {
		t.Fatalf("event id mismatch: %s vs %s", got, event.ID)
	}

	invalidLimit := fixture.do(fixture.server.titanEvents, http.MethodGet, "/api/v1/titan/events?limit=nope", "", titanAPIToken, "")
	if invalidLimit.Code != http.StatusBadRequest {
		t.Fatalf("invalid limit status = %d, want 400", invalidLimit.Code)
	}
	invalidCursor := fixture.do(fixture.server.titanEvents, http.MethodGet, "/api/v1/titan/events?before=@@@", "", titanAPIToken, "")
	if invalidCursor.Code != http.StatusBadRequest {
		t.Fatalf("invalid cursor status = %d, want 400", invalidCursor.Code)
	}
	capped := fixture.do(fixture.server.titanEvents, http.MethodGet, "/api/v1/titan/events?limit=500", "", titanAPIToken, "")
	if capped.Code != http.StatusOK {
		t.Fatalf("capped limit status = %d", capped.Code)
	}
}

func TestTitanAPIPolicyMutation(t *testing.T) {
	fixture := newTitanAPIFixture(t, nil)
	noRequestID := fixture.do(fixture.server.titanSetPolicy, http.MethodPost, "/api/v1/titan/policy", `{"mode":"CONTAIN","armed":true,"auto_contain":true,"reason":"operator enables containment"}`, titanAPIToken, "")
	if noRequestID.Code != http.StatusConflict {
		t.Fatalf("missing request id status = %d, want 409", noRequestID.Code)
	}
	valid := fixture.do(fixture.server.titanSetPolicy, http.MethodPost, "/api/v1/titan/policy", `{"mode":"CONTAIN","armed":true,"auto_contain":true,"reason":"operator enables containment for the pilot"}`, titanAPIToken, "titan-api-policy-0001")
	if valid.Code != http.StatusOK {
		t.Fatalf("valid policy status = %d: %s", valid.Code, valid.Body.String())
	}
	var status TitanStatus
	if err := json.Unmarshal(valid.Body.Bytes(), &status); err != nil {
		t.Fatalf("policy status decode: %v", err)
	}
	if status.Mode != TitanModeContain || !status.Armed || !status.AutoContain {
		t.Fatalf("policy mutation not applied: %+v", status)
	}
	if got := fixture.rig.engine.Status(); got.Mode != TitanModeContain {
		t.Fatalf("engine policy = %q", got.Mode)
	}
	cases := map[string]string{
		"missing-reason":  `{"mode":"OBSERVE","armed":false,"auto_contain":false}`,
		"invalid-mode":    `{"mode":"TURBO","armed":false,"auto_contain":false,"reason":"operator supplies an invalid mode"}`,
		"unknown-field":   `{"mode":"OBSERVE","armed":false,"auto_contain":false,"reason":"operator supplies unknown fields","extra":true}`,
		"trailing-json":   `{"mode":"OBSERVE","armed":false,"auto_contain":false,"reason":"operator supplies trailing JSON"} {}`,
		"control-reason":  `{"mode":"OBSERVE","armed":false,"auto_contain":false,"reason":"operator\u0000reason"}`,
		"short-reason":    `{"mode":"OBSERVE","armed":false,"auto_contain":false,"reason":"short"}`,
		"wrong-body-type": `[]`,
	}
	index := 0
	for name, body := range cases {
		index++
		requestID := "titan-api-policy-bad-" + twoDigits(index)
		recorder := fixture.do(fixture.server.titanSetPolicy, http.MethodPost, "/api/v1/titan/policy", body, titanAPIToken, requestID)
		if recorder.Code != http.StatusBadRequest && recorder.Code != http.StatusConflict {
			t.Fatalf("%s status = %d, want 400/409: %s", name, recorder.Code, recorder.Body.String())
		}
	}
	// A repeated request identifier is rejected by the replay guard.
	replay := fixture.do(fixture.server.titanSetPolicy, http.MethodPost, "/api/v1/titan/policy", `{"mode":"OBSERVE","armed":false,"auto_contain":false,"reason":"operator replays a request identifier"}`, titanAPIToken, "titan-api-policy-0001")
	if replay.Code != http.StatusConflict {
		t.Fatalf("replayed request id status = %d, want 409", replay.Code)
	}
}

func TestTitanAPIReviewAndQuarantine(t *testing.T) {
	fixture := newTitanAPIFixture(t, nil)
	event := fixture.rig.observe(fixture.rig.write("review-api.bin", "payload"), TitanChangeCreated)
	invalidBody := fixture.doReview("/api/v1/titan/events/"+event.ID+"/review", `{"decision":"NOPE","reason":"operator supplies an invalid review decision"}`, titanAPIToken, "titan-api-review-bad-1")
	if invalidBody.Code != http.StatusBadRequest {
		t.Fatalf("invalid review status = %d, want 400", invalidBody.Code)
	}
	unknown := fixture.doReview("/api/v1/titan/events/deadbeefdeadbeef/review", `{"decision":"REVIEWED","reason":"operator reviews an unknown event identifier"}`, titanAPIToken, "titan-api-review-unknown")
	if unknown.Code != http.StatusNotFound {
		t.Fatalf("unknown review status = %d, want 404", unknown.Code)
	}
	valid := fixture.doReview("/api/v1/titan/events/"+event.ID+"/review", `{"decision":"REVIEWED","reason":"operator reviewed the dropped file and closed the finding"}`, titanAPIToken, "titan-api-review-0001")
	if valid.Code != http.StatusOK {
		t.Fatalf("valid review status = %d: %s", valid.Code, valid.Body.String())
	}
	var reviewResponse struct {
		Status string     `json:"status"`
		Event  TitanEvent `json:"event"`
	}
	if err := json.Unmarshal(valid.Body.Bytes(), &reviewResponse); err != nil {
		t.Fatalf("review decode: %v", err)
	}
	if reviewResponse.Status != "ok" || reviewResponse.Event.Review != "REVIEWED" {
		t.Fatalf("review response is wrong: %+v", reviewResponse)
	}
	quarantine := fixture.do(fixture.server.titanQuarantine, http.MethodGet, "/api/v1/titan/quarantine", "", titanAPIToken, "")
	if quarantine.Code != http.StatusOK {
		t.Fatalf("quarantine status = %d", quarantine.Code)
	}
	var quarantinePayload struct {
		Items []map[string]json.RawMessage `json:"items"`
		Count int                          `json:"count"`
	}
	if err := json.Unmarshal(quarantine.Body.Bytes(), &quarantinePayload); err != nil {
		t.Fatalf("quarantine decode: %v", err)
	}
	if quarantinePayload.Count != 0 || len(quarantinePayload.Items) != 0 {
		t.Fatalf("unexpected quarantine payload: %+v", quarantinePayload)
	}
}

func TestTitanAPIContainment(t *testing.T) {
	fixture := newTitanAPIFixture(t, nil)
	event := fixture.rig.observe(fixture.rig.write("contain-api.bin", "payload"), TitanChangeCreated)
	unknown := fixture.do(fixture.server.titanContain, http.MethodPost, "/api/v1/titan/contain", `{"event_id":"deadbeefdeadbeef","reason":"operator contains an unknown event identifier"}`, titanAPIToken, "titan-api-contain-unknown")
	if unknown.Code != http.StatusNotFound {
		t.Fatalf("unknown containment status = %d, want 404", unknown.Code)
	}
	invalid := fixture.do(fixture.server.titanContain, http.MethodPost, "/api/v1/titan/contain", `{"event_id":"`+event.ID+`"}`, titanAPIToken, "titan-api-contain-invalid")
	if invalid.Code != http.StatusBadRequest {
		t.Fatalf("invalid containment status = %d, want 400", invalid.Code)
	}
	contained := fixture.do(fixture.server.titanContain, http.MethodPost, "/api/v1/titan/contain", `{"event_id":"`+event.ID+`","reason":"operator contains a suspicious dropped file"}`, titanAPIToken, "titan-api-contain-0001")
	if contained.Code != http.StatusOK {
		t.Fatalf("containment status = %d: %s", contained.Code, contained.Body.String())
	}
	var response struct {
		Status string `json:"status"`
		Action string `json:"action"`
		Detail string `json:"detail"`
	}
	if err := json.Unmarshal(contained.Body.Bytes(), &response); err != nil {
		t.Fatalf("containment decode: %v", err)
	}
	if response.Status != "CONTAINED" || response.Action != "QUARANTINE" || response.Detail == "" {
		t.Fatalf("containment response is not honest: %+v", response)
	}
	quarantine := fixture.do(fixture.server.titanQuarantine, http.MethodGet, "/api/v1/titan/quarantine", "", titanAPIToken, "")
	var quarantinePayload TitanQuarantineStatus
	if err := json.Unmarshal(quarantine.Body.Bytes(), &quarantinePayload); err != nil {
		t.Fatalf("quarantine decode: %v", err)
	}
	if quarantinePayload.Count != 1 || len(quarantinePayload.Items) != 1 || quarantinePayload.Items[0].EventID != event.ID {
		t.Fatalf("quarantine view is incomplete: %+v", quarantinePayload)
	}
}

func TestTitanAPIUnavailableAndMalformedInput(t *testing.T) {
	// An API server whose state carries no Titan engine must return the explicit
	// unavailable state instead of a fabricated success.
	bareState := NewState(titanTestVersion, Config{})
	bare := &APIServer{state: bareState, token: titanAPIToken, replay: NewReplayGuard(time.Minute), limiter: NewRateLimiter(1000, 1000)}
	unavailableRequest := httptest.NewRequest(http.MethodGet, "/api/v1/titan/status", nil)
	unavailableRequest.Header.Set("Authorization", "Bearer "+titanAPIToken)
	unavailable := httptest.NewRecorder()
	bare.auth(bare.titanStatus)(unavailable, unavailableRequest)
	if unavailable.Code != http.StatusServiceUnavailable {
		t.Fatalf("unavailable status = %d, want 503", unavailable.Code)
	}
	if !strings.Contains(unavailable.Body.String(), "Titan engine unavailable") {
		t.Fatalf("unavailable response is not explicit: %s", unavailable.Body.String())
	}
	unavailableEventsRequest := httptest.NewRequest(http.MethodGet, "/api/v1/titan/events", nil)
	unavailableEventsRequest.Header.Set("Authorization", "Bearer "+titanAPIToken)
	unavailableEvents := httptest.NewRecorder()
	bare.auth(bare.titanEvents)(unavailableEvents, unavailableEventsRequest)
	if unavailableEvents.Code != http.StatusServiceUnavailable {
		t.Fatalf("unavailable events = %d, want 503", unavailableEvents.Code)
	}

	fixture := newTitanAPIFixture(t, nil)
	bodies := []string{
		"", "{}", "null", "[]", `{"feeds":[]}`,
		`{"event_id":"` + strings.Repeat("a", 500) + `","reason":"operator uses an oversized event identifier"}`,
		`{"event_id":"deadbeefdeadbeef","reason":"` + strings.Repeat("r", 5000) + `"}`,
		strings.Repeat("{", 200),
		`{"reason":"` + strings.Repeat("\u00e4", 300) + `"}`,
	}
	requestIndex := 0
	for _, body := range bodies {
		requestIndex++
		func() {
			defer func() {
				if recovered := recover(); recovered != nil {
					t.Fatalf("Titan policy handler panicked on malformed body: %v", recovered)
				}
			}()
			recorder := fixture.do(fixture.server.titanSetPolicy, http.MethodPost, "/api/v1/titan/policy", body, titanAPIToken, "titan-api-malformed-"+twoDigits(requestIndex))
			if recorder.Code >= 500 && recorder.Code != http.StatusServiceUnavailable {
				t.Fatalf("malformed body produced server fault %d", recorder.Code)
			}
		}()
	}
	reviewRequest := httptest.NewRequest(http.MethodPost, "/api/v1/titan/events/"+strings.Repeat("a", 500)+"/review", strings.NewReader(`{"decision":"REVIEWED","reason":"operator reviews a malformed event identifier"}`))
	reviewRequest.Header.Set("Content-Type", "application/json")
	reviewRequest.Header.Set("Authorization", "Bearer "+titanAPIToken)
	reviewRequest.Header.Set("X-VGT-Request-ID", "titan-api-malformed-review")
	reviewRequest.SetPathValue("id", strings.Repeat("a", 500))
	reviewRecorder := httptest.NewRecorder()
	func() {
		defer func() {
			if recovered := recover(); recovered != nil {
				t.Fatalf("Titan review handler panicked: %v", recovered)
			}
		}()
		fixture.server.auth(fixture.server.titanReview)(reviewRecorder, reviewRequest)
	}()
	if reviewRecorder.Code != http.StatusBadRequest {
		t.Fatalf("oversized review id status = %d, want 400", reviewRecorder.Code)
	}
}
