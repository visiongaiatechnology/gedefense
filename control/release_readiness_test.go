// STATUS: DIAMANT VGT SUPREME
package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestReleaseReadinessEndpoint(t *testing.T) {
	cfg, state, policy, release := betaReleaseFixture(t)
	token := "0123456789abcdef0123456789abcdef"
	server := NewAPIServer(cfg, state, nil, nil, policy, nil, release, nil, token)

	// 1. Unauthorized request must be rejected with 401
	unauthReq := httptest.NewRequest(http.MethodGet, "http://127.0.0.1/api/v1/release/readiness?target=canary", nil)
	unauthReq.Host = "127.0.0.1"
	unauthRec := httptest.NewRecorder()
	server.http.Handler.ServeHTTP(unauthRec, unauthReq)
	if unauthRec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for unauthorized readiness, got %d", unauthRec.Code)
	}

	// 2. Query target=canary (valid from observe phase)
	req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1/api/v1/release/readiness?target=canary", nil)
	req.Host = "127.0.0.1"
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	server.http.Handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 for canary readiness, got %d: %s", rec.Code, rec.Body.String())
	}

	var canaryRes ReleaseReadiness
	if err := json.Unmarshal(rec.Body.Bytes(), &canaryRes); err != nil {
		t.Fatalf("failed to decode readiness JSON: %v", err)
	}
	if canaryRes.Target != "canary" {
		t.Fatalf("expected target=canary, got %s", canaryRes.Target)
	}
	if canaryRes.CurrentPhase != "observe" {
		t.Fatalf("expected current_phase=observe, got %s", canaryRes.CurrentPhase)
	}
	if !canaryRes.Ready {
		t.Fatalf("expected ready=true for canary in fixture, got blockers=%v", canaryRes.Blockers)
	}

	// 3. Query target=enforce (invalid directly from observe phase)
	enforceReq := httptest.NewRequest(http.MethodGet, "http://127.0.0.1/api/v1/release/readiness?target=enforce", nil)
	enforceReq.Host = "127.0.0.1"
	enforceReq.Header.Set("Authorization", "Bearer "+token)
	enforceRec := httptest.NewRecorder()
	server.http.Handler.ServeHTTP(enforceRec, enforceReq)
	if enforceRec.Code != http.StatusOK {
		t.Fatalf("expected 200 for enforce readiness check, got %d: %s", enforceRec.Code, enforceRec.Body.String())
	}

	var enforceRes ReleaseReadiness
	if err := json.Unmarshal(enforceRec.Body.Bytes(), &enforceRes); err != nil {
		t.Fatalf("failed to decode enforce readiness JSON: %v", err)
	}
	if enforceRes.Ready {
		t.Fatalf("expected ready=false for enforce direct promotion from observe")
	}
	foundStageBlocker := false
	for _, b := range enforceRes.Blockers {
		if b == "enforce promotion requires canary phase" {
			foundStageBlocker = true
			break
		}
	}
	if !foundStageBlocker {
		t.Fatalf("expected staged promotion blocker in enforce blockers: %v", enforceRes.Blockers)
	}

	// 4. Invalid target parameter rejected with 400
	badReq := httptest.NewRequest(http.MethodGet, "http://127.0.0.1/api/v1/release/readiness?target=invalid_phase", nil)
	badReq.Host = "127.0.0.1"
	badReq.Header.Set("Authorization", "Bearer "+token)
	badRec := httptest.NewRecorder()
	server.http.Handler.ServeHTTP(badRec, badReq)
	if badRec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid target, got %d", badRec.Code)
	}
}

func TestL7FindingsEndpoint(t *testing.T) {
	cfg, state, policy, release := betaReleaseFixture(t)
	token := "0123456789abcdef0123456789abcdef"
	server := NewAPIServer(cfg, state, nil, nil, policy, nil, release, nil, token)

	// Inject a sample L7 incident into state
	sampleIncident := XDRIncident{
		ID:         "inc-l7-test-01",
		Time:       time.Now().UTC(),
		Severity:   "high",
		Score:      96,
		PID:        4242,
		Process:    "php-fpm",
		Remote:     "198.51.100.23",
		RequestID:  "req-uuid-test-999",
		HTTPMethod: "POST",
		HTTPHost:   "example.org",
		HTTPPath:   "/api/login",
		BodySHA256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		RuleIDs:    []string{"L7.SQLI.UNION_SELECT"},
		Categories: []string{"sqli"},
		Summary:    "SQL Injection attempt in login credentials parameter",
		Decision:   "deny-http",
		Action:     "deny-request",
		Outcome:    "blocked before upstream application handling",
		AttackStory: []AttackStoryNode{
			{
				NodeID:     "http-req-uuid-test-999",
				Timestamp:  time.Now().UTC(),
				Sensor:     "l7",
				Category:   "sqli",
				EventType:  "HTTP_REQUEST",
				EntityID:   "example.org/api/login",
				Actor:      "IP:198.51.100.23",
				Severity:   "high",
				Confidence: 99,
				CausalEdge: EdgeRootCause,
			},
		},
	}
	state.AddIncident(sampleIncident)

	// Query L7 findings endpoint
	req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1/api/v1/l7/findings?limit=10", nil)
	req.Host = "127.0.0.1"
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	server.http.Handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 for l7 findings, got %d: %s", rec.Code, rec.Body.String())
	}

	var res struct {
		Findings []struct {
			ID         string   `json:"id"`
			Severity   string   `json:"severity"`
			Score      int      `json:"score"`
			Confidence int      `json:"confidence"`
			RequestID  string   `json:"request_id"`
			Method     string   `json:"method"`
			Host       string   `json:"host"`
			Path       string   `json:"path"`
			RemoteIP   string   `json:"remote_ip"`
			RuleIDs    []string `json:"rule_ids"`
			Categories []string `json:"categories"`
			BodySHA256 string   `json:"body_sha256"`
			Decision   string   `json:"decision"`
		} `json:"findings"`
		Total int `json:"total"`
	}

	if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil {
		t.Fatalf("failed to decode l7 findings JSON: %v", err)
	}

	if res.Total < 1 || len(res.Findings) < 1 {
		t.Fatalf("expected at least 1 finding, got total=%d len=%d", res.Total, len(res.Findings))
	}

	finding := res.Findings[0]
	if finding.RequestID != "req-uuid-test-999" {
		t.Fatalf("expected request_id req-uuid-test-999, got %s", finding.RequestID)
	}
	if finding.Method != "POST" || finding.Path != "/api/login" {
		t.Fatalf("unexpected method/path: %s %s", finding.Method, finding.Path)
	}
	if finding.Score != 96 || finding.Confidence != 99 {
		t.Fatalf("unexpected score/confidence: %d %d", finding.Score, finding.Confidence)
	}
	if finding.BodySHA256 != "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" {
		t.Fatalf("unexpected body SHA256: %s", finding.BodySHA256)
	}
}
