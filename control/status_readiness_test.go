// STATUS: DIAMANT VGT SUPREME
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// The dashboard snapshot is the single frame the interface renders from. Two properties are pinned
// here: it carries the release readiness (so the client does not have to poll it beside the status),
// and it leaves out the per-incident attack story (which made the frame 12.9 MB on the production
// host while the timeline row never rendered it).
func TestStatusSnapshotCarriesReleaseReadiness(t *testing.T) {
	cfg, state, policy, release := betaReleaseFixture(t)
	token := "0123456789abcdef0123456789abcdef"
	server := NewAPIServer(cfg, state, nil, nil, policy, nil, release, nil, token)

	req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1/api/v1/status", nil)
	req.Host = "127.0.0.1"
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	server.http.Handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 for status, got %d: %s", rec.Code, rec.Body.String())
	}

	var payload struct {
		Readiness *ReleaseReadinessSet `json:"readiness"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("failed to decode status JSON: %v", err)
	}
	if payload.Readiness == nil {
		t.Fatal("the status snapshot does not carry release readiness; the dashboard would have to poll it separately")
	}
	if payload.Readiness.Canary.Target != ReleasePhaseCanary {
		t.Fatalf("expected readiness for canary, got %q", payload.Readiness.Canary.Target)
	}
	if payload.Readiness.Enforce.Target != ReleasePhaseEnforce {
		t.Fatalf("expected readiness for enforce, got %q", payload.Readiness.Enforce.Target)
	}

	wantCanary, err := release.Readiness(ReleasePhaseCanary)
	if err != nil {
		t.Fatalf("release controller refused canary readiness: %v", err)
	}
	if payload.Readiness.Canary.Ready != wantCanary.Ready {
		t.Fatalf("status readiness and release controller disagree on canary: %v vs %v",
			payload.Readiness.Canary.Ready, wantCanary.Ready)
	}
	wantEnforce, err := release.Readiness(ReleasePhaseEnforce)
	if err != nil {
		t.Fatalf("release controller refused enforce readiness: %v", err)
	}
	if payload.Readiness.Enforce.Ready != wantEnforce.Ready {
		t.Fatalf("status readiness and release controller disagree on enforce: %v vs %v",
			payload.Readiness.Enforce.Ready, wantEnforce.Ready)
	}
	// Enforce cannot be promoted directly from observe. The blocker proves the snapshot carries
	// the real gate decision and not an empty placeholder.
	if payload.Readiness.Enforce.Ready {
		t.Fatalf("expected enforce readiness to be blocked in observe phase, got blockers=%v",
			payload.Readiness.Enforce.Blockers)
	}
}

func TestStreamSnapshotCarriesReleaseReadiness(t *testing.T) {
	cfg, state, policy, release := betaReleaseFixture(t)
	token := "0123456789abcdef0123456789abcdef"
	server := NewAPIServer(cfg, state, nil, nil, policy, nil, release, nil, token)
	httpServer := httptest.NewServer(server.http.Handler)
	defer httpServer.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, httpServer.URL+"/api/v1/stream", nil)
	if err != nil {
		t.Fatalf("failed to build stream request: %v", err)
	}
	req.Host = "127.0.0.1"
	req.Header.Set("Authorization", "Bearer "+token)
	response, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("stream request failed: %v", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 for stream, got %d", response.StatusCode)
	}

	reader := bufio.NewReader(response.Body)
	var dataLine string
	for dataLine == "" {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("stream ended before the snapshot frame: %v", err)
		}
		if strings.HasPrefix(line, "data: ") {
			dataLine = strings.TrimSpace(strings.TrimPrefix(line, "data: "))
		}
	}

	var payload struct {
		Readiness *ReleaseReadinessSet `json:"readiness"`
	}
	if err := json.Unmarshal([]byte(dataLine), &payload); err != nil {
		t.Fatalf("failed to decode the stream snapshot: %v", err)
	}
	if payload.Readiness == nil {
		t.Fatal("the stream's initial snapshot does not carry release readiness")
	}
	if payload.Readiness.Canary.Target != ReleasePhaseCanary || payload.Readiness.Enforce.Target != ReleasePhaseEnforce {
		t.Fatalf("unexpected readiness targets in the stream snapshot: %q, %q",
			payload.Readiness.Canary.Target, payload.Readiness.Enforce.Target)
	}
}

func TestStatusSnapshotDropsAttackStoryButKeepsItInState(t *testing.T) {
	cfg, state, policy, release := betaReleaseFixture(t)
	token := "0123456789abcdef0123456789abcdef"
	server := NewAPIServer(cfg, state, nil, nil, policy, nil, release, nil, token)

	// A story large enough to dominate the frame is exactly the shape the production host had:
	// hundreds of nodes per correlated incident.
	const nodeCount = 300
	nodes := make([]AttackStoryNode, 0, nodeCount)
	for index := 0; index < nodeCount; index++ {
		nodes = append(nodes, AttackStoryNode{
			NodeID:     fmt.Sprintf("node-%03d", index),
			Timestamp:  time.Now().UTC(),
			Sensor:     "xdr",
			Category:   "scan",
			EventType:  "NETWORK",
			EntityID:   "10.0.0.1",
			Actor:      "IP:10.0.0.1",
			Severity:   "high",
			Confidence: 80,
		})
	}
	state.AddIncident(XDRIncident{
		ID:          "incident-heavy-story",
		Time:        time.Now().UTC(),
		Severity:    "high",
		Score:       70,
		Summary:     "heavy correlated incident",
		RuleIDs:     []string{"XDR.STORY"},
		Categories:  []string{"scan"},
		AttackStory: nodes,
	})

	req := httptest.NewRequest(http.MethodGet, "http://127.0.0.1/api/v1/status", nil)
	req.Host = "127.0.0.1"
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	server.http.Handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 for status, got %d: %s", rec.Code, rec.Body.String())
	}

	var payload struct {
		Incidents []struct {
			ID          string            `json:"id"`
			AttackStory []AttackStoryNode `json:"attack_story"`
		} `json:"incidents"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("failed to decode status JSON: %v", err)
	}
	found := false
	for _, incident := range payload.Incidents {
		if incident.ID == "incident-heavy-story" {
			found = true
			if len(incident.AttackStory) != 0 {
				t.Fatalf("the status frame still carries %d attack-story nodes", len(incident.AttackStory))
			}
		}
	}
	if !found {
		t.Fatal("the injected incident is missing from the status snapshot")
	}

	// The state keeps the story: the trimming belongs to the dashboard frame, not to the record.
	found = false
	for _, incident := range state.Snapshot().Incidents {
		if incident.ID == "incident-heavy-story" {
			found = true
			if len(incident.AttackStory) != nodeCount {
				t.Fatalf("state lost the attack story: have %d nodes, want %d",
					len(incident.AttackStory), nodeCount)
			}
		}
	}
	if !found {
		t.Fatal("the injected incident is missing from the state snapshot")
	}
}
