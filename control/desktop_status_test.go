// STATUS: DIAMANT VGT SUPREME
// SPDX-FileCopyrightText: 2026 VisionGaia Technology
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func desktopTestSnapshot() Snapshot {
	return Snapshot{
		Version: "4.2.4", NodeName: "test-node", CoreConnected: true, Enforcement: "enforce",
		XDR:      XDRStatus{Enabled: true, Mode: "enforce", Sensor: "fanotify-exec+procfs-fallback"},
		Release:  ReleaseStatus{Phase: ReleasePhaseEnforce, KernelPolicyState: "verified-enforce", FailSafeVerified: true},
		Evidence: EvidenceStatus{Enabled: true, Healthy: true},
		FIM:      FIMStatus{Enabled: true, Health: "VERIFIED"},
	}
}

// TestDesktopStatusDerivation pins the mapping from state to indicator, including the decision that
// a blocked attack is not an alarm.
func TestDesktopStatusDerivation(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	window := 10 * time.Minute
	recent := now.Add(-2 * time.Minute)
	old := now.Add(-2 * time.Hour)

	cases := []struct {
		name   string
		mutate func(*Snapshot)
		want   string
		reason string
	}{
		{"healthy platform is secure", func(s *Snapshot) {}, desktopStateSecure, "Durchsetzung aktiv"},
		{"core missing stops the protection", func(s *Snapshot) { s.CoreConnected = false }, desktopStateStopped, "Kern nicht verbunden"},
		{"observe enforcement stops the protection", func(s *Snapshot) { s.Enforcement = "observe" }, desktopStateStopped, "Schutz nicht aktiv"},
		{"tampered file is an alert", func(s *Snapshot) { s.FIM.Health = "TAMPERED" }, desktopStateAlert, "Systemintegrität verletzt"},
		{"critical incident inside the window is an alert", func(s *Snapshot) {
			s.Incidents = []XDRIncident{{Time: recent, Severity: "critical", Summary: "malware blocked"}}
		}, desktopStateAlert, "Kritischer Vorfall"},
		{"critical incident outside the window is not an alert", func(s *Snapshot) {
			s.Incidents = []XDRIncident{{Time: old, Severity: "critical", Summary: "malware blocked"}}
		}, desktopStateSecure, ""},
		{"high incident inside the window is a warning", func(s *Snapshot) {
			s.Incidents = []XDRIncident{{Time: recent, Severity: "high", Summary: "port scan"}}
		}, desktopStateWarning, "hoher Schwere"},
		{"degraded XDR is a warning because enforcement stays", func(s *Snapshot) {
			s.XDR.Degraded = true
			s.XDR.DegradedReason = "incident log rotation failed"
		}, desktopStateWarning, "Automatik ausgesetzt"},
		{"a phase below enforce is a warning", func(s *Snapshot) { s.Release.Phase = ReleasePhaseCanary }, desktopStateWarning, "Freigabephase"},
		{"an unhealthy evidence ledger is a warning", func(s *Snapshot) { s.Evidence.Healthy = false }, desktopStateWarning, "Forensik-Ledger"},
		{"a blocked attack keeps the indicator calm", func(s *Snapshot) {
			s.Blocks = []BlockEntry{{Target: "203.0.113.9", Enforced: true, CreatedAt: recent}}
		}, desktopStateSecure, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			snapshot := desktopTestSnapshot()
			tc.mutate(&snapshot)
			decision := deriveDesktopStatus(snapshot, now, window)
			if decision.Status != tc.want {
				t.Fatalf("status = %q, want %q (reason %q)", decision.Status, tc.want, decision.Reason)
			}
			if tc.reason != "" && !strings.Contains(decision.Reason, tc.reason) {
				t.Fatalf("reason %q does not name %q", decision.Reason, tc.reason)
			}
			if decision.Reason == "" {
				t.Fatal("a decision without a reason is the defect this telegram exists to avoid")
			}
		})
	}
}

// TestDesktopThreatCountCountsTodayOnly keeps the number honest: a lifetime counter would never
// reset and the indicator would claim a day that is not today.
func TestDesktopThreatCountCountsTodayOnly(t *testing.T) {
	now := time.Date(2026, 10, 16, 15, 30, 0, 0, time.UTC)
	yesterday := time.Date(2026, 10, 15, 23, 59, 0, 0, time.UTC)
	todayEarly := time.Date(2026, 10, 16, 0, 0, 1, 0, time.UTC)
	todayLate := time.Date(2026, 10, 16, 15, 0, 0, 0, time.UTC)
	blocks := []BlockEntry{
		{Target: "a", CreatedAt: yesterday},
		{Target: "b", CreatedAt: todayEarly},
		{Target: "c", CreatedAt: todayLate},
		{Target: "d"},
	}
	if got := threatsToday(blocks, now); got != 2 {
		t.Fatalf("threats today = %d, want 2", got)
	}
	if got := enforcedBlockCount([]BlockEntry{{Enforced: true}, {Enforced: false}, {Enforced: true}}); got != 2 {
		t.Fatalf("enforced blocks = %d, want 2", got)
	}
}

// TestDesktopTelegramStaysInsideTheBudget is the resource ceiling: hostile incident text must not be
// able to grow the telegram beyond the protocol limit, and a cut must not split a rune.
func TestDesktopTelegramStaysInsideTheBudget(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	snapshot := desktopTestSnapshot()
	snapshot.Incidents = []XDRIncident{{
		Time: now.Add(-time.Minute), Severity: "high",
		Summary: strings.Repeat("ä", 4000) + "\x00\x1b[31mcontrol",
	}}
	payload := buildDesktopStatus(snapshot, now, 10*time.Minute)
	data, err := encodeDesktopPayload(payload)
	if err != nil {
		t.Fatalf("telegram rejected its own bounded payload: %v", err)
	}
	if len(data) > desktopResponseLimit {
		t.Fatalf("telegram is %d bytes, limit is %d", len(data), desktopResponseLimit)
	}
	if !json.Valid(data) {
		t.Fatal("telegram is not valid JSON")
	}
	if strings.ContainsAny(payload.LastAnomalyText, "\x00\x1b") {
		t.Fatalf("control characters survived the bound: %q", payload.LastAnomalyText)
	}
	if len(payload.LastAnomalyText) > desktopSummaryLimit {
		t.Fatalf("summary is %d bytes, limit is %d", len(payload.LastAnomalyText), desktopSummaryLimit)
	}
	// A long sensor string and node name must be bounded too, not copied through.
	snapshot.XDR.Sensor = strings.Repeat("s", 500)
	snapshot.NodeName = strings.Repeat("n", 500)
	bounded := buildDesktopStatus(snapshot, now, 10*time.Minute)
	if len(bounded.Sensor) > 96 || len(bounded.NodeName) > 64 {
		t.Fatalf("unbounded text reached the telegram: sensor=%d node=%d", len(bounded.Sensor), len(bounded.NodeName))
	}
}

// TestDesktopRequestValidation is the allowlist: one operation, one version, nothing else.
func TestDesktopRequestValidation(t *testing.T) {
	valid := []string{
		`{"v":1,"op":"status"}` + "\n",
		`{"v":1,"op":"STATUS"}` + "\n",
		"  {\"v\":1,\"op\":\" status \"}\n",
	}
	for _, request := range valid {
		if err := validateDesktopRequest([]byte(request)); err != nil {
			t.Fatalf("valid request rejected: %q: %v", request, err)
		}
	}
	invalid := map[string]string{
		"wrong version":  `{"v":2,"op":"status"}` + "\n",
		"unknown op":     `{"v":1,"op":"shutdown"}` + "\n",
		"extra field":    `{"v":1,"op":"status","path":"/etc/shadow"}` + "\n",
		"trailing data":  `{"v":1,"op":"status"}{"v":1,"op":"status"}` + "\n",
		"not json":       "GET / HTTP/1.1\n",
		"empty object":   "{}\n",
		"wrong type":     `{"v":"1","op":"status"}` + "\n",
		"array payload":  `["status"]` + "\n",
		"nested payload": `{"v":1,"op":{"name":"status"}}` + "\n",
	}
	for name, request := range invalid {
		if err := validateDesktopRequest([]byte(request)); err == nil {
			t.Fatalf("%s was accepted: %q", name, request)
		}
	}
}

func startDesktopTestServer(t *testing.T, mutate func(*DesktopConfig)) (string, *DesktopStatusServer) {
	t.Helper()
	cfg := defaultDesktopConfig()
	cfg.SocketPath = filepath.Join(t.TempDir(), "gedefense.sock")
	// The group exists only on a provisioned host; the test socket must not depend on it.
	cfg.SocketGroup = ""
	if mutate != nil {
		mutate(&cfg)
	}
	server := NewDesktopStatusServer(cfg, NewState("test-node", defaultConfig()))
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		if err := server.Start(ctx); err != nil {
			t.Errorf("desktop server: %v", err)
		}
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("desktop server did not stop")
		}
	})
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(cfg.SocketPath); err == nil {
			return cfg.SocketPath, server
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("desktop socket never appeared")
	return "", nil
}

func desktopRoundTrip(t *testing.T, path, request string) (string, error) {
	t.Helper()
	conn, err := net.DialTimeout("unix", path, 2*time.Second)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write([]byte(request)); err != nil {
		return "", err
	}
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil && line == "" {
		return "", err
	}
	return line, nil
}

// TestDesktopSocketServesTheTelegram is the end-to-end protocol proof over a real socket.
func TestDesktopSocketServesTheTelegram(t *testing.T) {
	path, _ := startDesktopTestServer(t, nil)
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o660 {
		t.Fatalf("socket mode is %o, want 660", info.Mode().Perm())
	}
	if info.Mode()&os.ModeSocket == 0 {
		t.Fatal("the path is not a socket")
	}
	line, err := desktopRoundTrip(t, path, `{"v":1,"op":"status"}`+"\n")
	if err != nil {
		t.Fatalf("round trip failed: %v", err)
	}
	var payload desktopStatusPayload
	if err := json.Unmarshal([]byte(line), &payload); err != nil {
		t.Fatalf("telegram is not valid JSON: %v (%q)", err, line)
	}
	if payload.Version != desktopStatusProtocolVersion {
		t.Fatalf("protocol version = %d", payload.Version)
	}
	switch payload.Status {
	case desktopStateSecure, desktopStateWarning, desktopStateAlert, desktopStateStopped:
	default:
		t.Fatalf("unknown status %q", payload.Status)
	}
	if payload.StatusReason == "" {
		t.Fatal("telegram carries no reason")
	}
	if len(line) > desktopResponseLimit {
		t.Fatalf("telegram is %d bytes", len(line))
	}
}

// TestDesktopSocketRejectsHostileRequests proves the boundary: malformed, oversized and unknown
// requests are answered with a bounded error and never with state.
func TestDesktopSocketRejectsHostileRequests(t *testing.T) {
	path, _ := startDesktopTestServer(t, nil)
	oversized := `{"v":1,"op":"status","pad":"` + strings.Repeat("A", desktopRequestLimit*2) + `"}` + "\n"
	cases := map[string]string{
		"unknown operation": `{"v":1,"op":"export-everything"}` + "\n",
		"wrong version":     `{"v":9,"op":"status"}` + "\n",
		"oversized":         oversized,
		"garbage":           strings.Repeat("\x00\xff", 64) + "\n",
	}
	for name, request := range cases {
		t.Run(name, func(t *testing.T) {
			line, err := desktopRoundTrip(t, path, request)
			if err != nil && line == "" {
				// A closed connection is a valid refusal for unparseable input.
				return
			}
			if strings.Contains(line, "status_reason") || strings.Contains(line, "product_version") {
				t.Fatalf("a refused request received state: %q", line)
			}
			if len(line) > desktopResponseLimit {
				t.Fatalf("refusal is %d bytes", len(line))
			}
		})
	}
	// The service is still healthy after the hostile batch.
	line, err := desktopRoundTrip(t, path, `{"v":1,"op":"status"}`+"\n")
	if err != nil || !strings.Contains(line, "\"v\":1") {
		t.Fatalf("the socket did not survive hostile input: %v %q", err, line)
	}
}

// TestDesktopSocketBoundsConnectionsAndRate keeps one local identity from occupying the socket.
func TestDesktopSocketBoundsConnectionsAndRate(t *testing.T) {
	path, _ := startDesktopTestServer(t, func(cfg *DesktopConfig) {
		cfg.MaxConnectionsPerUser = 1
		cfg.RateLimitPerMinute = 60
		cfg.RateLimitBurst = 1
	})
	first, err := net.DialTimeout("unix", path, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	// The first connection holds the only slot for this identity.
	time.Sleep(100 * time.Millisecond)
	line, err := desktopRoundTrip(t, path, `{"v":1,"op":"status"}`+"\n")
	if err != nil && line == "" {
		t.Fatalf("the second connection was closed instead of answered: %v", err)
	}
	if !strings.Contains(line, "\"error\"") {
		t.Fatalf("the connection cap did not apply: %q", line)
	}
}

// TestDesktopSocketRefusesASecondServer keeps two control planes from fighting over one socket.
func TestDesktopSocketRefusesASecondServer(t *testing.T) {
	path, _ := startDesktopTestServer(t, nil)
	cfg := defaultDesktopConfig()
	cfg.SocketPath = path
	cfg.SocketGroup = ""
	second := NewDesktopStatusServer(cfg, NewState("test-node", defaultConfig()))
	err := second.Start(context.Background())
	if err == nil || !strings.Contains(err.Error(), "already served") {
		t.Fatalf("a second server did not refuse a live socket: %v", err)
	}
}

// TestDesktopSocketPathGuards rejects unclean or unrelated paths instead of deleting them.
func TestDesktopSocketPathGuards(t *testing.T) {
	if err := prepareDesktopSocketPath("relative/gedefense.sock"); err == nil {
		t.Fatal("a relative path was accepted")
	}
	if err := prepareDesktopSocketPath("/tmp/../tmp/gedefense.sock"); err == nil {
		t.Fatal("an unclean path was accepted")
	}
	if err := prepareDesktopSocketPath("/" + strings.Repeat("a", 120) + ".sock"); err == nil {
		t.Fatal("an overlong path was accepted")
	}
	file := filepath.Join(t.TempDir(), "regular.txt")
	if err := os.WriteFile(file, []byte("keep me"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := prepareDesktopSocketPath(file); err == nil {
		t.Fatal("a regular file was accepted as a socket path")
	}
	content, err := os.ReadFile(file)
	if err != nil || string(content) != "keep me" {
		t.Fatalf("the guard modified an unrelated file: %q %v", content, err)
	}
}

func TestDesktopSocketModeParsing(t *testing.T) {
	for _, valid := range []string{"0600", "0660", "0666", "640"} {
		if _, err := parseDesktopSocketMode(valid); err != nil {
			t.Fatalf("valid mode %q rejected: %v", valid, err)
		}
	}
	for _, invalid := range []string{"0", "999", "abc", "0660x", "17777"} {
		if _, err := parseDesktopSocketMode(invalid); err == nil {
			t.Fatalf("invalid mode %q accepted", invalid)
		}
	}
	cfg := defaultDesktopConfig()
	if cfg.SocketMode != defaultDesktopSocketMode || cfg.SocketPath != defaultDesktopSocketPath {
		t.Fatalf("defaults drifted: %+v", cfg)
	}
	if cfg.SocketGroup == "" {
		t.Fatal("the default must name a group; an ungrouped socket is world-readable")
	}
	if fmt.Sprintf("%o", mustMode(t, cfg.SocketMode)) != "660" {
		t.Fatal("the default mode is not 660")
	}
}

func mustMode(t *testing.T, value string) os.FileMode {
	t.Helper()
	mode, err := parseDesktopSocketMode(value)
	if err != nil {
		t.Fatal(err)
	}
	return mode
}
