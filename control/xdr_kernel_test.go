// STATUS: DIAMANT VGT SUPREME
package main

import (
	"encoding/hex"
	"strings"
	"testing"
	"time"
)

func TestParseCoreExecArgvAndProbeEventsStrictBounds(t *testing.T) {
	if events, err := parseCoreExecArgvEvents("empty"); err != nil || events != nil {
		t.Fatalf("empty exec-argv decode = (%v, %v)", events, err)
	}
	validExec := "4242:100:1000:1000:" +
		hex.EncodeToString([]byte("sh")) + ":" +
		hex.EncodeToString([]byte("/usr/bin/sh")) + ":" +
		hex.EncodeToString([]byte("sh -c id"))
	execEvents, err := parseCoreExecArgvEvents(validExec)
	if err != nil || len(execEvents) != 1 {
		t.Fatalf("valid exec-argv decode failed: %v %v", execEvents, err)
	}
	if execEvents[0].PID != 4242 || execEvents[0].Filename != "/usr/bin/sh" || execEvents[0].Cmdline != "sh -c id" {
		t.Fatalf("decoded exec-argv mismatch: %+v", execEvents[0])
	}
	for _, bad := range []string{
		"0:1:1:1:61:61:61",
		"1:1:1:1:zz:61:61",
		"1:1:1:1:61:61",
		strings.TrimSuffix(strings.Repeat(validExec+",", maxExecArgvEventsPerResponse+1), ","),
	} {
		if _, err := parseCoreExecArgvEvents(bad); err == nil {
			t.Fatalf("expected invalid exec-argv payload to be rejected: %q", bad)
		}
	}

	if probes, err := parseCoreKernelProbeEvents("empty"); err != nil || probes != nil {
		t.Fatalf("empty kernel-probe decode = (%v, %v)", probes, err)
	}
	validProbe := "1700000000000:5150:1000:1:1:2:16:" +
		hex.EncodeToString([]byte("probe")) + ":" +
		hex.EncodeToString([]byte("ptrace"))
	probeEvents, err := parseCoreKernelProbeEvents(validProbe)
	if err != nil || len(probeEvents) != 1 || probeEvents[0].Kind != KernelProbeKindPtrace {
		t.Fatalf("valid kernel-probe decode failed: %+v %v", probeEvents, err)
	}
	for _, bad := range []string{
		"0:5150:1000:1:1:2:16:70:70",
		"1:0:1000:1:1:2:16:70:70",
		"1:5:1000:1:99:2:16:70:70",
		"1:5:1000:1:1:9:16:70:70",
		"1:5:1000:1:1:2:16:70",
	} {
		if _, err := parseCoreKernelProbeEvents(bad); err == nil {
			t.Fatalf("expected invalid kernel-probe payload to be rejected: %q", bad)
		}
	}
}

func TestXDRRulesDetectShortLivedSubshellAndIgnoreBenignWorkloads(t *testing.T) {
	rules := NewXDRRuleEngine()
	attacks := []struct {
		name    string
		cmdline string
		wantID  string
	}{
		{"encoded pipe shell", "bash -c echo 'dW5hbWUgLWE7IGlk' | base64 -d | sh", "KD.LINUX.ENCODED_EXEC"},
		{"account discovery", "bash -c id && getent passwd | head -n 10 && sudo -n true", "KD.LINUX.DISCOVERY.ACCOUNT"},
		{"suid discovery", "find /usr/bin -perm -4000", "KD.LINUX.DISCOVERY.SUID"},
		{"cron persistence", "bash -c (crontab -l; echo '# x') | crontab -", "KD.LINUX.PERSISTENCE_DROPIN"},
	}
	for _, tc := range attacks {
		dec := rules.EvaluateProcess(ProcessSample{
			PID: 9001, UID: 1000, Comm: "bash", Exe: "/usr/bin/bash", Cmdline: tc.cmdline,
		}, nil, nil, nil)
		if !containsString(dec.RuleIDs, tc.wantID) {
			t.Fatalf("%s: expected rule %s in %+v", tc.name, tc.wantID, dec.RuleIDs)
		}
		if dec.Score < 40 {
			t.Fatalf("%s: score %d below AlertScore", tc.name, dec.Score)
		}
		if tc.wantID == "KD.LINUX.DISCOVERY.ACCOUNT" || tc.wantID == "KD.LINUX.DISCOVERY.SUID" {
			if dec.Decision != "alert" || dec.KillSignals != 0 {
				t.Fatalf("%s: discovery rule must be alert-only with zero kill signals (got %+v)", tc.name, dec)
			}
		}
	}

	benign := []ProcessSample{
		{PID: 9100, UID: 1000, Comm: "dpkg-query", Exe: "/usr/bin/dpkg-query", Cmdline: "dpkg-query -W -f=${Version} bash"},
		{PID: 9101, UID: 1000, Comm: "python3", Exe: "/usr/bin/python3", Cmdline: "python3 -c import os, json; print(json.dumps({'ok': os.path.isdir('/etc/nginx')}))"},
	}
	for _, p := range benign {
		dec := rules.EvaluateProcess(p, nil, nil, nil)
		if dec.Decision != "none" || len(dec.RuleIDs) != 0 {
			t.Fatalf("benign workload %q unexpectedly matched rules: %+v", p.Cmdline, dec)
		}
	}
}

func TestConsumeKernelProbeEventsCreatesTypedIncidents(t *testing.T) {
	engine := &XDREngine{
		state: NewState("test", defaultConfig()), correlator: NewIncidentCorrelator(0),
		dedupe: map[string]time.Time{}, degradeCauses: map[string]string{}, forensicFailures: map[string]int{},
	}
	now := time.Now().UTC()
	probes := []CoreKernelProbeEvent{
		{TsNS: 100, PID: 111, UID: 1000, TargetPID: 1, Kind: KernelProbeKindPtrace, Action: KernelProbeActionAudit, DetailCode: 16, Comm: "probe", Detail: "ptrace"},
		{TsNS: 101, PID: 112, UID: 1000, TargetPID: 0, Kind: KernelProbeKindProtocol, Action: KernelProbeActionDeny, DetailCode: 132, Comm: "probe", Detail: "SCTP"},
		{TsNS: 102, PID: 113, UID: 1000, TargetPID: 0, Kind: KernelProbeKindCredOpenat, Action: KernelProbeActionAudit, DetailCode: 0, Comm: "evgen", Detail: "/etc/shadow"},
		{TsNS: 103, PID: 114, UID: 1000, TargetPID: 0, Kind: KernelProbeKindSymlink, Action: KernelProbeActionAudit, DetailCode: 0, Comm: "evgen", Detail: "/etc/shadow"},
	}
	delay := engine.consumeKernelProbeEvents(probes, nil, now)
	if delay != 100*time.Millisecond {
		t.Fatalf("unexpected probe poll delay: %s", delay)
	}
	incidents := engine.state.Snapshot().Incidents
	if len(incidents) != 4 {
		t.Fatalf("expected 4 incidents, got %d", len(incidents))
	}
	// Repeat identical events inside dedup window must not create duplicate incidents.
	engine.consumeKernelProbeEvents(probes, nil, now.Add(time.Second))
	if len(engine.state.Snapshot().Incidents) != 4 {
		t.Fatalf("duplicate kernel probe events generated duplicate incidents")
	}
}
