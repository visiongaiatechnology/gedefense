// STATUS: DIAMANT VGT SUPREME
package main

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func TestMorpheusRASP_MemoryScrapingDefense(t *testing.T) {
	correlator := NewIncidentCorrelator(1800 * time.Second)
	var capturedIncident *XDRIncident

	rasp := NewMorpheusRASP("", correlator, func(inc XDRIncident) error {
		capturedIncident = &inc
		return nil
	})

	// Register PID 4001 as protected vault
	rasp.RegisterProtectedPID(4001)

	// 1. Unauthorized attacker PID 9999 attempts to scrape protected PID 4001
	event, err := rasp.InspectMemoryAccess(9999, "malware_dumper", 4001, "key-broker", false)
	if err == nil {
		t.Fatal("expected memory scraping error, got nil")
	}
	var secErr *MorpheusSecurityException
	if !errors.As(err, &secErr) {
		t.Fatalf("expected MorpheusSecurityException, got %T", err)
	}
	if event == nil || event.ThreatType != "PROCESS_MEMORY_SCRAPING" {
		t.Fatalf("expected PROCESS_MEMORY_SCRAPING event")
	}

	// Verify incident captured
	if capturedIncident == nil {
		t.Fatal("expected XDR incident from RASP violation")
	}
	if capturedIncident.Severity != "CRITICAL" {
		t.Fatalf("expected CRITICAL, got %s", capturedIncident.Severity)
	}
	if len(capturedIncident.AttackStory) == 0 {
		t.Fatal("expected attack story nodes attached")
	}
	if capturedIncident.AttackStory[0].CausalEdge != EdgePrivilegeEscalated {
		t.Fatalf("expected causal edge EdgePrivilegeEscalated, got %s", capturedIncident.AttackStory[0].CausalEdge)
	}

	// 2. Legitimate child debugger/tracer should pass
	childEvent, childErr := rasp.InspectMemoryAccess(4000, "legit_parent", 4001, "key-broker", true)
	if childErr != nil || childEvent != nil {
		t.Fatalf("expected child access to be permitted, got err=%v, event=%v", childErr, childEvent)
	}
}

func TestMorpheusRASP_CredentialScrubber(t *testing.T) {
	rawCmd := "curl -H 'Authorization: Bearer super-secret-token-xyz123' -d 'PASSWORD=MyMasterSecretPassword123!' https://api.internal/login"
	scrubbed := ScrubSensitiveCredentials(rawCmd)

	if strings.Contains(scrubbed, "super-secret-token-xyz123") {
		t.Fatal("bearer token was not redacted")
	}
	if strings.Contains(scrubbed, "MyMasterSecretPassword123!") {
		t.Fatal("password was not redacted")
	}
	if !strings.Contains(scrubbed, "[VGT_REDACTED_SECRET]") {
		t.Fatal("expected [VGT_REDACTED_SECRET] placeholder")
	}
}

func TestMorpheusRASP_InspectProcess(t *testing.T) {
	correlator := NewIncidentCorrelator(1800 * time.Second)
	var capturedIncident *XDRIncident

	rasp := NewMorpheusRASP("", correlator, func(inc XDRIncident) error {
		capturedIncident = &inc
		return nil
	})

	rasp.RegisterProtectedPID(5000)

	// 1. Innocent process
	innocent := ProcessSample{
		PID:     2001,
		Comm:    "nginx",
		Cmdline: "nginx -g daemon off;",
	}
	evt, err := rasp.InspectProcess(innocent)
	if err != nil || evt != nil {
		t.Fatalf("expected innocent process to pass, got err=%v evt=%v", err, evt)
	}

	// 2. GDB targeting protected vault PID 5000
	scraper := ProcessSample{
		PID:     3333,
		Comm:    "gdb",
		Cmdline: "gdb -p 5000",
	}
	evt, err = rasp.InspectProcess(scraper)
	if err == nil {
		t.Fatal("expected scraping attempt to be blocked, got nil")
	}
	if evt == nil || evt.ThreatType != "PROCESS_MEMORY_SCRAPING" {
		t.Fatalf("expected PROCESS_MEMORY_SCRAPING, got %v", evt)
	}
	if capturedIncident == nil || capturedIncident.PID != 3333 {
		t.Fatalf("expected incident for scraper PID 3333, got %v", capturedIncident)
	}
}

// TestMorpheusRASPBindsTrustedDebuggerToIdentity is the FIND-026 trust regression: the
// exemption is an identity, so a binary that merely carries a trusted name - or a trusted tool
// started by a non-root user - is not exempt.
func TestMorpheusRASPBindsTrustedDebuggerToIdentity(t *testing.T) {
	correlator := NewIncidentCorrelator(1800 * time.Second)
	var captured *XDRIncident
	rasp := NewMorpheusRASP("", correlator, func(inc XDRIncident) error {
		captured = &inc
		return nil
	})
	rasp.ApplyPolicy(HardeningRASPSettings{
		Enabled: true, ProtectedNames: []string{"vault"}, TrustedDebuggers: []string{"gdb"},
		ContainmentEnabled: true,
	})
	rasp.RegisterProtectedPID(5000)

	// 1. A copy of gdb outside the signed system location is not the trusted tool.
	renamedCopy := ProcessSample{PID: 6101, UID: 0, Comm: "gdb", Exe: "/tmp/gdb", Cmdline: "gdb -p 5000"}
	event, err := rasp.InspectProcess(renamedCopy)
	if event == nil || err == nil {
		t.Fatalf("a renamed copy of a trusted debugger name was exempt: event=%v err=%v", event, err)
	}
	if captured == nil || captured.PID != 6101 {
		t.Fatalf("expected an XDR incident for the renamed copy, got %v", captured)
	}

	// 2. The exemption also requires privilege: ptracing a protected daemon is a root operation,
	// so an unprivileged process with a trusted name and system path is still a scraper.
	captured = nil
	unprivileged := ProcessSample{PID: 6102, UID: 1000, Comm: "gdb", Exe: "/usr/bin/gdb", Cmdline: "gdb -p 5000"}
	event, err = rasp.InspectProcess(unprivileged)
	if event == nil || err == nil {
		t.Fatalf("an unprivileged trusted-name process was exempt: event=%v err=%v", event, err)
	}
	if captured == nil || captured.PID != 6102 {
		t.Fatalf("expected an XDR incident for the unprivileged process, got %v", captured)
	}
}

// TestMorpheusRASPDETECTSRenamedDebuggerBinary proves detection no longer depends on the tool
// names: a renamed binary that attaches to a protected PID is caught by the attach-style
// argument, which survives the rename.
func TestMorpheusRASPDETECTSRenamedDebuggerBinary(t *testing.T) {
	correlator := NewIncidentCorrelator(1800 * time.Second)
	var captured *XDRIncident
	rasp := NewMorpheusRASP("", correlator, func(inc XDRIncident) error {
		captured = &inc
		return nil
	})
	rasp.ApplyPolicy(HardeningRASPSettings{
		Enabled: true, ProtectedNames: []string{"vault"}, TrustedDebuggers: []string{"gdb"},
		ContainmentEnabled: true,
	})
	rasp.RegisterProtectedPID(5001)

	renamed := ProcessSample{PID: 6103, UID: 0, Comm: "updater", Exe: "/tmp/updater", Cmdline: "/tmp/updater --pid=5001"}
	event, err := rasp.InspectProcess(renamed)
	if event == nil || err == nil {
		t.Fatalf("a renamed debugger binary targeting a protected PID was not detected: event=%v err=%v", event, err)
	}
	if event.ThreatType != "PROCESS_MEMORY_SCRAPING" {
		t.Fatalf("unexpected threat type %q", event.ThreatType)
	}
	if captured == nil || captured.PID != 6103 {
		t.Fatalf("expected an XDR incident for the renamed debugger, got %v", captured)
	}
	if len(captured.RuleIDs) == 0 || captured.RuleIDs[0] != "MORPHEUS.RASP.MEM_SCRAPE" {
		t.Fatalf("the renamed debugger incident lost its rule binding: %+v", captured.RuleIDs)
	}

	// A process that only ships a protected name in its arguments, without an attach-style
	// argument and without an inspection tool identity, is not reported.
	benign := ProcessSample{PID: 6104, UID: 0, Comm: "systemctl", Exe: "/usr/bin/systemctl", Cmdline: "systemctl status vault"}
	if event, err := rasp.InspectProcess(benign); event != nil || err != nil {
		t.Fatalf("a benign status query was reported: event=%v err=%v", event, err)
	}
}

// TestMorpheusRASPAlertOnlyStillReturnsTheDetectionEvent covers the !containment branch: a
// report-only policy must still produce the complete event and incident, it only suppresses the
// active response.
func TestMorpheusRASPAlertOnlyStillReturnsTheDetectionEvent(t *testing.T) {
	correlator := NewIncidentCorrelator(1800 * time.Second)
	var captured *XDRIncident
	rasp := NewMorpheusRASP("", correlator, func(inc XDRIncident) error {
		captured = &inc
		return nil
	})
	rasp.ApplyPolicy(HardeningRASPSettings{
		Enabled: true, ProtectedNames: []string{"vault"},
		ContainmentEnabled: false, AlertOnly: true,
	})
	rasp.RegisterProtectedPID(5002)

	event, err := rasp.InspectProcess(ProcessSample{PID: 6105, UID: 0, Comm: "gdb", Cmdline: "gdb -p 5002"})
	if event == nil {
		t.Fatal("alert-only RASP returned no detection event")
	}
	if err != nil {
		t.Fatalf("alert-only RASP authorized an active response: %v", err)
	}
	if captured == nil {
		t.Fatal("alert-only RASP emitted no XDR incident")
	}
	if captured.Decision != "alert" || captured.Action != "observe" {
		t.Fatalf("the report-only incident was not classified as observed: decision=%s action=%s", captured.Decision, captured.Action)
	}
}

// TestMorpheusAlertOnlyDetectionReachesTheXDRAlarm is the caller-side half of the same defect:
// xdr.go dispatched only on the security error, so an alert-only detection produced no alarm at
// all. The event must now be signalled through the XDR state regardless of containment.
func TestMorpheusAlertOnlyDetectionReachesTheXDRAlarm(t *testing.T) {
	cfg := defaultConfig()
	state := NewState("morpheus-test", cfg)
	engine := &XDREngine{
		cfg: cfg, state: state, selfPID: -1, rules: NewXDRRuleEngine(),
		protected:     map[string]protectedObject{},
		degradeCauses: map[string]string{},
		tamperSeen:    map[string]string{},
	}
	engine.morpheus = NewMorpheusRASP("", engine.correlator, func(inc XDRIncident) error {
		engine.appendIncident(inc)
		return nil
	})
	engine.morpheus.ApplyPolicy(HardeningRASPSettings{
		Enabled: true, ProtectedNames: []string{"vault"},
		ContainmentEnabled: false, AlertOnly: true,
	})
	engine.morpheus.RegisterProtectedPID(5003)

	engine.evaluate(ProcessSample{
		PID: 6106, UID: 0, Comm: "gdb", Exe: "/usr/bin/gdb", Cmdline: "gdb -p 5003", StartTicks: 42,
	}, nil, "exec")

	alarm := false
	for _, event := range state.Snapshot().Events {
		if event.Kind == "morpheus.memory_scraping_detected" {
			alarm = true
		}
	}
	if !alarm {
		t.Fatal("an alert-only RASP detection produced no XDR alarm event")
	}
	incidents := incidentsWithRule(state, "MORPHEUS.RASP.MEM_SCRAPE")
	if len(incidents) == 0 {
		t.Fatal("an alert-only RASP detection produced no XDR incident")
	}
	if incidents[0].Decision != "alert" {
		t.Fatalf("the alert-only incident was not classified as alert: %s", incidents[0].Decision)
	}
}

// TestMorpheusDetectionWithoutTargetIsNotATargetCheckBypass keeps the exemption from turning
// into a general off switch: a trusted debugger that addresses no protected process is a no-op,
// and a non-debugger that addresses a protected PID is still detected.
func TestMorpheusDetectionWithoutTargetIsNotATargetCheckBypass(t *testing.T) {
	rasp := NewMorpheusRASP("", nil, nil)
	rasp.ApplyPolicy(HardeningRASPSettings{
		Enabled: true, ProtectedNames: []string{"vault"}, TrustedDebuggers: []string{"gdb"},
		ContainmentEnabled: true,
	})
	// Trusted debugger, no protected target: nothing to report.
	if event, err := rasp.InspectProcess(ProcessSample{PID: 6107, UID: 0, Comm: "gdb", Cmdline: "gdb /tmp/unrelated"}); event != nil || err != nil {
		t.Fatalf("a trusted debugger without a protected target was reported: event=%v err=%v", event, err)
	}
	// Untrusted process, protected name target: reported.
	if event, err := rasp.InspectProcess(ProcessSample{PID: 6108, UID: 0, Comm: "frida", Cmdline: "frida -- /usr/bin/vault"}); event == nil || err == nil {
		t.Fatalf("an untrusted scraper targeting a protected name was not contained: event=%v err=%v", event, err)
	}
}
