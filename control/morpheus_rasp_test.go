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
