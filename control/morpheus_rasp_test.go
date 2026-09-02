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

func TestMorpheusRASP_SSRFDestinationValidation(t *testing.T) {
	// 1. Block IMDS IP
	err := ValidateSSRFDestination("http://169.254.169.254/latest/meta-data/")
	if err == nil {
		t.Fatal("expected SSRF error on 169.254.169.254")
	}

	// 2. Block Google Cloud Metadata Hostname
	err = ValidateSSRFDestination("http://metadata.google.internal/computeMetadata/v1/")
	if err == nil {
		t.Fatal("expected SSRF error on metadata.google.internal")
	}

	// 3. Block Alibaba Cloud IMDS
	err = ValidateSSRFDestination("http://100.100.100.200/latest/meta-data/")
	if err == nil {
		t.Fatal("expected SSRF error on 100.100.100.200")
	}

	// 4. Block Decimal Integer representation of 169.254.169.254 (2852039166)
	err = ValidateSSRFDestination("http://2852039166/latest/meta-data/")
	if err == nil {
		t.Fatal("expected SSRF error on decimal dword 2852039166")
	}

	// 5. Block Hex representation of 169.254.169.254 (0xa9fea9fe)
	err = ValidateSSRFDestination("http://0xa9fea9fe/latest/meta-data/")
	if err == nil {
		t.Fatal("expected SSRF error on hex 0xa9fea9fe")
	}

	// 6. Block Octal representation of 169.254.169.254 (0251.0376.0251.0376)
	err = ValidateSSRFDestination("http://0251.0376.0251.0376/latest/meta-data/")
	if err == nil {
		t.Fatal("expected SSRF error on octal 0251.0376.0251.0376")
	}

	// 7. Block AWS IMDSv2 IPv6 ([fd00:ec2::254])
	err = ValidateSSRFDestination("http://[fd00:ec2::254]/latest/meta-data/")
	if err == nil {
		t.Fatal("expected SSRF error on IPv6 IMDS [fd00:ec2::254]")
	}

	// 8. Block Azure WireServer (168.63.129.16)
	err = ValidateSSRFDestination("http://168.63.129.16/machine/plugins/")
	if err == nil {
		t.Fatal("expected SSRF error on Azure WireServer 168.63.129.16")
	}

	// 9. Block Loopback (localhost and 127.0.0.1)
	err = ValidateSSRFDestination("http://localhost:9844/api/v1/internal")
	if err == nil {
		t.Fatal("expected SSRF error on localhost")
	}
	err = ValidateSSRFDestination("http://127.0.0.1:8080/admin")
	if err == nil {
		t.Fatal("expected SSRF error on 127.0.0.1")
	}

	// 10. Legitimate public destination
	err = ValidateSSRFDestination("https://beta.gaiacom.de/api/v1/sync")
	if err != nil {
		t.Fatalf("unexpected error on legitimate destination: %v", err)
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
