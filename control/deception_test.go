// STATUS: DIAMANT VGT SUPREME
package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDeceptionEngine_RegisterAndAccess(t *testing.T) {
	key := []byte("vgt-super-secret-deception-key-32")
	dispatcher := newMockDispatcher()
	respEngine := NewResponseEngine(DefaultResponseConfig(), dispatcher, nil)
	correlator := NewIncidentCorrelator(1800 * time.Second)

	var loggedIncident *XDRIncident
	engine, err := NewDeceptionEngine(key, respEngine, correlator, func(inc XDRIncident) error {
		loggedIncident = &inc
		return nil
	})
	if err != nil {
		t.Fatalf("failed to create deception engine: %v", err)
	}

	// 1. Register Canary
	canaryPath := "/tmp/.aws_credentials"
	token, err := engine.RegisterCanary(canaryPath, CanaryCloudCred, 1000, 0600)
	if err != nil {
		t.Fatalf("failed to register canary: %v", err)
	}
	if !engine.IsCanaryPath(canaryPath) {
		t.Fatalf("expected canary path %s to be registered", canaryPath)
	}
	if token.Type != CanaryCloudCred {
		t.Fatalf("expected canary type CLOUD_CRED, got %s", token.Type)
	}

	// 2. Simulate unauthorized access
	ctx := context.Background()
	now := time.Now().UTC()
	accessEvt := DeceptionAccessEvent{
		CanaryPath:         canaryPath,
		AccessorPID:        4412,
		AccessorStartTicks: 88888,
		AccessorUID:        1000,
		AccessorComm:       "malware.elf",
		RemoteIP:           "198.51.100.99",
		Timestamp:          now,
	}

	inc, respRec, err := engine.HandleCanaryAccess(ctx, accessEvt)
	if err != nil {
		t.Fatalf("failed to handle canary access: %v", err)
	}

	// Verify Incident properties (Calibrated High Assurance for untrusted actor)
	if inc.Severity != "CRITICAL" {
		t.Fatalf("expected CRITICAL severity, got %s", inc.Severity)
	}
	if inc.Score != 200 {
		t.Fatalf("expected score 200, got %d", inc.Score)
	}
	if len(inc.AttackStory) == 0 {
		t.Fatal("expected attack story nodes attached to canary incident")
	}
	if inc.AttackStory[0].CausalEdge != EdgeCanaryTriggered {
		t.Fatalf("expected causal edge CANARY_TRIGGERED, got %s", inc.AttackStory[0].CausalEdge)
	}
	if inc.AttackStory[0].Confidence != 98 {
		t.Fatalf("expected calibrated 98%% confidence for untrusted accessor, got %d", inc.AttackStory[0].Confidence)
	}
	if inc.AttackStory[0].Metadata["trigger_reason"] != "CANARY_UNAUTHORIZED_PROBE" {
		t.Fatalf("expected trigger reason CANARY_UNAUTHORIZED_PROBE, got %s", inc.AttackStory[0].Metadata["trigger_reason"])
	}

	// Verify Incident Sink callback
	if loggedIncident == nil || loggedIncident.ID != inc.ID {
		t.Fatal("expected incident to be passed to incidentSink")
	}

	// Verify automated mitigation response: PID 4412 must be frozen!
	if respRec == nil {
		t.Fatal("expected response record returned for PID freeze")
	}
	if respRec.ActionType != ActionFreezeExecution {
		t.Fatalf("expected action FREEZE_EXECUTION, got %s", respRec.ActionType)
	}
	if respRec.Confidence != 98 {
		t.Fatalf("expected response record confidence 98, got %d", respRec.Confidence)
	}
	if respRec.ReasonCode != "CANARY_UNAUTHORIZED_PROBE" {
		t.Fatalf("expected response reason CANARY_UNAUTHORIZED_PROBE, got %s", respRec.ReasonCode)
	}
	if !dispatcher.frozenPIDs[4412] {
		t.Fatal("expected PID 4412 to be frozen in kernel dispatcher")
	}
	// Verify remote IP was also contained
	if !dispatcher.blockedIPs["198.51.100.99"] {
		t.Fatal("expected remote IP 198.51.100.99 to be contained in dispatcher")
	}
}

func TestDeceptionEngine_SystemScannerCalibration(t *testing.T) {
	key := []byte("vgt-super-secret-deception-key-32")
	dispatcher := newMockDispatcher()
	respEngine := NewResponseEngine(DefaultResponseConfig(), dispatcher, nil)
	correlator := NewIncidentCorrelator(1800 * time.Second)

	engine, err := NewDeceptionEngine(key, respEngine, correlator, nil)
	if err != nil {
		t.Fatalf("failed to create deception engine: %v", err)
	}

	canaryPath := "/etc/shadow.bak"
	_, err = engine.RegisterCanary(canaryPath, CanaryShadow, 0, 0600)
	if err != nil {
		t.Fatalf("failed to register canary: %v", err)
	}

	ctx := context.Background()
	now := time.Now().UTC()

	// Test 1: Root accessor (UID 0, e.g. administrative or system tool)
	rootEvt := DeceptionAccessEvent{
		CanaryPath:         canaryPath,
		AccessorPID:        1050,
		AccessorStartTicks: 77777,
		AccessorUID:        0,
		AccessorComm:       "cat",
		Timestamp:          now,
	}

	incRoot, respRecRoot, err := engine.HandleCanaryAccess(ctx, rootEvt)
	if err != nil {
		t.Fatalf("failed to handle root access: %v", err)
	}
	if incRoot.Severity != "HIGH" {
		t.Fatalf("expected HIGH severity for root access, got %s", incRoot.Severity)
	}
	if incRoot.Score != 160 {
		t.Fatalf("expected score 160 for HIGH severity, got %d", incRoot.Score)
	}
	if incRoot.AttackStory[0].Confidence != 85 {
		t.Fatalf("expected 85%% confidence for root system access, got %d", incRoot.AttackStory[0].Confidence)
	}
	if incRoot.AttackStory[0].Metadata["trigger_reason"] != "CANARY_SUSPICIOUS_SYSTEM_ACCESS" {
		t.Fatalf("expected trigger reason CANARY_SUSPICIOUS_SYSTEM_ACCESS, got %s", incRoot.AttackStory[0].Metadata["trigger_reason"])
	}
	if respRecRoot == nil || respRecRoot.Confidence != 85 || respRecRoot.ReasonCode != "CANARY_SUSPICIOUS_SYSTEM_ACCESS" {
		t.Fatalf("expected response record with confidence 85 and reason CANARY_SUSPICIOUS_SYSTEM_ACCESS, got %+v", respRecRoot)
	}

	// Test 2: Known scanner / indexer tool (e.g. updatedb by non-root)
	scannerEvt := DeceptionAccessEvent{
		CanaryPath:   canaryPath,
		AccessorPID:  2040,
		AccessorUID:  1000,
		AccessorComm: "updatedb",
		Timestamp:    now,
	}

	incScan, _, err := engine.HandleCanaryAccess(ctx, scannerEvt)
	if err != nil {
		t.Fatalf("failed to handle scanner access: %v", err)
	}
	if incScan.Severity != "HIGH" || incScan.AttackStory[0].Confidence != 85 {
		t.Fatalf("expected HIGH / 85%% for updatedb, got %s / %d", incScan.Severity, incScan.AttackStory[0].Confidence)
	}

	// Test 3: Backup daemon (e.g. backup-runner)
	backupEvt := DeceptionAccessEvent{
		CanaryPath:   canaryPath,
		AccessorPID:  3099,
		AccessorUID:  1001,
		AccessorComm: "backup-runner",
		Timestamp:    now,
	}

	incBackup, _, err := engine.HandleCanaryAccess(ctx, backupEvt)
	if err != nil {
		t.Fatalf("failed to handle backup access: %v", err)
	}
	if incBackup.Severity != "HIGH" || incBackup.AttackStory[0].Confidence != 85 {
		t.Fatalf("expected HIGH / 85%% for backup-runner, got %s / %d", incBackup.Severity, incBackup.AttackStory[0].Confidence)
	}
}

func TestDeceptionEngine_DeployCanaryFile(t *testing.T) {
	tempDir := t.TempDir()

	types := []struct {
		canaryType CanaryType
		relPath    string
		subString  string
	}{
		{CanaryCloudCred, ".aws/credentials", "aws_access_key_id"},
		{CanaryShadow, "etc/shadow.bak", "root:$6$vgt$"},
		{CanarySSHKey, ".ssh/id_ed25519_decoy", "BEGIN OPENSSH PRIVATE KEY"},
		{CanaryDotEnv, "app/.env", "DATABASE_URL"},
	}

	for _, tt := range types {
		target := filepath.Join(tempDir, tt.relPath)
		err := DeployCanaryFile(target, tt.canaryType)
		if err != nil {
			t.Fatalf("failed to deploy canary %s: %v", tt.canaryType, err)
		}

		content, readErr := os.ReadFile(target)
		if readErr != nil {
			t.Fatalf("failed to read deployed canary %s: %v", target, readErr)
		}
		if !strings.Contains(string(content), tt.subString) {
			t.Fatalf("canary file %s does not contain expected substring %q: %s", target, tt.subString, string(content))
		}

		// Verify idempotency: deploying again should succeed without rewriting or failing
		errSecond := DeployCanaryFile(target, tt.canaryType)
		if errSecond != nil {
			t.Fatalf("idempotent deployment of %s failed: %v", target, errSecond)
		}
	}

	// Invalid empty or root path validation
	if err := DeployCanaryFile("", CanaryCloudCred); err == nil {
		t.Fatal("expected validation error for empty canary path, got nil")
	}
	if err := DeployCanaryFile("/", CanaryCloudCred); err == nil {
		t.Fatal("expected validation error for root canary path, got nil")
	}
}

func TestDeceptionEngine_PathJail(t *testing.T) {
	engine, err := NewDeceptionEngine([]byte("vgt-super-secret-deception-key-32"), nil, nil, nil)
	if err != nil {
		t.Fatalf("err: %v", err)
	}

	// Valid jail path
	valid, err := engine.JailedPath("/home/user", ".ssh/id_rsa_backup")
	if err != nil {
		t.Fatalf("expected valid jail path, got error: %v", err)
	}
	if valid == "" {
		t.Fatal("expected non-empty path")
	}

	// Path traversal attempt -> must fail closed
	_, err = engine.JailedPath("/home/user", "../../../etc/shadow")
	if err == nil {
		t.Fatal("expected security exception on path traversal, got nil")
	}
	var secErr *DeceptionSecurityException
	if !errors.As(err, &secErr) {
		t.Fatalf("expected DeceptionSecurityException, got %T", err)
	}
}
