// STATUS: DIAMANT VGT SUPREME
package main

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
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

// ---------------------------------------------------------------------------
// Privileged canary transport + kernel sensor wiring.
// ---------------------------------------------------------------------------

type fakeCanaryTransport struct {
	deployed   []string
	contents   [][]byte
	modes      []uint32
	removed    []string
	deployErr  error
	removeErr  error
	deployCall int
}

func (f *fakeCanaryTransport) DeployCanary(path string, _ CanaryType, _ uint32, mode uint32, content []byte) error {
	f.deployCall++
	if f.deployErr != nil {
		return f.deployErr
	}
	f.deployed = append(f.deployed, path)
	f.contents = append(f.contents, append([]byte(nil), content...))
	f.modes = append(f.modes, mode)
	return nil
}

func (f *fakeCanaryTransport) RemoveCanary(path string) error {
	if f.removeErr != nil {
		return f.removeErr
	}
	f.removed = append(f.removed, path)
	return nil
}

type fakeCanarySource struct {
	batch     CanaryEventBatch
	status    CanaryBrokerStatus
	eventsErr error
	statusErr error
}

func (f *fakeCanarySource) CanaryEvents() (CanaryEventBatch, error) {
	return f.batch, f.eventsErr
}

func (f *fakeCanarySource) CanaryStatus() (CanaryBrokerStatus, error) {
	return f.status, f.statusErr
}

func newTestDeceptionEngine(t *testing.T) (*DeceptionEngine, *[]XDRIncident) {
	t.Helper()
	incidents := make([]XDRIncident, 0, 4)
	engine, err := NewDeceptionEngine([]byte("vgt-super-secret-deception-key-32"), nil, nil, func(incident XDRIncident) error {
		incidents = append(incidents, incident)
		return nil
	})
	if err != nil {
		t.Fatalf("deception engine: %v", err)
	}
	return engine, &incidents
}

func TestCanaryApplyPolicyUsesPrivilegedTransportAndDeterministicContent(t *testing.T) {
	engine, _ := newTestDeceptionEngine(t)
	transport := &fakeCanaryTransport{}
	engine.SetCanaryDeployer(transport)
	engine.SetCanaryRemover(transport)

	canaryPath := canaryRootPath + "/.aws_credentials"
	settings := defaultHardeningFabricSettings(Config{}, "").Deception
	settings.Canaries = []CanarySettings{
		{Path: canaryPath, Type: string(CanaryCloudCred), Enabled: true, OwnerUID: 0, FileMode: 0o600},
	}
	registered, removed, err := engine.ApplyPolicy(settings)
	if err != nil {
		t.Fatalf("apply policy: %v", err)
	}
	if registered != 1 || removed != 0 {
		t.Fatalf("registered=%d removed=%d, want 1/0", registered, removed)
	}
	if len(transport.deployed) != 1 || transport.deployed[0] != canaryPath {
		t.Fatalf("privileged transport not used: %+v", transport.deployed)
	}
	if transport.modes[0] != 0o600 {
		t.Fatalf("mode=%#o, want 0600", transport.modes[0])
	}
	content := transport.contents[0]
	if !strings.Contains(string(content), "aws_access_key_id") || !strings.Contains(string(content), "VGT Nemesis") {
		t.Fatalf("unexpected canary content: %q", string(content))
	}
	// The same definition must render byte-identical bait on every revision;
	// otherwise the core's idempotent "exists" check could never hold across
	// restarts and a new random "authentic" decoy would be minted each boot.
	if again := engine.canaryContent(canaryPath, CanaryCloudCred); string(again) != string(content) {
		t.Fatal("canary content is not deterministic across renders")
	}

	// Removing the definition must remove the decoy through the same transport.
	settings.Canaries = nil
	registered, removed, err = engine.ApplyPolicy(settings)
	if err != nil {
		t.Fatalf("apply removal: %v", err)
	}
	if registered != 0 || removed != 1 || len(transport.removed) != 1 || transport.removed[0] != canaryPath {
		t.Fatalf("removal not routed: registered=%d removed=%d transport=%+v", registered, removed, transport.removed)
	}
	if engine.IsCanaryPath(canaryPath) {
		t.Fatal("removed canary is still registered")
	}
}

func TestCanaryApplyPolicySkipsDefinitionsOutsidePrivilegedRoot(t *testing.T) {
	engine, _ := newTestDeceptionEngine(t)
	transport := &fakeCanaryTransport{deployErr: fmt.Errorf("%w: /etc/shadow.bak", ErrCanaryOutsideRoot)}
	engine.SetCanaryDeployer(transport)

	settings := defaultHardeningFabricSettings(Config{}, "").Deception
	settings.Canaries = []CanarySettings{
		{Path: "/etc/shadow.bak", Type: string(CanaryShadow), Enabled: true, OwnerUID: 0, FileMode: 0o600},
	}
	registered, _, err := engine.ApplyPolicy(settings)
	if err != nil {
		t.Fatalf("outside-root definition must be skipped, not fatal: %v", err)
	}
	if registered != 0 {
		t.Fatalf("registered=%d, want 0", registered)
	}
	if engine.IsCanaryPath("/etc/shadow.bak") {
		t.Fatal("skipped canary remained in the grid (fake enrollment)")
	}
}

func TestCanaryApplyPolicyRejectsPublicFileModeForPrivilegedTransport(t *testing.T) {
	engine, _ := newTestDeceptionEngine(t)
	engine.SetCanaryDeployer(&fakeCanaryTransport{})
	settings := defaultHardeningFabricSettings(Config{}, "").Deception
	settings.Canaries = []CanarySettings{
		{Path: canaryRootPath + "/app.env", Type: string(CanaryDotEnv), Enabled: true, OwnerUID: 0, FileMode: 0o644},
	}
	if _, _, err := engine.ApplyPolicy(settings); err == nil {
		t.Fatal("expected public decoy mode to be rejected for the privileged transport")
	}
}

func TestCanarySensorPollDispatchesToDeceptionAndDedupes(t *testing.T) {
	engine, incidents := newTestDeceptionEngine(t)
	canaryPath := canaryRootPath + "/shadow.bak"
	if _, err := engine.RegisterCanary(canaryPath, CanaryShadow, 0, 0o600); err != nil {
		t.Fatalf("register canary: %v", err)
	}
	source := &fakeCanarySource{
		batch: CanaryEventBatch{Events: []CanaryAccessEvent{{
			PID: os.Getpid(), UID: uint32(os.Geteuid()), Path: canaryPath, Type: string(CanaryShadow),
		}}},
		status: CanaryBrokerStatus{Roots: 1, Registered: 1, Watcher: "active"},
	}
	sensor := NewCanarySensor(source, engine, nil)
	fixed := time.Unix(1_700_000_000, 0).UTC()
	sensor.now = func() time.Time { return fixed }
	ctx := context.Background()

	sensor.poll(ctx)
	if len(*incidents) != 1 {
		t.Fatalf("incidents after first poll=%d, want 1", len(*incidents))
	}
	sensor.poll(ctx)
	if len(*incidents) != 1 {
		t.Fatalf("duplicate event was dispatched again: incidents=%d", len(*incidents))
	}
	source.batch = CanaryEventBatch{Events: []CanaryAccessEvent{{
		PID: os.Getpid() + 1, UID: uint32(os.Geteuid()), Path: canaryPath, Type: string(CanaryShadow),
	}}}
	sensor.poll(ctx)
	if len(*incidents) != 2 {
		t.Fatalf("second accessor was suppressed: incidents=%d, want 2", len(*incidents))
	}
}

func TestCanarySensorReportsDroppedEventsAndDegradedWatcher(t *testing.T) {
	engine, _ := newTestDeceptionEngine(t)
	source := &fakeCanarySource{
		batch:  CanaryEventBatch{Dropped: 3},
		status: CanaryBrokerStatus{Watcher: "degraded", Registered: 0},
	}
	sensor := NewCanarySensor(source, engine, nil)
	sensor.now = func() time.Time { return time.Unix(1_700_000_300, 0).UTC() }
	sensor.poll(context.Background())
	// Note: no state is attached in this test; the sensor must still survive a
	// degraded broker without panicking or blocking the poll loop.
	if sensor.lastStatus.IsZero() {
		t.Fatal("status was not refreshed")
	}
}

func TestParseCanaryEventsBoundedAndStrict(t *testing.T) {
	pathToken := base64.RawURLEncoding.EncodeToString([]byte(canaryRootPath + "/.env"))
	batch, err := parseCanaryEvents("2|4242:1000:" + pathToken + ":DOTENV:1")
	if err != nil {
		t.Fatalf("parse valid batch: %v", err)
	}
	if batch.Dropped != 2 || len(batch.Events) != 1 {
		t.Fatalf("unexpected batch: %+v", batch)
	}
	event := batch.Events[0]
	if event.PID != 4242 || event.UID != 1000 || !event.Exec || event.Type != string(CanaryDotEnv) {
		t.Fatalf("unexpected event: %+v", event)
	}
	if batch, err := parseCanaryEvents("empty"); err != nil || batch.Dropped != 0 || len(batch.Events) != 0 {
		t.Fatalf("empty batch mismatch: %+v %v", batch, err)
	}
	traversalToken := base64.RawURLEncoding.EncodeToString([]byte("/etc/../canaries/x"))
	malformed := []string{
		"0|4242:1000:" + pathToken + ":DOTENV:1:extra",
		"0|0:1000:" + pathToken + ":DOTENV:0",
		"0|4242:1000:" + pathToken + ":UNKNOWN:0",
		"0|4242:1000:" + traversalToken + ":DOTENV:0",
		"0|4242:1000:" + pathToken + ":DOTENV:2",
		"not-a-batch",
	}
	for _, response := range malformed {
		if _, err := parseCanaryEvents(response); err == nil {
			t.Fatalf("malformed canary batch accepted: %q", response)
		}
	}
}

func TestParseCanaryBrokerStatusStrict(t *testing.T) {
	status, err := parseCanaryBrokerStatus("roots=1:registered=2:queued=0:dropped=3:mark_failures=4:watcher=active:last_error=deadbeef")
	if err != nil {
		t.Fatalf("parse status: %v", err)
	}
	if status.Roots != 1 || status.Registered != 2 || status.Dropped != 3 || status.MarkFailures != 4 || status.Watcher != "active" {
		t.Fatalf("unexpected status: %+v", status)
	}
	for _, malformed := range []string{
		"roots=1:registered=2",
		"roots=1:registered=2:queued=0:dropped=3:mark_failures=4:watcher=unknown:last_error=deadbeef",
		"roots=x:registered=2:queued=0:dropped=3:mark_failures=4:watcher=active:last_error=deadbeef",
	} {
		if _, err := parseCanaryBrokerStatus(malformed); err == nil {
			t.Fatalf("malformed status accepted: %q", malformed)
		}
	}
}

func TestCoreCanaryTransportRejectsPathsOutsideRootBeforeIPC(t *testing.T) {
	deployer := coreCanaryDeployer{}
	if err := deployer.DeployCanary("/etc/shadow.bak", CanaryShadow, 0, 0o600, []byte("decoy")); !errors.Is(err, ErrCanaryOutsideRoot) {
		t.Fatalf("outside-root deploy error=%v, want ErrCanaryOutsideRoot", err)
	}
	if err := deployer.DeployCanary(canaryRootPath+"/x.env", CanaryDotEnv, 0, 0o600, []byte("decoy")); !errors.Is(err, ErrCanaryCoreUnavailable) {
		t.Fatalf("missing core error=%v, want ErrCanaryCoreUnavailable", err)
	}
	remover := coreCanaryRemover{}
	if err := remover.RemoveCanary("/etc/shadow.bak"); !errors.Is(err, ErrCanaryOutsideRoot) {
		t.Fatalf("outside-root remove error=%v, want ErrCanaryOutsideRoot", err)
	}
}
