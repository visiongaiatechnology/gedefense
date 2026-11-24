// STATUS: DIAMANT VGT SUPREME

package main

// V6.3.0 AP-7: PermitV1 broker test corpus.
//
// Covers TTL expiry, invalid signer handling, corrupt/duplicate store
// fail-closed behaviour, AUTHORIZED suppression (evidence, no response),
// TOLERATED downgrade (alert/none, evidence kept), ANALYST_MODE record-only,
// non-suppressible kernel rules, the never-auto-block dev-build simulation,
// auto-invalidation, store atomicity/mode and TTL bounds.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// --------------------------------------------------------- engine integration

func TestPermitAuthorizedSuppressionRecordsEvidenceNoResponse(t *testing.T) {
	dir := t.TempDir()
	e := newAP7TestEngine(t, dir)
	publicKey, privateKey := permitTestKeypair(t)
	broker := newBoundPermitTestBroker(t, dir, publicKey, privateKey)
	sample, digest, inode, ruleIDs := permitEngineSample(t, dir, "cargo")
	permit := permitTestObject(t, time.Now().UTC(), permitTrustAuthorized, sample.Exe, digest, inode,
		permitTestScope(ruleIDs...), time.Hour)
	if err := broker.UpsertPermit(permit); err != nil {
		t.Fatalf("upsert authorized permit: %v", err)
	}
	e.permits = broker

	e.evaluate(sample, nil, "exec")
	if incidents := permitIncidentCount(e); incidents != 0 {
		t.Fatalf("AUTHORIZED permit still produced %d incident(s)", incidents)
	}
	if kinds := permitEventKinds(e); !permitContainsKind(kinds, "xdr.permit.authorized_suppressed") {
		t.Fatalf("AUTHORIZED suppression did not record a bounded event: %v", kinds)
	}
}

func TestPermitToleratedDowngradesToAlertAndKeepsEvidence(t *testing.T) {
	dir := t.TempDir()
	e := newAP7TestEngine(t, dir)
	publicKey, privateKey := permitTestKeypair(t)
	broker := newBoundPermitTestBroker(t, dir, publicKey, privateKey)
	sample, digest, inode, ruleIDs := permitEngineSample(t, dir, "cargo")
	permit := permitTestObject(t, time.Now().UTC(), permitTrustTolerated, sample.Exe, digest, inode,
		permitTestScope(ruleIDs...), time.Hour)
	if err := broker.UpsertPermit(permit); err != nil {
		t.Fatalf("upsert tolerated permit: %v", err)
	}
	e.permits = broker

	e.evaluate(sample, nil, "exec")
	snapshot := e.state.Snapshot()
	if len(snapshot.Incidents) != 1 {
		t.Fatalf("TOLERATED finding was not kept as evidence: %d incidents", len(snapshot.Incidents))
	}
	incident := snapshot.Incidents[0]
	if incident.Decision != "alert" || incident.Action != "none" {
		t.Fatalf("TOLERATED permit did not downgrade to alert/none: decision=%q action=%q", incident.Decision, incident.Action)
	}
	if incident.Permit == nil || incident.Permit.TrustLevel != permitTrustTolerated || incident.Permit.PermitID != permit.PermitID {
		t.Fatalf("TOLERATED incident lacks its permit metadata: %+v", incident.Permit)
	}
	// Evidence semantics are untouched: the score the detector computed stays.
	if incident.Score <= 0 || incident.ResponseScore <= 0 {
		t.Fatalf("permit downgrade destroyed the evidence score: %+v", incident)
	}
	if incident.Explainability == nil || len(incident.Explainability.Rules) == 0 {
		t.Fatal("downgraded incident lacks the mandatory explainability block")
	}
}

func TestPermitAnalystModeRecordsForReviewOnly(t *testing.T) {
	dir := t.TempDir()
	e := newAP7TestEngine(t, dir)
	broker := newBoundPermitTestBroker(t, dir, nil, nil)
	sample, digest, inode, ruleIDs := permitEngineSample(t, dir, "cargo")
	permit := permitTestObject(t, time.Now().UTC(), permitTrustAnalyst, sample.Exe, digest, inode,
		permitTestScope(ruleIDs...), time.Hour)
	if err := broker.UpsertPermit(permit); err != nil {
		t.Fatalf("upsert analyst permit: %v", err)
	}
	e.permits = broker

	e.evaluate(sample, nil, "exec")
	snapshot := e.state.Snapshot()
	if len(snapshot.Incidents) != 1 {
		t.Fatalf("ANALYST_MODE finding was not recorded: %d incidents", len(snapshot.Incidents))
	}
	incident := snapshot.Incidents[0]
	if incident.Decision != "alert" || incident.Action != "none" {
		t.Fatalf("ANALYST_MODE finding was actionable: decision=%q action=%q", incident.Decision, incident.Action)
	}
	if incident.Permit == nil || incident.Permit.TrustLevel != permitTrustAnalyst {
		t.Fatalf("ANALYST_MODE incident lacks its permit metadata: %+v", incident.Permit)
	}
}

func TestPermitNoPermitKeepsTheUnchangedKillGate(t *testing.T) {
	dir := t.TempDir()
	e := newAP7TestEngine(t, dir)
	// No bound broker at all: the kill gate must behave exactly as before.
	sample, _, _, _ := permitEngineSample(t, dir, "cargo")
	decision := e.rules.EvaluateProcess(sample, nil, nil, nil)
	if decision.Decision != "kill" {
		t.Fatalf("precondition failed: the dev-build sample no longer reaches the kill gate: %+v", decision)
	}
	if permit := e.evaluatePermitBroker(sample, decision); permit != nil {
		t.Fatalf("unbound broker invented a permit: %+v", permit)
	}
}

// --------------------------------------------------------- suppressible scope

func TestPermitNonSuppressibleKernelRulesStayIncident(t *testing.T) {
	dir := t.TempDir()
	publicKey, privateKey := permitTestKeypair(t)
	broker := newBoundPermitTestBroker(t, dir, publicKey, privateKey)
	sample, digest, inode := permitTestExecutable(t, dir, "cargo", []byte("permit-kernel-rule"))
	permit := permitTestObject(t, time.Now().UTC(), permitTrustAuthorized, sample, digest, inode,
		permitTestScope("XDR.CREDENTIAL_READ_BLOCKED", "XDR.SELF_TAMPER"), time.Hour)
	if err := broker.UpsertPermit(permit); err != nil {
		t.Fatalf("upsert kernel-rule permit: %v", err)
	}
	for _, ruleID := range []string{"XDR.CREDENTIAL_READ_BLOCKED", "XDR.SELF_TAMPER", "MALWARE.CONTENT_MATCH", "XDR.RANSOM_ENTROPY_BURST"} {
		decision := broker.Evaluate(ProcessSample{PID: 37, Comm: "cargo", Exe: sample}, []string{ruleID}, []string{"credential"})
		if decision != nil {
			t.Fatalf("non-suppressible rule %s was suppressed by a permit: %+v", ruleID, decision)
		}
	}
}

func TestPermitScopeMustCoverEveryRule(t *testing.T) {
	dir := t.TempDir()
	publicKey, privateKey := permitTestKeypair(t)
	broker := newBoundPermitTestBroker(t, dir, publicKey, privateKey)
	// Deliberately not a built-in profile name: this test proves the stored
	// permit's own scope/lineage checks, not the profile fallback.
	sample, digest, inode := permitTestExecutable(t, dir, "ap7-scope-tool", []byte("permit-scope"))
	permit := permitTestObject(t, time.Now().UTC(), permitTrustAuthorized, sample, digest, inode,
		permitTestScope("XDR.TEMP_EXEC"), time.Hour)
	if err := broker.UpsertPermit(permit); err != nil {
		t.Fatalf("upsert scope permit: %v", err)
	}
	process := ProcessSample{PID: 38, Comm: "cargo", Exe: sample}
	if decision := broker.Evaluate(process, []string{"XDR.TEMP_EXEC"}, []string{"origin"}); decision == nil {
		t.Fatal("fully covered rule did not match")
	}
	if decision := broker.Evaluate(process, []string{"XDR.TEMP_EXEC", "KD.LINUX.REVERSE_SHELL"}, []string{"origin", "network"}); decision != nil {
		t.Fatalf("out-of-scope rule was suppressed: %+v", decision)
	}
	// Parent lineage and path scope are enforced too; replace the unrestricted
	// permit so only the lineage-constrained object can match.
	if err := broker.RemovePermit(permit.PermitID); err != nil {
		t.Fatalf("remove unrestricted permit: %v", err)
	}
	lineagePermit := permitTestObject(t, time.Now().UTC(), permitTrustAuthorized, sample, digest, inode,
		permitTestScope("XDR.TEMP_EXEC"), time.Hour)
	lineagePermit.AllowedParents = []string{"/usr/bin/systemd"}
	if err := broker.UpsertPermit(lineagePermit); err != nil {
		t.Fatalf("upsert lineage permit: %v", err)
	}
	process.ParentExe = "/bin/bash"
	if decision := broker.Evaluate(process, []string{"XDR.TEMP_EXEC"}, []string{"origin"}); decision != nil {
		t.Fatalf("permit matched a disallowed parent lineage: %+v", decision)
	}
}

// ------------------------------------------------------------- never-auto-block

// TestPermitNeverAutoBlockDevBuildSimulation is the anti-FP gate: realistic
// development false-positive combinations reach the unchanged kill gate without
// a permit, and every built-in TOLERATED profile downgrades them so the
// simulation yields zero kill decisions.
func TestPermitNeverAutoBlockDevBuildSimulation(t *testing.T) {
	broker := NewPermitBroker()
	devMatches := []RuleMatch{
		{ID: "XDR.TEMP_EXEC", Category: "origin", Score: 55, Summary: "temporary build path", KillEligible: true},
		{ID: "BASELINE.PARENT_MISMATCH", Category: "lineage", Score: 50, Summary: "build daemon parent", KillEligible: true},
		{ID: "XDR.NAME_PATH_MISMATCH", Category: "masquerading", Score: 15, Summary: "build wrapper name"},
		{ID: "BASELINE.UID_MISMATCH", Category: "identity", Score: 55, Summary: "service uid"},
	}
	baseline := combineMatches(devMatches)
	if baseline.Decision != "kill" {
		t.Fatalf("kill gate precondition broken: %+v", baseline)
	}
	devTools := []string{"cargo", "rustc", "go", "gcc", "cc", "make", "npm", "node", "pytest"}
	runtimeTools := []string{"runc", "containerd", "containerd-shim", "dockerd", "podman"}
	securityTools := []string{"bpftrace", "perf", "cilium", "cilium-agent", "falco", "tetragon", "tcpdump", "dumpcap", "gdb"}
	killDecisions := 0
	for _, tools := range [][]string{devTools, runtimeTools, securityTools} {
		for _, tool := range tools {
			sample := ProcessSample{PID: 500, Comm: tool, Exe: "/usr/bin/" + tool, ParentExe: "/usr/bin/build-daemon"}
			permit := broker.Evaluate(sample, baseline.RuleIDs, baseline.Categories)
			if permit == nil {
				t.Fatalf("built-in profile did not explain the dev/build finding for %q", tool)
			}
			if permit.TrustLevel != permitTrustTolerated {
				t.Fatalf("built-in profile for %q is not TOLERATED: %+v", tool, permit)
			}
			decided := applyPermitDecision(baseline, permit)
			if decided.Decision == "kill" || decided.Decision == "contain" {
				t.Fatalf("dev-build simulation produced %q for %q", decided.Decision, tool)
			}
			if decided.Score != baseline.Score || decided.ResponseScore != baseline.ResponseScore {
				t.Fatalf("permit changed evidence scores for %q: %+v", tool, decided)
			}
		}
	}
	// Web service pools only own the non-kill part of the scope: they must not
	// claim a kill-eligible finding, and the kill decision therefore never
	// becomes a tolerated one.
	for _, tool := range []string{"nginx", "php-fpm8.2", "mariadbd", "mysqld", "postgres", "redis-server"} {
		sample := ProcessSample{PID: 501, Comm: tool, Exe: "/usr/sbin/" + tool}
		if permit := broker.Evaluate(sample, baseline.RuleIDs, baseline.Categories); permit != nil {
			t.Fatalf("web pool profile claimed a kill-eligible finding for %q: %+v", tool, permit)
		}
	}
	if killDecisions != 0 {
		t.Fatalf("dev-build simulation produced %d kill decisions", killDecisions)
	}
}

// ------------------------------------------------------------ auto-invalidate

func TestPermitAutoInvalidatesOnBinaryChange(t *testing.T) {
	dir := t.TempDir()
	publicKey, privateKey := permitTestKeypair(t)
	broker := newBoundPermitTestBroker(t, dir, publicKey, privateKey)
	now := time.Now().UTC()
	executable, digest, inode := permitTestExecutable(t, dir, "tool-i", []byte("permit-binary-change"))
	permit := permitTestObject(t, now, permitTrustTolerated, executable, digest, inode,
		permitTestScope("XDR.TEMP_EXEC"), time.Hour)
	permit.AutoInvalidateOn = []string{"binary_changed"}
	if err := broker.UpsertPermit(permit); err != nil {
		t.Fatalf("upsert auto-invalidating permit: %v", err)
	}
	if err := os.WriteFile(executable, []byte("replaced binary payload"), 0o755); err != nil {
		t.Fatalf("replace permitted executable: %v", err)
	}
	invalidated, err := broker.invalidateBinaryChanges(now.Add(time.Minute))
	if err != nil {
		t.Fatalf("invalidate changed binaries: %v", err)
	}
	if invalidated != 1 {
		t.Fatalf("changed executable did not invalidate the permit: %d", invalidated)
	}
	if report := broker.PermitReport(); report.Stored != 0 {
		t.Fatalf("invalidated permit still stored: %+v", report)
	}
	reloaded := newBoundPermitTestBroker(t, dir, publicKey, privateKey)
	if report := reloaded.PermitReport(); report.Stored != 0 {
		t.Fatalf("binary invalidation was not persisted: %+v", report)
	}
}

func TestPermitInvalidatePermitsByEventKind(t *testing.T) {
	dir := t.TempDir()
	publicKey, privateKey := permitTestKeypair(t)
	broker := newBoundPermitTestBroker(t, dir, publicKey, privateKey)
	now := time.Now().UTC()
	executable, digest, inode := permitTestExecutable(t, dir, "tool-j", []byte("permit-policy-update"))
	permit := permitTestObject(t, now, permitTrustTolerated, executable, digest, inode,
		permitTestScope("XDR.TEMP_EXEC"), time.Hour)
	permit.AutoInvalidateOn = []string{"policy_update"}
	if err := broker.UpsertPermit(permit); err != nil {
		t.Fatalf("upsert policy-invalidated permit: %v", err)
	}
	removed, err := broker.InvalidatePermits("policy_update")
	if err != nil || removed != 1 {
		t.Fatalf("policy_update invalidation failed: removed=%d err=%v", removed, err)
	}
	if _, err := broker.InvalidatePermits("unknown_event"); err == nil {
		t.Fatal("unknown invalidation kind was accepted")
	}
	if report := broker.PermitReport(); report.Stored != 0 {
		t.Fatalf("invalidated permit still stored: %+v", report)
	}
}

func TestPermitStoreSizeBoundRefusesUnreadableDocument(t *testing.T) {
	dir := t.TempDir()
	broker := newBoundPermitTestBroker(t, dir, nil, nil)
	now := time.Now().UTC()
	// 140 permits x ~33 KiB scope exceeds the 4 MiB plaintext bound; writing
	// such a document would be unreadable at the next startup, so the broker
	// must refuse it as a capacity condition before the atomic rename.
	rules := make([]string, permitMaxScopeRules)
	for index := range rules {
		rules[index] = strings.Repeat("R", permitMaxFieldBytes)
	}
	large := make(map[string]*PermitV1, 140)
	for index := 0; index < 140; index++ {
		permitID, err := newPermitID()
		if err != nil {
			t.Fatalf("mint permit id: %v", err)
		}
		large[permitID] = &PermitV1{
			Schema: permitSchemaV1, PermitID: permitID, TrustLevel: permitTrustAnalyst,
			SHA256: strings.Repeat("ab", 32), Inode: PermitInode{Device: 8, Inode: uint64(index + 1)},
			Scope: PermitScope{Rules: rules}, ValidFrom: now, ValidUntil: now.Add(time.Hour),
			Signature: permitSignatureAbsent,
		}
	}
	broker.mu.Lock()
	err := broker.persistPermitStoreLocked(large)
	broker.mu.Unlock()
	if err == nil {
		t.Fatal("an unreadable oversized permit store was persisted")
	}
	if !strings.Contains(err.Error(), "size bound") {
		t.Fatalf("oversized store was rejected for the wrong reason: %v", err)
	}
	if _, statErr := os.Lstat(filepath.Join(dir, permitStoreFileName)); statErr == nil {
		t.Fatal("a refused oversized store must not replace the on-disk store")
	}
}

// --------------------------------------------------------------- report shape

func TestPermitReportIsBoundedAndHonest(t *testing.T) {
	broker := NewPermitBroker()
	report := broker.PermitReport()
	if report.Loaded || report.Corrupt {
		t.Fatalf("an unbound broker must report neither loaded nor corrupt: %+v", report)
	}
	if report.BuiltinProfiles != len(builtinPermitProfiles()) {
		t.Fatalf("built-in profile count not reported: %+v", report)
	}
	if report.SignatureStatus != permitSignatureAbsent {
		t.Fatalf("unbound broker claimed a signature key: %+v", report)
	}
	if report.Authorized != 0 || report.Stored != 0 {
		t.Fatalf("inert broker reported active permits: %+v", report)
	}
}
