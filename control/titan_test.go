// STATUS: DIAMANT VGT SUPREME
// SPDX-FileCopyrightText: 2026 VisionGaia Technology
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

const titanTestVersion = "5.0.0-beta.1-titan-test"

type fakeTitanFIM struct {
	mu         sync.Mutex
	records    map[string]FIMRecord
	generation uint64
	unhealthy  bool
}

func newFakeTitanFIM() *fakeTitanFIM {
	return &fakeTitanFIM{records: make(map[string]FIMRecord), generation: 7}
}

func (f *fakeTitanFIM) TitanBaselineRecord(path string) (FIMRecord, uint64, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.unhealthy {
		return FIMRecord{}, f.generation, false
	}
	record, exists := f.records[filepath.Clean(path)]
	return record, f.generation, exists
}

func (f *fakeTitanFIM) set(path, content string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.records[filepath.Clean(path)] = FIMRecord{SHA256: titanSHA256(content), Size: int64(len(content))}
}

type fakeTitanPackages struct {
	mu     sync.Mutex
	owners map[string]titanPackageOwner
	err    error
}

func newFakeTitanPackages() *fakeTitanPackages {
	return &fakeTitanPackages{owners: make(map[string]titanPackageOwner)}
}

func (f *fakeTitanPackages) Owner(_ context.Context, path string) (titanPackageOwner, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return titanPackageOwner{}, false, f.err
	}
	owner, exists := f.owners[filepath.Clean(path)]
	return owner, exists, nil
}

func (f *fakeTitanPackages) own(path, manager, pkg string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.owners[filepath.Clean(path)] = titanPackageOwner{Manager: manager, Package: pkg}
}

type fakeTitanContext struct {
	mu    sync.Mutex
	count int
	err   error
}

func (f *fakeTitanContext) RecentIncidents(context.Context, time.Time) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.count, f.err
}

type fakeTitanContainment struct {
	mu            sync.Mutex
	fail          error
	calls         int
	lastPath      string
	lastReason    string
	items         []titanQuarantineItem
	transactionID string
}

func newFakeTitanContainment() *fakeTitanContainment {
	return &fakeTitanContainment{transactionID: "TX-titan-test-01"}
}

func (f *fakeTitanContainment) RequestContain(_ context.Context, path, reason string) (titanContainmentResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	f.lastPath = path
	f.lastReason = reason
	if f.fail != nil {
		return titanContainmentResult{}, f.fail
	}
	return titanContainmentResult{TransactionID: f.transactionID, ObjectID: "QV-test", SHA256: titanSHA256("contained")}, nil
}

func (f *fakeTitanContainment) Items() []titanQuarantineItem {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]titanQuarantineItem(nil), f.items...)
}

func (f *fakeTitanContainment) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

type fakeTitanEvidence struct {
	mu      sync.Mutex
	records []EvidenceRecord
}

func (f *fakeTitanEvidence) Record(record EvidenceRecord) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.records = append(f.records, record)
	return nil
}

func (f *fakeTitanEvidence) snapshot() []EvidenceRecord {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]EvidenceRecord(nil), f.records...)
}

func (f *fakeTitanEvidence) hasKind(kind string) bool {
	for _, record := range f.snapshot() {
		if record.Kind == kind {
			return true
		}
	}
	return false
}

type titanTestRig struct {
	t           *testing.T
	engine      *TitanEngine
	cfg         TitanConfig
	root        string
	stateDir    string
	fim         *fakeTitanFIM
	packages    *fakeTitanPackages
	xdrContext  *fakeTitanContext
	containment *fakeTitanContainment
	evidence    *fakeTitanEvidence
	eventsMu    sync.Mutex
	events      []Event
	now         time.Time
}

func newTitanTestRig(t *testing.T, mutate func(*titanTestRig)) *titanTestRig {
	t.Helper()
	base := t.TempDir()
	root := filepath.Join(base, "roots")
	stateDir := filepath.Join(base, "state")
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		t.Fatal(err)
	}
	cfg := defaultTitanConfig()
	cfg.Enabled = true
	cfg.Mode = string(TitanModeObserve)
	cfg.Roots = []string{root}
	cfg.MaxFileBytes = 1 << 20
	cfg.MaxEvents = 50
	cfg.JournalMaxBytes = titanMinJournalBytes
	cfg.PolicyFile = filepath.Join(stateDir, "titan-policy.json")
	cfg.JournalFile = filepath.Join(stateDir, "titan-journal.json")
	rig := &titanTestRig{
		t: t, cfg: cfg, root: root, stateDir: stateDir,
		fim: newFakeTitanFIM(), packages: newFakeTitanPackages(), xdrContext: &fakeTitanContext{},
		containment: newFakeTitanContainment(), evidence: &fakeTitanEvidence{},
		now: time.Date(2026, 10, 22, 20, 0, 0, 0, time.UTC),
	}
	if mutate != nil {
		mutate(rig)
	}
	var containment titanContainment
	if rig.containment != nil {
		containment = rig.containment
	}
	deps := TitanDeps{
		Version: titanTestVersion, DataRoot: stateDir,
		FIM: rig.fim, Packages: rig.packages, Context: rig.xdrContext, Containment: containment,
		Evidence: rig.evidence.Record,
		Events: func(event Event) {
			rig.eventsMu.Lock()
			defer rig.eventsMu.Unlock()
			rig.events = append(rig.events, event)
		},
		Now: func() time.Time { return rig.now },
	}
	engine, err := NewTitanEngine(rig.cfg, deps)
	if err != nil {
		t.Fatalf("NewTitanEngine() error: %v", err)
	}
	rig.engine = engine
	return rig
}

func (r *titanTestRig) path(relative string) string {
	return filepath.Join(r.root, relative)
}

func (r *titanTestRig) write(relative, content string) string {
	r.t.Helper()
	path := r.path(relative)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		r.t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		r.t.Fatal(err)
	}
	return path
}

func (r *titanTestRig) observe(path string, change TitanChangeType) TitanEvent {
	r.t.Helper()
	r.engine.observe(titanObservation{Path: path, ChangeType: change, ObservedUTC: r.now, Sensor: "test-observer", Live: true})
	return r.lastEvent()
}

func (r *titanTestRig) lastEvent() TitanEvent {
	r.engine.mu.RLock()
	defer r.engine.mu.RUnlock()
	if len(r.engine.events) == 0 {
		r.t.Fatal("no Titan event recorded")
	}
	return cloneTitanEvent(r.engine.events[len(r.engine.events)-1])
}

func (r *titanTestRig) eventByID(id string) (TitanEvent, bool) {
	r.engine.mu.RLock()
	defer r.engine.mu.RUnlock()
	for index := len(r.engine.events) - 1; index >= 0; index-- {
		if r.engine.events[index].ID == id {
			return cloneTitanEvent(r.engine.events[index]), true
		}
	}
	return TitanEvent{}, false
}

func (r *titanTestRig) emittedEvents() []Event {
	r.eventsMu.Lock()
	defer r.eventsMu.Unlock()
	return append([]Event(nil), r.events...)
}

func titanSHA256(content string) string {
	digest := sha256.Sum256([]byte(content))
	return hex.EncodeToString(digest[:])
}

func TestTitanTrustAuthorizationLadder(t *testing.T) {
	t.Run("explicit allowlist authorizes a regular file", func(t *testing.T) {
		var target string
		rig := newTitanTestRig(t, func(rig *titanTestRig) {
			target = filepath.Join(rig.root, "allowed.conf")
			rig.cfg.Allowlist = []string{target}
		})
		path := rig.write("allowed.conf", "content")
		event := rig.observe(path, TitanChangeModified)
		if event.TrustState != TitanTrustAuthorized || event.Severity != "info" || event.Response != TitanResponseObserved {
			t.Fatalf("allowlisted change not authorized: %+v", event)
		}
		if event.AuthorizationReason == "" {
			t.Fatal("authorized event has no authorization reason")
		}
	})

	t.Run("approved FIM baseline authorizes matching content", func(t *testing.T) {
		var target string
		rig := newTitanTestRig(t, func(rig *titanTestRig) {
			target = filepath.Join(rig.root, "baseline.conf")
		})
		rig.fim.set(target, "approved-content")
		path := rig.write("baseline.conf", "approved-content")
		event := rig.observe(path, TitanChangeAttributes)
		if event.TrustState != TitanTrustAuthorized {
			t.Fatalf("baseline match not authorized: %+v", event)
		}
	})

	t.Run("package ownership without approval is tolerated, not authorized", func(t *testing.T) {
		var target string
		rig := newTitanTestRig(t, func(rig *titanTestRig) {})
		target = filepath.Join(rig.root, "package-owned.conf")
		rig.packages.own(target, "dpkg", "openssl")
		path := rig.write("package-owned.conf", "vendor content")
		event := rig.observe(path, TitanChangeModified)
		if event.TrustState != TitanTrustTolerated || event.Severity != "low" {
			t.Fatalf("package evidence raised trust without approval: %+v", event)
		}
		if !strings.Contains(event.AuthorizationReason, "openssl") {
			t.Fatalf("package evidence missing from reason: %+v", event)
		}
	})

	t.Run("unknown file without evidence is unexpected", func(t *testing.T) {
		rig := newTitanTestRig(t, nil)
		path := rig.write("unknown.bin", "payload")
		event := rig.observe(path, TitanChangeCreated)
		if event.TrustState != TitanTrustUnexpected || event.Severity != "medium" {
			t.Fatalf("missing evidence did not lower trust: %+v", event)
		}
	})

	t.Run("development root is tolerated, never authorized", func(t *testing.T) {
		var devRoot string
		rig := newTitanTestRig(t, func(rig *titanTestRig) {
			devRoot = filepath.Join(rig.root, "dev")
			rig.cfg.DevelopmentRoots = []string{devRoot}
		})
		path := rig.write("dev/tool.sh", "#!/bin/sh\n")
		event := rig.observe(path, TitanChangeCreated)
		if event.TrustState != TitanTrustTolerated {
			t.Fatalf("development root was treated as authorization: %+v", event)
		}
	})

	t.Run("protected baseline deviation is unexpected without context", func(t *testing.T) {
		var target, protected string
		rig := newTitanTestRig(t, func(rig *titanTestRig) {
			protected = filepath.Join(rig.root, "protected")
			rig.cfg.ProtectedPaths = []string{protected}
			target = filepath.Join(protected, "sshd_config")
		})
		rig.fim.set(target, "approved")
		path := rig.write("protected/sshd_config", "tampered")
		event := rig.observe(path, TitanChangeModified)
		if event.TrustState != TitanTrustUnexpected || event.Severity != "high" {
			t.Fatalf("protected deviation not high severity: %+v", event)
		}
	})

	t.Run("protected deviation with temporal XDR context is compromised", func(t *testing.T) {
		var target string
		rig := newTitanTestRig(t, func(rig *titanTestRig) {
			rig.cfg.ProtectedPaths = []string{filepath.Join(rig.root, "protected")}
			rig.xdrContext.count = 2
		})
		target = filepath.Join(rig.root, "protected", "authorized_keys")
		rig.fim.set(target, "old-key")
		path := rig.write("protected/authorized_keys", "attacker-key")
		event := rig.observe(path, TitanChangeModified)
		if event.TrustState != TitanTrustCompromised || event.Severity != "critical" {
			t.Fatalf("multi-signal protected deviation not compromised: %+v", event)
		}
		if event.CorrelationQuality != TitanCorrelationTemporal {
			t.Fatalf("temporal context mislabelled: %+v", event)
		}
	})

	t.Run("allowlisted symlink is never authorized", func(t *testing.T) {
		var linkTarget string
		rig := newTitanTestRig(t, func(rig *titanTestRig) {
			linkTarget = filepath.Join(rig.root, "link.conf")
			rig.cfg.Allowlist = []string{linkTarget}
		})
		real := rig.write("real.conf", "data")
		if err := os.Symlink(real, linkTarget); err != nil {
			t.Skipf("symlink not available: %v", err)
		}
		event := rig.observe(linkTarget, TitanChangeCreated)
		if event.TrustState == TitanTrustAuthorized {
			t.Fatalf("symlink was authorized: %+v", event)
		}
		if !strings.Contains(event.AuthorizationReason, "symlink") {
			t.Fatalf("symlink reason missing: %+v", event)
		}
	})

	t.Run("missing object identity is not authorized", func(t *testing.T) {
		rig := newTitanTestRig(t, nil)
		missing := filepath.Join(rig.root, "never-existed.bin")
		event := rig.observe(missing, TitanChangeCreated)
		if event.TrustState == TitanTrustAuthorized || event.SHA256 != "" {
			t.Fatalf("missing identity was fabricated: %+v", event)
		}
	})
}

func TestTitanResponseModes(t *testing.T) {
	t.Run("OBSERVE never contains", func(t *testing.T) {
		rig := newTitanTestRig(t, func(rig *titanTestRig) {
			rig.cfg.Armed = true
			rig.cfg.AutoContain = true
		})
		event := rig.observe(rig.write("observe.bin", "x"), TitanChangeCreated)
		if event.TrustState != TitanTrustUnexpected || event.Response != TitanResponseObserved {
			t.Fatalf("observe mode acted: %+v", event)
		}
		if rig.containment.callCount() != 0 {
			t.Fatal("observe mode called the containment engine")
		}
	})

	t.Run("CONTAIN disarmed takes no action", func(t *testing.T) {
		rig := newTitanTestRig(t, func(rig *titanTestRig) {
			rig.cfg.Mode = string(TitanModeContain)
			rig.cfg.Armed = false
			rig.cfg.AutoContain = true
		})
		event := rig.observe(rig.write("contain-disarmed.bin", "x"), TitanChangeCreated)
		if event.Response != TitanResponseNoAction || rig.containment.callCount() != 0 {
			t.Fatalf("disarmed containment acted: %+v", event)
		}
	})

	t.Run("CONTAIN armed with verification contains", func(t *testing.T) {
		rig := newTitanTestRig(t, func(rig *titanTestRig) {
			rig.cfg.Mode = string(TitanModeContain)
			rig.cfg.Armed = true
			rig.cfg.AutoContain = true
		})
		event := rig.observe(rig.write("contain.bin", "x"), TitanChangeCreated)
		if event.Response != TitanResponseContained || event.Containment != "CONTAINED" || event.QuarantineID == "" {
			t.Fatalf("armed containment did not report verified containment: %+v", event)
		}
		if rig.containment.callCount() != 1 {
			t.Fatalf("containment engine calls = %d, want 1", rig.containment.callCount())
		}
		if got := rig.engine.Status().QuarantineCount; got != 1 {
			t.Fatalf("quarantine count = %d, want 1", got)
		}
	})

	t.Run("CONTAIN failure is never reported as success", func(t *testing.T) {
		rig := newTitanTestRig(t, func(rig *titanTestRig) {
			rig.cfg.Mode = string(TitanModeContain)
			rig.cfg.Armed = true
			rig.cfg.AutoContain = true
			rig.containment.fail = errors.New("injected privilege failure")
		})
		event := rig.observe(rig.write("contain-fail.bin", "x"), TitanChangeCreated)
		if event.Response != TitanResponseContainFailed || event.Containment != "FAILED" {
			t.Fatalf("failed containment was reported as %q: %+v", event.Response, event)
		}
		if !rig.evidence.hasKind("titan.auto_contain.failed") {
			t.Fatal("failed containment was not evidenced")
		}
	})

	t.Run("STRICT requires review for non-contained findings", func(t *testing.T) {
		rig := newTitanTestRig(t, func(rig *titanTestRig) {
			rig.cfg.Mode = string(TitanModeStrict)
			rig.cfg.Armed = false
		})
		target := filepath.Join(rig.root, "strict-tolerated.conf")
		rig.packages.own(target, "rpm", "vendor-tool")
		event := rig.observe(rig.write("strict-tolerated.conf", "x"), TitanChangeModified)
		if event.TrustState != TitanTrustTolerated || event.Response != TitanResponseReviewRequired {
			t.Fatalf("strict tolerated change was not escalated for review: %+v", event)
		}
	})
}

func TestTitanManualContainment(t *testing.T) {
	t.Run("verified containment is recorded and viewable", func(t *testing.T) {
		rig := newTitanTestRig(t, nil)
		event := rig.observe(rig.write("manual-contain.bin", "evil"), TitanChangeCreated)
		response, err := rig.engine.Contain(context.Background(), event.ID, "operator contains a suspicious dropped file")
		if err != nil {
			t.Fatalf("containment failed: %v", err)
		}
		if response.Status != "CONTAINED" || response.Action != "QUARANTINE" || response.QuarantineID == "" {
			t.Fatalf("containment response is not honest: %+v", response)
		}
		if rig.containment.lastPath != event.Path {
			t.Fatalf("containment path = %q, want %q", rig.containment.lastPath, event.Path)
		}
		quarantine := rig.engine.Quarantine()
		if quarantine.Count != 1 || quarantine.Items[0].EventID != event.ID {
			t.Fatalf("quarantine view incomplete: %+v", quarantine)
		}
		updated, exists := rig.eventByID(event.ID)
		if !exists || updated.Containment != "CONTAINED" {
			t.Fatalf("contained event not updated: %+v", updated)
		}
	})

	t.Run("authorized changes are not contained", func(t *testing.T) {
		var target string
		rig := newTitanTestRig(t, func(rig *titanTestRig) {
			target = filepath.Join(rig.root, "authorized.bin")
			rig.cfg.Allowlist = []string{target}
		})
		event := rig.observe(rig.write("authorized.bin", "ok"), TitanChangeModified)
		response, err := rig.engine.Contain(context.Background(), event.ID, "operator tries to contain an authorized file")
		if err != nil {
			t.Fatal(err)
		}
		if response.Status != "REJECTED" || rig.containment.callCount() != 0 {
			t.Fatalf("authorized file was contained: %+v", response)
		}
	})

	t.Run("unavailable quarantine core fails closed", func(t *testing.T) {
		rig := newTitanTestRig(t, func(rig *titanTestRig) { rig.containment = nil })
		event := rig.observe(rig.write("unavailable.bin", "x"), TitanChangeCreated)
		response, err := rig.engine.Contain(context.Background(), event.ID, "operator requests unavailable containment")
		if err != nil {
			t.Fatal(err)
		}
		if response.Status != "UNAVAILABLE" || response.Action != "NONE" || response.Detail == "" {
			t.Fatalf("unavailable containment was not fail-closed: %+v", response)
		}
	})

	t.Run("transaction failure fails closed", func(t *testing.T) {
		rig := newTitanTestRig(t, func(rig *titanTestRig) {
			rig.containment.fail = errors.New("privileged core rejected the transaction")
		})
		event := rig.observe(rig.write("tx-fail.bin", "x"), TitanChangeCreated)
		response, err := rig.engine.Contain(context.Background(), event.ID, "operator requests containment that will fail")
		if err != nil {
			t.Fatal(err)
		}
		if response.Status != "UNAVAILABLE" || strings.Contains(response.Status, "CONTAINED") {
			t.Fatalf("transaction failure was reported as success: %+v", response)
		}
	})

	t.Run("unsafe paths are refused", func(t *testing.T) {
		rig := newTitanTestRig(t, nil)
		outside := filepath.Join(t.TempDir(), "outside.bin")
		if err := os.WriteFile(outside, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		event := rig.observe(outside, TitanChangeCreated)
		response, _ := rig.engine.Contain(context.Background(), event.ID, "operator requests containment of an outside path")
		if response.Status != "UNAVAILABLE" {
			t.Fatalf("outside-root containment not refused: %+v", response)
		}
		link := filepath.Join(rig.root, "unsafe-link")
		real := rig.write("unsafe-real.bin", "x")
		if err := os.Symlink(real, link); err == nil {
			linkEvent := rig.observe(link, TitanChangeCreated)
			linkResponse, _ := rig.engine.Contain(context.Background(), linkEvent.ID, "operator requests containment of a symlink")
			if linkResponse.Status == "CONTAINED" {
				t.Fatalf("symlink containment reported success: %+v", linkResponse)
			}
		}
		if err := rig.engine.validateTitanContainSafePath(rig.cfg.PolicyFile); err == nil {
			// Policy file is outside the roots in this fixture, so either guard is
			// acceptable; the important part is that it is refused.
			t.Fatal("state document was accepted for containment")
		}
	})
}

func TestTitanPolicyPersistenceAndValidation(t *testing.T) {
	t.Run("policy change persists and survives restart", func(t *testing.T) {
		rig := newTitanTestRig(t, nil)
		status, err := rig.engine.ApplyPolicy(TitanModeStrict, true, true, "operator enables strict containment for the pilot")
		if err != nil {
			t.Fatalf("policy change rejected: %v", err)
		}
		if status.Mode != TitanModeStrict || !status.Armed || !status.AutoContain {
			t.Fatalf("policy status not updated: %+v", status)
		}
		if !rig.evidence.hasKind("titan.policy.updated") {
			t.Fatal("policy change was not evidenced")
		}
		info, err := os.Stat(rig.cfg.PolicyFile)
		if err != nil {
			t.Fatalf("policy file missing: %v", err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("policy file mode = %o, want 600", info.Mode().Perm())
		}
		restarted := newTitanTestRigForCfg(t, rig.cfg, rig.stateDir)
		if got := restarted.engine.Status(); got.Mode != TitanModeStrict || !got.Armed || !got.AutoContain {
			t.Fatalf("persisted policy not restored: %+v", got)
		}
	})

	t.Run("invalid policy and reason are rejected without state change", func(t *testing.T) {
		rig := newTitanTestRig(t, nil)
		before := rig.engine.Status()
		if _, err := rig.engine.ApplyPolicy(TitanMode("NOPE"), false, false, "operator supplies an invalid mode value"); err == nil {
			t.Fatal("invalid mode accepted")
		}
		if _, err := rig.engine.ApplyPolicy(TitanModeStrict, true, true, "short"); err == nil {
			t.Fatal("short reason accepted")
		}
		if _, err := rig.engine.ApplyPolicy(TitanModeStrict, true, true, "bad\x00reason here"); err == nil {
			t.Fatal("control character reason accepted")
		}
		after := rig.engine.Status()
		if after.Mode != before.Mode || after.Armed != before.Armed {
			t.Fatalf("rejected policy mutated state: %+v", after)
		}
	})

	t.Run("corrupt policy falls back without destroying the file", func(t *testing.T) {
		base := t.TempDir()
		stateDir := filepath.Join(base, "state")
		if err := os.MkdirAll(stateDir, 0o700); err != nil {
			t.Fatal(err)
		}
		policyPath := filepath.Join(stateDir, "titan-policy.json")
		corrupt := []byte("not-a-policy")
		if err := os.WriteFile(policyPath, corrupt, 0o600); err != nil {
			t.Fatal(err)
		}
		root := filepath.Join(base, "roots")
		if err := os.MkdirAll(root, 0o700); err != nil {
			t.Fatal(err)
		}
		cfg := defaultTitanConfig()
		cfg.Roots = []string{root}
		cfg.PolicyFile = policyPath
		cfg.JournalFile = filepath.Join(stateDir, "titan-journal.json")
		engine, err := NewTitanEngine(cfg, TitanDeps{Version: titanTestVersion, DataRoot: stateDir, Now: func() time.Time { return time.Now().UTC() }})
		if err != nil {
			t.Fatalf("corrupt policy stopped the engine: %v", err)
		}
		if engine.loadWarning == "" {
			t.Fatal("corrupt policy was not surfaced")
		}
		if engine.Status().Mode != TitanModeObserve {
			t.Fatalf("corrupt policy did not fall back to configured defaults: %+v", engine.Status())
		}
		preserved, err := os.ReadFile(policyPath)
		if err != nil || string(preserved) != string(corrupt) {
			t.Fatalf("corrupt policy was modified: %v", err)
		}
	})

	t.Run("persistence failure reverts the in-memory policy", func(t *testing.T) {
		rig := newTitanTestRig(t, nil)
		if err := os.MkdirAll(rig.cfg.PolicyFile, 0o700); err != nil {
			t.Fatal(err)
		}
		before := rig.engine.Status()
		if _, err := rig.engine.ApplyPolicy(TitanModeContain, true, false, "operator enables containment while storage is broken"); err == nil {
			t.Fatal("persistence failure was reported as success")
		}
		if got := rig.engine.Status(); got.Mode != before.Mode || got.Armed != before.Armed {
			t.Fatalf("failed persistence left a changed policy: %+v", got)
		}
	})

	t.Run("configuration validation", func(t *testing.T) {
		cases := []struct {
			name   string
			mutate func(*TitanConfig)
			valid  bool
		}{
			{"default", func(*TitanConfig) {}, true},
			{"strict mode", func(c *TitanConfig) { c.Mode = "strict" }, true},
			{"invalid mode", func(c *TitanConfig) { c.Mode = "bogus" }, false},
			{"relative root", func(c *TitanConfig) { c.Roots = []string{"relative/path"} }, false},
			{"filesystem root", func(c *TitanConfig) { c.Roots = []string{"/"} }, false},
			{"nul path", func(c *TitanConfig) { c.Roots = []string{"/tmp/a\x00b"} }, false},
			{"too few events", func(c *TitanConfig) { c.MaxEvents = 1 }, false},
			{"too many bytes", func(c *TitanConfig) { c.MaxFileBytes = 1 << 40 }, false},
			{"journal outside bounds", func(c *TitanConfig) { c.JournalMaxBytes = 1 }, false},
		}
		for _, testCase := range cases {
			t.Run(testCase.name, func(t *testing.T) {
				cfg := defaultTitanConfig()
				cfg.Roots = []string{"/tmp"}
				testCase.mutate(&cfg)
				err := validateTitanConfig(&cfg)
				if testCase.valid && err != nil {
					t.Fatalf("valid config rejected: %v", err)
				}
				if !testCase.valid && err == nil {
					t.Fatal("invalid config accepted")
				}
			})
		}
		full := defaultConfig()
		full.Titan.Roots = []string{"/tmp"}
		if err := assignTitanConfig(&full, "mode", "\"contain\""); err != nil || full.Titan.Mode != "contain" {
			t.Fatalf("assign titan.mode: %v %q", err, full.Titan.Mode)
		}
		if err := assignTitanConfig(&full, "unknown", "true"); err == nil {
			t.Fatal("unknown titan key accepted")
		}
	})
}

func newTitanTestRigForCfg(t *testing.T, cfg TitanConfig, stateDir string) *titanTestRig {
	t.Helper()
	rig := &titanTestRig{
		t: t, cfg: cfg, stateDir: stateDir,
		fim: newFakeTitanFIM(), packages: newFakeTitanPackages(), xdrContext: &fakeTitanContext{},
		containment: newFakeTitanContainment(), evidence: &fakeTitanEvidence{},
		now: time.Date(2026, 10, 22, 20, 0, 0, 0, time.UTC),
	}
	var containment titanContainment = rig.containment
	deps := TitanDeps{
		Version: titanTestVersion, DataRoot: stateDir,
		FIM: rig.fim, Packages: rig.packages, Context: rig.xdrContext, Containment: containment,
		Evidence: rig.evidence.Record,
		Events:   func(Event) {},
		Now:      func() time.Time { return rig.now },
	}
	engine, err := NewTitanEngine(cfg, deps)
	if err != nil {
		t.Fatalf("NewTitanEngine() error: %v", err)
	}
	rig.engine = engine
	return rig
}

func TestTitanJournalBoundsPaginationAndReload(t *testing.T) {
	rig := newTitanTestRig(t, func(rig *titanTestRig) {
		rig.cfg.MaxEvents = titanMinJournalEvents
	})
	for index := 0; index < 60; index++ {
		rig.observe(rig.write(filepath.Join("bulk", "file-"+twoDigits(index)+".bin"), "x"), TitanChangeCreated)
	}
	status := rig.engine.Status()
	if status.EventsTotal != 60 {
		t.Fatalf("events_total = %d, want 60", status.EventsTotal)
	}
	if got := status.Trust.Unexpected + status.Trust.Authorized + status.Trust.Tolerated + status.Trust.Compromised; got != titanMinJournalEvents {
		t.Fatalf("retained trust counts = %d, want %d", got, titanMinJournalEvents)
	}
	if got := status.OpenFindings; got != titanMinJournalEvents {
		t.Fatalf("open findings = %d, want %d", got, titanMinJournalEvents)
	}
	// Pagination walks the retained window exactly once, newest-first.
	seen := make(map[string]struct{}, titanMinJournalEvents)
	cursor := ""
	firstBatch, next, err := rig.engine.Events(10, "")
	if err != nil {
		t.Fatalf("events page failed: %v", err)
	}
	if len(firstBatch) != 10 || next == "" {
		t.Fatalf("first page = %d events next=%q", len(firstBatch), next)
	}
	for _, event := range firstBatch {
		seen[event.ID] = struct{}{}
	}
	cursor = next
	for cursor != "" {
		batch, nextCursor, pageErr := rig.engine.Events(10, cursor)
		if pageErr != nil {
			t.Fatalf("page cursor %q failed: %v", cursor, pageErr)
		}
		for _, event := range batch {
			if _, duplicate := seen[event.ID]; duplicate {
				t.Fatalf("pagination returned duplicate event %s", event.ID)
			}
			seen[event.ID] = struct{}{}
		}
		cursor = nextCursor
	}
	if len(seen) != titanMinJournalEvents {
		t.Fatalf("pagination covered %d events, want %d", len(seen), titanMinJournalEvents)
	}
	// The limit is capped, never expanded by the caller.
	capped, _, err := rig.engine.Events(500, "")
	if err != nil || len(capped) > titanMaxLimit {
		t.Fatalf("event limit not capped: %d %v", len(capped), err)
	}
	if _, _, err := rig.engine.Events(10, "%%%not-base64%%%"); err == nil {
		t.Fatal("malformed cursor accepted")
	}
	// Journal file stays inside its byte budget.
	info, err := os.Stat(rig.cfg.JournalFile)
	if err != nil {
		t.Fatalf("journal file missing: %v", err)
	}
	if info.Size() > rig.cfg.JournalMaxBytes {
		t.Fatalf("journal size %d exceeds budget %d", info.Size(), rig.cfg.JournalMaxBytes)
	}
	// A restart restores the retained window and continues the sequence.
	restarted := newTitanTestRigForCfg(t, rig.cfg, rig.stateDir)
	restartedStatus := restarted.engine.Status()
	if restartedStatus.EventsTotal != 60 || restartedStatus.OpenFindings != titanMinJournalEvents {
		t.Fatalf("journal restart state wrong: %+v", restartedStatus)
	}
	events, _, err := restarted.engine.Events(titanMaxLimit, "")
	if err != nil || len(events) != titanMinJournalEvents {
		t.Fatalf("journal restart events = %d err=%v", len(events), err)
	}
	for index := 1; index < len(events); index++ {
		if events[index-1].JournalSequence <= events[index].JournalSequence {
			t.Fatalf("events are not newest-first: %d then %d", events[index-1].JournalSequence, events[index].JournalSequence)
		}
	}
}

func TestTitanJournalByteBudgetTrimming(t *testing.T) {
	rig := newTitanTestRig(t, func(rig *titanTestRig) {
		rig.cfg.MaxEvents = 300
		rig.cfg.JournalMaxBytes = titanMinJournalBytes
	})
	deep := filepath.Join("trim", strings.Repeat("d", 180), strings.Repeat("e", 180))
	if err := os.MkdirAll(rig.path(deep), 0o700); err != nil {
		t.Fatal(err)
	}
	for index := 0; index < 400; index++ {
		name := "f" + threeDigits(index)
		rig.write(filepath.Join(deep, name), "x")
		rig.engine.observe(titanObservation{Path: rig.path(filepath.Join(deep, name)), ChangeType: TitanChangeCreated, ObservedUTC: rig.now, Sensor: "test", Live: true})
	}
	info, err := os.Stat(rig.cfg.JournalFile)
	if err != nil {
		t.Fatalf("journal file missing: %v", err)
	}
	if info.Size() > titanMinJournalBytes {
		t.Fatalf("journal size %d exceeds bounded budget %d", info.Size(), titanMinJournalBytes)
	}
	rig.engine.mu.RLock()
	retained := len(rig.engine.events)
	rig.engine.mu.RUnlock()
	if retained < titanMinJournalEvents || retained > 400 {
		t.Fatalf("retained events = %d after byte trimming", retained)
	}
}

func TestTitanCorruptJournalFallsBack(t *testing.T) {
	rig := newTitanTestRig(t, nil)
	rig.observe(rig.write("one.bin", "x"), TitanChangeCreated)
	corrupt := []byte("{corrupt journal")
	if err := os.WriteFile(rig.cfg.JournalFile, corrupt, 0o600); err != nil {
		t.Fatal(err)
	}
	restarted := newTitanTestRigForCfg(t, rig.cfg, rig.stateDir)
	if restarted.engine.loadWarning == "" {
		t.Fatal("corrupt journal was not surfaced")
	}
	if got := restarted.engine.Status().EventsTotal; got != 0 {
		t.Fatalf("corrupt journal produced events_total=%d", got)
	}
	preserved, err := os.ReadFile(rig.cfg.JournalFile)
	if err != nil || string(preserved) != string(corrupt) {
		t.Fatalf("corrupt journal was modified: %v", err)
	}
}

func TestTitanReviewFlow(t *testing.T) {
	rig := newTitanTestRig(t, nil)
	event := rig.observe(rig.write("review.bin", "payload"), TitanChangeCreated)
	if got := rig.engine.Status().OpenFindings; got != 1 {
		t.Fatalf("open findings = %d, want 1", got)
	}
	updated, err := rig.engine.Review(event.ID, "REVIEWED", "operator reviewed the dropped file and accepted the finding")
	if err != nil {
		t.Fatalf("review failed: %v", err)
	}
	if updated.Review != "REVIEWED" || updated.ReviewReason == "" {
		t.Fatalf("review state not recorded: %+v", updated)
	}
	if got := rig.engine.Status().OpenFindings; got != 0 {
		t.Fatalf("open findings after review = %d, want 0", got)
	}
	if !rig.evidence.hasKind("titan.review") {
		t.Fatal("review was not evidenced")
	}
	if _, err := rig.engine.Review(event.ID, "SOMETHING", "operator supplies an invalid review decision"); err == nil {
		t.Fatal("invalid review decision accepted")
	}
	if _, err := rig.engine.Review("deadbeefdeadbeef", "REVIEWED", "operator reviews an unknown event identifier"); err == nil {
		t.Fatal("unknown event accepted")
	}
	if _, err := rig.engine.Review(event.ID, "ESCALATED", "short"); err == nil {
		t.Fatal("short review reason accepted")
	}
}

func TestTitanStatusAndEventJSONContract(t *testing.T) {
	rig := newTitanTestRig(t, nil)
	event := rig.observe(rig.write("contract.bin", "x"), TitanChangeCreated)
	statusJSON, err := json.Marshal(rig.engine.Status())
	if err != nil {
		t.Fatalf("status marshal: %v", err)
	}
	var status map[string]json.RawMessage
	if err := json.Unmarshal(statusJSON, &status); err != nil {
		t.Fatalf("status unmarshal: %v", err)
	}
	for _, key := range []string{"version", "mode", "armed", "auto_contain", "trust", "correlation", "events_total", "open_findings", "quarantine_count", "sensor", "updated_utc"} {
		if _, exists := status[key]; !exists {
			t.Fatalf("status JSON missing %q: %s", key, statusJSON)
		}
	}
	var trust map[string]json.RawMessage
	if err := json.Unmarshal(status["trust"], &trust); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"AUTHORIZED", "TOLERATED", "UNEXPECTED", "COMPROMISED"} {
		if _, exists := trust[key]; !exists {
			t.Fatalf("trust JSON missing %q", key)
		}
	}
	var correlation map[string]json.RawMessage
	if err := json.Unmarshal(status["correlation"], &correlation); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"OBSERVED", "TEMPORAL", "NONE"} {
		if _, exists := correlation[key]; !exists {
			t.Fatalf("correlation JSON missing %q", key)
		}
	}
	var sensor map[string]json.RawMessage
	if err := json.Unmarshal(status["sensor"], &sensor); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"state", "last_observation_utc", "error"} {
		if _, exists := sensor[key]; !exists {
			t.Fatalf("sensor JSON missing %q", key)
		}
	}
	if string(sensor["last_observation_utc"]) != "null" {
		// After the observation above the timestamp must be present and RFC3339.
		var timestamp time.Time
		if err := json.Unmarshal(sensor["last_observation_utc"], &timestamp); err != nil || timestamp.IsZero() {
			t.Fatalf("sensor last_observation_utc is not a RFC3339 timestamp: %s", sensor["last_observation_utc"])
		}
	}
	eventJSON, err := json.Marshal(event)
	if err != nil {
		t.Fatalf("event marshal: %v", err)
	}
	var eventMap map[string]json.RawMessage
	if err := json.Unmarshal(eventJSON, &eventMap); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"id", "observed_utc", "path", "change_type", "trust_state", "authorization_reason", "response", "correlation_quality", "severity", "sensor", "sha256", "size"} {
		if _, exists := eventMap[key]; !exists {
			t.Fatalf("event JSON missing %q: %s", key, eventJSON)
		}
	}
	quarantineJSON, err := json.Marshal(rig.engine.Quarantine())
	if err != nil {
		t.Fatal(err)
	}
	var quarantine map[string]json.RawMessage
	if err := json.Unmarshal(quarantineJSON, &quarantine); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"items", "count"} {
		if _, exists := quarantine[key]; !exists {
			t.Fatalf("quarantine JSON missing %q", key)
		}
	}
}

func TestTitanSensorHealthAndDisabledStates(t *testing.T) {
	t.Run("sensor failure degrades status and is evidenced", func(t *testing.T) {
		rig := newTitanTestRig(t, func(rig *titanTestRig) {
			rig.cfg.Roots = []string{rig.root}
		})
		engine, err := NewTitanEngine(rig.cfg, TitanDeps{
			Version: titanTestVersion, DataRoot: rig.stateDir,
			Observer: failingTitanObserver{err: errors.New("injected inotify failure")},
			Evidence: rig.evidence.Record, Events: func(Event) {},
			Now: func() time.Time { return rig.now },
		})
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		go func() { engine.Run(ctx); close(done) }()
		deadline := time.Now().Add(4 * time.Second)
		status := engine.Status()
		for time.Now().Before(deadline) {
			status = engine.Status()
			if status.Sensor.State == "degraded" && status.Sensor.Error != "" && rig.evidence.hasKind("titan.sensor.failed") {
				break
			}
			time.Sleep(10 * time.Millisecond)
		}
		if status.Sensor.State != "degraded" || status.Sensor.Error == "" {
			t.Fatalf("sensor failure did not degrade status: %+v", status.Sensor)
		}
		if !rig.evidence.hasKind("titan.sensor.failed") {
			t.Fatal("sensor failure was not evidenced")
		}
		cancel()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Fatal("Titan Run did not stop after cancellation")
		}
	})

	t.Run("disabled module reports an explicit disabled sensor", func(t *testing.T) {
		rig := newTitanTestRig(t, func(rig *titanTestRig) { rig.cfg.Enabled = false })
		status := rig.engine.Status()
		if status.Sensor.State != "disabled" {
			t.Fatalf("disabled Titan sensor = %q", status.Sensor.State)
		}
		rig.engine.Run(context.Background())
	})
}

type failingTitanObserver struct {
	err error
}

func (o failingTitanObserver) Run(context.Context, []string, chan<- titanObservation) error {
	return o.err
}

func TestTitanNilSafety(t *testing.T) {
	var engine *TitanEngine
	if status := engine.Status(); status.Sensor.State != "disabled" {
		t.Fatalf("nil engine status = %+v", status)
	}
	if engine.Enabled() {
		t.Fatal("nil engine reported enabled")
	}
	if _, _, err := engine.Events(10, ""); err == nil {
		t.Fatal("nil engine accepted an events query")
	}
	if _, err := engine.ApplyPolicy(TitanModeObserve, false, false, "operator calls a nil Titan engine"); err == nil {
		t.Fatal("nil engine accepted a policy update")
	}
	if _, err := engine.Review("deadbeefdeadbeef", "REVIEWED", "operator calls a nil Titan engine"); err == nil {
		t.Fatal("nil engine accepted a review")
	}
	if _, err := engine.Contain(context.Background(), "deadbeefdeadbeef", "operator calls a nil Titan engine"); err == nil {
		t.Fatal("nil engine accepted containment")
	}
	if quarantine := engine.Quarantine(); quarantine.Count != 0 {
		t.Fatalf("nil engine quarantine = %+v", quarantine)
	}
	if policy := engine.Policy(); policy.Mode != "" {
		t.Fatalf("nil engine policy = %+v", policy)
	}
}

func twoDigits(value int) string {
	if value < 10 {
		return "0" + string(rune('0'+value))
	}
	return string(rune('0'+value/10)) + string(rune('0'+value%10))
}

func threeDigits(value int) string {
	return string([]rune{'0' + rune(value/100), '0' + rune((value/10)%10), '0' + rune(value%10)})
}
