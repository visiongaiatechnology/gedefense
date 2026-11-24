// STATUS: DIAMANT VGT SUPREME
// SPDX-FileCopyrightText: 2026 VisionGaia Technology
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
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
