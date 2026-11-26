// V6.3.0 AP-5 regression tests: XDR classification/anti-false-positive policy,
// the one-shot arm/baseline cycle, dedupe/rate-limit and the honest operator
// report. Every finding must stay observe-only (Decision "alert", Action
// "none") and the correlation quality must never claim a lock state the core
// cannot observe.

package main

import (
	"os"
	"strings"
	"testing"
	"time"
)

type fakePersistenceCore struct {
	status        CorePersistenceStatus
	statusErr     error
	events        []CorePersistenceEvent
	dropped       uint64
	eventsErr     error
	setErr        error
	baselineErr   error
	setCalls      int
	baselineCalls int
	statusCalls   int
	eventCalls    int
	lastSet       bool
}

func (f *fakePersistenceCore) PersistenceStatus() (CorePersistenceStatus, error) {
	f.statusCalls++
	return f.status, f.statusErr
}

func (f *fakePersistenceCore) PersistenceEvents() ([]CorePersistenceEvent, uint64, error) {
	f.eventCalls++
	return f.events, f.dropped, f.eventsErr
}

func (f *fakePersistenceCore) PersistenceSet(enabled bool) error {
	f.setCalls++
	f.lastSet = enabled
	if f.setErr != nil {
		return f.setErr
	}
	if enabled {
		f.status.Enabled = true
	}
	return nil
}

func (f *fakePersistenceCore) PersistenceBaseline() (string, error) {
	f.baselineCalls++
	return "roots=5:verified=5:drifted=0:at_ms=1700000000000", f.baselineErr
}

func newPersistenceTestEngine(core persistenceCore) *XDREngine {
	return &XDREngine{
		state:           NewState("test", defaultConfig()),
		persistenceCore: core,
		selfPID:         os.Getpid(),
		persistenceSeen: map[string]time.Time{},
	}
}

func persistenceEngineWithStatus(core persistenceCore, status CorePersistenceStatus) *XDREngine {
	engine := newPersistenceTestEngine(core)
	engine.persistenceStatus = status
	engine.persistenceStatusAt = time.Now().UTC()
	engine.persistenceCapabilityKnown = true
	return engine
}

func persistenceHealthyStatus() CorePersistenceStatus {
	return CorePersistenceStatus{
		Enabled:           true,
		Attached:          true,
		AttachedMask:      PersistenceHookFileOpen | PersistenceHookMmap | PersistenceHookPtrace | PersistenceHookReadv | PersistenceHookWritev | PersistenceStatusIdentityOffsets | PersistenceStatusPkgdbReady | PersistenceStatusSessionsKnown,
		HookFileOpen:      true,
		HookMmap:          true,
		HookPtrace:        true,
		HookReadv:         true,
		HookWritev:        true,
		IdentityOffsetsOK: true,
		PkgdbReady:        true,
		SessionsKnown:     true,
		Pkgdb:             "dpkg",
		SessionsTotal:     2,
		SessionsActive:    1,
		SessionsInactive:  1,
		IdleHint:          "unavailable",
	}
}

func persistenceIntegrityEvent(comm string, class uint8, detail uint32) CorePersistenceEvent {
	return CorePersistenceEvent{
		TsNS: 1_700_000_000_000_000_000, PID: 4242, TGID: 4242, UID: 1000,
		Class: class, Kind: PersistenceKindIntegrityWrite, Action: PersistenceActionAudit,
		DetailCode: detail, Dev: 8, Ino: 123456, Comm: comm,
	}
}

func persistenceDeviceEvent(comm string, class uint8, detail uint32) CorePersistenceEvent {
	return CorePersistenceEvent{
		TsNS: 1_700_000_000_000_000_001, PID: 4242, TGID: 4242, UID: 1000,
		Class: class, Kind: PersistenceKindPeripheralOpen, Action: PersistenceActionAudit,
		DetailCode: detail, Dev: 8, Ino: 777, Comm: comm,
	}
}

func TestPersistenceEventClassification(t *testing.T) {
	status := persistenceHealthyStatus()
	engine := newPersistenceTestEngine(nil)

	// Linker-path write by a plain process: LD_PRELOAD integrity, OBSERVED.
	assessment := engine.assessPersistenceEvent(persistenceIntegrityEvent("bash", PersistenceClassLDPreload, 1), status)
	if assessment.Tolerated || assessment.InfoOnly || assessment.RuleID != PersistenceRuleLDPreload ||
		assessment.Score != 110 || assessment.CorrelationQuality != persistenceQualityObserved ||
		assessment.Severity != "high" {
		t.Fatalf("linker write assessment is wrong: %+v", assessment)
	}
	// Read-only open is information, not an incident.
	assessment = engine.assessPersistenceEvent(persistenceIntegrityEvent("bash", PersistenceClassLDPreload, 0), status)
	if !assessment.InfoOnly || assessment.Tolerated {
		t.Fatalf("read-only persistence open must stay informational: %+v", assessment)
	}
	// Unknown access intent must stay conservative (a possible write) and say so.
	assessment = engine.assessPersistenceEvent(persistenceIntegrityEvent("bash", PersistenceClassPAM, PersistenceDetailAccUnknown), status)
	if assessment.InfoOnly || len(assessment.Limitations) == 0 ||
		!strings.Contains(strings.Join(assessment.Limitations, ";"), "access intent unknown") {
		t.Fatalf("unknown access intent must be conservative with an explicit limitation: %+v", assessment)
	}
	// systemd drop-in write by a plain process: entry drift.
	assessment = engine.assessPersistenceEvent(persistenceIntegrityEvent("bash", PersistenceClassSystemdDropin, 2), status)
	if assessment.RuleID != PersistenceRuleDrift || assessment.Score != 100 {
		t.Fatalf("systemd drop-in write must be XDR.PERSISTENCE_ENTRY_DRIFT: %+v", assessment)
	}
	// Drift records reuse the class ladder.
	drift := persistenceIntegrityEvent("bash", PersistenceClassLDConf, PersistenceDriftContent)
	drift.Kind = PersistenceKindDrift
	assessment = engine.assessPersistenceEvent(drift, status)
	if assessment.RuleID != PersistenceRuleLDPreload || assessment.Score != 110 ||
		!strings.Contains(assessment.Summary, "SHA-256 drift") {
		t.Fatalf("linker drift must be XDR.LD_PRELOAD_INTEGRITY: %+v", assessment)
	}

	// Foreign library mapped into sshd: LINKER_HOOK with an observable pkgdb.
	mmapEvent := CorePersistenceEvent{TsNS: 10, PID: 4242, TGID: 4242, UID: 0,
		Class: PersistenceClassLDSO, Kind: PersistenceKindLibraryMmap,
		Action: PersistenceActionAudit, DetailCode: 5, Dev: 8, Ino: 99, Comm: "sshd"}
	assessment = engine.assessPersistenceEvent(mmapEvent, status)
	if assessment.RuleID != PersistenceRuleLinker || assessment.Score != 120 ||
		assessment.CorrelationQuality != persistenceQualityObserved || assessment.Tolerated {
		t.Fatalf("foreign library assessment is wrong: %+v", assessment)
	}
	// pkgdb unsupported: still an incident but explicitly NONE, never ownership.
	unsupported := status
	unsupported.Pkgdb = "unsupported"
	unsupported.PkgdbReady = false
	assessment = engine.assessPersistenceEvent(mmapEvent, unsupported)
	if assessment.CorrelationQuality != persistenceQualityNone ||
		!strings.Contains(strings.Join(assessment.Limitations, ";"), "pkgdb=unsupported") {
		t.Fatalf("pkgdb-unsupported library event must state the limitation: %+v", assessment)
	}

	// Camera without an active session: TEMPORAL, never OBSERVED lock state.
	assessment = engine.assessPersistenceEvent(
		persistenceDeviceEvent("bash", PersistenceClassDeviceCamera, PersistenceDetailSessionKnown), status)
	if assessment.RuleID != PersistenceRulePeripheral || assessment.Score != 90 ||
		assessment.CorrelationQuality != persistenceQualityTemporal ||
		!strings.Contains(strings.Join(assessment.Limitations, ";"), "idlehint=unavailable") {
		t.Fatalf("inactive-session camera access must be TEMPORAL with the idlehint limitation: %+v", assessment)
	}
	// Desktop-session owner reading its own camera: TOLERATED.
	assessment = engine.assessPersistenceEvent(persistenceDeviceEvent("pipewire", PersistenceClassDeviceCamera,
		PersistenceDetailSessionKnown|PersistenceDetailSessionActive), status)
	if !assessment.Tolerated {
		t.Fatalf("desktop-session media owner must be tolerated: %+v", assessment)
	}
	// Active session but a non-desktop process: incident with NONE correlation.
	assessment = engine.assessPersistenceEvent(persistenceDeviceEvent("bash", PersistenceClassDeviceCamera,
		PersistenceDetailSessionKnown|PersistenceDetailSessionActive), status)
	if assessment.Tolerated || assessment.CorrelationQuality != persistenceQualityNone {
		t.Fatalf("non-desktop device access during an active session must not be tolerated nor temporally explained: %+v", assessment)
	}
	// No session view at all: information only, no incident on a guess.
	assessment = engine.assessPersistenceEvent(persistenceDeviceEvent("bash", PersistenceClassDeviceCamera, 0), status)
	if !assessment.InfoOnly {
		t.Fatalf("missing session view must not produce a session-inactive incident: %+v", assessment)
	}
	// evdev by a plain process during an active session: keylogger-class.
	assessment = engine.assessPersistenceEvent(persistenceDeviceEvent("bash", PersistenceClassDeviceEvdev,
		PersistenceDetailSessionKnown|PersistenceDetailSessionActive), status)
	if assessment.RuleID != PersistenceRuleEvdev || assessment.Score != 100 || assessment.Tolerated {
		t.Fatalf("non-input-consumer evdev access must be EVDEV_KEYLOG_PROBE: %+v", assessment)
	}
	// Legitimate input consumer during an active session: TOLERATED.
	assessment = engine.assessPersistenceEvent(persistenceDeviceEvent("systemd-logind", PersistenceClassDeviceEvdev,
		PersistenceDetailSessionKnown|PersistenceDetailSessionActive), status)
	if !assessment.Tolerated {
		t.Fatalf("legitimate evdev consumer must be tolerated: %+v", assessment)
	}

	// Secret store opened by the expected tool is tolerated; by another tool it
	// is an observe-only finding.
	secret := CorePersistenceEvent{TsNS: 1, PID: 4242, TGID: 4242, UID: 1000,
		Class: PersistenceClassSecretSSH, Kind: PersistenceKindSecretOpen,
		Action: PersistenceActionAudit, DetailCode: 1000, Dev: 8, Ino: 42, Comm: "ssh"}
	assessment = engine.assessPersistenceEvent(secret, status)
	if !assessment.Tolerated {
		t.Fatalf("expected secret tool must be tolerated: %+v", assessment)
	}
	secret.Comm = "bash"
	assessment = engine.assessPersistenceEvent(secret, status)
	if assessment.Tolerated || assessment.RuleID != PersistenceRuleSecret || assessment.Score != 90 {
		t.Fatalf("unexpected secret tool must be XDR.SECRET_STORE_ACCESS: %+v", assessment)
	}
	// Expected tool but a different opener uid: still a finding (cross-uid).
	cross := secret
	cross.Comm = "ssh"
	cross.UID = 1001
	assessment = engine.assessPersistenceEvent(cross, status)
	if assessment.Tolerated || !strings.Contains(strings.Join(assessment.Limitations, ";"), "cross-uid") {
		t.Fatalf("cross-uid secret access must be a finding with the cross-uid limitation: %+v", assessment)
	}

	// Memory scrape without a resolved target: bounded warning, NONE.
	scrape := CorePersistenceEvent{TsNS: 1, PID: 4242, TGID: 4242, UID: 1000,
		Class: PersistenceClassUnspecified, Kind: PersistenceKindMemoryScrape,
		Action: PersistenceActionAudit, DetailCode: 0, Comm: "bash", Detail: "readv"}
	assessment = engine.assessPersistenceEvent(scrape, status)
	if assessment.RuleID != PersistenceRuleMemory || assessment.Score != 70 ||
		assessment.CorrelationQuality != persistenceQualityNone {
		t.Fatalf("degraded memory scrape assessment is wrong: %+v", assessment)
	}
	// Same-uid ptrace is information-only (debugger/self-service class).
	ptrace := CorePersistenceEvent{TsNS: 1, PID: os.Getpid(), TGID: os.Getpid(), UID: uint32(os.Getuid()),
		Class: PersistenceClassUnspecified, Kind: PersistenceKindPtraceAccess,
		Action: PersistenceActionAudit, DetailCode: uint32(os.Getpid()), Comm: "gdb", Detail: "3"}
	assessment = engine.assessPersistenceEvent(ptrace, status)
	if !assessment.InfoOnly {
		t.Fatalf("same-uid ptrace must stay informational: %+v", assessment)
	}
	// Root non-attach NOAUDIT procfs read (mode=13: READ|NOAUDIT|FSCREDS) from a system binary is informational,
	// while attach/mem (mode=10 / bit 0x02) or /tmp binary must still escalate.
	rootProcRead := CorePersistenceEvent{TsNS: 2, PID: 12345, TGID: 12345, UID: 0,
		Class: PersistenceClassUnspecified, Kind: PersistenceKindPtraceAccess,
		Action: PersistenceActionAudit, DetailCode: uint32(os.Getpid()), Comm: "landscape-sysin", Detail: "13"}
	if os.Getuid() != 0 {
		engine.execPathOverride = func(int) string { return "/usr/bin/python3.12" }
		assessment = engine.assessPersistenceEvent(rootProcRead, status)
		if !assessment.InfoOnly || assessment.EventKind != "xdr.persistence_proc_read_noaudit" {
			t.Fatalf("root non-attach NOAUDIT procfs read must stay informational: %+v", assessment)
		}
		rootAttach := rootProcRead
		rootAttach.Detail = "10" // PTRACE_MODE_ATTACH | PTRACE_MODE_FSCREDS
		assessment = engine.assessPersistenceEvent(rootAttach, status)
		if assessment.InfoOnly || assessment.RuleID != PersistenceRuleMemory || assessment.Score != 110 {
			t.Fatalf("cross-uid PTRACE_MODE_ATTACH must still escalate: %+v", assessment)
		}
		engine.execPathOverride = func(int) string { return "/tmp/spy" }
		assessment = engine.assessPersistenceEvent(rootProcRead, status)
		if assessment.InfoOnly || assessment.RuleID != PersistenceRuleMemory {
			t.Fatalf("untrusted /tmp binary NOAUDIT read must NOT be exempted: %+v", assessment)
		}
		engine.execPathOverride = nil
	}
	// Baseline marker is information, never an incident.
	baseline := CorePersistenceEvent{TsNS: 1, PID: 99, TGID: 99, Kind: PersistenceKindBaseline,
		Action: PersistenceActionAudit, DetailCode: 5, Comm: "gedefense-core"}
	assessment = engine.assessPersistenceEvent(baseline, status)
	if !assessment.InfoOnly || assessment.RuleID != "" {
		t.Fatalf("baseline marker must be informational: %+v", assessment)
	}
}

func TestPersistenceToleratedActors(t *testing.T) {
	engine := newPersistenceTestEngine(nil)
	status := persistenceHealthyStatus()
	managedPaths := map[string]string{
		"dpkg":             "/usr/bin/dpkg",
		"apt":              "/usr/bin/apt",
		"systemd-udevd":    "/usr/lib/systemd/systemd-udevd",
		"udevadm":          "/usr/bin/udevadm",
		"gedefense-core":   "/opt/vgt/gedefense/current/libexec/gedefense-core",
		"systemd-tmpfiles": "/usr/lib/systemd/systemd-tmpfiles",
	}
	for comm, exePath := range managedPaths {
		engine.execPathOverride = func(int) string { return exePath }
		assessment := engine.assessPersistenceEvent(persistenceIntegrityEvent(comm, PersistenceClassLDPreload, 1), status)
		if !assessment.Tolerated {
			t.Fatalf("%q at %q must be TOLERATED for persistence writes: %+v", comm, exePath, assessment)
		}
	}
	// Spoofed comm with unknown or /tmp executable MUST NOT be tolerated.
	for _, fakeExe := range []string{"unknown", "/tmp/evil-apt", "/dev/shm/gedefense-core"} {
		engine.execPathOverride = func(int) string { return fakeExe }
		for _, comm := range []string{"apt", "dpkg", "systemd-udevd", "gedefense-core"} {
			assessment := engine.assessPersistenceEvent(persistenceIntegrityEvent(comm, PersistenceClassLDPreload, 1), status)
			if assessment.Tolerated {
				t.Fatalf("spoofed comm %q with exe %q must NOT be tolerated", comm, fakeExe)
			}
		}
	}
	engine.execPathOverride = nil
	// The cores own PID is tolerated regardless of the task name.
	own := persistenceIntegrityEvent("some-worker", PersistenceClassPAM, 1)
	own.PID = os.Getpid()
	if assessment := engine.assessPersistenceEvent(own, status); !assessment.Tolerated {
		t.Fatalf("own process must be TOLERATED: %+v", assessment)
	}
	for _, comm := range []string{"bash", "curl", "python3", "cat"} {
		assessment := engine.assessPersistenceEvent(persistenceIntegrityEvent(comm, PersistenceClassLDPreload, 1), status)
		if assessment.Tolerated {
			t.Fatalf("%q must not be TOLERATED for a linker write: %+v", comm, assessment)
		}
	}
	// Package-manager tolerance is scoped to persistence paths, not to secret
	// stores: a package manager reading a user secret store stays a finding.
	secret := CorePersistenceEvent{TsNS: 1, PID: 4242, TGID: 4242, UID: 1000,
		Class: PersistenceClassSecretSSH, Kind: PersistenceKindSecretOpen,
		Action: PersistenceActionAudit, DetailCode: 1000, Dev: 8, Ino: 42, Comm: "dpkg"}
	if assessment := engine.assessPersistenceEvent(secret, status); assessment.Tolerated {
		t.Fatalf("package-manager tolerance must not cover secret stores: %+v", assessment)
	}
}

func TestPersistenceDedupeAndRateLimit(t *testing.T) {
	engine := newPersistenceTestEngine(nil)
	event := persistenceIntegrityEvent("bash", PersistenceClassLDPreload, 1)
	now := time.Now().UTC()
	if !engine.claimPersistenceEvent(event, now) {
		t.Fatal("first persistence record must be accepted")
	}
	if engine.claimPersistenceEvent(event, now) {
		t.Fatal("duplicate persistence record must be deduped")
	}
	other := event
	other.Ino++
	if !engine.claimPersistenceEvent(other, now) {
		t.Fatal("a record with a different inode must be accepted")
	}
	if !engine.claimPersistenceIncident(PersistenceRuleLDPreload, 4242, PersistenceClassLDPreload, "high", now) {
		t.Fatal("first incident must be rate-limit accepted")
	}
	if engine.claimPersistenceIncident(PersistenceRuleLDPreload, 4242, PersistenceClassLDPreload, "high", now.Add(time.Minute)) {
		t.Fatal("same rule/pid/class within the window must be rate-limited")
	}
	if !engine.claimPersistenceIncident(PersistenceRuleLDPreload, 4242, PersistenceClassLDConf, "high", now.Add(time.Minute)) {
		t.Fatal("a different class must not be rate-limited")
	}
	// The rate-limited call above must not extend the window: the original
	// five-minute window has expired six minutes after the first incident.
	if !engine.claimPersistenceIncident(PersistenceRuleLDPreload, 4242, PersistenceClassLDPreload, "high", now.Add(6*time.Minute)) {
		t.Fatal("the rate-limit window must expire")
	}
	if engine.claimPersistenceIncident(PersistenceRuleLDPreload, 4242, PersistenceClassLDPreload, "high", now.Add(7*time.Minute)) {
		t.Fatal("the refreshed rate-limit window must apply")
	}
}

func TestPollPersistenceArmsAndBaselinesOnce(t *testing.T) {
	fake := &fakePersistenceCore{
		status: CorePersistenceStatus{Attached: true, AttachedMask: PersistenceHookFileOpen | PersistenceStatusIdentityOffsets,
			HookFileOpen: true, IdentityOffsetsOK: true, SessionsKnown: true, Pkgdb: "dpkg", IdleHint: "unavailable"},
	}
	engine := newPersistenceTestEngine(fake)
	runtime := RuntimeSettings{XDREnabled: true}
	now := time.Now().UTC()
	next := engine.pollPersistence(runtime, now, time.Time{})
	if fake.statusCalls != 1 || fake.setCalls != 1 || !fake.lastSet {
		t.Fatalf("first poll must sample status and arm once: status=%d set=%d last=%v",
			fake.statusCalls, fake.setCalls, fake.lastSet)
	}
	if fake.baselineCalls != 0 {
		t.Fatalf("baseline must wait until the core reports an armed guard, got %d calls", fake.baselineCalls)
	}
	next = engine.pollPersistence(runtime, now.Add(11*time.Second), next)
	if fake.setCalls != 1 {
		t.Fatalf("arm must latch after success, got %d calls", fake.setCalls)
	}
	if fake.baselineCalls != 1 {
		t.Fatalf("one PERSIST_BASELINE after arming was expected, got %d calls", fake.baselineCalls)
	}
	next = engine.pollPersistence(runtime, now.Add(22*time.Second), next)
	if fake.setCalls != 1 || fake.baselineCalls != 1 {
		t.Fatalf("arm/baseline are one-shot, got set=%d baseline=%d", fake.setCalls, fake.baselineCalls)
	}
	if fake.eventCalls == 0 {
		t.Fatal("the drain must run on every poll")
	}
	// The retry gate must not issue any command.
	before := fake.statusCalls
	gate := now.Add(time.Hour)
	if got := engine.pollPersistence(runtime, now.Add(23*time.Second), gate); !got.Equal(gate) {
		t.Fatalf("retry gate changed: %v", got)
	}
	if fake.statusCalls != before {
		t.Fatal("retry gate must not query the core")
	}
}

func TestPollPersistenceCapabilityMissingIsNotDegradation(t *testing.T) {
	fake := &fakePersistenceCore{statusErr: ErrPersistenceUnavailable}
	engine := newPersistenceTestEngine(fake)
	now := time.Now().UTC()
	engine.pollPersistence(RuntimeSettings{XDREnabled: true}, now, time.Time{})
	report := engine.PersistenceGuardReport()
	if report.State != "unavailable" || report.Capability != "missing" {
		t.Fatalf("missing capability must be unavailable/missing, got %+v", report)
	}
	if engine.persistenceArmedRequested {
		t.Fatal("a missing capability must not latch an arm request")
	}
}

func TestPersistenceGuardReport(t *testing.T) {
	engine := newPersistenceTestEngine(nil)
	if report := engine.PersistenceGuardReport(); report.State != "unavailable" || report.Capability != "unknown" {
		t.Fatalf("fresh engine report is wrong: %+v", report)
	}
	status := persistenceHealthyStatus()
	engine.consumePersistenceStatus(status, nil, time.Now().UTC())
	report := engine.PersistenceGuardReport()
	if report.State != "active" || !report.Enabled || !report.Attached {
		t.Fatalf("healthy report is not active: %+v", report)
	}
	if report.CorrelationQuality != persistenceQualityTemporal {
		t.Fatalf("idlehint=unavailable must cap correlation quality at TEMPORAL, got %q", report.CorrelationQuality)
	}
	if report.SampledAt == nil {
		t.Fatal("active report must carry a sample time")
	}
	// Unknown session view: correlation NONE, never a guessed idle state.
	noSessions := status
	noSessions.SessionsKnown = false
	noSessions.AttachedMask &^= PersistenceStatusSessionsKnown
	engine.consumePersistenceStatus(noSessions, nil, time.Now().UTC())
	if report = engine.PersistenceGuardReport(); report.CorrelationQuality != persistenceQualityNone {
		t.Fatalf("unknown session view must yield correlation NONE, got %q", report.CorrelationQuality)
	}
	// A status-query failure is degraded, not healthy.
	engine.consumePersistenceStatus(CorePersistenceStatus{}, os.ErrDeadlineExceeded, time.Now().UTC())
	if report = engine.PersistenceGuardReport(); report.State != "degraded" || report.Reason == "" {
		t.Fatalf("failed status query must be degraded with a reason: %+v", report)
	}
	// Disarmed guard reports disarmed, not active.
	engine.consumePersistenceStatus(CorePersistenceStatus{Attached: true, HookFileOpen: true,
		IdentityOffsetsOK: true, SessionsKnown: true, IdleHint: "unavailable"}, nil, time.Now().UTC())
	if report = engine.PersistenceGuardReport(); report.State != "disarmed" {
		t.Fatalf("disarmed guard must report disarmed: %+v", report)
	}
}

func TestPersistenceFindingsAreObserveOnly(t *testing.T) {
	engine := newPersistenceTestEngine(nil)
	event := persistenceIntegrityEvent("bash", PersistenceClassLDPreload, 1)
	now := time.Now().UTC()
	assessment := engine.assessPersistenceEvent(event, persistenceHealthyStatus())
	engine.recordPersistenceFinding(assessment, event, now)
	incidents := engine.state.Snapshot().Incidents
	if len(incidents) != 1 {
		t.Fatalf("expected one observe-only incident, got %d", len(incidents))
	}
	incident := incidents[0]
	if incident.Decision != "alert" || incident.Action != "none" || incident.Score != 110 {
		t.Fatalf("persistence incident shape is wrong: %+v", incident)
	}
	if len(incident.RuleIDs) != 1 || incident.RuleIDs[0] != PersistenceRuleLDPreload {
		t.Fatalf("persistence rule id missing: %+v", incident.RuleIDs)
	}
	if len(incident.AttackStory) != 1 {
		t.Fatalf("persistence attack story missing: %+v", incident.AttackStory)
	}
	metadata := incident.AttackStory[0].Metadata
	if metadata["observe_only"] != "true" || metadata["kill_eligibility"] != "none" ||
		metadata["decided_by"] != "persistence_guard" {
		t.Fatalf("persistence metadata is wrong: %+v", metadata)
	}
	if !strings.Contains(incident.Outcome, "observe-only") {
		t.Fatalf("persistence outcome is not observe-only: %q", incident.Outcome)
	}
}
