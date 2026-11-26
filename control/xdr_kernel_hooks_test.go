// STATUS: DIAMANT VGT SUPREME
package main

// V6.3.0 AP-4 regression tests: the TOLERATED module/io_uring policy, the
// XDR.LKM_LOAD / XDR.IO_URING_ANOMALY rules (evidence-first, alert-only, never
// kill), the capability/overflow health events, the report states and the poll
// cadence/arming contract with synthetic core answers (no socket, no kernel).

import (
	"errors"
	"testing"
	"time"
)

type fakeKernelHooksCore struct {
	setCalls    []bool
	setErr      error
	status      CoreKernelHookStatus
	statusErr   error
	events      []CoreKernelHookEvent
	dropped     uint64
	eventsErr   error
	epoch       string
	epochErr    error
	statusCalls int
	eventCalls  int
	epochCalls  int
}

func (f *fakeKernelHooksCore) KernelHookSet(enabled bool) error {
	f.setCalls = append(f.setCalls, enabled)
	if f.setErr != nil {
		return f.setErr
	}
	if enabled {
		f.status.Enabled = true
	}
	return nil
}

func (f *fakeKernelHooksCore) KernelHookStatus() (CoreKernelHookStatus, error) {
	f.statusCalls++
	return f.status, f.statusErr
}

func (f *fakeKernelHooksCore) KernelHookEvents() ([]CoreKernelHookEvent, uint64, error) {
	f.eventCalls++
	if f.eventsErr != nil {
		return nil, 0, f.eventsErr
	}
	return f.events, f.dropped, nil
}

func (f *fakeKernelHooksCore) KernelHookEpoch() (string, error) {
	f.epochCalls++
	return f.epoch, f.epochErr
}

func newKernelHooksTestEngine(fake kernelHooksCore) *XDREngine {
	return &XDREngine{
		state: NewState("test", defaultConfig()), correlator: NewIncidentCorrelator(0),
		dedupe: map[string]time.Time{}, degradeCauses: map[string]string{}, forensicFailures: map[string]int{},
		kernelHooksCore: fake,
	}
}

func syntheticKernelHookEvent(kind uint8, pid int, ts uint64, comm, detail string) CoreKernelHookEvent {
	return CoreKernelHookEvent{
		TsNS: ts, PID: pid, TGID: pid, UID: 1000,
		Kind: kind, Action: KernelHookActionAudit,
		Detail: detail, Comm: comm,
	}
}

func kernelHookIncidentsWithRule(engine *XDREngine, ruleID string) []XDRIncident {
	var out []XDRIncident
	for _, incident := range engine.state.Snapshot().Incidents {
		if containsString(incident.RuleIDs, ruleID) {
			out = append(out, incident)
		}
	}
	return out
}

func kernelHookStateEventKinds(engine *XDREngine) map[string]int {
	out := map[string]int{}
	for _, event := range engine.state.Snapshot().Events {
		out[event.Kind]++
	}
	return out
}

func TestKernelHookLKMFromUntrustedLineageIsObserveOnly(t *testing.T) {
	engine := newKernelHooksTestEngine(&fakeKernelHooksCore{})
	now := time.Now().UTC()
	event := syntheticKernelHookEvent(KernelHookKindModuleLoad, 999999, 1700000000000000000, "weirdloader", "evil_lkm")
	engine.consumeKernelHookEvents([]CoreKernelHookEvent{event}, 0, now)
	incidents := kernelHookIncidentsWithRule(engine, "XDR.LKM_LOAD")
	if len(incidents) != 1 {
		t.Fatalf("expected one XDR.LKM_LOAD incident, got %d", len(incidents))
	}
	incident := incidents[0]
	if incident.Score != 120 || incident.Decision != "alert" || incident.Action != "none" ||
		incident.Severity != "high" {
		t.Fatalf("LKM_LOAD incident is not observe-only: %+v", incident)
	}
	if len(incident.AttackStory) != 1 || incident.AttackStory[0].Sensor != "kernel-kernel-hooks" ||
		incident.AttackStory[0].Metadata["observe_only"] != "true" {
		t.Fatalf("LKM_LOAD attack-story node missing: %+v", incident.AttackStory)
	}
	if incident.Outcome == "" || incident.EvidenceRoot == "" {
		t.Fatalf("LKM_LOAD incident lacks outcome/evidence root: %+v", incident)
	}
	if !containsString(incident.Categories, "kernel") {
		t.Fatalf("LKM_LOAD incident lacks the kernel category: %+v", incident.Categories)
	}
	// Dedupe: the same (ts, kind, pid) record must not repeat.
	engine.consumeKernelHookEvents([]CoreKernelHookEvent{event}, 0, now)
	if got := len(kernelHookIncidentsWithRule(engine, "XDR.LKM_LOAD")); got != 1 {
		t.Fatalf("duplicate kernel-hook record created %d incidents", got)
	}
}

func TestKernelHookLKMTaintIsReportedAsHighSeverityEvidence(t *testing.T) {
	engine := newKernelHooksTestEngine(&fakeKernelHooksCore{})
	now := time.Now().UTC()
	event := syntheticKernelHookEvent(KernelHookKindLkmTaint, 999998, 1700000000000000001, "weirdloader", "evil_lkm")
	event.DetailCode = 0x1000 // out-of-tree module taint bit
	engine.consumeKernelHookEvents([]CoreKernelHookEvent{event}, 0, now)
	incidents := kernelHookIncidentsWithRule(engine, "XDR.LKM_LOAD")
	if len(incidents) != 1 {
		t.Fatalf("expected one tainted-load incident, got %d", len(incidents))
	}
	if incidents[0].AttackStory[0].Metadata["taint"] != "0x1000" {
		t.Fatalf("taint mask missing from the incident metadata: %+v", incidents[0].AttackStory[0].Metadata)
	}
}

func TestKernelHookModulePathAndToolPolicy(t *testing.T) {
	cases := []struct {
		name      string
		comm      string
		path      string
		parent    string
		core      bool
		tolerated bool
	}{
		{"boot path", "modprobe", "/usr/sbin/modprobe", "systemd", false, true},
		{"package path", "modprobe", "/usr/sbin/modprobe", "dpkg", false, true},
		{"module tooling managed path", "insmod", "/usr/sbin/insmod", "bash", false, true},
		{"module tooling temp path", "insmod", "/tmp/insmod", "bash", false, false},
		{"module tooling unresolved path", "insmod", "unknown", "bash", false, false},
		{"modprobe managed path is tolerated", "modprobe", "/usr/sbin/modprobe", "", false, true},
		{"modprobe unresolved path is not tolerated", "modprobe", "unknown", "", false, false},
		{"modprobe from a temp path is not tolerated", "modprobe", "/tmp/modprobe", "bash", false, false},
		{"systemd comm is tolerated", "systemd", "/usr/lib/systemd/systemd", "", false, true},
		{"own core process", "gedefense-core", "/opt/vgt/gedefense/current/libexec/gedefense-core", "", false, true},
		{"spoofed core comm from temp is not tolerated", "gedefense-core", "/tmp/evil", "", false, false},
		{"own core process comm", "weird", "unknown", "", true, true},
		{"shell loader", "evil", "/tmp/evil.ko", "bash", false, false},
		{"developer loader", "cargo", "/usr/bin/cargo", "bash", false, false},
	}
	for _, testCase := range cases {
		tolerated, reason := kernelHookModuleTolerated(
			testCase.comm, testCase.path, testCase.parent, testCase.core)
		if tolerated != testCase.tolerated {
			t.Fatalf("%s: tolerated=%t want %t (reason %q)",
				testCase.name, tolerated, testCase.tolerated, reason)
		}
	}
	// Tolerated module loads must not create an incident; untrusted ones must.
	engine := newKernelHooksTestEngine(&fakeKernelHooksCore{})
	engine.execPathOverride = func(pid int) string {
		if pid == 999990 {
			return "/usr/sbin/modprobe"
		}
		return "/tmp/evil"
	}
	now := time.Now().UTC()
	engine.consumeKernelHookEvents([]CoreKernelHookEvent{
		syntheticKernelHookEvent(KernelHookKindModuleLoad, 999990, 1700000000000000100, "modprobe", "ok_module"),
		syntheticKernelHookEvent(KernelHookKindModuleLoad, 999991, 1700000000000000101, "evil", "evil_module"),
	}, 0, now)
	if got := len(kernelHookIncidentsWithRule(engine, "XDR.LKM_LOAD")); got != 1 {
		t.Fatalf("tolerated module load produced %d incidents, want exactly 1 (the untrusted one)", got)
	}
	if kinds := kernelHookStateEventKinds(engine); kinds["xdr.kernel_hook_tolerated"] == 0 {
		t.Fatalf("tolerated module load did not produce an info event: %+v", kinds)
	}
}

func TestKernelHookIoUringUnusualPolicy(t *testing.T) {
	cases := []struct {
		comm    string
		path    string
		parent  string
		deleted bool
		unusual bool
	}{
		{"fio", "/usr/bin/fio", "systemd", false, false},
		{"bespoke-worker", "/opt/app/worker", "systemd", false, false},
		{"bespoke-worker", "unknown", "", false, false},
		{"bespoke-worker", "/tmp/worker", "systemd", false, true},
		{"bespoke-worker", "/dev/shm/worker", "systemd", false, true},
		{"bespoke-worker", "/usr/bin/worker", "systemd", true, true},
		{"bespoke-worker", "/usr/bin/worker", "bash", false, true},
		{"bash", "/usr/bin/bash", "systemd", false, true},
	}
	for _, testCase := range cases {
		unusual, trigger := kernelHookIoUringUnusual(
			testCase.comm, testCase.path, testCase.parent, testCase.deleted)
		if unusual != testCase.unusual {
			t.Fatalf("io_uring policy for %q path=%q parent=%q deleted=%t: unusual=%t want %t (%s)",
				testCase.comm, testCase.path, testCase.parent, testCase.deleted,
				unusual, testCase.unusual, trigger)
		}
		if unusual && trigger == "" {
			t.Fatal("an unusual io_uring observation must carry a trigger")
		}
	}
	if tolerated, _ := kernelHookIoUringTolerated("mariadbd", "/usr/sbin/mariadbd", false); !tolerated {
		t.Fatal("a known legitimate io_uring consumer must be tolerated")
	}
	if tolerated, _ := kernelHookIoUringTolerated("mariadbd", "unknown", false); tolerated {
		t.Fatal("spoofed io_uring consumer with unresolved path must not be tolerated")
	}
	if tolerated, _ := kernelHookIoUringTolerated("gedefense-core", "/opt/vgt/gedefense/current/libexec/gedefense-core", false); !tolerated {
		t.Fatal("the privileged core's own io_uring usage must be tolerated")
	}
	if tolerated, _ := kernelHookIoUringTolerated("gedefense-core", "/tmp/evil", false); tolerated {
		t.Fatal("spoofed core comm under /tmp must not be tolerated")
	}
	if tolerated, _ := kernelHookIoUringTolerated("weird", "/usr/bin/weird", false); tolerated {
		t.Fatal("an unknown io_uring user must not be tolerated")
	}
}

func TestKernelHookIoUringFindingIsObserveOnly(t *testing.T) {
	engine := newKernelHooksTestEngine(&fakeKernelHooksCore{})
	now := time.Now().UTC()
	event := syntheticKernelHookEvent(KernelHookKindIoUringCreate, 999997, 1700000000000000200, "worker", "")
	event.DetailCode = 9
	event.Detail = "\x20\x80\x00\x00"
	engine.recordKernelHookIoUringFinding(event, "/tmp/worker", "bash", false,
		"executable lives in a temporary writable path", now)
	incidents := kernelHookIncidentsWithRule(engine, "XDR.IO_URING_ANOMALY")
	if len(incidents) != 1 {
		t.Fatalf("expected one XDR.IO_URING_ANOMALY incident, got %d", len(incidents))
	}
	incident := incidents[0]
	if incident.Score != 90 || incident.Decision != "alert" || incident.Action != "none" ||
		incident.Severity != "warning" {
		t.Fatalf("IO_URING_ANOMALY incident is not observe-only: %+v", incident)
	}
	if len(incident.AttackStory) != 1 || incident.AttackStory[0].Sensor != "kernel-kernel-hooks" ||
		incident.AttackStory[0].Metadata["observe_only"] != "true" ||
		incident.AttackStory[0].Metadata["detail"] != "0x20800000" {
		t.Fatalf("IO_URING_ANOMALY attack-story node missing: %+v", incident.AttackStory)
	}
	if incident.Outcome == "" || incident.EvidenceRoot == "" {
		t.Fatalf("IO_URING_ANOMALY incident lacks outcome/evidence root: %+v", incident)
	}
}

func TestKernelHookSubmitSamplingDoesNotSpamTheOperator(t *testing.T) {
	engine := newKernelHooksTestEngine(&fakeKernelHooksCore{})
	now := time.Now().UTC()
	// A tolerated database worker submits once per sampled window: no incident and
	// no per-second info event.
	for index := 0; index < 3; index++ {
		engine.consumeKernelHookEvents([]CoreKernelHookEvent{
			syntheticKernelHookEvent(
				KernelHookKindIoUringSubmit, 999980,
				uint64(1700000000000000300+index), "mariadbd", ""),
		}, 0, now)
	}
	// An ordinary (non-tolerated comm) io_uring submitter with no unusual lineage
	// is still not evidence, and its sampled records produce no info flood either.
	for index := 0; index < 3; index++ {
		engine.consumeKernelHookEvents([]CoreKernelHookEvent{
			syntheticKernelHookEvent(
				KernelHookKindIoUringSubmit, 999981,
				uint64(1700000000000000400+index), "bespoke-worker", ""),
		}, 0, now)
	}
	if got := len(kernelHookIncidentsWithRule(engine, "XDR.IO_URING_ANOMALY")); got != 0 {
		t.Fatalf("sampled submissions created %d incidents", got)
	}
	if kinds := kernelHookStateEventKinds(engine); kinds["xdr.kernel_hook_tolerated"] != 0 {
		t.Fatalf("sampled submissions produced %d tolerated info events",
			kinds["xdr.kernel_hook_tolerated"])
	}
	// The submission-anomaly window admits one report per process per minute.
	if !engine.claimKernelHookSubmitWindow(4321, now) {
		t.Fatal("the first submission-anomaly report was rejected")
	}
	if engine.claimKernelHookSubmitWindow(4321, now.Add(time.Second)) {
		t.Fatal("a second submission-anomaly report was admitted inside the window")
	}
	if !engine.claimKernelHookSubmitWindow(4321, now.Add(kernelHooksSubmitIncidentGap+time.Second)) {
		t.Fatal("the submission-anomaly window did not expire after its gap")
	}
	// A different process has its own window.
	if !engine.claimKernelHookSubmitWindow(4322, now.Add(time.Second)) {
		t.Fatal("the submission-anomaly window is shared between processes")
	}
}

func TestKernelHookOwnControlPidIsTolerated(t *testing.T) {
	engine := newKernelHooksTestEngine(&fakeKernelHooksCore{})
	engine.selfPID = 4242
	now := time.Now().UTC()
	// An untrusted-looking module load by our own control process is tolerated and
	// recorded as information only.
	engine.consumeKernelHookEvents([]CoreKernelHookEvent{
		syntheticKernelHookEvent(KernelHookKindModuleLoad, 4242, 1700000000000000500, "weirdloader", "own_lkm"),
	}, 0, now)
	if got := len(kernelHookIncidentsWithRule(engine, "XDR.LKM_LOAD")); got != 0 {
		t.Fatalf("the control process's own module load created %d incidents", got)
	}
	if kinds := kernelHookStateEventKinds(engine); kinds["xdr.kernel_hook_tolerated"] != 1 {
		t.Fatalf("own-pid tolerance did not produce exactly one info event: %+v", kinds)
	}
}

func TestKernelHookCapabilityMissingIsAFactNotDegradation(t *testing.T) {
	fake := &fakeKernelHooksCore{}
	engine := newKernelHooksTestEngine(fake)
	now := time.Now().UTC()
	healthy := CoreKernelHookStatus{Enabled: true, Attached: true, IoUring: true, ModuleTrace: true, Kprobes: 3}
	engine.consumeKernelHooksStatus(healthy, nil, now)
	if report := engine.KernelHooksReport(); report.State != "active" || report.Capability != "available" {
		t.Fatalf("healthy status reported as %+v", report)
	}
	fake.statusErr = ErrKernelHooksUnavailable
	fake.eventsErr = ErrKernelHooksUnavailable
	next := engine.pollKernelHooks(expectedRuntimeXDREnabled(), now.Add(6*time.Second), time.Time{})
	if next.IsZero() {
		t.Fatal("poll did not schedule a retry")
	}
	report := engine.KernelHooksReport()
	if report.State != "unavailable" || report.Capability != "missing" {
		t.Fatalf("missing capability reported as %+v", report)
	}
	if report.Epoch != "" {
		t.Fatalf("missing capability kept a stale epoch: %q", report.Epoch)
	}
	if kinds := kernelHookStateEventKinds(engine); kinds["xdr.kernel_hooks_capability_missing"] != 1 {
		t.Fatalf("capability loss was not recorded as a fact: %+v", kinds)
	}
	if len(kernelHookIncidentsWithRule(engine, "XDR.LKM_LOAD")) != 0 ||
		len(kernelHookIncidentsWithRule(engine, "XDR.IO_URING_ANOMALY")) != 0 {
		t.Fatal("a missing capability must not fabricate incidents")
	}
}

// expectedRuntimeXDREnabled is the minimal RuntimeSettings the poll path needs.
func expectedRuntimeXDREnabled() RuntimeSettings {
	return RuntimeSettings{XDREnabled: true}
}

func TestKernelHookPollCadenceArmsOnceAndDrains(t *testing.T) {
	fake := &fakeKernelHooksCore{
		status: CoreKernelHookStatus{Enabled: false, Attached: true, IoUring: true, ModuleTrace: true},
		epoch:  "0123456789abcdef",
	}
	engine := newKernelHooksTestEngine(fake)
	start := time.Now().UTC()
	runtime := expectedRuntimeXDREnabled()

	next := engine.pollKernelHooks(runtime, start, time.Time{})
	if fake.statusCalls != 1 || fake.eventCalls != 1 || fake.epochCalls != 1 {
		t.Fatalf("first poll calls: status=%d events=%d epoch=%d",
			fake.statusCalls, fake.eventCalls, fake.epochCalls)
	}
	if len(fake.setCalls) != 1 || !fake.setCalls[0] {
		t.Fatalf("the observe-only family was not armed exactly once: %+v", fake.setCalls)
	}
	if !next.Equal(start.Add(kernelHooksDrainInterval)) {
		t.Fatalf("first poll scheduled %v, want drain cadence", next.Sub(start))
	}
	// Inside the drain interval nothing runs.
	next = engine.pollKernelHooks(runtime, start.Add(100*time.Millisecond), next)
	if fake.eventCalls != 1 || fake.statusCalls != 1 {
		t.Fatalf("early poll ran: status=%d events=%d", fake.statusCalls, fake.eventCalls)
	}
	// One second later the drain runs, the 5 s status cadence does not.
	next = engine.pollKernelHooks(runtime, start.Add(time.Second), next)
	if fake.eventCalls != 2 || fake.statusCalls != 1 {
		t.Fatalf("drain cadence calls: status=%d events=%d", fake.statusCalls, fake.eventCalls)
	}
	if len(fake.setCalls) != 1 {
		t.Fatalf("the family was armed more than once: %+v", fake.setCalls)
	}
	// The status cadence fires after 5 s and the epoch is fetched only once.
	next = engine.pollKernelHooks(runtime, start.Add(5*time.Second), next)
	if fake.statusCalls != 2 || fake.epochCalls != 1 {
		t.Fatalf("status cadence calls: status=%d epoch=%d", fake.statusCalls, fake.epochCalls)
	}
	if len(fake.setCalls) != 1 {
		t.Fatalf("a later status re-armed the family: %+v", fake.setCalls)
	}
	report := engine.KernelHooksReport()
	if report.State != "active" || report.Epoch != "0123456789abcdef" || report.SampledAt == nil {
		t.Fatalf("active report is wrong: %+v", report)
	}
}

func TestKernelHookArmFailureIsReported(t *testing.T) {
	fake := &fakeKernelHooksCore{
		status: CoreKernelHookStatus{Enabled: false, Attached: true, IoUring: true, ModuleTrace: true},
		setErr: errors.New("broker rejected the arm"),
	}
	engine := newKernelHooksTestEngine(fake)
	engine.pollKernelHooks(expectedRuntimeXDREnabled(), time.Now().UTC(), time.Time{})
	report := engine.KernelHooksReport()
	if report.State != "degraded" || report.Capability != "available" || report.Reason == "" {
		t.Fatalf("a failed arm was not reported as degraded: %+v", report)
	}
}

func TestKernelHookOverflowIsRateLimitedHealthTelemetry(t *testing.T) {
	engine := newKernelHooksTestEngine(&fakeKernelHooksCore{})
	now := time.Now().UTC()
	engine.consumeKernelHookEvents(nil, 3, now)
	kinds := kernelHookStateEventKinds(engine)
	if kinds["xdr.kernel_hooks_overflow"] != 1 {
		t.Fatalf("ring overflow was not reported: %+v", kinds)
	}
	engine.consumeKernelHookEvents(nil, 3, now.Add(time.Second))
	if kinds := kernelHookStateEventKinds(engine); kinds["xdr.kernel_hooks_overflow"] != 1 {
		t.Fatalf("ring overflow repeated inside the rate-limit window: %+v", kinds)
	}
	engine.consumeKernelHookEvents(nil, 2, now.Add(kernelHooksOverflowMinGap+time.Second))
	if kinds := kernelHookStateEventKinds(engine); kinds["xdr.kernel_hooks_overflow"] != 2 {
		t.Fatalf("ring overflow was not re-reported after the window: %+v", kinds)
	}
}

func TestKernelHooksReportStates(t *testing.T) {
	engine := newKernelHooksTestEngine(&fakeKernelHooksCore{})
	now := time.Now().UTC()
	cases := []struct {
		name    string
		status  CoreKernelHookStatus
		err     error
		state   string
		capable string
	}{
		{"unavailable", CoreKernelHookStatus{}, ErrKernelHooksUnavailable, "unavailable", "missing"},
		{"disarmed", CoreKernelHookStatus{Enabled: false, Attached: true, IoUring: true, ModuleTrace: true}, nil, "disarmed", "available"},
		{"not attached", CoreKernelHookStatus{Enabled: true, Attached: false}, nil, "degraded", "available"},
		{"io_uring missing", CoreKernelHookStatus{Enabled: true, Attached: true, ModuleTrace: true, Kprobes: 3}, nil, "degraded", "available"},
		{"module missing", CoreKernelHookStatus{Enabled: true, Attached: true, IoUring: true}, nil, "degraded", "available"},
		{"active", CoreKernelHookStatus{Enabled: true, Attached: true, IoUring: true, ModuleTrace: true, Kprobes: 3}, nil, "active", "available"},
		{"status error", CoreKernelHookStatus{Enabled: true, Attached: true, IoUring: true, ModuleTrace: true}, errors.New("query failed"), "degraded", "available"},
	}
	for _, testCase := range cases {
		engine.consumeKernelHooksStatus(testCase.status, testCase.err, now)
		report := engine.KernelHooksReport()
		if report.State != testCase.state || report.Capability != testCase.capable {
			t.Fatalf("%s: report state=%q capability=%q want %q/%q (reason %q)",
				testCase.name, report.State, report.Capability, testCase.state, testCase.capable, report.Reason)
		}
		if report.State != "active" && report.State != "unavailable" && report.Reason == "" {
			t.Fatalf("%s: a %q report must state a reason", testCase.name, report.State)
		}
	}
	// A nil engine and a nil core must never claim visibility.
	var nilEngine *XDREngine
	if report := nilEngine.KernelHooksReport(); report.State != "unavailable" {
		t.Fatalf("nil engine reported %+v", report)
	}
	// The report reason is bounded.
	engine.consumeKernelHooksStatus(CoreKernelHookStatus{}, errors.New(string(make([]byte, 4096))), now)
	if report := engine.KernelHooksReport(); len(report.Reason) > kernelHooksReportReasonBytes+64 {
		t.Fatalf("report reason is not bounded: %d bytes", len(report.Reason))
	}
}
