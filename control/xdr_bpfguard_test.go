// STATUS: DIAMANT VGT SUPREME
package main

// V6.3.0 AP-2 regression tests: the TOLERATED loader policy, the
// XDR.BPF_ANOMALY / XDR.BPF_ROOTKIT_HELPER rules (evidence-first, alert-only,
// never kill), the attach-time guard report states and the poll cadence/arming
// contract with synthetic core answers (no socket, no kernel).

import (
	"errors"
	"os"
	"testing"
	"time"
)

type fakeBpfGuardCore struct {
	setCalls    []bool
	setErr      error
	status      CoreBpfGuardStatus
	statusErr   error
	events      []CoreBpfGuardEvent
	dropped     uint64
	eventsErr   error
	epoch       string
	epochErr    error
	statusCalls int
	eventCalls  int
	epochCalls  int
}

func (f *fakeBpfGuardCore) BpfGuardSet(enabled bool) error {
	f.setCalls = append(f.setCalls, enabled)
	if f.setErr != nil {
		return f.setErr
	}
	if enabled {
		f.status.Enabled = true
	}
	return nil
}

func (f *fakeBpfGuardCore) BpfGuardStatus() (CoreBpfGuardStatus, error) {
	f.statusCalls++
	return f.status, f.statusErr
}

func (f *fakeBpfGuardCore) BpfGuardEvents() ([]CoreBpfGuardEvent, uint64, error) {
	f.eventCalls++
	if f.eventsErr != nil {
		return nil, 0, f.eventsErr
	}
	return f.events, f.dropped, nil
}

func (f *fakeBpfGuardCore) BpfGuardEpoch() (string, error) {
	f.epochCalls++
	return f.epoch, f.epochErr
}

func newBpfGuardTestEngine(fake bpfGuardCore) *XDREngine {
	return &XDREngine{
		state: NewState("test", defaultConfig()), correlator: NewIncidentCorrelator(0),
		dedupe: map[string]time.Time{}, degradeCauses: map[string]string{}, forensicFailures: map[string]int{},
		bpfGuardCore: fake,
	}
}

func syntheticBpfGuardEvent(action uint8, pid int, mask uint32, ts uint64, comm string) CoreBpfGuardEvent {
	event := CoreBpfGuardEvent{
		TsNS: ts, PID: pid, TGID: pid, UID: 1000, Action: action,
		Command: BpfGuardCommandProgLoad, ProgType: BpfGuardProgTypeKprobe,
		HelperMask: mask, Comm: comm,
	}
	if action == BpfGuardActionHelperRisk {
		index := 0
		for _, identifier := range []uint32{BpfGuardHelperIDProbeWriteUser, BpfGuardHelperIDOverrideReturn, BpfGuardHelperIDSendSignal} {
			if mask&BpfGuardHelperIDToBit(identifier) != 0 && index < BpfGuardHelperBitsPerEvent {
				event.HelperIDs[index] = identifier
				index++
			}
		}
	}
	return event
}

func bpfGuardIncidentsWithRule(engine *XDREngine, ruleID string) []XDRIncident {
	var out []XDRIncident
	for _, incident := range engine.state.Snapshot().Incidents {
		if containsString(incident.RuleIDs, ruleID) {
			out = append(out, incident)
		}
	}
	return out
}

func TestBpfGuardAnomalyFromUntoleratedLoaderIsObserveOnly(t *testing.T) {
	engine := newBpfGuardTestEngine(&fakeBpfGuardCore{})
	now := time.Now().UTC()
	event := syntheticBpfGuardEvent(BpfGuardActionObserved, 999999, 0, 1700000000000000000, "unknown-loader")
	engine.consumeBpfGuardEvents([]CoreBpfGuardEvent{event}, 0, now)
	incidents := bpfGuardIncidentsWithRule(engine, "XDR.BPF_ANOMALY")
	if len(incidents) != 1 {
		t.Fatalf("expected one XDR.BPF_ANOMALY incident, got %d", len(incidents))
	}
	incident := incidents[0]
	if incident.Score != 45 || incident.Decision != "alert" || incident.Action != "none" || incident.Severity != "warning" {
		t.Fatalf("BPF anomaly incident is not observe-only: %+v", incident)
	}
	if len(incident.AttackStory) != 1 || incident.AttackStory[0].Sensor != "kernel-bpf-guard" ||
		incident.AttackStory[0].Metadata["observe_only"] != "true" {
		t.Fatalf("BPF anomaly attack-story node missing: %+v", incident.AttackStory)
	}
	if incident.Outcome == "" || incident.EvidenceRoot == "" {
		t.Fatalf("BPF anomaly incident lacks outcome/evidence root: %+v", incident)
	}
	// Dedupe: the same (ts,pid,action,helper_mask) record must not repeat.
	engine.consumeBpfGuardEvents([]CoreBpfGuardEvent{event}, 0, now)
	if got := len(bpfGuardIncidentsWithRule(engine, "XDR.BPF_ANOMALY")); got != 1 {
		t.Fatalf("duplicate BPF record created %d incidents", got)
	}
}

func TestBpfGuardHelperAggregationEscalatesToRootkitWithinOneHour(t *testing.T) {
	engine := newBpfGuardTestEngine(&fakeBpfGuardCore{})
	now := time.Now().UTC()
	pid := 424242
	// First single high-risk helper: below the two-bit threshold -> anomaly.
	engine.consumeBpfGuardEvents([]CoreBpfGuardEvent{
		syntheticBpfGuardEvent(BpfGuardActionHelperRisk, pid, BpfGuardHelperBitProbeWriteUser, 1700000000000000000, "rootkit"),
	}, 0, now)
	if got := len(bpfGuardIncidentsWithRule(engine, "XDR.BPF_ROOTKIT_HELPER")); got != 0 {
		t.Fatalf("a single helper bit produced %d rootkit incidents", got)
	}
	if got := len(bpfGuardIncidentsWithRule(engine, "XDR.BPF_ANOMALY")); got != 1 {
		t.Fatalf("single-helper record did not produce the anomaly fallback: %d", got)
	}
	// Second distinct high-risk helper within the hour -> two bits -> rootkit.
	engine.consumeBpfGuardEvents([]CoreBpfGuardEvent{
		syntheticBpfGuardEvent(BpfGuardActionHelperRisk, pid, BpfGuardHelperBitOverrideReturn, 1700000000000000001, "rootkit"),
	}, 0, now.Add(2*time.Minute))
	rootkits := bpfGuardIncidentsWithRule(engine, "XDR.BPF_ROOTKIT_HELPER")
	if len(rootkits) != 1 {
		t.Fatalf("two helper bits did not escalate to XDR.BPF_ROOTKIT_HELPER: %d", len(rootkits))
	}
	rootkit := rootkits[0]
	if rootkit.Score != 120 || rootkit.Decision != "alert" || rootkit.Action != "none" || rootkit.Severity != "high" {
		t.Fatalf("rootkit incident is not alert-only: %+v", rootkit)
	}
	for _, incident := range engine.state.Snapshot().Incidents {
		if incident.Decision == "kill" || incident.Decision == "contain" || incident.Action != "none" {
			t.Fatalf("BPF guard produced an active response: %+v", incident)
		}
	}
}

func TestBpfGuardToleratedLoadersNeverCreateIncidents(t *testing.T) {
	engine := newBpfGuardTestEngine(&fakeBpfGuardCore{})
	engine.execPathOverride = func(pid int) string {
		if idx := pid - 900000; idx >= 0 && idx < 4 {
			names := []string{"bpftrace", "perf", "falco", "cargo"}
			return "/usr/bin/" + names[idx]
		}
		return "unknown"
	}
	now := time.Now().UTC()
	tolerated := bpfGuardToleratedLoaderComms()
	if len(tolerated) == 0 {
		t.Fatal("tolerated loader context list is empty")
	}
	for _, comm := range []string{
		"bpftrace", "perf", "cilium-agent", "cilium", "falco", "tetragon", "docker",
		"containerd", "runc", "cargo", "go", "gcc", "clang", "node", "npm", "systemd",
		"gedefense-core", "gedefense-control", "bpftool",
	} {
		if _, ok := bpfGuardToleratedComms[comm]; !ok {
			t.Fatalf("required tolerated loader %q is missing from the policy", comm)
		}
	}
	for index, comm := range []string{"bpftrace", "perf", "falco", "cargo"} {
		event := syntheticBpfGuardEvent(BpfGuardActionHelperRisk, 900000+index, 3, 1700000000000000000+uint64(index), comm)
		engine.consumeBpfGuardEvents([]CoreBpfGuardEvent{event}, 0, now)
	}
	if incidents := engine.state.Snapshot().Incidents; len(incidents) != 0 {
		t.Fatalf("tolerated loaders produced %d incidents: %+v", len(incidents), incidents)
	}
	// Spoofing comm via prctl() from /tmp or an unknown path MUST NOT be tolerated.
	for _, comm := range []string{"go", "bpftrace", "gedefense-core"} {
		if tol, _ := engine.bpfGuardEventTolerated(syntheticBpfGuardEvent(BpfGuardActionHelperRisk, 999500, 3, 1700000000000000100, comm)); tol {
			t.Fatalf("spoofed comm %q with unresolved path was tolerated", comm)
		}
	}
	engine.execPathOverride = func(int) string { return "/tmp/evil-loader" }
	for _, comm := range []string{"go", "bpftrace", "gedefense-core"} {
		if tol, _ := engine.bpfGuardEventTolerated(syntheticBpfGuardEvent(BpfGuardActionHelperRisk, 999501, 3, 1700000000000000101, comm)); tol {
			t.Fatalf("spoofed comm %q from /tmp/evil-loader was tolerated", comm)
		}
	}
	found := false
	for _, event := range engine.state.Snapshot().Events {
		if event.Kind == "xdr.bpf_guard_tolerated" {
			found = true
		}
	}
	if !found {
		t.Fatal("tolerated loader activity did not reach the info event stream")
	}
}

func TestBpfGuardOwnProcessAndHelperPredicates(t *testing.T) {
	engine := newBpfGuardTestEngine(&fakeBpfGuardCore{})
	engine.selfPID = os.Getpid()
	tolerated, reason := engine.bpfGuardEventTolerated(CoreBpfGuardEvent{PID: os.Getpid(), Comm: "gedefense-control"})
	if !tolerated || reason != "own control process" {
		t.Fatalf("own process was not tolerated: %v %q", tolerated, reason)
	}
	coreClient := &CoreClient{}
	coreClient.peerPID.Store(42424)
	engine.core = coreClient
	tolerated, reason = engine.bpfGuardEventTolerated(CoreBpfGuardEvent{PID: 42424, Comm: "gedefense-core"})
	if !tolerated || reason != "own core daemon" {
		t.Fatalf("verified core daemon PID was not tolerated: %v %q", tolerated, reason)
	}
	if !bpfGuardPathUnderAny("/tmp/loader", bpfGuardTempPathPrefixes) ||
		!bpfGuardPathUnderAny("/dev/shm/x", bpfGuardTempPathPrefixes) ||
		!bpfGuardPathUnderAny("/var/tmp/y", bpfGuardTempPathPrefixes) {
		t.Fatal("temporary-path predicate misses a drop root")
	}
	if bpfGuardPathUnderAny("/usr/bin/bpftool", bpfGuardTempPathPrefixes) {
		t.Fatal("temporary-path predicate matched an installation path")
	}
	for _, comm := range []string{"bash", "sh", "zsh"} {
		if !bpfGuardCommIn(comm, bpfGuardShellComms) {
			t.Fatalf("%q is missing from the shell-lineage set", comm)
		}
	}
	if bpfGuardCommIn("sshd", bpfGuardShellComms) {
		t.Fatal("sshd matched the shell-lineage set")
	}
}

func TestBpfGuardReportNeverClaimsPartialAttachIsActive(t *testing.T) {
	engine := newBpfGuardTestEngine(&fakeBpfGuardCore{})
	if report := engine.BpfGuardReport(); report.State != "unavailable" || report.Capability != "missing" {
		t.Fatalf("missing capability reported as %+v", report)
	}
	now := time.Now().UTC()
	engine.consumeBpfGuardStatus(CoreBpfGuardStatus{
		Enabled: true, Attached: true, LSMAttached: true, TPAttached: true,
		Events: 4, Drops: 1, Loads: 2, HelperRisk: 3,
	}, nil, now)
	report := engine.BpfGuardReport()
	if report.State != "active" || !report.Enabled || !report.LSM || !report.TP || report.SampledAt == nil {
		t.Fatalf("fully attached guard reported as %+v", report)
	}
	if report.Events != 4 || report.Drops != 1 || report.Loads != 2 || report.HelperRisk != 3 {
		t.Fatalf("guard counters projected wrong: %+v", report)
	}
	engine.consumeBpfGuardStatus(CoreBpfGuardStatus{Enabled: true, Attached: true, KprobeAttached: true}, nil, now)
	if got := engine.BpfGuardReport(); got.State != "degraded" || got.Reason == "" {
		t.Fatalf("helper-kprobe-only guard reported as %+v", got)
	}
	engine.consumeBpfGuardStatus(CoreBpfGuardStatus{Enabled: false, Attached: true, LSMAttached: true, TPAttached: true}, nil, now)
	if got := engine.BpfGuardReport(); got.State != "disarmed" {
		t.Fatalf("disarmed guard reported as %+v", got)
	}
	engine.consumeBpfGuardStatus(CoreBpfGuardStatus{}, errors.New("transport reset"), now)
	if got := engine.BpfGuardReport(); got.State != "degraded" || got.Capability != "available" {
		t.Fatalf("failed status query reported as %+v", got)
	}
	engine.consumeBpfGuardStatus(CoreBpfGuardStatus{}, ErrBpfGuardUnavailable, now)
	if got := engine.BpfGuardReport(); got.State != "unavailable" {
		t.Fatalf("capability loss reported as %+v", got)
	}
}

func TestPollBpfGuardArmsOnceAndKeepsCadence(t *testing.T) {
	fake := &fakeBpfGuardCore{
		status: CoreBpfGuardStatus{Enabled: false, Attached: true, LSMAttached: true, TPAttached: true},
		epoch:  "0123456789abcdef",
	}
	engine := newBpfGuardTestEngine(fake)
	runtime := RuntimeSettings{XDREnabled: true}
	now := time.Now().UTC()
	next := engine.pollBpfGuard(runtime, now, time.Time{})
	if !next.Equal(now.Add(bpfGuardDrainInterval)) {
		t.Fatalf("poll returned cadence %v, want %v", next.Sub(now), bpfGuardDrainInterval)
	}
	if fake.statusCalls != 1 || fake.eventCalls != 1 || fake.epochCalls != 1 {
		t.Fatalf("first poll did not run status/drain/epoch: %+v", fake)
	}
	if len(fake.setCalls) != 1 || !fake.setCalls[0] {
		t.Fatalf("disarmed guard was not armed once: %v", fake.setCalls)
	}
	// The report reflects the last status sample, which predates the arm
	// request; it must not claim an armed guard before the core confirms it.
	if report := engine.BpfGuardReport(); report.State != "disarmed" {
		t.Fatalf("report claimed a state the core did not confirm yet: %+v", report)
	}
	// One second later: drain runs, status is not due (5 s cadence).
	engine.pollBpfGuard(runtime, now.Add(time.Second), next)
	if fake.statusCalls != 1 || fake.eventCalls != 2 || len(fake.setCalls) != 1 {
		t.Fatalf("second poll broke the cadence/arming contract: %+v", fake)
	}
	// Six seconds later: status is due again and now reports the armed guard.
	engine.pollBpfGuard(runtime, now.Add(6*time.Second), now.Add(2*time.Second))
	if fake.statusCalls != 2 || fake.eventCalls != 3 || len(fake.setCalls) != 1 {
		t.Fatalf("status cadence did not fire at 5 s: %+v", fake)
	}
	if report := engine.BpfGuardReport(); report.State != "active" || report.Epoch != "0123456789abcdef" {
		t.Fatalf("confirmed armed guard report is wrong: %+v", report)
	}
	// A disabled runtime never polls the core.
	statusCalls, eventCalls := fake.statusCalls, fake.eventCalls
	engine.pollBpfGuard(RuntimeSettings{XDREnabled: false}, now.Add(20*time.Second), time.Time{})
	if fake.statusCalls != statusCalls || fake.eventCalls != eventCalls {
		t.Fatal("poll ran while XDR was disabled")
	}
}

func TestPollBpfGuardDegradesHonestlyOnDrainFailure(t *testing.T) {
	fake := &fakeBpfGuardCore{
		status:    CoreBpfGuardStatus{Enabled: true, Attached: true, LSMAttached: true, TPAttached: true},
		eventsErr: errors.New("core IPC transport reset"),
	}
	engine := newBpfGuardTestEngine(fake)
	now := time.Now().UTC()
	next := engine.pollBpfGuard(RuntimeSettings{XDREnabled: true}, now, time.Time{})
	report := engine.BpfGuardReport()
	if report.State != "degraded" || report.Reason == "" {
		t.Fatalf("drain failure was reported healthy: %+v", report)
	}
	fake.eventsErr = nil
	engine.pollBpfGuard(RuntimeSettings{XDREnabled: true}, now.Add(time.Second), next)
	if report := engine.BpfGuardReport(); report.State != "active" {
		t.Fatalf("recovered drain was not reflected: %+v", report)
	}
}

func TestPollBpfGuardCapabilityMissing(t *testing.T) {
	fake := &fakeBpfGuardCore{statusErr: ErrBpfGuardUnavailable}
	engine := newBpfGuardTestEngine(fake)
	next := engine.pollBpfGuard(RuntimeSettings{XDREnabled: true}, time.Now().UTC(), time.Time{})
	if next.IsZero() {
		t.Fatal("poll did not return a retry time for a missing capability")
	}
	if report := engine.BpfGuardReport(); report.State != "unavailable" || report.Capability != "missing" {
		t.Fatalf("missing capability reported as %+v", report)
	}
	if len(fake.setCalls) != 0 {
		t.Fatal("set was issued while the capability was missing")
	}
}

func TestBpfGuardCommandAndProgramTypeNamesAreBounded(t *testing.T) {
	for command, want := range map[uint8]string{
		BpfGuardCommandMapCreate:         "BPF_MAP_CREATE",
		BpfGuardCommandProgLoad:          "BPF_PROG_LOAD",
		BpfGuardCommandProgAttach:        "BPF_PROG_ATTACH",
		BpfGuardCommandRawTracepointOpen: "BPF_RAW_TRACEPOINT_OPEN",
		BpfGuardCommandLinkCreate:        "BPF_LINK_CREATE",
	} {
		if got := bpfGuardCommandName(command); got != want {
			t.Fatalf("command %d rendered %q, want %q", command, got, want)
		}
	}
	for progType, want := range map[uint8]string{
		BpfGuardProgTypeKprobe:        "kprobe",
		BpfGuardProgTypeTracepoint:    "tracepoint",
		BpfGuardProgTypeRawTracepoint: "raw_tracepoint",
		BpfGuardProgTypeTracing:       "tracing",
		BpfGuardProgTypeStructOps:     "struct_ops",
		BpfGuardProgTypeLSM:           "lsm",
		BpfGuardProgTypeSkLookup:      "sk_lookup",
		BpfGuardProgTypeSyscall:       "syscall",
	} {
		if got := bpfGuardProgTypeName(progType); got != want {
			t.Fatalf("program type %d rendered %q, want %q", progType, got, want)
		}
	}
	if got := bpfGuardHelperMaskText(0); got != "none" {
		t.Fatalf("empty helper mask rendered %q", got)
	}
	if got := bpfGuardHelperIDsText([BpfGuardHelperBitsPerEvent]uint32{0, 0, 0, 0}); got != "none" {
		t.Fatalf("empty helper ids rendered %q", got)
	}
}

func TestBpfGuardInodeResolutionTolerationFailClosed(t *testing.T) {
	if resolved := resolveToleratedPathByInode("../bash", 1, 1); resolved != "" {
		t.Fatalf("path traversal comm resolved to %q", resolved)
	}
	if resolved := resolveToleratedPathByInode("bash", 1, 1); resolved != "" {
		t.Fatalf("non-tolerated comm resolved to %q", resolved)
	}
	if resolved := resolveToleratedPathByInode("systemd", 0, 123); resolved != "" {
		t.Fatalf("zero device resolved to %q", resolved)
	}
}
