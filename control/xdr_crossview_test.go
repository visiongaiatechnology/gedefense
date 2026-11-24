// STATUS: DIAMANT VGT SUPREME
package main

// V6.3.0 AP-3 regression tests: the contradiction → XDR rule mapping
// (evidence-first, alert-only, never kill), the TOLERATED raw-tap policy, the
// dedupe/overflow contract, the capability-missing fact handling and the
// status/report poll cadence with synthetic core answers (no socket, no kernel).

import (
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

type fakeCrossViewCore struct {
	status      CoreCrossViewStatus
	statusErr   error
	report      string
	reportErr   error
	events      []CoreCrossViewEvent
	dropped     uint64
	eventsErr   error
	statusCalls int
	reportCalls int
	eventCalls  int
}

func (f *fakeCrossViewCore) CrossViewStatus() (CoreCrossViewStatus, error) {
	f.statusCalls++
	return f.status, f.statusErr
}

func (f *fakeCrossViewCore) CrossViewReport() (string, error) {
	f.reportCalls++
	if f.reportErr != nil {
		return "", f.reportErr
	}
	if f.report == "" {
		return "bounds=ok:domains=8:contradictions=0:events=0:scans=1:drops=0:age_ms=0:tap=1:mods=1:procs=1:bpf=1:pkgdb=debian:trace=1:pins=2", nil
	}
	return f.report, nil
}

func (f *fakeCrossViewCore) CrossViewEvents() ([]CoreCrossViewEvent, uint64, error) {
	f.eventCalls++
	if f.eventsErr != nil {
		return nil, 0, f.eventsErr
	}
	return f.events, f.dropped, nil
}

func newCrossViewTestEngine(fake crossViewCore) *XDREngine {
	return &XDREngine{
		state: NewState("test", defaultConfig()), correlator: NewIncidentCorrelator(0),
		dedupe: map[string]time.Time{}, degradeCauses: map[string]string{}, forensicFailures: map[string]int{},
		crossViewCore: fake,
	}
}

func syntheticCrossViewEvent(kind, domain, severity uint8, pid int, ino, ts uint64, comm string, detail uint32) CoreCrossViewEvent {
	return CoreCrossViewEvent{
		TsNS: ts, Domain: domain, Kind: kind, Severity: severity,
		PID: pid, UID: 0, Dev: 0, Ino: ino, DetailCode: detail, Detail: CrossViewKindName(kind), Comm: comm,
	}
}

func crossViewIncidentsWithRule(engine *XDREngine, ruleID string) []XDRIncident {
	var out []XDRIncident
	for _, incident := range engine.state.Snapshot().Incidents {
		if containsString(incident.RuleIDs, ruleID) {
			out = append(out, incident)
		}
	}
	return out
}

func TestCrossViewHiddenProgIsEvidenceFirstObserveOnly(t *testing.T) {
	engine := newCrossViewTestEngine(&fakeCrossViewCore{})
	now := time.Now().UTC()
	event := syntheticCrossViewEvent(CrossViewKindHiddenProg, CrossViewDomainEBPFIDGap,
		CrossViewSeverityCritical, 0, 42, 1700000000000000000, "bpf-prog", CrossViewDetailIDGap)
	engine.consumeCrossViewEvents([]CoreCrossViewEvent{event}, 0, now)
	incidents := crossViewIncidentsWithRule(engine, "XDR.HIDDEN_BPF_PROG")
	if len(incidents) != 1 {
		t.Fatalf("expected one XDR.HIDDEN_BPF_PROG incident, got %d", len(incidents))
	}
	incident := incidents[0]
	if incident.Decision != "alert" || incident.Action != "none" || incident.Severity != "critical" ||
		incident.Score < 140 || incident.KillSignals != 0 || incident.ResponseScore != 0 {
		t.Fatalf("hidden-prog incident is not observe-only: %+v", incident)
	}
	if incident.Outcome == "" || incident.EvidenceRoot == "" || incident.ExecutionChainID == "" {
		t.Fatalf("hidden-prog incident lacks evidence/outcome: %+v", incident)
	}
	if len(incident.AttackStory) != 1 || incident.AttackStory[0].Sensor != "kernel-cross-view" ||
		incident.AttackStory[0].Metadata["observe_only"] != "true" ||
		incident.AttackStory[0].Metadata["kind"] != "HIDDEN_PROG" {
		t.Fatalf("hidden-prog attack-story node missing: %+v", incident.AttackStory)
	}
	// Dedupe: the same (ts,domain,kind,pid,ino) record must not repeat.
	engine.consumeCrossViewEvents([]CoreCrossViewEvent{event}, 0, now)
	if got := len(crossViewIncidentsWithRule(engine, "XDR.HIDDEN_BPF_PROG")); got != 1 {
		t.Fatalf("duplicate cross-view record created %d incidents", got)
	}
}

func TestCrossViewRuleMappingCoversEveryKind(t *testing.T) {
	cases := []struct {
		kind     uint8
		domain   uint8
		severity uint8
		rule     string
		want     string
	}{
		{CrossViewKindHiddenProg, CrossViewDomainEBPFIDGap, CrossViewSeverityCritical, "XDR.HIDDEN_BPF_PROG", "critical"},
		{CrossViewKindHiddenMap, CrossViewDomainEBPFIDGap, CrossViewSeverityCritical, "XDR.HIDDEN_BPF_MAP", "critical"},
		{CrossViewKindHiddenLink, CrossViewDomainEBPFIDGap, CrossViewSeverityCritical, "XDR.HIDDEN_BPF_LINK", "critical"},
		{CrossViewKindLinkTamper, CrossViewDomainEBPFIDGap, CrossViewSeverityCritical, "XDR.BPF_LINK_TAMPER", "critical"},
		{CrossViewKindHiddenSocket, CrossViewDomainSocketView, CrossViewSeverityHigh, "XDR.HIDDEN_SOCKET", "high"},
		{CrossViewKindPortlessRawTap, CrossViewDomainSocketView, CrossViewSeverityHigh, "XDR.PORTLESS_RAW_TAP", "high"},
		{CrossViewKindHiddenProcess, CrossViewDomainProcessView, CrossViewSeverityHigh, "XDR.HIDDEN_PROCESS", "high"},
		{CrossViewKindLKMHidden, CrossViewDomainModuleTrace, CrossViewSeverityHigh, "XDR.LKM_HIDDEN", "high"},
		{CrossViewKindFtraceHook, CrossViewDomainModuleTrace, CrossViewSeverityHigh, "XDR.FTRACE_HOOK_ANOMALY", "high"},
		{CrossViewKindLibraryMismatch, CrossViewDomainLibraryView, CrossViewSeverityHigh, "XDR.LIBRARY_CROSSVIEW", "high"},
		{CrossViewKindPinMismatch, CrossViewDomainPinView, CrossViewSeverityHigh, "XDR.BPF_PIN_TAMPER", "critical"},
	}
	for index, tc := range cases {
		engine := newCrossViewTestEngine(&fakeCrossViewCore{})
		now := time.Now().UTC()
		event := syntheticCrossViewEvent(tc.kind, tc.domain, tc.severity, 1234, uint64(index+1),
			uint64(1700000000000000000+index), "cross", 1)
		engine.recordCrossViewContradiction(event, now)
		incidents := crossViewIncidentsWithRule(engine, tc.rule)
		if len(incidents) != 1 {
			t.Fatalf("kind %d did not produce rule %s (got %d)", tc.kind, tc.rule, len(incidents))
		}
		incident := incidents[0]
		if incident.Severity != tc.want {
			t.Fatalf("kind %d severity = %q, want %q", tc.kind, incident.Severity, tc.want)
		}
		if incident.Decision != "alert" || incident.Action != "none" || incident.KillSignals != 0 {
			t.Fatalf("kind %d is not observe-only: %+v", tc.kind, incident)
		}
	}
}

func TestCrossViewNameHeuristicIsWarningNotCritical(t *testing.T) {
	engine := newCrossViewTestEngine(&fakeCrossViewCore{})
	now := time.Now().UTC()
	event := syntheticCrossViewEvent(CrossViewKindHiddenProg, CrossViewDomainMapNameView,
		CrossViewSeverityMedium, 0, 7, 1700000000000000000, "bpf-name", CrossViewDetailNameHeuristic)
	engine.recordCrossViewContradiction(event, now)
	incidents := crossViewIncidentsWithRule(engine, "XDR.HIDDEN_BPF_PROG")
	if len(incidents) != 1 {
		t.Fatalf("name heuristic did not produce one evidence incident: %d", len(incidents))
	}
	if incidents[0].Severity != "warning" || incidents[0].Score != 60 {
		t.Fatalf("name heuristic should stay a warning, got %+v", incidents[0])
	}
}

func TestCrossViewRawTapToleratedPolicy(t *testing.T) {
	engine := newCrossViewTestEngine(&fakeCrossViewCore{})
	engine.selfPID = os.Getpid()
	now := time.Now().UTC()

	// 1. Own control process: always tolerated, never an incident.
	own := syntheticCrossViewEvent(CrossViewKindRawTapFilter, CrossViewDomainNetlinkFilter,
		CrossViewSeverityMedium, engine.selfPID, 0, 1700000000000000000, "gedefense-control", CrossViewDetailTapFilter)
	engine.recordCrossViewRawTap(own, now)

	// 2. A documented tool name is TOLERATED even without a resolvable path.
	tool := syntheticCrossViewEvent(CrossViewKindRawTapFilter, CrossViewDomainNetlinkFilter,
		CrossViewSeverityMedium, 424242, 0, 1700000000000000001, "dhclient", CrossViewDetailTapFilter)
	engine.recordCrossViewRawTap(tool, now)

	// 3. Unattributed tap: an observation, never an invented verdict.
	unattributed := syntheticCrossViewEvent(CrossViewKindRawTapFilter, CrossViewDomainNetlinkFilter,
		CrossViewSeverityMedium, 0, 77, 1700000000000000002, "packet", CrossViewDetailTapFilter)
	engine.recordCrossViewRawTap(unattributed, now)

	if incidents := crossViewIncidentsWithRule(engine, "XDR.PORTLESS_RAW_TAP"); len(incidents) != 0 {
		t.Fatalf("tolerated/unattributed taps created %d incidents", len(incidents))
	}
	events := engine.state.Snapshot().Events
	var tolerated, unattributedSeen bool
	for _, event := range events {
		switch event.Kind {
		case "xdr.cross_view_raw_tap_tolerated":
			tolerated = true
		case "xdr.cross_view_raw_tap_unattributed":
			unattributedSeen = true
		}
	}
	if !tolerated || !unattributedSeen {
		t.Fatalf("tolerated/unattributed tap evidence missing (tolerated=%v unattributed=%v)", tolerated, unattributedSeen)
	}

	// 4. A core-judged PORTLESS_RAW_TAP contradiction becomes an incident.
	portless := syntheticCrossViewEvent(CrossViewKindPortlessRawTap, CrossViewDomainSocketView,
		CrossViewSeverityHigh, 500, 7, 1700000000000000003, "bpfd", CrossViewDetailTapSuspicious)
	engine.consumeCrossViewEvents([]CoreCrossViewEvent{portless}, 0, now)
	if incidents := crossViewIncidentsWithRule(engine, "XDR.PORTLESS_RAW_TAP"); len(incidents) != 1 {
		t.Fatalf("portless raw tap produced %d incidents", len(incidents))
	}
	// 5. The policy helpers are total and bounded.
	for path, want := range map[string]bool{
		"/tmp/bpfd":            true,
		"/var/tmp/x":           true,
		"/dev/shm/x":           true,
		"/home/user/implant":   true,
		"/run/user/0/x":        true,
		"/usr/bin/tcpdump":     false,
		"/usr/sbin/suricata":   false,
		"unknown":              false,
		"":                     false,
		"/tmp/tool (deleted)":  true,
		"/usr/lib/libselinux":  false,
		"/var/run/user/0/bpfd": true,
	} {
		if got := crossViewSuspiciousExecPath(path); got != want {
			t.Fatalf("crossViewSuspiciousExecPath(%q) = %v, want %v", path, got, want)
		}
	}
}

func TestCrossViewDedupeKeyIncludesIno(t *testing.T) {
	engine := newCrossViewTestEngine(&fakeCrossViewCore{})
	now := time.Now().UTC()
	first := syntheticCrossViewEvent(CrossViewKindHiddenMap, CrossViewDomainEBPFIDGap,
		CrossViewSeverityCritical, 0, 7, 1700000000000000000, "bpf-map", CrossViewDetailIDGap)
	engine.consumeCrossViewEvents([]CoreCrossViewEvent{first}, 0, now)
	sameKey := first
	engine.consumeCrossViewEvents([]CoreCrossViewEvent{sameKey}, 0, now)
	differentIno := first
	differentIno.Ino = 8
	engine.consumeCrossViewEvents([]CoreCrossViewEvent{differentIno}, 0, now)
	if got := len(crossViewIncidentsWithRule(engine, "XDR.HIDDEN_BPF_MAP")); got != 2 {
		t.Fatalf("dedupe by (ts,domain,kind,pid,ino) produced %d incidents, want 2", got)
	}
}

func TestCrossViewOverflowIsRateLimited(t *testing.T) {
	engine := newCrossViewTestEngine(&fakeCrossViewCore{})
	now := time.Now().UTC()
	engine.consumeCrossViewEvents(nil, 3, now)
	countOverflow := func() int {
		seen := 0
		for _, event := range engine.state.Snapshot().Events {
			if event.Kind == "xdr.cross_view_overflow" {
				seen++
			}
		}
		return seen
	}
	if got := countOverflow(); got != 1 {
		t.Fatalf("overflow telemetry = %d, want 1", got)
	}
	engine.consumeCrossViewEvents(nil, 4, now.Add(time.Second))
	if got := countOverflow(); got != 1 {
		t.Fatalf("overflow telemetry not rate-limited: %d", got)
	}
	engine.consumeCrossViewEvents(nil, 4, now.Add(6*time.Minute))
	if got := countOverflow(); got != 2 {
		t.Fatalf("overflow telemetry did not re-arm after the gap: %d", got)
	}
}

func TestCrossViewLkmTaintMetadata(t *testing.T) {
	engine := newCrossViewTestEngine(&fakeCrossViewCore{})
	now := time.Now().UTC()
	event := syntheticCrossViewEvent(CrossViewKindLKMHidden, CrossViewDomainModuleTrace,
		CrossViewSeverityHigh, 0, 0, 1700000000000000000, "rootkit", CrossViewDetailProcOnly)
	event.Dev = 1 << 12
	engine.consumeCrossViewEvents([]CoreCrossViewEvent{event}, 0, now)
	incidents := crossViewIncidentsWithRule(engine, "XDR.LKM_HIDDEN")
	if len(incidents) != 1 {
		t.Fatalf("LKM hidden produced %d incidents", len(incidents))
	}
	metadata := incidents[0].AttackStory[0].Metadata
	if metadata["taint_raw"] != "0x1000" || metadata["taint_forced_or_oot"] != "true" {
		t.Fatalf("module taint metadata missing: %+v", metadata)
	}
}

func TestPollCrossViewCadenceAndCapability(t *testing.T) {
	fake := &fakeCrossViewCore{
		status: CoreCrossViewStatus{Enabled: true, Scans: 1, Domains: 8, Tap: true, Mods: true,
			Procs: true, BPF: true, Trace: true, PkgDB: CrossViewPkgDBDebian},
		events: []CoreCrossViewEvent{
			syntheticCrossViewEvent(CrossViewKindHiddenSocket, CrossViewDomainSocketView,
				CrossViewSeverityHigh, 0, 9, 1700000000000000000, "socket", CrossViewDetailNetlinkOnly),
		},
	}
	engine := newCrossViewTestEngine(fake)
	engine.selfPID = os.Getpid()
	runtime := RuntimeSettings{XDREnabled: true}
	t0 := time.Now().UTC()
	next := engine.pollCrossView(runtime, t0, time.Time{})
	if fake.statusCalls != 1 || fake.reportCalls != 1 || fake.eventCalls != 1 {
		t.Fatalf("first poll calls status=%d report=%d events=%d", fake.statusCalls, fake.reportCalls, fake.eventCalls)
	}
	if !next.Equal(t0.Add(crossViewDrainInterval)) {
		t.Fatalf("first poll returned %v, want drain cadence", next.Sub(t0))
	}
	// Within the retry window nothing happens.
	engine.pollCrossView(runtime, t0.Add(100*time.Millisecond), next)
	if fake.statusCalls != 1 || fake.eventCalls != 1 {
		t.Fatalf("early poll bypassed the retry window: status=%d events=%d", fake.statusCalls, fake.eventCalls)
	}
	// The fast drain cadence keeps working; the 15 s status/report cadence does not.
	engine.pollCrossView(runtime, t0.Add(time.Second), next)
	if fake.statusCalls != 1 || fake.eventCalls != 2 || fake.reportCalls != 1 {
		t.Fatalf("second poll calls status=%d report=%d events=%d", fake.statusCalls, fake.reportCalls, fake.eventCalls)
	}
	// After 15 s the status+report query is due again.
	engine.pollCrossView(runtime, t0.Add(crossViewStatusInterval), next)
	if fake.statusCalls != 2 || fake.reportCalls != 2 {
		t.Fatalf("status cadence missed: status=%d report=%d", fake.statusCalls, fake.reportCalls)
	}
	// Disabled runtime: no request at all.
	engine.pollCrossView(RuntimeSettings{XDREnabled: false}, t0.Add(time.Hour), next)
	if fake.statusCalls != 2 || fake.eventCalls != 3 {
		t.Fatalf("disabled runtime was polled: status=%d events=%d", fake.statusCalls, fake.eventCalls)
	}
}

func TestPollCrossViewCapabilityMissingIsFactNotDegradation(t *testing.T) {
	fake := &fakeCrossViewCore{statusErr: ErrCrossViewUnavailable}
	engine := newCrossViewTestEngine(fake)
	next := engine.pollCrossView(RuntimeSettings{XDREnabled: true}, time.Now().UTC(), time.Time{})
	if next.IsZero() {
		t.Fatal("poll returned a zero retry time")
	}
	if engine.crossViewCapabilityKnown {
		t.Fatal("capability reported known after ErrCrossViewUnavailable")
	}
	if degraded, reason := engine.degradedState(); degraded {
		t.Fatalf("capability-missing degraded the engine: %s", reason)
	}
	found := false
	for _, event := range engine.state.Snapshot().Events {
		if event.Kind == "xdr.cross_view_capability_missing" {
			found = true
		}
	}
	if !found {
		t.Fatal("capability-missing fact event missing")
	}
}

func TestPollCrossViewHonestDrainFailure(t *testing.T) {
	fake := &fakeCrossViewCore{
		status:    CoreCrossViewStatus{Enabled: true, Domains: 2, Procs: true, Mods: true},
		eventsErr: errors.New("core socket timeout"),
	}
	engine := newCrossViewTestEngine(fake)
	engine.pollCrossView(RuntimeSettings{XDREnabled: true}, time.Now().UTC(), time.Time{})
	engine.crossViewMu.Lock()
	statusErr := engine.crossViewStatusErr
	engine.crossViewMu.Unlock()
	if !strings.Contains(statusErr, "event drain failed") {
		t.Fatalf("drain failure not surfaced: %q", statusErr)
	}
	report := engine.CrossViewReport()
	if report.State != "degraded" || report.Reason == "" {
		t.Fatalf("projection hides the drain failure: %+v", report)
	}
}

func TestCrossViewReportProjectionNeverClaimsActiveWithoutDomain(t *testing.T) {
	engine := newCrossViewTestEngine(&fakeCrossViewCore{})
	report := engine.CrossViewReport()
	if report.State != "unavailable" || report.Capability != "unknown" {
		t.Fatalf("unknown capability projected as %+v", report)
	}
	fake := &fakeCrossViewCore{
		status: CoreCrossViewStatus{Enabled: true, Domains: 0, Scans: 1},
	}
	engine = newCrossViewTestEngine(fake)
	engine.pollCrossView(RuntimeSettings{XDREnabled: true}, time.Now().UTC(), time.Time{})
	report = engine.CrossViewReport()
	if report.State != "degraded" || !strings.Contains(report.Reason, "no domain") {
		t.Fatalf("armed-but-blind verifier projected as %+v", report)
	}
	fake = &fakeCrossViewCore{
		status: CoreCrossViewStatus{Enabled: true, Domains: 8, Scans: 2, Contradictions: 1, Events: 3,
			Tap: true, Mods: true, Procs: true, BPF: true, Trace: true, PkgDB: CrossViewPkgDBDebian},
	}
	engine = newCrossViewTestEngine(fake)
	engine.pollCrossView(RuntimeSettings{XDREnabled: true}, time.Now().UTC(), time.Time{})
	report = engine.CrossViewReport()
	if report.State != "active" || report.Capability != "available" ||
		report.Contradictions != 1 || report.Events != 3 || report.Domains != 8 {
		t.Fatalf("healthy verifier projected as %+v", report)
	}
}
