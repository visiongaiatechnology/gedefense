// STATUS: DIAMANT VGT SUPREME
package main

// M2.2 / M2.3 regression tests: bounded core parsers, strict rule tokens and the
// freeze -> (evidence-backed kill tree | resume group) contract with synthetic
// core answers.

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func TestParseCoreRansomEventsBoundedAndStrict(t *testing.T) {
	valid := "3|4242:4242:1000:19:entropy_burst:1700000000000000000:12:6375726c,4343:4000:0:19:rename_storm:1700000000000000001:30:"
	events, dropped, err := parseCoreRansomEvents(valid)
	if err != nil {
		t.Fatalf("valid ransom batch rejected: %v", err)
	}
	if dropped != 3 || len(events) != 2 {
		t.Fatalf("batch parsed to %d events dropped=%d", len(events), dropped)
	}
	if events[0].TGID != 4242 || events[0].PGID != 4242 || events[0].UID != 1000 ||
		events[0].Signal != 19 || events[0].Reason != RansomReasonEntropyBurst ||
		events[0].Count != 12 || events[0].Comm != "curl" {
		t.Fatalf("first ransom event decoded wrong: %+v", events[0])
	}
	if _, gotDropped, err := parseCoreRansomEvents("7|"); err != nil || gotDropped != 7 {
		t.Fatalf("drop-only batch is wrong: dropped=%d err=%v", gotDropped, err)
	}
	if events, _, err := parseCoreRansomEvents("empty"); err != nil || events != nil {
		t.Fatalf("empty batch is wrong: %+v %v", events, err)
	}
	invalid := []string{
		"",
		" 0|",
		"x|",
		"0",
		"0|4242:4242:1000:19:entropy_burst:1700000000000000000:12",                // missing comm field
		"0|4242:4242:1000:19:entropy_burst:1700000000000000000:12:6375726c:extra", // extra field
		"0|0:4242:1000:19:entropy_burst:1700000000000000000:12:",                  // zero tgid
		"0|4242:4242:1000:0:entropy_burst:1700000000000000000:12:",                // zero signal
		"0|4242:4242:1000:99:entropy_burst:1700000000000000000:12:",               // signal out of range
		"0|4242:4242:1000:19:unknown_reason:1700000000000000000:12:",              // unknown reason
		"0|4242:4242:1000:19:entropy_burst:0:12:",                                 // zero timestamp
		"0|4242:4242:1000:19:entropy_burst:1700000000000000000:0:",                // zero count
		"0|4242:4242:1000:19:entropy_burst:1700000000000000000:12:6",              // odd comm hex
		"0|4242:4242:1000:19:entropy_burst:1700000000000000000:12:00",             // NUL comm
		"0|" + strings.Repeat("4", maxRansomPayloadBytes),
	}
	for _, response := range invalid {
		if events, _, err := parseCoreRansomEvents(response); err == nil || events != nil {
			t.Fatalf("hostile ransom batch accepted: %.60q", response)
		}
	}
	tooMany := "0|" + strings.TrimSuffix(strings.Repeat("4242:4242:1000:19:entropy_burst:1700000000000000000:12:,", maxRansomEventsPerResponse+1), ",")
	if _, _, err := parseCoreRansomEvents(tooMany); err == nil {
		t.Fatal("a batch above the core ceiling was accepted")
	}
}

func TestParseCoreRansomStatusBoundedAndStrict(t *testing.T) {
	status, err := parseCoreRansomStatus("1:1:500:0:42:1:2:0")
	if err != nil {
		t.Fatalf("valid ransom status rejected: %v", err)
	}
	if !status.Armed || !status.Attached || status.Emitted != 500 || status.StopsOK != 42 ||
		status.StopsFailed != 1 || status.StopsSkipped != 2 || status.TrackFailures != 0 {
		t.Fatalf("ransom status decoded wrong: %+v", status)
	}
	for _, response := range []string{
		"", "1:1:2", "1:1:2:3:4:5:6:7:8", "2:0:0:0:0:0:0:0", "1:x:0:0:0:0:0:0",
		" 1:1:0:0:0:0:0:0", "1:1:0:0:0:0:0:0\x00", strings.Repeat("1", 300),
	} {
		if _, err := parseCoreRansomStatus(response); err == nil {
			t.Fatalf("hostile ransom status accepted: %.40q", response)
		}
	}
}

func TestXDRRuleTokensAreClosedAndInjectionFree(t *testing.T) {
	valid := []string{
		"XDR.RANSOM_ENTROPY_BURST", "XDR.RANSOM_RENAME_STORM", "XDR.MEMFD_EXEC",
		"KD.LINUX.DESTRUCTIVE", "BASELINE.HASH_MISMATCH", "L7.CORRELATED_REMOTE",
	}
	for _, rule := range valid {
		if !validXDRRuleToken(rule) {
			t.Fatalf("documented rule token %q rejected", rule)
		}
	}
	invalid := []string{"", "XDR", "XDR.X;rm -rf /", "XDR.X Y", "RM -RF /", "XDR." + strings.Repeat("A", 80)}
	for _, rule := range invalid {
		if validXDRRuleToken(rule) {
			t.Fatalf("unsafe rule token accepted: %q", rule)
		}
	}
	client := &CoreClient{}
	if _, err := client.KillTree(0, 1, "XDR.MEMFD_EXEC"); err == nil {
		t.Fatal("tree kill accepted a zero pid")
	}
	if _, err := client.KillTree(1, 1, "XDR.X;rm"); err == nil {
		t.Fatal("tree kill accepted an injected rule token")
	}
	if err := client.StopGroup(-1, "XDR.MEMFD_EXEC"); err == nil {
		t.Fatal("group stop accepted a negative pid")
	}
	if err := client.ResumeGroup(0, "XDR.MEMFD_EXEC"); err == nil {
		t.Fatal("group resume accepted a zero pgid")
	}
	if err := client.StopGroup(42, "not-a-rule"); err == nil {
		t.Fatal("group stop accepted a rule token outside the closed prefixes")
	}
}

// ------------------------------------------------------- engine integration

type fakeRansomCore struct {
	killed    []int
	resumed   []int
	killErr   error
	resumeErr error
	killCount int
	setCalls  []bool
}

func (f *fakeRansomCore) KillTree(pid int, _ uint64, _ string) (int, error) {
	f.killed = append(f.killed, pid)
	if f.killErr != nil {
		return 0, f.killErr
	}
	return f.killCount, nil
}
func (f *fakeRansomCore) StopGroup(int, string) error { return nil }
func (f *fakeRansomCore) ResumeGroup(pgid int, _ string) error {
	f.resumed = append(f.resumed, pgid)
	return f.resumeErr
}
func (f *fakeRansomCore) RansomSet(enabled bool) error {
	f.setCalls = append(f.setCalls, enabled)
	return nil
}
func (f *fakeRansomCore) RansomEvents() ([]CoreRansomEvent, uint64, error) { return nil, 0, nil }
func (f *fakeRansomCore) RansomStatus() (CoreRansomStatus, error)          { return CoreRansomStatus{}, nil }

func newRansomTestEngine(fake *fakeRansomCore) *XDREngine {
	engine := &XDREngine{
		state: NewState("test", defaultConfig()), correlator: NewIncidentCorrelator(0),
		dedupe: map[string]time.Time{}, degradeCauses: map[string]string{}, forensicFailures: map[string]int{},
		ransomCore: fake,
	}
	return engine
}

func syntheticRansomEvent(reason string) CoreRansomEvent {
	return CoreRansomEvent{
		TGID: 4242, PGID: 4242, UID: 1000, Signal: 19, Reason: reason,
		TsNS: 1700000000000000000, Count: 30, Comm: "encryptor",
	}
}

func TestRansomFreezeEscalatesOnlyWithEvidenceAndEnforce(t *testing.T) {
	previousHook := ransomStartTicksHook
	ransomStartTicksHook = func(pid int) (uint64, error) {
		if pid != 4242 {
			t.Fatalf("tree kill resolved the wrong tgid: %d", pid)
		}
		return 9911, nil
	}
	t.Cleanup(func() { ransomStartTicksHook = previousHook })
	fake := &fakeRansomCore{killCount: 3}
	engine := newRansomTestEngine(fake)
	now := time.Now().UTC()
	engine.handleRansomEvents([]CoreRansomEvent{syntheticRansomEvent(RansomReasonEntropyBurst)}, now, true)
	incidents := engine.state.Snapshot().Incidents
	if len(incidents) != 1 {
		t.Fatalf("expected one ransom incident, got %d", len(incidents))
	}
	incident := incidents[0]
	if !containsString(incident.RuleIDs, "XDR.RANSOM_ENTROPY_BURST") || incident.Action != "kill-tree" {
		t.Fatalf("ransom freeze was not escalated with a tree kill: %+v", incident)
	}
	if len(fake.killed) != 1 || fake.killed[0] != 4242 {
		t.Fatalf("tree kill was not issued for the frozen tgid: %v", fake.killed)
	}
	if strings.Contains(incident.Outcome, "freeze retained") {
		t.Fatalf("outcome contradicts the applied kill: %q", incident.Outcome)
	}
}

func TestRansomFreezeIsRetainedWhenStartIdentityCannotBeResolved(t *testing.T) {
	previousHook := ransomStartTicksHook
	ransomStartTicksHook = func(int) (uint64, error) { return 0, errors.New("stat vanished") }
	t.Cleanup(func() { ransomStartTicksHook = previousHook })
	fake := &fakeRansomCore{killCount: 3}
	engine := newRansomTestEngine(fake)
	engine.handleRansomEvents([]CoreRansomEvent{syntheticRansomEvent(RansomReasonEntropyBurst)}, time.Now().UTC(), true)
	incidents := engine.state.Snapshot().Incidents
	if len(incidents) != 1 || !strings.Contains(incidents[0].Outcome, "freeze retained") {
		t.Fatalf("unresolved start identity must retain the freeze: %+v", incidents)
	}
	if len(fake.killed) != 0 {
		t.Fatal("tree kill was issued without a resolved start-time identity")
	}
}

func TestRansomFreezeIsReleasedWhenEscalationIsNotAllowed(t *testing.T) {
	fake := &fakeRansomCore{}
	engine := newRansomTestEngine(fake)
	engine.handleRansomEvents([]CoreRansomEvent{syntheticRansomEvent(RansomReasonRenameStorm)}, time.Now().UTC(), false)
	incidents := engine.state.Snapshot().Incidents
	if len(incidents) != 1 || incidents[0].Action != "resume" {
		t.Fatalf("non-escalation did not release the freeze: %+v", incidents)
	}
	if len(fake.resumed) != 1 || fake.resumed[0] != 4242 {
		t.Fatalf("GROUP_CONT was not issued for the frozen pgid: %v", fake.resumed)
	}
	if len(fake.killed) != 0 {
		t.Fatal("non-escalation issued a kill")
	}
}

func TestRansomFreezeRetentionIsReportedWhenReleaseFails(t *testing.T) {
	fake := &fakeRansomCore{resumeErr: errors.New("broker unavailable")}
	engine := newRansomTestEngine(fake)
	engine.handleRansomEvents([]CoreRansomEvent{syntheticRansomEvent(RansomReasonEntropyBurst)}, time.Now().UTC(), false)
	incidents := engine.state.Snapshot().Incidents
	if len(incidents) != 1 || !strings.Contains(incidents[0].Outcome, "freeze retained") {
		t.Fatalf("failed release was not reported honestly: %+v", incidents)
	}
	orphan := false
	for _, event := range engine.state.Snapshot().Events {
		if event.Kind == "xdr.ransom_freeze_orphaned" {
			orphan = true
		}
	}
	if !orphan {
		t.Fatal("an unreleased kernel freeze was not raised as an operator condition")
	}
}

func TestRansomDrainUsesFastExecTickCadence(t *testing.T) {
	engine := newRansomTestEngine(&fakeRansomCore{})
	if got := engine.consumeRansomEvents(nil, 0, nil, time.Now().UTC(), false); got != 100*time.Millisecond {
		t.Fatalf("ransom drain cadence = %s, want 100ms", got)
	}
}

func TestRansomSensorReportIsHonestAboutArmAndAttach(t *testing.T) {
	engine := newRansomTestEngine(&fakeRansomCore{})
	if got := engine.RansomSensorReport(); got.State != "unavailable" || got.Capability != "missing" {
		t.Fatalf("missing capability reported as %+v", got)
	}
	now := time.Now().UTC()
	engine.consumeRansomStatus(CoreRansomStatus{Armed: true, Attached: true, Emitted: 9, Drops: 1, StopsOK: 4}, nil, now)
	report := engine.RansomSensorReport()
	if report.State != "active" || !report.Armed || !report.Attached || report.Emitted != 9 || report.StopsOK != 4 || report.SampledAt == nil {
		t.Fatalf("active sensor reported as %+v", report)
	}
	engine.consumeRansomStatus(CoreRansomStatus{Armed: true, Attached: false}, nil, now)
	if got := engine.RansomSensorReport(); got.State != "degraded" || !strings.Contains(got.Reason, "not attached") {
		t.Fatalf("armed-but-unattached sensor reported as %+v", got)
	}
	engine.consumeRansomStatus(CoreRansomStatus{Armed: false, Attached: true}, nil, now)
	if got := engine.RansomSensorReport(); got.State != "disarmed" {
		t.Fatalf("disarmed sensor reported as %+v", got)
	}
	engine.consumeRansomStatus(CoreRansomStatus{}, ErrRansomUnavailable, now)
	if got := engine.RansomSensorReport(); got.State != "unavailable" {
		t.Fatalf("capability loss reported as %+v", got)
	}
}

func TestRansomFreezeReleasesProtectedTargetOnProtectedRejection(t *testing.T) {
	previousHook := ransomStartTicksHook
	ransomStartTicksHook = func(int) (uint64, error) { return 9911, nil }
	t.Cleanup(func() { ransomStartTicksHook = previousHook })
	fake := &fakeRansomCore{killErr: errors.New("core rejected command: kill tree root is protected")}
	engine := newRansomTestEngine(fake)
	ev := syntheticRansomEvent(RansomReasonRenameStorm)
	ev.TGID, ev.PGID, ev.Comm = 1912, 1912, "systemd-udevd"
	engine.handleRansomEvents([]CoreRansomEvent{ev}, time.Now().UTC(), true)
	if len(fake.resumed) != 1 || fake.resumed[0] != 1912 {
		t.Fatalf("protected target freeze was not resumed via GROUP_CONT: resumed=%v", fake.resumed)
	}
	incidents := engine.state.Snapshot().Incidents
	if len(incidents) != 1 || incidents[0].Action != "resume" {
		t.Fatalf("expected resume action for protected target, got %+v", incidents)
	}
}
