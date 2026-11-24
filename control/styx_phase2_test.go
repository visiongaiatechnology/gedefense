// STATUS: DIAMANT VGT SUPREME
package main

// V6.3.0 AP-6 regression tests: the phase-2 PCR rule (0.60 boundary, volume
// floor, five-minute window expiry, saturating counters), the First-Seen /
// dedupe rules, the honest correlation-quality ladder (RX unavailable and
// tx-only data can never produce OBSERVED), the bounded logind session reader
// (real WSL `/run/systemd/sessions/9`-style fixture, missing SEAT tolerated),
// the bounded entity maps and the observe-only incident shape.
//
// The tests are pure in-memory/table-driven: no socket, no kernel, no root.

import (
	"errors"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// styxPhase2TestEngine builds an XDREngine with the minimum wiring the phase-2
// poll/emitter needs (the pattern used by `xdr_bpfguard_test.go`).
func styxPhase2TestEngine() *XDREngine {
	return &XDREngine{
		state:            NewState("test", defaultConfig()),
		dedupe:           map[string]time.Time{},
		degradeCauses:    map[string]string{},
		forensicFailures: map[string]int{},
		styxPhase2:       NewStyxPhase2Engine(),
	}
}

// styxPhase2TestEvent builds one CoreStyxFlowEvent exactly like the core's text
// wire decoder produces it (canonical 4-byte IPv4 destination for family 4).
func styxPhase2TestEvent(cgroup uint64, pid int, tx, rx uint64, packets uint32, dst string, port, srcPort uint16, family, proto, direction uint8) CoreStyxFlowEvent {
	address := netip.MustParseAddr(dst)
	event := CoreStyxFlowEvent{
		CgroupID:    cgroup,
		TimestampNS: 1_000_000_000,
		TxBytes:     tx,
		RxBytes:     rx,
		PID:         pid,
		UID:         1000,
		DstIP:       net.IP(address.AsSlice()),
		DstPort:     port,
		SrcPort:     srcPort,
		Packets:     packets,
		Family:      family,
		Proto:       proto,
		Direction:   direction,
		Verdict:     0,
		Comm:        "exfil",
	}
	if proto == 6 {
		event.TCPFlags = 0x18
	}
	return event
}

// styxPhase2QualifyingPair is one egress record plus the matching inbound
// record: 1 MiB out, 64 KiB in, PCR = (1024-64)/1088 = 0.882 > 0.60, window
// 1.0625 MiB >= 256 KiB.
func styxPhase2QualifyingPair(cgroup uint64, pid int, remote string, port, localPort uint16) []CoreStyxFlowEvent {
	return []CoreStyxFlowEvent{
		styxPhase2TestEvent(cgroup, pid, 1<<20, 0, 64, remote, port, localPort, 4, 6, 1),
		styxPhase2TestEvent(cgroup, 0, 0, 64<<10, 8, remote, port, localPort, 4, 6, 2),
	}
}

// styxPhase2EnableRx marks the fake engine as "ingress capability attached".
func styxPhase2EnableRx(engine *StyxPhase2Engine) {
	engine.mu.Lock()
	engine.rxCapabilityKnown = true
	engine.rxObservationAvailable = true
	engine.rxAttached = true
	engine.mu.Unlock()
}

// styxPhase2IncidentCount counts the incidents the engine produced at `now`.
func styxPhase2IncidentCount(engine *StyxPhase2Engine, now time.Time) int {
	return len(engine.evaluatePCR(now))
}

// ---------------------------------------------------------------------------
// PCR math
// ---------------------------------------------------------------------------

func TestPCRThresholdIsTheExactSixtyPercentBoundary(t *testing.T) {
	if styxPhase2PCRThreshold != 0.60 {
		t.Fatalf("documented PCR threshold = %v, want 0.60", styxPhase2PCRThreshold)
	}
	tests := []struct {
		name string
		tx   uint64
		rx   uint64
		want bool
	}{
		{"zero flow", 0, 0, false},
		{"symmetric", 1000, 1000, false},
		{"rx dominates", 10, 1000, false},
		{"just below", 3, 1, false},        // PCR = 0.50
		{"boundary equality", 4, 1, false}, // PCR = 0.60 exactly -> no fire
		{"just above", 401, 100, true},     // PCR > 0.60
		{"tx only", 256 << 10, 0, true},    // threshold form; volume/observed gates apply elsewhere
		{"rx overflow guard", 1, (1 << 63) + 1, false},
		{"large rx saturates the guard", 1<<63 - 1, (1 << 63) + 1, false},
		{"large tx at the boundary", 1 << 62, 1 << 60, false}, // 4*rx == tx
		{"large tx above the boundary", (1 << 62) + 1, 1 << 60, true},
	}
	for _, test := range tests {
		if got := styxPhase2PCROverThreshold(test.tx, test.rx); got != test.want {
			t.Fatalf("%s: tx=%d rx=%d: got %v want %v", test.name, test.tx, test.rx, got, test.want)
		}
	}
}

func TestPCRValueUsesSaturatingArithmetic(t *testing.T) {
	if got := styxPhase2PCRValue(0, 0); got != 0 {
		t.Fatalf("empty window PCR = %v, want 0", got)
	}
	if got := styxPhase2PCRValue(3, 2); got >= 0.21 || got <= 0.19 {
		t.Fatalf("PCR(3,2) = %v, want 0.2", got)
	}
	if got := styxPhase2PCRValue(4, 1); got < 0.599 || got > 0.601 {
		t.Fatalf("PCR(4,1) = %v, want 0.60", got)
	}
	if got := styxPhase2PCRValue(1, 0); got != 1 {
		t.Fatalf("PCR(1,0) = %v, want 1", got)
	}
	// Maximal counters saturate the sum instead of wrapping to a negative ratio.
	if got := styxPhase2PCRValue(^uint64(0), 1); got < 0.99 || got > 1.01 {
		t.Fatalf("saturated PCR = %v, want ~1", got)
	}
	if got := styxPhase2PCRValue(^uint64(0), ^uint64(0)); got != 0 {
		t.Fatalf("symmetric saturated PCR = %v, want 0", got)
	}
}

func TestPCRSat32CounterSaturates(t *testing.T) {
	if got := styxSaturatingAdd32(1, 2); got != 3 {
		t.Fatalf("saturating add = %d, want 3", got)
	}
	if got := styxSaturatingAdd32(^uint32(0), 1); got != ^uint32(0) {
		t.Fatalf("uint32 counter wrapped to %d", got)
	}
}

// ---------------------------------------------------------------------------
// Window / evidence rule
// ---------------------------------------------------------------------------

func TestStyxPhase2WindowNeedsVolumeAndObservedRx(t *testing.T) {
	now := time.Date(2026, 11, 24, 12, 0, 0, 0, time.UTC)
	engine := NewStyxPhase2Engine()
	styxPhase2EnableRx(engine)

	// Too small: 64 KiB tx + 4 KiB rx is below the 256 KiB window floor.
	engine.observeBatch([]CoreStyxFlowEvent{
		styxPhase2TestEvent(1, 10, 64<<10, 0, 4, "203.0.113.9", 443, 41000, 4, 6, 1),
		styxPhase2TestEvent(1, 0, 0, 4<<10, 1, "203.0.113.9", 443, 41000, 4, 6, 2),
	}, now)
	if got := styxPhase2IncidentCount(engine, now); got != 0 {
		t.Fatalf("sub-threshold window produced %d incidents", got)
	}

	// Tx-only: above the volume floor and PCR=1, but no inbound sample was ever
	// observed for the entity, so no PCR statement is allowed.
	engine.observeBatch([]CoreStyxFlowEvent{
		styxPhase2TestEvent(2, 11, 2<<20, 0, 128, "203.0.113.10", 443, 41001, 4, 6, 1),
	}, now)
	if got := styxPhase2IncidentCount(engine, now); got != 0 {
		t.Fatalf("tx-only flow produced %d PCR incidents; RX must never be inferred from tx-only data", got)
	}

	// Same flow plus the matching inbound record qualifies.
	engine.observeBatch(styxPhase2QualifyingPair(3, 12, "203.0.113.11", 443, 41002), now)
	if got := styxPhase2IncidentCount(engine, now); got != 1 {
		t.Fatalf("qualifying bidirectional window produced %d incidents, want 1", got)
	}
}

func TestStyxPhase2WindowExpiry(t *testing.T) {
	now := time.Date(2026, 11, 24, 12, 0, 0, 0, time.UTC)
	engine := NewStyxPhase2Engine()
	styxPhase2EnableRx(engine)
	engine.observeBatch(styxPhase2QualifyingPair(1, 10, "203.0.113.20", 443, 41000), now)
	if got := styxPhase2IncidentCount(engine, now); got != 1 {
		t.Fatalf("fresh window produced %d incidents, want 1", got)
	}
	// Six minutes later the five one-minute buckets belong to the past window and
	// the entity is pruned: no stale evidence may survive the window.
	if got := styxPhase2IncidentCount(engine, now.Add(6*time.Minute)); got != 0 {
		t.Fatalf("expired window produced %d incidents, want 0", got)
	}
}

func TestStyxPhase2BoundaryEqualityDoesNotFire(t *testing.T) {
	now := time.Date(2026, 11, 24, 12, 0, 0, 0, time.UTC)

	// tx = 4*rx exactly: PCR == 0.60, window 320 KiB >= 256 KiB. Must NOT fire.
	boundary := NewStyxPhase2Engine()
	styxPhase2EnableRx(boundary)
	boundary.observeBatch([]CoreStyxFlowEvent{
		styxPhase2TestEvent(1, 10, 4*(64<<10), 0, 128, "203.0.113.30", 443, 41000, 4, 6, 1),
		styxPhase2TestEvent(1, 0, 0, 64<<10, 16, "203.0.113.30", 443, 41000, 4, 6, 2),
	}, now)
	if got := styxPhase2IncidentCount(boundary, now); got != 0 {
		t.Fatalf("PCR==0.60 boundary fired %d incidents", got)
	}

	// One byte more outbound crosses the boundary and fires.
	above := NewStyxPhase2Engine()
	styxPhase2EnableRx(above)
	above.observeBatch([]CoreStyxFlowEvent{
		styxPhase2TestEvent(1, 10, 4*(64<<10)+1, 0, 128, "203.0.113.31", 443, 41000, 4, 6, 1),
		styxPhase2TestEvent(1, 0, 0, 64<<10, 16, "203.0.113.31", 443, 41000, 4, 6, 2),
	}, now)
	if got := styxPhase2IncidentCount(above, now); got != 1 {
		t.Fatalf("PCR just above the boundary produced %d incidents, want 1", got)
	}
}

func TestStyxPhase2FirstSeenRule(t *testing.T) {
	now := time.Date(2026, 11, 24, 12, 0, 0, 0, time.UTC)
	engine := NewStyxPhase2Engine()
	styxPhase2EnableRx(engine)
	remote := netip.MustParseAddr("203.0.113.40")
	// The remote is known for two hours: no First-Seen evidence.
	engine.mu.Lock()
	engine.firstSeen[remote] = now.Add(-2 * time.Hour)
	engine.mu.Unlock()
	engine.observeBatch(styxPhase2QualifyingPair(1, 10, remote.String(), 443, 41000), now)
	if got := styxPhase2IncidentCount(engine, now); got != 0 {
		t.Fatalf("known remote produced %d First-Seen incidents, want 0", got)
	}

	// A remote first observed inside the TTL fires.
	fresh := NewStyxPhase2Engine()
	styxPhase2EnableRx(fresh)
	fresh.observeBatch(styxPhase2QualifyingPair(1, 10, "203.0.113.41", 443, 41000), now)
	if got := styxPhase2IncidentCount(fresh, now); got != 1 {
		t.Fatalf("first-seen remote produced %d incidents, want 1", got)
	}
}

func TestStyxPhase2DedupeWindowAndExpiry(t *testing.T) {
	now := time.Date(2026, 11, 24, 12, 0, 0, 0, time.UTC)
	engine := NewStyxPhase2Engine()
	styxPhase2EnableRx(engine)
	engine.observeBatch(styxPhase2QualifyingPair(1, 10, "203.0.113.50", 443, 41000), now)
	if got := styxPhase2IncidentCount(engine, now); got != 1 {
		t.Fatalf("first evaluation produced %d incidents, want 1", got)
	}
	// Same entity, same window, a few seconds later: deduplicated.
	engine.observeBatch(styxPhase2QualifyingPair(1, 10, "203.0.113.50", 443, 41000), now.Add(5*time.Second))
	if got := styxPhase2IncidentCount(engine, now.Add(5*time.Second)); got != 0 {
		t.Fatalf("deduplicated entity produced %d incidents, want 0", got)
	}

	// 31 minutes later the dedupe entry expired and a new window qualifies again.
	later := now.Add(31 * time.Minute)
	engine.observeBatch(styxPhase2QualifyingPair(1, 10, "203.0.113.50", 443, 41000), later)
	if got := styxPhase2IncidentCount(engine, later); got != 1 {
		t.Fatalf("post-dedupe window produced %d incidents, want 1", got)
	}
}

func TestStyxPhase2RxUnavailableNeverYieldsObserved(t *testing.T) {
	now := time.Date(2026, 11, 24, 12, 0, 0, 0, time.UTC)

	// Capability never known: even full bidirectional synthetic data produces no
	// incident and no OBSERVED correlation-quality claim.
	engine := NewStyxPhase2Engine()
	engine.observeBatch(styxPhase2QualifyingPair(1, 10, "203.0.113.60", 443, 41000), now)
	if got := styxPhase2IncidentCount(engine, now); got != 0 {
		t.Fatalf("engine without RX capability produced %d PCR incidents", got)
	}
	report := engine.report(now)
	if report.RxObservation != "unknown" {
		t.Fatalf("unknown capability reported as %q", report.RxObservation)
	}
	if report.CorrelationQuality == "OBSERVED" {
		t.Fatalf("unknown RX capability claimed OBSERVED correlation quality")
	}
	for _, entity := range report.Entities {
		if entity.PCRObserved || entity.CorrelationQuality == "OBSERVED" {
			t.Fatalf("entity without RX observation claimed a PCR/OBSERVED quality: %+v", entity)
		}
	}

	// Capability known but not attached: explicit "unavailable", still no claim.
	engine.mu.Lock()
	engine.rxCapabilityKnown = true
	engine.rxObservationAvailable = false
	engine.mu.Unlock()
	report = engine.report(now)
	if report.RxObservation != "unavailable" || report.Limitation == "" {
		t.Fatalf("detached RX capability not reported honestly: %+v", report)
	}
	if got := len(engine.evaluatePCR(now)); got != 0 {
		t.Fatalf("detached RX capability produced %d PCR incidents", got)
	}
}

func TestStyxPhase2IdleHintUpgradesOnlyToTemporal(t *testing.T) {
	now := time.Date(2026, 11, 24, 12, 0, 0, 0, time.UTC)
	engine := NewStyxPhase2Engine()
	engine.sessionsRoot = styxPhase2InactiveSessionDir(t)
	engine.refreshSessions(now)

	// Tx-only entity: no PCR claim, but the session-inactive context upgrades the
	// reporting quality from NONE to TEMPORAL. It may never become OBSERVED.
	engine.observeBatch([]CoreStyxFlowEvent{
		styxPhase2TestEvent(1, 10, 2<<20, 0, 128, "203.0.113.70", 443, 41000, 4, 6, 1),
	}, now)
	if got := styxPhase2IncidentCount(engine, now); got != 0 {
		t.Fatalf("tx-only entity with idle session produced %d incidents, want 0", got)
	}
	report := engine.report(now)
	if report.IdleHint != "inactive" {
		t.Fatalf("idlehint = %q, want inactive", report.IdleHint)
	}
	if report.CorrelationQuality != "TEMPORAL" {
		t.Fatalf("overall correlation quality = %q, want TEMPORAL", report.CorrelationQuality)
	}
	if len(report.Entities) != 1 || report.Entities[0].CorrelationQuality != "TEMPORAL" {
		t.Fatalf("entity correlation quality was not upgraded to TEMPORAL: %+v", report.Entities)
	}
	if report.Entities[0].PCRObserved {
		t.Fatalf("tx-only entity claimed PCR observation")
	}
}

// ---------------------------------------------------------------------------
// Incident shape
// ---------------------------------------------------------------------------

func TestStyxPhase2IncidentIsEvidenceFirstAndObserveOnly(t *testing.T) {
	now := time.Date(2026, 11, 24, 12, 0, 0, 0, time.UTC)
	engine := NewStyxPhase2Engine()
	styxPhase2EnableRx(engine)
	engine.observeBatch(styxPhase2QualifyingPair(7, 4242, "203.0.113.80", 8443, 51234), now)
	incidents := engine.evaluatePCR(now)
	if len(incidents) != 1 {
		t.Fatalf("expected one PCR incident, got %d", len(incidents))
	}
	incident := incidents[0]
	if incident.Decision != "alert" {
		t.Fatalf("Decision = %q, want alert", incident.Decision)
	}
	if incident.Action != "none" {
		t.Fatalf("Action = %q, want none (observe-only)", incident.Action)
	}
	if incident.KillSignals != 0 {
		t.Fatalf("KillSignals = %d, want 0 (never kill-eligible)", incident.KillSignals)
	}
	if strings.Contains(strings.ToLower(incident.Action), "kill") || strings.Contains(strings.ToLower(incident.Action), "contain") {
		t.Fatalf("phase-2 incident carries an active action: %q", incident.Action)
	}
	if incident.Severity != "high" || incident.Score != 100 {
		t.Fatalf("severity/score = %s/%d, want high/100", incident.Severity, incident.Score)
	}
	if len(incident.RuleIDs) != 1 || incident.RuleIDs[0] != styxPhase2RulePCRExfil {
		t.Fatalf("rule ids = %v, want [%s]", incident.RuleIDs, styxPhase2RulePCRExfil)
	}
	if len(incident.Categories) != 2 || incident.Categories[0] != "network" || incident.Categories[1] != "c2" {
		t.Fatalf("categories = %v, want [network c2]", incident.Categories)
	}
	if len(incident.AttackStory) != 1 || incident.AttackStory[0].Sensor != styxPhase2SensorName {
		t.Fatalf("attack story node missing: %+v", incident.AttackStory)
	}
	if incident.AttackStory[0].Metadata["observe_only"] != "true" ||
		incident.AttackStory[0].Metadata["correlation_quality"] != "OBSERVED" {
		t.Fatalf("attack story metadata does not state observe-only/OBSERVED: %+v", incident.AttackStory[0].Metadata)
	}
	if incident.EvidenceRoot == "" || incident.Outcome == "" {
		t.Fatalf("incident lacks evidence root/outcome: %+v", incident)
	}
	if incident.CellCgroupID != 7 || incident.PID != 4242 || incident.Remote != "203.0.113.80:8443" {
		t.Fatalf("incident entity fields wrong: %+v", incident)
	}

	// The engine's sink records the incident without ever deriving an action.
	xdr := styxPhase2TestEngine()
	xdr.emitStyxPhase2Incident(incident)
	snapshot := xdr.state.Snapshot()
	if len(snapshot.Incidents) != 1 {
		t.Fatalf("emitter recorded %d incidents, want 1", len(snapshot.Incidents))
	}
	if snapshot.Incidents[0].Action != "none" || snapshot.Incidents[0].KillSignals != 0 {
		t.Fatalf("emitted incident is not observe-only: %+v", snapshot.Incidents[0])
	}
}

// ---------------------------------------------------------------------------
// IdleHint / session reader
// ---------------------------------------------------------------------------

// styxPhase2WSLSessionFile is the real Ubuntu-24.04 WSL logind session file
// (`/run/systemd/sessions/5`), which has no SEAT= line: the parser must tolerate
// the missing optional field.
const styxPhase2WSLSessionFile = `# This is private data. Do not parse.
UID=1000
USER=masterboard
ACTIVE=1
IS_DISPLAY=1
STATE=active
REMOTE=0
TYPE=tty
ORIGINAL_TYPE=tty
CLASS=user
SCOPE=session-9.scope
FIFO=/run/systemd/sessions/9.ref
TTY=pts/1
TTY_VALIDITY=from-pam
SERVICE=login
POSITION=0
LEADER=607
AUDIT=5
REALTIME=1795516709994241
MONOTONIC=276151245
`

func styxPhase2WriteSession(t *testing.T, root, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(root, name), []byte(content), 0o600); err != nil {
		t.Fatalf("write session fixture %s: %v", name, err)
	}
}

func styxPhase2InactiveSessionDir(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	styxPhase2WriteSession(t, root, "3", "UID=0\nACTIVE=0\nSTATE=closing\nCLASS=greeter\nTYPE=tty\nSEAT=seat0\n")
	return root
}

func TestStyxPhase2IdleHintParser(t *testing.T) {
	root := t.TempDir()
	// Real WSL fixture: active session, missing SEAT tolerated.
	styxPhase2WriteSession(t, root, "5", styxPhase2WSLSessionFile)
	// Inactive session WITH a SEAT: presence is tolerated too.
	styxPhase2WriteSession(t, root, "12", "UID=0\nACTIVE=0\nSTATE=closing\nCLASS=greeter\nTYPE=tty\nSEAT=seat0\n")
	// systemd keeps a companion `.ref` FIFO; a non-decimal name is never a
	// session record (a regular file here is skipped by the name rule).
	styxPhase2WriteSession(t, root, "5.ref", "not a session record")
	// Malformed: no ACTIVE= field -> unreadable, never counted as active.
	styxPhase2WriteSession(t, root, "7", "UID=1000\nSTATE=active\n")
	// Oversized: > 16 KiB -> unreadable, bounded reader.
	styxPhase2WriteSession(t, root, "8", "UID=1000\nACTIVE=1\n"+strings.Repeat("#", 17*1024))

	summary, err := readStyxSessions(root)
	if err != nil {
		t.Fatalf("readStyxSessions: %v", err)
	}
	if summary.Total != 2 || summary.Active != 1 || summary.Inactive != 1 {
		t.Fatalf("session counters = %+v, want total=2 active=1 inactive=1", summary)
	}
	if summary.Unreadable != 2 {
		t.Fatalf("unreadable = %d, want 2", summary.Unreadable)
	}
	if summary.IdleHint != "active" {
		t.Fatalf("idlehint = %q, want active", summary.IdleHint)
	}

	// No active session: the only honest statement is "inactive" (never locked).
	inactive, err := readStyxSessions(styxPhase2InactiveSessionDir(t))
	if err != nil {
		t.Fatalf("readStyxSessions(inactive): %v", err)
	}
	if inactive.IdleHint != "inactive" || inactive.Total != 1 || inactive.Active != 0 {
		t.Fatalf("inactive projection = %+v", inactive)
	}

	// Missing directory: unavailable, not an error path in the poll.
	missing, err := readStyxSessions(filepath.Join(root, "missing"))
	if err == nil {
		t.Fatalf("missing session directory returned no error")
	}
	if missing.IdleHint != "unavailable" || missing.Total != 0 {
		t.Fatalf("missing-directory projection = %+v", missing)
	}
}

func TestStyxPhase2SessionParserRejectsHostileFiles(t *testing.T) {
	hostile := []string{
		"",                     // empty
		"UID=abc\nACTIVE=1\n",  // non-decimal uid
		"UID=1000\nACTIVE=2\n", // out-of-range active flag
		"UID=1000\nACTIVE=1\nSTATE=locked-bogus\n", // unknown state
		"UID=1000\nACTIVE=1\nACTIVE=1\n",           // duplicate key
		"UID=1000\nACTIVE=1\nBAD-KEY=x\n",          // invalid key syntax
		"UID=1000\nACTIVE=1\nCLASS=User\n",         // invalid token vocabulary
		"UID=1000\x00\nACTIVE=1\n",                 // NUL byte
	}
	for index, content := range hostile {
		if _, ok := parseStyxSessionFile([]byte(content)); ok {
			t.Fatalf("hostile session fixture %d was accepted: %q", index, content)
		}
	}
	// Missing SEAT is explicitly valid.
	if _, ok := parseStyxSessionFile([]byte("UID=1000\nACTIVE=1\nSTATE=online\nCLASS=user\nTYPE=tty\n")); !ok {
		t.Fatalf("valid session without SEAT was rejected")
	}
}

// ---------------------------------------------------------------------------
// RX capability polling
// ---------------------------------------------------------------------------

func TestStyxPhase2RxCapabilityMissIsInfoNotDegradation(t *testing.T) {
	engine := styxPhase2TestEngine()
	engine.styxPhase2.rxStatusQuery = func() (CoreStyxIngressStatus, error) {
		return CoreStyxIngressStatus{}, ErrStyxIngressUnavailable
	}
	now := time.Date(2026, 11, 24, 12, 0, 0, 0, time.UTC)
	next := engine.pollStyxPhase2(RuntimeSettings{XDREnabled: true}, now, time.Time{})
	if next.Sub(now) != styxPhase2RetryInterval {
		t.Fatalf("capability miss retry = %s, want %s", next.Sub(now), styxPhase2RetryInterval)
	}
	if degraded, reason := engine.degradedState(); degraded {
		t.Fatalf("missing ingress capability degraded the platform: %s", reason)
	}
	snapshot := engine.state.Snapshot()
	infoEvents := 0
	for _, event := range snapshot.Events {
		if event.Kind == "styx.phase2_rx_capability_missing" {
			infoEvents++
			if event.Severity != "info" {
				t.Fatalf("capability fact recorded as %q, want info", event.Severity)
			}
		}
	}
	if infoEvents != 1 {
		t.Fatalf("capability-missing info event recorded %d times, want 1", infoEvents)
	}
	// The second poll must not duplicate the transition event.
	second := now.Add(styxPhase2RetryInterval)
	engine.pollStyxPhase2(RuntimeSettings{XDREnabled: true}, second, next)
	snapshot = engine.state.Snapshot()
	infoEvents = 0
	for _, event := range snapshot.Events {
		if event.Kind == "styx.phase2_rx_capability_missing" {
			infoEvents++
		}
	}
	if infoEvents != 1 {
		t.Fatalf("capability-missing info event repeated: %d", infoEvents)
	}
	report := engine.StyxPhase2Report()
	if report.RxObservation != "unknown" || report.Limitation == "" {
		t.Fatalf("missing capability report = %+v", report)
	}
}

func TestStyxPhase2RxAttachedExposesBeaconCapabilityAdditively(t *testing.T) {
	engine := styxPhase2TestEngine()
	engine.styxBeacon = NewStyxBeaconEngine(StyxBeaconConfig{
		Enabled: true, Mode: StyxModeMonitor, FlowCapabilityKnown: true,
	}, nil, nil)
	engine.styxPhase2.rxStatusQuery = func() (CoreStyxIngressStatus, error) {
		return CoreStyxIngressStatus{Attached: true, RxEvents: 7, ReadFailures: 2}, nil
	}
	now := time.Date(2026, 11, 24, 12, 0, 0, 0, time.UTC)
	next := engine.pollStyxPhase2(RuntimeSettings{XDREnabled: true}, now, time.Time{})
	if next.Sub(now) != styxPhase2PollInterval {
		t.Fatalf("attached poll interval = %s, want %s", next.Sub(now), styxPhase2PollInterval)
	}
	engine.styxBeacon.mu.Lock()
	capability := engine.styxBeacon.cfg.RxObservationCapability
	phaseOneGate := engine.styxBeacon.cfg.RxObservationAvailable
	engine.styxBeacon.mu.Unlock()
	if !capability {
		t.Fatalf("beacon RX capability was not projected")
	}
	if phaseOneGate {
		t.Fatalf("phase-1 RxObservationAvailable gate was weakened by the capability fact")
	}
	beaconSnapshot := engine.styxBeacon.Snapshot()
	if beaconSnapshot.RxObservation != "available" {
		t.Fatalf("beacon snapshot RX observation = %q, want available", beaconSnapshot.RxObservation)
	}
	report := engine.StyxPhase2Report()
	if report.RxObservation != "available" || report.RxEvents != 7 || report.RxReadFailures != 2 {
		t.Fatalf("attached capability report = %+v", report)
	}
}

// ---------------------------------------------------------------------------
// Bounds
// ---------------------------------------------------------------------------

func TestStyxPhase2MapsStayBounded(t *testing.T) {
	now := time.Date(2026, 11, 24, 12, 0, 0, 0, time.UTC)
	engine := NewStyxPhase2Engine()
	const entities = styxPhase2MaxEntities + 128
	for start := 0; start < entities; start += 16 {
		end := start + 16
		if end > entities {
			end = entities
		}
		batch := make([]CoreStyxFlowEvent, 0, end-start)
		for index := start; index < end; index++ {
			// 198.18.0.0/15 is the RFC 2544 benchmark range: external, unique and
			// clearly not one of the harness's own addresses.
			remote := netip.AddrFrom4([4]byte{198, 18, byte(index >> 8), byte(index)})
			batch = append(batch, styxPhase2TestEvent(
				uint64(index+1), index+1, 512, 0, 1, remote.String(), 443, 40000, 4, 6, 1,
			))
		}
		engine.observeBatch(batch, now)
	}
	engine.mu.Lock()
	entityCount := len(engine.entities)
	rxIndexCount := len(engine.rxIndex)
	endpointCount := len(engine.endpoints)
	firstSeenCount := len(engine.firstSeen)
	engine.mu.Unlock()
	if entityCount > styxPhase2MaxEntities {
		t.Fatalf("entity map grew to %d, bound %d", entityCount, styxPhase2MaxEntities)
	}
	if rxIndexCount > styxPhase2MaxEntities {
		t.Fatalf("rx index grew to %d, bound %d", rxIndexCount, styxPhase2MaxEntities)
	}
	if endpointCount > styxPhase2MaxEntities {
		t.Fatalf("endpoint index grew to %d, bound %d", endpointCount, styxPhase2MaxEntities)
	}
	if firstSeenCount > styxPhase2MaxFirstSeen {
		t.Fatalf("first-seen set grew to %d, bound %d", firstSeenCount, styxPhase2MaxFirstSeen)
	}
	// Tiny flows never qualify: bounded eviction is not a detection source.
	if got := styxPhase2IncidentCount(engine, now); got != 0 {
		t.Fatalf("evicted tiny flows produced %d incidents", got)
	}
}

func TestStyxPhase2ReportIsBounded(t *testing.T) {
	now := time.Date(2026, 11, 24, 12, 0, 0, 0, time.UTC)
	engine := NewStyxPhase2Engine()
	styxPhase2EnableRx(engine)
	for index := 0; index < 128; index++ {
		remote := netip.AddrFrom4([4]byte{198, 19, 0, byte(index)})
		engine.observeBatch([]CoreStyxFlowEvent{
			styxPhase2TestEvent(uint64(index+1), index+1, 1<<20, 0, 32, remote.String(), 443, 40000, 4, 6, 1),
			styxPhase2TestEvent(uint64(index+1), 0, 0, 64<<10, 8, remote.String(), 443, 40000, 4, 6, 2),
		}, now)
	}
	report := engine.report(now)
	if len(report.Entities) > styxPhase2MaxReportEntities {
		t.Fatalf("report carries %d entities, bound %d", len(report.Entities), styxPhase2MaxReportEntities)
	}
	if report.EntityCount != 128 {
		t.Fatalf("report entity count = %d, want 128", report.EntityCount)
	}
	if report.RxObservation != "available" || report.CorrelationQuality != "OBSERVED" {
		t.Fatalf("report capability projection = %+v", report)
	}
}

// ---------------------------------------------------------------------------
// STYX_INGRESS_STATUS parser
// ---------------------------------------------------------------------------

func TestStyxIngressStatusParserAcceptsTheExactWire(t *testing.T) {
	status, err := parseCoreStyxIngressStatus("attached=1:rx_events=18446744073709551615:read_failures=3")
	if err != nil {
		t.Fatalf("valid status rejected: %v", err)
	}
	if !status.Attached || status.RxEvents != ^uint64(0) || status.ReadFailures != 3 {
		t.Fatalf("decoded status = %+v", status)
	}
	detached, err := parseCoreStyxIngressStatus("attached=0:rx_events=0:read_failures=0")
	if err != nil {
		t.Fatalf("valid detached status rejected: %v", err)
	}
	if detached.Attached || detached.RxEvents != 0 || detached.ReadFailures != 0 {
		t.Fatalf("decoded detached status = %+v", detached)
	}
}

func TestStyxIngressStatusParserRejectsHostileInput(t *testing.T) {
	hostile := []string{
		"",
		"attached=0",
		"attached=0:rx_events=0",
		"attached=0:rx_events=0:read_failures=0:extra=1",
		"attached=0:read_failures=0:rx_events=0",                    // wrong order
		"attached=2:rx_events=0:read_failures=0",                    // out-of-range flag
		"attached=0:rx_events=-1:read_failures=3",                   // sign
		"attached=0:rx_events=0:read_failures=18446744073709551616", // u64 overflow
		"attached=0:rx_events=0:read_failures= 0",                   // space
		"attached=0:rx_events=0:read_failures=0 ",
		" attached=0:rx_events=0:read_failures=0",
		"attached=0:rx_events=0x10:read_failures=0", // hex
		"attached=0:rx_events=0:read_failures=0\x00",
		"attached=0:rx_events=0:read_failures=0:" + strings.Repeat("0", 200),
	}
	for index, response := range hostile {
		if _, err := parseCoreStyxIngressStatus(response); err == nil {
			t.Fatalf("hostile status fixture %d was accepted: %q", index, response)
		}
	}
}

func TestStyxIngressStatusNilClientIsCapabilityFact(t *testing.T) {
	var client *CoreClient
	if _, err := client.StyxIngressStatus(); !errors.Is(err, ErrStyxIngressUnavailable) {
		t.Fatalf("nil client error = %v, want ErrStyxIngressUnavailable", err)
	}
}
