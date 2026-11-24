// STATUS: V6.3.0 AP-6
package main

// V6.3.0 AP-6 regression tests for the SBC graph: default/clamped half-life,
// exact decay mathematics, bounded capacity with deterministic eviction,
// deterministic entity-key priority, bounded report ordering and pruning.

import (
	"fmt"
	"math"
	"strings"
	"testing"
	"time"
)

func TestSBCDefaultHalfLifeAndClamp(t *testing.T) {
	engine := NewSBCFusionEngine()
	if got := engine.HalfLifeMinutes(); got != 30 {
		t.Fatalf("default half-life is %v minutes, want 30", got)
	}
	if got := engine.SetHalfLife(time.Minute); got != 15*time.Minute {
		t.Fatalf("half-life was not clamped up to 15 minutes: %v", got)
	}
	if got := engine.HalfLifeMinutes(); got != 15 {
		t.Fatalf("half-life after clamp is %v, want 15", got)
	}
	if got := engine.SetHalfLife(6 * time.Hour); got != 60*time.Minute {
		t.Fatalf("half-life was not clamped down to 60 minutes: %v", got)
	}
	if got := engine.SetHalfLife(0); got != 30*time.Minute {
		t.Fatalf("zero half-life did not reset to the default: %v", got)
	}
	var missing *SBCFusionEngine
	if missing.HalfLifeMinutes() != 0 || missing.SetHalfLife(time.Hour) != 0 {
		t.Fatal("nil engine did not answer with zero values")
	}
}

func TestSBCHalfLifeDecayMath(t *testing.T) {
	base := sbcTestBaseTime()
	engine := NewSBCFusionEngine()
	incident := sbcTestIncident("i-1", "/opt/sbc/entity-bin", "XDR.TEMP_EXEC", "warning", base)
	if context := engine.observeIncident(incident, SBCFamilyProvenance, base); context != nil {
		t.Fatalf("first observation invented a prior context: %+v", context)
	}
	key := sbcEntityKey(incident)
	cases := []struct {
		age  time.Duration
		want float64
	}{
		{0, 1.0},
		{30 * time.Minute, 0.5},
		{60 * time.Minute, 0.25},
		{90 * time.Minute, 0.125},
	}
	for _, tc := range cases {
		snapshot, ok := engine.EntitySnapshot(key, base.Add(tc.age))
		if !ok {
			t.Fatalf("entity missing at age %v", tc.age)
		}
		if math.Abs(snapshot.DecayedScore-tc.want) > 1e-9 {
			t.Fatalf("decayed score at age %v is %v, want %v", tc.age, snapshot.DecayedScore, tc.want)
		}
	}
	// The second observation reads the decayed value *before* adding its own
	// weight: 1.0 weight decayed by 30 minutes is exactly 0.5.
	second := sbcTestIncident("i-2", "/opt/sbc/entity-bin", "XDR.THREAT_INTEL_C2", "warning", base.Add(30*time.Minute))
	context := engine.observeIncident(second, SBCFamilyC2, base.Add(30*time.Minute))
	if context == nil {
		t.Fatal("second observation lost the prior context")
	}
	if math.Abs(context.DecayedScore-0.5) > 1e-9 {
		t.Fatalf("prior context score is %v, want 0.5", context.DecayedScore)
	}
	if context.HalfLifeMinutes != 30 || context.Corroborations != 1 {
		t.Fatalf("context is %+v, want half-life 30 and one corroborating family", context)
	}
	if len(context.Families) != 1 || context.Families[0] != SBCFamilyProvenance {
		t.Fatalf("prior families are %v, want [%s]", context.Families, SBCFamilyProvenance)
	}
	// Configurable half-life: at 15 minutes with a 15 minute half-life the prior
	// weight is exactly halved.
	short := NewSBCFusionEngine()
	short.SetHalfLife(15 * time.Minute)
	short.observeIncident(incident, SBCFamilyProvenance, base)
	context = short.observeIncident(second, SBCFamilyC2, base.Add(15*time.Minute))
	if context == nil || math.Abs(context.DecayedScore-0.5) > 1e-9 {
		t.Fatalf("15 minute half-life context is %+v, want score 0.5", context)
	}
	if context.HalfLifeMinutes != 15 {
		t.Fatalf("context half-life is %v, want 15", context.HalfLifeMinutes)
	}
}

func TestSBCCapacityIsBoundedAndEvictionDeterministic(t *testing.T) {
	base := sbcTestBaseTime()
	engine := NewSBCFusionEngine()
	for i := 0; i < SBCCapacity+1; i++ {
		incident := sbcTestIncident(fmt.Sprintf("i-%d", i), fmt.Sprintf("/opt/sbc/bin-%d", i), "XDR.TEMP_EXEC", "warning", base)
		engine.observeIncident(incident, SBCFamilyProvenance, base)
	}
	report := engine.Report(base, 0)
	if report.Entities != SBCCapacity {
		t.Fatalf("entity graph holds %d entities, want the bound %d", report.Entities, SBCCapacity)
	}
	if report.Capacity != SBCCapacity {
		t.Fatalf("report capacity is %d, want %d", report.Capacity, SBCCapacity)
	}
	if report.Evictions != 1 {
		t.Fatalf("eviction count is %d, want 1", report.Evictions)
	}
	if report.Observations != uint64(SBCCapacity+1) {
		t.Fatalf("observation count is %d, want %d", report.Observations, SBCCapacity+1)
	}
	// The report projection itself is bounded.
	if len(report.Top) > sbcReportTopEntities {
		t.Fatalf("report projects %d entities, bound is %d", len(report.Top), sbcReportTopEntities)
	}
}

func TestSBCEntityKeyPriority(t *testing.T) {
	inodeIncident := XDRIncident{
		ID: "inode", Executable: "/opt/sbc/binary", PID: 42,
		AttackStory: []AttackStoryNode{{Metadata: map[string]string{"sbc_entity": "inode:8:123"}}},
	}
	if key := sbcEntityKey(inodeIncident); key != "meta:inode:8:123" {
		t.Fatalf("kernel identity metadata did not win: %q", key)
	}
	// Entity metadata from an earlier correlated finding must not become the
	// identity of the current one (the producer appends its own node last).
	priorChainIncident := XDRIncident{
		ID: "prior-chain", Executable: "/opt/sbc/current", PID: 42,
		AttackStory: []AttackStoryNode{
			{Metadata: map[string]string{"sbc_entity": "inode:8:999"}},
			{},
		},
	}
	if key, want := sbcEntityKey(priorChainIncident), "exe:"+sbcHashIdentity("/opt/sbc/current"); key != want {
		t.Fatalf("prior chain identity was used: %q, want %q", key, want)
	}
	executableIncident := XDRIncident{ID: "exe", Executable: "/opt/sbc/binary", PID: 42}
	if key := sbcEntityKey(executableIncident); !strings.HasPrefix(key, "exe:") {
		t.Fatalf("executable path hash priority failed: %q", key)
	}
	if got, want := sbcEntityKey(executableIncident), "exe:"+sbcHashIdentity("/opt/sbc/binary"); got != want {
		t.Fatalf("executable key is %q, want %q", got, want)
	}
	// The kernel's deleted-file marker must not split one binary into two entities.
	deleted := XDRIncident{ID: "deleted", Executable: "/opt/sbc/binary (deleted)"}
	if sbcEntityKey(deleted) != sbcEntityKey(executableIncident) {
		t.Fatal("deleted-file marker changed the entity identity")
	}
	processIncident := XDRIncident{ID: "proc", PID: 42, UID: 1000, StartTicks: 7}
	if key := sbcEntityKey(processIncident); key != "proc:42:1000:7" {
		t.Fatalf("process identity key is %q", key)
	}
	remoteIncident := XDRIncident{ID: "net", Remote: "203.0.113.9"}
	if key := sbcEntityKey(remoteIncident); key != "net:"+sbcHashIdentity("203.0.113.9") {
		t.Fatalf("remote identity key is %q", key)
	}
	chainIncident := XDRIncident{ID: "chain", EvidenceRoot: "chain-digest"}
	if key := sbcEntityKey(chainIncident); key != "evid:"+sbcHashIdentity("chain-digest") {
		t.Fatalf("evidence-root identity key is %q", key)
	}
	anonymous := XDRIncident{ID: "anonymous"}
	if key := sbcEntityKey(anonymous); key != "anon:anonymous" {
		t.Fatalf("anonymous identity key is %q", key)
	}
	// An incident without an id must not share a key with every other id-less
	// incident: the observation time, then the rule id, keep it distinct.
	timed := XDRIncident{Time: sbcTestBaseTime(), RuleIDs: []string{"XDR.TEMP_EXEC"}}
	if key := sbcEntityKey(timed); key != "anon:"+sbcTestBaseTime().UTC().Format(time.RFC3339Nano) {
		t.Fatalf("time-based anonymous key is %q", key)
	}
	untimed := XDRIncident{RuleIDs: []string{"XDR.TEMP_EXEC"}}
	if key := sbcEntityKey(untimed); key != "anon:rule:XDR.TEMP_EXEC" {
		t.Fatalf("rule-based anonymous key is %q", key)
	}
	// An entity identity never leaks a raw executable path.
	if strings.Contains(sbcEntityKey(executableIncident), "/opt/sbc/binary") {
		t.Fatal("entity key contains the raw executable path")
	}
}

func TestSBCReportIsBoundedAndDeterministicallyOrdered(t *testing.T) {
	engine := NewSBCFusionEngine()
	base := sbcTestBaseTime()
	add := func(executable, ruleID, severity string, at time.Time) {
		incident := sbcTestIncident("", executable, ruleID, severity, at)
		engine.observeIncident(incident, sbcBoundedFamilyForRule(ruleID), at)
	}
	// Six observations spread over three entities with distinct weights.
	for i := 0; i < 3; i++ {
		add("/opt/sbc/alpha", "XDR.CREDENTIAL_READ_BLOCKED", "critical", base)
	}
	add("/opt/sbc/beta", "XDR.TEMP_EXEC", "warning", base)
	add("/opt/sbc/gamma", "XDR.WORKER_CRASH_STORM", "high", base)
	add("/opt/sbc/gamma", "XDR.WORKER_CRASH_STORM", "high", base)

	report := engine.Report(base, sbcReportTopEntities)
	if got, want := report.Entities, 3; got != want {
		t.Fatalf("entities is %d, want %d", got, want)
	}
	if len(report.Top) != 3 {
		t.Fatalf("top projection has %d entries, want 3", len(report.Top))
	}
	wantScores := []float64{6.0, 3.0, 1.0} // alpha 3x critical, gamma 2x high, beta 1x warning
	for i, want := range wantScores {
		if math.Abs(report.Top[i].DecayedScore-want) > 1e-9 {
			t.Fatalf("top[%d] score is %v, want %v", i, report.Top[i].DecayedScore, want)
		}
	}
	if report.Top[0].Entity != "exe:"+sbcHashIdentity("/opt/sbc/alpha") {
		t.Fatalf("top entity is %q", report.Top[0].Entity)
	}
	// Family lists are sorted, never map order.
	multi := NewSBCFusionEngine()
	for _, ruleID := range []string{"XDR.TEMP_EXEC", "XDR.CREDENTIAL_READ_BLOCKED", "XDR.THREAT_INTEL_C2"} {
		incident := sbcTestIncident("", "/opt/sbc/multi", ruleID, "warning", base)
		multi.observeIncident(incident, sbcBoundedFamilyForRule(ruleID), base)
	}
	context := multi.observeIncident(sbcTestIncident("", "/opt/sbc/multi", "XDR.TEMP_EXEC", "warning", base), SBCFamilyProvenance, base)
	if context == nil {
		t.Fatal("multi-family entity lost its context")
	}
	for i := 1; i < len(context.Families); i++ {
		if context.Families[i-1] > context.Families[i] {
			t.Fatalf("families are not sorted: %v", context.Families)
		}
	}
	for _, entity := range report.Top {
		for i := 1; i < len(entity.Families); i++ {
			if entity.Families[i-1] > entity.Families[i] {
				t.Fatalf("report families are not sorted: %v", entity.Families)
			}
		}
	}
}

func TestSBCReportUnavailableWithoutSeam(t *testing.T) {
	var nilEngine *XDREngine
	report := nilEngine.SBCFusionReport()
	if report.State != "unavailable" || report.Version != SBCFusionVersion {
		t.Fatalf("nil engine report is %+v", report)
	}
	unwired := &XDREngine{}
	if report := unwired.SBCFusionReport(); report.State != "unavailable" {
		t.Fatalf("engine without fusion reports %q", report.State)
	}
	fusedEngine, _ := newSBCTestEngine(t)
	report = fusedEngine.SBCFusionReport()
	if report.State != "active" || report.Version != SBCFusionVersion || report.Capacity != SBCCapacity {
		t.Fatalf("wired report is %+v", report)
	}
}

func TestSBCPruneDropsStaleEntities(t *testing.T) {
	engine := NewSBCFusionEngine()
	base := sbcTestBaseTime()
	incident := sbcTestIncident("stale", "/opt/sbc/stale", "XDR.TEMP_EXEC", "warning", base)
	engine.observeIncident(incident, SBCFamilyProvenance, base)
	key := sbcEntityKey(incident)
	if _, ok := engine.EntitySnapshot(key, base); !ok {
		t.Fatal("entity was not recorded")
	}
	// Four hours is eight 30-minute half-lives: the decayed weight 1/256 is
	// below the prune epsilon.
	staleAt := base.Add(4 * time.Hour)
	engine.mu.Lock()
	engine.pruneLocked(staleAt)
	engine.mu.Unlock()
	if _, ok := engine.EntitySnapshot(key, staleAt); ok {
		t.Fatal("stale entity survived pruning")
	}
	report := engine.Report(staleAt, 0)
	if report.Entities != 0 || report.Prunings == 0 {
		t.Fatalf("report after prune is %+v", report)
	}
}
