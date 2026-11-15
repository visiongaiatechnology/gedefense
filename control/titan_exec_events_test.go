// STATUS: DIAMANT VGT SUPREME
package main

// POINT 1 / P1-T5 parser and XDR-integration tests: the §3.3 text wire, the
// §3.2 reject matrix, all-or-nothing batches, the bounded history/overflow
// contract and the kernel-decision -> evidence -> incident path of §7.4.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------- fixtures

// titanExecValidRecord is one bprm audit record in canonical §3.3 form.
func titanExecValidRecord() []string {
	return []string{
		"12345", "1700000000000000000", "64768", "33188", "4242", "7",
		"321", "321", "1000", "1000", "0", "0", "1", "1", "0", "62617368",
	}
}

// titanExecMmapAuditRecord is a valid executable mmap audit record (PROT_EXEC|WRITE, reason WX).
func titanExecMmapAuditRecord() []string {
	return []string{
		"99", "1700000001000000000", "64768", "33261", "77", "0",
		"4194000", "4194000", "0", "0", "5", "0", "2", "1", "5", "",
	}
}

func titanExecDenyRecord(pid string) []string {
	return []string{
		"12345", "1700000002000000000", "64768", "33188", "88", "0",
		pid, pid, "0", "0", "0", "0", "1", "2", "4", "7472757374",
	}
}

func titanExecJoin(record []string) string { return strings.Join(record, ":") }

func titanExecBatch(records ...[]string) string {
	parts := make([]string, 0, len(records))
	for _, record := range records {
		parts = append(parts, titanExecJoin(record))
	}
	return "0|" + strings.Join(parts, ",")
}

func titanExecRecordWith(mutate func(fields []string)) string {
	fields := titanExecValidRecord()
	mutate(fields)
	return "0|" + titanExecJoin(fields)
}

// titanExecTestSettingsStore persists one revision with the TitanExec namespace
// enabled in observe mode (or the upgrade default) and never touches the kernel.
func titanExecTestSettingsStore(t *testing.T, enabled bool) *SettingsStore {
	t.Helper()
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "runtime.key")
	if err := os.WriteFile(keyPath, make([]byte, 32), 0o600); err != nil {
		t.Fatal(err)
	}
	store, err := NewSettingsStore(filepath.Join(dir, "runtime.json"), keyPath, func() Config {
		cfg := defaultConfig()
		// The settings store authenticates with the explicit key path; the host
		// storage-master-key path must not leak into a unit test environment.
		cfg.Runtime.StorageKeyFile = ""
		return cfg
	}())
	if err != nil {
		t.Fatalf("titan exec test settings store: %v", err)
	}
	current := store.Get()
	namespace := defaultTitanExecFabricSettings()
	if enabled {
		namespace.Enabled = true
		namespace.Mode = TitanExecModeObserve
	}
	current.TitanExec = &namespace
	if _, err := store.Update(current); err != nil {
		t.Fatalf("persist titan exec test settings: %v", err)
	}
	return store
}

// newTitanExecTestEngine builds the minimal honest engine the ingestion path
// needs. No constructor, no collectors: the tests drive the drain directly.
func newTitanExecTestEngine(t *testing.T, enabled bool) (*XDREngine, *State) {
	t.Helper()
	state := NewState("test", defaultConfig())
	engine := &XDREngine{
		state: state, correlator: NewIncidentCorrelator(0), core: &CoreClient{},
		dedupe: map[string]time.Time{}, degradeCauses: map[string]string{}, forensicFailures: map[string]int{},
		titanExecCapability: titanExecCapabilityUnknown,
	}
	if enabled {
		engine.settings = titanExecTestSettingsStore(t, true)
	}
	return engine, state
}

func countTitanExecEvents(events []Event, kind string) int {
	count := 0
	for _, event := range events {
		if event.Kind == kind {
			count++
		}
	}
	return count
}

// ------------------------------------------------------------------ parser

func TestParseCoreTitanExecEventsAcceptsValidWire(t *testing.T) {
	events, dropped, err := parseCoreTitanExecEvents(titanExecBatch(titanExecValidRecord(), titanExecMmapAuditRecord()))
	if err != nil || dropped != 0 || len(events) != 2 {
		t.Fatalf("valid wire rejected: events=%d dropped=%d err=%v", len(events), dropped, err)
	}
	first := events[0]
	if first.CgroupID != 12345 || first.TsNS != 1700000000000000000 || first.Dev != 64768 ||
		first.InodeMode != 33188 || first.Ino != 4242 || first.Generation != 7 ||
		first.PID != 321 || first.TGID != 321 || first.UID != 1000 || first.GID != 1000 ||
		first.Prot != 0 || first.FFlags != 0 || first.Hook != titanExecHookBprm ||
		first.Action != titanExecActionAudit || first.Reason != 0 || first.Comm != "bash" {
		t.Fatalf("decoded record does not match the wire: %+v", first)
	}
	second := events[1]
	if second.Hook != titanExecHookMmap || second.Action != titanExecActionAudit || second.Prot != 5 ||
		second.Reason != titanExecReasonWX || second.Comm != "" {
		t.Fatalf("decoded mmap record does not match the wire: %+v", second)
	}
	if droppedOnly, dropped, err := parseCoreTitanExecEvents("3|"); err != nil || len(droppedOnly) != 0 || dropped != 3 {
		t.Fatalf("loss-only batch rejected: events=%d dropped=%d err=%v", len(droppedOnly), dropped, err)
	}
	if events, dropped, err := parseCoreTitanExecEvents("empty"); err != nil || len(events) != 0 || dropped != 0 {
		t.Fatalf("empty batch rejected: %v", err)
	}
}

func TestParseCoreTitanExecEventsAcceptsIdentityExceptions(t *testing.T) {
	readFailure := titanExecValidRecord()
	readFailure[2], readFailure[4], readFailure[14] = "0", "0", "7" // dev, ino, reason READ_FAILURE
	if _, dropped, err := parseCoreTitanExecEvents("0|" + titanExecJoin(readFailure)); err != nil || dropped != 0 {
		t.Fatalf("read-failure audit identity exception rejected: %v", err)
	}
	anonymous := titanExecMmapAuditRecord()
	anonymous[2], anonymous[4] = "0", "0" // no file, no inode
	anonymous[14] = "6"                   // ANON_NO_JIT
	if _, _, err := parseCoreTitanExecEvents("0|" + titanExecJoin(anonymous)); err != nil {
		t.Fatalf("anonymous executable mmap identity exception rejected: %v", err)
	}
}

func TestParseCoreTitanExecEventsAcceptsRawKernelComm(t *testing.T) {
	cases := []struct {
		name string
		hex  string
		want string
	}{
		{"non-UTF8 bytes", "fffe4142", "??AB"},
		{"control byte", "410a42", "A?B"},
		{"trailing NUL padding", "41420000", "AB"},
		{"space is printable", "57656220436f6e74656e74", "Web Content"},
		{"printable UTF-8", "c3a4", "ä"},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			record := titanExecValidRecord()
			record[15] = testCase.hex
			events, dropped, err := parseCoreTitanExecEvents("0|" + titanExecJoin(record))
			if err != nil || dropped != 0 || len(events) != 1 {
				t.Fatalf("raw kernel comm rejected: events=%d dropped=%d err=%v", len(events), dropped, err)
			}
			if got := events[0].Comm; got != testCase.want {
				t.Fatalf("comm sanitised to %q, want %q", got, testCase.want)
			}
		})
	}
}

func TestParseCoreTitanExecEventsRejectsHostileBatches(t *testing.T) {
	nineRecords := make([]string, 0, 9)
	for index := 0; index < 9; index++ {
		record := titanExecValidRecord()
		record[6] = "100" + string(rune('0'+index))
		nineRecords = append(nineRecords, titanExecJoin(record))
	}
	hugeComm := strings.Repeat("61", 17)
	cases := []struct {
		name    string
		payload string
	}{
		{"empty payload", ""},
		{"oversized payload", strings.Repeat("A", titanExecMaxEventsPayloadBytes+1)},
		{"missing separator", "0"},
		{"empty dropped counter", "|" + titanExecJoin(titanExecValidRecord())},
		{"non-decimal dropped counter", "x|" + titanExecJoin(titanExecValidRecord())},
		{"negative dropped counter", "-1|" + titanExecJoin(titanExecValidRecord())},
		{"leading-zero dropped counter", "01|" + titanExecJoin(titanExecValidRecord())},
		{"empty batch with zero drops", "0|"},
		{"trailing whitespace", "empty "},
		{"embedded NUL", "empty\x00"},
		{"nine records", "0|" + strings.Join(nineRecords, ",")},
		{"fifteen fields", "0|" + titanExecJoin(titanExecValidRecord()[:15])},
		{"seventeen fields", "0|" + titanExecJoin(append(titanExecValidRecord(), "1"))},
		{"non-decimal field", titanExecRecordWith(func(fields []string) { fields[0] = "1x" })},
		{"leading-zero field", titanExecRecordWith(func(fields []string) { fields[2] = "064768" })},
		{"out-of-range dev", titanExecRecordWith(func(fields []string) { fields[2] = "4294967296" })},
		{"invalid hook", titanExecRecordWith(func(fields []string) { fields[12] = "3" })},
		{"invalid action", titanExecRecordWith(func(fields []string) { fields[13] = "3" })},
		{"reason out of range", titanExecRecordWith(func(fields []string) { fields[14] = "11" })},
		{"zero pid", titanExecRecordWith(func(fields []string) { fields[6] = "0" })},
		{"zero timestamp", titanExecRecordWith(func(fields []string) { fields[1] = "0" })},
		{"mmap without protection", "0|" + titanExecJoin(func() []string {
			record := titanExecMmapAuditRecord()
			record[10] = "0"
			return record
		}())},
		{"deny without ground", titanExecRecordWith(func(fields []string) { fields[13] = "2"; fields[14] = "0" })},
		{"deny as read failure", titanExecRecordWith(func(fields []string) { fields[13] = "2"; fields[14] = "7" })},
		{"half-null identity", titanExecRecordWith(func(fields []string) { fields[2] = "0" })},
		{"null identity outside exceptions", titanExecRecordWith(func(fields []string) {
			fields[2], fields[4], fields[14] = "0", "0", "2"
		})},
		{"non-zero comm padding", titanExecRecordWith(func(fields []string) { fields[15] = "410042" })},
		{"odd comm hex", titanExecRecordWith(func(fields []string) { fields[15] = "abc" })},
		{"non-hex comm", titanExecRecordWith(func(fields []string) { fields[15] = "zz" })},
		{"oversized comm", titanExecRecordWith(func(fields []string) { fields[15] = hugeComm })},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			events, dropped, err := parseCoreTitanExecEvents(testCase.payload)
			if err == nil {
				t.Fatalf("hostile batch accepted: %q", testCase.payload)
			}
			if events != nil || dropped != 0 {
				t.Fatalf("rejected batch returned partial state: events=%d dropped=%d", len(events), dropped)
			}
		})
	}
}

func TestParseCoreTitanExecEventsIsAllOrNothing(t *testing.T) {
	valid := titanExecValidRecord()
	invalid := titanExecValidRecord()
	invalid[6] = "0" // pid zero
	payload := "7|" + titanExecJoin(valid) + "," + titanExecJoin(invalid)
	events, dropped, err := parseCoreTitanExecEvents(payload)
	if err == nil || events != nil || dropped != 0 {
		t.Fatalf("mixed batch did not reject atomically: events=%d dropped=%d err=%v", len(events), dropped, err)
	}
}

// ------------------------------------------------------------ XDR integration

func TestTitanExecXDRIntegrationRecordsEvidenceBackedIncident(t *testing.T) {
	engine, state := newTitanExecTestEngine(t, true)
	ledger, _ := evidenceFixture(t)
	if err := state.AttachEvidenceLedger(ledger); err != nil {
		t.Fatal(err)
	}
	state.SetModes("enforcement", "enforce")
	now := time.Now().UTC()
	payload := titanExecBatch(titanExecDenyRecord("4194000"))
	if delay := engine.consumeTitanExecDrain(payload, nil, now); delay != titanExecDrainInterval {
		t.Fatalf("enabled clean drain returned %s, want %s", delay, titanExecDrainInterval)
	}
	incidents := state.Snapshot().Incidents
	if len(incidents) != 1 {
		t.Fatalf("expected exactly one exec-gate incident, got %d: %+v", len(incidents), incidents)
	}
	incident := incidents[0]
	if len(incident.RuleIDs) != 1 || incident.RuleIDs[0] != "TITAN.EXEC_DENIED" {
		t.Fatalf("incident rule ids are wrong: %+v", incident.RuleIDs)
	}
	if incident.CellCgroupID != 12345 {
		t.Fatalf("incident carries no cell cgroup, CellGuard could not act: %+v", incident)
	}
	if incident.Decision != "deny-exec" || incident.Action != "deny" {
		t.Fatalf("a kernel deny was not reported as deny-exec: %+v", incident)
	}
	if !strings.Contains(incident.Outcome, "blocked by kernel BPF-LSM") ||
		strings.Contains(incident.Outcome, "frozen") {
		t.Fatalf("the outcome does not name the kernel enforcement honestly: %q", incident.Outcome)
	}
	if incident.Executable != "" || !strings.Contains(incident.Summary, "path=unknown") {
		t.Fatalf("unresolvable path was invented instead of reported unknown: %+v", incident)
	}
	// Evidence first: the mandatory record exists and was committed before the
	// response decision evidence written by the existing respond() path. Recent()
	// returns newest first, so the kernel evidence must carry the lower sequence.
	titanEvidenceSequence, responseIntentSequence := uint64(0), uint64(0)
	for _, record := range ledger.Recent(50) {
		switch record.Kind {
		case "titan.exec.denied":
			if titanEvidenceSequence == 0 {
				titanEvidenceSequence = record.Sequence
			}
		case "xdr.response.intent":
			if responseIntentSequence == 0 {
				responseIntentSequence = record.Sequence
			}
		}
	}
	if titanEvidenceSequence == 0 {
		t.Fatal("no mandatory evidence record was written for the kernel deny")
	}
	if responseIntentSequence != 0 && responseIntentSequence < titanEvidenceSequence {
		t.Fatal("response evidence was written before the kernel-decision evidence")
	}
	// Dedupe: the same kernel decision drained twice stays exactly one incident
	// (and exactly one piece of mandatory evidence - the ledger budget must not be
	// fillable by replaying one kernel denial).
	engine.consumeTitanExecDrain(payload, nil, now)
	if got := len(state.Snapshot().Incidents); got != 1 {
		t.Fatalf("dedupe failed, incident count grew to %d", got)
	}
	deniedEvidence := 0
	for _, record := range ledger.Recent(50) {
		if record.Kind == "titan.exec.denied" {
			deniedEvidence++
		}
	}
	if deniedEvidence != 1 {
		t.Fatalf("a replayed kernel decision produced %d evidence records", deniedEvidence)
	}
	counters := engine.TitanExecEventsReport(titanExecEventHistoryLimit).Counters
	if counters.EventsTotal != 2 || counters.Incidents != 1 || counters.Denies != 2 {
		t.Fatalf("ingestion counters are wrong: %+v", counters)
	}
}

func TestTitanExecXDRDegradedAndObserveDoNotRespond(t *testing.T) {
	observeEngine, observeState := newTitanExecTestEngine(t, true)
	observeLedger, _ := evidenceFixture(t)
	if err := observeState.AttachEvidenceLedger(observeLedger); err != nil {
		t.Fatal(err)
	}
	observeState.SetModes("enforcement", "observe")
	observeEngine.consumeTitanExecDrain(titanExecBatch(titanExecDenyRecord("4194001")), nil, time.Now().UTC())
	observed := observeState.Snapshot().Incidents
	if len(observed) != 1 || observed[0].Action != "deny" ||
		!strings.Contains(observed[0].Outcome, "kernel-side enforcement") {
		t.Fatalf("observe mode did not keep the kernel fact while pausing the response: %+v", observed)
	}
	if hasEvidenceKind(observeLedger.Recent(50), "xdr.response.intent") {
		t.Fatal("observe mode reached the active response path")
	}

	degradedEngine, degradedState := newTitanExecTestEngine(t, true)
	degradedLedger, _ := evidenceFixture(t)
	if err := degradedState.AttachEvidenceLedger(degradedLedger); err != nil {
		t.Fatal(err)
	}
	degradedState.SetModes("enforcement", "enforce")
	degradedEngine.markDegradedCause("test", "simulated degradation")
	degradedEngine.consumeTitanExecDrain(titanExecBatch(titanExecDenyRecord("4194002")), nil, time.Now().UTC())
	degradedIncidents := degradedState.Snapshot().Incidents
	if len(degradedIncidents) != 1 || degradedIncidents[0].Action != "deny" {
		t.Fatalf("degraded XDR must still record the kernel decision: %+v", degradedIncidents)
	}
	if hasEvidenceKind(degradedLedger.Recent(50), "xdr.response.intent") {
		t.Fatal("degraded XDR reached the active response path")
	}
}

func TestTitanExecAuditEventIsHonestAndUnblocked(t *testing.T) {
	engine, state := newTitanExecTestEngine(t, true)
	state.SetModes("enforcement", "enforce")
	ledger, _ := evidenceFixture(t)
	if err := state.AttachEvidenceLedger(ledger); err != nil {
		t.Fatal(err)
	}
	engine.consumeTitanExecDrain(titanExecBatch(titanExecMmapAuditRecord()), nil, time.Now().UTC())
	incidents := state.Snapshot().Incidents
	if len(incidents) != 1 {
		t.Fatalf("expected one audit incident, got %d", len(incidents))
	}
	incident := incidents[0]
	if incident.RuleIDs[0] != "TITAN.EXEC_AUDIT" || incident.Decision != "audit" || incident.Action != "none" {
		t.Fatalf("audit record claims a block it cannot prove: %+v", incident)
	}
	if !strings.Contains(incident.Outcome, "audited, not blocked") {
		t.Fatalf("audit outcome is not honest: %q", incident.Outcome)
	}
	if hasEvidenceKind(ledger.Recent(50), "xdr.response.intent") {
		t.Fatal("an audit-only decision reached the active response path")
	}
}

func TestTitanExecHostileCommDoesNotSuppressBatch(t *testing.T) {
	engine, state := newTitanExecTestEngine(t, true)
	ledger, _ := evidenceFixture(t)
	if err := state.AttachEvidenceLedger(ledger); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	hostile := titanExecDenyRecord("4194010")
	// PR_SET_NAME can carry any byte except NUL; the kernel and the Rust decoder
	// accept it, so the whole batch must survive and the bytes are only rendered
	// as '?' on the operator surface.
	hostile[15] = "fffe4142"
	plain := titanExecDenyRecord("4194011")
	if delay := engine.consumeTitanExecDrain(titanExecBatch(hostile, plain), nil, now); delay != titanExecDrainInterval {
		t.Fatalf("a hostile comm rejected the batch and backed off: %s", delay)
	}
	incidents := state.Snapshot().Incidents
	if len(incidents) != 2 {
		t.Fatalf("batch with a hostile comm produced %d incidents, want 2", len(incidents))
	}
	processByPID := map[int]string{}
	for _, incident := range incidents {
		processByPID[incident.PID] = incident.Process
	}
	if got := processByPID[4194010]; got != "??AB" {
		t.Fatalf("hostile comm was not sanitised for display: %q", got)
	}
	if got := processByPID[4194011]; got != "trust" {
		t.Fatalf("valid ASCII comm changed: %q", got)
	}
	counters := engine.TitanExecEventsReport(titanExecEventHistoryLimit).Counters
	if counters.EventsTotal != 2 || counters.Incidents != 2 || counters.ParseErrors != 0 || counters.Dropped != 0 {
		t.Fatalf("hostile comm corrupted the ingestion counters: %+v", counters)
	}
	if degraded, reason := engine.degradedState(); degraded {
		t.Fatalf("a hostile comm degraded the sensor: %s", reason)
	}
	deniedEvidence := 0
	for _, record := range ledger.Recent(50) {
		if record.Kind == "titan.exec.denied" {
			deniedEvidence++
		}
	}
	if deniedEvidence != 2 {
		t.Fatalf("hostile comm suppressed evidence: %d records, want 2", deniedEvidence)
	}
}

func TestTitanExecOverflowRepeatsThenDegradesAndRecovers(t *testing.T) {
	engine, state := newTitanExecTestEngine(t, true)
	now := time.Now().UTC()
	engine.consumeTitanExecDrain("5|", nil, now)
	if degraded, _ := engine.degradedState(); degraded {
		t.Fatal("a single overflow already degraded XDR")
	}
	engine.consumeTitanExecDrain("5|", nil, now)
	snapshot := state.Snapshot()
	if degraded, _ := engine.degradedState(); !degraded {
		t.Fatal("a repeated overflow did not degrade the sensor")
	}
	if got := countTitanExecEvents(snapshot.Events, "xdr.titan_exec_overflow"); got != 1 {
		t.Fatalf("overflow must be reported once per series, got %d", got)
	}
	if got := countTitanExecEvents(snapshot.Events, "xdr.titan_exec_sensor_degraded"); got != 1 {
		t.Fatalf("sensor degradation must be reported once, got %d", got)
	}
	for _, event := range snapshot.Events {
		if event.Kind == "xdr.titan_exec_overflow" && !strings.Contains(event.Message, "does not claim") {
			t.Fatalf("overflow event claims more than it can prove: %q", event.Message)
		}
	}
	if counters := engine.TitanExecEventsReport(titanExecEventHistoryLimit).Counters; counters.Dropped != 10 {
		t.Fatalf("dropped counter is wrong: %+v", counters)
	}
	if delay := engine.consumeTitanExecDrain("empty", nil, now); delay != titanExecDrainInterval {
		t.Fatalf("clean drain after overflow returned %s", delay)
	}
	if degraded, _ := engine.degradedState(); degraded {
		t.Fatal("a clean drain did not clear the ingestion degradation")
	}
	if got := countTitanExecEvents(state.Snapshot().Events, "xdr.titan_exec_sensor_recovered"); got != 1 {
		t.Fatalf("sensor recovery was not reported exactly once, got %d", got)
	}
}

// ------------------------------------------------- capability / size bounds

func hasEvidenceKind(records []EvidenceRecord, kind string) bool {
	for _, record := range records {
		if record.Kind == kind {
			return true
		}
	}
	return false
}
