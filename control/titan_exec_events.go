// STATUS: DIAMANT VGT SUPREME
package main

// POINT 1 / P1-T5: the Titan exec-gate event text wire (§3.3), the bounded
// kernel-decision -> XDR bridge (§7.4) and the honest ingestion bookkeeping that
// feeds GET /api/v1/titan/exec/{status,events}.
//
// The kernel has already decided and enforced before any of this runs: a DENY
// record means the execve or the executable mmap was refused inside the LSM hook.
// Nothing here opens a second enforcement route - an event becomes mandatory
// evidence first, then a normal XDR incident whose CellCgroupID lets the existing
// CellGuard/response scanners act exactly as on every other incident.

import (
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const (
	// §3.3: one answer carries at most eight records and at most 2048 bytes. The
	// control plane enforces both independently: a buggy or hostile core must not
	// be able to force unbounded parsing work per poll.
	titanExecMaxEventsPerResponse  = 8
	titanExecMaxEventsPayloadBytes = 2048
	// titanExecEventHistoryLimit bounds the read-only event history behind the
	// API. The kernel wire is stateless, so this is the only replay an operator
	// gets; it is deliberately small and contains kernel facts only.
	titanExecEventHistoryLimit = 64

	// titanExecDedupeBucketNS collapses identical kernel decisions inside one
	// second. The wire has no start_ticks, so pid+identity+hook+action+time bucket
	// is the strongest stable fingerprint available (§7.4).
	titanExecDedupeBucketNS = uint64(time.Second)

	// Cadences of the poll inside the existing 100 ms XDR tick (§7.4). A healthy
	// drain runs once a second; every failure or capability fact backs off; the
	// kernel health counters are sampled every ten seconds.
	titanExecDrainInterval        = time.Second
	titanExecDrainBackoff         = 10 * time.Second
	titanExecHealthInterval       = 10 * time.Second
	titanExecOverflowEventSpacing = time.Minute

	// titanExecCapabilityAvailable is the negotiation result the drain records when
	// the core proved the TITAN_EXEC_* command family. "unknown" and "missing" are
	// shared with the syncer status vocabulary (titan_exec_syncer_status.go).
	titanExecCapabilityAvailable = "available"

	// titanExecSensorCause is the single degradation cause of this ingestion path.
	// A transient failure is journaled, a repeated one degrades XDR, and the next
	// clean poll clears it again (§8 "bei Wiederholung degraded nur für dieses Modul").
	titanExecSensorCause = "titan_exec_sensor"

	// §3.1 hook, action and reason values this control plane validates against.
	titanExecHookBprm uint8 = 1
	titanExecHookMmap uint8 = 2

	titanExecActionAudit uint8 = 1
	titanExecActionDeny  uint8 = 2

	titanExecReasonNone          uint8 = 0
	titanExecReasonUnlinked      uint8 = 1
	titanExecReasonTmpfs         uint8 = 2
	titanExecReasonMemfd         uint8 = 3
	titanExecReasonNotAllowlist  uint8 = 4
	titanExecReasonWX            uint8 = 5
	titanExecReasonAnonNoJit     uint8 = 6
	titanExecReasonReadFailure   uint8 = 7
	titanExecReasonStateNotRdy   uint8 = 8
	titanExecReasonCtimeMismatch uint8 = 9
	titanExecReasonFSHard        uint8 = 10
	titanExecReasonMax           uint8 = 13

	// PROT_EXEC from <linux/mman.h>; an anonymous executable mmap without the JIT
	// scope exception is the only null-identity mmap the producer can emit (§3.2).
	titanExecProtExec uint32 = 0x4

	// titanExecPathMaxBytes bounds the /proc/<pid>/exe enrichment. The path is
	// evidence decoration only; the policy identity stays (dev, ino).
	titanExecPathMaxBytes = 512
)

// CoreTitanExecEvent mirrors one decoded §3.3 record. All numeric fields are
// kernel facts carried through unchanged; only Comm is text (the producer's
// NUL-truncated task name). It is never serialized directly: the API view type
// carries exactly these bounded fields.
type CoreTitanExecEvent struct {
	CgroupID   uint64
	TsNS       uint64
	Dev        uint32
	InodeMode  uint32
	Ino        uint64
	Generation uint32
	PID        uint32
	TGID       uint32
	UID        uint32
	GID        uint32
	Prot       uint32
	FFlags     uint32
	Hook       uint8
	Action     uint8
	Reason     uint8
	Flags      uint8
	Comm       string
}

// titanExecEventCounters is the bounded ingestion projection reported by the API.
// It counts observations, not policy state: EventsTotal counts every decoded
// record (including duplicates collapsed by the incident dedupe) and Incidents
// counts evidence-backed incidents.
type titanExecEventCounters struct {
	EventsTotal uint64
	Denies      uint64
	Audits      uint64
	Dropped     uint64
	ParseErrors uint64
	Incidents   uint64
}

// parseCoreTitanExecEvents decodes the §3.3 text wire. It is all-or-nothing: one
// malformed record rejects the whole batch, so no caller can act on a partially
// parsed batch. It never panics and never returns partial state.
func parseCoreTitanExecEvents(payload string) (events []CoreTitanExecEvent, dropped uint64, err error) {
	if len(payload) == 0 || len(payload) > titanExecMaxEventsPayloadBytes {
		return nil, 0, errors.New("core returned an empty or oversized titan exec event batch")
	}
	if payload == "empty" {
		return nil, 0, nil
	}
	// The record grammar has no whitespace and no NUL; accepting either would blur
	// the boundary between fields and let a hostile core smuggle separators.
	if strings.TrimSpace(payload) != payload || strings.ContainsAny(payload, "\x00\r\n\t ") {
		return nil, 0, errors.New("core returned a malformed titan exec event batch")
	}
	droppedText, recordsText, ok := strings.Cut(payload, "|")
	if !ok {
		return nil, 0, errors.New("core returned a malformed titan exec event batch")
	}
	dropped, err = titanExecParseDecimal(droppedText, 64)
	if err != nil {
		return nil, 0, errors.New("core returned an invalid titan exec drop counter")
	}
	if recordsText == "" {
		// <dropped>| is the loss-only shape. Zero drops without a record is not a
		// producer output ("empty" is) and is rejected instead of repaired.
		if dropped == 0 {
			return nil, 0, errors.New("core returned a titan exec batch without records and without drops")
		}
		return nil, dropped, nil
	}
	records := strings.Split(recordsText, ",")
	if len(records) > titanExecMaxEventsPerResponse {
		return nil, 0, errors.New("core returned too many titan exec events")
	}
	events = make([]CoreTitanExecEvent, 0, len(records))
	for _, record := range records {
		event, recordErr := parseCoreTitanExecEvent(record)
		if recordErr != nil {
			return nil, 0, recordErr
		}
		events = append(events, event)
	}
	return events, dropped, nil
}

// parseCoreTitanExecEvent decodes and validates one §3.3 record against the §3.2
// reject matrix. Rejection is the only repair.
func parseCoreTitanExecEvent(record string) (CoreTitanExecEvent, error) {
	malformed := errors.New("core returned a malformed titan exec event record")
	fields := strings.Split(record, ":")
	if len(fields) != 16 {
		return CoreTitanExecEvent{}, malformed
	}
	cgroupID, cgroupErr := titanExecParseDecimal(fields[0], 64)
	tsNS, tsErr := titanExecParseDecimal(fields[1], 64)
	dev, devErr := titanExecParseDecimal(fields[2], 32)
	inodeMode, modeErr := titanExecParseDecimal(fields[3], 32)
	ino, inoErr := titanExecParseDecimal(fields[4], 64)
	generation, generationErr := titanExecParseDecimal(fields[5], 32)
	pid, pidErr := titanExecParseDecimal(fields[6], 32)
	tgid, tgidErr := titanExecParseDecimal(fields[7], 32)
	uid, uidErr := titanExecParseDecimal(fields[8], 32)
	gid, gidErr := titanExecParseDecimal(fields[9], 32)
	prot, protErr := titanExecParseDecimal(fields[10], 32)
	fFlags, fFlagsErr := titanExecParseDecimal(fields[11], 32)
	hook, hookErr := titanExecParseDecimal(fields[12], 8)
	action, actionErr := titanExecParseDecimal(fields[13], 8)
	reason, reasonErr := titanExecParseDecimal(fields[14], 8)
	if cgroupErr != nil || tsErr != nil || devErr != nil || modeErr != nil || inoErr != nil ||
		generationErr != nil || pidErr != nil || tgidErr != nil || uidErr != nil || gidErr != nil ||
		protErr != nil || fFlagsErr != nil || hookErr != nil || actionErr != nil || reasonErr != nil {
		return CoreTitanExecEvent{}, errors.New("core returned invalid titan exec event fields")
	}
	comm, commErr := decodeTitanExecComm(fields[15])
	if commErr != nil {
		return CoreTitanExecEvent{}, commErr
	}
	event := CoreTitanExecEvent{
		CgroupID: cgroupID, TsNS: tsNS, Dev: uint32(dev), InodeMode: uint32(inodeMode), Ino: ino,
		Generation: uint32(generation), PID: uint32(pid), TGID: uint32(tgid), UID: uint32(uid),
		GID: uint32(gid), Prot: uint32(prot), FFlags: uint32(fFlags), Hook: uint8(hook),
		Action: uint8(action), Reason: uint8(reason), Comm: comm,
	}
	if event.Hook != titanExecHookBprm && event.Hook != titanExecHookMmap {
		return CoreTitanExecEvent{}, errors.New("core returned an invalid titan exec hook")
	}
	if event.Action != titanExecActionAudit && event.Action != titanExecActionDeny {
		return CoreTitanExecEvent{}, errors.New("core returned an invalid titan exec action")
	}
	if event.Reason > titanExecReasonMax {
		return CoreTitanExecEvent{}, errors.New("core returned an invalid titan exec reason")
	}
	if event.PID == 0 || event.TsNS == 0 {
		return CoreTitanExecEvent{}, errors.New("core returned a titan exec event without pid or timestamp")
	}
	// mmap events always carry the requested protection (§3.2); a zero value there
	// means the producer emitted an unusable record.
	if event.Hook == titanExecHookMmap && event.Prot == 0 {
		return CoreTitanExecEvent{}, errors.New("core returned an mmap event without a protection mask")
	}
	// A deny needs a ground the gate can name.
	if event.Action == titanExecActionDeny &&
		(event.Reason == titanExecReasonNone || event.Reason == titanExecReasonReadFailure) {
		return CoreTitanExecEvent{}, errors.New("core returned a titan exec deny without a policy ground")
	}
	// A half-null identity is corruption; a fully null identity is only producible
	// for a read-failure audit or an anonymous executable mmap without JIT scope
	// (§3.2 identity exceptions). Everything else is rejected.
	if (event.Dev == 0) != (event.Ino == 0) {
		return CoreTitanExecEvent{}, errors.New("core returned a titan exec event with a half-null identity")
	}
	if event.Dev == 0 && event.Ino == 0 {
		readFailureAudit := event.Action == titanExecActionAudit && event.Reason == titanExecReasonReadFailure
		anonymousExecMmap := event.Hook == titanExecHookMmap && event.Reason == titanExecReasonAnonNoJit &&
			event.Prot&titanExecProtExec != 0
		if !readFailureAudit && !anonymousExecMmap {
			return CoreTitanExecEvent{}, errors.New("core returned a titan exec event with an identity the producer cannot emit")
		}
	}
	// The flags byte is carried through unchanged: Phase 1 defines bit0 (ctime
	// mismatch observed) and bit1 (scope snapshot), the producer owns the rest.
	// f_flags is Phase 1 reserved and never rejected for being 0 (§3.2).
	return event, nil
}

// titanExecParseDecimal accepts the canonical decimal shape only: digits, no
// sign, no leading zero (except for the value zero itself) and within the field
// width. The core's format! output is canonical, so a deviation is a protocol
// violation, not a number to repair.
func titanExecParseDecimal(field string, bits int) (uint64, error) {
	invalid := errors.New("core returned a non-canonical titan exec counter")
	if field == "" || len(field) > 20 {
		return 0, invalid
	}
	if len(field) > 1 && field[0] == '0' {
		return 0, invalid
	}
	for index := 0; index < len(field); index++ {
		if field[index] < '0' || field[index] > '9' {
			return 0, invalid
		}
	}
	value, err := strconv.ParseUint(field, 10, bits)
	if err != nil {
		return 0, invalid
	}
	return value, nil
}

// decodeTitanExecComm decodes the comm hex field. The kernel fills the task name
// from arbitrary process-controlled bytes (PR_SET_NAME allows anything but NUL,
// at most 15 bytes plus terminator), so this function accepts every hex sequence
// up to 16 bytes and only enforces the NUL-padding shape of §3.2. Rejecting the
// bytes would let one hostile comm record suppress a whole all-or-nothing batch;
// rendering is the sanitiser's job, not the parser's.
func decodeTitanExecComm(field string) (string, error) {
	invalid := errors.New("core returned an invalid titan exec comm")
	if len(field) > 2*16 || len(field)%2 != 0 {
		return "", invalid
	}
	if len(field) == 0 {
		return "", nil
	}
	decoded, err := hex.DecodeString(field)
	if err != nil || len(decoded) > 16 {
		return "", invalid
	}
	// Padding rule: after the first NUL only NUL bytes may follow. The text
	// producer truncates at the first NUL, so this only matters for a hostile or
	// future core that emits the raw fixed-size comm field.
	end := len(decoded)
	for index, character := range decoded {
		if character != 0 {
			continue
		}
		end = index
		for _, padding := range decoded[index:] {
			if padding != 0 {
				return "", errors.New("core returned a titan exec comm with non-zero padding")
			}
		}
		break
	}
	return sanitizeTitanExecComm(decoded[:end]), nil
}

// ------------------------------------------------------- event -> XDR bridge

// titanExecRuleID is the §7.4 rule vocabulary: deny records name the hook they
// enforced, audit records are observations only.
func titanExecRuleID(event CoreTitanExecEvent) string {
	if event.Action == titanExecActionAudit {
		return "TITAN.EXEC_AUDIT"
	}
	if event.Hook == titanExecHookMmap {
		return "TITAN.MMAP_DENIED"
	}
	return "TITAN.EXEC_DENIED"
}

func titanExecDecision(event CoreTitanExecEvent) string {
	if event.Action == titanExecActionDeny {
		return "deny-exec"
	}
	return "audit"
}

// titanExecEventFingerprint is the dedupe key of §7.4. The wire carries no
// start_ticks, so the time bucket is the only stable disambiguator between two
// identical decisions of the same pid in the same second.
func titanExecEventFingerprint(event CoreTitanExecEvent) string {
	return fmt.Sprintf("titan-exec:%d:%d:%d:%d:%d:%d", event.PID, event.Dev, event.Ino,
		event.Hook, event.Action, event.TsNS/titanExecDedupeBucketNS)
}

func titanExecIdentityTarget(event CoreTitanExecEvent) string {
	if event.Dev == 0 && event.Ino == 0 {
		// Null identity is legitimate (§3.2) but must never be reported as a
		// specific object; the summary names the reason instead.
		return ""
	}
	return fmt.Sprintf("dev:%d:ino:%d", event.Dev, event.Ino)
}

// titanExecProcessPath enriches one decision with the executable behind the pid.
// It is best-effort and bounded: /proc/<pid>/exe is a symlink read once, and
// every failure, overlong target or non-absolute result becomes "unknown". The
// path is never used as identity or for a decision.
func titanExecProcessPath(pid uint32) string {
	if pid == 0 {
		return "unknown"
	}
	target, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil {
		return "unknown"
	}
	target = strings.TrimSuffix(target, " (deleted)")
	if target == "" || len(target) > titanExecPathMaxBytes || !filepath.IsAbs(target) ||
		strings.ContainsAny(target, "\x00\r\n\t") {
		return "unknown"
	}
	return target
}

func titanExecEventSummary(event CoreTitanExecEvent, path string) string {
	identity := "anonymous"
	if event.Dev != 0 || event.Ino != 0 {
		identity = fmt.Sprintf("dev=%d ino=%d", event.Dev, event.Ino)
	}
	return fmt.Sprintf("Titan exec gate %s on %s: pid=%d tgid=%d uid=%d gid=%d cgroup=%d reason=%s identity=%s comm=%q path=%s",
		titanExecActionName(event.Action), titanExecHookName(event.Hook), event.PID, event.TGID,
		event.UID, event.GID, event.CgroupID, titanExecReasonName(event.Reason), identity, event.Comm, path)
}

// recordCoreTitanExecEvent turns one kernel decision into XDR evidence and an
// incident. Evidence is written before any response decision (§7.4, §1.5); the
// incident then goes through the existing appendIncident path. There is no new
// response route: for a deny the kernel already blocked, so the existing
// respond() decision can only ever add a documented, evidence-backed action.
func (e *XDREngine) recordCoreTitanExecEvent(event CoreTitanExecEvent) {
	if e == nil || e.state == nil {
		return
	}
	if !e.claimFingerprint(titanExecEventFingerprint(event)) {
		return
	}
	path := titanExecProcessPath(event.PID)
	executable := ""
	if path != "unknown" {
		executable = path
	}
	severity := "high"
	score := 220
	evidenceKind := "titan.exec.denied"
	action := "deny"
	outcome := "blocked by kernel BPF-LSM before " + titanExecHookVerb(event.Hook) +
		" (kernel-side enforcement; no additional XDR response)"
	if event.Action == titanExecActionAudit {
		evidenceKind = "titan.exec.audited"
		score = 180
		action = "none"
		outcome = "audited, not blocked (kernel audit-only decision; no XDR response)"
	}
	summary := titanExecEventSummary(event, path)
	incident := XDRIncident{
		ID: randomID(), Time: time.Now().UTC(), Severity: severity, Score: score, ResponseScore: score,
		PID: int(event.PID), UID: event.UID, Process: event.Comm, Executable: executable,
		CellCgroupID: event.CgroupID, RuleIDs: []string{titanExecRuleID(event)},
		Categories: []string{"execution"}, Summary: summary,
		Decision: titanExecDecision(event), Action: action, Outcome: outcome,
	}
	if err := e.state.RecordEvidence(EvidenceRecord{
		Severity: severity, Kind: evidenceKind, Source: "titan-exec", Message: summary,
		Target: titanExecIdentityTarget(event),
	}); err != nil { // No evidence, no response (§1.5); the incident is still journalized and
		// says exactly why nothing was done.
		incident.Action, incident.Outcome = "none", "mandatory evidence commit failed; active response disabled"
	} else if event.Action == titanExecActionDeny {
		if degraded, _ := e.degradedState(); !degraded {
			if _, xdrMode := e.state.Modes(); xdrMode != "observe" {
				// The kernel already blocked. The existing respond() decision is
				// consulted so a future response rule can never bypass this gate,
				// but "deny-exec" is not a response decision: the outcome keeps the
				// kernel fact and never claims a second freeze.
				if responseAction, responseOutcome := e.respond(incident); responseAction != "none" {
					incident.Action = "deny+" + responseAction
					incident.Outcome = incident.Outcome + "; " + responseOutcome
				}
			}
		}
	}
	e.titanExecMu.Lock()
	e.titanExecStats.Incidents++
	e.titanExecMu.Unlock()
	e.appendIncident(incident)
}

// recordTitanExecBatch projects one drained batch: counters and bounded history
// first, then evidence-backed incidents, then the visibility loss. A non-empty
// dropped delta is reported and degraded only after it repeats - never silently
// accepted (§7.4 "kein stilles OK").
func (e *XDREngine) recordTitanExecBatch(events []CoreTitanExecEvent, dropped uint64, now time.Time) bool {
	if e == nil || e.state == nil {
		return dropped == 0
	}
	e.titanExecMu.Lock()
	e.titanExecStats.EventsTotal += uint64(len(events))
	for _, event := range events {
		if event.Action == titanExecActionDeny {
			e.titanExecStats.Denies++
		} else {
			e.titanExecStats.Audits++
		}
	}
	if len(events) > 0 {
		e.titanExecHistory = append(e.titanExecHistory, events...)
		if over := len(e.titanExecHistory) - titanExecEventHistoryLimit; over > 0 {
			e.titanExecHistory = append([]CoreTitanExecEvent(nil), e.titanExecHistory[over:]...)
		}
	}
	e.titanExecMu.Unlock()
	for _, event := range events {
		e.recordCoreTitanExecEvent(event)
	}
	if dropped == 0 {
		return true
	}
	e.titanExecMu.Lock()
	e.titanExecStats.Dropped += dropped
	report := e.titanExecLastOverflowEvent.IsZero() ||
		now.Sub(e.titanExecLastOverflowEvent) >= titanExecOverflowEventSpacing
	if report {
		e.titanExecLastOverflowEvent = now
	}
	e.titanExecMu.Unlock()
	if report {
		e.state.AddEvent(Event{Severity: "high", Kind: "xdr.titan_exec_overflow", Source: "titan-exec",
			Message: fmt.Sprintf("The kernel Titan exec gate reported %d dropped decision events; XDR visibility is reduced and does not claim that no exec/mmap decision was made", dropped)})
	}
	if effectiveTitanExecFabricSettings(e.runtimeSettings()).Enabled {
		e.noteTitanExecSensorFailure(fmt.Sprintf("kernel titan exec ring reported %d dropped decision events", dropped))
	}
	return false
}
