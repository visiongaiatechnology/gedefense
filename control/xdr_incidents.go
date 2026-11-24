// STATUS: DIAMANT VGT SUPREME
package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// restoreIncidentHistory seeds the in-memory incident list from the log on disk.
//
// The engine's list is what every forensic surface reads, and it is in memory - so it
// began empty on every start while the log held every incident the host had ever seen. A
// host whose control plane had been restarted reported zero incidents in the operator's
// view next to a log file containing 220 of them. The record was never lost; there was
// simply nothing that read it back.
//
// The most recent incidents are restored, bounded by the same cap the live list uses, so
// the memory cost does not grow with the age of the installation.
func (e *XDREngine) restoreIncidentHistory() error {
	if e == nil || e.logger == nil || e.state == nil {
		return nil
	}
	limit := e.state.incidentCap
	if limit <= 0 {
		return nil
	}
	incidents, err := e.logger.ReadRecent(limit)
	if err != nil {
		return err
	}
	if len(incidents) == 0 {
		return nil
	}
	e.state.RestoreIncidents(incidents)
	return nil
}

func (e *XDREngine) appendIncident(incident XDRIncident) {
	// The incident log is the forensic record of what the sensors emitted. It must carry
	// the same normalised severity as the state and the case store, otherwise the same
	// incident reads differently in the log, in the dashboard and in the case list.
	incident.Severity = strings.ToLower(strings.TrimSpace(incident.Severity))
	// V6.3.0 AP-6/AP-7: attach the GIEF v1.0 envelope and the mandatory
	// explainability block before the forensic log record is sealed. Both are
	// metadata only: score, decision and action are never changed here.
	incident = e.attachGIEFEnvelope(incident)
	incident = e.attachFindingExplainability(incident)
	// V6.3.0 AP-9 (S08/S15): self-tamper/evidence findings go to the out-of-band
	// witness before the local forensic record is written, so a later local
	// truncation cannot erase the only copy.
	e.pushCriticalWitness(incident)
	// V6.3.0 AP-7: offer the sealed finding to the persistent review queue.
	// Storage failures degrade the queue; they never fail the XDR path.
	e.enqueueReviewFinding(incident)
	if e.logger != nil {
		if hash, err := e.logger.Append(incident); err == nil {
			incident.RecordHash = hash
		} else {
			log.Printf("xdr incident log: %v", err)
			e.markDegradedCause("incident_log", "incident log unavailable: "+err.Error())
		}
	}
	e.state.AddIncident(incident)
	// POINT 5 / P5-T3: the Emergency Lockdown observes the incident stream. The
	// hook is optional and inert unless the operator enabled the namespace; it never
	// changes the incident record and never fails the XDR path.
	if e.lockdown != nil {
		e.lockdown.ObserveIncident(incident)
	}
}

func (e *XDREngine) recordMalwareEvent(event CoreMalwareEvent) {
	severity := "high"
	score := 180
	ruleID := "MALWARE.CONTENT_SUSPICIOUS"
	if event.State == "malicious" {
		severity = "critical"
		score = 250
		ruleID = "MALWARE.CONTENT_MATCH"
	} else if event.State == "blocked" {
		severity = "critical"
		score = 250
		ruleID = "MALWARE.SCAN_FAILURE"
	}
	message := fmt.Sprintf("Execution blocked before first instruction: type=%s reason=%s size=%d sha256=%s pid=%d uid=%d", event.Classification, event.Reason, event.Size, event.SHA256, event.PID, event.UID)
	e.state.AddEvent(Event{Severity: severity, Kind: "malware.execution_blocked", Source: "fanotify", Message: message, Target: event.Path})
	fingerprint := fmt.Sprintf("malware:%d:%s:%s:%s", event.PID, event.SHA256, event.State, event.Reason)
	if !e.claimFingerprint(fingerprint) {
		return
	}
	e.appendIncident(XDRIncident{
		ID: randomID(), Time: time.Now().UTC(), Severity: severity, Score: score, ResponseScore: score,
		PID: event.PID, UID: event.UID, Executable: event.Path, CommandSHA256: event.SHA256,
		RuleIDs: []string{ruleID}, Categories: []string{"malware", "integrity"}, Summary: message,
		Decision: "deny-execution", Action: "deny-exec", Outcome: "blocked by fanotify before execution",
	})
}

func (e *XDREngine) recordManualMalwareFinding(path string, result MalwareScanResult) {
	severity := "high"
	score := 180
	ruleID := "MALWARE.MANUAL_SUSPICIOUS"
	if result.State == "malicious" {
		severity = "critical"
		score = 250
		ruleID = "MALWARE.MANUAL_MATCH"
	}
	fingerprint := fmt.Sprintf("manual-malware:%s:%s:%s", result.SHA256, result.State, result.Reason)
	if !e.claimFingerprint(fingerprint) {
		return
	}
	summary := fmt.Sprintf("Manual content scan %s: type=%s reason=%s size=%d sha256=%s", result.State, result.Classification, result.Reason, result.Size, result.SHA256)
	e.appendIncident(XDRIncident{
		ID: randomID(), Time: time.Now().UTC(), Severity: severity, Score: score, ResponseScore: score,
		Executable: path, CommandSHA256: result.SHA256, RuleIDs: []string{ruleID}, Categories: []string{"malware", "manual-scan"},
		Summary: summary, Decision: "alert", Action: "none", Outcome: "operator scan recorded; quarantine authorization required",
	})
}

func (e *XDREngine) recordMalwareOverflow(dropped uint64) {
	reason := fmt.Sprintf("malware event queue overflow: %d records were dropped", dropped)
	e.markDegraded(reason)
	e.state.AddEvent(Event{Severity: "critical", Kind: "malware.event_queue_overflow", Source: "fanotify", Message: reason})
	fingerprint := fmt.Sprintf("malware-overflow:%d", dropped)
	if !e.claimFingerprint(fingerprint) {
		return
	}
	e.appendIncident(XDRIncident{
		ID: randomID(), Time: time.Now().UTC(), Severity: "critical", Score: 250, ResponseScore: 250,
		RuleIDs: []string{"MALWARE.EVENT_QUEUE_OVERFLOW"}, Categories: []string{"malware", "sensor-health"}, Summary: reason,
		Decision: "degrade", Action: "disable-response", Outcome: "fanotify blocking remains fail-closed; XDR active response disabled",
	})
}

func (e *XDREngine) captureProtected(paths []string) {
	uniq := map[string]struct{}{}
	for _, raw := range paths {
		if strings.TrimSpace(raw) == "" {
			continue
		}
		p, err := filepath.Abs(raw)
		if err != nil {
			continue
		}
		p = filepath.Clean(p)
		if _, ok := uniq[p]; ok {
			continue
		}
		uniq[p] = struct{}{}
		st, err := os.Stat(p)
		if err != nil || !st.Mode().IsRegular() {
			continue
		}
		digest, err := hashFile(p)
		if err != nil {
			continue
		}
		e.protected[p] = protectedObject{path: p, digest: digest, mode: st.Mode().Perm(), size: st.Size()}
	}
}

func (e *XDREngine) checkProtected() {
	// The protected set is read under the lock because an authorized update window moves the
	// recorded state of an object while the XDR workers run.
	e.mu.RLock()
	objects := make(map[string]protectedObject, len(e.protected))
	for key, object := range e.protected {
		objects[key] = object
	}
	e.mu.RUnlock()
	paths := make([]string, 0, len(objects))
	for p := range objects {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	for _, p := range paths {
		old := objects[p]
		identity := resolvedIdentity(p)
		st, err := os.Stat(p)
		if err != nil {
			if e.updateWindowCovers(identity, "", true) {
				e.applyAuthorizedUpdate(p, identity, "", "missing", true, protectedObject{})
				continue
			}
			e.selfTamper(p, "missing", "protected object disappeared")
			continue
		}
		digest, err := hashFile(p)
		observed := digest
		if err != nil {
			observed = "unreadable"
		}
		// Content, permissions and size are what the baseline recorded, so all three are
		// part of the state that is compared and announced.
		observed = fmt.Sprintf("%s:%04o:%d", observed, st.Mode().Perm(), st.Size())
		if err == nil && digest == old.digest && st.Mode().Perm() == old.mode && st.Size() == old.size {
			continue
		}
		// A signed, currently open update window is the only exception: the change has to
		// match the digest the verified release manifest names for exactly this artifact.
		if e.updateWindowCovers(identity, digest, false) {
			e.applyAuthorizedUpdate(p, identity, digest, observed, false,
				protectedObject{path: p, digest: digest, mode: st.Mode().Perm(), size: st.Size()})
			continue
		}
		e.selfTamper(p, observed, "protected object changed after XDR initialization")
	}
}

// resolvedIdentity names the object behind a protected path rather than the route to it.
//
// The protected set reaches the access gateway twice: once through
// /opt/vgt/gedefense/current/bin/gedefense-access, the stable name an operator knows, and
// once through /opt/vgt/gedefense/releases/<version>/bin/gedefense-access, which is what the
// running process resolves to. Both are the same file, so replacing it once was reported
// twice - two critical incidents for one change. Reporting the object collapses the pair,
// and it keeps working when /current is retargeted, because the resolved target is what the
// baseline actually hashed.
func resolvedIdentity(path string) string {
	if resolved, err := filepath.EvalSymlinks(path); err == nil {
		return resolved
	}
	return path
}

// claimTamper reports whether this observed state of this object still needs announcing.
//
// A tamper is a state, not an event that repeats: the object keeps not matching until
// somebody changes it back or the service restarts against a fresh baseline. This used to
// be announced through the time-based dedupe window, so an unremediated change produced a
// fresh critical incident every dedupe interval - five minutes by default - and one fact
// buried the rest of the ledger. Keying on the object and its observed state reports each
// distinct change exactly once, and a further modification is still a new fact.
func (e *XDREngine) claimTamper(identity, observed string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.tamperSeen == nil {
		e.tamperSeen = map[string]string{}
	}
	if announced, ok := e.tamperSeen[identity]; ok && announced == observed {
		return false
	}
	e.tamperSeen[identity] = observed
	return true
}

// selfTamper records that a protected object no longer matches the state this process
// started with. The object and the state it was found in decide whether this is news:
// see claimTamper.
//
// A change to one of GeDefense's own components is not exempt. The protected set contains
// this installation's own executables, and every legitimate update replaces them while the
// service runs - but that update has to be attributable, so the only sanctioned path is a
// verified signed release manifest that opened a bounded update window (see
// BeginSignedUpdateWindow). The window is checked by the observation path before this call;
// reaching this point with an own component therefore means the replacement is unauthorized,
// and it gets the same fail-closed treatment as a third-party object: a critical
// XDR.SELF_TAMPER incident, a release-blocking degradation, and no active response on top of
// a platform that has just declared its own trust boundary broken.
func (e *XDREngine) selfTamper(path, observed, reason string) {
	identity := resolvedIdentity(path)
	if !e.claimTamper(identity, observed) {
		return
	}
	// One cause per object, so the reported reason names everything that changed rather
	// than only the last thing that did.
	e.markDegradedCause("runtime:"+identity, reason+": "+path)
	i := XDRIncident{ID: randomID(), Time: time.Now().UTC(), Severity: "critical", Score: 250, Executable: path,
		RuleIDs: []string{"XDR.SELF_TAMPER"}, Categories: []string{"integrity"}, Summary: reason, Decision: "degrade", Action: "disable-response", Outcome: "active XDR response disabled until restart and verification"}
	e.appendIncident(i)
	e.state.AddEvent(Event{Severity: "critical", Kind: "xdr.self_tamper", Source: "integrity", Message: reason, Target: path})
}

func (e *XDREngine) markDegraded(reason string) {
	e.markDegradedCause("runtime", reason)
}

// forensicFailureThreshold is how many consecutive failed checks a forensic artefact may produce
// before it degrades the platform.
//
// One failed check used to degrade XDR immediately, and XDR degraded means the automatic response
// pauses and stays paused until the calm holds again - so a single hiccup, a momentarily busy
// writer or a verification that read while a record was being appended became a visible
// fail-safe in the interface. A condition is what persists; a hiccup is what does not.
const forensicFailureThreshold = 2

// noteVerificationFailure applies that policy: the first failure is named in the journal, a
// repeated one degrades XDR. The journal line matters as much as the threshold - a degradation
// that cannot be seen in the journal cannot be diagnosed, which is what made this one take an
// afternoon of guessing.
func (e *XDREngine) noteVerificationFailure(cause, reason string) {
	count, repeated := e.claimRepeatedFailure(cause)
	if repeated {
		if count == forensicFailureThreshold {
			log.Printf("xdr degraded after %d consecutive failures: %s", count, reason)
		}
		e.markDegradedCause(cause, reason)
		return
	}
	log.Printf("xdr verification failed (%d/%d, not degrading yet): %s", count, forensicFailureThreshold, reason)
}

// noteVerificationSuccess clears the failure counter and the cause it may have set.
func (e *XDREngine) noteVerificationSuccess(cause string) {
	e.clearRepeatedFailure(cause)
	e.clearDegradedCause(cause)
}

func (e *XDREngine) claimRepeatedFailure(cause string) (int, bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.forensicFailures == nil {
		e.forensicFailures = make(map[string]int)
	}
	e.forensicFailures[cause]++
	count := e.forensicFailures[cause]
	return count, count >= forensicFailureThreshold
}

func (e *XDREngine) clearRepeatedFailure(cause string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	delete(e.forensicFailures, cause)
}

// verifyForensicArtefacts keeps the forensic artefacts and the degradation causes they set in
// step with each other.
//
// Verification used to run in one direction only: a failure recorded a cause, a success cleared
// nothing. Only a rotation or an operator recovery could clear one, so a single transient failure
// left XDR degraded - and a degraded XDR blocks every promotion and pauses the automatic response
// - until somebody restarted the control plane. That is what happened twice on the production
// host: the state was cleared by a restart rather than by the platform noticing that the problem
// had gone. A verification that succeeds is exactly that observation, so it clears the cause it
// would otherwise have set.
func (e *XDREngine) verifyForensicArtefacts(ctx context.Context) {
	if e.logger != nil {
		// Seal the chain before the budget is reached. A full incident ledger stops recording,
		// degrades XDR, and that degradation blocks every promotion and pauses the automatic
		// response until an operator archives the segment by hand - which is exactly what
		// happened twice on the production host, and what the retention design has to prevent
		// instead of reporting.
		if size, budget := e.logger.StoredBytes(); budget > 0 && size > 0 && size*100 >= budget*evidenceRotationThresholdPercent {
			result, rotateErr := e.logger.Rotate(ctx, "incident-log retention budget reached; sealing the segment before recording stops")
			switch {
			case rotateErr != nil:
				e.markDegradedCause("incident_log", "incident log rotation failed: "+rotateErr.Error())
			case e.state == nil:
				e.clearDegradedCause("incident_log")
			default:
				e.state.AddEvent(Event{Severity: "high", Kind: "xdr.incident_log_rotated", Source: "xdr",
					Message: fmt.Sprintf("Incident ledger sealed into %s and started a fresh chain", result.ArchiveID)})
				if err := e.state.RecordEvidence(EvidenceRecord{
					Severity: "high", Kind: "xdr.incident_log_rotated", Source: "xdr",
					Message: "Incident ledger sealed at its retention budget; a fresh chain continues",
					Target:  "archive:" + result.ArchiveID + " manifest_sha256:" + result.ManifestSHA256,
				}); err != nil {
					e.markDegradedCause("evidence", "mandatory evidence ledger unavailable during rotation")
				} else {
					e.clearDegradedCause("incident_log")
				}
			}
		} else if err := e.logger.Verify(); err != nil {
			e.noteVerificationFailure("incident_log", "incident log verification failed: "+err.Error())
		} else {
			e.noteVerificationSuccess("incident_log")
		}
	}
	if e.state == nil {
		return
	}
	// The evidence ledger has the same property: a healthy ledger means the cause recorded while
	// it was unavailable no longer holds.
	if ledger := e.state.EvidenceLedger(); ledger != nil {
		if err := ledger.Healthy(); err != nil {
			e.noteVerificationFailure("evidence", "mandatory evidence ledger unavailable: "+err.Error())
		} else {
			e.noteVerificationSuccess("evidence")
		}
	}
}

func (e *XDREngine) markDegradedCause(cause, reason string) {
	e.mu.Lock()
	if e.degradeCauses == nil {
		e.degradeCauses = make(map[string]string)
	}
	previous, existed := e.degradeCauses[cause]
	e.degradeCauses[cause] = reason
	e.recomputeDegradedLocked()
	degraded, degradedReason := e.degraded, e.degradeWhy
	e.mu.Unlock()
	e.state.SetXDRDegraded(degraded, degradedReason)
	// Logged once per distinct reason, not once per check: a persistent cause must be visible in
	// the journal without flooding it every thirty seconds.
	if !existed || previous != reason {
		log.Printf("xdr degraded: cause=%s reason=%s", cause, reason)
	}
}

func (e *XDREngine) clearDegradedCause(cause string) {
	e.mu.Lock()
	previous, existed := e.degradeCauses[cause]
	delete(e.degradeCauses, cause)
	e.recomputeDegradedLocked()
	degraded, reason := e.degraded, e.degradeWhy
	e.mu.Unlock()
	e.state.SetXDRDegraded(degraded, reason)
	if existed {
		log.Printf("xdr recovered: cause=%s was=%s", cause, previous)
	}
}

func (e *XDREngine) recomputeDegradedLocked() {
	if len(e.degradeCauses) == 0 {
		e.degraded = false
		e.degradeWhy = ""
		return
	}
	keys := make([]string, 0, len(e.degradeCauses))
	for key := range e.degradeCauses {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	reasons := make([]string, 0, len(keys))
	for _, key := range keys {
		reasons = append(reasons, e.degradeCauses[key])
	}
	e.degraded = true
	e.degradeWhy = strings.Join(reasons, "; ")
}

func (e *XDREngine) degradedState() (bool, string) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.degraded, e.degradeWhy
}

func (e *XDREngine) incidentRecoveryAllowed() bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	if len(e.degradeCauses) != 1 {
		return false
	}
	_, ok := e.degradeCauses["incident_log"]
	return ok
}

// TitanExecStatusSnapshot builds the bounded field attached to /api/v1/status.
// It is nil for an engine without exec-gate wiring, so the payload of an
// installation that never enabled the gate stays byte-identical.
func (e *XDREngine) TitanExecStatusSnapshot() *TitanExecStatus {
	if e == nil || e.titanExec == nil {
		return nil
	}
	sync := e.TitanExecPolicyStatus()
	e.titanExecMu.Lock()
	stats := e.titanExecStats
	e.titanExecMu.Unlock()
	return &TitanExecStatus{
		State: sync.State, SensorState: e.titanExecSensorState(), Capability: sync.Capability,
		Enabled: sync.Enabled, Mode: sync.Mode, Path: sync.Path, LSM: sync.LSM, Offsets: sync.Offsets,
		Entries: sync.Entries, Scopes: sync.Scopes,
		EventsTotal: stats.EventsTotal, Denies: stats.Denies, Audits: stats.Audits,
		Dropped: stats.Dropped, ParseErrors: stats.ParseErrors, Incidents: stats.Incidents,
	}
}

// TitanExecStatusReport builds the GET /api/v1/titan/exec/status payload.
func (e *XDREngine) TitanExecStatusReport() TitanExecStatusView {
	view := TitanExecStatusView{
		State: TitanExecSyncStateUnavailable, SensorState: "unavailable", Capability: titanExecCapabilityUnknown,
		Sync:         titanExecUnavailableStatus(),
		Kernel:       TitanExecKernelView{Path: titanExecPathNone, LSM: titanExecLSMInactive, Offsets: titanExecOffsetsInvalid},
		HistoryLimit: titanExecEventHistoryLimit,
	}
	if e == nil {
		return view
	}
	sync := e.TitanExecPolicyStatus()
	health, healthAt, healthErr, drainErr := e.titanExecHealthSnapshot()
	e.titanExecMu.Lock()
	stats := e.titanExecStats
	e.titanExecMu.Unlock()
	view.State = sync.State
	view.Capability = sync.Capability
	view.SensorState = e.titanExecSensorState()
	view.Sync = sync
	view.Kernel = TitanExecKernelView{
		Path: sync.Path, LSM: sync.LSM, Offsets: sync.Offsets, Entries: sync.Entries, Scopes: sync.Scopes,
		Health: health, HealthAt: healthAt, HealthError: healthErr, DrainError: drainErr,
	}
	view.Counters = titanExecCountersView(stats)
	return view
}

// TitanExecEventsReport builds the bounded GET /api/v1/titan/exec/events payload:
// the newest `limit` events of the bounded history, newest first.
func (e *XDREngine) TitanExecEventsReport(limit int) TitanExecEventsView {
	if limit < 1 {
		limit = 1
	}
	if limit > titanExecEventHistoryLimit {
		limit = titanExecEventHistoryLimit
	}
	view := TitanExecEventsView{Events: []TitanExecEventView{}, Limit: limit, HistoryLimit: titanExecEventHistoryLimit}
	if e == nil {
		return view
	}
	e.titanExecMu.Lock()
	history := append([]CoreTitanExecEvent(nil), e.titanExecHistory...)
	stats := e.titanExecStats
	e.titanExecMu.Unlock()
	view.Available = len(history)
	view.Counters = titanExecCountersView(stats)
	start := len(history) - limit
	if start < 0 {
		start = 0
	}
	view.Events = make([]TitanExecEventView, 0, len(history)-start)
	for index := len(history) - 1; index >= start; index-- {
		view.Events = append(view.Events, titanExecEventViewOf(history[index]))
	}
	return view
}

func titanExecEventViewOf(event CoreTitanExecEvent) TitanExecEventView {
	return TitanExecEventView{
		CgroupID: event.CgroupID, TsNS: event.TsNS, Dev: event.Dev, InodeMode: event.InodeMode,
		Ino: event.Ino, Generation: event.Generation, PID: event.PID, TGID: event.TGID,
		UID: event.UID, GID: event.GID, Prot: event.Prot, FFlags: event.FFlags,
		Hook: event.Hook, Action: event.Action, Reason: event.Reason, Flags: event.Flags,
		Comm: event.Comm, RuleID: titanExecRuleID(event),
	}
}

// ------------------------------------------------ Titan exec label helpers
//
// The operator-facing names of §3.1. They contain no policy decision; they only
// make a decoded record readable in evidence and in the event summary.

func titanExecHookName(hook uint8) string {
	if hook == titanExecHookMmap {
		return "mmap_file"
	}
	return "bprm_check_security"
}

func titanExecHookVerb(hook uint8) string {
	if hook == titanExecHookMmap {
		return "an executable memory mapping"
	}
	return "execution"
}

func titanExecReasonName(reason uint8) string {
	switch reason {
	case titanExecReasonNone:
		return "NONE"
	case titanExecReasonUnlinked:
		return "UNLINKED"
	case titanExecReasonTmpfs:
		return "TMPFS"
	case titanExecReasonMemfd:
		return "MEMFD"
	case titanExecReasonNotAllowlist:
		return "NOT_ALLOWLISTED"
	case titanExecReasonWX:
		return "WX"
	case titanExecReasonAnonNoJit:
		return "ANON_NO_JIT"
	case titanExecReasonReadFailure:
		return "READ_FAILURE"
	case titanExecReasonStateNotRdy:
		return "STATE_NOT_READY"
	case titanExecReasonCtimeMismatch:
		return "CTIME_MISMATCH"
	case titanExecReasonFSHard:
		return "FS_HARD"
	default:
		return "UNKNOWN"
	}
}

// ------------------------------------------------ Titan exec drain / health
//
// The poll classification and the two-hit degradation policy of §7.4. Both are
// driven from the engine's 100 ms tick through consumeTitanExecDrain and
// consumeTitanExecHealth; keeping them here (next to the other sensor health
// paths) is why titan_exec_events.go stays the wire/parser + event bridge.

// consumeTitanExecDrain classifies one TITAN_EXEC_EVENTS answer and returns the
// delay until the next drain. A capability-missing answer is a fact, not an XDR
// degradation; only repeated real failures degrade, and only while the operator
// enabled the namespace.
func (e *XDREngine) consumeTitanExecDrain(payload string, drainErr error, now time.Time) time.Duration {
	if e == nil {
		return titanExecDrainBackoff
	}
	enabled := effectiveTitanExecFabricSettings(e.runtimeSettings()).Enabled
	switch {
	case errors.Is(drainErr, ErrTitanExecUnavailable):
		// The capability fact replaces a previously recorded transient error: a
		// downgraded core is not an event-drain failure any more.
		e.setTitanExecCapability(false)
		e.titanExecMu.Lock()
		e.titanExecDrainErr = ""
		e.titanExecMu.Unlock()
		return titanExecDrainBackoff
	case drainErr != nil:
		text := boundedTitanExecText(drainErr)
		e.titanExecMu.Lock()
		e.titanExecDrainErr = text
		e.titanExecMu.Unlock()
		if enabled {
			e.noteTitanExecSensorFailure("kernel titan exec event drain unavailable: " + text)
		}
		return titanExecDrainBackoff
	}
	e.setTitanExecCapability(true)
	e.titanExecMu.Lock()
	e.titanExecDrainErr = ""
	e.titanExecMu.Unlock()
	events, dropped, parseErr := parseCoreTitanExecEvents(payload)
	if parseErr != nil {
		text := boundedTitanExecText(parseErr)
		e.titanExecMu.Lock()
		e.titanExecStats.ParseErrors++
		e.titanExecMu.Unlock()
		if enabled {
			e.noteTitanExecSensorFailure("kernel titan exec event payload rejected: " + text)
		}
		return titanExecDrainBackoff
	}
	if e.recordTitanExecBatch(events, dropped, now) {
		e.noteTitanExecSensorSuccess()
	}
	if enabled {
		return titanExecDrainInterval
	}
	return titanExecDrainBackoff
}

// consumeTitanExecHealth stores the last kernel counter sample. The health
// channel is diagnostic: events are the authoritative ingestion path, so a
// failing health command is reported in the status view but never creates a
// second degradation cause for the same sensor.
func (e *XDREngine) consumeTitanExecHealth(health CoreTitanExecHealth, healthErr error, now time.Time) {
	if e == nil {
		return
	}
	if errors.Is(healthErr, ErrTitanExecUnavailable) {
		e.setTitanExecCapability(false)
		return
	}
	e.titanExecMu.Lock()
	defer e.titanExecMu.Unlock()
	if healthErr != nil {
		e.titanExecHealthErr = boundedTitanExecText(healthErr)
		return
	}
	e.titanExecHealth = health
	e.titanExecHealthAt = now
	e.titanExecHealthErr = ""
}

// noteTitanExecSensorFailure applies the two-hit policy of the existing engine:
// the first failure is journaled, a repeated one degrades this module only, and
// the transition is reported as an event.
func (e *XDREngine) noteTitanExecSensorFailure(reason string) {
	if e == nil || e.state == nil {
		return
	}
	wasDegraded, _ := e.degradedState()
	e.noteVerificationFailure(titanExecSensorCause, reason)
	if degraded, degradedReason := e.degradedState(); !wasDegraded && degraded {
		e.state.AddEvent(Event{Severity: "critical", Kind: "xdr.titan_exec_sensor_degraded", Source: "titan-exec",
			Message: "Titan exec-gate XDR ingestion degraded after repeated failures; kernel enforcement is unaffected on its own path: " + degradedReason})
	}
}

// noteTitanExecSensorSuccess clears the failure counter and any cause this module
// set, and reports the recovery once.
func (e *XDREngine) noteTitanExecSensorSuccess() {
	if e == nil || e.state == nil {
		return
	}
	wasSet := e.titanExecSensorCauseSet()
	e.noteVerificationSuccess(titanExecSensorCause)
	if wasSet && !e.titanExecSensorCauseSet() {
		e.state.AddEvent(Event{Severity: "info", Kind: "xdr.titan_exec_sensor_recovered", Source: "titan-exec",
			Message: "Titan exec-gate XDR ingestion recovered after a clean drain"})
	}
}

func (e *XDREngine) titanExecSensorCauseSet() bool {
	if e == nil {
		return false
	}
	e.mu.RLock()
	defer e.mu.RUnlock()
	_, set := e.degradeCauses[titanExecSensorCause]
	return set
}
