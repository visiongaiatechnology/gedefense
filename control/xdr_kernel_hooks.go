// STATUS: DIAMANT VGT SUPREME
package main

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

// V6.3.0 AP-4: XDR integration of the io_uring/LKM hook family.
//
// Maps kernel observations onto `XDR.LKM_LOAD` (a module load outside the
// boot/package path, score 120) and `XDR.IO_URING_ANOMALY` (an io_uring ring
// operation by a process whose lineage or executable is unusual, score 90).
// Both rules are evidence-first and observe-only: `Decision:"alert"`,
// `Action:"none"`, an explicit observe-only outcome, no kill path and no change
// to `combineMatches`.
//
// TOLERATED policy (enforced here in the control plane, never silently in the
// kernel):
//   - module loads by the boot path (parent `systemd`/`udevd`/`modprobe`/…),
//     the package path (`dpkg`/`apt`/`rpm`/`dnf`/`pacman`/…) or by
//     `insmod`/`modprobe`/`kmod` executing from an installation-managed path
//     (`/usr/bin`, `/usr/sbin`, `/sbin`, `/bin`, `/lib/modules`,
//     `/usr/lib/modules`),
//   - our own control process / the privileged `gedefense-core` daemon,
//   - known io_uring-heavy legitimate workers (databases, storage, VM hosts,
//     container runtimes) for the io_uring family,
//   - network-facing/interpreter shell lineage is NEVER tolerated for io_uring.
//
// Everything else is evidence for the operator. A capability-missing core is
// reported as a capability fact (info event, no degradation claim), ring
// overflow is reported as one rate-limited high-severity health event, and every
// record is deduplicated by `(ts, kind, pid)`.

// pollKernelHooks runs one status + drain cycle and returns the next due time.
// The XDR loop ticks every 100 ms; this returns the drain cadence (1 s) and
// performs the status query only when its 5 s cadence is due, so neither can
// delay the other ingestion path.
func (e *XDREngine) pollKernelHooks(runtime RuntimeSettings, now time.Time, retryAfter time.Time) time.Time {
	if e == nil || e.kernelHooksCore == nil || !runtime.XDREnabled || now.Before(retryAfter) {
		return retryAfter
	}
	if e.kernelHooksStatusDue(now) {
		status, statusErr := e.kernelHooksCore.KernelHookStatus()
		e.consumeKernelHooksStatus(status, statusErr, now)
		if statusErr == nil {
			// Arm the observe-only family once. The core arms itself at load; this
			// covers a core that was explicitly disarmed and then upgraded, and a
			// later operator disarm stays authoritative because the request latches.
			if !status.Enabled && !e.kernelHooksArmedRequested {
				e.kernelHooksArmedRequested = true
				if err := e.kernelHooksCore.KernelHookSet(true); err != nil {
					e.kernelHooksArmedRequested = false
					e.setKernelHooksStatusError(err)
				}
			}
			e.kernelHooksFetchEpoch()
		}
	}
	events, dropped, drainErr := e.kernelHooksCore.KernelHookEvents()
	if drainErr != nil {
		if errors.Is(drainErr, ErrKernelHooksUnavailable) {
			e.consumeKernelHooksStatus(CoreKernelHookStatus{}, ErrKernelHooksUnavailable, now)
		} else {
			// Never pretend healthy: the report shows degraded with this reason
			// until the drain succeeds again.
			e.setKernelHooksDrainError(drainErr)
		}
		return now.Add(kernelHooksDrainInterval)
	}
	e.clearKernelHooksDrainError()
	e.consumeKernelHookEvents(events, dropped, now)
	return now.Add(kernelHooksDrainInterval)
}

func (e *XDREngine) kernelHooksStatusDue(now time.Time) bool {
	e.kernelHooksMu.Lock()
	defer e.kernelHooksMu.Unlock()
	return e.kernelHooksStatusAt.IsZero() ||
		now.Sub(e.kernelHooksStatusAt) >= kernelHooksStatusInterval
}

func (e *XDREngine) setKernelHooksStatusError(err error) {
	if e == nil || err == nil {
		return
	}
	e.kernelHooksMu.Lock()
	e.kernelHooksStatusErr = "status query failed: " + boundedStyxText(err)
	e.kernelHooksMu.Unlock()
}

func (e *XDREngine) setKernelHooksDrainError(err error) {
	if e == nil || err == nil {
		return
	}
	e.kernelHooksMu.Lock()
	e.kernelHooksStatusErr = "event drain failed: " + boundedStyxText(err)
	e.kernelHooksMu.Unlock()
}

// clearKernelHooksDrainError forgets only a drain-origin error; a persistent
// status-query failure is cleared by the next successful status query.
func (e *XDREngine) clearKernelHooksDrainError() {
	if e == nil {
		return
	}
	e.kernelHooksMu.Lock()
	if strings.HasPrefix(e.kernelHooksStatusErr, "event drain failed:") {
		e.kernelHooksStatusErr = ""
	}
	e.kernelHooksMu.Unlock()
}

// kernelHooksFetchEpoch caches the per-boot epoch once (best effort; a failure is
// recorded as a degraded status reason but never blocks the drain).
func (e *XDREngine) kernelHooksFetchEpoch() {
	e.kernelHooksMu.Lock()
	known := e.kernelHooksEpoch != ""
	e.kernelHooksMu.Unlock()
	if known {
		return
	}
	epoch, err := e.kernelHooksCore.KernelHookEpoch()
	if err != nil {
		e.setKernelHooksStatusError(err)
		return
	}
	e.kernelHooksMu.Lock()
	e.kernelHooksEpoch = epoch
	e.kernelHooksMu.Unlock()
}

func (e *XDREngine) consumeKernelHooksStatus(status CoreKernelHookStatus, statusErr error, now time.Time) {
	if e == nil {
		return
	}
	e.kernelHooksMu.Lock()
	wasKnown := e.kernelHooksCapabilityKnown
	if statusErr == nil {
		e.kernelHooksStatus = status
		e.kernelHooksStatusAt = now
		e.kernelHooksStatusErr = ""
		e.kernelHooksCapabilityKnown = true
	} else if errors.Is(statusErr, ErrKernelHooksUnavailable) {
		e.kernelHooksCapabilityKnown = false
		e.kernelHooksStatus = CoreKernelHookStatus{}
		e.kernelHooksStatusAt = time.Time{}
		e.kernelHooksStatusErr = ""
		e.kernelHooksEpoch = ""
	} else {
		e.kernelHooksStatusErr = "status query failed: " + boundedStyxText(statusErr)
	}
	known := e.kernelHooksCapabilityKnown
	e.kernelHooksMu.Unlock()
	if e.state == nil {
		return
	}
	switch {
	case !known && wasKnown:
		e.state.AddEvent(Event{Severity: "info", Kind: "xdr.kernel_hooks_capability_missing", Source: "kernel",
			Message: "The privileged core no longer advertises the KERNEL_HOOK_* command family; io_uring and LKM kernel visibility is unavailable (capability fact, not an XDR degradation)"})
	case known && !wasKnown:
		e.state.AddEvent(Event{Severity: "info", Kind: "xdr.kernel_hooks_capability_available", Source: "kernel",
			Message: "io_uring/LKM kernel hooks are available; ring/module records are ingested (observe-only)"})
	}
}

// consumeKernelHookEvents turns one bounded kernel batch into evidence/incidents.
func (e *XDREngine) consumeKernelHookEvents(events []CoreKernelHookEvent, dropped uint64, now time.Time) {
	if e == nil {
		return
	}
	for _, event := range events {
		if !e.claimKernelHookRecord(event, now) {
			continue
		}
		e.recordKernelHookFinding(event, now)
	}
	if dropped > 0 && e.state != nil {
		e.kernelHooksMu.Lock()
		last := e.kernelHooksLastOverflow
		if last.IsZero() || now.Sub(last) >= kernelHooksOverflowMinGap {
			e.kernelHooksLastOverflow = now
			e.kernelHooksMu.Unlock()
			e.state.AddEvent(Event{Severity: "high", Kind: "xdr.kernel_hooks_overflow", Source: "kernel",
				Message: fmt.Sprintf("io_uring/LKM hook ring dropped %d record(s); kernel hook visibility is reduced", dropped)})
		} else {
			e.kernelHooksMu.Unlock()
		}
	}
}

// recordKernelHookFinding is the single decision point for one record: either it
// is TOLERATED context (info event) or it becomes one observe-only incident for
// the matching XDR rule.
func (e *XDREngine) recordKernelHookFinding(event CoreKernelHookEvent, now time.Time) {
	path, deleted := kernelHookProcessEvidence(event.PID)
	_, parentComm := kernelHookParentInfo(event.PID)
	// TOLERATED: our own control process (own pid) and the privileged core
	// daemon (comm/executable identity; the exact core pid is not transported
	// over VGT3 today).
	coreProcess := kernelHookIsCoreComm(event.Comm) || (e != nil && e.selfPID > 0 && event.PID == e.selfPID)
	if KernelHookKindIsModule(event.Kind) {
		if tolerated, reason := kernelHookModuleTolerated(event.Comm, path, parentComm, coreProcess); tolerated {
			e.addKernelHookToleratedEvent(event, now, reason)
			return
		}
		e.recordKernelHookModuleFinding(event, path, parentComm, deleted, now)
		return
	}
	if KernelHookKindIsIoUring(event.Kind) {
		if tolerated, reason := kernelHookIoUringTolerated(event.Comm, coreProcess); tolerated {
			// `submit_req` is sampled per second; a tolerated process must not
			// produce an info event per second either.
			if event.Kind != KernelHookKindIoUringSubmit {
				e.addKernelHookToleratedEvent(event, now, reason)
			}
			return
		}
		unusual, trigger := kernelHookIoUringUnusual(event.Comm, path, parentComm, deleted)
		if !unusual {
			// An ordinary io_uring user with a resolved installation-managed (or
			// unknown but unremarkable) executable is not evidence by itself.
			if event.Kind != KernelHookKindIoUringSubmit {
				e.addKernelHookToleratedEvent(event, now, "ordinary io_uring user; no unusual lineage or executable evidence")
			}
			return
		}
		if event.Kind == KernelHookKindIoUringSubmit && !e.claimKernelHookSubmitWindow(event.PID, now) {
			// One submission-anomaly incident per process per minute is enough
			// evidence; the kernel keeps sampling the records.
			return
		}
		e.recordKernelHookIoUringFinding(event, path, parentComm, deleted, trigger, now)
	}
}

// recordKernelHookModuleFinding creates evidence first, then exactly one
// alert-only `XDR.LKM_LOAD` incident for an untrusted module load. No response is
// derived: the kernel hook is observe-only.
func (e *XDREngine) recordKernelHookModuleFinding(
	event CoreKernelHookEvent, path, parentComm string, deleted bool, now time.Time,
) {
	ruleID := "XDR.LKM_LOAD"
	eventKind := "xdr.lkm_load"
	eventType := "LKM_LOAD_OBSERVED"
	severity := "high"
	score := 120
	taintText := "none"
	if event.Kind == KernelHookKindModuleLoad || event.Kind == KernelHookKindLkmTaint {
		taintText = fmt.Sprintf("0x%x", event.DetailCode)
	}
	moduleText := kernelHookDetailText(event.Kind, []byte(event.Detail))
	summary := fmt.Sprintf(
		"Kernel LKM hook observed a module load outside the boot/package path: kind=%s pid=%d tgid=%d uid=%d comm=%s module=%s taint=%s path=%s parent=%s deleted_exe=%t",
		KernelHookKindName(event.Kind), event.PID, event.TGID, event.UID, event.Comm,
		moduleText, taintText, path, kernelHookOrNone(parentComm), deleted)
	e.recordKernelHookIncident(kernelHookIncidentInput{
		ruleID:    ruleID,
		eventKind: eventKind,
		eventType: eventType,
		severity:  severity,
		score:     score,
		categories: []string{
			"kernel", "kernel-module",
		},
		summary:   summary,
		sensor:    "kernel-kernel-hooks",
		actor:     fmt.Sprintf("uid:%d", event.UID),
		entityID:  fmt.Sprintf("pid:%d", event.TGID),
		target:    fmt.Sprintf("pid:%d:kind:%d:code:%d", event.PID, event.Kind, event.DetailCode),
		extraMeta: map[string]string{"family": "lkm", "module": moduleText, "taint": taintText},
	}, event, path, parentComm, deleted, now)
}

// recordKernelHookIoUringFinding creates the `XDR.IO_URING_ANOMALY` incident.
func (e *XDREngine) recordKernelHookIoUringFinding(
	event CoreKernelHookEvent, path, parentComm string, deleted bool, trigger string, now time.Time,
) {
	detailText := kernelHookDetailText(event.Kind, []byte(event.Detail))
	summary := fmt.Sprintf(
		"Kernel io_uring hook observed an unusual ring operation: kind=%s pid=%d tgid=%d uid=%d comm=%s detail=%s path=%s parent=%s deleted_exe=%t trigger=%s",
		KernelHookKindName(event.Kind), event.PID, event.TGID, event.UID, event.Comm,
		kernelHookDetailCodeText(event.Kind, event.DetailCode), path,
		kernelHookOrNone(parentComm), deleted, trigger)
	if event.Kind == KernelHookKindIoUringCreate || event.Kind == KernelHookKindIoUringRegister {
		summary = summary + "; flags=" + detailText
	}
	e.recordKernelHookIncident(kernelHookIncidentInput{
		ruleID:     "XDR.IO_URING_ANOMALY",
		eventKind:  "xdr.io_uring_anomaly",
		eventType:  "IO_URING_ANOMALY_OBSERVED",
		severity:   "warning",
		score:      90,
		categories: []string{"kernel"},
		summary:    summary,
		sensor:     "kernel-kernel-hooks",
		actor:      fmt.Sprintf("uid:%d", event.UID),
		entityID:   fmt.Sprintf("pid:%d", event.TGID),
		target:     fmt.Sprintf("pid:%d:kind:%d:code:%d", event.PID, event.Kind, event.DetailCode),
		extraMeta:  map[string]string{"family": "io_uring", "trigger": trigger, "detail": detailText},
	}, event, path, parentComm, deleted, now)
}

// kernelHookIncidentInput groups the per-rule constants of one incident.
type kernelHookIncidentInput struct {
	ruleID     string
	eventKind  string
	eventType  string
	severity   string
	score      int
	categories []string
	summary    string
	sensor     string
	actor      string
	entityID   string
	target     string
	extraMeta  map[string]string
}

// recordKernelHookIncident writes the evidence record first, then the
// alert-only incident, exactly like the other V6.3.0 sensor families.
func (e *XDREngine) recordKernelHookIncident(
	input kernelHookIncidentInput, event CoreKernelHookEvent,
	path, parentComm string, deleted bool, now time.Time,
) {
	if e == nil {
		return
	}
	outcome := "observed only; the io_uring/LKM kernel hooks are observe-only and no active response was derived"
	if e.state != nil {
		evidenceErr := e.state.RecordEvidence(EvidenceRecord{
			Severity: input.severity, Kind: input.eventKind, Source: "kernel",
			Message: "Kernel hook evidence recorded before any response: " + input.summary,
			Target:  input.target, Time: now,
		})
		if evidenceErr != nil {
			outcome = "observed only; mandatory evidence commit failed, incident recorded without response: " + evidenceErr.Error()
		}
	}
	metadata := map[string]string{
		"kind":         KernelHookKindName(event.Kind),
		"kind_code":    fmt.Sprintf("%d", event.Kind),
		"action":       KernelHookActionName(event.Action),
		"detail_code":  fmt.Sprintf("%d", event.DetailCode),
		"pid":          fmt.Sprintf("%d", event.PID),
		"tgid":         fmt.Sprintf("%d", event.TGID),
		"uid":          fmt.Sprintf("%d", event.UID),
		"loader_path":  path,
		"parent_comm":  parentComm,
		"deleted_exe":  fmt.Sprintf("%t", deleted),
		"ts_ns":        fmt.Sprintf("%d", event.TsNS),
		"observe_only": "true",
	}
	for key, value := range input.extraMeta {
		metadata[key] = value
	}
	node := AttackStoryNode{
		NodeID:     fmt.Sprintf("kernel-hooks-%d-%d", event.PID, now.UnixNano()),
		Timestamp:  now,
		Sensor:     input.sensor,
		Category:   "kernel",
		EventType:  input.eventType,
		EntityID:   input.entityID,
		Actor:      input.actor,
		Severity:   input.severity,
		Confidence: 90,
		CausalEdge: EdgeRootCause,
		EventUUID:  randomID(),
		Metadata:   metadata,
	}
	node.Digest = node.ComputeNodeDigest()
	incident := XDRIncident{
		ID: randomID(), Time: now, Severity: input.severity, Score: input.score,
		PID: event.PID, UID: event.UID, Process: event.Comm,
		RuleIDs: []string{input.ruleID}, Categories: input.categories,
		Summary: input.summary, Decision: "alert", Action: "none", Outcome: outcome,
		ExecutionChainID: node.NodeID, AttackStory: []AttackStoryNode{node},
		EvidenceRoot: node.Digest,
	}
	e.appendIncident(incident)
	if e.state != nil {
		e.state.AddEvent(Event{Time: now, Severity: input.severity, Kind: input.eventKind, Source: "kernel",
			Message: input.summary + "; " + outcome, Target: fmt.Sprintf("pid:%d", event.PID)})
	}
}

// kernelHookModuleTolerated is the single TOLERATED policy enforcement point for
// module-load records. `path` is the loader executable (`unknown` when the
// process already exited), `parentComm` the parent task name ("" when unknown).
func kernelHookModuleTolerated(comm, path, parentComm string, coreProcess bool) (bool, string) {
	if coreProcess {
		return true, "own privileged core process"
	}
	comm = strings.ToLower(strings.TrimSpace(comm))
	parentComm = strings.ToLower(strings.TrimSpace(parentComm))
	if _, ok := kernelHooksCoreComms[comm]; ok {
		return true, "own privileged core process"
	}
	if parentComm != "" {
		if _, ok := kernelHooksToleratedModuleParents[parentComm]; ok {
			return true, "boot, package or module-tooling parent"
		}
	}
	if _, tool := kernelHooksModuleToolComms[comm]; tool {
		if kernelHookPathUnderAny(path, kernelHooksManagedPathPrefixes) {
			return true, "module tooling from an installation-managed path"
		}
		// Without a resolvable executable a bare `insmod` could be a copy in
		// /tmp; keep it untrusted rather than guessing.
		return false, ""
	}
	if _, ok := kernelHooksToleratedModuleComms[comm]; ok {
		if kernelHookPathUnderAny(path, kernelHooksTempPathPrefixes) {
			// A binary merely named like a package tool but executing from a
			// writable drop root is not the package tool.
			return false, ""
		}
		return true, "package manager or module tooling"
	}
	return false, ""
}

// kernelHookIoUringTolerated is the TOLERATED policy for the io_uring family.
func kernelHookIoUringTolerated(comm string, coreProcess bool) (bool, string) {
	if coreProcess {
		return true, "own privileged core process"
	}
	comm = strings.ToLower(strings.TrimSpace(comm))
	if _, ok := kernelHooksCoreComms[comm]; ok {
		return true, "own privileged core process"
	}
	if _, ok := kernelHooksToleratedIoUringComms[comm]; ok {
		return true, "known legitimate io_uring consumer"
	}
	return false, ""
}
