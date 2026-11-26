// STATUS: DIAMANT VGT SUPREME
package main

import (
	"errors"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// V6.3.0 AP-3: XDR integration of the 8-domain cross-view verifier.
//
// Maps the verifier's contradictions to observe-only XDR evidence:
//
//	HIDDEN_PROG/HIDDEN_MAP/HIDDEN_LINK -> XDR.HIDDEN_BPF_PROG/MAP/LINK (critical)
//	LINK_TAMPER                        -> XDR.BPF_LINK_TAMPER (critical)
//	HIDDEN_SOCKET                      -> XDR.HIDDEN_SOCKET (high)
//	PORTLESS_RAW_TAP                   -> XDR.PORTLESS_RAW_TAP (high)
//	HIDDEN_PROCESS                     -> XDR.HIDDEN_PROCESS (high)
//	LKM_HIDDEN                         -> XDR.LKM_HIDDEN (high)
//	FTRACE_HOOK                        -> XDR.FTRACE_HOOK_ANOMALY (high)
//	LIBRARY_MISMATCH                   -> XDR.LIBRARY_CROSSVIEW (high)
//	PIN_MISMATCH                       -> XDR.BPF_PIN_TAMPER (critical)
//	RAW_TAP_FILTER                     -> tolerated policy, escalated only for a
//	                                      writable/deleted executable
//
// Every rule is evidence-first (RecordEvidence before the incident; an evidence
// failure is carried into the incident outcome), emits an attack-story node and
// sets `Decision:"alert"` / `Action:"none"`. The verifier never derives an active
// response: no kill path, no containment, no change to `combineMatches` are
// introduced here, and a contradiction alone can never authorise a kill.
//
// TOLERATED raw-tap policy (mirrors the documented TAP_ALLOWLIST): tcpdump,
// dumpcap, dhclient, NetworkManager, systemd-networkd, lldpd, keepalived,
// suricata, nmap, wireshark and tshark, plus installation-managed executable
// paths under /usr/bin, /usr/sbin, /usr/local/{bin,sbin}, /opt and /usr/libexec
// are observations, never incidents. A non-allowlisted tap whose executable
// resolves under /tmp, /var/tmp, /dev/shm, /home, /run/user or was deleted after
// being mapped is the BPFDoor signature and becomes XDR.PORTLESS_RAW_TAP.
// An unattributed tap (pid unresolved) is an observation: no verdict is invented
// from a socket inode alone.
//
// A core without the CROSS_VIEW_* family is a capability fact: an info event,
// never an XDR degradation.

const (
	// crossViewStatusInterval is the status+report cadence.
	crossViewStatusInterval = 15 * time.Second
	// crossViewDrainInterval is the event drain cadence.
	crossViewDrainInterval = time.Second
	// crossViewDedupeTTL bounds the record dedupe window.
	crossViewDedupeTTL = 10 * time.Minute
	// crossViewSeenLimit bounds the dedupe bookkeeping map.
	crossViewSeenLimit = 4096
	// crossViewOverflowMinGap rate-limits ring/queue overflow telemetry.
	crossViewOverflowMinGap = 5 * time.Minute
	// crossViewPathMaxBytes bounds one /proc/<pid>/exe readlink result.
	crossViewPathMaxBytes = 512
	// crossViewReportReasonBytes bounds operator-facing reason text.
	crossViewReportReasonBytes = 240
	// crossViewEvidenceTargetBytes bounds the evidence/incident target token.
	crossViewEvidenceTargetBytes = 160
)

// crossViewToleratedRawTaps is the TOLERATED raw-tap tool list. The comparison
// runs on the lowercased task comm and on the lowercased executable basename.
var crossViewToleratedRawTaps = map[string]struct{}{
	"tcpdump": {}, "dumpcap": {}, "dhclient": {}, "networkmanager": {},
	"systemd-networkd": {}, "lldpd": {}, "keepalived": {}, "suricata": {},
	"nmap": {}, "wireshark": {}, "tshark": {},
}

// pollCrossView runs one status/report/drain cycle and returns the next due time.
// The XDR loop ticks every 100 ms; this returns the 1 s drain cadence and
// performs the status+report query only when the 15 s cadence is due. Nothing
// here changes enforcement: there is no arm and no response request.
func (e *XDREngine) pollCrossView(runtime RuntimeSettings, now time.Time, retryAfter time.Time) time.Time {
	if e == nil || e.crossViewCore == nil || !runtime.XDREnabled || now.Before(retryAfter) {
		return retryAfter
	}
	if e.crossViewStatusDue(now) {
		status, statusErr := e.crossViewCore.CrossViewStatus()
		e.consumeCrossViewStatus(status, statusErr, now)
		if statusErr == nil {
			report, reportErr := e.crossViewCore.CrossViewReport()
			e.consumeCrossViewReport(report, reportErr, now)
		}
	}
	events, dropped, drainErr := e.crossViewCore.CrossViewEvents()
	if drainErr != nil {
		if errors.Is(drainErr, ErrCrossViewUnavailable) {
			e.consumeCrossViewStatus(CoreCrossViewStatus{}, ErrCrossViewUnavailable, now)
		} else {
			e.setCrossViewError("event drain failed: " + boundedStyxText(drainErr))
		}
		return now.Add(crossViewDrainInterval)
	}
	e.clearCrossViewDrainError()
	e.consumeCrossViewEvents(events, dropped, now)
	return now.Add(crossViewDrainInterval)
}

func (e *XDREngine) crossViewStatusDue(now time.Time) bool {
	e.crossViewMu.Lock()
	defer e.crossViewMu.Unlock()
	return e.crossViewStatusAt.IsZero() || now.Sub(e.crossViewStatusAt) >= crossViewStatusInterval
}

func (e *XDREngine) setCrossViewError(reason string) {
	if e == nil || reason == "" {
		return
	}
	e.crossViewMu.Lock()
	e.crossViewStatusErr = reason
	e.crossViewMu.Unlock()
}

// clearCrossViewDrainError forgets only a drain-origin error; a persistent
// status/report failure is cleared by the next successful query.
func (e *XDREngine) clearCrossViewDrainError() {
	if e == nil {
		return
	}
	e.crossViewMu.Lock()
	if strings.HasPrefix(e.crossViewStatusErr, "event drain failed:") {
		e.crossViewStatusErr = ""
	}
	e.crossViewMu.Unlock()
}

// consumeCrossViewStatus projects one status answer and records capability
// transitions as facts (info events), never as an XDR degradation.
func (e *XDREngine) consumeCrossViewStatus(status CoreCrossViewStatus, statusErr error, now time.Time) {
	if e == nil {
		return
	}
	e.crossViewMu.Lock()
	wasKnown := e.crossViewCapabilityKnown
	firstObservation := e.crossViewStatusAt.IsZero()
	switch {
	case statusErr == nil:
		e.crossViewStatus = status
		e.crossViewStatusAt = now
		e.crossViewStatusErr = ""
		e.crossViewCapabilityKnown = true
	case errors.Is(statusErr, ErrCrossViewUnavailable):
		e.crossViewStatus = CoreCrossViewStatus{}
		e.crossViewStatusAt = now
		e.crossViewStatusErr = ""
		e.crossViewCapabilityKnown = false
	default:
		e.crossViewStatusAt = now
		e.crossViewStatusErr = "status query failed: " + boundedStyxText(statusErr)
	}
	known := e.crossViewCapabilityKnown
	e.crossViewMu.Unlock()
	if e.state == nil {
		return
	}
	switch {
	case !known && (wasKnown || firstObservation):
		e.state.AddEvent(Event{Severity: "info", Kind: "xdr.cross_view_capability_missing", Source: "kernel",
			Message: "The privileged core does not advertise the CROSS_VIEW_* command family; the 8-domain cross-view verifier is unavailable (capability fact, not an XDR degradation)"})
	case known && !wasKnown:
		e.state.AddEvent(Event{Severity: "info", Kind: "xdr.cross_view_capability_available", Source: "kernel",
			Message: "8-domain cross-view verifier is available; contradictions are ingested as observe-only evidence"})
	}
}

// consumeCrossViewReport records bound/integrity changes of the latest forced
// scan. A degraded bounds token means at least one view was truncated or
// refused, which is reported as a bounded warning (rate-limited by content).
func (e *XDREngine) consumeCrossViewReport(reportText string, reportErr error, now time.Time) {
	if e == nil {
		return
	}
	if reportErr != nil {
		e.setCrossViewError("report query failed: " + boundedStyxText(reportErr))
		return
	}
	e.crossViewMu.Lock()
	if strings.HasPrefix(e.crossViewStatusErr, "report query failed:") {
		e.crossViewStatusErr = ""
	}
	e.crossViewMu.Unlock()
	report, err := parseCoreCrossViewReport(reportText)
	if err != nil {
		e.setCrossViewError("report parse failed: " + boundedStyxText(err))
		return
	}
	if e.state == nil {
		return
	}
	reason := ""
	if !report.BoundsOK {
		reason = "bounds_degraded"
	}
	if len(report.Reasons) > 0 {
		reason = strings.Join(report.Reasons, ",")
	}
	if reason == "" || !e.claimCrossViewSeen("report:"+reason, now, crossViewDedupeTTL) {
		return
	}
	severity := "info"
	kind := "xdr.cross_view_report_bounded"
	message := "Cross-view scan completed inside its documented bounds"
	if !report.BoundsOK {
		severity = "warning"
		kind = "xdr.cross_view_bounds_degraded"
		message = "Cross-view scan was truncated or a required view was refused; the report range is reduced (observe-only)"
	}
	if len(report.Reasons) > 0 {
		message = message + "; reasons: " + crossViewBounded(strings.Join(report.Reasons, ","), crossViewReportReasonBytes)
	}
	e.state.AddEvent(Event{Severity: severity, Kind: kind, Source: "kernel", Message: message})
}

// consumeCrossViewEvents turns one bounded verifier batch into evidence and
// observe-only incidents.
func (e *XDREngine) consumeCrossViewEvents(events []CoreCrossViewEvent, dropped uint64, now time.Time) {
	if e == nil {
		return
	}
	for _, event := range events {
		if !e.claimCrossViewRecord(event, now) {
			continue
		}
		switch event.Kind {
		case CrossViewKindRawTapFilter:
			e.recordCrossViewRawTap(event, now)
		case CrossViewKindPortlessRawTap, CrossViewKindHiddenSocket, CrossViewKindHiddenProg,
			CrossViewKindHiddenMap, CrossViewKindHiddenLink, CrossViewKindLinkTamper,
			CrossViewKindHiddenProcess, CrossViewKindLKMHidden, CrossViewKindFtraceHook,
			CrossViewKindLibraryMismatch, CrossViewKindPinMismatch:
			e.recordCrossViewContradiction(event, now)
		default:
			if e.state != nil {
				e.state.AddEvent(Event{Time: now, Severity: "info", Kind: "xdr.cross_view_unknown_kind", Source: "kernel",
					Message: fmt.Sprintf("Cross-view record with an unhandled kind=%d domain=%d ignored (transport already validated it)",
						event.Kind, event.Domain)})
			}
		}
	}
	if dropped > 0 && e.state != nil {
		e.crossViewMu.Lock()
		last := e.crossViewLastOverflow
		if last.IsZero() || now.Sub(last) >= crossViewOverflowMinGap {
			e.crossViewLastOverflow = now
			e.crossViewMu.Unlock()
			e.state.AddEvent(Event{Severity: "high", Kind: "xdr.cross_view_overflow", Source: "kernel",
				Message: fmt.Sprintf("Cross-view verifier dropped %d record(s); contradiction coverage is reduced for this window", dropped)})
		} else {
			e.crossViewMu.Unlock()
		}
	}
}

// crossViewRawTapTolerated is the single TOLERATED policy enforcement point for
// tap observations. It only classifies; it never suppresses the evidence itself.
func (e *XDREngine) crossViewRawTapTolerated(event CoreCrossViewEvent) (bool, string) {
	if e != nil && e.selfPID > 0 && event.PID == e.selfPID {
		return true, "own control process"
	}
	comm := strings.ToLower(strings.TrimSpace(event.Comm))
	path := crossViewTapOwnerPath(event)
	base := ""
	if path != "unknown" {
		base = strings.ToLower(filepath.Base(path))
	}
	if _, ok := crossViewToleratedRawTaps[comm]; ok {
		return true, "tolerated raw-tap comm"
	}
	if base != "" {
		if _, ok := crossViewToleratedRawTaps[base]; ok {
			return true, "tolerated raw-tap executable"
		}
	}
	if path != "unknown" && crossViewPathUnderAny(path, crossViewToleratedPathPrefixes) {
		return true, "installation-managed executable path"
	}
	return false, ""
}

func crossViewSuspiciousExecPath(path string) bool {
	if path == "" || path == "unknown" {
		return false
	}
	if strings.HasSuffix(path, " (deleted)") {
		return true
	}
	return crossViewPathUnderAny(path, crossViewSuspiciousExecRoots)
}

// recordCrossViewRawTap applies the TOLERATED policy to one tap observation.
// Only a non-allowlisted tap whose executable lives in a writable drop root (or
// was deleted) escalates to XDR.PORTLESS_RAW_TAP; everything else is an info
// event, and an unattributed tap (pid unresolved) is never escalated from an
// inode alone.
func (e *XDREngine) recordCrossViewRawTap(event CoreCrossViewEvent, now time.Time) {
	path := crossViewTapOwnerPath(event)
	if tolerated, reason := e.crossViewRawTapTolerated(event); tolerated {
		if e.state != nil {
			e.state.AddEvent(Event{Time: now, Severity: "info", Kind: "xdr.cross_view_raw_tap_tolerated", Source: "kernel",
				Message: fmt.Sprintf("Tolerated raw packet tap observed: pid=%d uid=%d comm=%s path=%s (%s)",
					event.PID, event.UID, event.Comm, path, reason),
				Target: crossViewTarget(event)})
		}
		return
	}
	if event.PID == 0 || path == "unknown" {
		if e.state != nil && e.claimCrossViewSeen(fmt.Sprintf("unattrib-tap:%d:%s", event.UID, event.Comm), now, crossViewDedupeTTL) {
			e.state.AddEvent(Event{Time: now, Severity: "info", Kind: "xdr.cross_view_raw_tap_unattributed", Source: "kernel",
				Message: fmt.Sprintf("Raw packet tap observed without a resolvable owner: uid=%d ino=%d comm=%s; no verdict is derived from the socket identity alone",
					event.UID, event.Ino, event.Comm),
				Target: crossViewTarget(event)})
		}
		return
	}
	if !crossViewSuspiciousExecPath(path) {
		if e.state != nil {
			e.state.AddEvent(Event{Time: now, Severity: "info", Kind: "xdr.cross_view_raw_tap_observed", Source: "kernel",
				Message: fmt.Sprintf("Raw packet tap observed outside the TOLERATED list but from a system-managed path: pid=%d uid=%d comm=%s path=%s (observe-only)",
					event.PID, event.UID, event.Comm, path),
				Target: crossViewTarget(event)})
		}
		return
	}
	// The BPFDoor signature: a filtered packet tap from a writable/deleted path.
	e.recordCrossViewContradiction(event, now)
}

// recordCrossViewContradiction creates evidence first, then exactly one
// alert-only incident. No response is derived and no kill signal is produced.
func (e *XDREngine) recordCrossViewContradiction(event CoreCrossViewEvent, now time.Time) {
	if e == nil || e.state == nil {
		return
	}
	ruleID, eventKind, eventType, severity, score, categories := crossViewRuleForKind(event.Kind)
	if event.Severity >= CrossViewSeverityCritical {
		severity = "critical"
		if score < 140 {
			score = 140
		}
	}
	if event.DetailCode == CrossViewDetailNameHeuristic {
		// A name hit alone is heuristic evidence, not a proven gap.
		severity = "warning"
		score = 60
	}
	path := crossViewProcessPath(uint32(event.PID))
	summary := fmt.Sprintf(
		"Cross-view contradiction: domain=%s kind=%s severity=%s pid=%d uid=%d dev=%d ino=%d detail=%d comm=%s exec_path=%s",
		CrossViewDomainName(event.Domain), CrossViewKindName(event.Kind), severity,
		event.PID, event.UID, event.Dev, event.Ino, event.DetailCode, event.Comm, path)
	summary = crossViewBounded(summary, crossViewReportReasonBytes*2)
	evidenceErr := e.state.RecordEvidence(EvidenceRecord{
		Severity: severity, Kind: eventKind, Source: "kernel",
		Message: "Cross-view verifier evidence recorded before any response: " + summary,
		Target:  crossViewTarget(event), Time: now,
	})
	outcome := "observed only; the cross-view verifier is observe-only and no active response was derived"
	if evidenceErr != nil {
		outcome = "observed only; mandatory evidence commit failed, incident recorded without response: " + evidenceErr.Error()
	}
	node := AttackStoryNode{
		NodeID:     fmt.Sprintf("crossview-%d-%d", event.PID, now.UnixNano()),
		Timestamp:  now,
		Sensor:     "kernel-cross-view",
		Category:   "kernel",
		EventType:  eventType,
		EntityID:   crossViewTarget(event),
		Actor:      fmt.Sprintf("uid:%d", event.UID),
		Severity:   severity,
		Confidence: 90,
		CausalEdge: EdgeRootCause,
		EventUUID:  randomID(),
		Metadata: map[string]string{
			"domain":       CrossViewDomainName(event.Domain),
			"kind":         CrossViewKindName(event.Kind),
			"detail_code":  strconv.FormatUint(uint64(event.DetailCode), 10),
			"pid":          strconv.Itoa(event.PID),
			"uid":          strconv.FormatUint(uint64(event.UID), 10),
			"dev":          strconv.FormatUint(uint64(event.Dev), 10),
			"ino":          strconv.FormatUint(event.Ino, 10),
			"ts_ns":        strconv.FormatUint(event.TsNS, 10),
			"comm":         event.Comm,
			"exec_path":    path,
			"observe_only": "true",
		},
	}
	if event.Kind == CrossViewKindLKMHidden {
		// Module records carry the raw kernel taint word in `dev` (documented
		// AP-3 field reuse); decode O/E/forced bits for the operator view.
		node.Metadata["taint_raw"] = fmt.Sprintf("0x%x", event.Dev)
		node.Metadata["module_detail"] = strconv.FormatUint(uint64(event.DetailCode&crossViewModuleDetail), 10)
		if event.Dev&crossViewTaintMask != 0 {
			node.Metadata["taint_forced_or_oot"] = "true"
		}
	}
	node.Digest = node.ComputeNodeDigest()
	incident := XDRIncident{
		ID: randomID(), Time: now, Severity: severity, Score: score,
		PID: event.PID, UID: event.UID, Process: event.Comm, Executable: path,
		RuleIDs: []string{ruleID}, Categories: categories,
		Summary: summary, Decision: "alert", Action: "none", Outcome: outcome,
		ExecutionChainID: node.NodeID, AttackStory: []AttackStoryNode{node},
		EvidenceRoot: node.Digest,
	}
	e.appendIncident(incident)
	e.recordLocalSecCritMirror("cross-view", CrossViewKindName(event.Kind), now)
	e.state.AddEvent(Event{Time: now, Severity: severity, Kind: eventKind, Source: "kernel",
		Message: summary + "; " + outcome, Target: crossViewTarget(event)})
}

// crossViewRuleForKind is the closed kind â†’ rule/severity/category mapping.
func crossViewRuleForKind(kind uint8) (ruleID, eventKind, eventType, severity string, score int, categories []string) {
	switch kind {
	case CrossViewKindHiddenProg:
		return "XDR.HIDDEN_BPF_PROG", "xdr.hidden_bpf_prog", "BPF_PROG_ID_GAP", "critical", 150, []string{"kernel", "defense-evasion"}
	case CrossViewKindHiddenMap:
		return "XDR.HIDDEN_BPF_MAP", "xdr.hidden_bpf_map", "BPF_MAP_ID_GAP", "critical", 150, []string{"kernel", "defense-evasion"}
	case CrossViewKindHiddenLink:
		return "XDR.HIDDEN_BPF_LINK", "xdr.hidden_bpf_link", "BPF_LINK_ID_GAP", "critical", 150, []string{"kernel", "defense-evasion"}
	case CrossViewKindLinkTamper:
		return "XDR.BPF_LINK_TAMPER", "xdr.bpf_link_tamper", "BPF_LINK_PROGRAM_TAMPER", "critical", 140, []string{"kernel", "defense-evasion"}
	case CrossViewKindHiddenSocket:
		return "XDR.HIDDEN_SOCKET", "xdr.hidden_socket", "SOCKET_VIEW_GAP", "high", 110, []string{"kernel", "defense-evasion"}
	case CrossViewKindPortlessRawTap:
		return "XDR.PORTLESS_RAW_TAP", "xdr.portless_raw_tap", "RAW_PACKET_TAP", "high", 120, []string{"kernel", "defense-evasion"}
	case CrossViewKindHiddenProcess:
		return "XDR.HIDDEN_PROCESS", "xdr.hidden_process", "PROCESS_VIEW_GAP", "high", 100, []string{"kernel", "defense-evasion"}
	case CrossViewKindLKMHidden:
		return "XDR.LKM_HIDDEN", "xdr.lkm_hidden", "MODULE_VIEW_GAP", "high", 130, []string{"kernel", "defense-evasion"}
	case CrossViewKindFtraceHook:
		return "XDR.FTRACE_HOOK_ANOMALY", "xdr.ftrace_hook_anomaly", "FTRACE_HOOK_ENABLED", "high", 115, []string{"kernel", "defense-evasion"}
	case CrossViewKindLibraryMismatch:
		return "XDR.LIBRARY_CROSSVIEW", "xdr.library_crossview", "LIBRARY_UNOWNED", "high", 95, []string{"kernel", "persistence"}
	case CrossViewKindPinMismatch:
		return "XDR.BPF_PIN_TAMPER", "xdr.bpf_pin_tamper", "BPF_PIN_MISMATCH", "critical", 140, []string{"kernel", "defense-evasion"}
	case CrossViewKindRawTapFilter:
		return "XDR.PORTLESS_RAW_TAP", "xdr.portless_raw_tap", "RAW_PACKET_TAP", "high", 100, []string{"kernel", "defense-evasion"}
	default:
		return "XDR.CROSS_VIEW_ANOMALY", "xdr.cross_view_anomaly", "CROSS_VIEW_RECORD", "warning", 40, []string{"kernel"}
	}
}
