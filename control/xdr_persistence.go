// STATUS: DIAMANT VGT SUPREME
package main

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

// V6.3.0 AP-5: XDR integration of the persistence/peripheral guard.
//
// The privileged core resolves the watched linker/PAM/systemd/udev/auth/shell
// roots, the protected executables (`sshd`/`sudo`/`su`/`login`/`curl`), the
// user secret stores and the desktop peripherals, and cross-checks mapped
// libraries against the parsed package database. This file turns the bounded
// evidence into eight observe-only rules:
//
//	XDR.LD_PRELOAD_INTEGRITY   linker-path write/drift by a non-package writer (110)
//	XDR.LINKER_HOOK            foreign library mapped into a protected executable (120)
//	XDR.PERSISTENCE_ENTRY_DRIFT systemd/udev/PAM/authorized_keys/shell drift (100)
//	XDR.PERIPHERAL_BG_ACCESS   camera/mic/capture-socket access (90)
//	XDR.EVDEV_KEYLOG_PROBE     keyboard-sniffer class evdev access (100)
//	XDR.MEMORY_SCRAPE_PROBE    process_vm/ ptrace access across uids (110)
//	XDR.SECRET_STORE_ACCESS    secret store opened by a non-owner tool (90)
//
// Every rule is evidence-first: `RecordEvidence` is committed before the
// incident, the incident is `Decision:"alert"`, `Action:"none"`, never
// kill-eligible, and no response path is derived. `PERSIST_BASELINE` markers are
// informational. The TOLERATED policy below is enforced in the control plane
// (never silently in the kernel): package managers, the core/control itself,
// systemd/udev boot writers and desktop-session owners of their own devices.
//
// Correlation honesty: the core reports `idlehint=unavailable` because logind's
// IdleHint is a D-Bus property, not a file. A peripheral finding therefore never
// claims `OBSERVED` lock state: session-inactive evidence is `TEMPORAL`, and a
// missing session view is an explicit `NONE` limitation. The same `NONE`
// applies to library ownership when the package database is unsupported.

const (
	// persistenceStatusInterval is the status/baseline-verification cadence.
	persistenceStatusInterval = 10 * time.Second
	// persistenceDrainInterval is the ring drain cadence.
	persistenceDrainInterval = time.Second
	// persistenceDedupeTTL bounds the kernel-record dedupe window.
	persistenceDedupeTTL = 5 * time.Minute
	// persistenceRateLimitWindow is the "one incident per rule per pid+class"
	// window; independent events with a different class still surface.
	persistenceRateLimitWindow = 5 * time.Minute
	// persistenceSeenLimit bounds the dedupe/rate-limit bookkeeping map.
	persistenceSeenLimit = 4096
	// persistenceOverflowMinGap rate-limits ring-drop telemetry.
	persistenceOverflowMinGap = 5 * time.Minute
	// persistenceProcReadBytes bounds every /proc enrichment read.
	persistenceProcReadBytes = 8192
	// persistenceReasonBytes bounds operator-facing reason text.
	persistenceReasonBytes = 240
	// persistenceBaselineSentinelKey marks the one-shot PERSIST_BASELINE request
	// inside the existing `persistenceSeen` map (xdr.go is owned by the
	// integration seam and must not grow a new field for this).
	persistenceBaselineSentinelKey = "boot:persistence-baseline-requested"
)

// Persistence rule ids (stable, observe-only).
const (
	PersistenceRuleLDPreload  = "XDR.LD_PRELOAD_INTEGRITY"
	PersistenceRuleLinker     = "XDR.LINKER_HOOK"
	PersistenceRuleDrift      = "XDR.PERSISTENCE_ENTRY_DRIFT"
	PersistenceRulePeripheral = "XDR.PERIPHERAL_BG_ACCESS"
	PersistenceRuleEvdev      = "XDR.EVDEV_KEYLOG_PROBE"
	PersistenceRuleMemory     = "XDR.MEMORY_SCRAPE_PROBE"
	PersistenceRuleSecret     = "XDR.SECRET_STORE_ACCESS"
)

// Correlation qualities (GIEF-compatible vocabulary, no guess).
const (
	persistenceQualityObserved = "OBSERVED"
	persistenceQualityTemporal = "TEMPORAL"
	persistenceQualityNone     = "NONE"
)

// persistenceCore is the subset of the privileged client the AP-5 contract needs.
type persistenceCore interface {
	PersistenceStatus() (CorePersistenceStatus, error)
	PersistenceEvents() ([]CorePersistenceEvent, uint64, error)
	PersistenceSet(enabled bool) error
	PersistenceBaseline() (string, error)
}

// pollPersistence runs one status + drain cycle and returns the next due time.
// The XDR loop ticks every 100 ms; this returns the 1 s drain cadence and
// performs the 10 s status sample only when it is due. It arms the observe-only
// guard once, triggers one `PERSIST_BASELINE` after the guard is armed (the core
// also captures a baseline at load; the explicit request re-verifies and makes
// the reference point operator-visible) and never derives a response action.
func (e *XDREngine) pollPersistence(runtime RuntimeSettings, now time.Time, retryAfter time.Time) time.Time {
	if e == nil || e.persistenceCore == nil || !runtime.XDREnabled || now.Before(retryAfter) {
		return retryAfter
	}
	e.persistenceMu.Lock()
	statusAt := e.persistenceStatusAt
	known := e.persistenceCapabilityKnown
	armedRequested := e.persistenceArmedRequested
	_, baselineRequested := e.persistenceSeen[persistenceBaselineSentinelKey]
	e.persistenceMu.Unlock()

	if statusAt.IsZero() || now.Sub(statusAt) >= persistenceStatusInterval {
		status, statusErr := e.persistenceCore.PersistenceStatus()
		e.consumePersistenceStatus(status, statusErr, now)
		e.persistenceMu.Lock()
		known = e.persistenceCapabilityKnown
		armedRequested = e.persistenceArmedRequested
		e.persistenceMu.Unlock()
		if statusErr == nil {
			if !status.Enabled && !armedRequested {
				// Arm once. The core refuses an armed-but-blind guard; the error is
				// a capability/reason fact surfaced in the status, not a panic.
				e.persistenceMu.Lock()
				e.persistenceArmedRequested = true
				e.persistenceMu.Unlock()
				if err := e.persistenceCore.PersistenceSet(true); err != nil {
					e.persistenceMu.Lock()
					e.persistenceArmedRequested = false
					e.persistenceStatusErr = "arm request failed: " + boundedStyxText(err)
					e.persistenceMu.Unlock()
				}
			}
			if status.Enabled && !baselineRequested {
				e.persistenceMu.Lock()
				if e.persistenceSeen == nil {
					e.persistenceSeen = make(map[string]time.Time)
				}
				_, alreadyRequested := e.persistenceSeen[persistenceBaselineSentinelKey]
				e.persistenceSeen[persistenceBaselineSentinelKey] = now.Add(100 * 365 * 24 * time.Hour)
				e.persistenceMu.Unlock()
				if !alreadyRequested {
					if baseline, err := e.persistenceCore.PersistenceBaseline(); err != nil {
						e.persistenceMu.Lock()
						delete(e.persistenceSeen, persistenceBaselineSentinelKey)
						e.persistenceStatusErr = "baseline request failed: " + boundedStyxText(err)
						e.persistenceMu.Unlock()
					} else if e.state != nil {
						e.state.AddEvent(Event{Time: now, Severity: "info", Kind: "xdr.persistence_baseline",
							Source: "kernel", Message: "Persistence integrity baseline verified and re-captured: " + persistenceBoundedText(baseline, persistenceReasonBytes)})
					}
				}
			}
		}
	}
	if known {
		events, dropped, drainErr := e.persistenceCore.PersistenceEvents()
		if drainErr != nil {
			if errors.Is(drainErr, ErrPersistenceUnavailable) {
				e.consumePersistenceStatus(CorePersistenceStatus{}, ErrPersistenceUnavailable, now)
			} else {
				e.persistenceMu.Lock()
				e.persistenceStatusErr = "event drain failed: " + boundedStyxText(drainErr)
				e.persistenceMu.Unlock()
			}
			return now.Add(persistenceDrainInterval)
		}
		e.persistenceMu.Lock()
		if strings.HasPrefix(e.persistenceStatusErr, "event drain failed:") {
			e.persistenceStatusErr = ""
		}
		e.persistenceMu.Unlock()
		e.consumePersistenceEvents(events, dropped, now)
	}
	return now.Add(persistenceDrainInterval)
}

// consumePersistenceStatus stores the honest sample and reports capability
// transitions. An absent command family is a fact (info), not an XDR outage.
func (e *XDREngine) consumePersistenceStatus(status CorePersistenceStatus, statusErr error, now time.Time) {
	if e == nil {
		return
	}
	e.persistenceMu.Lock()
	wasKnown := e.persistenceCapabilityKnown
	switch {
	case statusErr == nil:
		e.persistenceStatus = status
		e.persistenceStatusAt = now
		e.persistenceStatusErr = ""
		e.persistenceCapabilityKnown = true
	case errors.Is(statusErr, ErrPersistenceUnavailable):
		e.persistenceCapabilityKnown = false
		e.persistenceStatus = CorePersistenceStatus{}
		// Keep the sample timestamp on a capability-missing answer: the 10 s
		// status cadence must not turn into a 100 ms query storm against a core
		// that simply does not speak this family.
		e.persistenceStatusAt = now
		e.persistenceStatusErr = ""
	default:
		e.persistenceStatusErr = "status query failed: " + boundedStyxText(statusErr)
		e.persistenceStatusAt = now
	}
	known := e.persistenceCapabilityKnown
	e.persistenceMu.Unlock()
	if e.state == nil {
		return
	}
	switch {
	case !known && wasKnown:
		e.state.AddEvent(Event{Severity: "info", Kind: "xdr.persistence_capability_missing", Source: "kernel",
			Message: "The privileged core no longer advertises the PERSIST_GUARD_* command family; persistence/peripheral evidence is unavailable (capability fact, not an XDR degradation)"})
	case known && !wasKnown:
		e.state.AddEvent(Event{Severity: "info", Kind: "xdr.persistence_capability_available", Source: "kernel",
			Message: "Persistence/peripheral guard is available; linker/PAM/systemd/device/secret observations are ingested (observe-only)"})
	}
	if !known || statusErr != nil {
		return
	}
	if !status.IdentityOffsetsOK {
		e.persistenceNoteOnce("degraded:offsets", Event{Time: now, Severity: "warning", Kind: "xdr.persistence_offsets_missing", Source: "kernel",
			Message: "Persistence file/open ladder has no vmlinux-BTF identity offsets; the affected hooks fail open and stay blind (attached mask reports the partial ladder)"}, now, 30*time.Minute)
	}
	if status.Pkgdb == "unsupported" {
		e.persistenceNoteOnce("degraded:pkgdb", Event{Time: now, Severity: "info", Kind: "xdr.persistence_pkgdb_unsupported", Source: "kernel",
			Message: "No usable package database on this host; mapped-library ownership cannot be verified and linker-hook correlation is NONE for every event (evidence, not an ownership claim)"}, now, 30*time.Minute)
	} else if !status.PkgdbReady {
		e.persistenceNoteOnce("degraded:pkgdb-index", Event{Time: now, Severity: "info", Kind: "xdr.persistence_pkgdb_index", Source: "kernel",
			Message: fmt.Sprintf("Package database format %q was parsed but produced no usable inode->package reverse index; linker-hook correlation is NONE", status.Pkgdb)}, now, 30*time.Minute)
	}
	if !status.SessionsKnown {
		e.persistenceNoteOnce("degraded:sessions", Event{Time: now, Severity: "info", Kind: "xdr.persistence_sessions_unknown", Source: "kernel",
			Message: "No readable /run/systemd/sessions view; peripheral findings are reported with correlation NONE and are never escalated on a guessed idle state"}, now, 30*time.Minute)
	}
}

// persistenceNoteOnce records a bounded, periodically repeated degradation note.
func (e *XDREngine) persistenceNoteOnce(key string, event Event, now time.Time, ttl time.Duration) {
	if e == nil || e.state == nil {
		return
	}
	e.persistenceMu.Lock()
	if e.persistenceSeen == nil {
		e.persistenceSeen = make(map[string]time.Time)
	}
	if until, exists := e.persistenceSeen[key]; exists && now.Before(until) {
		e.persistenceMu.Unlock()
		return
	}
	e.persistenceSeen[key] = now.Add(ttl)
	e.persistenceMu.Unlock()
	if event.Time.IsZero() {
		event.Time = now
	}
	e.state.AddEvent(event)
}

// consumePersistenceEvents turns one bounded core batch into evidence/incidents.
func (e *XDREngine) consumePersistenceEvents(events []CorePersistenceEvent, dropped uint64, now time.Time) {
	if e == nil {
		return
	}
	for _, event := range events {
		if !e.claimPersistenceEvent(event, now) {
			continue
		}
		status := e.persistenceStatusSnapshot()
		assessment := e.assessPersistenceEvent(event, status)
		switch {
		case assessment.Tolerated:
			if e.state != nil {
				e.state.AddEvent(Event{Time: now, Severity: "info", Kind: "xdr.persistence_tolerated", Source: "kernel",
					Message: fmt.Sprintf("Tolerated persistence/peripheral activity: pid=%d uid=%d comm=%s class=%s kind=%s (%s)",
						event.PID, event.UID, event.Comm, PersistenceClassName(event.Class), PersistenceKindName(event.Kind), assessment.ToleratedReason),
					Target: fmt.Sprintf("pid:%d", event.PID)})
			}
		case assessment.InfoOnly:
			if e.state != nil {
				e.state.AddEvent(Event{Time: now, Severity: "info", Kind: assessment.EventKind, Source: "kernel",
					Message: assessment.Summary, Target: fmt.Sprintf("pid:%d", event.PID)})
			}
		default:
			if !e.claimPersistenceIncident(assessment.RuleID, event.PID, event.Class, assessment.Severity, now) {
				continue
			}
			e.recordPersistenceFinding(assessment, event, now)
		}
	}
	if dropped > 0 && e.state != nil {
		e.persistenceMu.Lock()
		last := e.persistenceLastOverflow
		if last.IsZero() || now.Sub(last) >= persistenceOverflowMinGap {
			e.persistenceLastOverflow = now
			e.persistenceMu.Unlock()
			e.state.AddEvent(Event{Severity: "high", Kind: "xdr.persistence_overflow", Source: "kernel",
				Message: fmt.Sprintf("Persistence/peripheral evidence queue dropped %d record(s); visibility is reduced (event queue bounded)", dropped)})
		} else {
			e.persistenceMu.Unlock()
		}
	}
}

// persistenceIntegrityTolerated implements the package-manager / boot-writer /
// own-process tolerance for the persistence-path ladder.
func (e *XDREngine) persistenceIntegrityTolerated(event CorePersistenceEvent) (bool, string) {
	if e != nil && e.selfPID > 0 && event.PID == e.selfPID {
		return true, "own control process"
	}
	if persistenceCommIn(event.Comm, persistenceOwnComms) {
		return true, "the GeDefense core/control itself"
	}
	if persistenceCommIn(event.Comm, persistencePackageManagerComms) {
		return true, "package manager writer"
	}
	if persistenceCommIn(event.Comm, persistenceBootWriterComms) || strings.HasPrefix(event.Comm, "systemd") {
		return true, "systemd/udev boot writer"
	}
	exe := persistenceExecutablePath(event.PID)
	if exe != "unknown" {
		for _, prefix := range persistencePackageManagerPathPrefixes {
			if strings.HasPrefix(exe, prefix) {
				return true, "package manager executable path"
			}
		}
		for _, prefix := range persistenceBootWriterPathPrefixes {
			if strings.HasPrefix(exe, prefix) {
				return true, "systemd/udev executable path"
			}
		}
	}
	return false, ""
}

// claimPersistenceEvent dedupes one kernel/userspace record by the mandated
// `(ts,kind,pid,ino,class)` key with a bounded five-minute memory.
func (e *XDREngine) claimPersistenceEvent(event CorePersistenceEvent, now time.Time) bool {
	key := fmt.Sprintf("event:%d|%d|%d|%d|%d", event.TsNS, event.Kind, event.PID, event.Ino, event.Class)
	e.persistenceMu.Lock()
	defer e.persistenceMu.Unlock()
	if e.persistenceSeen == nil {
		e.persistenceSeen = make(map[string]time.Time)
	}
	if until, exists := e.persistenceSeen[key]; exists && now.Before(until) {
		return false
	}
	e.persistenceSeen[key] = now.Add(persistenceDedupeTTL)
	e.persistencePruneSeenLocked(now)
	return true
}

// claimPersistenceIncident rate-limits one incident per rule per pid+class; an
// independent event of another class still surfaces. A critical severity is the
// documented exception (no AP-5 rule is critical today, the branch documents the
// contract for future severity changes).
func (e *XDREngine) claimPersistenceIncident(ruleID string, pid int, class uint8, severity string, now time.Time) bool {
	if severity == "critical" {
		return true
	}
	key := fmt.Sprintf("rate:%s|%d|%d", ruleID, pid, class)
	e.persistenceMu.Lock()
	defer e.persistenceMu.Unlock()
	if e.persistenceSeen == nil {
		e.persistenceSeen = make(map[string]time.Time)
	}
	if until, exists := e.persistenceSeen[key]; exists && now.Before(until) {
		return false
	}
	e.persistenceSeen[key] = now.Add(persistenceRateLimitWindow)
	e.persistencePruneSeenLocked(now)
	return true
}

func (e *XDREngine) persistencePruneSeenLocked(now time.Time) {
	if len(e.persistenceSeen) <= persistenceSeenLimit {
		return
	}
	for key, until := range e.persistenceSeen {
		if !until.After(now) {
			delete(e.persistenceSeen, key)
		}
	}
}

// persistenceStatusSnapshot returns the last known honest status.
func (e *XDREngine) persistenceStatusSnapshot() CorePersistenceStatus {
	if e == nil {
		return CorePersistenceStatus{}
	}
	e.persistenceMu.Lock()
	defer e.persistenceMu.Unlock()
	return e.persistenceStatus
}
