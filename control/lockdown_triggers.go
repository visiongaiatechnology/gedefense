// SPDX-FileCopyrightText: 2026 VisionGaia Technology
// SPDX-License-Identifier: AGPL-3.0-only

package main

// POINT 5 / P5-T3: the trigger evaluators of the Emergency Lockdown engine.
//
// Four sources are wired here and nowhere else:
//
//   (a) The XDR incident stream. Only two families are accepted: a
//       MORPHEUS.RASP.* rule with severity CRITICAL, and a
//       KD.LINUX.CANARY_ACCESS incident whose trigger reason is
//       CANARY_UNAUTHORIZED_PROBE (the system/scanner access path carries a
//       different reason and severity and never triggers). A trusted-debugger
//       exemption never reaches this hook because Morpheus already suppressed
//       the incident, and a non-CRITICAL record is discarded here again.
//   (b) The 60 s boot-trust reconciliation. Only a degradation from VERIFIED to
//       OBSERVE triggers; NOT_SUPPORTED and UNKNOWN are platform facts, not
//       drift.
//   (c) The optional duress token file, polled every second only when an
//       operator configured a path.
//   (d) The operator API (lockdown_api.go), which bypasses the automatic
//       correlation requirements because it is explicit intent.
//
// All automatic sources pass the same guards: fingerprint dedupe, the
// configured cooldown and the RequireSources correlation. A suppressed
// candidate is counted once per window in the false-positive guard instead of
// being written to the event stream on every tick.

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	// lockdownSourceCorrelationWindow is the window in which distinct trigger
	// sources are correlated for RequireSources > 1.
	lockdownSourceCorrelationWindow = 5 * time.Minute
	// lockdownDedupeWindow suppresses a repeated candidate from the same source.
	lockdownDedupeWindow = 5 * time.Minute
	// Maintenance cadences. They only run while the namespace is enabled, so the
	// shipped default produces no traffic at all.
	lockdownDuressPollInterval = time.Second
	lockdownBootTrustInterval  = 60 * time.Second
	lockdownCorePollInterval   = 10 * time.Second
	lockdownAutoArmRetry       = 30 * time.Second
	lockdownAutoArmMaxAttempts = 20
	lockdownDuressMaxBytes     = 4096
)

// errLockdownSourcesPending means the candidate is a valid trigger source but
// RequireSources is not satisfied yet. It is not an operator-visible failure.
var errLockdownSourcesPending = errors.New("lockdown trigger sources are still being correlated")

// AttachBootTrust wires the periodic boot-trust verdict provider. The provider
// returns (status, summary) where status is the honest verdict of the boot
// evidence module. It is optional: without it the boot-trust trigger is inert.
func (e *LockdownEngine) AttachBootTrust(provider func() (string, string)) {
	e.stateMu.Lock()
	e.bootTrust = provider
	e.bootTrustSeen = false
	e.bootTrustLast = ""
	e.stateMu.Unlock()
}

// ObserveIncident is the XDR incident hook (called from appendIncident). It is
// deliberately cheap and side-effect free while the namespace is disabled.
func (e *LockdownEngine) ObserveIncident(incident XDRIncident) {
	settings := e.effectiveSettings()
	if !settings.Enabled {
		return
	}
	candidate, ok := lockdownIncidentCandidate(settings, incident)
	if !ok {
		return
	}
	// The incident path must never run the phase orchestration (kernel IPC plus
	// cell freezes) on the XDR worker goroutine. One automatic evaluation runs at a
	// time; a further candidate is dropped because the latch it would establish is
	// already being established.
	if !e.triggerBusy.TryLock() {
		return
	}
	go func(candidate lockdownTriggerCandidate) {
		defer e.triggerBusy.Unlock()
		_ = e.maybeTrigger(candidate)
	}(candidate)
}

// lockdownIncidentCandidate maps one incident onto the closed trigger
// vocabulary. It returns false for every incident that is not one of the two
// documented families, including the trusted-debugger and system-scanner cases.
func lockdownIncidentCandidate(settings LockdownFabricSettings, incident XDRIncident) (lockdownTriggerCandidate, bool) {
	if !strings.EqualFold(strings.TrimSpace(incident.Severity), "critical") {
		return lockdownTriggerCandidate{}, false
	}
	if settings.TriggerMorpheusCritical {
		for _, ruleID := range incident.RuleIDs {
			if strings.HasPrefix(ruleID, "MORPHEUS.RASP.") {
				return lockdownTriggerCandidate{
					Source: lockdownSourcePolicy, Reason: lockdownReasonTamper,
					Fingerprint: lockdownFingerprint("morpheus", ruleID, strings.ToLower(incident.Process),
						strconv.Itoa(incident.PID), strconv.FormatUint(incident.StartTicks, 10)),
					Incident: incident.ID, ReasonText: incident.Summary,
					PID: incident.PID, StartTicks: incident.StartTicks, UID: incident.UID,
				}, true
			}
		}
	}
	if settings.TriggerCanaryUnauthorized && containsString(incident.RuleIDs, "KD.LINUX.CANARY_ACCESS") {
		// The reason is the differentiator, not the rule id: a system or scanner
		// access is recorded as CANARY_SUSPICIOUS_SYSTEM_ACCESS and is a different
		// product decision, so it must never latch the platform.
		if !lockdownCanaryUnauthorizedProbe(incident) {
			return lockdownTriggerCandidate{}, false
		}
		return lockdownTriggerCandidate{
			Source: lockdownSourcePolicy, Reason: lockdownReasonXDRCritical,
			Fingerprint: lockdownFingerprint("canary", lockdownCanaryTarget(incident),
				strings.ToLower(incident.Process), strconv.Itoa(incident.PID)),
			Incident: incident.ID, ReasonText: incident.Summary,
			PID: incident.PID, StartTicks: incident.StartTicks, UID: incident.UID,
		}, true
	}
	return lockdownTriggerCandidate{}, false
}

func lockdownCanaryUnauthorizedProbe(incident XDRIncident) bool {
	for _, node := range incident.AttackStory {
		if node.Metadata == nil {
			continue
		}
		if node.Metadata["trigger_reason"] == "CANARY_UNAUTHORIZED_PROBE" {
			return true
		}
	}
	return false
}

func lockdownCanaryTarget(incident XDRIncident) string {
	for _, node := range incident.AttackStory {
		if node.Metadata != nil && node.Metadata["target_path"] != "" {
			return node.Metadata["target_path"]
		}
	}
	return "canary"
}

// lockdownFingerprint is a bounded, non-reversible identity of one candidate.
// It is used for dedupe and persisted with the trigger; no raw path, command or
// PID list is stored.
func lockdownFingerprint(parts ...string) string {
	digest := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return hex.EncodeToString(digest[:8])
}

// maybeTrigger is the single automatic-entry point. Guard failures are not
// events (they are counted in the false-positive guard); an engine error is
// published once so a broken path is never silent.
func (e *LockdownEngine) maybeTrigger(candidate lockdownTriggerCandidate) error {
	_, err := e.Trigger(candidate)
	switch {
	case err == nil:
		return nil
	case errors.Is(err, errLockdownCooldown), errors.Is(err, errLockdownSourcesPending),
		errors.Is(err, errLockdownDisabled), errors.Is(err, errLockdownLatched):
		return nil
	default:
		e.addEvent("critical", "lockdown.trigger_failed",
			"Automatic lockdown trigger failed: "+lockdownReasonText(err.Error()))
		return err
	}
}

// TriggerWitnessEquivocation is the additive POINT 4 entry point used by the
// witness engine. It evaluates one automatic candidate and therefore runs through
// the same fingerprint dedupe, cooldown and RequireSources guards as every other
// automatic source - the witness engine cannot bypass them. The namespace and the
// source switch must both be enabled; otherwise the trigger is refused without a
// latch and without an event.
func (e *LockdownEngine) TriggerWitnessEquivocation(fingerprint string) error {
	settings := e.effectiveSettings()
	if !settings.Enabled {
		return errLockdownDisabled
	}
	if !settings.TriggerWitnessEquivocation {
		return errors.New("witness equivocation is not an accepted lockdown trigger source")
	}
	return e.maybeTrigger(lockdownTriggerCandidate{
		Source: lockdownSourcePolicy, Reason: lockdownReasonWitnessEquivocation,
		Fingerprint: lockdownFingerprint("witness-equivocation", fingerprint),
		ReasonText:  "out-of-band witness reported ledger equivocation or rollback",
	})
}

func lockdownSourceLabel(source string) string {
	return lockdownReasonText(source)
}

func lockdownReasonLabel(reason string) string {
	return lockdownReasonText(reason)
}

// applyTriggerGuards enforces dedupe, cooldown and RequireSources for
// non-operator candidates. It must be called before the latch is touched.
func (e *LockdownEngine) applyTriggerGuards(settings LockdownFabricSettings, candidate lockdownTriggerCandidate) error {
	now := e.now()
	fingerprint := candidate.Fingerprint
	if fingerprint == "" {
		fingerprint = lockdownFingerprint(candidate.Source, candidate.Reason, candidate.Incident)
	}
	e.stateMu.Lock()
	previousFingerprint := e.lastFingerprint
	previousAt := e.lastFingerprintAt
	lastAutomatic := e.lastAutomaticAt
	// Drop stale correlation entries so the map can never grow with the incident
	// rate of the host.
	for source, at := range e.pendingSources {
		if now.Sub(at) > lockdownSourceCorrelationWindow {
			delete(e.pendingSources, source)
		}
	}
	e.stateMu.Unlock()

	if previousFingerprint == fingerprint && !previousAt.IsZero() && now.Sub(previousAt) < lockdownDedupeWindow {
		e.noteFalsePositiveGuard("the same trigger candidate is already being handled")
		return errLockdownCooldown
	}
	cooldown := time.Duration(settings.CooldownSeconds) * time.Second
	if cooldown > 0 && !lastAutomatic.IsZero() && now.Sub(lastAutomatic) < cooldown {
		e.noteFalsePositiveGuard(fmt.Sprintf("the automatic trigger cooldown of %ds is still active", settings.CooldownSeconds))
		return errLockdownCooldown
	}
	if settings.RequireSources > 1 {
		// Correlate on the reason family, not on the four-token wire source: a
		// Morpheus CRITICAL and a canary probe both arrive as source=policy, and
		// treating them as one source would make the multi-source requirement
		// impossible to satisfy for the two strongest incident families.
		sourceKey := candidate.Reason
		if sourceKey == "" {
			sourceKey = candidate.Source
		}
		e.stateMu.Lock()
		if sourceKey != "" {
			e.pendingSources[sourceKey] = now
		}
		pending := len(e.pendingSources)
		e.pendingFingerprint = fingerprint
		e.pendingID = candidate.Incident
		e.stateMu.Unlock()
		if pending < settings.RequireSources {
			return errLockdownSourcesPending
		}
		// The requirement is satisfied: consume the correlation and continue.
		e.stateMu.Lock()
		e.pendingSources = make(map[string]time.Time)
		e.pendingFingerprint = ""
		e.pendingID = ""
		e.stateMu.Unlock()
	}
	e.stateMu.Lock()
	e.lastFingerprint = fingerprint
	e.lastFingerprintAt = now
	e.stateMu.Unlock()
	return nil
}

// noteFalsePositiveGuard counts one suppressed candidate. The counter always
// moves; the event and the evidence record are written at most once per dedupe
// window so a recurring candidate cannot flood the audit trail.
func (e *LockdownEngine) noteFalsePositiveGuard(reason string) {
	now := e.now()
	e.stateMu.Lock()
	e.falsePositiveGuards++
	write := e.lastGuardEvidence.IsZero() || now.Sub(e.lastGuardEvidence) >= lockdownDedupeWindow
	if write {
		e.lastGuardEvidence = now
	}
	e.stateMu.Unlock()
	if !write {
		return
	}
	message := "A lockdown trigger candidate was suppressed: " + reason
	e.addEvent("warning", "lockdown.false_positive_guard", message)
	_ = e.recordEvidence("warning", "lockdown.false_positive_guard", message, "candidate-suppressed")
}

func (e *LockdownEngine) reconcileBootTrust(now time.Time) {
	e.stateMu.RLock()
	provider := e.bootTrust
	e.stateMu.RUnlock()
	if provider == nil {
		return
	}
	status, summary := provider()
	status = strings.ToUpper(strings.TrimSpace(status))
	e.stateMu.Lock()
	previous, seen := e.bootTrustLast, e.bootTrustSeen
	// Only a verifiable verdict is a baseline. NOT_SUPPORTED (no hardware root of
	// trust) and UNKNOWN (unreadable probe) are platform facts: they must neither
	// trigger nor overwrite the last verified baseline, otherwise the platform
	// could never notice the degradation to OBSERVE later in the same boot.
	if status == bootTrustStatusVerified || status == bootTrustStatusObserve {
		e.bootTrustLast, e.bootTrustSeen = status, true
	}
	e.stateMu.Unlock()
	if !seen || previous != bootTrustStatusVerified || status != bootTrustStatusObserve {
		return
	}
	_ = e.maybeTrigger(lockdownTriggerCandidate{
		Source: lockdownSourceTimer, Reason: lockdownReasonBootTrust,
		Fingerprint: lockdownFingerprint("boot-trust", status, summary),
		ReasonText:  summary,
	})
}

// pollDuress reads the bounded duress token file. It never logs the content and
// only reacts to a token it has not seen before; a duress trigger is explicit
// human intent, so it bypasses the multi-source correlation.
func (e *LockdownEngine) pollDuress(now time.Time) {
	settings := e.effectiveSettings()
	token, ok := readLockdownDuressToken(settings.DuressTokenPath)
	if !ok {
		return
	}
	digest := lockdownFingerprint("duress", token)
	e.stateMu.Lock()
	seen := e.duressHash == digest
	if !seen {
		e.duressHash = digest
	}
	e.stateMu.Unlock()
	if seen {
		return
	}
	_ = e.maybeTrigger(lockdownTriggerCandidate{
		Source: lockdownSourceManual, Reason: lockdownReasonManual, Operator: true,
		Fingerprint: digest, ReasonText: "duress token presented",
	})
}

// readLockdownDuressToken reads at most 4 KiB from a regular, non-symlink file
// and returns true only for a non-empty token. The content is never logged.
func readLockdownDuressToken(path string) (string, bool) {
	if path == "" {
		return "", false
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 ||
		info.Size() <= 0 || info.Size() > lockdownDuressMaxBytes || info.Mode().Perm()&0o022 != 0 {
		return "", false
	}
	raw, err := os.ReadFile(path)
	if err != nil || len(raw) > lockdownDuressMaxBytes {
		return "", false
	}
	// A token must be a single printable line; anything else is a malformed file
	// and must not trigger (and must not leak into an event).
	token := strings.TrimSpace(string(raw))
	if token == "" || len(token) > 256 || strings.ContainsAny(token, "\r\n\x00") {
		return "", false
	}
	return token, true
}

// parseCoreLockdownEvents decodes "empty" or
// "<dropped>|<seq:ts:source:reason:phase:outcome>,…" as an Alles-oder-Nichts
// batch: one malformed record rejects the whole answer and returns no partial
// state (§5, same contract as the StyX/Titan parsers).
func parseCoreLockdownEvents(payload string) ([]CoreLockdownEvent, uint64, error) {
	if payload == "empty" {
		return nil, 0, nil
	}
	if len(payload) == 0 || len(payload) > maxLockdownPayloadBytes {
		return nil, 0, errors.New("core returned an oversized lockdown event batch")
	}
	batch := strings.SplitN(payload, "|", 2)
	if len(batch) != 2 {
		return nil, 0, errors.New("core returned a malformed lockdown event batch")
	}
	dropped, err := parseStyxUint(batch[0], 64)
	if err != nil {
		return nil, 0, errors.New("core returned an invalid lockdown event drop counter")
	}
	if batch[1] == "" {
		return nil, dropped, nil
	}
	records := strings.Split(batch[1], ",")
	if len(records) > maxLockdownEventsPerResponse {
		return nil, 0, errors.New("core returned too many lockdown events")
	}
	events := make([]CoreLockdownEvent, 0, len(records))
	for _, record := range records {
		fields := strings.Split(record, ":")
		if len(fields) != 6 {
			return nil, 0, errors.New("core returned a malformed lockdown event")
		}
		values := make([]uint64, len(fields))
		for index, field := range fields {
			value, parseErr := parseStyxUint(field, 64)
			if parseErr != nil {
				return nil, 0, errors.New("core returned an invalid lockdown event field")
			}
			values[index] = value
		}
		if values[0] == 0 || values[1] == 0 {
			return nil, 0, errors.New("core returned a lockdown event without sequence or timestamp")
		}
		if values[2] < 1 || values[2] > 4 || values[3] < 1 || values[3] > 8 ||
			values[4] > 8 || values[5] < 1 || values[5] > 5 {
			return nil, 0, errors.New("core returned out-of-range lockdown event enums")
		}
		events = append(events, CoreLockdownEvent{
			Seq: values[0], Timestamp: values[1],
			Source: uint8(values[2]), Reason: uint8(values[3]), Phase: uint8(values[4]), Outcome: uint8(values[5]),
		})
	}
	return events, dropped, nil
}
