// SPDX-FileCopyrightText: 2026 VisionGaia Technology
// SPDX-License-Identifier: AGPL-3.0-only

package main

// Titan acceptance of an authorized release rebaseline.
//
// The FIM rebaseline (fim_rebaseline.go) is the authority for "what the host is
// allowed to contain after the verified update". Titan's journal, however, is
// append-only forensic history: the findings recorded before the update stay
// recorded, because rewriting them would destroy exactly the evidence the
// module exists to preserve.
//
// What this file adds is the missing link between the two: after a verified
// rebaseline it closes the still-open UNEXPECTED findings whose path is now
// covered by the newly approved baseline, records the operator's reason on each
// of them, and appends one fresh observation per accepted path so the current
// state is answered by an AUTHORIZED event instead of by the old finding. A
// COMPROMISED finding is never closed here - correlation with an XDR incident
// stays an operator decision.

import (
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
)

const (
	titanRebaselineMaxPaths     = 512
	titanRebaselineMaxReported  = 32
	titanRebaselineReviewState  = "REBASELINED"
	titanRebaselineSensorSource = "baseline-acceptance"
)

// TitanRebaselineAcceptance is the bounded result of one acceptance pass.
type TitanRebaselineAcceptance struct {
	ApprovedPaths       int      `json:"approved_paths"`
	ClosedFindings      int      `json:"closed_findings"`
	FreshObservations   int      `json:"fresh_observations"`
	CompromisedDeferred int      `json:"compromised_deferred"`
	Skipped             []string `json:"skipped,omitempty"`
}

// AcceptRebaselinedPaths closes open UNEXPECTED findings whose path content now
// matches the approved FIM baseline and appends an AUTHORIZED observation for
// each accepted path. It refuses when the FIM baseline cannot vouch for the
// current content: acceptance is evidence-driven, never a blanket dismissal.
func (e *TitanEngine) AcceptRebaselinedPaths(paths []string, reason string) (TitanRebaselineAcceptance, error) {
	result := TitanRebaselineAcceptance{Skipped: make([]string, 0, 0)}
	if e == nil {
		return result, errors.New("Titan engine unavailable")
	}
	normalizedReason, reasonErr := validateTitanReason(reason)
	if reasonErr != nil {
		return result, reasonErr
	}
	if len(paths) == 0 {
		return result, errors.New("Titan baseline acceptance requires at least one approved path")
	}
	if len(paths) > titanRebaselineMaxPaths {
		return result, errors.New("Titan baseline acceptance exceeds its bounded path count")
	}

	e.mu.RLock()
	enabled := e.enabled
	policy := e.policy
	lookup := e.deps.FIM
	e.mu.RUnlock()
	if !enabled {
		return result, errors.New("Titan is disabled")
	}
	if lookup == nil {
		return result, errors.New("Titan baseline acceptance requires the approved FIM baseline")
	}

	approved := make(map[string]struct{}, len(paths))
	sort.Strings(paths)
	for _, raw := range paths {
		path := strings.TrimSpace(raw)
		if path == "" || len(path) > titanMaxPathBytes || !filepath.IsAbs(path) ||
			filepath.Clean(path) != path || strings.ContainsRune(path, '\x00') {
			appendTitanSkipped(&result, boundedTitanText(path, 120))
			continue
		}
		if !titanPathWithinRoots(path, policy.Roots) {
			appendTitanSkipped(&result, path)
			continue
		}
		record, _, exists := lookup.TitanBaselineRecord(path)
		if !exists || record.SHA256 == "" {
			appendTitanSkipped(&result, path)
			continue
		}
		identity := readTitanIdentity(path, policy.MaxFileBytes)
		if !identity.Regular || identity.Symlink || identity.SHA256 != record.SHA256 {
			// The FIM baseline does not vouch for the current bytes: leave the
			// finding open instead of accepting something the operator's own
			// rebaseline did not approve.
			appendTitanSkipped(&result, path)
			continue
		}
		approved[path] = struct{}{}
	}
	if len(approved) == 0 {
		return result, errors.New("no rebaselined path could be verified against the approved FIM baseline")
	}

	now := e.now()
	e.mu.Lock()
	for index := range e.events {
		event := &e.events[index]
		if _, ok := approved[event.Path]; !ok {
			continue
		}
		if event.Review != "" && event.Review != "PENDING" {
			continue
		}
		switch event.TrustState {
		case TitanTrustUnexpected:
			event.Review = titanRebaselineReviewState
			event.ReviewReason = boundedTitanText(normalizedReason, titanMaxReasonBytes)
			event.ReviewUTC = &now
			result.ClosedFindings++
		case TitanTrustCompromised:
			// Never closed automatically: an incident correlation outranks a
			// baseline update and needs an explicit operator review.
			result.CompromisedDeferred++
		}
	}
	e.recountLocked()
	document := e.journalDocumentLocked()
	e.mu.Unlock()
	if err := e.persistJournal(document); err != nil {
		return result, fmt.Errorf("Titan baseline acceptance could not persist the journal: %w", err)
	}

	pathsApproved := make([]string, 0, len(approved))
	for path := range approved {
		pathsApproved = append(pathsApproved, path)
	}
	sort.Strings(pathsApproved)
	for _, path := range pathsApproved {
		// A fresh observation against the newly approved baseline. This is the
		// answer to "what does the changed file look like now": AUTHORIZED,
		// with the acceptance reason in the journal instead of the old finding.
		e.observe(titanObservation{
			Path:        path,
			ChangeType:  TitanChangeModified,
			ObservedUTC: now,
			Sensor:      titanRebaselineSensorSource,
			Live:        true,
		})
		result.FreshObservations++
	}
	result.ApprovedPaths = len(approved)
	e.recordEvidence(EvidenceRecord{
		Time: now, Severity: "high", Kind: "titan.baseline.accepted", Source: "titan",
		Message: fmt.Sprintf(
			"Authorized release rebaseline accepted %d approved path(s); closed %d open UNEXPECTED finding(s), %d COMPROMISED finding(s) kept for operator review; reason-sha256=%s",
			result.ApprovedPaths, result.ClosedFindings, result.CompromisedDeferred, titanReasonDigest(normalizedReason)),
	})
	e.emitEvent(Event{
		Severity: "info", Kind: "titan.baseline.accepted", Source: "titan",
		Message: fmt.Sprintf("Titan accepted %d path(s) from the verified release baseline (%d findings closed)",
			result.ApprovedPaths, result.ClosedFindings),
	})
	return result, nil
}

func appendTitanSkipped(result *TitanRebaselineAcceptance, path string) {
	if path == "" || len(result.Skipped) >= titanRebaselineMaxReported {
		return
	}
	result.Skipped = append(result.Skipped, path)
}
