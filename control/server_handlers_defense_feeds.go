// STATUS: DIAMANT VGT SUPREME
// SPDX-FileCopyrightText: 2026 VisionGaia Technology
// SPDX-License-Identifier: AGPL-3.0-only

package main

// Threat-intelligence feed handlers split out of server.go (refactoring wave
// 1a, structure-only). The mux registration stays in server.go.

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"
)

func (s *APIServer) syncFeeds(w http.ResponseWriter, r *http.Request) {
	if s.settings == nil || !s.settings.Get().FeedsEnabled {
		apiError(w, http.StatusConflict, "threat intelligence is disabled (100% Opt-In)", nil)
		return
	}
	if s.feeds == nil {
		apiError(w, http.StatusServiceUnavailable, "threat intelligence manager unavailable", nil)
		return
	}
	allowlist := s.settings.Get().ManagementAllowlist
	ctx, cancel := context.WithTimeout(r.Context(), 45*time.Second)
	defer cancel()
	s.state.AddEvent(Event{Severity: "info", Kind: "feeds.sync_started", Source: "intelligence", Message: "Threat intelligence synchronization started: fetching and validating configured sources"})
	items, errs, err := s.feeds.SyncWithLock(ctx, "operator")
	if err != nil {
		var lockErr *ThreatIntelLockException
		severity := "error"
		if errors.As(err, &lockErr) {
			severity = "warning"
			s.state.AddEvent(Event{Severity: severity, Kind: "feeds.sync_failed", Source: "intelligence", Message: err.Error()})
			apiFault(w, http.StatusConflict, err)
			return
		}
		s.state.AddEvent(Event{Severity: severity, Kind: "feeds.sync_failed", Source: "intelligence", Message: "Threat intelligence source synchronization failed"})
		apiError(w, http.StatusInternalServerError, "feed synchronization failed", err)
		return
	}

	downloadSeverity := "info"
	downloadKind := "feeds.sources_validated"
	downloadMessage := fmt.Sprintf("Threat intelligence sources validated: %d active block vectors composed", len(items))
	if len(errs) > 0 {
		downloadSeverity = "warning"
		downloadKind = "feeds.sources_partial"
		downloadMessage = fmt.Sprintf("Threat intelligence source fetch completed partially: %d source errors; last-known-good data preserved", len(errs))
	}
	s.state.AddEvent(Event{Severity: downloadSeverity, Kind: downloadKind, Source: "intelligence", Message: downloadMessage})

	// Automatic kernel publication is administrable. With it disabled the
	// validated generation stays in userspace until the operator applies it
	// explicitly, so a sync alone can never change kernel policy.
	policy := effectiveThreatIntelSettings(s.settings.Get())
	added, deleted := 0, 0
	if policy.Kernel.AutoApply {
		s.state.AddEvent(Event{Severity: "info", Kind: "feeds.kernel_applying", Source: "intelligence", Message: "Applying validated BLOCK feed generation to kernel policy"})
		var applyErr error
		added, deleted, applyErr = s.feeds.ApplyToKernel(s.core, allowlist)
		if applyErr != nil {
			s.state.AddEvent(Event{Severity: "error", Kind: "feeds.kernel_apply_failed", Source: "intelligence", Message: "Threat intelligence kernel synchronization failed"})
			apiError(w, http.StatusInternalServerError, "kernel synchronization failed", applyErr)
			return
		}
	} else {
		s.state.AddEvent(Event{Severity: "info", Kind: "feeds.kernel_pending", Source: "intelligence", Message: "Validated generation held in userspace: automatic kernel publication is disabled, apply explicitly to enforce it"})
	}

	blockCount := s.feeds.BlockIndex().Count()
	correlateCount := s.feeds.CorrelateIndex().Count()
	annotateCount := s.feeds.AnnotateIndex().Count()
	gen := s.feeds.Generation()
	fingerprint := s.feeds.Fingerprint()
	status := s.feeds.OverallStatus()
	lastAttempt := s.feeds.LastAttemptAt()
	lastSuccess := s.feeds.LastSuccessfulSyncAt()
	lastFullSuccess := s.feeds.LastFullySuccessfulSyncAt()

	s.state.SetFeedState(blockCount, correlateCount, annotateCount, gen, fingerprint, status, lastAttempt, lastSuccess, lastFullSuccess)
	severity := "info"
	message := fmt.Sprintf("Threat intelligence synchronized [gen=%d fp=%.12s]: %d vectors (block=%d, correlate=%d, annotate=%d, kernel: +%d/-%d)",
		gen, fingerprint, len(items), blockCount, correlateCount, annotateCount, added, deleted)
	if len(errs) > 0 {
		severity = "warning"
		message += fmt.Sprintf("; %d source errors", len(errs))
	}
	s.state.AddEvent(Event{Severity: severity, Kind: "feeds.synced", Source: "intelligence", Message: message})
	telemetry := s.feeds.Telemetry()
	writeJSON(w, http.StatusOK, map[string]any{
		"vectors":                         len(items),
		"generation":                      gen,
		"fingerprint":                     fingerprint,
		"overall_status":                  telemetry.OverallStatus,
		"last_attempt_at":                 telemetry.LastAttemptAt,
		"last_successful_sync_at":         telemetry.LastSuccessfulSyncAt,
		"last_partial_successful_sync_at": telemetry.LastPartialSuccessfulSyncAt,
		"last_fully_successful_sync_at":   telemetry.LastFullySuccessfulSyncAt,
		"block_vectors":                   blockCount,
		"correlate_vectors":               correlateCount,
		"annotate_vectors":                annotateCount,
		"source_errors":                   len(errs),
		"kernel_added":                    added,
		"kernel_deleted":                  deleted,
		"kernel_apply_status":             telemetry.KernelApplyStatus,
		"kernel_generation":               telemetry.KernelGeneration,
		"feeds":                           telemetry.Feeds,
		"auto_apply":                      policy.Kernel.AutoApply,
		"lock":                            threatIntelLockKey,
		"note":                            "Threat intelligence active at kernel speed (XDP + cgroup_skb egress).",
	})
}

// applyFeeds publishes the currently validated userspace generation to the
// kernel. It is the explicit counterpart to automatic publication and is the
// only way to enforce a generation while "apply to kernel automatically" is
// switched off.
func (s *APIServer) applyFeeds(w http.ResponseWriter, r *http.Request) {
	if s.feeds == nil {
		apiError(w, http.StatusServiceUnavailable, "threat intelligence manager unavailable", nil)
		return
	}
	var allowlist []string
	if s.settings != nil {
		allowlist = s.settings.Get().ManagementAllowlist
	}
	added, deleted, err := s.feeds.ApplyToKernel(s.core, allowlist)
	if err != nil {
		s.state.AddEvent(Event{Severity: "error", Kind: "feeds.kernel_apply_failed", Source: "intelligence", Message: "Explicit threat intelligence kernel publication failed"})
		apiError(w, http.StatusInternalServerError, "kernel synchronization failed", err)
		return
	}
	telemetry := s.feeds.Telemetry()
	s.state.SetFeedState(
		s.feeds.BlockIndex().Count(), s.feeds.CorrelateIndex().Count(), s.feeds.AnnotateIndex().Count(),
		telemetry.Generation, telemetry.Fingerprint, telemetry.OverallStatus,
		telemetry.LastAttemptAt, telemetry.LastSuccessfulSyncAt, telemetry.LastFullySuccessfulSyncAt,
	)
	s.state.AddEvent(Event{Severity: "info", Kind: "feeds.kernel_applied", Source: "intelligence",
		Message: fmt.Sprintf("Operator published threat intelligence generation %d to the kernel: +%d/-%d", telemetry.Generation, added, deleted)})
	writeJSON(w, http.StatusOK, map[string]any{
		"kernel_added":        added,
		"kernel_deleted":      deleted,
		"kernel_apply_status": telemetry.KernelApplyStatus,
		"kernel_generation":   telemetry.KernelGeneration,
		"generation":          telemetry.Generation,
		"fingerprint":         telemetry.Fingerprint,
	})
}

func (s *APIServer) getFeedStatus(w http.ResponseWriter, r *http.Request) {
	if s.feeds == nil {
		writeJSON(w, http.StatusOK, ThreatIntelTelemetry{OverallStatus: "DISABLED", KernelApplyStatus: "NOT_APPLIED"})
		return
	}
	writeJSON(w, http.StatusOK, s.feeds.Telemetry())
}
