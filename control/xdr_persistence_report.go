package main

import (
	"time"
)

// PersistenceGuardReport is the bounded operator projection of the AP-5 guard
// for future API wiring (no route is added by AP-5). `State` is only "active"
// when the guard is armed, a visibility hook is attached and the BTF identity
// offsets are published; every partial ladder is reported as degraded with the
// explicit reason, never as enforcement.
type PersistenceGuardReport struct {
	State              string     `json:"state"` // active | degraded | disarmed | unavailable
	Capability         string     `json:"capability"`
	Reason             string     `json:"reason,omitempty"`
	Enabled            bool       `json:"enabled"`
	Attached           bool       `json:"attached"`
	HookMask           uint64     `json:"hook_mask"`
	HookFileOpen       bool       `json:"hook_file_open"`
	HookMmap           bool       `json:"hook_mmap"`
	HookPtrace         bool       `json:"hook_ptrace"`
	HookReadv          bool       `json:"hook_readv"`
	HookWritev         bool       `json:"hook_writev"`
	IdentityOffsetsOK  bool       `json:"identity_offsets_ok"`
	PkgdbReady         bool       `json:"pkgdb_ready"`
	ReadvOffsetsOK     bool       `json:"readv_offsets_ok"`
	WritevOffsetsOK    bool       `json:"writev_offsets_ok"`
	ReadFailuresSeen   bool       `json:"read_failures_seen"`
	SessionsKnown      bool       `json:"sessions_known"`
	Paths              uint64     `json:"paths"`
	Execs              uint64     `json:"execs"`
	Devices            uint64     `json:"devices"`
	Secrets            uint64     `json:"secrets"`
	Pkgdb              string     `json:"pkgdb"`
	Roots              uint64     `json:"roots"`
	Drifted            uint64     `json:"drifted"`
	BaselineAtMS       uint64     `json:"baseline_at_ms"`
	Events             uint64     `json:"events"`
	Drops              uint64     `json:"drops"`
	SessionsTotal      uint64     `json:"sessions_total"`
	SessionsActive     uint64     `json:"sessions_active"`
	SessionsInactive   uint64     `json:"sessions_inactive"`
	IdleHint           string     `json:"idlehint"`
	CorrelationQuality string     `json:"correlation_quality"` // OBSERVED | TEMPORAL | NONE
	SampledAt          *time.Time `json:"sampled_at,omitempty"`
}

// PersistenceGuardReport returns the honest operator view of the AP-5 guard.
// AP-5 intentionally wires no route; the future API owner can expose it as is.
func (e *XDREngine) PersistenceGuardReport() PersistenceGuardReport {
	report := PersistenceGuardReport{State: "unavailable", Capability: "unknown", CorrelationQuality: persistenceQualityNone}
	if e == nil {
		return report
	}
	e.persistenceMu.Lock()
	status := e.persistenceStatus
	sampled := e.persistenceStatusAt
	statusErr := e.persistenceStatusErr
	known := e.persistenceCapabilityKnown
	e.persistenceMu.Unlock()
	report.Enabled = status.Enabled
	report.Attached = status.Attached
	report.HookMask = status.AttachedMask
	report.HookFileOpen = status.HookFileOpen
	report.HookMmap = status.HookMmap
	report.HookPtrace = status.HookPtrace
	report.HookReadv = status.HookReadv
	report.HookWritev = status.HookWritev
	report.IdentityOffsetsOK = status.IdentityOffsetsOK
	report.PkgdbReady = status.PkgdbReady
	report.ReadvOffsetsOK = status.ReadvOffsetsOK
	report.WritevOffsetsOK = status.WritevOffsetsOK
	report.ReadFailuresSeen = status.ReadFailuresSeen
	report.SessionsKnown = status.SessionsKnown
	report.Paths = status.Paths
	report.Execs = status.Execs
	report.Devices = status.Devices
	report.Secrets = status.Secrets
	report.Pkgdb = status.Pkgdb
	report.Roots = status.Roots
	report.Drifted = status.Drifted
	report.BaselineAtMS = status.BaselineAtMS
	report.Events = status.Events
	report.Drops = status.Drops
	report.SessionsTotal = status.SessionsTotal
	report.SessionsActive = status.SessionsActive
	report.SessionsInactive = status.SessionsInactive
	report.IdleHint = status.IdleHint
	if !sampled.IsZero() {
		at := sampled
		report.SampledAt = &at
	}
	switch {
	case !known:
		report.Capability = "missing"
		if statusErr != "" {
			report.State = "degraded"
			report.Reason = "persistence guard " + statusErr
		} else if sampled.IsZero() {
			report.Capability = "unknown"
			report.State = "unavailable"
			report.Reason = "the persistence/peripheral guard has not been sampled yet"
		} else {
			report.State = "unavailable"
			report.Reason = "the privileged core does not advertise the PERSIST_GUARD_* command family (the kernel is fail-open, no enforcement claim)"
		}
	case statusErr != "":
		report.State = "degraded"
		report.Capability = "available"
		report.Reason = "persistence guard " + statusErr
	case !status.Enabled:
		report.State = "disarmed"
		report.Capability = "available"
		report.Reason = "persistence guard is not armed (PERSIST_GUARD_SET 0 or the core refused to arm a blind ladder)"
	case !status.Attached:
		report.State = "degraded"
		report.Capability = "available"
		report.Reason = "persistence guard is armed but no LSM/TP hook is attached"
	case !status.IdentityOffsetsOK:
		report.State = "degraded"
		report.Capability = "available"
		report.Reason = "persistence file/open ladder has no vmlinux-BTF identity offsets; the affected hooks fail open and stay blind"
	default:
		report.State = "active"
		report.Capability = "available"
		if status.Pkgdb == "unsupported" {
			report.Reason = "linker-hook ownership cannot be verified: pkgdb=unsupported, correlation NONE"
		}
	}
	// Correlation honesty: a session-inactive correlation needs a session view;
	// IdleHint is unavailable, so the best possible quality is TEMPORAL.
	if known && status.SessionsKnown {
		report.CorrelationQuality = persistenceQualityTemporal
		if status.IdleHint != "unavailable" {
			report.CorrelationQuality = persistenceQualityObserved
		}
	}
	report.Reason = persistenceBoundedText(report.Reason, persistenceReasonBytes)
	return report
}
