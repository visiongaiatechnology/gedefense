package main

import (
	"fmt"
	"time"
)

// CrossViewReport is the bounded operator projection of the verifier for
// future API wiring (no route is added by AP-3).
type CrossViewReport struct {
	State          string     `json:"state"` // active | degraded | unavailable
	Capability     string     `json:"capability"`
	Reason         string     `json:"reason,omitempty"`
	Enabled        bool       `json:"enabled"`
	Scans          uint64     `json:"scans"`
	Contradictions uint64     `json:"contradictions"`
	Events         uint64     `json:"events"`
	Drops          uint64     `json:"drops"`
	Domains        uint64     `json:"domains"`
	LastScanAgeMS  uint64     `json:"last_scan_age_ms"`
	Tap            bool       `json:"tap"`
	Mods           bool       `json:"mods"`
	Procs          bool       `json:"procs"`
	BPF            bool       `json:"bpf"`
	Trace          bool       `json:"trace"`
	PkgDB          string     `json:"pkgdb"`
	SampledAt      *time.Time `json:"sampled_at,omitempty"`
}

// CrossViewReport is the honest operator projection of the verifier (no API
// route is wired by AP-3; the method exists for the future handler).
func (e *XDREngine) CrossViewReport() CrossViewReport {
	report := CrossViewReport{State: "unavailable", Capability: "unknown"}
	if e == nil {
		return report
	}
	e.crossViewMu.Lock()
	status := e.crossViewStatus
	statusErr := e.crossViewStatusErr
	known := e.crossViewCapabilityKnown
	sampled := e.crossViewStatusAt
	e.crossViewMu.Unlock()
	report.Enabled = status.Enabled
	report.Scans = status.Scans
	report.Contradictions = status.Contradictions
	report.Events = status.Events
	report.Drops = status.Drops
	report.Domains = status.Domains
	report.LastScanAgeMS = status.LastScanAgeMS
	report.Tap = status.Tap
	report.Mods = status.Mods
	report.Procs = status.Procs
	report.BPF = status.BPF
	report.Trace = status.Trace
	report.PkgDB = status.PkgDB
	if known && statusErr == "" && !sampled.IsZero() {
		at := sampled
		report.SampledAt = &at
	}
	switch {
	case !known && sampled.IsZero():
		report.Capability = "unknown"
		report.Reason = "the cross-view verifier has not been sampled yet"
	case !known:
		report.Capability = "missing"
		if statusErr != "" {
			report.State = "degraded"
			report.Reason = "cross-view verifier " + statusErr
		} else {
			report.Reason = "the privileged core does not advertise the CROSS_VIEW_* command family"
		}
	case statusErr != "":
		report.State = "degraded"
		report.Capability = "available"
		report.Reason = "cross-view verifier " + statusErr
	case !status.Enabled:
		report.Capability = "available"
		report.Reason = "cross-view verifier is not armed in the privileged core"
	case status.Domains == 0:
		report.State = "degraded"
		report.Capability = "available"
		report.Reason = "cross-view verifier is armed but no domain produced a readable view"
	case !status.Tap && !status.Mods && !status.Procs && !status.BPF:
		report.State = "degraded"
		report.Capability = "available"
		report.Reason = "cross-view verifier is armed but every kernel view is unavailable on this host"
	default:
		report.State = "active"
		report.Capability = "available"
		if status.Domains < uint64(CrossViewDomainMax) {
			report.Reason = fmt.Sprintf("%d/%d cross-view domains readable on this host (capability gap, not an outage)",
				status.Domains, CrossViewDomainMax)
		}
	}
	if status.Drops > 0 && report.Reason == "" {
		report.Reason = fmt.Sprintf("%d cross-view record(s) were dropped by the bounded queue", status.Drops)
	}
	report.Reason = crossViewBounded(report.Reason, crossViewReportReasonBytes)
	return report
}
