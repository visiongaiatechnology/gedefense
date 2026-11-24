package main

import (
	"fmt"
	"time"
)

// BpfGuardReport is the bounded operator projection of the attach-time guard for
// future API wiring (no route is added by AP-2). State is only "active" when the
// guard is armed and at least one load-visibility hook (LSM or syscall
// tracepoint) is attached; partial attach ladders are reported as degraded.
type BpfGuardReport struct {
	State        string     `json:"state"` // active | degraded | disarmed | unavailable
	Capability   string     `json:"capability"`
	Reason       string     `json:"reason,omitempty"`
	Enabled      bool       `json:"enabled"`
	Attached     bool       `json:"attached"`
	LSM          bool       `json:"lsm"`
	TP           bool       `json:"tp"`
	Kprobe       bool       `json:"kprobe"`
	Events       uint64     `json:"events"`
	Drops        uint64     `json:"drops"`
	ReadFailures uint64     `json:"read_failures"`
	Loads        uint64     `json:"loads"`
	HelperRisk   uint64     `json:"helper_risk"`
	Epoch        string     `json:"epoch,omitempty"`
	SampledAt    *time.Time `json:"sampled_at,omitempty"`
}

// BpfGuardReport returns the honest operator view of the attach-time guard.
func (e *XDREngine) BpfGuardReport() BpfGuardReport {
	report := BpfGuardReport{State: "unavailable", Capability: "unknown"}
	if e == nil {
		return report
	}
	e.bpfGuardMu.Lock()
	status := e.bpfGuardStatus
	statusErr := e.bpfGuardStatusErr
	known := e.bpfGuardCapabilityKnown
	epoch := e.bpfGuardEpoch
	sampled := e.bpfGuardStatusAt
	e.bpfGuardMu.Unlock()
	report.Enabled = status.Enabled
	report.Attached = status.Attached
	report.LSM = status.LSMAttached
	report.TP = status.TPAttached
	report.Kprobe = status.KprobeAttached
	report.Events = status.Events
	report.Drops = status.Drops
	report.ReadFailures = status.ReadFailures
	report.Loads = status.Loads
	report.HelperRisk = status.HelperRisk
	report.Epoch = epoch
	if known && statusErr == "" && !sampled.IsZero() {
		at := sampled
		report.SampledAt = &at
	}
	switch {
	case !known:
		report.Capability = "missing"
		if statusErr != "" {
			report.State = "degraded"
			report.Reason = "attach-time eBPF guard " + statusErr
		} else {
			report.State = "unavailable"
			report.Reason = "the privileged core does not advertise the BPF_GUARD_* command family"
		}
	case statusErr != "":
		report.State = "degraded"
		report.Capability = "available"
		report.Reason = "attach-time eBPF guard " + statusErr
	case !status.Enabled:
		report.State = "disarmed"
		report.Capability = "available"
		report.Reason = "attach-time eBPF guard is armed off (BPF_GUARD_SET 0)"
	case !status.LSMAttached && !status.TPAttached:
		report.State = "degraded"
		report.Capability = "available"
		report.Reason = "attach-time eBPF guard is armed but no load-visibility hook (LSM bpf_prog / sys_enter_bpf) is attached"
		report.Attached = status.Attached
	default:
		report.State = "active"
		report.Capability = "available"
		if !status.KprobeAttached {
			report.Reason = "helper-risk kprobe (check_helper_call) is not attached; load/attach visibility is active but helper ids are not observed"
		}
	}
	if status.ReadFailures > 0 && report.Reason == "" {
		report.Reason = fmt.Sprintf("%d kernel-side read failure(s) reported by the guard", status.ReadFailures)
	}
	report.Reason = bpfGuardBoundedText(report.Reason, bpfGuardReportReasonBytes)
	return report
}
