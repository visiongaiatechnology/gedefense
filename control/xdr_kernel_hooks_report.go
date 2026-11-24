package main

import (
	"time"
)

// KernelHooksReport is the bounded operator projection of the io_uring/LKM hook
// family for future API wiring (no route is added by AP-4). State is only
// "active" when the family is armed and both sensor halves are attached; partial
// ladders are reported as degraded with the missing piece named.
type KernelHooksReport struct {
	State       string     `json:"state"` // active | degraded | disarmed | unavailable
	Capability  string     `json:"capability"`
	Reason      string     `json:"reason,omitempty"`
	Enabled     bool       `json:"enabled"`
	Attached    bool       `json:"attached"`
	IoUring     bool       `json:"io_uring"`
	ModuleTrace bool       `json:"module_trace"`
	Kprobes     uint8      `json:"kprobes"`
	LsmExtra    uint8      `json:"lsm_extra"`
	Events      uint64     `json:"events"`
	Drops       uint64     `json:"drops"`
	Loads       uint64     `json:"loads"`
	RingCreates uint64     `json:"ring_creates"`
	Epoch       string     `json:"epoch,omitempty"`
	SampledAt   *time.Time `json:"sampled_at,omitempty"`
}

// KernelHooksReport returns the honest operator view of the io_uring/LKM hooks.
func (e *XDREngine) KernelHooksReport() KernelHooksReport {
	report := KernelHooksReport{State: "unavailable", Capability: "unknown"}
	if e == nil {
		return report
	}
	e.kernelHooksMu.Lock()
	status := e.kernelHooksStatus
	statusErr := e.kernelHooksStatusErr
	known := e.kernelHooksCapabilityKnown
	epoch := e.kernelHooksEpoch
	sampled := e.kernelHooksStatusAt
	e.kernelHooksMu.Unlock()
	report.Enabled = status.Enabled
	report.Attached = status.Attached
	report.IoUring = status.IoUring
	report.ModuleTrace = status.ModuleTrace
	report.Kprobes = status.Kprobes
	report.LsmExtra = status.LsmExtra
	report.Events = status.Events
	report.Drops = status.Drops
	report.Loads = status.Loads
	report.RingCreates = status.RingCreates
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
			report.Reason = "io_uring/LKM kernel hooks " + statusErr
		} else {
			report.State = "unavailable"
			report.Reason = "the privileged core does not advertise the KERNEL_HOOK_* command family"
		}
	case statusErr != "":
		report.State = "degraded"
		report.Capability = "available"
		report.Reason = "io_uring/LKM kernel hooks " + statusErr
	case !status.Enabled:
		report.State = "disarmed"
		report.Capability = "available"
		report.Reason = "io_uring/LKM kernel hooks are armed off (KERNEL_HOOK_SET 0)"
	case !status.IoUring || (!status.ModuleTrace && status.Kprobes == 0):
		report.State = "degraded"
		report.Capability = "available"
		switch {
		case !status.IoUring && !status.ModuleTrace && status.Kprobes == 0:
			report.Reason = "io_uring/LKM kernel hooks are armed but no hook attached"
		case !status.IoUring:
			report.Reason = "io_uring tracepoints are not attached; only module-load visibility is active"
		default:
			report.Reason = "module-load visibility is not attached; only io_uring visibility is active"
		}
	default:
		report.State = "active"
		report.Capability = "available"
		switch {
		case status.LsmExtra == 0:
			report.Reason = "LSM uring_* hooks are not exposed by this kernel/BPF-LSM configuration (optional)"
		case status.Kprobes == 0:
			report.Reason = "module-syscall kprobes are not attached (symbols absent); module visibility relies on the module_load tracepoint"
		}
	}
	report.Reason = kernelHooksBoundedText(report.Reason, kernelHooksReportReasonBytes)
	return report
}
