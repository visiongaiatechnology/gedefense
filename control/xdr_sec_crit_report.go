// V6.3.0 AP-9 (S12): report-only operator projection of the independent
// high-priority security evidence ring, the two-class telemetry backpressure
// facts and the S12 quota review. The quotas are reported, never enforced.
package main

import (
	"errors"
	"fmt"
	"syscall"
	"time"
)

// SecCritReport is the bounded operator projection of the high-priority ring,
// the flood backpressure facts and the report-only S12 quota review. No route is
// added by this work package (no server.go edit); the method is the seam a later
// API wiring can call.
type SecCritReport struct {
	State            string             `json:"state"` // active | degraded | disarmed | unavailable
	Capability       string             `json:"capability"`
	Reason           string             `json:"reason,omitempty"`
	Enabled          bool               `json:"enabled"`
	Events           uint64             `json:"events"`
	Drops            uint64             `json:"drops"`
	RefusedUnarmed   uint64             `json:"refused_unarmed"`
	ReadFailures     uint64             `json:"read_failures"`
	Suppressed       uint64             `json:"suppressed"`
	BucketCapacity   uint64             `json:"bucket_capacity"`
	BucketAccounting string             `json:"bucket_accounting"`
	DedupeEntries    int                `json:"dedupe_entries"`
	LastPressureAt   *time.Time         `json:"last_pressure_at,omitempty"`
	SampledAt        *time.Time         `json:"sampled_at,omitempty"`
	Quotas           SecCritQuotaReport `json:"quotas"`
}

// SecCritQuotaReport is the report-only S12 hard-quota review. `Enforced` is
// false and stays false: the owning modules (parser cells, review queue,
// airlock) are outside this work package, so these numbers are reported
// honestly and never silently claim an enforcement the process does not apply.
type SecCritQuotaReport struct {
	Enforced                   bool     `json:"enforced"`
	CellHelperConcurrencyLimit int      `json:"cell_helper_concurrency_limit"`
	CellHelperActive           int      `json:"cell_helper_active"`
	CellHelperOK               bool     `json:"cell_helper_ok"`
	ReviewQueueBytes           int      `json:"review_queue_bytes"`
	ReviewQueueMaxBytes        int      `json:"review_queue_max_bytes"`
	ReviewQueueOK              bool     `json:"review_queue_ok"`
	QuarantineDir              string   `json:"quarantine_dir,omitempty"`
	QuarantineFreeBytes        uint64   `json:"quarantine_free_bytes"`
	QuarantineReserveBytes     uint64   `json:"quarantine_reserve_bytes"`
	QuarantineOK               bool     `json:"quarantine_ok"`
	Degraded                   []string `json:"degraded,omitempty"`
}

// SecCritReport returns the honest operator view. State is only "active" when a
// capability-known, enabled observer exists and no recent backpressure is
// pending; historical counters (drops/suppressed since boot) are always
// reported, so a recovered ring can never hide past loss.
func (e *XDREngine) SecCritReport() SecCritReport {
	report := SecCritReport{State: "unavailable", Capability: "unknown", Quotas: e.SecCritQuotaReport()}
	if e == nil {
		return report
	}
	e.secCritMu.Lock()
	status := e.secCritStatus
	statusErr := e.secCritStatusErr
	known := e.secCritCapabilityKnown
	sampled := e.secCritStatusAt
	seen := len(e.secCritSeen)
	var lastPressure time.Time
	probed := false
	pressureActive := false
	if e.secCrit != nil {
		lastPressure = e.secCrit.lastPressureAt
		probed = e.secCrit.capabilityProbed
		pressureActive = e.secCrit.pressureActive
	}
	e.secCritMu.Unlock()
	report.Enabled = status.Enabled
	report.Events = status.Events
	report.Drops = status.Drops
	report.RefusedUnarmed = status.RefusedUnarmed
	report.ReadFailures = status.ReadFailures
	report.Suppressed = status.Suppressed
	report.BucketCapacity = status.BucketCapacity
	report.BucketAccounting = secCritBucketAccounting
	report.DedupeEntries = seen
	if !lastPressure.IsZero() {
		at := lastPressure
		report.LastPressureAt = &at
	}
	if known && statusErr == "" && !sampled.IsZero() {
		at := sampled
		report.SampledAt = &at
	}
	switch {
	case !known:
		if probed {
			report.Capability = "missing"
		} else {
			report.Capability = "unknown"
		}
		if statusErr != "" {
			report.State = "degraded"
			report.Reason = "high-priority security ring " + statusErr
		} else {
			report.State = "unavailable"
			if probed {
				report.Reason = "the privileged core does not advertise the SEC_CRIT_* command family"
			} else {
				report.Reason = "high-priority security ring capability has not been sampled yet"
			}
		}
	case statusErr != "":
		report.State = "degraded"
		report.Capability = "available"
		report.Reason = "high-priority security ring " + statusErr
	case !status.Enabled:
		report.State = "disarmed"
		report.Capability = "available"
		report.Reason = "high-priority security ring is armed off (SEC_CRIT_SET 0); bulk telemetry is not throttled while disarmed"
	case pressureActive:
		report.State = "degraded"
		report.Capability = "available"
		report.Reason = fmt.Sprintf(
			"S12 telemetry backpressure active: suppressed=%d drops=%d refused_unarmed=%d read_failures=%d bucket capacity=%d",
			status.Suppressed, status.Drops, status.RefusedUnarmed, status.ReadFailures, status.BucketCapacity)
	default:
		report.State = "active"
		report.Capability = "available"
		if status.Drops > 0 || status.Suppressed > 0 {
			report.Reason = fmt.Sprintf(
				"history since boot: suppressed=%d, high-priority ring drops=%d (currently recovered; counters are monotonic)",
				status.Suppressed, status.Drops)
		}
	}
	report.Reason = boundedPermitText(report.Reason, secCritReasonBytes)
	return report
}

// SecCritQuotaReport reviews the three S12 hard quotas against the live owner
// modules. Report-only: it never refuses an ingest and never changes quarantine
// or parser-cell behaviour.
func (e *XDREngine) SecCritQuotaReport() SecCritQuotaReport {
	report := SecCritQuotaReport{
		Enforced:               false,
		QuarantineReserveBytes: secCritQuarantineReserve,
		CellHelperOK:           true,
		ReviewQueueOK:          true,
		QuarantineOK:           true,
	}
	if e == nil {
		return report
	}
	reasons := make([]string, 0, secCritQuotaReasonsShown)
	addReason := func(reason string) {
		if len(reasons) >= secCritQuotaReasonsShown {
			return
		}
		reasons = append(reasons, boundedPermitText(reason, secCritQuotaReasonBytes))
	}

	// 1. Parser-cell (R5) helper concurrency: read the manager's local snapshot
	//    (no helper I/O from this projection).
	if e.parserCells != nil {
		cells := e.parserCells.Status()
		report.CellHelperConcurrencyLimit = cells.MaxConcurrent
		report.CellHelperActive = cells.Active
		switch {
		case !cells.Enabled:
			report.CellHelperOK = true
		case cells.MaxConcurrent <= 0:
			report.CellHelperOK = false
			addReason("parser cell concurrency limit is not configured while parser cells are enabled")
		case cells.Active > cells.MaxConcurrent:
			report.CellHelperOK = false
			addReason(fmt.Sprintf("parser cell concurrency exceeded: active=%d limit=%d", cells.Active, cells.MaxConcurrent))
		case cells.Helper == "unavailable":
			report.CellHelperOK = false
			addReason("parser cell helper is unavailable; the concurrency quota is not enforceable")
		}
	}

	// 2. Review-queue byte quota (AP-7 queue projection).
	if e.reviewQueue != nil {
		queue := e.reviewQueue.Report()
		report.ReviewQueueBytes = queue.Bytes
		report.ReviewQueueMaxBytes = queue.MaxBytes
		switch {
		case queue.Corrupt:
			report.ReviewQueueOK = false
			addReason("persistent review queue store is corrupt; byte quota unobservable")
		case !queue.Loaded:
			report.ReviewQueueOK = false
			addReason("persistent review queue store is not bound/loaded; byte quota unobservable")
		case queue.MaxBytes > 0 && queue.Bytes > queue.MaxBytes:
			report.ReviewQueueOK = false
			addReason(fmt.Sprintf("review queue bytes exceeded: used=%d max=%d", queue.Bytes, queue.MaxBytes))
		case queue.Degraded:
			report.ReviewQueueOK = false
			addReason("review queue degraded: " + queue.DegradedReason)
		}
	}

	// 3. Quarantine filesystem reserve minimum. Report-only: a low reserve is
	//    surfaced as degraded capability but never changes quarantine behaviour.
	if e.airlock != nil {
		report.QuarantineDir = e.airlock.quarantineDir
		if report.QuarantineDir == "" {
			report.QuarantineOK = false
			addReason("quarantine directory is not configured")
		} else if free, err := secCritFilesystemFreeBytes(report.QuarantineDir); err != nil {
			report.QuarantineOK = false
			addReason("quarantine filesystem unavailable: " + boundedStyxText(err))
		} else {
			report.QuarantineFreeBytes = free
			if free < secCritQuarantineReserve {
				report.QuarantineOK = false
				addReason(fmt.Sprintf(
					"quarantine free space below the %d MiB reserve: free=%d MiB",
					secCritQuarantineReserve>>20, free>>20))
			}
		}
	}
	report.Degraded = reasons
	return report
}

// secCritFilesystemFreeBytes returns the unprivileged-available free bytes of
// the filesystem containing path (statfs, no shell).
func secCritFilesystemFreeBytes(path string) (uint64, error) {
	var stat syscall.Statfs_t
	if err := syscall.Statfs(path, &stat); err != nil {
		return 0, err
	}
	if stat.Bsize <= 0 {
		return 0, errors.New("filesystem block size is not positive")
	}
	return stat.Bavail * uint64(stat.Bsize), nil
}
