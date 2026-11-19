// STATUS: DIAMANT VGT SUPREME
package main

// GeDefense 6.1.0 Module B API payloads and handlers.
//
//	GET /api/v1/worker-guard/status
//	GET /api/v1/worker-guard/events

import (
	"net/http"
	"strconv"
	"time"

	"github.com/visiongaiatechnology/gedefense/control/internal/workerguard"
)

// -------------------------------------------------------------- API payloads

type workerGuardRegistryView struct {
	Comms         []string `json:"comms"`
	UIDs          []uint32 `json:"uids"`
	StrictCgroups []uint64 `json:"strict_cgroups"`
}

type workerGuardCountersView struct {
	Events     uint64 `json:"events"`
	Storms     uint64 `json:"storms"`
	DeniedExec uint64 `json:"denied_exec"`
	DeniedMmap uint64 `json:"denied_mmap"`
}

type workerGuardWorkerView struct {
	PID      int    `json:"pid"`
	Comm     string `json:"comm"`
	UID      uint32 `json:"uid"`
	CgroupID uint64 `json:"cgroup_id"`
	Strict   bool   `json:"strict"`
}

// workerGuardSkippedCgroupView explains why a cgroup was withheld from the
// strict Titan scope. Additive key: existing clients keep working, the dashboard
// can explain why no strict scope exists for a service.
type workerGuardSkippedCgroupView struct {
	CgroupID   uint64 `json:"cgroup_id"`
	CgroupPath string `json:"cgroup_path"`
	Comm       string `json:"comm"`
	Reason     string `json:"reason"`
}

type workerGuardStatusView struct {
	GeneratedAt    time.Time                      `json:"generated_at"`
	Mode           string                         `json:"mode"`
	Source         string                         `json:"source"`
	Capability     string                         `json:"capability"`
	Reason         string                         `json:"reason"`
	Registry       workerGuardRegistryView        `json:"registry"`
	Counters       workerGuardCountersView        `json:"counters"`
	Workers        []workerGuardWorkerView        `json:"workers"`
	RecentStorms   []workerguard.Storm            `json:"recent_storms"`
	SkippedCgroups []workerGuardSkippedCgroupView `json:"skipped_cgroups"`
	StrictReason   string                         `json:"strict_reason"`
}

type workerGuardEventView struct {
	At       time.Time `json:"at"`
	PID      int       `json:"pid"`
	Comm     string    `json:"comm"`
	UID      uint32    `json:"uid"`
	Signal   string    `json:"signal"`
	ExitCode int       `json:"exit_code"`
	CgroupID uint64    `json:"cgroup_id"`
	Peer     string    `json:"peer"`
	Source   string    `json:"source"`
}

// workerGuardStatus serves GET /api/v1/worker-guard/status.
func (s *APIServer) workerGuardStatus(w http.ResponseWriter, _ *http.Request) {
	view := workerGuardStatusView{
		GeneratedAt: time.Now().UTC(), Mode: "observe", Source: workerGuardSourceNone, Capability: "inactive",
		Reason:   "worker guard engine is not wired on this control plane",
		Registry: workerGuardRegistryView{Comms: []string{}, UIDs: []uint32{}, StrictCgroups: []uint64{}},
		Workers:  []workerGuardWorkerView{}, RecentStorms: []workerguard.Storm{},
		SkippedCgroups: []workerGuardSkippedCgroupView{},
	}
	if s.v61 == nil || s.v61.workerGuard == nil || s.settings == nil {
		writeJSON(w, http.StatusOK, view)
		return
	}
	engine := s.v61.workerGuard
	settings := effectiveWorkerGuardSettings(s.settings.Get())
	mode, reason, active := engine.liveSourceState()
	engine.mu.Lock()
	workers := append([]workerguard.Worker(nil), engine.workers...)
	skipped := append([]workerguard.SkippedCgroup(nil), engine.skippedCgroups...)
	strictReason := engine.strictReason
	correlator := engine.correlator
	engine.mu.Unlock()
	view.Source = mode
	view.Reason = reason
	// Capability is active only when a live source really runs. The eBPF source
	// itself reports mode `none` unless the core confirmed `attached=1`.
	if active {
		view.Capability = "active"
	}
	view.StrictReason = strictReason
	for _, skip := range skipped {
		view.SkippedCgroups = append(view.SkippedCgroups, workerGuardSkippedCgroupView{
			CgroupID: skip.CgroupID, CgroupPath: skip.CgroupPath, Comm: skip.Comm, Reason: skip.Reason,
		})
	}
	view.Registry.Comms = append([]string{}, settings.Comms...)
	view.Registry.UIDs = append([]uint32{}, settings.UIDs...)
	view.Registry.StrictCgroups = strictCgroupIDs(workers)
	if !settings.Enabled {
		view.Mode = "disabled"
	} else if active && (len(view.Registry.StrictCgroups) > 0 || settings.StrictExec || settings.StrictMmap) {
		view.Mode = "enforce"
	} else if active {
		view.Mode = "active"
	}
	for _, worker := range workers {
		view.Workers = append(view.Workers, workerGuardWorkerView{PID: worker.PID, Comm: worker.Comm, UID: worker.UID, CgroupID: worker.CgroupID, Strict: worker.Strict})
	}
	view.Counters = workerGuardCountersView{}
	if correlator != nil {
		counters := correlator.CounterSnapshot()
		view.Counters.Events = counters.Events
		view.Counters.Storms = counters.Storms
		view.RecentStorms = correlator.RecentStorms(8)
	}
	view.Counters.DeniedExec, view.Counters.DeniedMmap = titanExecDenyCounters(s.xdr)
	writeJSON(w, http.StatusOK, view)
}

// workerGuardEvents serves GET /api/v1/worker-guard/events.
func (s *APIServer) workerGuardEvents(w http.ResponseWriter, r *http.Request) {
	if s.v61 == nil || s.v61.workerGuard == nil {
		writeJSON(w, http.StatusOK, map[string]any{"events": []workerGuardEventView{}, "next": "0"})
		return
	}
	limit := clampQueryInt(r.URL.Query().Get("limit"), 100, 1, workerGuardEventRing)
	cursor := clampQueryInt(r.URL.Query().Get("cursor"), 0, 0, workerGuardEventRing)
	engine := s.v61.workerGuard
	engine.mu.Lock()
	total := len(engine.events)
	if cursor > total {
		cursor = total
	}
	end := cursor + limit
	if end > total {
		end = total
	}
	events := append([]workerGuardEventView(nil), engine.events[cursor:end]...)
	engine.mu.Unlock()
	next := strconv.Itoa(end)
	writeJSON(w, http.StatusOK, map[string]any{"events": events, "next": next})
}

// strictCgroupIDs projects the strict worker cgroups in stable order.
func strictCgroupIDs(workers []workerguard.Worker) []uint64 {
	out := make([]uint64, 0, len(workers))
	seen := make(map[uint64]struct{}, len(workers))
	for _, worker := range workers {
		if worker.CgroupID == 0 || !worker.Strict {
			continue
		}
		if _, dup := seen[worker.CgroupID]; dup {
			continue
		}
		seen[worker.CgroupID] = struct{}{}
		out = append(out, worker.CgroupID)
	}
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j-1] > out[j]; j-- {
			out[j-1], out[j] = out[j], out[j-1]
		}
	}
	return out
}

// titanExecDenyCounters derives the bounded kernel deny split from the exec-gate
// event history. Only the retained history is counted; the payload names it as a
// window, never as a lifetime total.
func titanExecDenyCounters(xdr *XDREngine) (uint64, uint64) {
	if xdr == nil {
		return 0, 0
	}
	view := xdr.TitanExecEventsReport(64)
	var execDenies, mmapDenies uint64
	for _, event := range view.Events {
		if event.Action != titanExecActionDeny {
			continue
		}
		if event.Hook == titanExecHookMmap {
			mmapDenies++
		} else {
			execDenies++
		}
	}
	return execDenies, mmapDenies
}

// clampQueryInt parses a bounded integer query parameter.
func clampQueryInt(raw string, fallback, min, max int) int {
	if raw == "" {
		return fallback
	}
	value, err := strconv.Atoi(raw)
	if err != nil {
		return fallback
	}
	if value < min {
		return min
	}
	if value > max {
		return max
	}
	return value
}
