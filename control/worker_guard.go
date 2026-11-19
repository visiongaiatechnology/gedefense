// STATUS: DIAMANT VGT SUPREME
package main

// GeDefense 6.1.0 Module B: worker-integrity watch engine and API.
//
//	GET /api/v1/worker-guard/status
//	GET /api/v1/worker-guard/events
//
// The engine correlates fatal worker crashes (>= storm_threshold inside the
// window -> one CRITICAL incident with rule XDR.WORKER_CRASH_STORM), classifies
// the live web workers and, when auto_apply_strict is enabled, writes the
// computed strict-cgroup list through the existing Titan exec settings/apply
// path - never silently on load.

import (
	"context"
	"strconv"
	"sync"
	"time"

	"github.com/visiongaiatechnology/gedefense/control/internal/workerguard"
)

const (
	workerGuardEventRing     = 256
	workerGuardStatusLimit   = 256
	workerGuardStormScore    = 200
	workerGuardReconcileTick = 2 * time.Second
)

// WorkerGuardEngine is the Module B runtime.
type WorkerGuardEngine struct {
	settings *SettingsStore
	state    *State
	core     *CoreClient
	xdr      *XDREngine
	peers    func() []string

	mu                sync.Mutex
	source            CrashSource
	sourceStop        context.CancelFunc
	sourceMode        string
	sourceReason      string
	sourceRegistryKey string
	registry          workerguard.Registry
	correlator        *workerguard.Correlator
	correlatorKey     string
	workers           []workerguard.Worker
	skippedCgroups    []workerguard.SkippedCgroup
	scanReason        string
	strictReason      string
	skippedKey        string
	fallbackReason    string
	events            []workerGuardEventView
	cursor            uint64
	appliedStrict     string
}

// NewWorkerGuardEngine constructs the Module B engine.
func NewWorkerGuardEngine(settings *SettingsStore, state *State, core *CoreClient, xdr *XDREngine, peers func() []string) *WorkerGuardEngine {
	return &WorkerGuardEngine{
		settings: settings, state: state, core: core, xdr: xdr, peers: peers,
		sourceMode: workerGuardSourceNone, events: make([]workerGuardEventView, 0, workerGuardEventRing),
		correlator: workerguard.NewCorrelator(workerguard.Config{}),
	}
}

// Run reconciles the enabled namespace with the live sensor and classification.
func (e *WorkerGuardEngine) Run(ctx context.Context) {
	if e == nil {
		return
	}
	ticker := time.NewTicker(workerGuardReconcileTick)
	defer ticker.Stop()
	e.reconcile(ctx)
	for {
		select {
		case <-ctx.Done():
			e.stopSource()
			return
		case <-ticker.C:
			e.reconcile(ctx)
		}
	}
}

// reconcile reads the persisted settings, re-classifies the live workers and
// starts/stops/resynchronizes the crash source.
func (e *WorkerGuardEngine) reconcile(ctx context.Context) {
	if e == nil || e.settings == nil {
		return
	}
	settings := effectiveWorkerGuardSettings(e.settings.Get())
	registry := ToWorkerguardRegistry(settings)
	registryKey := workerguard.RegistryFingerprint(registry)
	e.mu.Lock()
	previousRegistry := e.registry
	previousKey := e.sourceRegistryKey
	e.registry = registry
	e.mu.Unlock()
	if !settings.Enabled {
		e.stopSource()
		e.mu.Lock()
		e.sourceMode, e.sourceReason = workerGuardSourceNone, "worker guard module is disabled; no crash source is subscribed"
		e.sourceRegistryKey = ""
		e.workers = nil
		e.skippedCgroups = nil
		e.scanReason = ""
		e.strictReason = ""
		e.mu.Unlock()
		return
	}
	e.ensureCorrelator(settings)
	e.refreshWorkers(registry, settings)
	if e.sourceRunning() {
		// The eBPF write path only adds entries, so a removed comm/uid would stay
		// armed. On a registry change the engine deletes the stale entries and
		// restarts the source with the new registry (FIND-005).
		if previousKey != "" && previousKey != registryKey {
			e.resyncSource(ctx, previousRegistry, registry, settings)
		}
		e.applyStrictPlan(settings)
		return
	}
	e.startSource(ctx, registry, settings)
	e.mu.Lock()
	e.sourceRegistryKey = registryKey
	e.mu.Unlock()
	e.applyStrictPlan(settings)
}

// ensureCorrelator rebuilds the correlation state when its bounds change.
func (e *WorkerGuardEngine) ensureCorrelator(settings WorkerGuardFabricSettings) {
	key := strconv.Itoa(settings.StormThreshold) + "|" + strconv.Itoa(settings.StormWindowSeconds) + "|" + strconv.FormatBool(settings.CorrelatePeers)
	e.mu.Lock()
	defer e.mu.Unlock()
	if key == e.correlatorKey {
		return
	}
	e.correlatorKey = key
	e.correlator = workerguard.NewCorrelator(workerguard.Config{
		Threshold: settings.StormThreshold, WindowSeconds: settings.StormWindowSeconds,
		CorrelatePeers: settings.CorrelatePeers,
	})
}

// refreshWorkers classifies the live workers for the status payload and plan,
// including the cgroups that were kept out of the strict scope because they host
// an excluded master/control process.
func (e *WorkerGuardEngine) refreshWorkers(registry workerguard.Registry, settings WorkerGuardFabricSettings) {
	result := ScanWorkers(registry, settings.StrictExec || settings.StrictMmap, workerGuardStatusLimit)
	strictReason := result.Reason
	if strictReason == "" && len(result.Skipped) > 0 {
		strictReason = strconv.Itoa(len(result.Skipped)) +
			" cgroup(s) kept out of the strict Titan scope because they also host an excluded master/control process"
	}
	key := skippedCgroupsKey(result.Skipped)
	e.mu.Lock()
	e.workers = result.Workers
	e.skippedCgroups = result.Skipped
	e.scanReason = result.Reason
	e.strictReason = strictReason
	changed := key != e.skippedKey
	e.skippedKey = key
	e.mu.Unlock()
	if changed && len(result.Skipped) > 0 {
		e.recordEvent("medium", "worker_guard.strict_scope_skipped",
			"strict Titan scope withheld for "+strconv.Itoa(len(result.Skipped))+" cgroup(s): "+result.Skipped[0].Reason)
	}
}

// skippedCgroupsKey is the change detector for the exclusion list.
func skippedCgroupsKey(skipped []workerguard.SkippedCgroup) string {
	key := ""
	for _, entry := range skipped {
		key += strconv.FormatUint(entry.CgroupID, 10) + ","
	}
	return key
}

// recordEvent publishes one operator-facing engine event.
func (e *WorkerGuardEngine) recordEvent(severity, kind, message string) {
	if e == nil || e.state == nil {
		return
	}
	e.state.AddEvent(Event{Severity: severity, Kind: kind, Source: "workerguard", Message: message})
}

// handleCrash is the correlation entry point for both crash sources.
func (e *WorkerGuardEngine) handleCrash(event WorkerCrashEvent) {
	if e == nil {
		return
	}
	comm, err := workerguard.NormalizeComm(event.Comm)
	if err != nil {
		return
	}
	e.mu.Lock()
	correlator := e.correlator
	settings := WorkerGuardFabricSettings{}
	if e.settings != nil {
		settings = effectiveWorkerGuardSettings(e.settings.Get())
	}
	e.mu.Unlock()
	if correlator == nil || !settings.Enabled {
		return
	}
	outcome := correlator.Observe(workerguard.CrashEvent{
		At: event.At, PID: event.PID, Comm: comm, UID: event.UID, GID: event.GID,
		CgroupID: event.CgroupID, Signal: event.Signal, ExitCode: event.ExitCode,
		Peer: event.Peer, Source: event.Source,
	})
	if !outcome.Audit {
		return
	}
	view := workerGuardEventView{
		At: event.At, PID: event.PID, Comm: comm, UID: event.UID,
		Signal: workerguard.SignalName(event.Signal), ExitCode: event.ExitCode,
		CgroupID: event.CgroupID, Peer: event.Peer, Source: event.Source,
	}
	e.mu.Lock()
	e.events = append([]workerGuardEventView{view}, e.events...)
	if len(e.events) > workerGuardEventRing {
		e.events = e.events[:workerGuardEventRing]
	}
	e.mu.Unlock()
	if e.state != nil {
		e.state.AddEvent(Event{
			Severity: "medium", Kind: "worker_guard.crash", Source: "workerguard",
			Message: "web worker " + comm + " died from " + view.Signal + " (pid " + strconv.Itoa(event.PID) + ", exit " + strconv.Itoa(event.ExitCode) + ")",
		})
	}
	if outcome.Storm == nil {
		return
	}
	storm := *outcome.Storm
	if settings.CorrelatePeers && len(storm.Peers) == 0 && e.peers != nil {
		for _, peer := range e.peers() {
			storm.Peers = append(storm.Peers, peer)
			if len(storm.Peers) >= 8 {
				break
			}
		}
	}
	e.raiseStormIncident(storm)
}

// raiseStormIncident records the one CRITICAL incident per comm+window.
func (e *WorkerGuardEngine) raiseStormIncident(storm workerguard.Storm) {
	summary := "worker crash storm: " + storm.Comm + " crashed " + strconv.Itoa(storm.Crashes) +
		" times within " + strconv.Itoa(storm.WindowSeconds) + " s"
	remote := ""
	if len(storm.Peers) > 0 {
		remote = storm.Peers[0]
	}
	incident := XDRIncident{
		ID: randomID(), Time: time.Now().UTC(), Severity: "critical", Score: workerGuardStormScore, ResponseScore: workerGuardStormScore,
		PID: 0, UID: storm.UID, CellCgroupID: 0, Process: storm.Comm,
		Remote: remote, RuleIDs: []string{"XDR.WORKER_CRASH_STORM"},
		Categories: []string{"xdr", "worker-integrity"},
		Summary:    summary, Decision: "alert", Action: "none",
		Outcome: "crash storm recorded; strict scope and TLS flow review are available to the operator",
	}
	if e.xdr != nil {
		e.xdr.appendIncident(incident)
		return
	}
	if e.state != nil {
		e.state.AddIncident(incident)
	}
}

// applyStrictPlan writes the computed strict-cgroup list through the existing
// Titan exec settings/apply path. It is a no-op unless the operator enabled
// auto_apply_strict, and it never runs while the module is disabled. Cgroups
// that also host an excluded master/control process never reach e.workers, so
// they can never enter the strict scope.
func (e *WorkerGuardEngine) applyStrictPlan(settings WorkerGuardFabricSettings) {
	if !settings.Enabled || !settings.AutoApplyStrict || e.settings == nil {
		return
	}
	strict := settings.StrictExec || settings.StrictMmap
	if !strict {
		return
	}
	ids := make([]uint64, 0, 8)
	seen := make(map[uint64]struct{}, 8)
	e.mu.Lock()
	workers := append([]workerguard.Worker(nil), e.workers...)
	e.mu.Unlock()
	for _, worker := range workers {
		if worker.CgroupID == 0 || !worker.Strict {
			continue
		}
		if _, dup := seen[worker.CgroupID]; dup {
			continue
		}
		seen[worker.CgroupID] = struct{}{}
		ids = append(ids, worker.CgroupID)
	}
	if len(ids) == 0 {
		return
	}
	fingerprint := ""
	for _, id := range ids {
		fingerprint += strconv.FormatUint(id, 10) + ","
	}
	e.mu.Lock()
	alreadyApplied := fingerprint == e.appliedStrict
	e.mu.Unlock()
	if alreadyApplied {
		return
	}
	current := e.settings.Get()
	titan := effectiveTitanExecFabricSettings(current)
	next := cloneRuntimeSettings(current)
	nextTitan := cloneTitanExecFabricSettings(titan)
	nextTitan.StrictCgroups = ids
	next.TitanExec = &nextTitan
	updated, err := e.settings.Update(next)
	if err != nil {
		if e.state != nil {
			e.state.AddEvent(Event{Severity: "medium", Kind: "worker_guard.strict_plan_rejected", Source: "workerguard", Message: "strict Titan scope plan rejected: " + err.Error()})
		}
		return
	}
	if e.xdr != nil {
		if err := e.xdr.ApplyRuntimeSettings(updated); err != nil {
			if e.state != nil {
				e.state.AddEvent(Event{Severity: "medium", Kind: "worker_guard.strict_apply_failed", Source: "workerguard", Message: "strict Titan scope apply failed: " + err.Error()})
			}
			return
		}
	}
	e.mu.Lock()
	e.appliedStrict = fingerprint
	e.mu.Unlock()
	if e.state != nil {
		e.state.AddEvent(Event{Severity: "info", Kind: "worker_guard.strict_applied", Source: "workerguard", Message: "strict Titan exec scope plan persisted for " + strconv.Itoa(len(ids)) + " web-worker cgroup(s) through the Titan exec settings path"})
	}
}

// ApplyState maps the persisted revision onto the Fabric Settings vocabulary.
func (e *WorkerGuardEngine) ApplyState(settings RuntimeSettings) string {
	if e == nil {
		return "engine_unavailable"
	}
	desired := effectiveWorkerGuardSettings(settings)
	if !desired.Enabled {
		return "disabled"
	}
	if _, _, active := e.liveSourceState(); !active {
		return "engine_unavailable"
	}
	return "applied"
}

// Details is the Settings-module runtime projection.
func (e *WorkerGuardEngine) Details() map[string]any {
	if e == nil {
		return map[string]any{"runtime": "unavailable"}
	}
	mode, reason, active := e.liveSourceState()
	e.mu.Lock()
	workers := append([]workerguard.Worker(nil), e.workers...)
	skipped := append([]workerguard.SkippedCgroup(nil), e.skippedCgroups...)
	strictReason := e.strictReason
	e.mu.Unlock()
	return map[string]any{
		"runtime": map[string]any{
			"source": mode, "reason": reason, "active": active, "workers": len(workers),
			"strict_cgroups": strictCgroupIDs(workers), "strict_reason": strictReason,
			"skipped_cgroups": len(skipped),
		},
	}
}
