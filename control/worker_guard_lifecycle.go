package main

// GeDefense 6.1.0 Module B: crash-source lifecycle and capability honesty.
//
// The engine reports `source: ebpf` only after the core confirmed `attached=1`.
// When the eBPF surface is inactive or unavailable the engine disarms the stale
// maps, records the concrete reason and starts the proc-connector fallback; a
// registry change while a source runs deletes the stale comm/uid entries and
// restarts the source (FIND-005).

import (
	"context"
	"errors"
	"strconv"

	"github.com/visiongaiatechnology/gedefense/control/internal/workerguard"
)

// startSource starts the eBPF source (when a privileged core exists) with the
// proc connector as the announced fallback. The engine reports no capability
// until a source proves it is live.
func (e *WorkerGuardEngine) startSource(ctx context.Context, registry workerguard.Registry, settings WorkerGuardFabricSettings) {
	sourceCtx, cancel := context.WithCancel(ctx)
	if e.core == nil {
		source := NewNetlinkCrashSource(registry, settings.StrictExec || settings.StrictMmap)
		e.mu.Lock()
		e.source = source
		e.sourceStop = cancel
		e.sourceMode = workerGuardSourceNone
		e.sourceReason = "no privileged core client; starting the proc-connector fallback"
		e.mu.Unlock()
		go e.runNetlinkSource(sourceCtx, source)
		return
	}
	source := NewEBPFCrashSource(e.core, registry)
	e.mu.Lock()
	e.source = source
	e.sourceStop = cancel
	e.sourceMode = workerGuardSourceNone
	e.sourceReason = "eBPF worker guard source is starting"
	e.mu.Unlock()
	go e.runSource(sourceCtx, source, registry, settings)
}

// runSource starts the preferred source and hands over to the proc-connector
// fallback when the eBPF surface cannot serve. The reason is always recorded so
// the status payload can explain the degradation.
func (e *WorkerGuardEngine) runSource(ctx context.Context, source CrashSource, registry workerguard.Registry, settings WorkerGuardFabricSettings) {
	err := source.Start(ctx, e.handleCrash)
	if ctx.Err() != nil || err == nil {
		e.clearSource(source)
		return
	}
	if _, isEBPF := source.(*ebpfCrashSource); !isEBPF {
		mode, reason := normalizedSourceState(source, err)
		e.clearSource(source)
		e.setSourceState(mode, reason)
		return
	}
	_, reason := source.Status()
	if reason == "" {
		reason = err.Error()
	}
	// The eBPF maps may still be armed even though the source cannot serve them
	// (for example a drain that fails with the command family marked
	// unavailable). Disarm before handing over so no stale registry stays armed.
	if e.core != nil {
		_, _ = e.core.WorkerGuardSet(false)
	}
	if e.recordFallbackReason(reason) {
		e.recordEvent("medium", "worker_guard.crash_source_fallback",
			"eBPF worker guard source unavailable ("+reason+"); starting the proc-connector source")
	}
	fallback := NewNetlinkCrashSource(registry, settings.StrictExec || settings.StrictMmap)
	e.mu.Lock()
	if e.source != source || ctx.Err() != nil {
		e.mu.Unlock()
		e.clearSource(source)
		return
	}
	e.source = fallback
	e.sourceMode = workerGuardSourceNone
	e.sourceReason = reason
	e.mu.Unlock()
	e.runNetlinkSource(ctx, fallback)
}

// recordFallbackReason reports whether the fallback reason changed, so a broken
// environment does not write one event every reconcile tick.
func (e *WorkerGuardEngine) recordFallbackReason(reason string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.fallbackReason == reason {
		return false
	}
	e.fallbackReason = reason
	return true
}

// runNetlinkSource runs the proc-connector fallback to completion and records
// its verified state.
func (e *WorkerGuardEngine) runNetlinkSource(ctx context.Context, source CrashSource) {
	err := source.Start(ctx, e.handleCrash)
	if ctx.Err() != nil {
		e.clearSource(source)
		return
	}
	mode, reason := normalizedSourceState(source, err)
	if err != nil {
		reason = "proc-connector source unavailable: " + reason
	}
	e.clearSource(source)
	e.setSourceState(mode, reason)
}

// normalizedSourceState maps a returned source to its honest (mode, reason).
func normalizedSourceState(source CrashSource, startErr error) (string, string) {
	mode, reason := source.Status()
	if mode == "" {
		mode = workerGuardSourceNone
	}
	if startErr != nil && reason == "" {
		reason = startErr.Error()
	}
	return mode, reason
}

func (e *WorkerGuardEngine) setSourceState(mode, reason string) {
	e.mu.Lock()
	e.sourceMode, e.sourceReason = mode, reason
	e.mu.Unlock()
}

// clearSource forgets a source that returned and cancels the context that
// belonged to it, so the next reconcile tick retries cleanly.
func (e *WorkerGuardEngine) clearSource(source CrashSource) {
	e.mu.Lock()
	stop := e.sourceStop
	if e.source == source {
		e.source = nil
		e.sourceStop = nil
		e.sourceMode = workerGuardSourceNone
	} else {
		stop = nil
	}
	e.mu.Unlock()
	if stop != nil {
		stop()
	}
}

func (e *WorkerGuardEngine) sourceRunning() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.source != nil
}

// stopSource cancels the running source.
func (e *WorkerGuardEngine) stopSource() {
	e.mu.Lock()
	stop := e.sourceStop
	e.source = nil
	e.sourceStop = nil
	e.mu.Unlock()
	if stop != nil {
		stop()
	}
}

// resyncSource deletes the identities that are no longer armed and restarts the
// crash source with the new registry. Without the explicit delete the eBPF write
// path would keep a removed comm armed indefinitely.
func (e *WorkerGuardEngine) resyncSource(ctx context.Context, previous, next workerguard.Registry, settings WorkerGuardFabricSettings) {
	removedComms := workerguard.RemovedComms(previous, next)
	removedUIDs := workerguard.RemovedUIDs(previous, next)
	if e.core != nil {
		for _, comm := range removedComms {
			if err := e.core.WorkerGuardCommDel(comm); err != nil && !errors.Is(err, ErrWorkerGuardUnavailable) {
				e.recordEvent("medium", "worker_guard.registry_disarm_failed",
					"could not disarm removed worker comm "+strconv.Quote(comm)+": "+err.Error())
			}
		}
		for _, uid := range removedUIDs {
			if err := e.core.WorkerGuardUIDDel(uid); err != nil && !errors.Is(err, ErrWorkerGuardUnavailable) {
				e.recordEvent("medium", "worker_guard.registry_disarm_failed",
					"could not disarm removed worker uid "+strconv.FormatUint(uint64(uid), 10)+": "+err.Error())
			}
		}
	}
	e.stopSource()
	e.startSource(ctx, next, settings)
	e.mu.Lock()
	e.sourceRegistryKey = workerguard.RegistryFingerprint(next)
	e.mu.Unlock()
	e.recordEvent("info", "worker_guard.registry_resynced",
		"worker guard registry changed; crash source restarted ("+strconv.Itoa(len(removedComms))+" comm(s), "+strconv.Itoa(len(removedUIDs))+" uid(s) disarmed)")
}

// liveSourceState resolves the effective source state and whether a live source
// actually runs. `ebpf` is only returned when the eBPF source is attached; the
// status API therefore cannot claim `active` on top of maps without a
// tracepoint.
func (e *WorkerGuardEngine) liveSourceState() (mode, reason string, active bool) {
	if e == nil {
		return workerGuardSourceNone, "worker guard engine is unavailable", false
	}
	e.mu.Lock()
	mode, reason, source := e.sourceMode, e.sourceReason, e.source
	e.mu.Unlock()
	if source != nil {
		if liveMode, liveReason := source.Status(); liveMode != "" {
			mode = liveMode
			reason = liveReason
		}
	}
	active = mode == workerguard.SourceEBPF || mode == workerguard.SourceNetlink
	return mode, reason, active
}
