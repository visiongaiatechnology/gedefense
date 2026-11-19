package main

import (
	"context"
	"testing"

	"github.com/visiongaiatechnology/gedefense/control/internal/workerguard"
)

// stubCrashSource is a CrashSource with an administrable Status, used to lock
// the capability derivation without a privileged core.
type stubCrashSource struct {
	mode   string
	reason string
}

func (s stubCrashSource) Start(context.Context, func(WorkerCrashEvent)) error { return nil }
func (s stubCrashSource) Status() (string, string)                            { return s.mode, s.reason }

// TestWorkerGuardCapabilityRequiresLiveSource locks FIND-005: the status engine
// may only call a source active when it really runs. A source that reports
// `none` (maps present but tracepoint not attached) is inactive with the
// concrete reason.
func TestWorkerGuardCapabilityRequiresLiveSource(t *testing.T) {
	t.Parallel()
	engine := &WorkerGuardEngine{
		sourceMode:   workerGuardSourceNone,
		sourceReason: "worker guard module is disabled; no crash source is subscribed",
	}
	mode, reason, active := engine.liveSourceState()
	if mode != workerguard.SourceNone || active || reason == "" {
		t.Fatalf("disabled engine state = %q/%q active=%t", mode, reason, active)
	}
	engine.sourceMode = workerguard.SourceEBPF
	engine.sourceReason = ""
	engine.source = stubCrashSource{mode: workerGuardSourceNone, reason: "core reports attached=0; eBPF source inactive"}
	mode, reason, active = engine.liveSourceState()
	if mode != workerguard.SourceNone || active {
		t.Fatalf("attached=0 source was reported as %q active=%t", mode, active)
	}
	if reason == "" {
		t.Fatal("inactive source lost its concrete reason")
	}
	engine.source = stubCrashSource{mode: workerguard.SourceNetlink}
	mode, _, active = engine.liveSourceState()
	if mode != workerguard.SourceNetlink || !active {
		t.Fatalf("live netlink source state = %q active=%t", mode, active)
	}
}

// TestWorkerGuardApplyStateIsHonest proves the settings apply state does not
// claim `applied` without a live source.
func TestWorkerGuardApplyStateIsHonest(t *testing.T) {
	t.Parallel()
	engine := &WorkerGuardEngine{
		sourceMode:   workerGuardSourceNone,
		sourceReason: "core reports attached=0",
	}
	settings := RuntimeSettings{WorkerGuard: &WorkerGuardFabricSettings{Enabled: true}}
	if state := engine.ApplyState(settings); state != "engine_unavailable" {
		t.Fatalf("inactive engine apply state = %q", state)
	}
	engine.source = stubCrashSource{mode: workerguard.SourceEBPF}
	if state := engine.ApplyState(settings); state != "applied" {
		t.Fatalf("live engine apply state = %q", state)
	}
}
