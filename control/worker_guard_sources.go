// STATUS: DIAMANT VGT SUPREME
package main

// GeDefense 6.1.0 Module B: crash sources for the worker-integrity watch.
//
// Two kernel sources deliver the same WorkerCrashEvent shape:
//
//   - eBPF (rust/gedefense-ebpf/src/worker_guard.rs) through the authenticated
//     core command family in coreipc_worker.go. It is preferred when the core
//     advertises it, because it carries uid/cgroup at the tracepoint.
//   - the kernel proc connector (netlink CN_PROC) through
//     internal/workerguard. It is the portability fallback; a PID is resolved
//     against the bounded /proc worker map because the exit record itself has no
//     comm or uid.
//
// Neither source fabricates enforcement: a missing capability reports
// source "none" with a reason, and the engine never claims a crash it did not
// receive. In particular the eBPF source only reports `ebpf` when the core
// status line says `attached=1`; maps without an attached tracepoint see
// nothing and are reported as inactive (FIND-005).

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/visiongaiatechnology/gedefense/control/internal/workerguard"
)

const (
	workerGuardEBPFPollInterval = time.Second
	workerGuardScannerInterval  = 2 * time.Second
	workerGuardSourceNone       = workerguard.SourceNone
)

// WorkerCrashEvent is the bounded crash record both sources deliver.
type WorkerCrashEvent struct {
	At       time.Time
	PID      int
	Comm     string
	UID      uint32
	GID      uint32
	CgroupID uint64
	Signal   int
	ExitCode int
	Peer     string
	Source   string
}

// CrashSource is the source interface from the blueprint. Start blocks until the
// context is cancelled; an unavailable capability returns an error instead of
// silently doing nothing.
type CrashSource interface {
	Start(ctx context.Context, sink func(WorkerCrashEvent)) error
	Status() (mode, reason string)
}

// ------------------------------------------------------------- eBPF source

// ebpfCrashSource consumes the core's WORKER_GUARD_* family.
type ebpfCrashSource struct {
	core     *CoreClient
	registry workerguard.Registry

	mu       sync.Mutex
	mode     string
	reason   string
	attached bool
}

// NewEBPFCrashSource constructs the preferred kernel source.
func NewEBPFCrashSource(core *CoreClient, registry workerguard.Registry) CrashSource {
	return &ebpfCrashSource{core: core, registry: registry, mode: workerGuardSourceNone}
}

// Start arms the kernel sensor, synchronizes the registry and drains events.
//
// A core that answers `attached=0` has maps but no tracepoint: the sensor would
// observe nothing. It is disarmed again and ErrWorkerGuardInactive is returned
// so the engine falls back to the proc connector instead of reporting a
// capability it does not have (FIND-005).
func (s *ebpfCrashSource) Start(ctx context.Context, sink func(WorkerCrashEvent)) error {
	if s == nil || s.core == nil {
		return errors.New("worker guard: no privileged core client")
	}
	if err := s.syncRegistry(); err != nil {
		return err
	}
	status, err := s.core.WorkerGuardSet(true)
	if err != nil {
		return err
	}
	if !status.Attached {
		_, _ = s.core.WorkerGuardSet(false)
		reason := "cored reported worker guard maps but the tracepoint is not attached (attached=0); eBPF source inactive"
		s.setStatus(workerGuardSourceNone, reason, false)
		return fmt.Errorf("%w: core reports attached=0", ErrWorkerGuardInactive)
	}
	s.setStatus(workerguard.SourceEBPF, "", true)
	ticker := time.NewTicker(workerGuardEBPFPollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			_, _ = s.core.WorkerGuardSet(false)
			return ctx.Err()
		case <-ticker.C:
			samples, drainErr := s.core.WorkerGuardEvents()
			if drainErr != nil {
				if errors.Is(drainErr, ErrWorkerGuardUnavailable) {
					s.setStatus(workerGuardSourceNone, "the privileged core does not implement the worker guard command family", false)
					return drainErr
				}
				s.setStatus(workerguard.SourceEBPF, "worker guard event drain failed: "+drainErr.Error(), false)
				continue
			}
			for _, sample := range samples {
				sink(WorkerCrashEvent{
					At: time.Now().UTC(), PID: int(sample.PID), Comm: strings.TrimRight(sample.Comm, "\x00"),
					UID: sample.UID, GID: sample.GID, CgroupID: sample.CgroupID,
					Signal: int(sample.Signal), ExitCode: int(sample.ExitCode), Source: workerguard.SourceEBPF,
				})
			}
			fresh, statusErr := s.core.WorkerGuardStatus()
			if statusErr == nil && !fresh.Attached {
				// The tracepoint went away while the source was running: stop
				// claiming the kernel sensor and let the engine fall back.
				_, _ = s.core.WorkerGuardSet(false)
				s.setStatus(workerGuardSourceNone, "worker guard tracepoint detached (attached=0); eBPF source inactive", false)
				return fmt.Errorf("%w: tracepoint detached during run", ErrWorkerGuardInactive)
			}
			if statusErr == nil {
				s.setStatus(workerguard.SourceEBPF, "", true)
			}
		}
	}
}

// syncRegistry mirrors the administrable comm/uid set into the kernel maps.
func (s *ebpfCrashSource) syncRegistry() error {
	for _, comm := range s.registry.Comms {
		if err := s.core.WorkerGuardCommAdd(comm); err != nil {
			return err
		}
	}
	for _, uid := range s.registry.UIDs {
		if err := s.core.WorkerGuardUIDAdd(uid); err != nil {
			return err
		}
	}
	return nil
}

func (s *ebpfCrashSource) setStatus(mode, reason string, attached bool) {
	s.mu.Lock()
	s.mode, s.reason, s.attached = mode, reason, attached
	s.mu.Unlock()
}

// Status reports the live source state. The mode is `ebpf` only while the
// tracepoint is attached; an arming failure reports `none` with the reason.
func (s *ebpfCrashSource) Status() (string, string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.mode, s.reason
}

// ---------------------------------------------------------- netlink source

// netlinkCrashSource is the proc-connector fallback.
type netlinkCrashSource struct {
	scanner *workerguard.CgroupScanner

	mu     sync.Mutex
	mode   string
	reason string
}

// NewNetlinkCrashSource constructs the netlink fallback source.
func NewNetlinkCrashSource(registry workerguard.Registry, strict bool) CrashSource {
	return &netlinkCrashSource{scanner: workerguard.NewCgroupScanner(registry, strict), mode: workerGuardSourceNone}
}

// Start subscribes to PROC_EVENT_EXIT and refreshes the PID map on its own tick.
// The source reports `netlink` only once the kernel accepted the subscription.
func (s *netlinkCrashSource) Start(ctx context.Context, sink func(WorkerCrashEvent)) error {
	if s == nil || s.scanner == nil {
		return errors.New("worker guard: netlink source is not constructed")
	}
	s.scanner.Refresh()
	err := runProcExitSource(ctx, func() {
		// The kernel accepted the subscription: only now may the source claim
		// `netlink` to the status API.
		s.setStatus(workerguard.SourceNetlink, "")
		go s.refreshLoop(ctx)
	}, func(record workerguard.ExitRecord) {
		if !workerguard.IsFatalSignal(record.Signal) {
			return
		}
		worker, known := s.scanner.Lookup(record.PID)
		if !known {
			// The process exited before the bounded PID map observed it. The
			// sensor says so by dropping the record instead of inventing a worker.
			return
		}
		sink(WorkerCrashEvent{
			At: record.At, PID: record.PID, Comm: worker.Comm, UID: worker.UID,
			CgroupID: worker.CgroupID, Signal: record.Signal, ExitCode: record.ExitCode,
			Source: workerguard.SourceNetlink,
		})
	})
	if err != nil && ctx.Err() == nil {
		s.setStatus(workerGuardSourceNone, err.Error())
	}
	return err
}

func (s *netlinkCrashSource) refreshLoop(ctx context.Context) {
	ticker := time.NewTicker(workerGuardScannerInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.scanner.Refresh()
		}
	}
}

func (s *netlinkCrashSource) setStatus(mode, reason string) {
	s.mu.Lock()
	s.mode, s.reason = mode, reason
	s.mu.Unlock()
}

// Status reports the live source state.
func (s *netlinkCrashSource) Status() (string, string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.mode, s.reason
}

// ScanWorkers classifies the live workers from /proc for the status payload and
// the strict Titan scope plan, including the cgroups that were skipped because
// they host an excluded master/control process.
func ScanWorkers(registry workerguard.Registry, strict bool, max int) workerguard.ScanResult {
	result, reason := workerguard.ScanProcesses(registry, strict, max)
	if result.Reason == "" {
		result.Reason = reason
	}
	return result
}

// ToWorkerguardRegistry converts the settings namespace into the pure package
// registry type.
func ToWorkerguardRegistry(settings WorkerGuardFabricSettings) workerguard.Registry {
	return workerguard.Registry{
		Comms:        append([]string(nil), settings.Comms...),
		UIDs:         append([]uint32(nil), settings.UIDs...),
		ExcludeUnits: append([]string(nil), settings.ExcludeUnits...),
	}
}
