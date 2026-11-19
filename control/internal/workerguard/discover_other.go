//go:build !linux

package workerguard

import (
	"context"
	"errors"
	"sync"
	"time"
)

// ErrProcConnectorUnsupported reports that the proc connector netlink source is
// a Linux kernel facility and is therefore unavailable on this platform.
var ErrProcConnectorUnsupported = errors.New("proc connector netlink source is unavailable on this platform")

// ExitRecord is one kernel-reported process exit from the proc connector.
type ExitRecord struct {
	PID      int
	Signal   int
	ExitCode int
	At       time.Time
}

// ScanProcesses reports the platform limitation instead of inventing workers.
func ScanProcesses(_ Registry, _ bool, _ int) (ScanResult, string) {
	return ScanResult{Workers: []Worker{}, Skipped: []SkippedCgroup{}}, "worker process discovery is only available on Linux"
}

// RunProcConnector returns ErrProcConnectorUnsupported on non-Linux hosts.
func RunProcConnector(_ context.Context, _ func(), _ func(ExitRecord)) error {
	return ErrProcConnectorUnsupported
}

// CgroupScanner is the process-classification state; on non-Linux it stays empty.
type CgroupScanner struct {
	mu      sync.Mutex
	workers map[int]Worker
}

// NewCgroupScanner constructs the process classifier state.
func NewCgroupScanner(_ Registry, _ bool) *CgroupScanner {
	return &CgroupScanner{workers: make(map[int]Worker)}
}

// Refresh reports no workers on this platform.
func (s *CgroupScanner) Refresh() []Worker { return nil }

// Lookup never resolves a worker on this platform.
func (s *CgroupScanner) Lookup(int) (Worker, bool) { return Worker{}, false }
