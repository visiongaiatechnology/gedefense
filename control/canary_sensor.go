// STATUS: DIAMANT VGT SUPREME
package main

// Deception canary sensor.
//
// The privileged Rust core deploys decoy files inside its canary root and owns
// the fanotify instance that observes them. This sensor is the unprivileged
// half of that pipeline: it polls the core, rebuilds the accessor identity from
// the kernel-authenticated PID, feeds the result into the deception engine and
// therefore produces the incident + response without any manual API call.
//
// Every byte crossing the IPC is bounded and validated in coreipc.go; this file
// adds the lifecycle (start/stop), de-duplication and the deployment hook that
// the deception engine uses instead of writing files itself.

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	// canaryRootPath is the shipped core canary root
	// (`packaging/tmpfiles/vgt-gedefense.conf`, 0750 root:gedefense). It is the
	// same default the core uses when no `--canary-root` is passed; changing one
	// side without the other fails the deployment visibly instead of silently.
	canaryRootPath = "/var/lib/vgt/gedefense/canaries"

	canaryPollInterval     = 250 * time.Millisecond
	canaryStatusInterval   = 10 * time.Second
	canaryDedupeWindow     = 30 * time.Second
	canaryDedupeLimit      = 4096
	canaryErrorLogInterval = 60 * time.Second
	canaryProcessTextLimit = 64
	canaryStatLimit        = 4096
)

var (
	// ErrCanaryOutsideRoot is returned by the privileged transport when a canary
	// definition points outside the one directory the core may write. ApplyPolicy
	// treats this as a migration problem: the definition is skipped, logged and
	// reported through the evidence ledger instead of blocking service start.
	ErrCanaryOutsideRoot = errors.New("canary path is outside the privileged canary root")
	// ErrCanaryCoreUnavailable means the privileged broker cannot be reached.
	ErrCanaryCoreUnavailable = errors.New("canary privileged transport is unavailable")
)

// CanaryAccessEvent is one validated kernel-observed decoy access.
type CanaryAccessEvent struct {
	PID  int
	UID  uint32
	Path string
	Type string
	Exec bool
}

// CanaryEventBatch is one bounded poll result from the privileged core.
type CanaryEventBatch struct {
	Dropped uint64
	Events  []CanaryAccessEvent
}

// CanaryBrokerStatus is the bounded sensor health published by the core.
type CanaryBrokerStatus struct {
	Roots        int
	Registered   int
	Queued       int
	Dropped      uint64
	MarkFailures uint64
	Watcher      string
}

// CanaryEventSource is the subset of the core client the sensor needs. It is an
// interface so tests can drive the sensor with a fake kernel event source.
type CanaryEventSource interface {
	CanaryEvents() (CanaryEventBatch, error)
	CanaryStatus() (CanaryBrokerStatus, error)
}

// CanarySensor turns kernel canary events into deception incidents.
type CanarySensor struct {
	source    CanaryEventSource
	deception *DeceptionEngine
	state     *State
	now       func() time.Time

	mu         sync.Mutex
	seen       map[string]time.Time
	lastError  map[string]time.Time
	lastStatus time.Time
}

// NewCanarySensor builds the sensor. A nil source or deception engine yields a
// sensor whose Start is a no-op, so callers do not need their own guards.
func NewCanarySensor(source CanaryEventSource, deception *DeceptionEngine, state *State) *CanarySensor {
	return &CanarySensor{
		source:    source,
		deception: deception,
		state:     state,
		now:       time.Now,
		seen:      make(map[string]time.Time),
		lastError: make(map[string]time.Time),
	}
}

// Start runs the poll loop until ctx is cancelled.
func (s *CanarySensor) Start(ctx context.Context) {
	if s == nil || s.source == nil || s.deception == nil {
		return
	}
	go s.run(ctx)
}

func (s *CanarySensor) run(ctx context.Context) {
	ticker := time.NewTicker(canaryPollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.poll(ctx)
		}
	}
}

// poll drains one bounded event batch and refreshes sensor status on its own
// slower cadence. It is intentionally single-flight: a slow deception handler
// delays the next poll instead of piling up goroutines.
func (s *CanarySensor) poll(ctx context.Context) {
	batch, err := s.source.CanaryEvents()
	if err != nil {
		s.noteError("events", err)
		return
	}
	if batch.Dropped > 0 {
		s.noteError("event-drop", fmt.Errorf("core dropped %d canary event(s)", batch.Dropped))
	}
	for _, event := range batch.Events {
		s.dispatch(ctx, event)
	}
	if s.now().Sub(s.lastStatus) >= canaryStatusInterval {
		s.refreshStatus()
	}
}

func (s *CanarySensor) dispatch(ctx context.Context, event CanaryAccessEvent) {
	if event.PID <= 0 || event.Path == "" {
		return
	}
	key := fmt.Sprintf("%s|%d|%d|%t", event.Path, event.PID, event.UID, event.Exec)
	if s.duplicate(key) {
		return
	}
	access := DeceptionAccessEvent{
		CanaryPath:         event.Path,
		AccessorPID:        event.PID,
		AccessorStartTicks: readProcessStartTicks(event.PID),
		AccessorUID:        event.UID,
		AccessorComm:       readProcessComm(event.PID),
		Timestamp:          s.now().UTC(),
	}
	incident, _, err := s.deception.HandleCanaryAccess(ctx, access)
	if err != nil {
		// A definition removed between the kernel event and this handler is a
		// convergence race, not a sensor fault.
		var validation *DeceptionValidationException
		if errors.As(err, &validation) {
			return
		}
		s.noteError("handle", err)
		return
	}
	if incident == nil || s.state == nil {
		return
	}
	s.state.AddEvent(Event{
		Time:     incident.Time,
		Severity: strings.ToLower(incident.Severity),
		Kind:     "deception.canary_triggered",
		Source:   "deception-sensor",
		Message:  incident.Summary,
		Target:   event.Path,
	})
}

// duplicate suppresses the burst a single open() can produce (fanotify can
// report open and exec for the same file, and a shell may open a decoy twice).
func (s *CanarySensor) duplicate(key string) bool {
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	if at, seen := s.seen[key]; seen && now.Sub(at) < canaryDedupeWindow {
		return true
	}
	if len(s.seen) >= canaryDedupeLimit {
		for existing, at := range s.seen {
			if now.Sub(at) >= canaryDedupeWindow {
				delete(s.seen, existing)
			}
		}
	}
	s.seen[key] = now
	return false
}

// refreshStatus publishes a visible degradation when the privileged fanotify
// watcher is not armed or every decoy vanished from the registry. Silence would
// otherwise look identical to "no attacker touched the decoys".
func (s *CanarySensor) refreshStatus() {
	status, err := s.source.CanaryStatus()
	if err != nil {
		s.noteError("status", err)
		return
	}
	s.mu.Lock()
	s.lastStatus = s.now()
	s.mu.Unlock()
	if status.Watcher != "active" {
		s.noteError("watcher", fmt.Errorf(
			"canary fanotify watcher is %s (roots=%d registered=%d queued=%d mark_failures=%d)",
			status.Watcher, status.Roots, status.Registered, status.Queued, status.MarkFailures,
		))
	}
	if status.Registered == 0 {
		s.noteError("registration", errors.New("privileged broker reports no registered canary"))
	}
}

func (s *CanarySensor) noteError(kind string, err error) {
	if err == nil {
		return
	}
	now := s.now()
	s.mu.Lock()
	last, known := s.lastError[kind]
	if known && now.Sub(last) < canaryErrorLogInterval {
		s.mu.Unlock()
		return
	}
	s.lastError[kind] = now
	s.mu.Unlock()
	log.Printf("[VGT-DECEPTION] canary sensor %s error: %v", kind, err)
	if s.state != nil {
		s.state.AddEvent(Event{
			Severity: "warning",
			Kind:     "deception.sensor_error",
			Source:   "deception-sensor",
			Message:  fmt.Sprintf("Canary sensor %s: %v", kind, err),
		})
	}
}

// readProcessComm reads the bounded, kernel-provided comm of the accessor. The
// PID itself comes from fanotify; only the display label is read here.
func readProcessComm(pid int) string {
	if pid <= 0 {
		return "unknown"
	}
	file, err := os.Open("/proc/" + strconv.Itoa(pid) + "/comm")
	if err != nil {
		return "unknown"
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, canaryProcessTextLimit+1))
	if err != nil || len(data) == 0 || len(data) > canaryProcessTextLimit {
		return "unknown"
	}
	text := strings.TrimSpace(string(data))
	if text == "" {
		return "unknown"
	}
	for _, character := range text {
		if character < 0x20 || character == 0x7f {
			return "unknown"
		}
	}
	return text
}

// readProcessStartTicks reads field 22 of /proc/<pid>/stat so the response
// engine can address the process by (PID, start time) and cannot hit a recycled
// PID. A read failure yields 0, which the response engine treats as "PID only".
func readProcessStartTicks(pid int) uint64 {
	if pid <= 0 {
		return 0
	}
	file, err := os.Open("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return 0
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, canaryStatLimit+1))
	if err != nil || len(data) == 0 || len(data) > canaryStatLimit {
		return 0
	}
	closeIndex := strings.LastIndexByte(string(data), ')')
	if closeIndex < 0 || closeIndex+2 >= len(data) {
		return 0
	}
	fields := strings.Fields(string(data[closeIndex+2:]))
	if len(fields) <= 19 {
		return 0
	}
	ticks, parseErr := strconv.ParseUint(fields[19], 10, 64)
	if parseErr != nil {
		return 0
	}
	return ticks
}

// ------------------------------------------------------------------ transport

// coreCanaryDeployer is the production CanaryDeployer: it hands the bounded
// decoy to the privileged core and lets the core pick the fd-relative write.
type coreCanaryDeployer struct {
	core *CoreClient
}

func (d coreCanaryDeployer) DeployCanary(
	path string,
	canaryType CanaryType,
	ownerUID uint32,
	mode uint32,
	content []byte,
) error {
	_ = ownerUID // the privileged broker always creates the decoy as root
	clean := filepath.Clean(path)
	if !pathUnderCanaryRoot(clean) {
		return fmt.Errorf("%w: %s", ErrCanaryOutsideRoot, clean)
	}
	if d.core == nil {
		return ErrCanaryCoreUnavailable
	}
	if err := d.core.CanaryDeploy(clean, string(canaryType), mode, content); err != nil {
		return fmt.Errorf("canary deploy %s: %w", clean, err)
	}
	return nil
}

// coreCanaryRemover removes one decoy through the privileged core.
type coreCanaryRemover struct {
	core *CoreClient
}

func (r coreCanaryRemover) RemoveCanary(path string) error {
	clean := filepath.Clean(path)
	if !pathUnderCanaryRoot(clean) {
		return fmt.Errorf("%w: %s", ErrCanaryOutsideRoot, clean)
	}
	if r.core == nil {
		return ErrCanaryCoreUnavailable
	}
	if err := r.core.CanaryRemove(clean); err != nil {
		return fmt.Errorf("canary remove %s: %w", clean, err)
	}
	return nil
}

func pathUnderCanaryRoot(path string) bool {
	if !validCanaryTargetPath(path) {
		return false
	}
	return strings.HasPrefix(path, canaryRootPath+"/")
}

// AttachCanaryBroker wires the privileged deploy/remove transport into the
// deception engine. It must run before the first ApplyPolicy projection so the
// engine never falls back to writing decoy files with the unprivileged identity.
func AttachCanaryBroker(deception *DeceptionEngine, core *CoreClient) {
	if deception == nil || core == nil {
		return
	}
	deception.SetCanaryDeployer(coreCanaryDeployer{core: core})
	deception.SetCanaryRemover(coreCanaryRemover{core: core})
}

// StartCanarySensor wires the transport and starts the event poll loop. This is
// the single call the XDR engine needs in its Run loop.
func StartCanarySensor(ctx context.Context, core *CoreClient, deception *DeceptionEngine, state *State) {
	if core == nil || deception == nil {
		return
	}
	AttachCanaryBroker(deception, core)
	NewCanarySensor(core, deception, state).Start(ctx)
}
