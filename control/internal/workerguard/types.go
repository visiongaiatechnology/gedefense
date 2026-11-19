// Package workerguard is Module B of GeDefense 6.1.0: web-worker crash
// correlation and the strict-cgroup classification the Titan exec gate consumes.
//
// The package is split so the decision logic is pure and testable: the crash
// correlation window, the fatal-signal filter and the control-unit denylist live
// here, while the kernel sources (proc connector netlink, /proc discovery) live
// in build-tagged files.
package workerguard

import (
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Signal names for the fatal signals the sensor reports.
const (
	SignalABRT = 6
	SignalBUS  = 7
	SignalFPE  = 8
	SignalILL  = 4
	SignalSEGV = 11
)

// MaxCommBytes is the kernel's TASK_COMM_LEN-1 usable length.
const MaxCommBytes = 15

// builtinControlUnits is the compiled-in denylist. The operator's exclude_units
// setting extends it; it can never shorten it, because a strict Titan scope that
// includes systemd or an nginx master process is how an operator locks himself
// out of the machine.
var builtinControlUnits = []string{
	"systemd", "init", "kthreadd", "master", "control",
	"nginx: master", "php-fpm: master", "apache2: master",
}

// Registry is the administrable worker identity set.
type Registry struct {
	Comms        []string
	UIDs         []uint32
	ExcludeUnits []string
}

// RegistryFingerprint returns a stable, order-insensitive fingerprint of the
// administrable comm/uid set. The engine compares fingerprints on every
// reconcile tick: a change while a crash source is running means the kernel
// registry is stale and the source has to be resynchronized.
func RegistryFingerprint(registry Registry) string {
	comms := make([]string, 0, len(registry.Comms))
	seenComms := make(map[string]struct{}, len(registry.Comms))
	for _, comm := range registry.Comms {
		comm = strings.TrimSpace(comm)
		if comm == "" {
			continue
		}
		if _, dup := seenComms[comm]; dup {
			continue
		}
		seenComms[comm] = struct{}{}
		comms = append(comms, comm)
	}
	sort.Strings(comms)
	uids := make([]uint32, 0, len(registry.UIDs))
	seenUIDs := make(map[uint32]struct{}, len(registry.UIDs))
	for _, uid := range registry.UIDs {
		if _, dup := seenUIDs[uid]; dup {
			continue
		}
		seenUIDs[uid] = struct{}{}
		uids = append(uids, uid)
	}
	sort.Slice(uids, func(left, right int) bool { return uids[left] < uids[right] })
	var builder strings.Builder
	builder.WriteString("comms=")
	for _, comm := range comms {
		builder.WriteString(comm)
		builder.WriteByte(',')
	}
	builder.WriteString(";uids=")
	for _, uid := range uids {
		builder.WriteString(strconv.FormatUint(uint64(uid), 10))
		builder.WriteByte(',')
	}
	return builder.String()
}

// RemovedComms returns the comm values that were armed before but are absent
// from the new registry. The eBPF write path only adds entries, so the engine
// deletes these explicitly before restarting the source; otherwise a removed
// comm would stay armed in the kernel map.
func RemovedComms(previous, next Registry) []string {
	present := make(map[string]struct{}, len(next.Comms))
	for _, comm := range next.Comms {
		present[comm] = struct{}{}
	}
	removed := make([]string, 0, len(previous.Comms))
	seen := make(map[string]struct{}, len(previous.Comms))
	for _, comm := range previous.Comms {
		if _, still := present[comm]; still {
			continue
		}
		if _, dup := seen[comm]; dup {
			continue
		}
		seen[comm] = struct{}{}
		removed = append(removed, comm)
	}
	return removed
}

// RemovedUIDs returns the UIDs that were armed before but are absent from the
// new registry (same rationale as RemovedComms).
func RemovedUIDs(previous, next Registry) []uint32 {
	present := make(map[uint32]struct{}, len(next.UIDs))
	for _, uid := range next.UIDs {
		present[uid] = struct{}{}
	}
	removed := make([]uint32, 0, len(previous.UIDs))
	seen := make(map[uint32]struct{}, len(previous.UIDs))
	for _, uid := range previous.UIDs {
		if _, still := present[uid]; still {
			continue
		}
		if _, dup := seen[uid]; dup {
			continue
		}
		seen[uid] = struct{}{}
		removed = append(removed, uid)
	}
	return removed
}

// NormalizeComm trims a comm name to the kernel's 15-byte limit and rejects the
// values the kernel could never report.
func NormalizeComm(comm string) (string, error) {
	comm = strings.TrimSpace(comm)
	if comm == "" {
		return "", errors.New("comm must not be empty")
	}
	if strings.ContainsRune(comm, 0) {
		return "", errors.New("comm must not contain NUL")
	}
	if len(comm) > MaxCommBytes {
		comm = comm[:MaxCommBytes]
	}
	return comm, nil
}

// SignalName maps a fatal signal number to its operator-facing name.
func SignalName(signal int) string {
	switch signal {
	case SignalSEGV:
		return "SIGSEGV"
	case SignalBUS:
		return "SIGBUS"
	case SignalILL:
		return "SIGILL"
	case SignalABRT:
		return "SIGABRT"
	case SignalFPE:
		return "SIGFPE"
	case 9:
		return "SIGKILL"
	case 15:
		return "SIGTERM"
	default:
		return "SIG" + strconv.Itoa(signal)
	}
}

// IsFatalSignal reports whether a signal is a crash the guard treats as worker
// corruption. SIGTERM and SIGKILL are panel/reload shutdowns, never crashes.
func IsFatalSignal(signal int) bool {
	switch signal {
	case SignalSEGV, SignalBUS, SignalILL, SignalABRT, SignalFPE:
		return true
	}
	return false
}

// WaitStatusSignal extracts a terminating signal from a wait(2)-style status.
// A clean exit (status 0..127 without the signal flag) returns ok=false.
func WaitStatusSignal(exitCode int) (int, bool) {
	if exitCode <= 0 || exitCode > 255 {
		return 0, false
	}
	signal := exitCode & 0x7f
	if signal == 0 {
		return 0, false
	}
	return signal, true
}

// IsControlUnit reports whether a comm names a master/control unit. The operator
// exclude list is checked together with the compiled-in denylist; matching is
// substring-based because the kernel truncates comm to 15 bytes.
func IsControlUnit(comm string, exclude []string) bool {
	_, matched := MatchControlUnit(comm, exclude)
	return matched
}

// MatchControlUnit returns the denylist token that makes comm a control unit, so
// the caller can explain an exclusion instead of silently dropping a process.
func MatchControlUnit(comm string, exclude []string) (string, bool) {
	lower := strings.ToLower(strings.TrimSpace(comm))
	for _, unit := range builtinControlUnits {
		if strings.Contains(lower, unit) {
			return unit, true
		}
	}
	for _, unit := range exclude {
		unit = strings.ToLower(strings.TrimSpace(unit))
		if unit == "" {
			continue
		}
		if strings.Contains(lower, unit) {
			return unit, true
		}
	}
	return "", false
}

// IsTrackedComm reports whether a comm is registered. A registered comm is
// matched as an exact prefix so "php-fpm" also covers "php-fpm: pool www".
func IsTrackedComm(comm string, registry Registry) bool {
	lower := strings.ToLower(strings.TrimSpace(comm))
	if lower == "" {
		return false
	}
	for _, candidate := range registry.Comms {
		candidate = strings.ToLower(strings.TrimSpace(candidate))
		if candidate == "" {
			continue
		}
		if lower == candidate || strings.HasPrefix(lower, candidate+":") || strings.HasPrefix(lower, candidate+" ") {
			return true
		}
	}
	return false
}

// IsTrackedUID reports whether a UID is registered. An empty UID list means the
// comm registry alone decides; a non-empty list is a mandatory additional filter.
func IsTrackedUID(uid uint32, registry Registry) bool {
	if len(registry.UIDs) == 0 {
		return true
	}
	for _, candidate := range registry.UIDs {
		if candidate == uid {
			return true
		}
	}
	return false
}

// Worker is one classified live process.
type Worker struct {
	PID        int    `json:"pid"`
	Comm       string `json:"comm"`
	UID        uint32 `json:"uid"`
	CgroupID   uint64 `json:"cgroup_id"`
	Strict     bool   `json:"strict"`
	CgroupPath string `json:"-"`
}

// SkippedCgroup explains why a cgroup was kept out of the strict Titan scope.
// A systemd-managed service shares one cgroup between the master and its
// workers, so excluding the master process alone would still put the master
// under a strict exec/mmap scope. The whole cgroup is therefore excluded and the
// operator gets the concrete reason.
type SkippedCgroup struct {
	CgroupID   uint64 `json:"cgroup_id"`
	CgroupPath string `json:"cgroup_path"`
	Comm       string `json:"comm"`
	Reason     string `json:"reason"`
}

// ScanResult is the outcome of one bounded /proc classification walk.
type ScanResult struct {
	Workers []Worker        `json:"workers"`
	Skipped []SkippedCgroup `json:"skipped_cgroups"`
	Reason  string          `json:"reason"`
}

// ClassifyWorker decides whether a live process belongs in the strict Titan
// scope. It is deliberately conservative: a process enters the strict scope only
// when it is a registered, tracked worker and is not a control unit.
func ClassifyWorker(pid int, comm string, uid uint32, cgroupPath string, cgroupID uint64, registry Registry, strict bool) (Worker, bool) {
	if pid <= 0 {
		return Worker{}, false
	}
	name, err := NormalizeComm(comm)
	if err != nil {
		return Worker{}, false
	}
	if !IsTrackedComm(name, registry) || !IsTrackedUID(uid, registry) {
		return Worker{}, false
	}
	if IsControlUnit(name, registry.ExcludeUnits) {
		return Worker{}, false
	}
	return Worker{PID: pid, Comm: name, UID: uid, CgroupID: cgroupID, CgroupPath: cgroupPath, Strict: strict && cgroupID != 0}, true
}

// ParseCgroupPath extracts the cgroup v2 path from /proc/<pid>/cgroup content.
// The unified hierarchy is the only one the guard classifies (cgroup v1 has no
// single cgroup id and is reported as unsupported instead of guessed at).
func ParseCgroupPath(content string) (string, error) {
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, ":", 3)
		if len(parts) != 3 {
			continue
		}
		if parts[0] != "0" || parts[1] != "" {
			continue
		}
		path := strings.TrimSpace(parts[2])
		if !strings.HasPrefix(path, "/") {
			return "", fmt.Errorf("cgroup path %q is not absolute", path)
		}
		return path, nil
	}
	return "", errors.New("no cgroup v2 entry found")
}

// Storm is one correlated crash-storm incident.
type Storm struct {
	ID            string    `json:"id"`
	Comm          string    `json:"comm"`
	UID           uint32    `json:"uid"`
	Crashes       int       `json:"crashes"`
	WindowSeconds int       `json:"window_seconds"`
	FirstAt       time.Time `json:"first_at"`
	LastAt        time.Time `json:"last_at"`
	Severity      string    `json:"severity"`
	Peers         []string  `json:"peers"`
}

// Counters are the bounded Module B counters.
type Counters struct {
	Events     uint64 `json:"events"`
	Storms     uint64 `json:"storms"`
	DeniedExec uint64 `json:"denied_exec"`
	DeniedMmap uint64 `json:"denied_mmap"`
}

// CrashEvent is the shared shape both crash sources deliver.
type CrashEvent struct {
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

// Source names for the status payload.
const (
	SourceEBPF    = "ebpf"
	SourceNetlink = "netlink"
	SourceNone    = "none"
)
