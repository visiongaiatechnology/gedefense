package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	// bpfGuardStatusInterval is the status cadence (capability + arm + counters).
	bpfGuardStatusInterval = 5 * time.Second
	// bpfGuardDrainInterval is the ring drain cadence.
	bpfGuardDrainInterval = time.Second
	// bpfGuardDedupeTTL bounds the record dedupe window.
	bpfGuardDedupeTTL = 5 * time.Minute
	// bpfGuardRiskWindow is the ">= 2 high-risk helpers" aggregation window.
	bpfGuardRiskWindow = time.Hour
	// bpfGuardSeenLimit bounds the dedupe/risk bookkeeping map.
	bpfGuardSeenLimit = 4096
	// bpfGuardOverflowMinGap rate-limits ring-drop telemetry.
	bpfGuardOverflowMinGap = 5 * time.Minute
	// bpfGuardProcReadBytes bounds every /proc helper read.
	bpfGuardProcReadBytes = 8192
	// bpfGuardReportReasonBytes bounds operator-facing reason text.
	bpfGuardReportReasonBytes = 240
)

// bpfGuardToleratedComms is the TOLERATED loader context list. These are
// legitimate eBPF consumers (tooling, container runtimes, our own daemons); an
// event from one of them is recorded as information and never becomes an XDR
// incident. The list is enforced in bpfGuardEventTolerated below.
var bpfGuardToleratedComms = map[string]struct{}{
	"bpftrace": {}, "perf": {}, "cilium-agent": {}, "cilium": {}, "falco": {},
	"tetragon": {}, "docker": {}, "containerd": {}, "runc": {}, "cargo": {},
	"go": {}, "gcc": {}, "clang": {}, "node": {}, "npm": {}, "systemd": {},
	"gedefense-core": {}, "gedefense-control": {}, "bpftool": {},
}

// bpfGuardTrustedParentComms is the PermitV1-style trusted-parent context: a
// loader spawned by one of these parents is tolerated. (The full PermitV1 broker
// lands in AP-7; this is the local, documented subset.)
var bpfGuardTrustedParentComms = map[string]struct{}{
	"systemd": {}, "sshd": {}, "cron": {}, "containerd": {}, "containerd-shim": {},
	"dockerd": {}, "docker": {}, "runc": {}, "podman": {}, "gedefense-core": {},
	"gedefense-control": {},
}

// bpfGuardShellComms is the shell-lineage set used by the rootkit rule.
var bpfGuardShellComms = map[string]struct{}{
	"bash": {}, "sh": {}, "dash": {}, "zsh": {}, "ksh": {}, "fish": {}, "busybox": {},
}

// bpfGuardToleratedPathPrefixes are installation-managed executable roots.
var bpfGuardToleratedPathPrefixes = []string{
	"/usr/bin/", "/usr/sbin/", "/usr/local/bin/", "/opt/", "/usr/lib/systemd/", "/usr/libexec/",
}

// bpfGuardTempPathPrefixes are the writable drop roots that make a BPF loader
// rootkit-suspicious regardless of its helper set.
var bpfGuardTempPathPrefixes = []string{"/tmp/", "/var/tmp/", "/dev/shm/"}

// bpfGuardEventListener exposes the TOLERATED context list to tests and future
// PermitV1 wiring without duplicating the policy.
func bpfGuardToleratedLoaderComms() []string {
	out := make([]string, 0, len(bpfGuardToleratedComms))
	for comm := range bpfGuardToleratedComms {
		out = append(out, comm)
	}
	return out
}

func bpfGuardBoundedText(text string, max int) string {
	text = strings.TrimSpace(strings.Join(strings.Fields(text), " "))
	if max > 0 && len(text) > max {
		text = text[:max]
	}
	return text
}

func bpfGuardPathUnderAny(path string, prefixes []string) bool {
	if path == "" || path == "unknown" {
		return false
	}
	for _, prefix := range prefixes {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}
	return false
}

func bpfGuardCommIn(comm string, set map[string]struct{}) bool {
	if comm == "" {
		return false
	}
	_, ok := set[strings.ToLower(strings.TrimSpace(comm))]
	return ok
}

// bpfGuardParentInfo resolves the loader's parent process id and comm through
// bounded /proc reads. Failures return (0, "") — never a guess.
func bpfGuardParentInfo(pid int) (int, string) {
	if pid <= 1 {
		return 0, ""
	}
	status, err := bpfGuardReadBounded(fmt.Sprintf("/proc/%d/status", pid), bpfGuardProcReadBytes)
	if err != nil {
		return 0, ""
	}
	parentPID := 0
	for _, line := range strings.Split(string(status), "\n") {
		if !strings.HasPrefix(line, "PPid:") {
			continue
		}
		value := strings.TrimSpace(strings.TrimPrefix(line, "PPid:"))
		parsed, parseErr := strconv.Atoi(value)
		if parseErr != nil || parsed <= 0 || parsed > 4194304 {
			return 0, ""
		}
		parentPID = parsed
		break
	}
	if parentPID <= 0 {
		return 0, ""
	}
	commBytes, err := bpfGuardReadBounded(fmt.Sprintf("/proc/%d/comm", parentPID), 64)
	if err != nil {
		return parentPID, ""
	}
	return parentPID, strings.TrimSpace(string(commBytes))
}

func bpfGuardReadBounded(path string, limit int64) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	if limit <= 0 {
		return nil, errors.New("bounded read limit must be positive")
	}
	data, err := io.ReadAll(io.LimitReader(file, limit))
	if err != nil {
		return nil, err
	}
	return data, nil
}

func bpfGuardActionName(action uint8) string {
	switch action {
	case BpfGuardActionObserved:
		return "observed"
	case BpfGuardActionHelperRisk:
		return "helper-risk"
	case BpfGuardActionDenied:
		return "denied"
	default:
		return "unknown"
	}
}

func bpfGuardCommandName(command uint8) string {
	switch command {
	case BpfGuardCommandMapCreate:
		return "BPF_MAP_CREATE"
	case BpfGuardCommandProgLoad:
		return "BPF_PROG_LOAD"
	case BpfGuardCommandProgAttach:
		return "BPF_PROG_ATTACH"
	case BpfGuardCommandRawTracepointOpen:
		return "BPF_RAW_TRACEPOINT_OPEN"
	case BpfGuardCommandLinkCreate:
		return "BPF_LINK_CREATE"
	default:
		return fmt.Sprintf("BPF_CMD_%d", command)
	}
}

func bpfGuardProgTypeName(progType uint8) string {
	switch progType {
	case BpfGuardProgTypeUnknown:
		return "unknown"
	case BpfGuardProgTypeKprobe:
		return "kprobe"
	case BpfGuardProgTypeTracepoint:
		return "tracepoint"
	case BpfGuardProgTypeRawTracepoint:
		return "raw_tracepoint"
	case BpfGuardProgTypeTracing:
		return "tracing"
	case BpfGuardProgTypeStructOps:
		return "struct_ops"
	case BpfGuardProgTypeLSM:
		return "lsm"
	case BpfGuardProgTypeSkLookup:
		return "sk_lookup"
	case BpfGuardProgTypeSyscall:
		return "syscall"
	default:
		return fmt.Sprintf("prog_type_%d", progType)
	}
}

func bpfGuardHelperMaskText(mask uint32) string {
	if mask == 0 {
		return "none"
	}
	names := make([]string, 0, 3)
	if mask&BpfGuardHelperBitProbeWriteUser != 0 {
		names = append(names, "bpf_probe_write_user")
	}
	if mask&BpfGuardHelperBitOverrideReturn != 0 {
		names = append(names, "bpf_override_return")
	}
	if mask&BpfGuardHelperBitSendSignal != 0 {
		names = append(names, "bpf_send_signal")
	}
	return fmt.Sprintf("0x%x(%s)", mask, strings.Join(names, "+"))
}

func bpfGuardHelperIDsText(ids [BpfGuardHelperBitsPerEvent]uint32) string {
	parts := make([]string, 0, BpfGuardHelperBitsPerEvent)
	for _, identifier := range ids {
		if identifier == 0 {
			break
		}
		parts = append(parts, strconv.FormatUint(uint64(identifier), 10))
	}
	if len(parts) == 0 {
		return "none"
	}
	return strings.Join(parts, ",")
}
