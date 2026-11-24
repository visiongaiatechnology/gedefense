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
	// kernelHooksStatusInterval is the status cadence (capability + ladder).
	kernelHooksStatusInterval = 5 * time.Second
	// kernelHooksDrainInterval is the ring drain cadence.
	kernelHooksDrainInterval = time.Second
	// kernelHooksDedupeTTL bounds the record dedupe window.
	kernelHooksDedupeTTL = 5 * time.Minute
	// kernelHooksSeenLimit bounds the dedupe bookkeeping map.
	kernelHooksSeenLimit = 4096
	// kernelHooksOverflowMinGap rate-limits ring-drop telemetry.
	kernelHooksOverflowMinGap = 5 * time.Minute
	// kernelHooksSubmitIncidentGap bounds how often one process can produce a
	// submission-anomaly incident: `io_uring_submit_req` is sampled once per
	// second per TGID in the kernel, so an unusual submitter would otherwise
	// create one incident per second.
	kernelHooksSubmitIncidentGap = time.Minute
	// kernelHooksProcReadBytes bounds every /proc helper read.
	kernelHooksProcReadBytes = 8192
	// kernelHooksReportReasonBytes bounds operator-facing reason text.
	kernelHooksReportReasonBytes = 240
)

// kernelHooksCoreComm names are the cluster's own daemons: their module loads and
// io_uring usage are always TOLERATED. The exact core pid is not transported
// over VGT3 today, so the bounded comm/executable identity is the policy input.
var kernelHooksCoreComms = map[string]struct{}{
	"gedefense-core": {}, "gedefense-control": {},
}

// kernelHooksToleratedModuleParents are the legitimate parents of a module load:
// the boot path, the package path and the kernel's module tooling.
var kernelHooksToleratedModuleParents = map[string]struct{}{
	"systemd": {}, "systemd-udevd": {}, "udevd": {}, "udev-worker": {},
	"modprobe": {}, "kmod": {}, "kmodloader": {}, "depmod": {},
	"dpkg": {}, "apt": {}, "apt-get": {}, "rpm": {}, "dnf": {}, "yum": {},
	"pacman": {}, "dracut": {}, "mkinitcpio": {},
	"gedefense-core": {}, "gedefense-control": {},
}

// kernelHooksToleratedModuleComms are the systemd/package-manager/module-tooling
// processes whose module loads are the boot and package path. They are tolerated
// unless their executable resolves into a writable drop root (a binary merely
// *named* `modprobe` inside /tmp is not modprobe).
var kernelHooksToleratedModuleComms = map[string]struct{}{
	"systemd": {}, "systemd-udevd": {}, "udevd": {}, "udev-worker": {},
	"modprobe": {}, "kmod": {}, "kmodloader": {}, "depmod": {},
	"dpkg": {}, "apt": {}, "apt-get": {}, "rpm": {}, "dnf": {}, "yum": {},
	"pacman": {}, "dracut": {}, "mkinitcpio": {},
	"gedefense-core": {}, "gedefense-control": {},
}

// kernelHooksModuleToolComms are the tools that take an arbitrary module path
// from the command line: tolerated only from an installation-managed path.
var kernelHooksModuleToolComms = map[string]struct{}{
	"insmod": {},
}

// kernelHooksToleratedIoUringComms are known legitimate high-throughput io_uring
// consumers (databases, storage, VM hosts, container runtimes). `io_uring` is a
// performance interface, not a threat by itself; only an unusual lineage or
// executable makes a record evidence.
var kernelHooksToleratedIoUringComms = map[string]struct{}{
	"mariadbd": {}, "mysqld": {}, "postgres": {}, "redis-server": {},
	"fio": {}, "nvme": {}, "ceph-osd": {}, "scylladb": {},
	"qemu-system-x86_64": {}, "qemu-kvm": {}, "kvm": {},
	"runc": {}, "crun": {}, "containerd": {}, "containerd-shim": {},
	"dockerd": {}, "podman": {}, "systemd": {}, "systemd-journald": {},
}

// kernelHooksManagedPathPrefixes are installation-managed executable roots.
var kernelHooksManagedPathPrefixes = []string{
	"/usr/bin/", "/usr/sbin/", "/sbin/", "/bin/", "/lib/modules/", "/usr/lib/modules/",
}

// kernelHooksTempPathPrefixes are the writable drop roots that make an io_uring
// user or a module loader suspicious regardless of anything else.
var kernelHooksTempPathPrefixes = []string{"/tmp/", "/var/tmp/", "/dev/shm/"}

// kernelHooksShellComms is the shell-lineage set.
var kernelHooksShellComms = map[string]struct{}{
	"bash": {}, "sh": {}, "dash": {}, "zsh": {}, "ksh": {}, "fish": {}, "busybox": {},
}

// kernelHooksCore is the subset of the privileged client the AP-4 contract needs.
type kernelHooksCore interface {
	KernelHookSet(enabled bool) error
	KernelHookStatus() (CoreKernelHookStatus, error)
	KernelHookEvents() ([]CoreKernelHookEvent, uint64, error)
	KernelHookEpoch() (string, error)
}

// claimKernelHookRecord dedupes by the mandated (ts, kind, pid) key.
func (e *XDREngine) claimKernelHookRecord(event CoreKernelHookEvent, now time.Time) bool {
	key := fmt.Sprintf("record:%d|%d|%d", event.TsNS, event.Kind, event.PID)
	e.kernelHooksMu.Lock()
	defer e.kernelHooksMu.Unlock()
	if e.kernelHooksSeen == nil {
		e.kernelHooksSeen = make(map[string]time.Time)
	}
	if until, exists := e.kernelHooksSeen[key]; exists && now.Before(until) {
		return false
	}
	e.kernelHooksSeen[key] = now.Add(kernelHooksDedupeTTL)
	if len(e.kernelHooksSeen) > kernelHooksSeenLimit {
		for seenKey, until := range e.kernelHooksSeen {
			if !until.After(now) {
				delete(e.kernelHooksSeen, seenKey)
			}
		}
	}
	return true
}

// claimKernelHookSubmitWindow rate-limits submission-anomaly incidents per
// process. The kernel samples `io_uring_submit_req` once per second per TGID, so
// an unusual submitter is reported once per minute instead of once per second;
// the dedupe contract `(ts, kind, pid)` still applies to every other kind.
func (e *XDREngine) claimKernelHookSubmitWindow(pid int, now time.Time) bool {
	key := fmt.Sprintf("submit-window:%d", pid)
	e.kernelHooksMu.Lock()
	defer e.kernelHooksMu.Unlock()
	if e.kernelHooksSeen == nil {
		e.kernelHooksSeen = make(map[string]time.Time)
	}
	if until, exists := e.kernelHooksSeen[key]; exists && now.Before(until) {
		return false
	}
	e.kernelHooksSeen[key] = now.Add(kernelHooksSubmitIncidentGap)
	return true
}

func (e *XDREngine) addKernelHookToleratedEvent(event CoreKernelHookEvent, now time.Time, reason string) {
	if e.state == nil {
		return
	}
	e.state.AddEvent(Event{Time: now, Severity: "info", Kind: "xdr.kernel_hook_tolerated", Source: "kernel",
		Message: fmt.Sprintf("Tolerated %s hook activity observed: pid=%d tgid=%d uid=%d comm=%s (%s)",
			KernelHookKindName(event.Kind), event.PID, event.TGID, event.UID, event.Comm, reason),
		Target: fmt.Sprintf("pid:%d", event.PID)})
}

// kernelHookIoUringUnusual is the pure incident trigger for one io_uring record:
// a shell lineage, a writable drop path or a deleted executable. An unreachable
// `/proc` entry (process already exited) is NOT suspicious on its own — that
// would turn every short-lived io_uring user into a finding.
func kernelHookIoUringUnusual(comm, path, parentComm string, deleted bool) (bool, string) {
	comm = strings.ToLower(strings.TrimSpace(comm))
	parentComm = strings.ToLower(strings.TrimSpace(parentComm))
	if deleted {
		return true, "executable was deleted from disk"
	}
	if kernelHookPathUnderAny(path, kernelHooksTempPathPrefixes) {
		return true, "executable lives in a temporary writable path"
	}
	if _, shell := kernelHooksShellComms[comm]; shell {
		return true, "io_uring ring operation by a shell"
	}
	if parentComm != "" {
		if _, shell := kernelHooksShellComms[parentComm]; shell {
			return true, "shell lineage"
		}
	}
	return false, ""
}

func kernelHookPathUnderAny(path string, prefixes []string) bool {
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

func kernelHookIsCoreComm(comm string) bool {
	_, ok := kernelHooksCoreComms[strings.ToLower(strings.TrimSpace(comm))]
	return ok
}

// kernelHookProcessEvidence resolves `/proc/<pid>/exe` best-effort. It reports a
// bounded absolute path plus whether the kernel marked the target as
// " (deleted)" (unlinked executable). Every failure is ("", false): never a
// guess. The path is enrichment only, never identity.
func kernelHookProcessEvidence(pid int) (string, bool) {
	if pid <= 0 {
		return "unknown", false
	}
	target, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil {
		return "unknown", false
	}
	deleted := strings.HasSuffix(target, " (deleted)")
	target = strings.TrimSuffix(target, " (deleted)")
	if target == "" || len(target) > 4096 || !strings.HasPrefix(target, "/") ||
		strings.ContainsAny(target, "\x00\r\n\t") {
		return "unknown", deleted
	}
	return target, deleted
}

// kernelHookParentInfo resolves the loader's parent pid and comm through bounded
// /proc reads. Failures return (0, "") — never a guess.
func kernelHookParentInfo(pid int) (int, string) {
	if pid <= 1 {
		return 0, ""
	}
	status, err := kernelHookReadBounded(fmt.Sprintf("/proc/%d/status", pid), kernelHooksProcReadBytes)
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
	commBytes, err := kernelHookReadBounded(fmt.Sprintf("/proc/%d/comm", parentPID), 64)
	if err != nil {
		return parentPID, ""
	}
	return parentPID, strings.TrimSpace(string(commBytes))
}

func kernelHookReadBounded(path string, limit int64) ([]byte, error) {
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

// kernelHookDetailText renders the bounded, kind-specific detail payload. Binary
// payloads (io_uring setup flags / registration counts) are hex; printable module
// names are shown as-is. Never unescaped raw bytes.
func kernelHookDetailText(kind uint8, detail []byte) string {
	if len(detail) == 0 {
		return "none"
	}
	switch kind {
	case KernelHookKindIoUringCreate, KernelHookKindIoUringRegister:
		return fmt.Sprintf("0x%x", detail)
	}
	for _, character := range detail {
		if character < 0x20 || character > 0x7e {
			return fmt.Sprintf("0x%x", detail)
		}
	}
	return string(detail)
}

// kernelHookDetailCodeText names the kind-specific scalar of one record.
func kernelHookDetailCodeText(kind uint8, code uint32) string {
	switch kind {
	case KernelHookKindIoUringCreate:
		return fmt.Sprintf("fd=%d", code)
	case KernelHookKindIoUringRegister, KernelHookKindIoUringSubmit:
		return fmt.Sprintf("opcode=%d", code)
	case KernelHookKindModuleLoad, KernelHookKindLkmTaint:
		return fmt.Sprintf("taints=0x%x", code)
	case KernelHookKindModuleFinit:
		if code != 0 {
			return fmt.Sprintf("fd=%d", code)
		}
		return "none"
	case KernelHookKindModuleDelete:
		if code != 0 {
			return fmt.Sprintf("flags=0x%x", code)
		}
		return "none"
	default:
		return "none"
	}
}

func kernelHookOrNone(value string) string {
	if strings.TrimSpace(value) == "" {
		return "unknown"
	}
	return value
}

func kernelHooksBoundedText(text string, max int) string {
	text = strings.TrimSpace(strings.Join(strings.Fields(text), " "))
	if max > 0 && len(text) > max {
		text = text[:max]
	}
	return text
}
