package main

import (
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// persistencePackageManagerComms is the TOLERATED package-management writer set:
// a package upgrade legitimately rewrites linker/PAM/systemd/udev files.
var persistencePackageManagerComms = map[string]struct{}{
	"dpkg": {}, "apt": {}, "apt-get": {}, "aptitude": {}, "unattended-upgr": {},
	"rpm": {}, "dnf": {}, "yum": {}, "pacman": {}, "pamac": {}, "zypper": {},
}

// persistencePackageManagerPathPrefixes is the executable-path half of the same
// policy (a package manager invoked through a wrapper keeps its real path).
var persistencePackageManagerPathPrefixes = []string{
	"/usr/bin/dpkg", "/usr/lib/dpkg/", "/usr/bin/apt", "/usr/lib/apt/",
	"/usr/bin/rpm", "/usr/bin/dnf", "/usr/bin/yum", "/usr/bin/pacman",
}

// persistenceBootWriterComms is the TOLERATED systemd/udev boot writer set.
var persistenceBootWriterComms = map[string]struct{}{
	"systemd": {}, "systemd-udevd": {}, "udevd": {}, "udevadm": {},
	"systemd-sysctl": {}, "systemd-tmpfiles": {}, "systemd-sysusers": {},
	"systemd-modules-load": {}, "systemd-random-seed": {}, "systemd-binfmt": {},
	"systemd-update-utmp": {}, "systemd-user-sess": {},
}

// persistenceBootWriterPathPrefixes covers boot writers whose task name is not
// the packaged binary name.
var persistenceBootWriterPathPrefixes = []string{
	"/usr/lib/systemd/", "/lib/systemd/", "/usr/bin/udevadm", "/usr/sbin/udevadm",
}

// persistenceOwnComms is the TOLERATED "the core/control itself" context.
var persistenceOwnComms = map[string]struct{}{
	"gedefense-core": {}, "gedefense-control": {}, "gedefense-ebpf": {},
}

// persistenceDesktopMediaComms are the processes allowed to own their session's
// camera/microphone/capture socket while that session is active.
var persistenceDesktopMediaComms = map[string]struct{}{
	"pipewire": {}, "pipewire-pulse": {}, "wireplumber": {}, "pulseaudio": {},
	"gnome-shell": {}, "gnome-session-b": {}, "mutter": {}, "Xorg": {},
	"Xwayland": {}, "kwin_wayland": {}, "kwin_x11": {}, "sway": {},
	"Hyprland": {}, "wayfire": {}, "weston": {}, "chromium": {}, "chrome": {},
	"google-chrome": {}, "brave": {}, "firefox": {}, "firefox-esr": {},
	"msedge": {}, "opera": {}, "vivaldi": {}, "code": {}, "zoom": {},
	"teams": {}, "skypeforlinux": {}, "slack": {}, "discord": {}, "obs": {},
	"obs-studio": {}, "cheese": {}, "vlc": {}, "gst-launch-1.0": {},
}

// persistenceInputConsumerComms are the legitimate evdev consumers of an active
// desktop session. Anything else opening an event device is keylogger-class.
var persistenceInputConsumerComms = map[string]struct{}{
	"systemd-logind": {}, "Xorg": {}, "Xwayland": {}, "gnome-shell": {},
	"mutter": {}, "kwin_wayland": {}, "kwin_x11": {}, "sway": {},
	"Hyprland": {}, "wayfire": {}, "weston": {}, "libinput": {},
	"xf86-input-libin": {},
}

// persistenceSecretTools is the expected tool set per secret-store class. A
// process outside this set (or a different uid) is the cross-store access the
// rule reports; membership is an information/tolerance decision, never an
// enforcement decision.
var persistenceSecretTools = map[uint8]map[string]struct{}{
	PersistenceClassSecretSSH: {
		"ssh": {}, "sshd": {}, "ssh-add": {}, "ssh-agent": {}, "ssh-keygen": {},
		"ssh-keyscan": {}, "scp": {}, "sftp": {}, "git": {}, "rsync": {},
		"ansible": {}, "mosh": {}, "systemd": {}, "gpg": {}, "gpg-agent": {},
		"dbus-daemon": {},
	},
	PersistenceClassSecretGNUPG: {
		"gpg": {}, "gpg2": {}, "gpg-agent": {}, "git": {}, "thunderbird": {},
		"evolution": {}, "gnome-keyring": {}, "gnome-keyring-d": {},
		"kwalletd5": {}, "kwalletd6": {}, "pass": {}, "systemd": {},
	},
	PersistenceClassSecretCloud: {
		"aws": {}, "s3cmd": {}, "rclone": {}, "gcloud": {}, "az": {},
		"terraform": {}, "kubectl": {}, "helm": {}, "ansible": {}, "systemd": {},
		"python3": {},
	},
	PersistenceClassSecretBrowser: {
		"chrome": {}, "chromium": {}, "google-chrome": {}, "brave": {},
		"firefox": {}, "firefox-esr": {}, "msedge": {}, "opera": {},
		"vivaldi": {}, "gnome-keyring": {}, "gnome-keyring-d": {},
		"kwalletd5": {}, "kwalletd6": {}, "keepassxc": {}, "bitwarden": {},
		"1password": {}, "systemd": {},
	},
	PersistenceClassSecretKeyring: {
		"gnome-keyring": {}, "gnome-keyring-d": {}, "kwalletd5": {},
		"kwalletd6": {}, "secret-tool": {}, "keepassxc": {}, "systemd": {},
		"ssh": {}, "gpg-agent": {},
	},
}

// persistenceAssessment is the pure, testable classification of one record.
type persistenceAssessment struct {
	RuleID             string
	EventKind          string
	EventType          string
	Category           string
	Severity           string
	Score              int
	Confidence         int
	CausalEdge         string
	CorrelationQuality string
	Tolerated          bool
	InfoOnly           bool
	ToleratedReason    string
	Summary            string
	Limitations        []string
}

// persistenceWriteIntent separates a write/unknown open from a harmless
// read-only open. The eBPF hook publishes `O_ACCMODE`; an unreadable
// `file.f_flags` offset is the conservative "may be a write" case.
func persistenceWriteIntent(detailCode uint32) (write bool, unknown bool) {
	if detailCode == PersistenceDetailAccUnknown {
		return true, true
	}
	return detailCode&PersistenceDetailAccMask != 0, false
}

// persistenceSessionBits decodes the honest session correlation bits.
func persistenceSessionBits(detailCode uint32) (known bool, active bool) {
	return detailCode&PersistenceDetailSessionKnown != 0, detailCode&PersistenceDetailSessionActive != 0
}

func persistenceCommIn(comm string, set map[string]struct{}) bool {
	_, ok := set[strings.TrimSpace(comm)]
	return ok
}

// persistenceExecutablePath is a bounded best-effort enrichment; it is never
// used as an identity or a decision key.
func persistenceExecutablePath(pid int) string {
	if pid <= 0 {
		return "unknown"
	}
	return titanExecProcessPath(uint32(pid))
}

// persistenceExecutableBase returns the executable basename, or "" when unknown.
func persistenceExecutableBase(path string) string {
	if path == "" || path == "unknown" {
		return ""
	}
	base := filepath.Base(path)
	if base == "." || base == string(filepath.Separator) || len(base) > 64 {
		return ""
	}
	return base
}

// persistenceProcessIdentity reads the bounded uid/comm of one target pid. A
// failure is explicit ("unknown"), never a guess.
func persistenceProcessIdentity(pid int) (uid uint32, comm string, ok bool) {
	if pid <= 0 || pid > 4194304 {
		return 0, "", false
	}
	status, err := bpfGuardReadBounded(fmt.Sprintf("/proc/%d/status", pid), persistenceProcReadBytes)
	if err != nil {
		return 0, "", false
	}
	for _, line := range strings.Split(string(status), "\n") {
		if !strings.HasPrefix(line, "Uid:") {
			continue
		}
		fields := strings.Fields(strings.TrimPrefix(line, "Uid:"))
		if len(fields) == 0 {
			return 0, "", false
		}
		value, parseErr := strconv.ParseUint(fields[0], 10, 32)
		if parseErr != nil {
			return 0, "", false
		}
		commBytes, readErr := bpfGuardReadBounded(fmt.Sprintf("/proc/%d/comm", pid), 64)
		if readErr != nil {
			return uint32(value), "", true
		}
		return uint32(value), strings.TrimSpace(string(commBytes)), true
	}
	return 0, "", false
}

// assessPersistenceEvent is the single classification/anti-false-positive
// decision point. It is pure apart from bounded `/proc` enrichment and the
// engine's own PID, so it can be unit-tested with synthetic records.
func (e *XDREngine) assessPersistenceEvent(event CorePersistenceEvent, status CorePersistenceStatus) persistenceAssessment {
	summaryPrefix := fmt.Sprintf("pid=%d uid=%d comm=%s class=%s kind=%s dev=%d ino=%d",
		event.PID, event.UID, event.Comm, PersistenceClassName(event.Class), PersistenceKindName(event.Kind), event.Dev, event.Ino)

	switch event.Kind {
	case PersistenceKindBaseline:
		return persistenceAssessment{
			InfoOnly:  true,
			EventKind: "xdr.persistence_baseline_marker", Severity: "info", Score: 0,
			Summary: fmt.Sprintf("Persistence baseline marker: roots=%d (userspace in-memory reference point; no response action)",
				event.DetailCode),
		}
	case PersistenceKindIntegrityWrite, PersistenceKindDrift:
		ruleID, score, category := PersistenceRuleDrift, 100, "persistence"
		if event.Class <= PersistenceClassTLS {
			ruleID, score, category = PersistenceRuleLDPreload, 110, "integrity"
		}
		eventType, eventKind := "PERSISTENCE_PATH_WRITE", "xdr.persistence_entry_drift"
		summary := summaryPrefix
		var limitations []string
		if event.Kind == PersistenceKindDrift {
			eventType, eventKind = "PERSISTENCE_CONTENT_DRIFT", "xdr.persistence_content_drift"
			summary += fmt.Sprintf("; userspace SHA-256 drift detected (reason=%s): the file changed since the in-memory baseline",
				persistenceDriftReasonName(event.DetailCode))
		} else {
			write, unknown := persistenceWriteIntent(event.DetailCode)
			if !write {
				return persistenceAssessment{
					InfoOnly: true, EventKind: "xdr.persistence_read_open", Severity: "info", Score: 0,
					Summary: "Read-only open of a watched persistence path; no write intent, recorded as information only: " + summaryPrefix,
				}
			}
			if unknown {
				limitations = append(limitations, "access intent unknown (file.f_flags offset unavailable); treated conservatively as a write")
				eventType = "PERSISTENCE_PATH_WRITE_INTENT_UNKNOWN"
			}
		}
		if tolerated, reason := e.persistenceIntegrityTolerated(event); tolerated {
			return persistenceAssessment{Tolerated: true, ToleratedReason: reason, EventKind: eventKind, Score: score, Severity: "info"}
		}
		return persistenceAssessment{
			RuleID: ruleID, EventKind: eventKind, EventType: eventType, Category: category,
			Severity: "high", Score: score, Confidence: 95, CausalEdge: EdgeFileModified,
			CorrelationQuality: persistenceQualityObserved,
			Summary:            summary, Limitations: limitations,
		}
	case PersistenceKindLibraryMmap:
		quality := persistenceQualityNone
		var limitations []string
		if status.PkgdbReady {
			quality = persistenceQualityObserved
		} else if status.Pkgdb == "unsupported" {
			limitations = append(limitations, "pkgdb=unsupported: library ownership cannot be verified; the event is evidence with correlation NONE, not an ownership claim")
		} else {
			limitations = append(limitations, fmt.Sprintf("pkgdb=%s parsed without a usable inode index: ownership cannot be claimed; correlation NONE", status.Pkgdb))
		}
		summary := summaryPrefix + fmt.Sprintf("; library mapped into a protected executable with prot=%#x; package database not consulted for enforcement", event.DetailCode)
		return persistenceAssessment{
			RuleID: PersistenceRuleLinker, EventKind: "xdr.linker_hook", EventType: "PROTECTED_EXEC_LIBRARY_MMAP",
			Category: "linker", Severity: "high", Score: 120, Confidence: 90, CausalEdge: EdgeRootCause,
			CorrelationQuality: quality, Summary: summary, Limitations: limitations,
		}
	case PersistenceKindPeripheralOpen:
		known, active := persistenceSessionBits(event.DetailCode)
		ruleID, score, category := PersistenceRulePeripheral, 90, "peripheral"
		eventType := "PERIPHERAL_BACKGROUND_ACCESS"
		if event.Class == PersistenceClassDeviceEvdev {
			ruleID, score, category = PersistenceRuleEvdev, 100, "peripheral"
			eventType = "EVDEV_BACKGROUND_ACCESS"
		}
		expected := persistenceInputConsumerComms
		if event.Class != PersistenceClassDeviceEvdev {
			expected = persistenceDesktopMediaComms
		}
		summary := summaryPrefix
		var limitations []string
		quality := persistenceQualityNone
		switch {
		case !known:
			return persistenceAssessment{
				InfoOnly: true, EventKind: "xdr.persistence_peripheral_no_session_view", Severity: "info", Score: 0,
				Summary: "Peripheral access observed without a readable session view; not escalated because the session-inactive condition cannot be established (correlation NONE): " + summary,
			}
		case active && persistenceCommIn(event.Comm, expected):
			return persistenceAssessment{Tolerated: true, ToleratedReason: "desktop-session owner of its own device (active session, expected consumer)",
				EventKind: "xdr.persistence_peripheral_owner", Score: score, Severity: "info"}
		case active:
			quality = persistenceQualityNone
			limitations = append(limitations, "the process uid has an active local session but this process is not the expected desktop consumer; session correlation cannot explain the access")
			summary += "; device opened by a non-desktop process during an active session"
		default:
			quality = persistenceQualityTemporal
			limitations = append(limitations, "idlehint=unavailable (logind IdleHint is a D-Bus property, not a file); the finding is TEMPORAL session-inactive evidence, never OBSERVED lock state")
			summary += "; device opened while the process uid has no active local session"
		}
		return persistenceAssessment{
			RuleID: ruleID, EventKind: "xdr.peripheral_bg_access", EventType: eventType, Category: category,
			Severity: "warning", Score: score, Confidence: 80, CausalEdge: EdgeRootCause,
			CorrelationQuality: quality, Summary: summary, Limitations: limitations,
		}
	case PersistenceKindSecretOpen:
		tools, known := persistenceSecretTools[event.Class]
		expected := known && (persistenceCommIn(event.Comm, tools) || persistenceCommIn(persistenceExecutableBase(persistenceExecutablePath(event.PID)), tools))
		owner := event.DetailCode
		crossUser := owner != 0 && owner != event.UID
		if expected && !crossUser {
			return persistenceAssessment{Tolerated: true, ToleratedReason: "expected per-store tool set for the owning uid",
				EventKind: "xdr.persistence_secret_owner", Score: 90, Severity: "info"}
		}
		var limitations []string
		quality := persistenceQualityObserved
		exe := persistenceExecutablePath(event.PID)
		if exe == "unknown" {
			quality = persistenceQualityNone
			limitations = append(limitations, "the accessing executable could not be resolved through /proc; membership in the expected tool set is unknown (correlation NONE)")
		}
		if crossUser {
			limitations = append(limitations, fmt.Sprintf("cross-uid access: opener uid=%d, watched store owner uid=%d", event.UID, owner))
		}
		return persistenceAssessment{
			RuleID: PersistenceRuleSecret, EventKind: "xdr.secret_store_access", EventType: "SECRET_STORE_OPEN",
			Category: "credential", Severity: "warning", Score: 90, Confidence: 85, CausalEdge: EdgePrivilegeEscalated,
			CorrelationQuality: quality,
			Summary:            fmt.Sprintf("%s; secret store opened by a process outside the owner's expected tool set (owner_uid=%d)", summaryPrefix, owner),
			Limitations:        limitations,
		}
	case PersistenceKindMemoryScrape, PersistenceKindPtraceAccess:
		direction := "process_vm memory access"
		mode := ""
		if event.Kind == PersistenceKindMemoryScrape {
			if event.Detail != "" {
				direction = "process_vm_" + event.Detail
			}
		} else {
			direction = "ptrace_access_check"
			mode = event.Detail
		}
		target := int(event.DetailCode)
		if target <= 0 {
			return persistenceAssessment{
				RuleID: PersistenceRuleMemory, EventKind: "xdr.memory_scrape_probe", EventType: "MEMORY_SCRAPE_PROBE",
				Category: "memory", Severity: "warning", Score: 70, Confidence: 60, CausalEdge: EdgeMemoryScraped,
				CorrelationQuality: persistenceQualityNone,
				Summary:            fmt.Sprintf("%s; %s with an unresolved target pid (tracefs format unreadable, pid/comm-only degradation)", summaryPrefix, direction),
				Limitations:        []string{"target pid unavailable: the control plane cannot establish the unrelated-uid condition; the event is bounded evidence only"},
			}
		}
		targetUID, targetComm, ok := persistenceProcessIdentity(target)
		if !ok {
			return persistenceAssessment{
				RuleID: PersistenceRuleMemory, EventKind: "xdr.memory_scrape_probe", EventType: "MEMORY_SCRAPE_PROBE",
				Category: "memory", Severity: "warning", Score: 70, Confidence: 65, CausalEdge: EdgeMemoryScraped,
				CorrelationQuality: persistenceQualityNone,
				Summary:            fmt.Sprintf("%s; %s against target pid=%d (target exited or /proc unreadable; uid relation unknown)", summaryPrefix, direction, target),
				Limitations:        []string{"target process no longer resolvable: the unrelated-uid condition cannot be verified, correlation NONE"},
			}
		}
		if targetUID == event.UID {
			return persistenceAssessment{
				InfoOnly: true, EventKind: "xdr.persistence_memory_same_uid", Severity: "info", Score: 0,
				Summary: fmt.Sprintf("%s; %s against same-uid target pid=%d comm=%s (debugger/self-service class, information only; mode=%q)",
					summaryPrefix, direction, target, targetComm, mode),
			}
		}
		if event.Kind == PersistenceKindPtraceAccess && e.persistenceBenignRootProcRead(event, targetComm, mode) {
			return persistenceAssessment{
				InfoOnly: true, EventKind: "xdr.persistence_proc_read_noaudit", Severity: "info", Score: 0,
				Summary: fmt.Sprintf("%s; non-attach NOAUDIT procfs metadata read by managed root binary against pid=%d uid=%d comm=%s (mode=%q)",
					summaryPrefix, target, targetUID, targetComm, mode),
			}
		}
		return persistenceAssessment{
			RuleID: PersistenceRuleMemory, EventKind: "xdr.memory_scrape_probe", EventType: "MEMORY_SCRAPE_PROBE",
			Category: "memory", Severity: "high", Score: 110, Confidence: 92, CausalEdge: EdgeMemoryScraped,
			CorrelationQuality: persistenceQualityObserved,
			Summary: fmt.Sprintf("%s; %s against unrelated target pid=%d uid=%d comm=%s (mode=%q)",
				summaryPrefix, direction, target, targetUID, targetComm, mode),
		}
	}
	return persistenceAssessment{
		InfoOnly: true, EventKind: "xdr.persistence_unknown", Severity: "info", Score: 0,
		Summary: "Unclassified persistence record ignored: " + summaryPrefix,
	}
}

const (
	linuxPtraceModeAttach  uint64 = 0x02
	linuxPtraceModeNoAudit uint64 = 0x04
)

var persistenceManagedSystemPrefixes = []string{
	"/usr/bin/", "/usr/sbin/", "/bin/", "/sbin/",
	"/usr/lib/", "/lib/", "/usr/libexec/", "/opt/vgt/gedefense/",
}

// persistenceBenignRootProcRead filters non-attach PTRACE_MODE_NOAUDIT procfs
// reads (e.g., landscape-sysinfo/ps inspecting /proc/<pid>/stat or maps)
// strictly when initiated by root from an immutable system executable against
// non-GeDefense targets. Attach/mem reads (0x02), non-NOAUDIT reads (e.g.
// environ=0x09), unprivileged callers, writable-dir binaries, and GeDefense
// daemons always stay escalated.
func (e *XDREngine) persistenceBenignRootProcRead(event CorePersistenceEvent, targetComm, modeRaw string) bool {
	if event.UID != 0 {
		return false
	}
	modeVal, err := strconv.ParseUint(strings.TrimSpace(modeRaw), 10, 32)
	if err != nil {
		return false
	}
	if modeVal&linuxPtraceModeAttach != 0 || modeVal&linuxPtraceModeNoAudit == 0 {
		return false
	}
	lowerTarget := strings.ToLower(strings.TrimSpace(targetComm))
	if strings.HasPrefix(lowerTarget, "gedefense-") || persistenceCommIn(targetComm, persistenceOwnComms) {
		return false
	}
	exe := e.resolveProcessPath(event.PID)
	if exe == "" || exe == "unknown" || bpfGuardPathUnderAny(exe, bpfGuardTempPathPrefixes) {
		return false
	}
	cleanExe := filepath.Clean(exe)
	for _, prefix := range persistenceManagedSystemPrefixes {
		if strings.HasPrefix(cleanExe, prefix) {
			return true
		}
	}
	return false
}

// persistenceDriftReasonName names one drift reason code.
func persistenceDriftReasonName(reason uint32) string {
	switch reason {
	case PersistenceDriftContent:
		return "content-changed"
	case PersistenceDriftMissing:
		return "file-missing"
	case PersistenceDriftAppeared:
		return "file-appeared"
	case PersistenceDriftReplaced:
		return "inode-replaced"
	default:
		return fmt.Sprintf("reason-%d", reason)
	}
}

// recordPersistenceFinding creates evidence first, then exactly one alert-only
// incident with an attack-story node. No response action is derived and no
// kill-eligibility is added.
func (e *XDREngine) recordPersistenceFinding(assessment persistenceAssessment, event CorePersistenceEvent, now time.Time) {
	if e == nil || e.state == nil {
		return
	}
	exe := persistenceExecutablePath(event.PID)
	summary := assessment.Summary
	if len(assessment.Limitations) > 0 {
		summary = fmt.Sprintf("%s; limitations: %s", summary, strings.Join(assessment.Limitations, "; "))
	}
	summary = persistenceBoundedText(summary, 1024)
	target := fmt.Sprintf("pid:%d:dev:%d:ino:%d", event.PID, event.Dev, event.Ino)
	evidenceErr := e.state.RecordEvidence(EvidenceRecord{
		Severity: assessment.Severity, Kind: assessment.EventKind, Source: "kernel",
		Message: "Persistence/peripheral guard evidence recorded before any response: " + summary,
		Target:  target, Time: now,
	})
	outcome := "observe-only: the persistence/peripheral guard is evidence-first; no active response was derived and the kill gate is untouched"
	if evidenceErr != nil {
		outcome = "observe-only; mandatory evidence commit failed, incident recorded without response: " + evidenceErr.Error()
	}
	metadata := map[string]string{
		"action":              "alert",
		"decided_by":          "persistence_guard",
		"rule":                assessment.RuleID,
		"class":               PersistenceClassName(event.Class),
		"kind":                PersistenceKindName(event.Kind),
		"pid":                 strconv.Itoa(event.PID),
		"tgid":                strconv.Itoa(event.TGID),
		"uid":                 strconv.FormatUint(uint64(event.UID), 10),
		"dev":                 strconv.FormatUint(uint64(event.Dev), 10),
		"ino":                 strconv.FormatUint(event.Ino, 10),
		"comm":                event.Comm,
		"exe_path":            exe,
		"detail_code":         strconv.FormatUint(uint64(event.DetailCode), 10),
		"correlation_quality": assessment.CorrelationQuality,
		"observe_only":        "true",
		"kill_eligibility":    "none",
	}
	if len(assessment.Limitations) > 0 {
		metadata["limitations"] = persistenceBoundedText(strings.Join(assessment.Limitations, "; "), persistenceReasonBytes)
	}
	node := AttackStoryNode{
		NodeID:     fmt.Sprintf("persistence-%d-%d", event.PID, now.UnixNano()),
		Timestamp:  now,
		Sensor:     "kernel-persistence",
		Category:   assessment.Category,
		EventType:  assessment.EventType,
		EntityID:   fmt.Sprintf("pid:%d", event.TGID),
		Actor:      fmt.Sprintf("uid:%d", event.UID),
		Severity:   assessment.Severity,
		Confidence: assessment.Confidence,
		CausalEdge: assessment.CausalEdge,
		EventUUID:  randomID(),
		Metadata:   metadata,
	}
	node.Digest = node.ComputeNodeDigest()
	categories := []string{assessment.Category, "persistence"}
	incident := XDRIncident{
		ID: randomID(), Time: now, Severity: assessment.Severity, Score: assessment.Score,
		PID: event.PID, UID: event.UID, Process: event.Comm, Executable: exe,
		RuleIDs: []string{assessment.RuleID}, Categories: categories,
		Summary: summary, Decision: "alert", Action: "none", Outcome: outcome,
		ExecutionChainID: node.NodeID, AttackStory: []AttackStoryNode{node},
		EvidenceRoot: node.Digest,
	}
	e.appendIncident(incident)
	e.state.AddEvent(Event{Time: now, Severity: assessment.Severity, Kind: assessment.EventKind, Source: "kernel",
		Message: summary, Target: fmt.Sprintf("pid:%d", event.PID)})
}

// persistenceBoundedText collapses whitespace and bounds operator-facing text.
func persistenceBoundedText(text string, max int) string {
	text = strings.TrimSpace(strings.Join(strings.Fields(text), " "))
	if max > 0 && len(text) > max {
		text = text[:max]
	}
	return text
}
