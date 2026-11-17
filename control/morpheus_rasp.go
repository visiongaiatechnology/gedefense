// STATUS: DIAMANT VGT SUPREME
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// morpheusTrustedDebuggerRoots lists the system locations a trusted debugger binary may be
// installed in. The exemption is bound to the executable identity the kernel reports, so a
// binary that merely calls itself "gdb" - or a copy of gdb dropped in /tmp - is not exempt.
var morpheusTrustedDebuggerRoots = []string{
	"/usr/bin", "/bin", "/usr/sbin", "/sbin", "/usr/local/bin", "/usr/local/sbin",
}

// morpheusScrapingToolNames are the tool names this heuristic recognises. The list is a hint,
// not the detection boundary: a renamed copy of any of them is still caught when it addresses
// a protected process with an attach-style argument (see attachStylePID).
var morpheusScrapingToolNames = map[string]bool{
	"gdb": true, "gdbserver": true, "lldb": true, "lldb-server": true,
	"strace": true, "ltrace": true, "frida": true, "frida-server": true,
	"radare2": true, "r2": true, "procdump": true, "scanmem": true,
	"gameconqueror": true, "gcore": true, "process_vm_readv": true, "process_vm_writev": true,
}

// Typed Morpheus RASP Error Hierarchy (Section 1.5.A Compliance)
type MorpheusException struct {
	Message string
	Err     error
}

func (e *MorpheusException) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("%s: %v", e.Message, e.Err)
	}
	return e.Message
}

func (e *MorpheusException) Unwrap() error { return e.Err }

type MorpheusValidationException struct{ MorpheusException }
type MorpheusSecurityException struct{ MorpheusException }

func NewMorpheusValidationException(msg string, err error) *MorpheusValidationException {
	return &MorpheusValidationException{MorpheusException{Message: msg, Err: err}}
}

func NewMorpheusSecurityException(msg string, err error) *MorpheusSecurityException {
	return &MorpheusSecurityException{MorpheusException{Message: msg, Err: err}}
}

type RASPEvent struct {
	EventID    string            `json:"event_id"`
	Timestamp  time.Time         `json:"timestamp"`
	ThreatType string            `json:"threat_type"`
	Severity   string            `json:"severity"`
	SourcePID  int               `json:"source_pid"`
	TargetPID  int               `json:"target_pid"`
	SourceComm string            `json:"source_comm"`
	TargetComm string            `json:"target_comm"`
	Details    map[string]string `json:"details"`
	AttackNode *AttackStoryNode  `json:"attack_node,omitempty"`
}

type MorpheusRASP struct {
	mu               sync.RWMutex
	enabled          bool
	protectedNames   map[string]bool
	protectedPIDs    map[int]bool
	trustedDebuggers map[string]bool
	containment      bool
	yamaScopePath    string
	correlator       *IncidentCorrelator
	incidentSink     func(XDRIncident) error
}

func NewMorpheusRASP(
	yamaScopePath string,
	correlator *IncidentCorrelator,
	incidentSink func(XDRIncident) error,
) *MorpheusRASP {
	if yamaScopePath == "" {
		yamaScopePath = "/proc/sys/kernel/yama/ptrace_scope"
	}
	m := &MorpheusRASP{
		protectedNames: map[string]bool{
			"gedefense-core":     true,
			"gedefense-control":  true,
			"astraea-key-broker": true,
			"key-broker":         true,
			"systemd-resolved":   true,
			"ssh-agent":          true,
			"gnome-keyring-d":    true,
			"keepassxc":          true,
			"vault":              true,
		},
		enabled:          true,
		containment:      true,
		trustedDebuggers: make(map[string]bool),
		protectedPIDs:    make(map[int]bool),
		yamaScopePath:    yamaScopePath,
		correlator:       correlator,
		incidentSink:     incidentSink,
	}
	return m
}

// ApplyPolicy republishes the administrable RASP posture. Trusted debuggers are
// exemptions from detection, never a way to disable detection for everyone.
func (m *MorpheusRASP) ApplyPolicy(settings HardeningRASPSettings) {
	if m == nil {
		return
	}
	names := make(map[string]bool, len(settings.ProtectedNames))
	for _, name := range settings.ProtectedNames {
		names[strings.ToLower(name)] = true
	}
	debuggers := make(map[string]bool, len(settings.TrustedDebuggers))
	for _, name := range settings.TrustedDebuggers {
		debuggers[strings.ToLower(name)] = true
	}
	m.mu.Lock()
	m.enabled = settings.Enabled
	m.protectedNames = names
	m.trustedDebuggers = debuggers
	m.containment = settings.ContainmentEnabled && !settings.AlertOnly
	m.mu.Unlock()
}

// Enabled reports whether the RASP data path participates in evaluation.
func (m *MorpheusRASP) Enabled() bool {
	if m == nil {
		return false
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.enabled
}

// ContainmentEnabled reports whether a detection may also apply an active response.
//
// When it is false the detection is still a complete event: the incident is emitted by the
// sink, the caller must alarm on the returned event, and no freeze may be applied. This
// separates "report only" from "nothing happened", which an alert-only policy got wrong.
func (m *MorpheusRASP) ContainmentEnabled() bool {
	if m == nil {
		return false
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.containment
}

// RegisterProtectedPID marks a daemon or process ID as strictly immutable against ptrace/mem inspection.
func (m *MorpheusRASP) RegisterProtectedPID(pid int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.protectedPIDs[pid] = true
}

// UnregisterProtectedPID removes protection for terminating processes.
func (m *MorpheusRASP) UnregisterProtectedPID(pid int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.protectedPIDs, pid)
}

// ReadYamaPtraceScope reads the current kernel ptrace restriction level (0-3).
func (m *MorpheusRASP) ReadYamaPtraceScope() (int, error) {
	data, err := os.ReadFile(m.yamaScopePath)
	if err != nil {
		// Non-Linux or non-yama kernel defaults to scope 1 (restricted)
		return 1, nil
	}
	val := strings.TrimSpace(string(data))
	scope, err := strconv.Atoi(val)
	if err != nil {
		return 1, nil
	}
	return scope, nil
}

// InspectMemoryAccess inspects whether a process is attempting unauthorized ptrace or /proc/<pid>/mem reading.
//
// The trusted-debugger exemption is resolved by InspectProcess before this point, because it
// needs the caller's executable identity and UID; this function only evaluates the access
// itself. isChildOfSource keeps the legitimate parent/child debugging case permitted.
func (m *MorpheusRASP) InspectMemoryAccess(
	sourcePID int, sourceComm string,
	targetPID int, targetComm string,
	isChildOfSource bool,
) (*RASPEvent, error) {
	m.mu.RLock()
	enabled := m.enabled
	isProtectedName := m.protectedNames[strings.ToLower(targetComm)]
	isProtectedPID := m.protectedPIDs[targetPID]
	containment := m.containment
	m.mu.RUnlock()

	if !enabled {
		return nil, nil
	}

	now := time.Now().UTC()

	// Direct Violation: Any non-child process attempting to trace or inspect a protected vault/daemon
	if (isProtectedName || isProtectedPID) && !isChildOfSource {
		eventID := fmt.Sprintf("RASP-MEM-%d-%d", sourcePID, now.UnixNano())
		actorStr := fmt.Sprintf("PID:%d|%s", sourcePID, sourceComm)
		targetStr := fmt.Sprintf("PID:%d|%s", targetPID, targetComm)

		storyNode := AttackStoryNode{
			NodeID:     fmt.Sprintf("node-rasp-%d", now.UnixNano()),
			Timestamp:  now,
			Sensor:     "MORPHEUS_RASP_MEMORY",
			Category:   "PRIVILEGE_ESCALATION",
			EventType:  "PROCESS_MEMORY_SCRAPING",
			EntityID:   targetStr,
			Actor:      actorStr,
			Severity:   "critical",
			Confidence: 100,
			CausalEdge: EdgePrivilegeEscalated,
			EventUUID:  eventID,
			Metadata: map[string]string{
				"source_pid":  strconv.Itoa(sourcePID),
				"target_pid":  strconv.Itoa(targetPID),
				"source_comm": sourceComm,
				"target_comm": targetComm,
			},
		}

		var storyNodes []AttackStoryNode
		var recordHash string
		if m.correlator != nil {
			graph, _, err := m.correlator.IngestEvent(now, actorStr, targetComm, "PRIVILEGE_ESCALATION", storyNode)
			if err == nil && graph != nil {
				storyNodes = graph.CloneNodes()
				recordHash = graph.EvidenceRoot()
			}
		}
		if len(storyNodes) == 0 {
			storyNodes = []AttackStoryNode{storyNode}
			recordHash = storyNode.ComputeNodeDigest()
		}

		if m.incidentSink != nil {
			_ = m.incidentSink(XDRIncident{
				ID:            eventID,
				Time:          now,
				Severity:      "critical",
				Score:         250,
				ResponseScore: 250,
				PID:           sourcePID,
				Process:       sourceComm,
				Remote:        targetStr,
				Summary:       fmt.Sprintf("Process memory scraping blocked: PID %d (%s) attempted memory access on %s (PID %d)", sourcePID, sourceComm, targetComm, targetPID),
				RuleIDs:       []string{"MORPHEUS.RASP.MEM_SCRAPE", "MORPHEUS.PTRACE_PROTECTED"},
				Categories:    []string{"privilege_escalation", "credential_access"},
				Decision:      boolToDecision(containment, "block", "alert"),
				Action:        boolToDecision(containment, "freeze-execution", "observe"),
				Outcome:       boolToDecision(containment, "intercepted and reported by morpheus rasp", "reported by morpheus rasp; containment disabled by policy"),
				AttackStory:   storyNodes,
				EvidenceRoot:  recordHash,
			})
		}

		event := &RASPEvent{
			EventID:    eventID,
			Timestamp:  now,
			ThreatType: "PROCESS_MEMORY_SCRAPING",
			Severity:   "critical",
			SourcePID:  sourcePID,
			TargetPID:  targetPID,
			SourceComm: sourceComm,
			TargetComm: targetComm,
			Details: map[string]string{
				"reason": "unauthorized cross-process memory inspection against protected daemon",
			},
			AttackNode: &storyNode,
		}

		if !containment {
			return event, nil
		}
		return event, NewMorpheusSecurityException(
			fmt.Sprintf("unauthorized memory scraping attempt from PID %d against %s", sourcePID, targetComm),
			nil,
		)
	}

	return nil, nil
}

// raspTarget is the protected process an inspection or scraping attempt addresses.
type raspTarget struct {
	pid   int
	label string
}

// InspectProcess inspects live process telemetry for memory scraping, unauthorized ptrace, or
// /proc/<pid>/mem reads against protected daemons.
//
// The order is deliberate: the protected target is resolved first, then a trusted-debugger
// exemption is considered, and only then the detection signal. A trusted name therefore never
// short-circuits the target check, and the exemption itself is bound to the executable identity
// and UID the kernel reports rather than to whatever name the process presents.
func (m *MorpheusRASP) InspectProcess(p ProcessSample) (*RASPEvent, error) {
	if p.PID <= 1 {
		return nil, nil
	}
	if !m.Enabled() {
		return nil, nil
	}
	m.mu.RLock()
	protectedNames := make([]string, 0, len(m.protectedNames))
	for name := range m.protectedNames {
		protectedNames = append(protectedNames, name)
	}
	protectedPIDs := make([]int, 0, len(m.protectedPIDs))
	for pid := range m.protectedPIDs {
		protectedPIDs = append(protectedPIDs, pid)
	}
	m.mu.RUnlock()

	// 1. The target check comes first. A trusted debugger is an exemption from this detection,
	// not a global off switch, so it cannot retreat before it is established that a protected
	// process is addressed at all.
	target, attachStyle, ok := resolveRASPTarget(p, protectedNames, protectedPIDs)
	if !ok {
		return nil, nil
	}
	if m.trustedDebuggerExempt(p) {
		return nil, nil
	}

	// 2. The detection signal. A name-based tool match is one clue; an attach-style argument
	// aimed at a protected PID is another and survives renaming the tool binary.
	if !attachStyle && !memoryInspectionSignals(p) {
		return nil, nil
	}
	return m.InspectMemoryAccess(p.PID, p.Comm, target.pid, target.label, false)
}

// resolveRASPTarget decides whether the process addresses a protected daemon and whether that
// address carries an attach-style argument (which is a detection signal on its own).
func resolveRASPTarget(p ProcessSample, protectedNames []string, protectedPIDs []int) (raspTarget, bool, bool) {
	cmdLower := strings.ToLower(p.Cmdline)
	commLower := strings.ToLower(strings.TrimSpace(p.Comm))
	exeBase := strings.ToLower(strings.TrimSuffix(filepath.Base(strings.TrimSpace(p.Exe)), " (deleted)"))
	selfNames := map[string]bool{commLower: true}
	if exeBase != "" && exeBase != "." {
		selfNames[exeBase] = true
	}
	for _, name := range protectedNames {
		name = strings.ToLower(strings.TrimSpace(name))
		if name == "" || selfNames[name] {
			// A protected daemon's own command line names itself; that is not an inspection.
			continue
		}
		if strings.Contains(cmdLower, name) {
			return raspTarget{label: name}, hasAttachArguments(p.Cmdline), true
		}
	}
	for _, pid := range protectedPIDs {
		if pid <= 0 {
			continue
		}
		if attachStylePID(cmdLower, pid) {
			return raspTarget{pid: pid, label: "protected-vault"}, true, true
		}
		// A plain mention identifies a target but is not by itself an attach signal.
		if strings.Contains(cmdLower, strconv.Itoa(pid)) {
			return raspTarget{pid: pid, label: "protected-vault"}, false, true
		}
	}
	return raspTarget{}, false, false
}

// memoryInspectionSignals reports whether the process is recognisable as a memory-inspection or
// tracing tool, either by its executable/comm name or by inspection-only arguments.
func memoryInspectionSignals(p ProcessSample) bool {
	comm := strings.ToLower(strings.TrimSpace(p.Comm))
	exeBase := strings.ToLower(strings.TrimSuffix(filepath.Base(strings.TrimSpace(p.Exe)), " (deleted)"))
	if morpheusScrapingToolNames[comm] || (exeBase != "" && exeBase != "." && morpheusScrapingToolNames[exeBase]) {
		return true
	}
	cmdLower := strings.ToLower(p.Cmdline)
	for _, marker := range []string{"/mem", "ptrace", "process_vm_readv", "process_vm_writev", "gcore"} {
		if strings.Contains(cmdLower, marker) {
			return true
		}
	}
	return false
}

// hasAttachArguments reports whether the command line carries an attach-style argument. The
// check is argument-boundary based, so it does not confuse a PID with part of another number.
func hasAttachArguments(cmdline string) bool {
	fields := strings.Fields(cmdline)
	for i, raw := range fields {
		field := strings.ToLower(strings.Trim(raw, " \t\r\n,;'\"()"))
		switch field {
		case "-p", "--pid", "--attach", "-attach", "--tid":
			if i+1 < len(fields) && isDecimalToken(strings.Trim(fields[i+1], " \t\r\n,;'\"()=")) {
				return true
			}
		}
		for _, prefix := range []string{"--pid=", "--attach=", "--tid=", "-p"} {
			if strings.HasPrefix(field, prefix) && isDecimalToken(strings.Trim(field[len(prefix):], "=")) {
				return true
			}
		}
		if strings.Contains(field, "/proc/") && strings.HasSuffix(field, "/mem") {
			return true
		}
	}
	return false
}

// attachStylePID reports whether a specific protected PID is addressed in attach form, for
// example "gdb -p 1234", "strace --attach=1234" or "/proc/1234/mem". This is the signal that
// survives renaming the tool binary.
func attachStylePID(cmdLower string, pid int) bool {
	pidStr := strconv.Itoa(pid)
	fields := strings.Fields(cmdLower)
	for i, raw := range fields {
		field := strings.Trim(raw, " \t\r\n,;'\"()")
		switch field {
		case "-p", "--pid", "--attach", "-attach", "--tid":
			if i+1 < len(fields) && strings.Trim(fields[i+1], " \t\r\n,;'\"()=") == pidStr {
				return true
			}
		}
		for _, prefix := range []string{"--pid=", "--attach=", "--tid=", "-p"} {
			if strings.HasPrefix(field, prefix) && strings.Trim(field[len(prefix):], "=") == pidStr {
				return true
			}
		}
		if strings.Contains(field, "/proc/"+pidStr+"/mem") {
			return true
		}
	}
	return false
}

func isDecimalToken(value string) bool {
	if value == "" {
		return false
	}
	for _, r := range value {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// trustedDebuggerExempt reports whether the process holds an administrative debugger exemption.
//
// The exemption is bound to identity, not to the name the process presents: the process must run
// as root (ptracing another process requires privilege), and when the sensor resolved its
// executable that binary has to be a root-owned, non-writable regular file below a system
// directory. A binary copied to /tmp and renamed "gdb" therefore fails the identity check, while
// a renamed copy of gdb that addresses a protected PID is still detected as a scraper.
func (m *MorpheusRASP) trustedDebuggerExempt(p ProcessSample) bool {
	m.mu.RLock()
	trusted := m.trustedDebuggers
	m.mu.RUnlock()
	if len(trusted) == 0 {
		return false
	}
	comm := strings.ToLower(strings.TrimSpace(p.Comm))
	exe := strings.TrimSuffix(strings.TrimSpace(p.Exe), " (deleted)")
	exeBase := strings.ToLower(filepath.Base(exe))
	nameMatch := trusted[comm] || (exeBase != "" && exeBase != "." && trusted[exeBase])
	if !nameMatch {
		return false
	}
	if p.UID != 0 {
		return false
	}
	if exe == "" {
		// No executable identity was reported by the sensor (kernel thread, restricted
		// /proc). Only a root process may hold the exemption in that case; a reported path
		// would have to pass the stricter binary check below.
		return true
	}
	return verifiedDebuggerBinary(exe)
}

// verifiedDebuggerBinary reports whether exe is a plausible signed system debugger: an absolute,
// canonical path that resolves below a trusted system directory and is a regular file that
// neither the group nor the world may write to.
func verifiedDebuggerBinary(exe string) bool {
	if !filepath.IsAbs(exe) || filepath.Clean(exe) != exe {
		return false
	}
	info, err := os.Lstat(exe)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return false
	}
	if info.Mode().Perm()&0o022 != 0 {
		return false
	}
	resolved, err := filepath.EvalSymlinks(exe)
	if err != nil {
		return false
	}
	for _, root := range morpheusTrustedDebuggerRoots {
		if resolved == root || strings.HasPrefix(resolved, root+string(filepath.Separator)) {
			return true
		}
	}
	return false
}

// ScrubSensitiveCredentials redacts common secret tokens and keys in place with constant-time length preservation.
func ScrubSensitiveCredentials(input string) string {
	secretKeywords := []string{
		"AWS_SECRET_ACCESS_KEY=",
		"AWS_SESSION_TOKEN=",
		"PRIVATE_KEY=",
		"API_KEY=",
		"PASSWORD=",
		"TOKEN=",
		"BEARER ",
	}

	result := input
	for _, kw := range secretKeywords {
		idx := strings.Index(strings.ToUpper(result), kw)
		for idx != -1 {
			start := idx + len(kw)
			end := strings.IndexAny(result[start:], " \t\r\n;&|\"')")
			if end == -1 {
				end = len(result)
			} else {
				end = start + end
			}

			if end > start {
				valLen := end - start
				if valLen > 0 {
					replacement := "[VGT_REDACTED_SECRET]"
					result = result[:start] + replacement + result[end:]
				}
			}
			nextSearch := start + 20
			if nextSearch >= len(result) {
				break
			}
			idx = strings.Index(strings.ToUpper(result[nextSearch:]), kw)
			if idx != -1 {
				idx += nextSearch
			}
		}
	}
	return result
}
