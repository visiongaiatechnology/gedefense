// STATUS: DIAMANT VGT SUPREME
package main

import (
	"crypto/subtle"
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

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
	mu             sync.RWMutex
	protectedNames map[string]bool
	protectedPIDs  map[int]bool
	yamaScopePath  string
	correlator     *IncidentCorrelator
	incidentSink   func(XDRIncident) error
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
		protectedPIDs: make(map[int]bool),
		yamaScopePath: yamaScopePath,
		correlator:    correlator,
		incidentSink:  incidentSink,
	}
	return m
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
func (m *MorpheusRASP) InspectMemoryAccess(
	sourcePID int, sourceComm string,
	targetPID int, targetComm string,
	isChildOfSource bool,
) (*RASPEvent, error) {
	m.mu.RLock()
	isProtectedName := m.protectedNames[strings.ToLower(targetComm)]
	isProtectedPID := m.protectedPIDs[targetPID]
	m.mu.RUnlock()

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
			Severity:   "CRITICAL",
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
				Severity:      "CRITICAL",
				Score:         250,
				ResponseScore: 250,
				PID:           sourcePID,
				Process:       sourceComm,
				Remote:        targetStr,
				Summary:       fmt.Sprintf("Process memory scraping blocked: PID %d (%s) attempted memory access on %s (PID %d)", sourcePID, sourceComm, targetComm, targetPID),
				RuleIDs:       []string{"MORPHEUS.RASP.MEM_SCRAPE", "MORPHEUS.PTRACE_PROTECTED"},
				Categories:    []string{"privilege_escalation", "credential_access"},
				Decision:      "block",
				Action:        "freeze-execution",
				Outcome:       "intercepted and reported by morpheus rasp",
				AttackStory:   storyNodes,
				EvidenceRoot:  recordHash,
			})
		}

		event := &RASPEvent{
			EventID:    eventID,
			Timestamp:  now,
			ThreatType: "PROCESS_MEMORY_SCRAPING",
			Severity:   "CRITICAL",
			SourcePID:  sourcePID,
			TargetPID:  targetPID,
			SourceComm: sourceComm,
			TargetComm: targetComm,
			Details: map[string]string{
				"reason": "unauthorized cross-process memory inspection against protected daemon",
			},
			AttackNode: &storyNode,
		}

		return event, NewMorpheusSecurityException(
			fmt.Sprintf("unauthorized memory scraping attempt from PID %d against %s", sourcePID, targetComm),
			nil,
		)
	}

	return nil, nil
}

// InspectProcess inspects live process telemetry for memory scraping, unauthorized ptrace, or /proc/<pid>/mem reads against protected daemons.
func (m *MorpheusRASP) InspectProcess(p ProcessSample) (*RASPEvent, error) {
	if p.PID <= 1 {
		return nil, nil
	}

	cmdLower := strings.ToLower(p.Cmdline)
	commLower := strings.ToLower(p.Comm)

	// Check if this process is an inspection or memory-scraping tool
	isScraper := strings.Contains(commLower, "gdb") ||
		strings.Contains(commLower, "strace") ||
		strings.Contains(commLower, "frida") ||
		strings.Contains(commLower, "procdump") ||
		strings.Contains(commLower, "scanmem") ||
		strings.Contains(cmdLower, "/mem") ||
		strings.Contains(cmdLower, "ptrace") ||
		strings.Contains(cmdLower, "process_vm_readv")

	if !isScraper {
		return nil, nil
	}

	m.mu.RLock()
	protectedNamesCopy := make([]string, 0, len(m.protectedNames))
	for name := range m.protectedNames {
		protectedNamesCopy = append(protectedNamesCopy, name)
	}
	protectedPIDsCopy := make([]int, 0, len(m.protectedPIDs))
	for pid := range m.protectedPIDs {
		protectedPIDsCopy = append(protectedPIDsCopy, pid)
	}
	m.mu.RUnlock()

	// 1. Match against protected daemon names in cmdline / args
	for _, protectedName := range protectedNamesCopy {
		if strings.Contains(cmdLower, protectedName) {
			return m.InspectMemoryAccess(p.PID, p.Comm, 0, protectedName, false)
		}
	}

	// 2. Match against protected PIDs explicitly targeted (e.g. gdb -p 1234, strace -p 1234)
	for _, protectedPID := range protectedPIDsCopy {
		pidStr := strconv.Itoa(protectedPID)
		if strings.Contains(cmdLower, pidStr) {
			return m.InspectMemoryAccess(p.PID, p.Comm, protectedPID, "protected-vault", false)
		}
	}

	return nil, nil
}

// ValidateSSRFDestination inspects a target URL or destination string for cloud metadata, link-local or loopback evasion.
func ValidateSSRFDestination(targetURL string) error {
	raw := strings.TrimSpace(targetURL)
	if raw == "" {
		return NewMorpheusValidationException("empty destination url", nil)
	}

	parsed, err := url.Parse(raw)
	host := raw
	if err == nil && parsed.Host != "" {
		host = parsed.Hostname()
	} else if strings.Contains(host, ":") && !strings.Contains(host, "/") {
		if h, _, splitErr := net.SplitHostPort(host); splitErr == nil {
			host = h
		}
	}

	hostLower := strings.ToLower(strings.Trim(strings.TrimSpace(host), "[]"))

	// Block Loopback hostnames
	if hostLower == "localhost" || hostLower == "localhost.localdomain" || hostLower == "ip6-localhost" || hostLower == "ip6-loopback" {
		return NewMorpheusSecurityException("prohibited loopback destination", nil)
	}

	// Block Cloud Metadata hostnames
	forbiddenHosts := []string{
		"169.254.169.254",
		"169.254.169.123",
		"metadata.google.internal",
		"metadata.goog",
		"instance-data",
		"100.100.100.200", // Alibaba Cloud IMDS
		"168.63.129.16",   // Azure WireServer
		"fd00:ec2::254",   // AWS IMDSv2 IPv6
	}

	for _, fh := range forbiddenHosts {
		if subtle.ConstantTimeCompare([]byte(hostLower), []byte(fh)) == 1 {
			return NewMorpheusSecurityException(fmt.Sprintf("prohibited cloud metadata destination: %s", host), nil)
		}
	}

	// Check if IP is Link-Local, Metadata, or Loopback with normalization for alternative encodings (hex/oct/dword)
	if ip := parseNormalizedIP(hostLower); ip != nil {
		if ip.IsLoopback() || (ip.To4() != nil && ip.To4()[0] == 127) {
			return NewMorpheusSecurityException("prohibited loopback destination", nil)
		}
		if IsCloudMetadataDestination(ip) {
			return NewMorpheusSecurityException("destination resolves to link-local metadata address", nil)
		}
	}

	return nil
}

// parseNormalizedIP parses standard dotted, integer, hex, octal and bracketed IP representations.
func parseNormalizedIP(host string) net.IP {
	clean := strings.Trim(strings.TrimSpace(host), "[]")
	if clean == "" {
		return nil
	}
	if ip := net.ParseIP(clean); ip != nil {
		return ip
	}
	// Parse 32-bit integer (decimal, hex e.g. 0xa9fea9fe, or octal e.g. 025177524776)
	if val, err := strconv.ParseUint(clean, 0, 32); err == nil {
		return net.IPv4(byte(val>>24), byte(val>>16), byte(val>>8), byte(val))
	}
	// Parse dotted notation with octal/hex components (e.g. 0251.0376.0251.0376)
	parts := strings.Split(clean, ".")
	if len(parts) == 4 {
		var octets [4]byte
		valid := true
		for i, part := range parts {
			partVal, err := strconv.ParseUint(part, 0, 8)
			if err != nil {
				valid = false
				break
			}
			octets[i] = byte(partVal)
		}
		if valid {
			return net.IPv4(octets[0], octets[1], octets[2], octets[3])
		}
	}
	return nil
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
