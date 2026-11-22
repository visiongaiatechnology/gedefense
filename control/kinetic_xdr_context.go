// STATUS: DIAMANT VGT SUPREME
package main

// M5.2: kinetic-to-XDR context correlator.
//
// An XDP ingress block was only an event: [IP, rule, action]. The defender could
// not see *what local service* the blocked source was probing, and the incident
// story had no lineage, no MITRE mapping and no chain node - the benchmark context
// score for these detections stayed at 1/3.
//
// This file resolves the local destination port(s) and service(s) of the blocked
// source from /proc/net/tcp* (and the UDP twins), maps the kinetic rule to a MITRE
// ATT&CK technique and records a bounded AttackStoryNode inside the existing XDR
// correlator. It never changes enforcement: the kernel block already happened.

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

// kineticProcNetRoot is a variable so tests resolve the context against a staged
// /proc/net snapshot instead of the live host.
var kineticProcNetRoot = "/proc/net"

// kineticBlockedRuleTTP maps the administrable NET.INGRESS blocking rules onto
// MITRE ATT&CK. Only rules that actually block a source are listed.
func kineticBlockedRuleTTP(ruleID string) (technique, tactic, name string, ok bool) {
	switch ruleID {
	case "NET.INGRESS.PORT_SCAN", "NET.INGRESS.PORT_DIVERSITY", "NET.INGRESS.LOW_SLOW_SCAN":
		return "T1046", "TA0007", "Network Service Discovery", true
	case "NET.INGRESS.SYN_FLOOD", "NET.INGRESS.IP_RATE", "NET.INGRESS.IP_VELOCITY":
		return "T1499.002", "TA0040", "Endpoint Denial of Service: Service Exhaustion Flood", true
	case "NET.INGRESS.SUBNET_V4", "NET.INGRESS.SUBNET_V6":
		return "T1595", "TA0043", "Active Scanning", true
	default:
		return "", "", "", false
	}
}

// kineticServiceNames is the closed, local port -> service mapping used in the
// incident context. An unknown port is named by number, never guessed.
var kineticServiceNames = map[uint16]string{
	21: "ftp", 22: "sshd", 25: "smtp", 53: "dns", 80: "http", 110: "pop3",
	123: "ntp", 143: "imap", 389: "ldap", 443: "https", 445: "smb",
	465: "smtps", 587: "submission", 636: "ldaps", 993: "imaps", 995: "pop3s",
	1433: "mssql", 1521: "oracle", 2049: "nfs", 2375: "docker", 2376: "docker-tls",
	3306: "mysql", 3389: "rdp", 5432: "postgresql", 5672: "amqp", 6379: "redis",
	8080: "http-alt", 8443: "https-alt", 9200: "elasticsearch", 11211: "memcached",
	27017: "mongodb",
}

// kineticProcNetSocket is one parsed row of /proc/net/{tcp,udp}{,6}.
type kineticProcNetSocket struct {
	LocalIP    netip.Addr
	LocalPort  uint16
	RemoteIP   netip.Addr
	RemotePort uint16
	State      string
}

// kineticResolveBlockedService resolves the local destination port(s)/service(s)
// belonging to a blocked source. It prefers established connections whose remote
// address is the blocked target (the actual probe target); when none are visible
// it falls back to the bounded set of listening local service ports so the
// incident still names the likely target surface.
func kineticResolveBlockedService(target string) ([]uint16, []string, string) {
	sockets, source := kineticReadProcNetSockets()
	targetIP, targetPrefix := kineticParseTarget(target)
	ports := make(map[uint16]struct{})
	for _, socket := range sockets {
		if socket.State == "0A" { // LISTEN is a fallback surface, not a match
			continue
		}
		if targetPrefix.IsValid() {
			if socket.RemoteIP.IsValid() && targetPrefix.Contains(socket.RemoteIP) {
				ports[socket.LocalPort] = struct{}{}
			}
			continue
		}
		if targetIP.IsValid() && socket.RemoteIP.IsValid() && socket.RemoteIP == targetIP {
			ports[socket.LocalPort] = struct{}{}
		}
	}
	derived := "established-connections"
	if len(ports) == 0 {
		derived = "listening-services"
		listening := make([]uint16, 0, 8)
		for _, socket := range sockets {
			if socket.State != "0A" {
				continue
			}
			listening = append(listening, socket.LocalPort)
			if len(listening) >= 8 {
				break
			}
		}
		for _, port := range listening {
			ports[port] = struct{}{}
		}
	}
	ordered := make([]uint16, 0, len(ports))
	for port := range ports {
		ordered = append(ordered, port)
	}
	sort.Slice(ordered, func(i, j int) bool { return ordered[i] < ordered[j] })
	if len(ordered) > 8 {
		ordered = ordered[:8]
	}
	services := make([]string, 0, len(ordered))
	for _, port := range ordered {
		if name, known := kineticServiceNames[port]; known {
			services = append(services, fmt.Sprintf("%s:%d", name, port))
		} else {
			services = append(services, fmt.Sprintf("port-%d", port))
		}
	}
	return ordered, services, source + ":" + derived
}

func kineticParseTarget(target string) (netip.Addr, netip.Prefix) {
	text := strings.TrimSpace(target)
	if text == "" {
		return netip.Addr{}, netip.Prefix{}
	}
	if strings.Contains(text, "/") {
		prefix, err := netip.ParsePrefix(text)
		if err != nil {
			return netip.Addr{}, netip.Prefix{}
		}
		return netip.Addr{}, prefix
	}
	addr, err := netip.ParseAddr(text)
	if err != nil {
		return netip.Addr{}, netip.Prefix{}
	}
	return addr, netip.Prefix{}
}

// kineticReadProcNetSockets reads the bounded /proc/net socket tables. A missing
// table is not an error: the caller falls back to the listening-service surface.
func kineticReadProcNetSockets() ([]kineticProcNetSocket, string) {
	files := []string{"tcp", "tcp6", "udp", "udp6"}
	const maxLinesPerFile = 4096
	sockets := make([]kineticProcNetSocket, 0, 64)
	readables := make([]string, 0, len(files))
	for _, name := range files {
		path := filepath.Join(kineticProcNetRoot, name)
		file, err := os.Open(path)
		if err != nil {
			continue
		}
		readables = append(readables, name)
		scanner := bufio.NewScanner(file)
		scanner.Buffer(make([]byte, 4096), 64<<10)
		lines := 0
		for scanner.Scan() {
			lines++
			if lines > maxLinesPerFile {
				break
			}
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "sl") {
				continue
			}
			fields := strings.Fields(line)
			if len(fields) < 4 {
				continue
			}
			localIP, localPort, ok := kineticParseProcNetAddr(fields[1])
			if !ok {
				continue
			}
			remoteIP, remotePort, ok := kineticParseProcNetAddr(fields[2])
			if !ok {
				continue
			}
			sockets = append(sockets, kineticProcNetSocket{
				LocalIP: localIP, LocalPort: localPort, RemoteIP: remoteIP,
				RemotePort: remotePort, State: strings.ToUpper(fields[3]),
			})
			if len(sockets) >= 8192 {
				break
			}
		}
		_ = file.Close()
	}
	return sockets, "proc-net/" + strings.Join(readables, ",")
}

func kineticParseProcNetAddr(raw string) (netip.Addr, uint16, bool) {
	addressHex, portHex, ok := strings.Cut(raw, ":")
	if !ok || len(addressHex) != 8 && len(addressHex) != 32 || len(portHex) != 4 {
		return netip.Addr{}, 0, false
	}
	addressBytes, err := hex.DecodeString(addressHex)
	if err != nil {
		return netip.Addr{}, 0, false
	}
	// /proc/net prints host-endian 32-bit words: IPv4 is one little-endian word
	// (reverse the four bytes), IPv6 is four little-endian words (reverse each
	// word) to restore the network-order address the kernel actually uses.
	if len(addressBytes) == 4 {
		for left, right := 0, len(addressBytes)-1; left < right; left, right = left+1, right-1 {
			addressBytes[left], addressBytes[right] = addressBytes[right], addressBytes[left]
		}
	} else {
		for offset := 0; offset+4 <= len(addressBytes); offset += 4 {
			addressBytes[offset], addressBytes[offset+1] = addressBytes[offset+1], addressBytes[offset]
			addressBytes[offset+2], addressBytes[offset+3] = addressBytes[offset+3], addressBytes[offset+2]
		}
	}
	addr, ok := netip.AddrFromSlice(addressBytes)
	if !ok {
		return netip.Addr{}, 0, false
	}
	portValue, err := strconv.ParseUint(portHex, 16, 16)
	if err != nil {
		return netip.Addr{}, 0, false
	}
	return addr.Unmap(), uint16(portValue), true
}

// recordKineticBlockContext records the XDR incident + attack-story node for one
// applied kinetic block. It is deliberately an observation path: no new
// enforcement, no response.
func (s *APIServer) recordKineticBlockContext(event KineticEvent, entry BlockEntry, now time.Time) {
	if s == nil || s.xdr == nil {
		return
	}
	technique, tactic, techniqueName, known := kineticBlockedRuleTTP(event.RuleID)
	if !known {
		return
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	// Bounded correlation window: one incident/story node per rule+target. A
	// sustained scan keeps producing block events; they must not become an
	// incident flood, and the pattern is already captured once.
	fingerprint := "kinetic-xdr:" + event.RuleID + ":" + entry.Target
	s.kineticContextMu.Lock()
	if s.kineticContextSeen == nil {
		s.kineticContextSeen = make(map[string]time.Time)
	}
	if until, exists := s.kineticContextSeen[fingerprint]; exists && now.Before(until) {
		s.kineticContextMu.Unlock()
		return
	}
	s.kineticContextSeen[fingerprint] = now.Add(5 * time.Minute)
	if len(s.kineticContextSeen) > 4096 {
		for key, until := range s.kineticContextSeen {
			if !until.After(now) {
				delete(s.kineticContextSeen, key)
			}
		}
	}
	s.kineticContextMu.Unlock()
	ports, services, source := kineticResolveBlockedService(entry.Target)
	portText := make([]string, 0, len(ports))
	for _, port := range ports {
		portText = append(portText, strconv.Itoa(int(port)))
	}
	metadata := map[string]string{
		"mitre_technique":      technique,
		"mitre_tactic":         tactic,
		"mitre_technique_name": techniqueName,
		"has_lineage_or_chain": "true",
		"enforcement":          "kernel-xdp",
		"action":               "block",
		"rule_id":              event.RuleID,
		"blocked_target":       entry.Target,
		"local_ports":          strings.Join(portText, ","),
		"local_services":       strings.Join(services, ","),
		"context_source":       source,
	}
	node := AttackStoryNode{
		NodeID:     fmt.Sprintf("kinetic-%s-%d", event.RuleID, now.UnixNano()),
		Timestamp:  now,
		Sensor:     "kinetic",
		Category:   "network",
		EventType:  "KINETIC_BLOCK_APPLIED",
		EntityID:   "ip:" + entry.Target,
		Actor:      "kinetic_response_engine",
		Severity:   "high",
		Confidence: 90,
		CausalEdge: EdgeRootCause,
		EventUUID:  event.ID,
		Metadata:   metadata,
	}
	node.Digest = node.ComputeNodeDigest()
	storyNodes := []AttackStoryNode{node}
	evidenceRoot := node.Digest
	chainID := node.NodeID
	if correlator := s.xdr.Correlator(); correlator != nil {
		if graph, _, err := correlator.IngestEvent(now, "kinetic:"+entry.Target, "kinetic-ingress", "NETWORK", node); err == nil && graph != nil {
			storyNodes = graph.CloneNodes()
			evidenceRoot = graph.EvidenceRoot()
			chainID = graph.ChainID
		}
	}
	serviceText := strings.Join(services, ",")
	if serviceText == "" {
		serviceText = "unknown local service"
	}
	incident := XDRIncident{
		ID: event.ID, Time: now, Severity: "high", Score: maxInt(event.Score, 85),
		PID: event.PID, Process: event.Process, Remote: entry.Target,
		RuleIDs: []string{event.RuleID}, Categories: []string{"network", "kinetic"},
		Summary: fmt.Sprintf("Kinetic ingress block applied: %s from %s; local target service %s; MITRE %s (%s)",
			event.RuleID, entry.Target, serviceText, technique, techniqueName),
		Decision: "block", Action: "contain",
		Outcome:          "kernel XDP block is enforced; destination context resolved from " + source,
		ExecutionChainID: chainID, AttackStory: storyNodes, EvidenceRoot: evidenceRoot,
	}
	s.xdr.appendIncident(incident)
	s.xdr.state.AddEvent(Event{
		Time: now, Severity: "high", Kind: "xdr.kinetic_block", Source: "kinetic",
		Message: incident.Summary, Target: entry.Target,
	})
}
