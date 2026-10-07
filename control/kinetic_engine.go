package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"
)

// IngressPacket represents minimal, verified network packet metadata.
type IngressPacket struct {
	Family       uint8     `json:"family"`   // 4 or 6
	Protocol     uint8     `json:"protocol"` // 6 (TCP), 17 (UDP), 1 (ICMP), 58 (ICMPv6)
	SrcIP        net.IP    `json:"src_ip"`
	DstIP        net.IP    `json:"dst_ip"`
	SrcPort      uint16    `json:"src_port"`
	DstPort      uint16    `json:"dst_port"`
	TCPFlags     uint8     `json:"tcp_flags"`
	AttemptCount uint32    `json:"attempt_count"` // exact kernel connection/activity attempts in this sample
	Packets      uint32    `json:"packets"`
	SYNCount     uint32    `json:"syn_count"`
	ACKCount     uint32    `json:"ack_count"`
	Bytes        uint32    `json:"bytes"`
	Timestamp    time.Time `json:"timestamp"`
	WindowEpoch  uint64    `json:"window_epoch,omitempty"` // monotonic kernel second for exact 1s grouping
}

// IPTrackingBucket maintains bounded sliding window counters for a single source IP.
type IPTrackingBucket struct {
	SrcIP           net.IP
	IsV6            bool
	Hits            int // raw observed packet delta for operator visibility
	Attempts        int // connection/activity attempts used by aggressive rules
	Attempts1m      int
	WindowHits      int
	Velocity1s      int
	CurrentSecEpoch int64
	LastSeen        time.Time
	FirstSeen       time.Time
	PortsSeen       map[uint16]bool
	PortAttempts    map[uint16]uint16
	SYNCount        int
	ACKCount        int
	SYN1m           int
	ACK1m           int
	MalformedCount  int
	Score           int
	LastStrikeRule  string
	LastStrikeAt    time.Time
	RuleLastSeen    map[string]time.Time
	CurrentMinute   int64
	LastWindowEpoch int64
	Hits1m          int
	FiveMinEpochs   [13]int64
	FiveMinHits     [13]uint16
	FiveMinAttempts [13]uint16
	FiveMinSYNs     [13]uint16
	FiveMinACKs     [13]uint16
	HourlyEpochs    [25]int64
	HourlyHits      [25]uint32
	HourlyAttempts  [25]uint32
	HourlySYNs      [25]uint32
	HourlyACKs      [25]uint32
}

// SubnetV4Bucket aggregates traffic across an IPv4 /24 network block.
type SubnetV4Bucket struct {
	Subnet        string
	AggregateHits int
	ActiveIPs     map[string]time.Time
	WindowStart   time.Time
	LastSeen      time.Time
	LastStrikeAt  time.Time
}

// WideV4Bucket aggregates traffic across an IPv4 /16 macro sector.
type WideV4Bucket struct {
	Sector        string
	AggregateHits int
	ActiveIPs     map[string]time.Time
	WindowStart   time.Time
	LastSeen      time.Time
	LastStrikeAt  time.Time
}

// SubnetV6Bucket aggregates traffic across an IPv6 /64 network block.
type SubnetV6Bucket struct {
	Subnet        string
	AggregateHits int
	ActiveIPs     map[string]time.Time
	WindowStart   time.Time
	LastSeen      time.Time
	LastStrikeAt  time.Time
}

// KineticEngine orchestrates sliding window ingestion, subnet aggregation, and rule evaluation.
type KineticEngine struct {
	mu                      sync.RWMutex
	cfg                     KineticConfig
	state                   *State
	rules                   *KineticRuleRegistry
	eventQueue              *BoundedEventQueue
	ipBuckets               map[string]*IPTrackingBucket
	subnetV4Buckets         map[string]*SubnetV4Bucket
	wideV4Buckets           map[string]*WideV4Bucket
	subnetV6Buckets         map[string]*SubnetV6Bucket
	allowlistNets           []*net.IPNet
	allowlistIPs            map[string]bool
	threatBlock             *ThreatIndex
	threatCorrelate         *ThreatIndex
	threatAnnotate          *ThreatIndex
	hitsTotal               uint64
	velocityBurstsTotal     uint64
	portscansTotal          uint64
	subnetStrikesTotal      uint64
	l7StrikesTotal          uint64
	trackingDropsTotal      uint64
	trackingEvictionsTotal  uint64
	aggregateEvictionsTotal uint64
	maxSubnetBuckets        int
	maxWideBuckets          int
	bansEnforcedTotal       uint64
	bansExpiredTotal        uint64
	tokenBucketAvailable    int
	tokenBucketLastSec      int64
	startedAt               time.Time
	secondHistory           [60]KineticTrafficBucket
	minuteHistory           [1441]KineticTrafficBucket
}

// NewKineticEngine instantiates a bounded Kinetic detection and aggregation engine.
func NewKineticEngine(cfg KineticConfig, state *State, rules *KineticRuleRegistry, allowlist []string) *KineticEngine {
	if cfg.MaxTrackingIPs <= 0 {
		cfg.MaxTrackingIPs = 65536
	}
	if cfg.IPThreshold <= 0 {
		cfg.IPThreshold = 35
	}
	if cfg.VelocityLimit <= 0 {
		cfg.VelocityLimit = 15
	}
	if cfg.RangeThreshold <= 0 {
		cfg.RangeThreshold = 45
	}
	if cfg.IPv6SubThreshold <= 0 {
		cfg.IPv6SubThreshold = 55
	}
	if cfg.WideRangeThreshold <= 0 {
		cfg.WideRangeThreshold = 77
	}
	if cfg.PortscanThreshold <= 0 {
		cfg.PortscanThreshold = 5
	}
	if cfg.SYNThreshold <= 0 {
		cfg.SYNThreshold = 25
	}
	if cfg.SYNAckRatio <= 0 {
		cfg.SYNAckRatio = 4
	}
	if cfg.LowSlowMinSeconds <= 0 {
		cfg.LowSlowMinSeconds = 60
	}
	if cfg.SubnetMinSources <= 0 {
		cfg.SubnetMinSources = 2
	}
	if cfg.IPv6SubnetMinSources <= 0 {
		cfg.IPv6SubnetMinSources = 2
	}
	if cfg.WideMinSources <= 0 {
		cfg.WideMinSources = 4
	}
	if cfg.MaxStrikesPerSec <= 0 {
		cfg.MaxStrikesPerSec = 100
	}
	if cfg.BanTTLSeconds <= 0 {
		cfg.BanTTLSeconds = 86400
	}

	maxSubnetBuckets := boundedAggregateCapacity(cfg.MaxTrackingIPs, 4, 256, 16384)
	maxWideBuckets := boundedAggregateCapacity(cfg.MaxTrackingIPs, 16, 128, 4096)

	eng := &KineticEngine{
		cfg:                  cfg,
		state:                state,
		rules:                rules,
		eventQueue:           NewBoundedEventQueue(250),
		ipBuckets:            make(map[string]*IPTrackingBucket),
		subnetV4Buckets:      make(map[string]*SubnetV4Bucket),
		wideV4Buckets:        make(map[string]*WideV4Bucket),
		subnetV6Buckets:      make(map[string]*SubnetV6Bucket),
		maxSubnetBuckets:     maxSubnetBuckets,
		maxWideBuckets:       maxWideBuckets,
		allowlistIPs:         make(map[string]bool),
		tokenBucketAvailable: cfg.MaxStrikesPerSec,
		tokenBucketLastSec:   time.Now().Unix(),
		startedAt:            time.Now().UTC(),
	}

	eng.UpdateAllowlist(allowlist)
	return eng
}

func boundedAggregateCapacity(maxTracking, divisor, floor, ceiling int) int {
	if divisor <= 0 {
		divisor = 1
	}
	capacity := maxTracking / divisor
	if capacity < floor {
		capacity = floor
	}
	if capacity > ceiling {
		capacity = ceiling
	}
	return capacity
}

// SetThreatIntel attaches the live feed indexes used only for correlation and
// operator context. Feed membership can raise confidence, but it never bypasses
// the rule registry, response policy, management allowlist, or release gates.
func (e *KineticEngine) SetThreatIntel(block, correlate, annotate *ThreatIndex) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.threatBlock = block
	e.threatCorrelate = correlate
	e.threatAnnotate = annotate
}

// UpdateAllowlist recompiles management CIDRs and addresses (Rule 7).
func (e *KineticEngine) UpdateAllowlist(allowlist []string) {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.allowlistNets = nil
	e.allowlistIPs = make(map[string]bool)

	// Inherent unroutable and loopback addresses
	defaults := []string{"127.0.0.1", "::1", "0.0.0.0", "::"}
	for _, d := range defaults {
		e.allowlistIPs[d] = true
	}

	// Link-local IPv6 prefix
	_, linkLocalNet, _ := net.ParseCIDR("fe80::/10")
	if linkLocalNet != nil {
		e.allowlistNets = append(e.allowlistNets, linkLocalNet)
	}

	for _, item := range allowlist {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if strings.Contains(item, "/") {
			_, cidrNet, err := net.ParseCIDR(item)
			if err == nil && cidrNet != nil {
				e.allowlistNets = append(e.allowlistNets, cidrNet)
			}
		} else {
			ip := net.ParseIP(item)
			if ip != nil {
				e.allowlistIPs[ip.String()] = true
			}
		}
	}
}

// IsAllowlisted verifies whether an address is exempt from kinetic containment.
func (e *KineticEngine) IsAllowlisted(ip net.IP) bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.isAllowlistedLocked(ip)
}

func (e *KineticEngine) isAllowlistedLocked(ip net.IP) bool {
	if ip == nil {
		return true
	}
	ipStr := ip.String()
	if e.allowlistIPs[ipStr] {
		return true
	}
	for _, cidr := range e.allowlistNets {
		if cidr.Contains(ip) {
			return true
		}
	}
	return false
}

// ClassifyService categorizes destination port using the effective runtime service groups.
func (e *KineticEngine) ClassifyService(port uint16) (string, int) {
	e.mu.RLock()
	cfg := e.cfg
	e.mu.RUnlock()
	return classifyKineticService(cfg, port)
}

func classifyKineticService(cfg KineticConfig, port uint16) (string, int) {
	contains := func(values []uint16, target uint16) bool {
		for _, value := range values {
			if value == target {
				return true
			}
		}
		return false
	}
	switch {
	case contains(cfg.ServicePortsWeb, port):
		return "web", 1
	case contains(cfg.ServicePortsMail, port):
		return "mail", 2
	case contains(cfg.ServicePortsAdmin, port):
		if port == 22 || port == 2222 {
			return "ssh", 5
		}
		if port == 3306 || port == 5432 || port == 27017 || port == 6379 {
			return "database", 6
		}
		return "admin_panel", 5
	case port == 21:
		return "ftp", 4
	default:
		return "other", 3
	}
}

func kineticConfigFromRuntime(base KineticConfig, runtime KineticRuntimeSettings) KineticConfig {
	base.Enabled = runtime.Enabled
	base.EnforcementMode = runtime.EnforcementMode
	base.IPThreshold = runtime.IPThreshold
	base.VelocityLimit = runtime.VelocityLimit
	base.RangeThreshold = runtime.RangeThreshold
	base.IPv6SubThreshold = runtime.IPv6SubThreshold
	base.WideRangeThreshold = runtime.WideRangeThreshold
	base.PortscanThreshold = runtime.PortscanThreshold
	base.SYNThreshold = runtime.SYNThreshold
	base.SYNAckRatio = runtime.SYNAckRatio
	base.LowSlowMinSeconds = runtime.LowSlowMinSeconds
	base.SubnetMinSources = runtime.SubnetMinSources
	base.IPv6SubnetMinSources = runtime.IPv6SubnetMinSources
	base.WideMinSources = runtime.WideMinSources
	base.AutoContainSingleIP = runtime.AutoContainSingleIP
	base.AutoContainIPv4Subnet = runtime.AutoContainIPv4Subnet
	base.AutoContainIPv6Subnet = runtime.AutoContainIPv6Subnet
	base.MaxTrackingIPs = runtime.MaxTrackingIPs
	base.BanTTLSeconds = runtime.BanTTLSeconds
	base.MaxStrikesPerSec = runtime.MaxStrikesPerSec
	base.ServicePortsWeb = append([]uint16(nil), runtime.ServicePortsWeb...)
	base.ServicePortsMail = append([]uint16(nil), runtime.ServicePortsMail...)
	base.ServicePortsAdmin = append([]uint16(nil), runtime.ServicePortsAdmin...)
	return base
}

// UpdateConfig atomically swaps Kinetic detection thresholds and bounded capacities.
// Existing observations are preserved, but excess entries are evicted immediately
// when an operator lowers a configured bound.
func (e *KineticEngine) UpdateConfig(runtime KineticRuntimeSettings) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.cfg = kineticConfigFromRuntime(e.cfg, runtime)
	e.maxSubnetBuckets = boundedAggregateCapacity(e.cfg.MaxTrackingIPs, 4, 256, 16384)
	e.maxWideBuckets = boundedAggregateCapacity(e.cfg.MaxTrackingIPs, 16, 128, 4096)
	if e.tokenBucketAvailable > e.cfg.MaxStrikesPerSec {
		e.tokenBucketAvailable = e.cfg.MaxStrikesPerSec
	}
	for len(e.ipBuckets) > e.cfg.MaxTrackingIPs {
		e.evictStaleIPBucketLocked(time.Now().UTC())
	}
	for len(e.subnetV4Buckets) > e.maxSubnetBuckets {
		e.evictOldestSubnetV4Locked()
	}
	for len(e.subnetV6Buckets) > e.maxSubnetBuckets {
		e.evictOldestSubnetV6Locked()
	}
	for len(e.wideV4Buckets) > e.maxWideBuckets {
		e.evictOldestWideV4Locked()
	}
}

// SubnetKeys calculates /24, /16 (IPv4) or /64 (IPv6) representation.
func SubnetKeys(ip net.IP) (isV6 bool, subKey string, wideKey string) {
	if ip == nil {
		return false, "", ""
	}
	v4 := ip.To4()
	if v4 != nil {
		range24 := fmt.Sprintf("%d.%d.%d.0/24", v4[0], v4[1], v4[2])
		wide16 := fmt.Sprintf("%d.%d.0.0/16", v4[0], v4[1])
		return false, range24, wide16
	}

	// IPv6 /64 normalization
	if len(ip) == net.IPv6len {
		prefix := fmt.Sprintf("%02x%02x:%02x%02x:%02x%02x:%02x%02x::/64",
			ip[0], ip[1], ip[2], ip[3], ip[4], ip[5], ip[6], ip[7])
		return true, prefix, "IPv6_WIDE"
	}
	return false, "", ""
}

// IngestPacket processes incoming packet metadata and evaluates kinetic rules (Points 11–30).
func (e *KineticEngine) IngestPacket(pkt IngressPacket) []KineticEvent {
	e.mu.Lock()
	defer e.mu.Unlock()

	if !e.cfg.Enabled || pkt.SrcIP == nil || e.isAllowlistedLocked(pkt.SrcIP) {
		return nil
	}

	sampleCount := int(pkt.Packets)
	if sampleCount <= 0 {
		sampleCount = 1
	}
	e.hitsTotal += uint64(sampleCount)
	now := pkt.Timestamp
	if now.IsZero() {
		now = time.Now().UTC()
	}
	secEpoch := now.Unix()
	if pkt.WindowEpoch > 0 {
		secEpoch = int64(pkt.WindowEpoch)
	}
	ipKey := pkt.SrcIP.String()

	// 1. Manage IP Tracking Bucket
	bucket, exists := e.ipBuckets[ipKey]
	if !exists {
		if len(e.ipBuckets) >= e.cfg.MaxTrackingIPs {
			e.evictStaleIPBucketLocked(now)
			if len(e.ipBuckets) >= e.cfg.MaxTrackingIPs {
				e.trackingDropsTotal++
				return nil
			}
		}
		isV6, _, _ := SubnetKeys(pkt.SrcIP)
		bucket = &IPTrackingBucket{
			SrcIP:           append(net.IP(nil), pkt.SrcIP...),
			IsV6:            isV6,
			FirstSeen:       now,
			LastSeen:        now,
			PortsSeen:       make(map[uint16]bool),
			PortAttempts:    make(map[uint16]uint16),
			CurrentSecEpoch: secEpoch,
			CurrentMinute:   secEpoch / 60,
			RuleLastSeen:    make(map[string]time.Time),
		}
		e.ipBuckets[ipKey] = bucket
	}

	// Normalize exact SYN/ACK deltas before any window accounting. Kernel
	// aggregates are authoritative; TCP-flag inference is only safe for a true
	// single-packet synthetic/compatibility sample.
	synDelta := int(pkt.SYNCount)
	ackDelta := int(pkt.ACKCount)
	if pkt.Protocol == 6 && sampleCount == 1 {
		isSYN := (pkt.TCPFlags & 0x02) != 0
		isACK := (pkt.TCPFlags & 0x10) != 0
		if synDelta == 0 && isSYN && !isACK {
			synDelta = 1
		}
		if ackDelta == 0 && isACK {
			ackDelta = 1
		}
	}

	// Rules that model scans/rates count connection or protocol activity, not
	// every TCP data/ACK packet. Otherwise a normal HTTPS download would hit the
	// old 35-hit threshold in seconds. For TCP and neutral carry-over samples the
	// exact SYN delta is the connection-attempt signal; non-TCP keeps packet
	// activity as the bounded approximation.
	activityCount := int(pkt.AttemptCount)
	if pkt.WindowEpoch == 0 {
		// Synthetic/compatibility callers predate the explicit kernel activity
		// counter. Infer their semantics without weakening the authenticated IPC
		// contract used by production.
		activityCount = sampleCount
		if pkt.Protocol == 6 || pkt.Protocol == 0 {
			activityCount = synDelta
		}
	}
	if activityCount < 0 || activityCount > sampleCount {
		activityCount = 0
	}

	// Update the exact 1-second connection-attempt window. The monotonic
	// WindowEpoch supplied by the kernel keeps different kernel seconds separate
	// even when several IPC batches are drained in one userspace poll. TCP
	// ACK/data packets do not inflate connection velocity; non-TCP activity uses
	// packet delta as its bounded approximation.
	if bucket.CurrentSecEpoch != secEpoch {
		bucket.CurrentSecEpoch = secEpoch
		bucket.Velocity1s = 0
	}
	if synDelta > 0 {
		// Neutral carry-over events still carry exact SYN deltas and a kernel
		// window epoch, so they can contribute to the correct historical second
		// without borrowing protocol/flag metadata from the next packet.
		bucket.Velocity1s += synDelta
	} else if pkt.Protocol != 0 && pkt.Protocol != 6 {
		bucket.Velocity1s += sampleCount
	}
	bucket.Hits += sampleCount
	bucket.Attempts += activityCount
	bucket.WindowHits += sampleCount
	bucket.LastSeen = now
	e.recordLongWindowsLocked(bucket, secEpoch, sampleCount, activityCount, synDelta, ackDelta)
	e.recordTrafficHistoryLocked(secEpoch, sampleCount, activityCount, synDelta, ackDelta)
	bucket.SYNCount += synDelta
	bucket.ACKCount += ackDelta

	// Track destination port diversity only for connection/activity attempts.
	// Established TCP ACK/data traffic must not manufacture a scanner profile.
	// Both the distinct-port set and per-port attempt counters are bounded.
	if activityCount > 0 && pkt.DstPort > 0 {
		if bucket.PortsSeen[pkt.DstPort] || len(bucket.PortsSeen) < 64 {
			bucket.PortsSeen[pkt.DstPort] = true
			if current := bucket.PortAttempts[pkt.DstPort]; current < ^uint16(0) {
				add := activityCount
				remaining := int(^uint16(0) - current)
				if add > remaining {
					add = remaining
				}
				if add > 0 {
					bucket.PortAttempts[pkt.DstPort] = current + uint16(add)
				}
			}
		}
	}

	// Track packet-level TCP flags only when the sample actually identifies TCP.
	if pkt.Protocol == 6 {
		isSYN := (pkt.TCPFlags & 0x02) != 0
		isRST := (pkt.TCPFlags & 0x04) != 0
		isFIN := (pkt.TCPFlags & 0x01) != 0
		isPSH := (pkt.TCPFlags & 0x08) != 0
		isURG := (pkt.TCPFlags & 0x20) != 0

		// Detect illegal TCP flag combinations (Point 8 & 29). Aggregated
		// samples inherit the flags of their trigger packet, so cap this counter
		// to one observation per aggregate instead of multiplying weak evidence.
		if pkt.TCPFlags == 0 || (isSYN && isRST) || (isFIN && isPSH && isURG) {
			bucket.MalformedCount++
		}
	}

	// 2. Update Subnet Aggregation Buckets
	isV6, subKey, wideKey := SubnetKeys(pkt.SrcIP)
	if !isV6 && subKey != "" && activityCount > 0 {
		v4b, exists := e.subnetV4Buckets[subKey]
		if !exists {
			if len(e.subnetV4Buckets) >= e.maxSubnetBuckets {
				e.evictOldestSubnetV4Locked()
			}
			v4b = &SubnetV4Bucket{
				Subnet: subKey, ActiveIPs: make(map[string]time.Time), WindowStart: now,
			}
			e.subnetV4Buckets[subKey] = v4b
		}
		if v4b.WindowStart.IsZero() || now.Sub(v4b.WindowStart) >= 5*time.Minute {
			v4b.AggregateHits = 0
			v4b.ActiveIPs = make(map[string]time.Time)
			v4b.WindowStart = now
		}
		v4b.AggregateHits += activityCount
		v4b.LastSeen = now
		if len(v4b.ActiveIPs) < 256 {
			v4b.ActiveIPs[ipKey] = now
		}

		if wideKey != "" {
			wb, exists := e.wideV4Buckets[wideKey]
			if !exists {
				if len(e.wideV4Buckets) >= e.maxWideBuckets {
					e.evictOldestWideV4Locked()
				}
				wb = &WideV4Bucket{
					Sector: wideKey, ActiveIPs: make(map[string]time.Time), WindowStart: now,
				}
				e.wideV4Buckets[wideKey] = wb
			}
			if wb.WindowStart.IsZero() || now.Sub(wb.WindowStart) >= 15*time.Minute {
				wb.AggregateHits = 0
				wb.ActiveIPs = make(map[string]time.Time)
				wb.WindowStart = now
			}
			wb.AggregateHits += activityCount
			wb.LastSeen = now
			if len(wb.ActiveIPs) < 1024 {
				wb.ActiveIPs[ipKey] = now
			}
		}
	} else if isV6 && subKey != "" && activityCount > 0 {
		v6b, exists := e.subnetV6Buckets[subKey]
		if !exists {
			if len(e.subnetV6Buckets) >= e.maxSubnetBuckets {
				e.evictOldestSubnetV6Locked()
			}
			v6b = &SubnetV6Bucket{
				Subnet: subKey, ActiveIPs: make(map[string]time.Time), WindowStart: now,
			}
			e.subnetV6Buckets[subKey] = v6b
		}
		if v6b.WindowStart.IsZero() || now.Sub(v6b.WindowStart) >= 5*time.Minute {
			v6b.AggregateHits = 0
			v6b.ActiveIPs = make(map[string]time.Time)
			v6b.WindowStart = now
		}
		v6b.AggregateHits += activityCount
		v6b.LastSeen = now
		if len(v6b.ActiveIPs) < 256 {
			v6b.ActiveIPs[ipKey] = now
		}
	}

	// 3. Rule Evaluation Pipeline
	var generatedEvents []KineticEvent

	// Correlation signal: live Threat Intelligence membership. This signal is
	// deliberately non-destructive by itself; feed BLOCK prefixes are already
	// enforced by the feed manager in kernel maps, while correlate-only feeds
	// enrich the decision chain without becoming a second hidden block path.
	threatMatch := e.threatCorrelate != nil && e.threatCorrelate.ContainsString(ipKey)
	feedBlockMatch := e.threatBlock != nil && e.threatBlock.ContainsString(ipKey)
	if (threatMatch || feedBlockMatch) && e.ruleReadyLocked(bucket, "NET.INGRESS.THREAT_INTEL_MATCH", now) {
		decision := "Threat-intelligence correlate prefix matched ingress source"
		if feedBlockMatch {
			decision = "Threat-intelligence BLOCK prefix matched ingress source; kernel feed policy owns enforcement"
		}
		evt := e.createEventLocked("NET.INGRESS.THREAT_INTEL_MATCH", pkt, bucket, subKey, decision, 80)
		if evt.Metadata == nil {
			evt.Metadata = map[string]interface{}{}
		}
		evt.Metadata["feed_block_match"] = feedBlockMatch
		evt.Metadata["feed_correlate_match"] = threatMatch
		generatedEvents = append(generatedEvents, evt)
	}

	// Rule 1: NET.INGRESS.MALFORMED_TCP
	if bucket.MalformedCount >= 3 && e.ruleReadyLocked(bucket, "NET.INGRESS.MALFORMED_TCP", now) {
		evt := e.createEventLocked("NET.INGRESS.MALFORMED_TCP", pkt, bucket, subKey, "Illegal TCP flag combination (NULL, SYN-RST, or XMAS)", 80)
		generatedEvents = append(generatedEvents, evt)
	}

	// Rule 2: NET.INGRESS.IP_VELOCITY (Burst Limit)
	if bucket.Velocity1s >= e.cfg.VelocityLimit && e.ruleReadyLocked(bucket, "NET.INGRESS.IP_VELOCITY", now) {
		e.velocityBurstsTotal++
		evt := e.createEventLocked("NET.INGRESS.IP_VELOCITY", pkt, bucket, subKey, fmt.Sprintf("High velocity burst: %d hits/sec", bucket.Velocity1s), 85)
		generatedEvents = append(generatedEvents, evt)
	}

	// Rule 3: NET.INGRESS.SYN_FLOOD
	if bucket.SYN1m >= e.cfg.SYNThreshold && (bucket.ACK1m == 0 || bucket.SYN1m >= bucket.ACK1m*e.cfg.SYNAckRatio) && e.ruleReadyLocked(bucket, "NET.INGRESS.SYN_FLOOD", now) {
		evt := e.createEventLocked("NET.INGRESS.SYN_FLOOD", pkt, bucket, subKey, fmt.Sprintf("SYN flood detected: %d SYNs vs %d ACKs in current 1m window", bucket.SYN1m, bucket.ACK1m), 90)
		generatedEvents = append(generatedEvents, evt)
	}

	// Rule 4: fast and low-and-slow port scans. Port diversity is retained for
	// one hour in bounded source buckets so one probe every few minutes cannot
	// evade the old Punisher capability by merely slowing down.
	service, _ := classifyKineticService(e.cfg, pkt.DstPort)
	if len(bucket.PortsSeen) >= e.cfg.PortscanThreshold && now.Sub(bucket.FirstSeen) >= time.Duration(e.cfg.LowSlowMinSeconds)*time.Second && bucket.Velocity1s < maxInt(2, e.cfg.VelocityLimit/2) && e.ruleReadyLocked(bucket, "NET.INGRESS.LOW_SLOW_SCAN", now) {
		e.portscansTotal++
		evt := e.createEventLocked("NET.INGRESS.LOW_SLOW_SCAN", pkt, bucket, subKey, fmt.Sprintf("Low-and-slow scan: %d distinct ports across %s (%d hits/15m)", len(bucket.PortsSeen), now.Sub(bucket.FirstSeen).Round(time.Second), e.windowHitsLocked(bucket, 15*time.Minute)), 92)
		generatedEvents = append(generatedEvents, evt)
	} else if len(bucket.PortsSeen) >= e.cfg.PortscanThreshold && e.ruleReadyLocked(bucket, "NET.INGRESS.PORT_SCAN", now) {
		e.portscansTotal++
		evt := e.createEventLocked("NET.INGRESS.PORT_SCAN", pkt, bucket, subKey, fmt.Sprintf("Portscan detected: %d distinct ports probed", len(bucket.PortsSeen)), 95)
		generatedEvents = append(generatedEvents, evt)
	} else if (service == "database" || service == "admin_panel") && bucket.PortAttempts[pkt.DstPort] >= 3 && e.ruleReadyLocked(bucket, "NET.INGRESS.PORT_SCAN", now) {
		// Dark port instant strike on critical internal ports
		e.portscansTotal++
		evt := e.createEventLocked("NET.INGRESS.PORT_SCAN", pkt, bucket, subKey, fmt.Sprintf("Connection probe to protected service port %d (%s)", pkt.DstPort, service), 95)
		generatedEvents = append(generatedEvents, evt)
	}

	// Rule 5: NET.INGRESS.IP_RATE (Sustained rate limit)
	if bucket.Attempts1m >= e.cfg.IPThreshold && e.ruleReadyLocked(bucket, "NET.INGRESS.IP_RATE", now) {
		evt := e.createEventLocked("NET.INGRESS.IP_RATE", pkt, bucket, subKey, fmt.Sprintf("Single IP connection/activity rate threshold reached: %d attempts/1m (%d attempts lifetime)", bucket.Attempts1m, bucket.Attempts), 75)
		generatedEvents = append(generatedEvents, evt)
	}

	// Rule 6: NET.INGRESS.SUBNET_V4 (Coordinated /24 flood)
	if !isV6 && subKey != "" {
		v4b := e.subnetV4Buckets[subKey]
		if v4b != nil && v4b.AggregateHits >= e.cfg.RangeThreshold && len(v4b.ActiveIPs) >= e.cfg.SubnetMinSources && now.Sub(v4b.LastStrikeAt) >= 30*time.Second {
			v4b.LastStrikeAt = now
			e.subnetStrikesTotal++
			evt := KineticEvent{
				ID:         generateEventID(),
				Time:       now,
				Layer:      LayerIngressNetwork,
				Sensor:     "radix_subnet_aggregator",
				RuleID:     "NET.INGRESS.SUBNET_V4",
				Category:   "botnet_aggregation",
				Severity:   "high",
				Score:      100,
				Confidence: 0.95,
				SourceIP:   ipKey,
				Subnet:     subKey,
				Hits:       v4b.AggregateHits,
				Metadata: map[string]interface{}{
					"active_sources": len(v4b.ActiveIPs),
				},
				Action:   e.resolveAction("NET.INGRESS.SUBNET_V4"),
				Decision: fmt.Sprintf("Coordinated IPv4 /24 flood: %d hits across %d IPs", v4b.AggregateHits, len(v4b.ActiveIPs)),
			}
			evt.ComputeFingerprint()
			e.eventQueue.Push(evt)
			generatedEvents = append(generatedEvents, evt)
		}
	}

	// Rule 7: NET.INGRESS.SUBNET_V6 (Coordinated /64 IPv6 flood)
	if isV6 && subKey != "" {
		v6b := e.subnetV6Buckets[subKey]
		if v6b != nil && v6b.AggregateHits >= e.cfg.IPv6SubThreshold && len(v6b.ActiveIPs) >= e.cfg.IPv6SubnetMinSources && now.Sub(v6b.LastStrikeAt) >= 30*time.Second {
			v6b.LastStrikeAt = now
			e.subnetStrikesTotal++
			evt := KineticEvent{
				ID:         generateEventID(),
				Time:       now,
				Layer:      LayerIngressNetwork,
				Sensor:     "radix_subnet_aggregator",
				RuleID:     "NET.INGRESS.SUBNET_V6",
				Category:   "botnet_aggregation",
				Severity:   "high",
				Score:      100,
				Confidence: 0.95,
				SourceIP:   ipKey,
				Subnet:     subKey,
				Hits:       v6b.AggregateHits,
				Metadata: map[string]interface{}{
					"active_sources": len(v6b.ActiveIPs),
				},
				Action:   e.resolveAction("NET.INGRESS.SUBNET_V6"),
				Decision: fmt.Sprintf("Coordinated IPv6 /64 flood: %d hits across %d IPs", v6b.AggregateHits, len(v6b.ActiveIPs)),
			}
			evt.ComputeFingerprint()
			e.eventQueue.Push(evt)
			generatedEvents = append(generatedEvents, evt)
		}
	}

	// Rule 8: NET.INGRESS.WIDE_V4 (Campaign level macro /16 aggregation)
	if !isV6 && wideKey != "" {
		wb := e.wideV4Buckets[wideKey]
		if wb != nil && wb.AggregateHits >= e.cfg.WideRangeThreshold && len(wb.ActiveIPs) >= e.cfg.WideMinSources && now.Sub(wb.LastStrikeAt) >= 60*time.Second {
			wb.LastStrikeAt = now
			evt := KineticEvent{
				ID:         generateEventID(),
				Time:       now,
				Layer:      LayerIngressNetwork,
				Sensor:     "radix_subnet_aggregator",
				RuleID:     "NET.INGRESS.WIDE_V4",
				Category:   "botnet_aggregation",
				Severity:   "critical",
				Score:      120,
				Confidence: 0.90,
				SourceIP:   ipKey,
				Subnet:     wideKey,
				Hits:       wb.AggregateHits,
				Action:     "warn", // Wide /16 is correlation-only by default (Point 26)
				Decision:   fmt.Sprintf("Mass campaign IPv4 /16 sector surge: %d hits across %d IPs", wb.AggregateHits, len(wb.ActiveIPs)),
			}
			evt.ComputeFingerprint()
			e.eventQueue.Push(evt)
			generatedEvents = append(generatedEvents, evt)
		}
	}

	// Update telemetry in state
	e.syncTelemetryStateLocked()

	return generatedEvents
}

func (e *KineticEngine) createEventLocked(ruleID string, pkt IngressPacket, bucket *IPTrackingBucket, subnet string, decision string, score int) KineticEvent {
	now := pkt.Timestamp
	if now.IsZero() {
		now = time.Now().UTC()
	}

	bucket.LastStrikeRule = ruleID
	bucket.LastStrikeAt = now
	if bucket.RuleLastSeen == nil {
		bucket.RuleLastSeen = make(map[string]time.Time)
	}
	bucket.RuleLastSeen[ruleID] = now

	ruleDef, exists := e.rules.Get(ruleID)
	severity := "medium"
	layer := LayerIngressNetwork
	category := "ingress_threat"
	if exists {
		severity = ruleDef.Severity
		layer = ruleDef.Layer
		category = ruleDef.Category
		if ruleDef.DefaultScore > 0 {
			score = ruleDef.DefaultScore
		}
	}
	feedBlockMatch := e.threatBlock != nil && e.threatBlock.ContainsString(pkt.SrcIP.String())
	feedCorrelateMatch := e.threatCorrelate != nil && e.threatCorrelate.ContainsString(pkt.SrcIP.String())
	if ruleID != "NET.INGRESS.THREAT_INTEL_MATCH" && (feedBlockMatch || feedCorrelateMatch) {
		boost := 10
		if feedBlockMatch {
			boost = 20
		}
		score += boost
		if score > 180 {
			score = 180
		}
	}

	if score > bucket.Score {
		bucket.Score = score
	}
	action := e.resolveAction(ruleID)
	protocolStr := "other"
	switch pkt.Protocol {
	case 6:
		protocolStr = "tcp"
	case 17:
		protocolStr = "udp"
	case 1:
		protocolStr = "icmp"
	case 58:
		protocolStr = "icmpv6"
	}

	evt := KineticEvent{
		ID:            generateEventID(),
		Time:          now,
		Layer:         layer,
		Sensor:        "xdp_ingress",
		RuleID:        ruleID,
		Category:      category,
		Severity:      severity,
		Score:         score,
		Confidence:    0.95,
		SourceIP:      pkt.SrcIP.String(),
		DestinationIP: pkt.DstIP.String(),
		Port:          pkt.DstPort,
		Protocol:      protocolStr,
		Subnet:        subnet,
		Hits:          bucket.Hits,
		RatePerSec:    float64(bucket.Velocity1s),
		Action:        action,
		Decision:      decision,
	}
	if feedBlockMatch || feedCorrelateMatch {
		evt.Metadata = map[string]interface{}{
			"threat_intel_match":   true,
			"feed_block_match":     feedBlockMatch,
			"feed_correlate_match": feedCorrelateMatch,
		}
		evt.Confidence = 0.99
	}
	evt.ComputeFingerprint()
	e.eventQueue.Push(evt)

	// Propagate to global state events
	if e.state != nil {
		e.state.AddEvent(Event{
			ID:       evt.ID,
			Time:     evt.Time,
			Severity: evt.Severity,
			Kind:     "kinetic_strike",
			Source:   evt.Sensor,
			Message:  fmt.Sprintf("[%s] %s (IP: %s, Port: %d)", evt.RuleID, evt.Decision, evt.SourceIP, evt.Port),
			Target:   evt.SourceIP,
		})
	}

	return evt
}

func (e *KineticEngine) resolveAction(ruleID string) string {
	def, exists := e.rules.Get(ruleID)
	if !exists {
		return "track"
	}
	switch e.cfg.EnforcementMode {
	case "block":
		if def.BlockEligible {
			return "block"
		}
		if def.ContainEligible {
			return "contain"
		}
		return "warn"
	case "contain":
		if def.ContainEligible {
			return "contain"
		}
		return "warn"
	default:
		return "track"
	}
}

func (e *KineticEngine) ruleReadyLocked(bucket *IPTrackingBucket, ruleID string, now time.Time) bool {
	if bucket == nil {
		return false
	}
	if bucket.RuleLastSeen == nil {
		bucket.RuleLastSeen = make(map[string]time.Time)
	}
	last := bucket.RuleLastSeen[ruleID]
	return last.IsZero() || now.Sub(last) >= 15*time.Second
}

func (e *KineticEngine) recordLongWindowsLocked(bucket *IPTrackingBucket, windowEpoch int64, hits, attempts, syns, acks int) {
	if bucket == nil || hits <= 0 {
		return
	}
	minute := windowEpoch / 60
	if bucket.CurrentMinute != minute {
		bucket.CurrentMinute = minute
		bucket.Hits1m = 0
		bucket.Attempts1m = 0
		bucket.SYN1m = 0
		bucket.ACK1m = 0
	}
	bucket.Hits1m += hits
	bucket.Attempts1m += attempts
	bucket.SYN1m += syns
	bucket.ACK1m += acks

	bucket.LastWindowEpoch = windowEpoch
	five := windowEpoch / 300
	idx := positiveRingIndex(five, len(bucket.FiveMinHits))
	if bucket.FiveMinEpochs[idx] != five {
		bucket.FiveMinEpochs[idx] = five
		bucket.FiveMinHits[idx] = 0
		bucket.FiveMinAttempts[idx] = 0
		bucket.FiveMinSYNs[idx] = 0
		bucket.FiveMinACKs[idx] = 0
	}
	addUint16Saturating(&bucket.FiveMinHits[idx], hits)
	addUint16Saturating(&bucket.FiveMinAttempts[idx], attempts)
	addUint16Saturating(&bucket.FiveMinSYNs[idx], syns)
	addUint16Saturating(&bucket.FiveMinACKs[idx], acks)

	hour := windowEpoch / 3600
	hourIdx := positiveRingIndex(hour, len(bucket.HourlyHits))
	if bucket.HourlyEpochs[hourIdx] != hour {
		bucket.HourlyEpochs[hourIdx] = hour
		bucket.HourlyHits[hourIdx] = 0
		bucket.HourlyAttempts[hourIdx] = 0
		bucket.HourlySYNs[hourIdx] = 0
		bucket.HourlyACKs[hourIdx] = 0
	}
	addUint32Saturating(&bucket.HourlyHits[hourIdx], hits)
	addUint32Saturating(&bucket.HourlyAttempts[hourIdx], attempts)
	addUint32Saturating(&bucket.HourlySYNs[hourIdx], syns)
	addUint32Saturating(&bucket.HourlyACKs[hourIdx], acks)
}

func (e *KineticEngine) windowHitsLocked(bucket *IPTrackingBucket, window time.Duration) int {
	if bucket == nil || window <= 0 {
		return 0
	}
	if window <= time.Minute {
		return bucket.Hits1m
	}
	nowFive := bucket.LastWindowEpoch / 300
	if nowFive == 0 {
		nowFive = bucket.LastSeen.Unix() / 300
	}
	buckets := int((window + 5*time.Minute - 1) / (5 * time.Minute))
	if buckets > len(bucket.FiveMinHits) {
		buckets = len(bucket.FiveMinHits)
	}
	total := 0
	for i := range bucket.FiveMinHits {
		epoch := bucket.FiveMinEpochs[i]
		if epoch > 0 && nowFive-epoch >= 0 && nowFive-epoch < int64(buckets) {
			total += int(bucket.FiveMinHits[i])
		}
	}
	return total
}

func (e *KineticEngine) evictOldestSubnetV4Locked() {
	oldestKey := ""
	var oldest time.Time
	for key, bucket := range e.subnetV4Buckets {
		if oldestKey == "" || bucket.LastSeen.Before(oldest) {
			oldestKey, oldest = key, bucket.LastSeen
		}
	}
	if oldestKey != "" {
		delete(e.subnetV4Buckets, oldestKey)
		e.aggregateEvictionsTotal++
	}
}

func (e *KineticEngine) evictOldestSubnetV6Locked() {
	oldestKey := ""
	var oldest time.Time
	for key, bucket := range e.subnetV6Buckets {
		if oldestKey == "" || bucket.LastSeen.Before(oldest) {
			oldestKey, oldest = key, bucket.LastSeen
		}
	}
	if oldestKey != "" {
		delete(e.subnetV6Buckets, oldestKey)
		e.aggregateEvictionsTotal++
	}
}

func (e *KineticEngine) evictOldestWideV4Locked() {
	oldestKey := ""
	var oldest time.Time
	for key, bucket := range e.wideV4Buckets {
		if oldestKey == "" || bucket.LastSeen.Before(oldest) {
			oldestKey, oldest = key, bucket.LastSeen
		}
	}
	if oldestKey != "" {
		delete(e.wideV4Buckets, oldestKey)
		e.aggregateEvictionsTotal++
	}
}

func (e *KineticEngine) evictStaleIPBucketLocked(now time.Time) {
	oldestKey := ""
	var oldestTime time.Time

	for k, b := range e.ipBuckets {
		if oldestKey == "" || b.LastSeen.Before(oldestTime) {
			oldestKey = k
			oldestTime = b.LastSeen
		}
		// If entry is older than 60 seconds, evict immediately
		if now.Sub(b.LastSeen) > time.Hour {
			delete(e.ipBuckets, k)
			e.trackingEvictionsTotal++
			return
		}
	}

	if oldestKey != "" {
		delete(e.ipBuckets, oldestKey)
		e.trackingEvictionsTotal++
	}
}

// Sweep cleans up inactive buckets and syncs telemetry (Rule 3).
func (e *KineticEngine) Sweep(now time.Time) {
	e.mu.Lock()
	defer e.mu.Unlock()

	// 1. Sweep inactive IP tracking buckets (> 1h idle; bounded MaxTrackingIPs still caps cardinality)
	for k, b := range e.ipBuckets {
		if now.Sub(b.LastSeen) > time.Hour {
			delete(e.ipBuckets, k)
			e.trackingEvictionsTotal++
		}
	}

	// 2. Sweep inactive subnets (> 300s idle)
	for k, sb := range e.subnetV4Buckets {
		if now.Sub(sb.LastSeen) > 300*time.Second {
			delete(e.subnetV4Buckets, k)
		}
	}
	for k, sb := range e.subnetV6Buckets {
		if now.Sub(sb.LastSeen) > 300*time.Second {
			delete(e.subnetV6Buckets, k)
		}
	}
	for k, wb := range e.wideV4Buckets {
		if now.Sub(wb.LastSeen) > 300*time.Second {
			delete(e.wideV4Buckets, k)
		}
	}

	// 3. Reset token bucket tokens (Point 15)
	sec := now.Unix()
	if sec != e.tokenBucketLastSec {
		e.tokenBucketLastSec = sec
		e.tokenBucketAvailable = e.cfg.MaxStrikesPerSec
	}

	e.syncTelemetryStateLocked()
}

func (e *KineticEngine) syncTelemetryStateLocked() {
	if e.state == nil {
		return
	}

	e.state.UpdateKineticTelemetry(func(t *KineticTelemetry) {
		t.HitsTotal = e.hitsTotal
		t.VelocityBurstsTotal = e.velocityBurstsTotal
		t.PortscansTotal = e.portscansTotal
		t.SubnetStrikesTotal = e.subnetStrikesTotal
		t.L7StrikesTotal = e.l7StrikesTotal
		t.TrackingDropsTotal = e.trackingDropsTotal
		t.TrackingEvictionsTotal = e.trackingEvictionsTotal
		t.AggregateEvictionsTotal = e.aggregateEvictionsTotal
		t.ActiveTrackingIPs = len(e.ipBuckets)
		t.ActiveSubnetsV4 = len(e.subnetV4Buckets)
		t.ActiveSubnetsV6 = len(e.subnetV6Buckets)
		t.ActiveWideV4 = len(e.wideV4Buckets)
		t.TrackingCapacity = e.cfg.MaxTrackingIPs
	})
}

// SnapshotTelemetry returns a copy of current metrics.
func (e *KineticEngine) SnapshotTelemetry() KineticTelemetry {
	e.mu.RLock()
	defer e.mu.RUnlock()

	// Start from the shared State snapshot so sensor coverage and layer health set
	// by the production runtime are preserved. Recreating DefaultKineticTelemetry
	// here would incorrectly report the verified XDP channel as OFFLINE.
	base := DefaultKineticTelemetry()
	if e.state != nil {
		base = e.state.KineticTelemetry()
	}
	base.HitsTotal = e.hitsTotal
	base.VelocityBurstsTotal = e.velocityBurstsTotal
	base.PortscansTotal = e.portscansTotal
	base.SubnetStrikesTotal = e.subnetStrikesTotal
	base.L7StrikesTotal = e.l7StrikesTotal
	base.TrackingDropsTotal = e.trackingDropsTotal
	base.TrackingEvictionsTotal = e.trackingEvictionsTotal
	base.AggregateEvictionsTotal = e.aggregateEvictionsTotal
	base.ActiveTrackingIPs = len(e.ipBuckets)
	base.ActiveSubnetsV4 = len(e.subnetV4Buckets)
	base.ActiveSubnetsV6 = len(e.subnetV6Buckets)
	base.ActiveWideV4 = len(e.wideV4Buckets)
	base.TrackingCapacity = e.cfg.MaxTrackingIPs
	return base
}

// RecentEvents returns the snapshot of events from the bounded event queue.
func (e *KineticEngine) RecentEvents() ([]KineticEvent, uint64) {
	return e.eventQueue.Snapshot()
}

func generateEventID() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("kin-%d", time.Now().UnixNano())
	}
	return "kin-" + hex.EncodeToString(b)
}

// KineticSourceSnapshot is the bounded operator-facing state for one observed source.
type KineticSourceSnapshot struct {
	SourceIP       string                `json:"source_ip"`
	Family         uint8                 `json:"family"`
	State          string                `json:"state"`
	FirstSeen      time.Time             `json:"first_seen"`
	LastSeen       time.Time             `json:"last_seen"`
	Hits           int                   `json:"hits"`
	Hits1m         int                   `json:"hits_1m"`
	Attempts       int                   `json:"attempts"`
	Attempts1m     int                   `json:"attempts_1m"`
	Hits15m        int                   `json:"hits_15m"`
	Hits1h         int                   `json:"hits_1h"`
	RatePerSec     int                   `json:"rate_per_sec"`
	SYNs           int                   `json:"syns"`
	ACKs           int                   `json:"acks"`
	Ports          []uint16              `json:"ports"`
	PortActivity   []KineticPortActivity `json:"port_activity,omitempty"`
	Service        string                `json:"service,omitempty"`
	Score          int                   `json:"score"`
	LastRule       string                `json:"last_rule,omitempty"`
	Subnet         string                `json:"subnet,omitempty"`
	Blocked        bool                  `json:"blocked"`
	Window         string                `json:"window,omitempty"`
	WindowHits     int                   `json:"window_hits,omitempty"`
	WindowAttempts int                   `json:"window_attempts,omitempty"`
	WindowSYNs     int                   `json:"window_syns,omitempty"`
	WindowACKs     int                   `json:"window_acks,omitempty"`
	CountryCode    string                `json:"country_code,omitempty"`
	Country        string                `json:"country,omitempty"`
	ASN            string                `json:"asn,omitempty"`
	ASName         string                `json:"as_name,omitempty"`
	Latitude       *float64              `json:"latitude,omitempty"`
	Longitude      *float64              `json:"longitude,omitempty"`
}

// SourceSnapshot returns the hottest/recent tracked sources without exposing the
// internal maps to the web layer. Results are bounded and sorted deterministically.
func (e *KineticEngine) SourceSnapshot(limit int) []KineticSourceSnapshot {
	if limit <= 0 || limit > 250 {
		limit = 100
	}
	blocked := make(map[string]bool)
	if e.state != nil {
		for _, entry := range e.state.BlocksSnapshot() {
			if ip, _, err := net.ParseCIDR(entry.Target); err == nil && ip != nil {
				blocked[ip.String()] = true
				continue
			}
			if ip := net.ParseIP(entry.Target); ip != nil {
				blocked[ip.String()] = true
			}
		}
	}

	e.mu.RLock()
	defer e.mu.RUnlock()
	out := make([]KineticSourceSnapshot, 0, minInt(limit, len(e.ipBuckets)))
	for _, bucket := range e.ipBuckets {
		ports := make([]uint16, 0, len(bucket.PortsSeen))
		for port := range bucket.PortsSeen {
			ports = append(ports, port)
		}
		sort.Slice(ports, func(i, j int) bool { return ports[i] < ports[j] })
		if len(ports) > 16 {
			ports = ports[:16]
		}
		service := ""
		if len(ports) > 0 {
			service, _ = classifyKineticService(e.cfg, ports[len(ports)-1])
		}
		_, subnet, _ := SubnetKeys(bucket.SrcIP)
		ipKey := bucket.SrcIP.String()
		state := sourceState(bucket, blocked[ipKey] || (e.threatBlock != nil && e.threatBlock.ContainsString(ipKey)))
		family := uint8(4)
		if bucket.IsV6 {
			family = 6
		}
		out = append(out, KineticSourceSnapshot{
			SourceIP: ipKey, Family: family, State: state, FirstSeen: bucket.FirstSeen,
			LastSeen: bucket.LastSeen, Hits: bucket.Hits, Hits1m: bucket.Hits1m, Attempts: bucket.Attempts, Attempts1m: bucket.Attempts1m,
			Hits15m: e.windowHitsLocked(bucket, 15*time.Minute), Hits1h: e.windowHitsLocked(bucket, time.Hour), RatePerSec: bucket.Velocity1s,
			SYNs: bucket.SYNCount, ACKs: bucket.ACKCount, Ports: ports, Service: service,
			Score: bucket.Score, LastRule: bucket.LastStrikeRule, Subnet: subnet,
			// Enforcement has two paths - the management block ledger and the feed
			// block index the kernel is fed from - and the display must reflect both.
			// Reporting only the ledger hid every feed-driven drop.
			Blocked: blocked[ipKey] || (e.threatBlock != nil && e.threatBlock.ContainsString(ipKey)),
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Blocked != out[j].Blocked {
			return out[i].Blocked
		}
		if out[i].Score != out[j].Score {
			return out[i].Score > out[j].Score
		}
		if out[i].RatePerSec != out[j].RatePerSec {
			return out[i].RatePerSec > out[j].RatePerSec
		}
		return out[i].LastSeen.After(out[j].LastSeen)
	})
	if len(out) > limit {
		out = out[:limit]
	}
	return out
}

func sourceState(bucket *IPTrackingBucket, blocked bool) string {
	if blocked {
		return "BLOCKED"
	}
	switch bucket.LastStrikeRule {
	case "NET.INGRESS.PORT_SCAN", "NET.INGRESS.PORT_DIVERSITY", "NET.INGRESS.LOW_SLOW_SCAN":
		return "SCAN"
	case "NET.INGRESS.IP_VELOCITY", "NET.INGRESS.SYN_FLOOD":
		return "BURST"
	}
	if bucket.Score >= 95 {
		return "THREAT"
	}
	if bucket.Score >= 75 {
		return "SUSPICIOUS"
	}
	return "TRACKING"
}

// IngestTLSFindings correlates L7/TLS findings with recent ingress state and
// live threat intelligence. TLS findings may suggest network containment, but
// they can never authorize host-process termination.
func (e *KineticEngine) IngestTLSFindings(clientIP string, summary TLSClientHelloSummary, findings []L7Finding, now time.Time) []KineticEvent {
	if e == nil || len(findings) == 0 {
		return nil
	}
	ip := net.ParseIP(clientIP)
	if ip == nil {
		return nil
	}
	clientIP = ip.String()
	if now.IsZero() {
		now = time.Now().UTC()
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	allowlisted := e.isAllowlistedLocked(ip)
	_, subnet, _ := SubnetKeys(ip)
	bucket := e.ipBuckets[clientIP]
	recentIngress := bucket != nil && now.Sub(bucket.LastSeen) <= time.Minute && bucket.Score >= 65
	feedBlock := e.threatBlock != nil && e.threatBlock.ContainsString(clientIP)
	feedCorrelate := e.threatCorrelate != nil && e.threatCorrelate.ContainsString(clientIP)

	generated := make([]KineticEvent, 0, len(findings))
	for _, finding := range findings {
		def, known := e.rules.Get(finding.RuleID)
		if !known || def.Layer != LayerApplicationL7 {
			continue
		}
		score := finding.Score
		if score <= 0 {
			score = def.DefaultScore
		}
		metadata := map[string]interface{}{
			"l7_finding":  true,
			"l7_location": finding.Location,
		}
		if finding.EvidenceSHA256 != "" {
			metadata["evidence_sha256"] = finding.EvidenceSHA256
		}
		if finding.FingerprintType != "" && finding.Fingerprint != "" {
			metadata["fingerprint_type"] = finding.FingerprintType
			metadata["fingerprint"] = finding.Fingerprint
		}
		if recentIngress {
			score += 15
			metadata["recent_ingress_correlation"] = true
		}
		if feedCorrelate {
			score += 10
			metadata["feed_correlate_match"] = true
		}
		if feedBlock {
			score += 20
			metadata["feed_block_match"] = true
		}
		if score > 180 {
			score = 180
		}
		action := e.resolveAction(finding.RuleID)
		if allowlisted {
			action = "warn"
			metadata["suppressed_by_management_allowlist"] = true
		}
		confidence := float64(finding.Confidence) / 100.0
		if confidence <= 0 || confidence > 1 {
			confidence = 0.8
		}
		if (recentIngress || feedBlock || feedCorrelate) && confidence < 0.99 {
			confidence += 0.04
			if confidence > 0.99 {
				confidence = 0.99
			}
		}

		event := KineticEvent{
			ID:             generateEventID(),
			Time:           now,
			Layer:          LayerApplicationL7,
			Sensor:         "l7_tls_parser",
			RuleID:         finding.RuleID,
			Category:       def.Category,
			Severity:       def.Severity,
			Score:          score,
			Confidence:     confidence,
			SourceIP:       clientIP,
			Protocol:       "tls",
			Domain:         summary.SNI,
			JA3Fingerprint: summary.JA3Hash,
			Subnet:         subnet,
			Action:         action,
			Decision:       finding.Summary,
			Metadata:       metadata,
		}
		event.ComputeFingerprint()
		e.eventQueue.Push(event)
		e.l7StrikesTotal++
		generated = append(generated, event)
		if e.state != nil {
			e.state.AddEvent(Event{
				ID: event.ID, Time: event.Time, Severity: event.Severity, Kind: "kinetic.l7_signal",
				Source: event.Sensor, Message: fmt.Sprintf("[%s] %s (IP: %s)", event.RuleID, event.Decision, event.SourceIP), Target: event.SourceIP,
			})
		}
	}
	e.syncTelemetryStateLocked()
	return generated
}
