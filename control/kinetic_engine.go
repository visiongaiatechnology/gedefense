package main

import (
	"fmt"
	"net"
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
