package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"sort"
	"time"
)

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
