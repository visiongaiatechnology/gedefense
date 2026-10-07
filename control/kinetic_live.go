package main

import (
	"math"
	"net"
	"sort"
	"strings"
	"time"
)

const kineticSourceRetention = time.Hour

// KineticTrafficBucket is a compact bounded rolling counter used only for
// operator-window metrics. It never stores payloads or unbounded source state.
type KineticTrafficBucket struct {
	Epoch    int64
	Hits     uint64
	Attempts uint64
	SYNs     uint64
	ACKs     uint64
}

// KineticWindowSpec is the canonical server-side definition of a live window.
type KineticWindowSpec struct {
	Name     string
	Duration time.Duration
}

// KineticTrafficWindow reports raw ingress activity for a selected window.
type KineticTrafficWindow struct {
	Name             string    `json:"name"`
	Seconds          int64     `json:"seconds"`
	GeneratedAt      time.Time `json:"generated_at"`
	Hits             uint64    `json:"hits"`
	Attempts         uint64    `json:"attempts"`
	SYNs             uint64    `json:"syns"`
	ACKs             uint64    `json:"acks"`
	BucketResolution string    `json:"bucket_resolution"`
	HistoryComplete  bool      `json:"history_complete"`
	RuntimeSeconds   int64     `json:"runtime_seconds"`
}

// KineticPortActivity gives bounded per-source context. Attempts are lifetime
// within the currently retained source bucket; window-scoped totals are carried
// separately by KineticSourceSnapshot.Window* fields.
type KineticPortActivity struct {
	Port     uint16 `json:"port"`
	Attempts uint16 `json:"attempts"`
	Service  string `json:"service,omitempty"`
}

// KineticSubnetAggregate is derived from the bounded source snapshot rather
// than exposing internal subnet maps directly to the web layer.
type KineticSubnetAggregate struct {
	Subnet         string `json:"subnet"`
	Family         uint8  `json:"family"`
	Sources        int    `json:"sources"`
	WindowHits     int    `json:"window_hits"`
	WindowAttempts int    `json:"window_attempts"`
	Blocked        int    `json:"blocked"`
	MaxScore       int    `json:"max_score"`
}

type KineticTopRule struct {
	RuleID string `json:"rule_id"`
	Count  int    `json:"count"`
}

type KineticTopPort struct {
	Port  uint16 `json:"port"`
	Count int    `json:"count"`
}

func parseKineticWindow(raw string) (KineticWindowSpec, bool) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", "live":
		return KineticWindowSpec{Name: "live", Duration: time.Minute}, true
	case "1m":
		return KineticWindowSpec{Name: "1m", Duration: time.Minute}, true
	case "5m":
		return KineticWindowSpec{Name: "5m", Duration: 5 * time.Minute}, true
	case "15m":
		return KineticWindowSpec{Name: "15m", Duration: 15 * time.Minute}, true
	case "1h":
		return KineticWindowSpec{Name: "1h", Duration: time.Hour}, true
	case "24h":
		return KineticWindowSpec{Name: "24h", Duration: 24 * time.Hour}, true
	default:
		return KineticWindowSpec{}, false
	}
}

func positiveRingIndex(epoch int64, size int) int {
	if size <= 0 {
		return 0
	}
	idx := epoch % int64(size)
	if idx < 0 {
		idx += int64(size)
	}
	return int(idx)
}

func addUint16Saturating(dst *uint16, value int) {
	if dst == nil || value <= 0 {
		return
	}
	remaining := int(^uint16(0) - *dst)
	if value > remaining {
		value = remaining
	}
	if value > 0 {
		*dst += uint16(value)
	}
}

func addUint32Saturating(dst *uint32, value int) {
	if dst == nil || value <= 0 {
		return
	}
	remaining := uint64(math.MaxUint32 - *dst)
	add := uint64(value)
	if add > remaining {
		add = remaining
	}
	*dst += uint32(add)
}

func (e *KineticEngine) recordTrafficHistoryLocked(secEpoch int64, hits, attempts, syns, acks int) {
	if secEpoch <= 0 || hits <= 0 {
		return
	}
	secIdx := positiveRingIndex(secEpoch, len(e.secondHistory))
	sec := &e.secondHistory[secIdx]
	if sec.Epoch != secEpoch {
		*sec = KineticTrafficBucket{Epoch: secEpoch}
	}
	sec.Hits += uint64(maxInt(hits, 0))
	sec.Attempts += uint64(maxInt(attempts, 0))
	sec.SYNs += uint64(maxInt(syns, 0))
	sec.ACKs += uint64(maxInt(acks, 0))

	minuteEpoch := secEpoch / 60
	minuteIdx := positiveRingIndex(minuteEpoch, len(e.minuteHistory))
	minute := &e.minuteHistory[minuteIdx]
	if minute.Epoch != minuteEpoch {
		*minute = KineticTrafficBucket{Epoch: minuteEpoch}
	}
	minute.Hits += uint64(maxInt(hits, 0))
	minute.Attempts += uint64(maxInt(attempts, 0))
	minute.SYNs += uint64(maxInt(syns, 0))
	minute.ACKs += uint64(maxInt(acks, 0))
}

func (e *KineticEngine) TrafficWindow(spec KineticWindowSpec, now time.Time) KineticTrafficWindow {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	e.mu.RLock()
	defer e.mu.RUnlock()
	out := KineticTrafficWindow{
		Name: spec.Name, Seconds: int64(spec.Duration / time.Second), GeneratedAt: now.UTC(),
		BucketResolution: "60s", RuntimeSeconds: int64(now.Sub(e.startedAt).Seconds()),
	}
	if out.RuntimeSeconds < 0 {
		out.RuntimeSeconds = 0
	}
	out.HistoryComplete = !e.startedAt.IsZero() && now.Sub(e.startedAt) >= spec.Duration

	if spec.Duration <= time.Minute {
		out.BucketResolution = "1s"
		cutoff := now.Unix() - int64(spec.Duration/time.Second) + 1
		for i := range e.secondHistory {
			b := e.secondHistory[i]
			if b.Epoch >= cutoff && b.Epoch <= now.Unix() {
				out.Hits += b.Hits
				out.Attempts += b.Attempts
				out.SYNs += b.SYNs
				out.ACKs += b.ACKs
			}
		}
		return out
	}

	cutoffUnix := now.Add(-spec.Duration).Unix()
	nowUnix := now.Unix()
	for i := range e.minuteHistory {
		b := e.minuteHistory[i]
		bucketStart := b.Epoch * 60
		bucketEnd := bucketStart + 59
		if b.Epoch > 0 && bucketEnd >= cutoffUnix && bucketStart <= nowUnix {
			out.Hits += b.Hits
			out.Attempts += b.Attempts
			out.SYNs += b.SYNs
			out.ACKs += b.ACKs
		}
	}
	return out
}

func (e *KineticEngine) sourceWindowCountsLocked(bucket *IPTrackingBucket, spec KineticWindowSpec, now time.Time) (hits, attempts, syns, acks int) {
	if bucket == nil || now.IsZero() || spec.Duration <= 0 {
		return
	}
	if now.Sub(bucket.LastSeen) > spec.Duration {
		return
	}
	if spec.Duration <= time.Minute {
		if bucket.CurrentMinute == now.Unix()/60 {
			return bucket.Hits1m, bucket.Attempts1m, bucket.SYN1m, bucket.ACK1m
		}
		return
	}
	if spec.Duration <= time.Hour {
		cutoffUnix := now.Add(-spec.Duration).Unix()
		nowUnix := now.Unix()
		for i := range bucket.FiveMinHits {
			epoch := bucket.FiveMinEpochs[i]
			bucketStart := epoch * 300
			bucketEnd := bucketStart + 299
			if epoch > 0 && bucketEnd >= cutoffUnix && bucketStart <= nowUnix {
				hits += int(bucket.FiveMinHits[i])
				attempts += int(bucket.FiveMinAttempts[i])
				syns += int(bucket.FiveMinSYNs[i])
				acks += int(bucket.FiveMinACKs[i])
			}
		}
		return
	}

	cutoffUnix := now.Add(-spec.Duration).Unix()
	nowUnix := now.Unix()
	for i := range bucket.HourlyHits {
		epoch := bucket.HourlyEpochs[i]
		bucketStart := epoch * 3600
		bucketEnd := bucketStart + 3599
		if epoch > 0 && bucketEnd >= cutoffUnix && bucketStart <= nowUnix {
			hits += int(bucket.HourlyHits[i])
			attempts += int(bucket.HourlyAttempts[i])
			syns += int(bucket.HourlySYNs[i])
			acks += int(bucket.HourlyACKs[i])
		}
	}
	return
}

func snapshotBlockMatchers(state *State) (map[string]bool, []*net.IPNet) {
	exact := make(map[string]bool)
	var nets []*net.IPNet
	if state == nil {
		return exact, nets
	}
	for _, entry := range state.BlocksSnapshot() {
		if ip, network, err := net.ParseCIDR(entry.Target); err == nil && ip != nil && network != nil {
			if ones, bits := network.Mask.Size(); ones == bits {
				exact[ip.String()] = true
			} else {
				nets = append(nets, network)
			}
			continue
		}
		if ip := net.ParseIP(entry.Target); ip != nil {
			exact[ip.String()] = true
		}
	}
	return exact, nets
}

func sourceBlocked(ip net.IP, exact map[string]bool, nets []*net.IPNet) bool {
	if ip == nil {
		return false
	}
	if exact[ip.String()] {
		return true
	}
	for _, network := range nets {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

// SourceSnapshotForWindow returns only sources active in the requested server
// window. The result is strictly bounded and carries explicit window counters.
func (e *KineticEngine) SourceSnapshotForWindow(limit int, spec KineticWindowSpec, now time.Time) []KineticSourceSnapshot {
	if limit <= 0 || limit > 250 {
		limit = 100
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	exact, nets := snapshotBlockMatchers(e.state)

	e.mu.RLock()
	defer e.mu.RUnlock()
	out := make([]KineticSourceSnapshot, 0, minInt(limit, len(e.ipBuckets)))
	for _, bucket := range e.ipBuckets {
		windowHits, windowAttempts, windowSYNs, windowACKs := e.sourceWindowCountsLocked(bucket, spec, now)
		if windowHits == 0 && now.Sub(bucket.LastSeen) > spec.Duration {
			continue
		}
		ports := make([]uint16, 0, len(bucket.PortsSeen))
		for port := range bucket.PortsSeen {
			ports = append(ports, port)
		}
		sort.Slice(ports, func(i, j int) bool { return ports[i] < ports[j] })
		if len(ports) > 16 {
			ports = ports[:16]
		}
		portActivity := make([]KineticPortActivity, 0, len(ports))
		for _, port := range ports {
			service, _ := classifyKineticService(e.cfg, port)
			portActivity = append(portActivity, KineticPortActivity{Port: port, Attempts: bucket.PortAttempts[port], Service: service})
		}
		service := ""
		if len(ports) > 0 {
			service, _ = classifyKineticService(e.cfg, ports[len(ports)-1])
		}
		_, subnet, _ := SubnetKeys(bucket.SrcIP)
		ipKey := bucket.SrcIP.String()
		blocked := sourceBlocked(bucket.SrcIP, exact, nets)
		family := uint8(4)
		if bucket.IsV6 {
			family = 6
		}
		out = append(out, KineticSourceSnapshot{
			SourceIP: ipKey, Family: family, State: sourceState(bucket, blocked), FirstSeen: bucket.FirstSeen,
			LastSeen: bucket.LastSeen, Hits: bucket.Hits, Hits1m: bucket.Hits1m, Attempts: bucket.Attempts, Attempts1m: bucket.Attempts1m,
			Hits15m: e.windowHitsLocked(bucket, 15*time.Minute), Hits1h: e.windowHitsLocked(bucket, time.Hour), RatePerSec: bucket.Velocity1s,
			SYNs: bucket.SYNCount, ACKs: bucket.ACKCount, Ports: ports, PortActivity: portActivity, Service: service,
			Score: bucket.Score, LastRule: bucket.LastStrikeRule, Subnet: subnet, Blocked: blocked,
			Window: spec.Name, WindowHits: windowHits, WindowAttempts: windowAttempts, WindowSYNs: windowSYNs, WindowACKs: windowACKs,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Blocked != out[j].Blocked {
			return out[i].Blocked
		}
		if out[i].Score != out[j].Score {
			return out[i].Score > out[j].Score
		}
		if out[i].WindowAttempts != out[j].WindowAttempts {
			return out[i].WindowAttempts > out[j].WindowAttempts
		}
		return out[i].LastSeen.After(out[j].LastSeen)
	})
	if len(out) > limit {
		out = out[:limit]
	}
	return out
}

func (e *KineticEngine) RecentEventsForWindow(spec KineticWindowSpec, now time.Time, limit int) ([]KineticEvent, uint64, bool) {
	if limit <= 0 || limit > 250 {
		limit = 100
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	all, drops := e.eventQueue.Snapshot()
	cutoff := now.Add(-spec.Duration)
	filtered := make([]KineticEvent, 0, minInt(limit, len(all)))
	for i := len(all) - 1; i >= 0; i-- {
		if all[i].Time.Before(cutoff) {
			continue
		}
		filtered = append(filtered, all[i])
		if len(filtered) >= limit {
			break
		}
	}
	for i, j := 0, len(filtered)-1; i < j; i, j = i+1, j-1 {
		filtered[i], filtered[j] = filtered[j], filtered[i]
	}
	complete := drops == 0
	if drops > 0 && len(all) > 0 {
		oldest := all[0].Time
		for i := 1; i < len(all); i++ {
			if all[i].Time.Before(oldest) {
				oldest = all[i].Time
			}
		}
		if !oldest.After(cutoff) {
			complete = true
		}
	}
	return filtered, drops, complete
}

func aggregateKineticSubnets(sources []KineticSourceSnapshot, limit int) []KineticSubnetAggregate {
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	bySubnet := make(map[string]*KineticSubnetAggregate)
	for _, src := range sources {
		if src.Subnet == "" {
			continue
		}
		a := bySubnet[src.Subnet]
		if a == nil {
			a = &KineticSubnetAggregate{Subnet: src.Subnet, Family: src.Family}
			bySubnet[src.Subnet] = a
		}
		a.Sources++
		a.WindowHits += src.WindowHits
		a.WindowAttempts += src.WindowAttempts
		if src.Blocked {
			a.Blocked++
		}
		if src.Score > a.MaxScore {
			a.MaxScore = src.Score
		}
	}
	out := make([]KineticSubnetAggregate, 0, len(bySubnet))
	for _, a := range bySubnet {
		out = append(out, *a)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].MaxScore != out[j].MaxScore {
			return out[i].MaxScore > out[j].MaxScore
		}
		if out[i].WindowAttempts != out[j].WindowAttempts {
			return out[i].WindowAttempts > out[j].WindowAttempts
		}
		return out[i].Subnet < out[j].Subnet
	})
	if len(out) > limit {
		out = out[:limit]
	}
	return out
}

func aggregateKineticRules(events []KineticEvent, limit int) []KineticTopRule {
	counts := make(map[string]int)
	for _, event := range events {
		if event.RuleID != "" {
			counts[event.RuleID]++
		}
	}
	out := make([]KineticTopRule, 0, len(counts))
	for rule, count := range counts {
		out = append(out, KineticTopRule{RuleID: rule, Count: count})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].RuleID < out[j].RuleID
	})
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out
}

func aggregateKineticPorts(events []KineticEvent, limit int) []KineticTopPort {
	counts := make(map[uint16]int)
	for _, event := range events {
		if event.Port > 0 {
			counts[event.Port]++
		}
	}
	out := make([]KineticTopPort, 0, len(counts))
	for port, count := range counts {
		out = append(out, KineticTopPort{Port: port, Count: count})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Port < out[j].Port
	})
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out
}

func kineticDecisions(events []KineticEvent, limit int) []KineticEvent {
	if limit <= 0 || limit > 100 {
		limit = 50
	}
	out := make([]KineticEvent, 0, minInt(limit, len(events)))
	for i := len(events) - 1; i >= 0; i-- {
		action := strings.ToLower(events[i].Action)
		if action != "contain" && action != "block" && action != "drop" {
			continue
		}
		out = append(out, events[i])
		if len(out) >= limit {
			break
		}
	}
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out
}
