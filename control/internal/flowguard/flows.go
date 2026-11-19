package flowguard

import (
	"sort"
	"sync"
	"time"
)

// Publish limits from the blueprint.
const (
	MaxTrackedFlowsLimit = 65536
	MinTrackedFlows      = 256
	HandshakeRingLimit   = 256
	EventRingLimit       = 256
	FlowListLimit        = 512
)

// FlowEntry is the tracked per-peer flow state.
type FlowEntry struct {
	Sample        FlowSample
	Verdict       string
	FirstSeen     time.Time
	LastSeen      time.Time
	Matches       int
	ThrottleUntil time.Time
	// Throttled marks a flow for which a throttle plan was emitted.
	Throttled bool
}

// FlowTable is a bounded LRU keyed on peer+port. It never grows past MaxFlows;
// the least recently seen entry is evicted, which is safe because the counters
// are re-read from the kernel on the next snapshot.
type FlowTable struct {
	mu       sync.Mutex
	maxFlows int
	flows    map[string]*FlowEntry
	now      func() time.Time
}

// NewFlowTable constructs the bounded table.
func NewFlowTable(maxFlows int, now func() time.Time) *FlowTable {
	if maxFlows < MinTrackedFlows {
		maxFlows = MinTrackedFlows
	}
	if maxFlows > MaxTrackedFlowsLimit {
		maxFlows = MaxTrackedFlowsLimit
	}
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	return &FlowTable{maxFlows: maxFlows, flows: make(map[string]*FlowEntry, 64), now: now}
}

// MaxFlows reports the configured capacity.
func (t *FlowTable) MaxFlows() int {
	if t == nil {
		return 0
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.maxFlows
}

func flowKey(peer string, port uint16) string {
	return peer + "|" + itoaUint32(uint32(port))
}

// Update applies one kernel snapshot to the table and returns the entries that
// changed verdict ordering (newest first is not needed; callers snapshot).
func (t *FlowTable) Update(samples []FlowSample, predicate Predicate) {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	at := t.now()
	for _, sample := range samples {
		if sample.Peer == "" {
			continue
		}
		key := flowKey(sample.Peer, sample.Port)
		entry, exists := t.flows[key]
		if !exists {
			if len(t.flows) >= t.maxFlows {
				t.evictOldestLocked()
			}
			entry = &FlowEntry{FirstSeen: at, Sample: sample}
			t.flows[key] = entry
		}
		entry.Sample = sample
		entry.LastSeen = at
		matched := false
		_, matched = Evaluate(predicate, sample)
		if matched {
			entry.Matches++
		} else {
			entry.Matches = 0
		}
		entry.Verdict = ClassifyFlow(predicate, sample, matched)
	}
}

// evictOldestLocked removes the entry with the oldest LastSeen.
func (t *FlowTable) evictOldestLocked() {
	var oldestKey string
	var oldestTime time.Time
	for key, entry := range t.flows {
		if oldestKey == "" || entry.LastSeen.Before(oldestTime) {
			oldestKey, oldestTime = key, entry.LastSeen
		}
	}
	if oldestKey != "" {
		delete(t.flows, oldestKey)
	}
}

// Snapshot returns the tracked flows ordered by peer then port. The list is
// bounded to FlowListLimit; the budget reports the true table size.
func (t *FlowTable) Snapshot(limit int) ([]FlowEntry, int) {
	if t == nil {
		return []FlowEntry{}, 0
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if limit <= 0 || limit > FlowListLimit {
		limit = FlowListLimit
	}
	entries := make([]FlowEntry, 0, len(t.flows))
	for _, entry := range t.flows {
		copy := *entry
		entries = append(entries, copy)
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].Sample.Peer != entries[j].Sample.Peer {
			return entries[i].Sample.Peer < entries[j].Sample.Peer
		}
		return entries[i].Sample.Port < entries[j].Sample.Port
	})
	if len(entries) > limit {
		entries = entries[:limit]
	}
	return entries, len(t.flows)
}

// itoaUint32 is a tiny local converter for the flow key.
func itoaUint32(value uint32) string {
	if value == 0 {
		return "0"
	}
	var buffer [10]byte
	index := len(buffer)
	for value > 0 {
		index--
		buffer[index] = byte('0' + value%10)
		value /= 10
	}
	return string(buffer[index:])
}
