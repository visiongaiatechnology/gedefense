package workerguard

import (
	"strings"
	"sync"
	"time"
)

// DefaultWindowSeconds and DefaultThreshold mirror the administrable defaults.
const (
	DefaultWindowSeconds = 60
	DefaultThreshold     = 3
	MaxPeersPerStorm     = 8
	maxStormsRetained    = 32
)

// Config bounds the correlation window.
type Config struct {
	Threshold      int
	WindowSeconds  int
	CorrelatePeers bool
	// Now is injected so the window arithmetic is deterministic in tests.
	Now func() time.Time
}

// NormalizeConfig fills the compiled-in defaults for zero values.
func NormalizeConfig(in Config) Config {
	out := in
	if out.Threshold < 2 {
		out.Threshold = DefaultThreshold
	}
	if out.Threshold > 100 {
		out.Threshold = 100
	}
	if out.WindowSeconds < 10 {
		out.WindowSeconds = DefaultWindowSeconds
	}
	if out.WindowSeconds > 600 {
		out.WindowSeconds = 600
	}
	if out.Now == nil {
		out.Now = func() time.Time { return time.Now().UTC() }
	}
	return out
}

// Outcome is the decision the correlator returns for one crash.
//
// Audit is true for every accepted fatal worker crash: the operator sees one
// medium event per crash. Storm is non-nil only when the threshold was reached
// and the incident has not already been recorded for this comm+window, which is
// what keeps one bad worker from opening a new critical incident every crash.
type Outcome struct {
	Audit    bool
	Severity string
	Storm    *Storm
}

// Correlator is the pure crash-correlation state machine. It is safe for
// concurrent use; the source goroutines call Observe.
type Correlator struct {
	mu  sync.Mutex
	cfg Config
	// buckets holds the crash timestamps per comm+uid inside the current window.
	buckets map[string][]time.Time
	// storms is the bounded recent-storm ring for the status payload.
	storms []Storm
	// lastStorm suppresses a duplicate critical incident for the same key inside
	// one window.
	lastStorm map[string]time.Time
	counters  Counters
}

// NewCorrelator constructs the correlation state machine.
func NewCorrelator(cfg Config) *Correlator {
	return &Correlator{
		cfg:       NormalizeConfig(cfg),
		buckets:   make(map[string][]time.Time, 8),
		lastStorm: make(map[string]time.Time, 8),
		storms:    make([]Storm, 0, 4),
	}
}

// CounterSnapshot returns a copy of the counters.
func (c *Correlator) CounterSnapshot() Counters {
	if c == nil {
		return Counters{}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.counters
}

// RecentlyStorms returns the bounded storm history, newest first.
func (c *Correlator) RecentStorms(limit int) []Storm {
	if c == nil {
		return []Storm{}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if limit <= 0 || limit > len(c.storms) {
		limit = len(c.storms)
	}
	out := make([]Storm, 0, limit)
	for index := len(c.storms) - 1; index >= 0 && len(out) < limit; index-- {
		storm := c.storms[index]
		storm.Peers = append([]string(nil), storm.Peers...)
		out = append(out, storm)
	}
	return out
}

// Observe records one crash and returns the decision. The key is comm+uid, so
// two different pools crashing cannot be merged into one storm.
func (c *Correlator) Observe(event CrashEvent) Outcome {
	if c == nil {
		return Outcome{}
	}
	if !IsFatalSignal(event.Signal) {
		// A clean exit, SIGTERM/SIGKILL and a non-crash signal never enter the
		// window: a panel reload must not look like corruption.
		return Outcome{}
	}
	comm, err := NormalizeComm(event.Comm)
	if err != nil {
		return Outcome{}
	}
	at := event.At
	if at.IsZero() {
		at = c.cfg.Now()
	}
	at = at.UTC()
	window := time.Duration(c.cfg.WindowSeconds) * time.Second
	key := comm + "|" + itoa(event.UID)

	c.mu.Lock()
	defer c.mu.Unlock()
	c.counters.Events++
	c.pruneLocked(key, at, window)
	bucket := append(c.buckets[key], at)
	c.buckets[key] = bucket
	outcome := Outcome{Audit: true, Severity: "medium"}
	if len(bucket) < c.cfg.Threshold {
		return outcome
	}
	if last, seen := c.lastStorm[key]; seen && at.Sub(last) < window {
		// The storm is already recorded for this comm inside the window; the crash
		// still counts as audit evidence but must not open a second incident.
		return outcome
	}
	c.lastStorm[key] = at
	peers := make([]string, 0, 4)
	if c.cfg.CorrelatePeers && event.Peer != "" {
		peers = appendUnique(peers, event.Peer)
	}
	storm := Storm{
		ID:            "worker-storm-" + key + "@" + at.Format("20060102T150405Z"),
		Comm:          comm,
		UID:           event.UID,
		Crashes:       len(bucket),
		WindowSeconds: c.cfg.WindowSeconds,
		FirstAt:       bucket[0],
		LastAt:        at,
		Severity:      "critical",
		Peers:         peers,
	}
	c.storms = append(c.storms, storm)
	if len(c.storms) > maxStormsRetained {
		c.storms = append([]Storm(nil), c.storms[len(c.storms)-maxStormsRetained:]...)
	}
	c.counters.Storms++
	outcome.Severity = "critical"
	outcome.Storm = &storm
	return outcome
}

// AddStormPeer adds a correlated peer address to the most recent storm for a
// comm, bounded to MaxPeersPerStorm. It is used by the engine once the TLS
// sensor's recent peer snapshot is known.
func (c *Correlator) AddStormPeer(comm string, peer string) {
	if c == nil || peer == "" {
		return
	}
	comm, err := NormalizeComm(comm)
	if err != nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for index := len(c.storms) - 1; index >= 0; index-- {
		if c.storms[index].Comm != comm {
			continue
		}
		c.storms[index].Peers = appendUnique(c.storms[index].Peers, peer)
		return
	}
}

// pruneLocked drops timestamps older than the window for one key.
func (c *Correlator) pruneLocked(key string, now time.Time, window time.Duration) {
	bucket := c.buckets[key]
	cutoff := now.Add(-window)
	index := 0
	for index < len(bucket) && bucket[index].Before(cutoff) {
		index++
	}
	if index > 0 {
		bucket = append([]time.Time(nil), bucket[index:]...)
	}
	// Bound the per-key bucket even when an attacker can force crashes faster
	// than the threshold: the count and the incident do not need more samples.
	if len(bucket) > 4096 {
		bucket = bucket[len(bucket)-4096:]
	}
	c.buckets[key] = bucket
}

func appendUnique(values []string, value string) []string {
	if len(values) >= MaxPeersPerStorm {
		return values
	}
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	return append(values, value)
}

// itoa is a tiny local converter to keep the lock-held path allocation-free.
func itoa(value uint32) string {
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

// MatchesExcludedUnit is a convenience for the engine applying the denylist to
// a full command line captured from /proc/<pid>/cmdline.
func MatchesExcludedUnit(commandLine string, exclude []string) bool {
	_, matched := MatchExcludedUnit(commandLine, exclude)
	return matched
}

// MatchExcludedUnit returns the denylist token matched inside a command line.
// The command line is what distinguishes `nginx: master process` from
// `nginx: worker process`, whose comm is identical after the kernel truncation.
func MatchExcludedUnit(commandLine string, exclude []string) (string, bool) {
	lower := strings.ToLower(commandLine)
	for _, unit := range builtinControlUnits {
		if strings.Contains(lower, unit) {
			return unit, true
		}
	}
	for _, unit := range exclude {
		unit = strings.ToLower(strings.TrimSpace(unit))
		if unit != "" && strings.Contains(lower, unit) {
			return unit, true
		}
	}
	return "", false
}
