// STATUS: DIAMANT VGT SUPREME
package main

// V6.3.0 AP-6: DNS tunnelling analytics (multi-signal, observe-only).
//
// The kernel captures bounded DNS query observations (UDP/53 sendto/sendmsg);
// this engine drains them on a 5 s cadence and runs the documented multi-signal
// test over a 5-minute sliding window (five 1-minute buckets):
//
//	a. subdomain Shannon entropy > 3.5 bits/char,
//	b. Zipf deviation: distinct subdomains / expected-distinct >= 3.0,
//	c. FQDN presentation length > 50 chars,
//	d. TXT/NULL share > 10 % of the domain's queries (>= 20 queries),
//	e. > 100 distinct subdomains in the last hour.
//
// An `XDR.DNS_TUNNEL` incident is produced only when **at least three signals
// fire simultaneously** for the same registrable domain; a single or double
// signal never escalates. The finding is evidence-first (mandatory evidence
// commit before the incident; an evidence failure is carried into the incident
// outcome), severity `high`, score 100, `Decision:"alert"`, `Action:"none"`,
// categories `network`/`c2`, and it is never kill-eligible: this engine has no
// path into the kill gate and derives no response action. GIEF v1.0 and SBC
// enrichment are attached later by `appendIncident` (not by this file).
//
// Bounds (all enforced, never grown on demand):
//
//   - 4096 query observations in the ring, 2048 tracked domains,
//   - 128 distinct-subdomain hash entries per domain for the 1-hour signal,
//   - 512 deduped domains (per-domain incident dedupe TTL 1 h),
//   - every text field that reaches evidence/events is truncated to a fixed
//     budget, and the overflow telemetry is rate-limited to one event per 5 min.
//
// The registrable-domain key is the documented "last two labels" heuristic. It
// is a heuristic, not a PSL implementation: single-label names (local search
// domains / pxy-style forwarders) use the label itself, and public-suffix corner
// cases (e.g. `co.uk`) are grouped under their last two labels. That is stated
// in the incident evidence rather than silently mis-grouped.
//
// Capability honesty: a core that does not advertise `DNS_CAPTURE_*` is a
// capability fact (info), never an XDR degradation. `DNSReport()` exposes
// `dns_observation: available|unavailable` so a later StyX phase-2/beacon
// consumer can use real DNS attribution instead of assuming it.

import (
	"errors"
	"sync"
	"time"
)

const (
	// dnsCaptureDrainInterval is the DNS_EVENTS drain cadence.
	dnsCaptureDrainInterval = 5 * time.Second
	// dnsCaptureRetryInterval is the retry cadence after a drain failure (and
	// the cadence while the capability is absent).
	dnsCaptureRetryInterval = 10 * time.Second
	// dnsCaptureStatusInterval is the status (capability/arm/counter) cadence.
	dnsCaptureStatusInterval = 30 * time.Second
	// dnsWindowBucketCount / dnsWindowBucketWidth describe the sliding window.
	dnsWindowBucketCount = 5
	dnsWindowBucketWidth = time.Minute
	// dnsMaxObservations is the hard ring capacity for query observations.
	dnsMaxObservations = 4096
	// dnsMaxDomains is the hard capacity of the per-domain map.
	dnsMaxDomains = 2048
	// dnsMaxHourDistinct bounds the per-domain 1-hour distinct-subdomain set.
	dnsMaxHourDistinct = 128
	// dnsHourWindow / dnsIncidentDedupeTTL bound the 1-hour aggregations.
	dnsHourWindow        = time.Hour
	dnsIncidentDedupeTTL = time.Hour
	// dnsMaxIncidentDomains bounds the per-domain incident dedupe map.
	dnsMaxIncidentDomains = 512
	// dnsOverflowMinGap rate-limits the ring-overflow telemetry event.
	dnsOverflowMinGap = 5 * time.Minute
	// dnsEntropySampleCap bounds the bytes fed into one entropy estimate.
	dnsEntropySampleCap = 4096
	// Analysis thresholds (documented in the module comment).
	dnsEntropyThreshold      = 3.5
	dnsMinEntropyLabels      = 4
	dnsMinEntropyBytes       = 32
	dnsZipfRatioThreshold    = 3.0
	dnsZipfMinQueries        = 8
	dnsLongFQDNThreshold     = 50
	dnsTXTNULLShareThreshold = 0.10
	dnsTXTNULLMinQueries     = 20
	dnsHourlyDistinctLimit   = 100
	dnsMinSignals            = 3
	// dnsMaxSampleSubdomains bounds the evidence sample.
	dnsMaxSampleSubdomains = 3
	// dnsReportReasonBytes bounds operator-facing reason text.
	dnsReportReasonBytes = 240
	// dnsEventTextBytes bounds state-event message text.
	dnsEventTextBytes = 512
)

// dnsSignals enumerates the five documented signals in a stable order.
var dnsSignalNames = []string{
	"entropy",
	"zipf",
	"fqdn_length",
	"txt_null_share",
	"subdomains_per_hour",
}

// dnsCaptureCore is the subset of the privileged client the AP-6 DNS contract
// needs (an interface so tests need no socket and no kernel).
type dnsCaptureCore interface {
	DnsSet(enabled bool) error
	DnsEvents() ([]CoreDnsEvent, uint64, error)
	DnsStatus() (CoreDnsStatus, error)
}

// dnsObservation is one query observation inside the bounded sliding window.
type dnsObservation struct {
	bucket    int64
	domain    string
	subdomain string
	qname     string
	qtype     uint16
	longFQDN  bool
	pid       int
	uid       uint32
	comm      string
}

// dnsDomainState is the per-domain bookkeeping that outlives the 5-minute ring
// (the 1-hour distinct-subdomain signal).
type dnsDomainState struct {
	lastSeen     time.Time
	hourDistinct map[uint64]time.Time
}

// dnsDomainAggregate is the bounded per-domain projection of the 5-minute ring.
type dnsDomainAggregate struct {
	queries     int
	subdomains  map[string]struct{}
	txtNull     int
	longFQDN    bool
	firstPID    int
	firstUID    uint32
	firstComm   string
	sampleSubs  []string
	lastQName   string
	qtypes      []uint16
	lastQueryAt int64
}

// dnsTunnelSignals is the deterministic result of the five-signal evaluation.
type dnsTunnelSignals struct {
	count          int
	names          []string
	entropy        float64
	entropyHit     bool
	zipfRatio      float64
	zipfHit        bool
	distinct       int
	fqdnLong       bool
	txtShare       float64
	txtShareHit    bool
	hourlyDistinct int
	hourlyHit      bool
}

// dnsTunnelTrigger is one deduped candidate handed to the incident writer.
type dnsTunnelTrigger struct {
	domain      string
	signals     dnsTunnelSignals
	queries     int
	windowStart time.Time
	firstPID    int
	firstUID    uint32
	firstComm   string
	sampleSubs  []string
	qtypes      []uint16
}

// DNSTunnelEngine holds the bounded per-domain window state and capability.
type DNSTunnelEngine struct {
	mu              sync.Mutex
	core            dnsCaptureCore
	status          CoreDnsStatus
	statusAt        time.Time
	statusErr       string
	capabilityKnown bool
	capabilitySeen  bool
	armedRequested  bool
	// observations is a fixed-size circular ring: never re-allocated on growth.
	observations     []dnsObservation
	observationHead  int
	observationCount int
	windowEvictions  uint64
	domains          map[string]*dnsDomainState
	seen             map[string]time.Time
	pidLastQuery     map[int]time.Time
	lastOverflow     time.Time
	queries          uint64
	droppedTotal     uint64
	incidents        uint64
	suppressed       uint64
}

// NewDNSTunnelEngine constructs the inert DNS tunnelling engine. It is called
// once from NewXDREngine; the capability is unknown until the first successful
// drain/status answer.
func NewDNSTunnelEngine() *DNSTunnelEngine {
	return &DNSTunnelEngine{
		domains:      make(map[string]*dnsDomainState),
		seen:         make(map[string]time.Time),
		pidLastQuery: make(map[int]time.Time),
	}
}

// bindCore latches the privileged client (the core pointer is immutable on the
// XDR engine, so the first non-nil binding is final).
func (t *DNSTunnelEngine) bindCore(core dnsCaptureCore) {
	if t == nil || core == nil {
		return
	}
	t.mu.Lock()
	if t.core == nil {
		t.core = core
	}
	t.mu.Unlock()
}

func (t *DNSTunnelEngine) coreSnapshot() dnsCaptureCore {
	if t == nil {
		return nil
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.core
}

func (t *DNSTunnelEngine) statusDue(now time.Time) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.statusAt.IsZero() || now.Sub(t.statusAt) >= dnsCaptureStatusInterval
}

func (t *DNSTunnelEngine) setStatusError(err error) {
	if t == nil || err == nil {
		return
	}
	t.mu.Lock()
	t.statusErr = "dns capture " + boundedStyxText(err)
	t.mu.Unlock()
}

func (t *DNSTunnelEngine) clearDrainError() {
	if t == nil {
		return
	}
	t.mu.Lock()
	if t.statusErr != "" {
		t.statusErr = ""
	}
	t.mu.Unlock()
}

func (t *DNSTunnelEngine) armDue() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return !t.armedRequested
}

func (t *DNSTunnelEngine) markArmedRequested() {
	t.mu.Lock()
	t.armedRequested = true
	t.mu.Unlock()
}

// pollDnsTunnel runs one status + drain cycle and returns the next due time.
// Failure isolation: a status query failure never blocks the drain and vice
// versa; both use the bounded 10 s retry cadence on error.
func (e *XDREngine) pollDnsTunnel(runtime RuntimeSettings, now time.Time, retryAfter time.Time) time.Time {
	if e == nil || e.dnsTunnel == nil || !runtime.XDREnabled || now.Before(retryAfter) {
		return retryAfter
	}
	if e.core != nil {
		e.dnsTunnel.bindCore(e.core)
	}
	core := e.dnsTunnel.coreSnapshot()
	if core == nil {
		e.consumeDnsStatus(CoreDnsStatus{}, ErrDnsUnavailable, now)
		return now.Add(dnsCaptureRetryInterval)
	}
	if e.dnsTunnel.statusDue(now) {
		status, statusErr := core.DnsStatus()
		e.consumeDnsStatus(status, statusErr, now)
		if statusErr == nil {
			if status.Enabled {
				e.dnsTunnel.markArmedRequested()
			} else if e.dnsTunnel.armDue() {
				// Arm the observe-only capture exactly once. The core arms itself
				// at load; this covers a core that was explicitly disarmed and
				// keeps a later operator disarm authoritative (the request latches
				// only after a successful call).
				if err := core.DnsSet(true); err != nil {
					e.dnsTunnel.setStatusError(err)
				} else {
					e.dnsTunnel.markArmedRequested()
				}
			}
		}
	}
	events, dropped, drainErr := core.DnsEvents()
	if drainErr != nil {
		if errors.Is(drainErr, ErrDnsUnavailable) {
			// Capability fact, not an outage: clear the counters and report the
			// missing family honestly instead of a degraded XDR sensor.
			e.consumeDnsStatus(CoreDnsStatus{}, ErrDnsUnavailable, now)
		} else {
			e.dnsTunnel.setStatusError(drainErr)
		}
		return now.Add(dnsCaptureRetryInterval)
	}
	e.dnsTunnel.clearDrainError()
	e.consumeDnsEvents(events, dropped, now)
	return now.Add(dnsCaptureDrainInterval)
}

// consumeDnsStatus folds one status answer (or capability error) into the
// engine and publishes the availability transition as an info event.
func (e *XDREngine) consumeDnsStatus(status CoreDnsStatus, statusErr error, now time.Time) {
	if e == nil || e.dnsTunnel == nil {
		return
	}
	t := e.dnsTunnel
	t.mu.Lock()
	wasKnown := t.capabilityKnown
	wasSeen := t.capabilitySeen
	switch {
	case statusErr == nil:
		t.status = status
		t.statusAt = now
		t.statusErr = ""
		t.capabilityKnown = true
	case errors.Is(statusErr, ErrDnsUnavailable):
		t.capabilityKnown = false
		t.status = CoreDnsStatus{}
		t.statusAt = time.Time{}
		t.statusErr = ""
		if t.armedRequested {
			t.armedRequested = false
		}
	default:
		t.statusErr = "status query failed: " + boundedStyxText(statusErr)
	}
	t.capabilitySeen = true
	known := t.capabilityKnown
	t.mu.Unlock()
	if e.styxBeacon != nil {
		dnsAvail := e.DNSObservationAvailable()
		e.styxBeacon.mu.Lock()
		e.styxBeacon.cfg.DNSObservationAvailable = dnsAvail
		e.styxBeacon.mu.Unlock()
	}
	if e.state == nil {
		return
	}
	switch {
	case !known && (wasKnown || !wasSeen):
		e.state.AddEvent(Event{Time: now, Severity: "info", Kind: "xdr.dns_capture_capability_missing", Source: "kernel",
			Message: "The privileged core does not advertise the DNS_CAPTURE_* command family; DNS query visibility is unavailable (capability fact, not an XDR degradation)"})
	case known && !wasKnown:
		e.state.AddEvent(Event{Time: now, Severity: "info", Kind: "xdr.dns_capture_capability_available", Source: "kernel",
			Message: "Bounded DNS query capture (UDP/53 sendto/sendmsg) is available; query observations feed the multi-signal tunnelling analysis (observe-only)"})
	}
}

// consumeDnsEvents feeds one drained kernel batch into the window and runs the
// analysis. The batch is bounded by the transport parser (<= 16 records).
func (e *XDREngine) consumeDnsEvents(events []CoreDnsEvent, dropped uint64, now time.Time) {
	if e == nil || e.dnsTunnel == nil {
		return
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	t := e.dnsTunnel
	triggers := t.observeBatchLocked(events, dropped, now)
	if dropped > 0 {
		e.reportDnsOverflow(dropped, now)
	}
	for _, trigger := range triggers {
		e.recordDnsTunnelIncident(trigger, now)
	}
}

// observeBatchLocked ingests one batch, prunes the window and evaluates every
// domain. It returns the deduped incident triggers (dedupe is claimed here so a
// concurrent drain cannot double-emit; the engine is only driven from the XDR
// tick).
func (t *DNSTunnelEngine) observeBatchLocked(events []CoreDnsEvent, dropped uint64, now time.Time) []dnsTunnelTrigger {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.observations == nil {
		t.observations = make([]dnsObservation, dnsMaxObservations)
	}
	if t.domains == nil {
		t.domains = make(map[string]*dnsDomainState)
	}
	if t.seen == nil {
		t.seen = make(map[string]time.Time)
	}
	if t.pidLastQuery == nil {
		t.pidLastQuery = make(map[int]time.Time)
	}
	bucket := now.Unix() / int64(dnsWindowBucketWidth/time.Second)
	accepted := 0
	for _, event := range events {
		if accepted >= dnsContinueEventCap {
			break
		}
		accepted++
		observation, ok := dnsObservationFromEvent(event, bucket)
		if !ok {
			continue
		}
		t.queries++
		if observation.pid > 0 {
			if len(t.pidLastQuery) >= 4096 {
				cutoff := now.Add(-FlowTTLSeconds * time.Second)
				for pid, seenAt := range t.pidLastQuery {
					if seenAt.Before(cutoff) {
						delete(t.pidLastQuery, pid)
					}
				}
				if len(t.pidLastQuery) >= 4096 {
					for pid := range t.pidLastQuery {
						delete(t.pidLastQuery, pid)
						break
					}
				}
			}
			t.pidLastQuery[observation.pid] = now
		}
		t.appendObservationLocked(observation)
		t.rememberHourDistinctLocked(observation, now)
	}
	t.droppedTotal = t.droppedTotal + dropped
	t.pruneWindowLocked(bucket)
	return t.analyzeLocked(now, bucket)
}

// dnsContinueEventCap is a defensive per-batch bound independent of the
// transport parser (the analyser must not depend on a single parser constant).
const dnsContinueEventCap = maxDnsEventsPerResponse

// DNSReport is the bounded, honest operator projection of the DNS capture and
// the tunnelling analysis (no route is added by AP-6).
type DNSReport struct {
	Version            string     `json:"version"`
	State              string     `json:"state"`           // active | degraded | disarmed | unavailable
	Capability         string     `json:"capability"`      // available | missing
	Observation        string     `json:"dns_observation"` // available | unavailable
	Reason             string     `json:"reason,omitempty"`
	Enabled            bool       `json:"enabled"`
	Attached           bool       `json:"attached"`
	Sendto             bool       `json:"sendto"`
	Sendmsg            bool       `json:"sendmsg"`
	Events             uint64     `json:"events"`
	Drops              uint64     `json:"drops"`
	ReadFailures       uint64     `json:"read_failures"`
	Queries            uint64     `json:"queries"`
	TrackedDomains     int        `json:"tracked_domains"`
	WindowObservations int        `json:"window_observations"`
	WindowEvictions    uint64     `json:"window_evictions"`
	Incidents          uint64     `json:"incidents"`
	Suppressed         uint64     `json:"suppressed"`
	SampledAt          *time.Time `json:"sampled_at,omitempty"`
}

// DNSObservationAvailable reports whether the multi-signal analysis currently
// has a real DNS observation channel (capture armed + at least one tracepoint).
// A later StyX phase-2/beacon consumer must use this instead of assuming DNS
// attribution exists (no styx file is edited here).
func (e *XDREngine) DNSObservationAvailable() bool {
	return e.dnsReportLockedProjection().Observation == "available"
}

// DNSQueryObservedForPID reports whether the DNS capture observed at least one
// DNS query from pid since the given cutoff timestamp.
func (e *XDREngine) DNSQueryObservedForPID(pid int, since time.Time) bool {
	if e == nil || e.dnsTunnel == nil || pid <= 0 {
		return false
	}
	t := e.dnsTunnel
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.pidLastQuery == nil {
		return false
	}
	last, ok := t.pidLastQuery[pid]
	return ok && !last.Before(since)
}

// DNSReport returns the bounded operator projection of the DNS capture and the
// tunnelling analysis.
func (e *XDREngine) DNSReport() DNSReport {
	return e.dnsReportLockedProjection()
}
