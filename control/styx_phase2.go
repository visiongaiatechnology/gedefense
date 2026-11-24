// STATUS: DIAMANT VGT SUPREME
package main

// V6.3.0 AP-6: StyX phase-2 flow analytics — bidirectional PCR, IdleHint
// coupling and the RX observation capability.
//
// The engine consumes the existing 104-byte FlowEvent records (direction
// EGRESS=1 / INGRESS=2, tx_bytes/rx_bytes) that the core already drains through
// `STYX_FLOW_EVENTS`; it never changes an enforcement decision and never emits a
// kill-eligible signal on its own.
//
// Contract with the integration seam:
//   - `NewStyxPhase2Engine()` (no arguments) is called from NewXDREngine,
//   - `pollStyxPhase2(runtime, now, retryAfter) time.Time` is called on the
//     100 ms tick and returns the next due time (5 s cadence, 10 s retry),
//   - `phase2ObserveFlowBatch(events, now)` is called from
//     `XDREngine.recordStyxFlowBatch` for every drained flow batch.
//
// ## PCR rule (evidence first)
//
// Per entity `(cgroup, pid, remote peer, remote port)` the engine keeps five
// one-minute buckets of tx/rx bytes. The five-minute window value is
//
//	PCR = (tx - rx) / (tx + rx)
//
// and the exfiltration evidence `XDR.STYX_PCR_EXFIL` requires ALL of:
//   - the ingress RX capability is known-attached AND the entity has at least
//     one **matched inbound** flow sample in the window (a tx-only entity is
//     reported as "RX unobserved", never silently scored as rx=0),
//   - the window carries >= 256 KiB (tx+rx),
//   - PCR > +0.60 (exactly: tx > 4*rx; the boundary PCR == 0.60 does NOT fire),
//   - the remote peer is a bare IP literal that is First-Seen: first observed by
//     this engine no more than one hour ago (bounded first-seen set).
//
// The emitted incident is evidence first (`Decision:"alert"`, `Action:"none"`,
// `KillSignals:0`), deduplicated per entity for 30 minutes, severity high,
// score 100, categories ["network","c2"], and it carries one attack-story node.
// It never calls `respond()` and never marks itself kill eligible.
//
// ## Correlation-quality honesty
//
// * `OBSERVED` — RX capability attached AND this entity has a matched inbound
//   sample. Only this quality is used for a PCR evidence incident.
// * `TEMPORAL` — RX not observed for the entity, but logind session files show
//   no active session (a session-inactive timing statement; never a "locked"
//   claim — logind IdleHint is D-Bus only and is not readable from the files).
// * `NONE` — neither. A missing RX capability is a capability fact and an
//   `info` event, never platform degradation.
//
// ## IdleHint
//
// The bounded reader of `/run/systemd/sessions/*` (<= 256 files, <= 16 KiB each)
// parses only `UID=`, `ACTIVE=`, `STATE=`, `CLASS=`, `TYPE=` strictly and
// tolerates a missing `SEAT=` (systemd removed/optional fields such as FIFO or
// SEAT are ignored, non-regular files such as the `.ref` FIFO are skipped).
// `idlehint=inactive` means "no ACTIVE=1 logind session is recorded"; it never
// claims a locked screen or a D-Bus IdleHint.
//
// ## Bounds
//
// Entities, first-seen set, dedupe set and both attribution indices are capped
// at 4096 entries; windows are pruned on every poll; all counters saturate; the
// status/report projections are bounded slices. No goroutine, no `os/exec`, Go
// standard library only.

import (
	"errors"
	"net/netip"
	"strings"
	"sync"
	"time"
)

const (
	// styxPhase2MaxEntities bounds the entity windows and each attribution index.
	styxPhase2MaxEntities = 4096
	// styxPhase2Buckets is the one-minute bucket count of the five-minute window.
	styxPhase2Buckets        = 5
	styxPhase2BucketDuration = time.Minute
	styxPhase2Window         = styxPhase2Buckets * styxPhase2BucketDuration
	// styxPhase2PollInterval / styxPhase2RetryInterval are the engine cadences.
	styxPhase2PollInterval  = 5 * time.Second
	styxPhase2RetryInterval = 10 * time.Second
	// styxPhase2PCRComputeBytes is the minimum tx+rx volume before a PCR value is
	// even computed (64 KiB): below that a ratio is statistically meaningless.
	styxPhase2PCRComputeBytes = 64 * 1024
	// styxPhase2MinWindowBytes is the minimum tx+rx volume of the 5-minute
	// window before any PCR *evidence* is claimed (256 KiB).
	styxPhase2MinWindowBytes = 256 * 1024
	// styxPhase2PCRThreshold is the documented +0.60 boundary. The exact integer
	// form is tx > 4*rx; equality (PCR == 0.60) does not fire.
	styxPhase2PCRThreshold = 0.60
	// styxPhase2DedupeTTL deduplicates one entity's incident for 30 minutes.
	styxPhase2DedupeTTL = 30 * time.Minute
	// styxPhase2FirstSeenTTL is the age under which a remote address still
	// counts as First-Seen. Older (known) remotes never produce this evidence.
	styxPhase2FirstSeenTTL = time.Hour
	// styxPhase2MaxFirstSeen bounds the engine-owned first-seen set.
	styxPhase2MaxFirstSeen = 4096
	// styxPhase2MaxIncidentsPerPoll bounds evidence emission per five-second
	// cycle; a flood of distinct entities must not flood the evidence ledger.
	styxPhase2MaxIncidentsPerPoll = 8
	// styxPhase2MaxEventsPerBatch bounds one ingested flow batch defensively
	// (the parser already caps a drain at 64 records).
	styxPhase2MaxEventsPerBatch = 256
	// styxPhase2MaxSessions / styxPhase2MaxSessionBytes bound the logind reader.
	styxPhase2MaxSessions     = 256
	styxPhase2MaxSessionBytes = 16 * 1024
	// styxPhase2SessionsRoot is the default logind runtime directory.
	styxPhase2SessionsRoot = "/run/systemd/sessions"
	// styxPhase2MaxReportEntities bounds the report projection.
	styxPhase2MaxReportEntities = 32

	// Rule / sensor identity of the phase-2 evidence.
	styxPhase2RulePCRExfil = "XDR.STYX_PCR_EXFIL"
	styxPhase2EventTypes   = "PCR_EXFIL_CANDIDATE"
	styxPhase2SensorName   = "styx-phase2"
	styxPhase2Severity     = "high"
	styxPhase2Score        = 100
)

// styxPhase2EntityKey is the PCR entity: the process identity (cgroup + pid the
// egress flow belongs to) and the remote peer it talks to.
type styxPhase2EntityKey struct {
	cgroupID uint64
	pid      int
	remote   netip.Addr
	port     uint16
}

// styxPhase2Bucket is one minute of an entity's window.
type styxPhase2Bucket struct {
	minute    int64 // Unix minute this slot currently represents
	tx        uint64
	rx        uint64
	txSamples uint32
	rxSamples uint32
}

// styxPhase2Entity is one bounded PCR window.
type styxPhase2Entity struct {
	key       styxPhase2EntityKey
	firstSeen time.Time
	lastSeen  time.Time
	uid       uint32
	family    uint8
	proto     uint8
	comm      string
	buckets   [styxPhase2Buckets]styxPhase2Bucket
	txTotal   uint64
	rxTotal   uint64
}

// styxPhase2RxKey attributes an inbound record to an egress entity by the
// (cgroup, remote peer, remote port) tuple the kernel reports for both
// directions.
type styxPhase2RxKey struct {
	cgroupID uint64
	remote   netip.Addr
	port     uint16
}

// styxPhase2EndpointKey attributes an inbound record without a usable ingress
// cgroup by the exact reverse 5-tuple of an observed egress flow.
type styxPhase2EndpointKey struct {
	remote     netip.Addr
	remotePort uint16
	localPort  uint16
	proto      uint8
}

// StyxPhase2Engine holds the bounded phase-2 state. All fields below `mu` are
// guarded by it; the two test seams (`rxStatusQuery`, `sessionsRoot`) are set
// before the engine is used and never mutated concurrently in production.
type StyxPhase2Engine struct {
	mu sync.Mutex

	entities  map[styxPhase2EntityKey]*styxPhase2Entity
	rxIndex   map[styxPhase2RxKey]styxPhase2EntityKey
	endpoints map[styxPhase2EndpointKey]styxPhase2EntityKey
	firstSeen map[netip.Addr]time.Time
	dedupe    map[string]time.Time

	rxCapabilityKnown      bool
	rxCapabilityAnnounced  bool
	rxObservationAvailable bool
	rxAttached             bool
	rxEvents               uint64
	rxReadFailures         uint64
	rxStatusAt             time.Time
	rxStatusErr            string

	sessions    StyxSessionSummary
	sessionsAt  time.Time
	sessionsErr string

	txEvents       uint64
	ingressEvents  uint64
	rxAttributed   uint64
	rxUnattributed uint64
	pcrCandidates  uint64
	pcrIncidents   uint64
	suppressed     uint64
	evictions      uint64

	// rxStatusQuery is the test seam for the STYX_INGRESS_STATUS poll; nil means
	// "use XDREngine.core" in production.
	rxStatusQuery func() (CoreStyxIngressStatus, error)
	// sessionsRoot overrides the logind directory in tests; empty means the
	// production /run/systemd/sessions.
	sessionsRoot string
}

// NewStyxPhase2Engine constructs the inert phase-2 engine. It holds no socket,
// starts no goroutine and performs no I/O until the 100 ms tick calls it.
func NewStyxPhase2Engine() *StyxPhase2Engine {
	return &StyxPhase2Engine{
		entities:  make(map[styxPhase2EntityKey]*styxPhase2Entity),
		rxIndex:   make(map[styxPhase2RxKey]styxPhase2EntityKey),
		endpoints: make(map[styxPhase2EndpointKey]styxPhase2EntityKey),
		firstSeen: make(map[netip.Addr]time.Time),
		dedupe:    make(map[string]time.Time),
	}
}

// pollStyxPhase2 runs one status + IdleHint + evaluation cycle and returns the
// next due time. A missing RX capability is an `info` capability fact; it never
// degrades the platform and never produces a fake OBSERVED correlation.
func (e *XDREngine) pollStyxPhase2(runtime RuntimeSettings, now time.Time, retryAfter time.Time) time.Time {
	if e == nil || e.styxPhase2 == nil || !runtime.XDREnabled || now.Before(retryAfter) {
		return retryAfter
	}
	engine := e.styxPhase2
	now = now.UTC()
	next := now.Add(styxPhase2PollInterval)

	status, statusErr := e.styxIngressStatusQuery()
	e.consumeStyxIngressStatus(status, statusErr, now)
	if statusErr != nil {
		next = now.Add(styxPhase2RetryInterval)
	}

	engine.refreshSessions(now)

	incidents := engine.evaluatePCR(now)
	for _, incident := range incidents {
		e.emitStyxPhase2Incident(incident)
	}
	return next
}

// styxIngressStatusQuery resolves the status source. Production uses the
// authenticated CoreClient; tests inject `rxStatusQuery`.
func (e *XDREngine) styxIngressStatusQuery() (CoreStyxIngressStatus, error) {
	if e == nil || e.styxPhase2 == nil {
		return CoreStyxIngressStatus{}, ErrStyxIngressUnavailable
	}
	if query := e.styxPhase2.rxStatusQuery; query != nil {
		return query()
	}
	if e.core == nil {
		return CoreStyxIngressStatus{}, ErrStyxIngressUnavailable
	}
	return e.core.StyxIngressStatus()
}

// consumeStyxIngressStatus projects one STYX_INGRESS_STATUS answer onto the
// engine and the (additive) beacon capability field. Transitions between
// "missing", "attached" and "not attached" are recorded as `info` events only:
// a missing RX capability must never degrade the platform.
//
// Lock order: the engine mutex is released before the beacon setter is called,
// so no lock cycle with `applyStyxBeaconSettings` (beacon lock -> engine read)
// can form.
func (e *XDREngine) consumeStyxIngressStatus(status CoreStyxIngressStatus, statusErr error, now time.Time) {
	if e == nil || e.styxPhase2 == nil {
		return
	}
	engine := e.styxPhase2
	engine.mu.Lock()
	knownBefore, availableBefore := engine.rxCapabilityKnown, engine.rxObservationAvailable
	announcedBefore := engine.rxCapabilityAnnounced
	switch {
	case statusErr == nil:
		engine.rxCapabilityKnown = true
		engine.rxObservationAvailable = status.Attached
		engine.rxAttached = status.Attached
		engine.rxEvents = status.RxEvents
		engine.rxReadFailures = status.ReadFailures
		engine.rxStatusErr = ""
	case errors.Is(statusErr, ErrStyxIngressUnavailable):
		engine.rxCapabilityKnown = false
		engine.rxObservationAvailable = false
		engine.rxAttached = false
		engine.rxStatusErr = boundedStyxText(statusErr)
	default:
		// Transient IPC/parse failure: the capability itself is still known from
		// an earlier poll, but this cycle cannot prove observation.
		engine.rxObservationAvailable = false
		engine.rxAttached = false
		engine.rxStatusErr = boundedStyxText(statusErr)
	}
	engine.rxStatusAt = now
	engine.rxCapabilityAnnounced = true
	known, available := engine.rxCapabilityKnown, engine.rxObservationAvailable
	engine.mu.Unlock()

	// Additive project onto the beacon path: metadata/reporting only, the
	// Phase-1 rx ratio gate (`RxObservationAvailable`) stays untouched.
	if e.styxBeacon != nil {
		e.styxBeacon.SetRxObservationCapability(available)
	}
	// The first status answer is always announced (verified baseline); later
	// answers only on a real transition, so the event stream never repeats the
	// same capability fact on every five-second poll.
	if e.state == nil || (announcedBefore && knownBefore == known && availableBefore == available) {
		return
	}
	switch {
	case !known:
		e.state.AddEvent(Event{
			Severity: "info", Kind: "styx.phase2_rx_capability_missing", Source: "kernel",
			Message: "StyX phase-2 ingress RX capability is missing (old core, rejected command or object without the AP-6 program); this is a capability fact, not a degradation. PCR is not computed from tx-only data and correlation quality stays NONE/TEMPORAL.",
		})
	case available:
		e.state.AddEvent(Event{
			Severity: "info", Kind: "styx.phase2_rx_available", Source: "kernel",
			Message: "StyX phase-2 ingress RX observer is attached; PCR may claim OBSERVED correlation for entities with matched inbound flow samples.",
		})
	default:
		e.state.AddEvent(Event{
			Severity: "info", Kind: "styx.phase2_rx_unavailable", Source: "kernel",
			Message: "StyX phase-2 ingress RX observer is not attached; PCR is not computed from tx-only data and correlation quality stays NONE/TEMPORAL.",
		})
	}
}

// emitStyxPhase2Incident is the detector's sink. Evidence first, then the
// incident; it never calls `respond()` and therefore can never kill, contain or
// otherwise act on this evidence.
func (e *XDREngine) emitStyxPhase2Incident(incident XDRIncident) {
	if e == nil || e.state == nil {
		return
	}
	incident.Severity = strings.ToLower(strings.TrimSpace(incident.Severity))
	evidenceErr := e.state.RecordEvidence(EvidenceRecord{
		Severity: incident.Severity, Kind: "xdr.styx_pcr_exfil", Source: styxPhase2SensorName,
		Message: "StyX phase-2 PCR exfiltration evidence recorded before any response: " + incident.Summary,
		Target:  incident.Remote, Time: incident.Time,
	})
	if evidenceErr != nil {
		// No evidence, no active response; the incident is still recorded with an
		// outcome that says why nothing happened.
		incident.Action = "none"
		incident.Outcome = "mandatory evidence commit failed; the phase-2 PCR detector never takes active response and the containment path is untouched"
		e.appendIncident(incident)
		return
	}
	e.appendIncident(incident)
	e.state.AddEvent(Event{
		Severity: "high", Kind: "xdr.styx_pcr_exfil", Source: styxPhase2SensorName,
		Message: incident.Summary, Target: incident.Remote,
	})
}

// phase2ObserveFlowBatch feeds one drained flow batch into the phase-2 window.
// The beacon detector remains the only consumer of the Phase-1 asymmetry rules.
func (e *XDREngine) phase2ObserveFlowBatch(events []CoreStyxFlowEvent, now time.Time) {
	if e == nil || e.styxPhase2 == nil || len(events) == 0 {
		return
	}
	e.styxPhase2.observeBatch(events, now.UTC())
}

// observeBatch applies one bounded flow batch under a single lock.
func (p *StyxPhase2Engine) observeBatch(events []CoreStyxFlowEvent, now time.Time) {
	if p == nil || len(events) == 0 {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if now.IsZero() {
		now = time.Now().UTC()
	}
	limit := len(events)
	if limit > styxPhase2MaxEventsPerBatch {
		limit = styxPhase2MaxEventsPerBatch
	}
	for i := 0; i < limit; i++ {
		address, ok := styxPhase2FlowAddress(events[i])
		if !ok {
			continue
		}
		switch events[i].Direction {
		case 1: // STYX_DIR_EGRESS
			p.observeEgressLocked(events[i], address, now)
		case 2: // STYX_DIR_INGRESS
			p.observeIngressLocked(events[i], address, now)
		}
	}
}

// styxPhase2FlowAddress validates one flow record and returns its canonical
// remote peer address. Only TCP/UDP flows of external peers participate in PCR.
func styxPhase2FlowAddress(event CoreStyxFlowEvent) (netip.Addr, bool) {
	var zero netip.Addr
	if event.Family != 4 && event.Family != 6 {
		return zero, false
	}
	if event.Proto != 6 && event.Proto != 17 {
		return zero, false
	}
	if (event.Direction != 1 && event.Direction != 2) || event.Verdict > 5 {
		return zero, false
	}
	if event.Packets == 0 || event.PID < 0 {
		return zero, false
	}
	// A peer port of 0 has no remote endpoint identity; fragments/ICMP are
	// already excluded by the proto check.
	if event.DstPort == 0 {
		return zero, false
	}
	address, ok := netip.AddrFromSlice(event.DstIP)
	if !ok {
		return zero, false
	}
	address = address.Unmap()
	if !address.IsValid() || address.IsUnspecified() || (event.Family == 4) != address.Is4() {
		return zero, false
	}
	// Local IPC and non-routable scopes are not exfiltration targets; the beacon
	// detector applies the same external-only rule.
	if address.IsLoopback() || address.IsLinkLocalUnicast() || address.IsLinkLocalMulticast() || address.IsMulticast() {
		return zero, false
	}
	return address, true
}
