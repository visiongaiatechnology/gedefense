// STATUS: DIAMANT VGT SUPREME
package main

// V6.3.0 AP-6 regression tests: the deterministic signal math (Shannon entropy,
// Zipf estimator), the registrable-domain heuristic, the multi-signal threshold
// (>= 3 signals, 2 must not fire), the benign-vs-tunnel corpus, the 1-hour
// dedupe, bounded overflow telemetry, window/domain capacity bounds and the
// honest capability reporting (no degradation for a missing command family).

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------- test corpus

type fakeDnsCaptureCore struct {
	setCalls    []bool
	setErr      error
	status      CoreDnsStatus
	statusErr   error
	events      []CoreDnsEvent
	dropped     uint64
	eventsErr   error
	statusCalls int
	eventCalls  int
}

func (f *fakeDnsCaptureCore) DnsSet(enabled bool) error {
	f.setCalls = append(f.setCalls, enabled)
	if f.setErr != nil {
		return f.setErr
	}
	if enabled {
		f.status.Enabled = true
	}
	return nil
}

func (f *fakeDnsCaptureCore) DnsEvents() ([]CoreDnsEvent, uint64, error) {
	f.eventCalls++
	if f.eventsErr != nil {
		return nil, 0, f.eventsErr
	}
	return f.events, f.dropped, nil
}

func (f *fakeDnsCaptureCore) DnsStatus() (CoreDnsStatus, error) {
	f.statusCalls++
	return f.status, f.statusErr
}

func newDnsTestEngine(t *testing.T) *XDREngine {
	t.Helper()
	return &XDREngine{
		state: NewState("test", defaultConfig()), correlator: NewIncidentCorrelator(0),
		dedupe: map[string]time.Time{}, degradeCauses: map[string]string{}, forensicFailures: map[string]int{},
		dnsTunnel: NewDNSTunnelEngine(), gief: NewGIEFEngine(), sbc: NewSBCFusionEngine(),
	}
}

// dnsTestLabel builds a deterministic high-entropy hex label.
func dnsTestLabel(seed int, length int) string {
	const alphabet = "0123456789abcdef"
	out := make([]byte, length)
	value := dnsHash64(fmt.Sprintf("ap6-seed-%d", seed))
	if value == 0 {
		value = 0x9e3779b97f4a7c15
	}
	for index := range out {
		value ^= value << 13
		value ^= value >> 7
		value ^= value << 17
		out[index] = alphabet[value&0xf]
	}
	return string(out)
}

func dnsTestEvent(ts uint64, pid int, qname string, qtype uint16, fqdnLen int) CoreDnsEvent {
	return CoreDnsEvent{
		TsNS: ts, PID: pid, TGID: pid, UID: 1000, QType: qtype,
		QName: qname, Comm: "dnsclient", Resolved: len(qname) == fqdnLen, FQDNLen: fqdnLen,
	}
}

// dnsCorpus builds one deterministic corpus of queries under `domain`.
func dnsCorpus(seed int, count int, domain string, subdomainLen int, qtypes []uint16) []CoreDnsEvent {
	events := make([]CoreDnsEvent, 0, count)
	for index := 0; index < count; index++ {
		subdomain := dnsTestLabel(seed+index, subdomainLen)
		qname := subdomain + "." + domain
		qtype := qtypes[index%len(qtypes)]
		events = append(events, dnsTestEvent(uint64(1_700_000_000_000_000_000)+uint64(index), 4242, qname, qtype, len(qname)))
	}
	return events
}

func feedDnsEvents(engine *XDREngine, events []CoreDnsEvent, now time.Time) {
	for start := 0; start < len(events); start += maxDnsEventsPerResponse {
		end := start + maxDnsEventsPerResponse
		if end > len(events) {
			end = len(events)
		}
		engine.consumeDnsEvents(events[start:end], 0, now)
	}
}

func dnsIncidents(engine *XDREngine) []XDRIncident {
	var out []XDRIncident
	for _, incident := range engine.state.Snapshot().Incidents {
		if containsString(incident.RuleIDs, "XDR.DNS_TUNNEL") {
			out = append(out, incident)
		}
	}
	return out
}

func dnsEventsOfKind(engine *XDREngine, kind string) []Event {
	var out []Event
	for _, event := range engine.state.Snapshot().Events {
		if event.Kind == kind {
			out = append(out, event)
		}
	}
	return out
}

func dnsAggregate(subdomains []string, queries int, txtNull int, longFQDN bool) *dnsDomainAggregate {
	aggregate := &dnsDomainAggregate{subdomains: make(map[string]struct{}, len(subdomains)), queries: queries, txtNull: txtNull, longFQDN: longFQDN}
	for _, subdomain := range subdomains {
		aggregate.subdomains[subdomain] = struct{}{}
	}
	return aggregate
}

// dnsEvaluateSignals runs the per-domain evaluation with the engine lock held,
// exactly like the production analysis path.
func dnsEvaluateSignals(t *testing.T, engine *XDREngine, domain string, aggregate *dnsDomainAggregate, now time.Time) dnsTunnelSignals {
	t.Helper()
	engine.dnsTunnel.mu.Lock()
	defer engine.dnsTunnel.mu.Unlock()
	if engine.dnsTunnel.domains == nil {
		engine.dnsTunnel.domains = map[string]*dnsDomainState{}
	}
	if _, ok := engine.dnsTunnel.domains[domain]; !ok {
		engine.dnsTunnel.domains[domain] = &dnsDomainState{lastSeen: now, hourDistinct: map[uint64]time.Time{}}
	}
	return engine.dnsTunnel.evaluateDomainLocked(domain, aggregate, now)
}

// ------------------------------------------------------------------ math tests

func TestDnsShannonEntropyKnownStrings(t *testing.T) {
	cases := []struct {
		text    string
		entropy float64
	}{
		{"", 0},
		{"aaaaaaaaaaaa", 0},
		{"abababab", 1},
		{"abcd", 2},
		{"abcdefgh", 3},
		{"aabbccdd", 2},
		{"0123456789abcdef", 4},
	}
	for _, testCase := range cases {
		if got := dnsShannonEntropy(testCase.text); got != testCase.entropy {
			t.Fatalf("entropy(%q) = %v, want %v", testCase.text, got, testCase.entropy)
		}
	}
	// A tunnel-style random hex label is clearly above the 3.5 threshold, while
	// benign words are below it.
	tunnelLabel := dnsTestLabel(1, 48)
	if entropy := dnsShannonEntropy(tunnelLabel); entropy <= dnsEntropyThreshold {
		t.Fatalf("tunnel label entropy %v is not above %v", entropy, dnsEntropyThreshold)
	}
	for _, benign := range []string{"www", "mail", "api", "assets-static-01"} {
		if entropy := dnsShannonEntropy(benign); entropy > dnsEntropyThreshold {
			t.Fatalf("benign label %q entropy %v unexpectedly above the threshold", benign, entropy)
		}
	}
}

func TestDnsZipfEstimatorCases(t *testing.T) {
	if got := dnsZipfExpectedDistinct(0); got != 1 {
		t.Fatalf("expected distinct for 0 observations = %v, want 1", got)
	}
	if got := dnsZipfExpectedDistinct(1); got != 1 {
		t.Fatalf("expected distinct for 1 observation = %v, want 1", got)
	} // n / ln(1+n): 100 / ln(101) ~= 21.7.
	if got := dnsZipfExpectedDistinct(100); got < 21 || got > 23 {
		t.Fatalf("expected distinct for 100 observations = %v, want ~21.7", got)
	}
	// All-distinct tunnel traffic deviates strongly (ratio ~ln(1+n)).
	if ratio := dnsZipfDeviation(100, 100); ratio < 4.5 || ratio > 5.0 {
		t.Fatalf("all-distinct deviation for 100 = %v, want ~4.6", ratio)
	}
	// Repeated benign lookups do not deviate.
	if ratio := dnsZipfDeviation(3, 400); ratio >= dnsZipfRatioThreshold {
		t.Fatalf("benign deviation %v crossed the threshold", ratio)
	}
	// The estimator exactly defines the signal threshold: at 20 all-distinct
	// queries the ratio is just above 3.0, at 8 it is below.
	if ratio := dnsZipfDeviation(20, 20); ratio < dnsZipfRatioThreshold {
		t.Fatalf("20 distinct/20 queries deviation %v should cross the threshold", ratio)
	}
	if ratio := dnsZipfDeviation(8, 8); ratio >= dnsZipfRatioThreshold {
		t.Fatalf("8 distinct/8 queries deviation %v should stay below the threshold", ratio)
	}
	if dnsZipfDeviation(0, 0) != 0 {
		t.Fatal("degenerate zipf deviation must be 0")
	}
}

func TestDnsRegistrableDomainHeuristic(t *testing.T) {
	cases := []struct {
		qname  string
		domain string
		sub    string
	}{
		{"www.example.com", "example.com", "www"},
		{"aGVsbG8ud29ybGQ.tunnel.example.com", "example.com", "aGVsbG8ud29ybGQ.tunnel"},
		{"example.com", "example.com", ""},
		{"localhost", "localhost", ""},
		{"x.example.co.uk", "co.uk", "x.example"},
	}
	for _, testCase := range cases {
		domain, sub := dnsRegistrableDomain(testCase.qname)
		if domain != testCase.domain || sub != testCase.sub {
			t.Fatalf("dnsRegistrableDomain(%q) = (%q,%q), want (%q,%q)",
				testCase.qname, domain, sub, testCase.domain, testCase.sub)
		}
	}
	if got := dnsNormalizeQName("WWW.Example.COM."); got != "www.example.com" {
		t.Fatalf("normalise = %q", got)
	}
	// A trailing dot is the fully-qualified form and is normalised, not rejected.
	if got := dnsNormalizeQName("example.com."); got != "example.com" {
		t.Fatalf("FQDN root dot normalised to %q", got)
	}
	for _, invalid := range []string{"", ".", "a..b", ".example.com", strings.Repeat("a", 64) + ".example.com"} {
		if got := dnsNormalizeQName(invalid); got != "" {
			t.Fatalf("invalid qname %q normalised to %q", invalid, got)
		}
	}
}

// ------------------------------------------------------- signal boundary tests

func TestDnsTunnelTXTNULLShareBoundary(t *testing.T) {
	engine := newDnsTestEngine(t)
	now := time.Unix(1_700_000_000, 0).UTC()
	domain := "example.com"
	subs := []string{"a", "b", "c"}

	// 2/20 = 10 % exactly: the documented signal is "> 10 %", so it must not fire.
	aggregate := dnsAggregate(subs, 20, 2, false)
	signals := dnsEvaluateSignals(t, engine, domain, aggregate, now)
	if signals.txtShareHit || signals.txtShare != 0.10 {
		t.Fatalf("10 %% TXT/NULL share fired: %+v", signals)
	}
	// 3/20 = 15 % > 10 %: fires.
	aggregate = dnsAggregate(subs, 20, 3, false)
	signals = dnsEvaluateSignals(t, engine, domain, aggregate, now)
	if !signals.txtShareHit {
		t.Fatalf("15 %% TXT/NULL share did not fire: %+v", signals)
	}
	// Below the minimum sample the share is not evaluated at all (1/1 == 100 % is
	// not evidence).
	aggregate = dnsAggregate(subs, 1, 1, false)
	signals = dnsEvaluateSignals(t, engine, domain, aggregate, now)
	if signals.txtShareHit {
		t.Fatalf("single-query TXT share fired: %+v", signals)
	}
	// NULL (10) and TXT (16) both count, other types do not.
	if !dnsQTypeIsTXTOrNull(16) || !dnsQTypeIsTXTOrNull(10) || dnsQTypeIsTXTOrNull(1) || dnsQTypeIsTXTOrNull(28) {
		t.Fatal("TXT/NULL type classification is wrong")
	}
}

func TestDnsTunnelHourlyDistinctBoundary(t *testing.T) {
	engine := newDnsTestEngine(t)
	now := time.Unix(1_700_000_000, 0).UTC()
	domain := "example.com"
	engine.dnsTunnel.mu.Lock()
	state := &dnsDomainState{lastSeen: now, hourDistinct: make(map[uint64]time.Time, dnsMaxHourDistinct)}
	engine.dnsTunnel.domains = map[string]*dnsDomainState{domain: state}
	for index := 0; index < dnsHourlyDistinctLimit; index++ {
		state.hourDistinct[dnsHash64(fmt.Sprintf("sub-%d", index))] = now.Add(dnsHourWindow)
	}
	engine.dnsTunnel.mu.Unlock()

	aggregate := dnsAggregate([]string{"a", "b"}, 5, 0, false)
	signals := dnsEvaluateSignals(t, engine, domain, aggregate, now)
	if signals.hourlyHit || signals.hourlyDistinct != dnsHourlyDistinctLimit {
		t.Fatalf("exactly %d distinct subdomains fired: %+v", dnsHourlyDistinctLimit, signals)
	}

	// One more distinct subdomain crosses the documented "> 100" boundary.
	engine.dnsTunnel.mu.Lock()
	state.hourDistinct[dnsHash64("sub-over-limit")] = now.Add(dnsHourWindow)
	engine.dnsTunnel.mu.Unlock()
	signals = dnsEvaluateSignals(t, engine, domain, aggregate, now)
	if !signals.hourlyHit || signals.hourlyDistinct != dnsHourlyDistinctLimit+1 {
		t.Fatalf("%d distinct subdomains did not fire: %+v", dnsHourlyDistinctLimit+1, signals)
	}

	// Expired entries are pruned before counting.
	engine.dnsTunnel.mu.Lock()
	state.hourDistinct = map[uint64]time.Time{dnsHash64("expired"): now.Add(-time.Minute)}
	engine.dnsTunnel.mu.Unlock()
	signals = dnsEvaluateSignals(t, engine, domain, aggregate, now)
	if signals.hourlyHit || signals.hourlyDistinct != 0 {
		t.Fatalf("expired hour entries were counted: %+v", signals)
	}
}

func TestDnsTunnelRequiresThreeSimultaneousSignals(t *testing.T) {
	engine := newDnsTestEngine(t)
	now := time.Unix(1_700_000_000, 0).UTC()
	domain := "example.com"
	subdomains := make([]string, 40)
	for index := range subdomains {
		subdomains[index] = dnsTestLabel(index, 48)
	}
	// High-entropy distinct subdomains: entropy + Zipf fire (2 signals).
	aggregate := dnsAggregate(subdomains, 40, 0, false)
	signals := dnsEvaluateSignals(t, engine, domain, aggregate, now)
	if signals.count != 2 || !signals.entropyHit || !signals.zipfHit || signals.fqdnLong || signals.txtShareHit || signals.hourlyHit {
		t.Fatalf("expected exactly entropy+zipf, got %+v", signals)
	}
	// Add the FQDN-length condition: now 3 signals fire.
	aggregate.longFQDN = true
	signals = dnsEvaluateSignals(t, engine, domain, aggregate, now)
	if signals.count != 3 || !signals.fqdnLong {
		t.Fatalf("expected three signals, got %+v", signals)
	}

	// End-to-end: the 2-signal corpus must not produce an incident at all.
	twoSignalEngine := newDnsTestEngine(t)
	shortCorpus := dnsCorpus(1000, 40, "e.com", 40, []uint16{1})
	if len(shortCorpus[0].QName) > dnsLongFQDNThreshold {
		t.Fatalf("test corpus qname unexpectedly long: %q", shortCorpus[0].QName)
	}
	feedDnsEvents(twoSignalEngine, shortCorpus, now)
	if incidents := dnsIncidents(twoSignalEngine); len(incidents) != 0 {
		t.Fatalf("two-signal corpus produced %d incident(s): %+v", len(incidents), incidents)
	}
	// Adding a TXT-heavy share pushes the same domain to three signals.
	txtCorpus := dnsCorpus(2000, 10, "e.com", 40, []uint16{16})
	feedDnsEvents(twoSignalEngine, txtCorpus, now)
	incidents := dnsIncidents(twoSignalEngine)
	if len(incidents) != 1 {
		t.Fatalf("third signal did not produce exactly one incident, got %d", len(incidents))
	}
}

// ------------------------------------------------------------ corpus level tests

func TestDnsTunnelDetectsMultiSignalTunnel(t *testing.T) {
	engine := newDnsTestEngine(t)
	now := time.Unix(1_700_000_000, 0).UTC()
	// 48 distinct high-entropy FQDNs (59 chars), half of them TXT: entropy,
	// Zipf, FQDN length and TXT/NULL share all fire; the hour signal is bounded
	// by the sample size.
	corpus := dnsCorpus(1, 48, "tunnel.example.com", 40, []uint16{1, 16})
	feedDnsEvents(engine, corpus, now)

	incidents := dnsIncidents(engine)
	if len(incidents) != 1 {
		t.Fatalf("expected exactly one XDR.DNS_TUNNEL incident, got %d", len(incidents))
	}
	incident := incidents[0]
	if incident.Score != 100 || incident.Severity != "high" || incident.Decision != "alert" || incident.Action != "none" {
		t.Fatalf("DNS tunnel incident is not the documented alert-only shape: %+v", incident)
	}
	if incident.ResponseScore != 0 || incident.KillSignals != 0 {
		t.Fatalf("DNS tunnel incident carries response/kill weight: %+v", incident)
	}
	if len(incident.Categories) != 2 || incident.Categories[0] != "network" || incident.Categories[1] != "c2" {
		t.Fatalf("categories = %v, want [network c2]", incident.Categories)
	}
	if len(incident.RuleIDs) != 1 || incident.RuleIDs[0] != "XDR.DNS_TUNNEL" {
		t.Fatalf("rule ids = %v", incident.RuleIDs)
	}
	if !strings.Contains(incident.Summary, "example.com") || !strings.Contains(incident.Summary, "signals") {
		t.Fatalf("summary does not name the domain/signals: %q", incident.Summary)
	}
	if incident.Outcome == "" || !strings.Contains(incident.Outcome, "observe") || incident.EvidenceRoot == "" {
		t.Fatalf("incident lacks outcome/evidence root: %+v", incident)
	}
	if len(incident.AttackStory) != 1 {
		t.Fatalf("attack story has %d nodes, want 1", len(incident.AttackStory))
	}
	node := incident.AttackStory[0]
	if node.Sensor != "dns-tunnel" || node.Category != "network" || node.EventType != "DNS_TUNNEL" {
		t.Fatalf("attack-story node wrong: %+v", node)
	}
	if node.Metadata["observe_only"] != "true" || node.Metadata["domain_heuristic"] != "last-two-labels" {
		t.Fatalf("attack-story metadata wrong: %+v", node.Metadata)
	}
	if node.Metadata["signal_count"] != "4" {
		t.Fatalf("expected 4 signals in the attack-story metadata, got %q (%s)",
			node.Metadata["signal_count"], node.Metadata["signals"])
	}
	if node.Digest == "" || incident.ExecutionChainID != node.NodeID {
		t.Fatalf("attack-story digest/chain missing: %+v", incident)
	}
	// The incident also flows through the later GIEF/SBC pipeline stage untouched.
	if incident.GIEF == nil || incident.GIEF.SBCFamily != SBCFamilyC2 {
		t.Fatalf("GIEF envelope not attached by the pipeline: %+v", incident.GIEF)
	}
	// Per-domain dedupe: the same corpus must not emit a second incident.
	feedDnsEvents(engine, corpus, now.Add(time.Minute))
	if got := len(dnsIncidents(engine)); got != 1 {
		t.Fatalf("dedupe failed, %d incidents", got)
	}
	if engine.dnsTunnel.suppressed == 0 {
		t.Fatal("suppressed counter was not incremented for a deduped domain")
	}
}

func TestDnsTunnelBenignDomainsDoNotFire(t *testing.T) {
	engine := newDnsTestEngine(t)
	now := time.Unix(1_700_000_000, 0).UTC()

	benign := func(count int, qname string, qtype uint16) []CoreDnsEvent {
		events := make([]CoreDnsEvent, 0, count)
		for index := 0; index < count; index++ {
			events = append(events, dnsTestEvent(uint64(1)+uint64(index), 4242, qname, qtype, len(qname)))
		}
		return events
	}
	// A typical web session: repeated A/AAAA lookups, a few service hosts.
	feedDnsEvents(engine, benign(120, "www.example.com", 1), now)
	feedDnsEvents(engine, benign(60, "api.example.com", 28), now.Add(7*time.Second))
	feedDnsEvents(engine, benign(60, "example.com", 1), now.Add(14*time.Second))

	// CDN multi-label hostnames: many queries, only a handful of distinct names.
	for index := 0; index < 5; index++ {
		feedDnsEvents(engine, benign(24, fmt.Sprintf("assets-static-%02d.cdn.example.com", index), 1), now.Add(20*time.Second))
	}
	// Long benign CDN hostnames (> 50 chars) but few distinct: the FQDN signal
	// alone (or with entropy) may fire, never three signals.
	for index := 0; index < 5; index++ {
		label := fmt.Sprintf("assets-cdn-static-000%d-abcdefghijklmnopqrst", index)
		qname := label + ".cdn.example.com"
		if len(qname) <= dnsLongFQDNThreshold {
			t.Fatalf("benign long corpus qname is not long enough: %q", qname)
		}
		feedDnsEvents(engine, benign(6, qname, 28), now.Add(30*time.Second))
	}

	if incidents := dnsIncidents(engine); len(incidents) != 0 {
		t.Fatalf("benign DNS activity produced %d incident(s): %+v", len(incidents), incidents)
	}
}

func TestDnsTunnelDedupeAndRecoveryAfterHour(t *testing.T) {
	engine := newDnsTestEngine(t)
	start := time.Unix(1_700_000_000, 0).UTC()

	fire := func(at time.Time, seed int) {
		feedDnsEvents(engine, dnsCorpus(seed, 48, "tunnel.example.com", 40, []uint16{1, 16}), at)
	}
	fire(start, 10)
	if got := len(dnsIncidents(engine)); got != 1 {
		t.Fatalf("first burst produced %d incidents", got)
	}
	// Same domain inside the 1-hour dedupe window: no second incident.
	fire(start.Add(30*time.Minute), 20)
	if got := len(dnsIncidents(engine)); got != 1 {
		t.Fatalf("dedupe window produced %d incidents", got)
	}
	// After the 1-hour dedupe TTL a new burst may produce a new incident.
	fire(start.Add(61*time.Minute), 30)
	if got := len(dnsIncidents(engine)); got != 2 {
		t.Fatalf("after the dedupe TTL expected 2 incidents, got %d", got)
	}
}

func TestDnsTunnelOverflowRateLimited(t *testing.T) {
	engine := newDnsTestEngine(t)
	now := time.Unix(1_700_000_000, 0).UTC()

	engine.consumeDnsEvents(nil, 7, now)
	if events := dnsEventsOfKind(engine, "xdr.dns_capture_overflow"); len(events) != 1 {
		t.Fatalf("first overflow produced %d telemetry events", len(events))
	}
	engine.consumeDnsEvents(nil, 5, now.Add(time.Minute))
	if events := dnsEventsOfKind(engine, "xdr.dns_capture_overflow"); len(events) != 1 {
		t.Fatalf("rate-limited overflow produced %d telemetry events", len(events))
	}
	engine.consumeDnsEvents(nil, 5, now.Add(6*time.Minute))
	if events := dnsEventsOfKind(engine, "xdr.dns_capture_overflow"); len(events) != 2 {
		t.Fatalf("after the rate-limit gap expected 2 telemetry events, got %d", len(events))
	}
	if engine.dnsTunnel.droppedTotal != 17 {
		t.Fatalf("dropped total = %d, want 17", engine.dnsTunnel.droppedTotal)
	}
}

func TestDnsTunnelObservationBounds(t *testing.T) {
	engine := newDnsTestEngine(t)
	now := time.Unix(1_700_000_000, 0).UTC()
	events := make([]CoreDnsEvent, 0, 5000)
	for index := 0; index < 5000; index++ {
		qname := fmt.Sprintf("sub.d%d.example", index%2500)
		events = append(events, dnsTestEvent(uint64(index+1), 4242, qname, 1, len(qname)))
	}
	for start := 0; start < len(events); start += maxDnsEventsPerResponse {
		end := start + maxDnsEventsPerResponse
		if end > len(events) {
			end = len(events)
		}
		engine.consumeDnsEvents(events[start:end], 0, now)
	}
	engine.dnsTunnel.mu.Lock()
	observationCount := engine.dnsTunnel.observationCount
	trackedDomains := len(engine.dnsTunnel.domains)
	evictions := engine.dnsTunnel.windowEvictions
	queries := engine.dnsTunnel.queries
	engine.dnsTunnel.mu.Unlock()
	if observationCount > dnsMaxObservations {
		t.Fatalf("observation ring grew to %d", observationCount)
	}
	if observationCount != dnsMaxObservations {
		t.Fatalf("observation ring = %d, want the %d hard capacity", observationCount, dnsMaxObservations)
	}
	if trackedDomains > dnsMaxDomains {
		t.Fatalf("domain map grew to %d", trackedDomains)
	}
	if trackedDomains != dnsMaxDomains {
		t.Fatalf("domain map = %d, want the %d hard capacity", trackedDomains, dnsMaxDomains)
	}
	if evictions != 5000-dnsMaxObservations {
		t.Fatalf("window evictions = %d, want %d", evictions, 5000-dnsMaxObservations)
	}
	if queries != 5000 {
		t.Fatalf("queries = %d, want 5000", queries)
	}
	report := engine.DNSReport()
	if report.WindowObservations != dnsMaxObservations || report.TrackedDomains != dnsMaxDomains {
		t.Fatalf("report hides the bounded state: %+v", report)
	}
}

// ---------------------------------------------------------- capability honesty

func TestDnsTunnelCapabilityAbsentIsHonest(t *testing.T) {
	engine := newDnsTestEngine(t)
	fake := &fakeDnsCaptureCore{statusErr: ErrDnsUnavailable, eventsErr: ErrDnsUnavailable}
	engine.dnsTunnel.bindCore(fake)
	now := time.Unix(1_700_000_000, 0).UTC()

	if next := engine.pollDnsTunnel(RuntimeSettings{XDREnabled: true}, now, time.Time{}); next.IsZero() {
		t.Fatal("poll returned a zero retry time")
	}
	report := engine.DNSReport()
	if report.State != "unavailable" || report.Capability != "missing" || report.Observation != "unavailable" {
		t.Fatalf("missing capability reported dishonestly: %+v", report)
	}
	if report.Reason == "" {
		t.Fatal("missing capability has no reason")
	}
	if engine.DNSObservationAvailable() {
		t.Fatal("DNSObservationAvailable claimed a channel that does not exist")
	}
	// Missing capability is a capability fact, never an XDR degradation.
	if len(engine.degradeCauses) != 0 {
		t.Fatalf("missing DNS capability degraded the engine: %v", engine.degradeCauses)
	}
	missingEvents := dnsEventsOfKind(engine, "xdr.dns_capture_capability_missing")
	if len(missingEvents) != 1 || missingEvents[0].Severity != "info" {
		t.Fatalf("capability-missing info event wrong: %+v", missingEvents)
	}
	// A repeated poll must not spam the event.
	engine.pollDnsTunnel(RuntimeSettings{XDREnabled: true}, now.Add(10*time.Second), now.Add(10*time.Second))
	if got := len(dnsEventsOfKind(engine, "xdr.dns_capture_capability_missing")); got != 1 {
		t.Fatalf("capability-missing event repeated %d times", got)
	}

	// The core upgrades and advertises the family again.
	fake.statusErr = nil
	fake.eventsErr = nil
	fake.status = CoreDnsStatus{Enabled: true, Attached: true, AttachMask: 3, ReadFailures: 2}
	engine.pollDnsTunnel(RuntimeSettings{XDREnabled: true}, now.Add(20*time.Second), now.Add(20*time.Second))
	report = engine.DNSReport()
	if report.State != "active" || report.Capability != "available" || report.Observation != "available" {
		t.Fatalf("available capability reported dishonestly: %+v", report)
	}
	if !report.Sendto || !report.Sendmsg || !report.Attached || !report.Enabled || report.ReadFailures != 2 {
		t.Fatalf("capability projection loses fields: %+v", report)
	}
	if got := len(dnsEventsOfKind(engine, "xdr.dns_capture_capability_available")); got != 1 {
		t.Fatalf("capability-available info event count = %d", got)
	}
	if engine.DNSObservationAvailable() != true {
		t.Fatal("DNSObservationAvailable did not become available")
	}
	// The status was already enabled, so no arm request may have been sent.
	if len(fake.setCalls) != 0 {
		t.Fatalf("unexpected DNS_SET calls: %v", fake.setCalls)
	}
}

func TestDnsTunnelArmsOnceAndReportsPartialLadder(t *testing.T) {
	engine := newDnsTestEngine(t)
	fake := &fakeDnsCaptureCore{status: CoreDnsStatus{Enabled: false, Attached: true, AttachMask: 1}}
	engine.dnsTunnel.bindCore(fake)
	now := time.Unix(1_700_000_000, 0).UTC()

	engine.pollDnsTunnel(RuntimeSettings{XDREnabled: true}, now, time.Time{})
	engine.pollDnsTunnel(RuntimeSettings{XDREnabled: true}, now.Add(31*time.Second), time.Time{})
	if len(fake.setCalls) != 1 || !fake.setCalls[0] {
		t.Fatalf("DNS_SET arm-once contract broken: %v", fake.setCalls)
	}
	report := engine.DNSReport()
	if report.State != "active" || !report.Sendto || report.Sendmsg {
		t.Fatalf("partial attach ladder reported dishonestly: %+v", report)
	}
	if !strings.Contains(report.Reason, "partial") {
		t.Fatalf("partial ladder has no reason: %q", report.Reason)
	}
}

func TestDnsTunnelPollIgnoresDisabledXDR(t *testing.T) {
	engine := newDnsTestEngine(t)
	fake := &fakeDnsCaptureCore{status: CoreDnsStatus{Enabled: true, Attached: true, AttachMask: 3}}
	engine.dnsTunnel.bindCore(fake)
	now := time.Unix(1_700_000_000, 0).UTC()
	retry := now.Add(time.Minute)
	if next := engine.pollDnsTunnel(RuntimeSettings{XDREnabled: false}, now, retry); !next.Equal(retry) {
		t.Fatalf("disabled XDR advanced the retry time to %v", next)
	}
	if fake.statusCalls != 0 || fake.eventCalls != 0 {
		t.Fatal("disabled XDR queried the core")
	}
}
