package main

import (
	"hash/fnv"
	"math"
	"sort"
	"strings"
	"time"
)

// dnsObservationFromEvent validates/normalises one transported record. A record
// that cannot be grouped (empty/invalid name) is skipped, never guessed.
func dnsObservationFromEvent(event CoreDnsEvent, bucket int64) (dnsObservation, bool) {
	name := dnsNormalizeQName(event.QName)
	if name == "" {
		return dnsObservation{}, false
	}
	fqdnLen := event.FQDNLen
	if fqdnLen <= 0 {
		fqdnLen = len(name)
	}
	domain, subdomain := dnsRegistrableDomain(name)
	if domain == "" {
		return dnsObservation{}, false
	}
	lower := strings.ToLower(subdomain)
	return dnsObservation{
		bucket:    bucket,
		domain:    domain,
		subdomain: lower,
		qname:     name,
		qtype:     event.QType,
		longFQDN:  fqdnLen > dnsLongFQDNThreshold || len(name) > dnsLongFQDNThreshold,
		pid:       event.PID,
		uid:       event.UID,
		comm:      dnsBoundedText(event.Comm, 16),
	}, true
}

func (t *DNSTunnelEngine) appendObservationLocked(observation dnsObservation) {
	if t.observationCount < dnsMaxObservations {
		index := (t.observationHead + t.observationCount) % dnsMaxObservations
		t.observations[index] = observation
		t.observationCount++
		return
	}
	// Ring full: drop the oldest observation and count the eviction. The window
	// stays bounded and the control plane sees the pressure honestly.
	t.observations[t.observationHead] = observation
	t.observationHead = (t.observationHead + 1) % dnsMaxObservations
	t.windowEvictions++
}

func (t *DNSTunnelEngine) pruneWindowLocked(nowBucket int64) {
	oldest := nowBucket - int64(dnsWindowBucketCount) + 1
	for t.observationCount > 0 {
		observation := &t.observations[t.observationHead]
		if observation.bucket >= oldest {
			return
		}
		t.observationHead = (t.observationHead + 1) % dnsMaxObservations
		t.observationCount--
	}
}

// rememberHourDistinctLocked records the subdomain in the per-domain 1-hour
// distinct set. The set is capped at dnsMaxHourDistinct; saturation is recorded
// (and still proves the > 100 threshold).
func (t *DNSTunnelEngine) rememberHourDistinctLocked(observation dnsObservation, now time.Time) {
	state := t.domainStateLocked(observation.domain, now)
	if state.hourDistinct == nil {
		state.hourDistinct = make(map[uint64]time.Time)
	}
	expiry := now.Add(dnsHourWindow)
	for key, until := range state.hourDistinct {
		if !until.After(now) {
			delete(state.hourDistinct, key)
		}
	}
	if len(state.hourDistinct) >= dnsMaxHourDistinct {
		// Hard capacity reached: newer subdomains are not tracked, but the set is
		// already far above the > 100 threshold, so the signal stays truthful.
		return
	}
	state.hourDistinct[dnsHash64(observation.subdomain)] = expiry
}

// domainStateLocked returns the bounded per-domain state, evicting the oldest
// domain when the hard capacity is reached.
func (t *DNSTunnelEngine) domainStateLocked(domain string, now time.Time) *dnsDomainState {
	if state, ok := t.domains[domain]; ok {
		state.lastSeen = now
		return state
	}
	if len(t.domains) >= dnsMaxDomains {
		t.evictOldestDomainLocked()
	}
	state := &dnsDomainState{lastSeen: now, hourDistinct: make(map[uint64]time.Time)}
	t.domains[domain] = state
	return state
}

func (t *DNSTunnelEngine) evictOldestDomainLocked() {
	oldestKey := ""
	var oldest time.Time
	for key, state := range t.domains {
		if oldestKey == "" || state.lastSeen.Before(oldest) {
			oldestKey = key
			oldest = state.lastSeen
		}
	}
	if oldestKey != "" {
		delete(t.domains, oldestKey)
	}
}

// analyzeLocked aggregates the bounded window per domain, evaluates the five
// signals and returns at most dnsMaxDomains deduped triggers.
func (t *DNSTunnelEngine) analyzeLocked(now time.Time, bucket int64) []dnsTunnelTrigger {
	oldest := bucket - int64(dnsWindowBucketCount) + 1
	aggregates := make(map[string]*dnsDomainAggregate)
	for offset := 0; offset < t.observationCount; offset++ {
		index := (t.observationHead + offset) % dnsMaxObservations
		observation := &t.observations[index]
		if observation.bucket < oldest {
			continue
		}
		aggregate, ok := aggregates[observation.domain]
		if !ok {
			aggregate = &dnsDomainAggregate{subdomains: make(map[string]struct{})}
			aggregates[observation.domain] = aggregate
		}
		aggregate.queries++
		if observation.subdomain != "" {
			aggregate.subdomains[observation.subdomain] = struct{}{}
		}
		if dnsQTypeIsTXTOrNull(observation.qtype) {
			aggregate.txtNull++
		}
		if observation.longFQDN {
			aggregate.longFQDN = true
		}
		if aggregate.firstPID == 0 {
			aggregate.firstPID = observation.pid
			aggregate.firstUID = observation.uid
			aggregate.firstComm = observation.comm
		}
		if len(aggregate.sampleSubs) < dnsMaxSampleSubdomains && observation.subdomain != "" {
			if !dnsContainsString(aggregate.sampleSubs, observation.subdomain) {
				aggregate.sampleSubs = append(aggregate.sampleSubs, observation.subdomain)
			}
		}
		if len(aggregate.qtypes) < 4 && !dnsContainsQType(aggregate.qtypes, observation.qtype) {
			aggregate.qtypes = append(aggregate.qtypes, observation.qtype)
		}
		aggregate.lastQName = observation.qname
	}
	if len(aggregates) == 0 {
		t.pruneDedupeLocked(now)
		return nil
	}
	domains := make([]string, 0, len(aggregates))
	for domain := range aggregates {
		domains = append(domains, domain)
	}
	sort.Strings(domains)
	triggers := make([]dnsTunnelTrigger, 0, dnsMinSignals)
	for _, domain := range domains {
		aggregate := aggregates[domain]
		signals := t.evaluateDomainLocked(domain, aggregate, now)
		if signals.count < dnsMinSignals {
			continue
		}
		if !t.claimIncidentLocked(domain, now) {
			t.suppressed++
			continue
		}
		triggers = append(triggers, dnsTunnelTrigger{
			domain:      domain,
			signals:     signals,
			queries:     aggregate.queries,
			windowStart: now.Add(-time.Duration(dnsWindowBucketCount) * dnsWindowBucketWidth),
			firstPID:    aggregate.firstPID,
			firstUID:    aggregate.firstUID,
			firstComm:   aggregate.firstComm,
			sampleSubs:  append([]string(nil), aggregate.sampleSubs...),
			qtypes:      append([]uint16(nil), aggregate.qtypes...),
		})
		if len(triggers) >= 64 {
			break
		}
	}
	t.pruneDedupeLocked(now)
	return triggers
}

// evaluateDomainLocked computes the five documented signals deterministically.
func (t *DNSTunnelEngine) evaluateDomainLocked(domain string, aggregate *dnsDomainAggregate, now time.Time) dnsTunnelSignals {
	signals := dnsTunnelSignals{distinct: len(aggregate.subdomains)}

	// a. Subdomain Shannon entropy: bytes/char of the concatenated distinct
	// leftmost labels. Concatenating the distinct labels (bounded) gives a
	// stable estimate even when a single label is short/truncated.
	if len(aggregate.subdomains) >= dnsMinEntropyLabels {
		entropyBytes := make([]byte, 0, dnsEntropySampleCap)
		for subdomain := range aggregate.subdomains {
			if len(entropyBytes)+len(subdomain) > dnsEntropySampleCap {
				break
			}
			entropyBytes = append(entropyBytes, subdomain...)
		}
		if len(entropyBytes) >= dnsMinEntropyBytes {
			signals.entropy = dnsShannonEntropy(string(entropyBytes))
			signals.entropyHit = signals.entropy > dnsEntropyThreshold
		}
	}

	// b. Zipf deviation: observed distinct subdomains versus the expected
	// distinct count of N draws under a Zipf-like vocabulary.
	if aggregate.queries >= dnsZipfMinQueries {
		expected := dnsZipfExpectedDistinct(aggregate.queries)
		if expected > 0 {
			signals.zipfRatio = float64(signals.distinct) / expected
			signals.zipfHit = signals.zipfRatio >= dnsZipfRatioThreshold
		}
	}

	// c. FQDN length: any observed name longer than 50 presentation chars.
	signals.fqdnLong = aggregate.longFQDN

	// d. TXT/NULL share, with a minimum sample so a 1/1 query cannot fire.
	if aggregate.queries >= dnsTXTNULLMinQueries {
		signals.txtShare = float64(aggregate.txtNull) / float64(aggregate.queries)
		signals.txtShareHit = signals.txtShare > dnsTXTNULLShareThreshold
	}

	// e. Distinct subdomains in the last hour (bounded per-domain set).
	if state, ok := t.domains[domain]; ok {
		for key, until := range state.hourDistinct {
			if !until.After(now) {
				delete(state.hourDistinct, key)
			}
		}
		signals.hourlyDistinct = len(state.hourDistinct)
		signals.hourlyHit = signals.hourlyDistinct > dnsHourlyDistinctLimit
	}

	if signals.entropyHit {
		signals.names = append(signals.names, dnsSignalNames[0])
		signals.count++
	}
	if signals.zipfHit {
		signals.names = append(signals.names, dnsSignalNames[1])
		signals.count++
	}
	if signals.fqdnLong {
		signals.names = append(signals.names, dnsSignalNames[2])
		signals.count++
	}
	if signals.txtShareHit {
		signals.names = append(signals.names, dnsSignalNames[3])
		signals.count++
	}
	if signals.hourlyHit {
		signals.names = append(signals.names, dnsSignalNames[4])
		signals.count++
	}
	return signals
}

// claimIncidentLocked dedupes per registrable domain for one hour.
func (t *DNSTunnelEngine) claimIncidentLocked(domain string, now time.Time) bool {
	if until, ok := t.seen[domain]; ok && now.Before(until) {
		return false
	}
	if len(t.seen) >= dnsMaxIncidentDomains {
		t.pruneDedupeLocked(now)
		if len(t.seen) >= dnsMaxIncidentDomains {
			t.evictOldestDedupeLocked()
		}
	}
	t.seen[domain] = now.Add(dnsIncidentDedupeTTL)
	return true
}

func (t *DNSTunnelEngine) pruneDedupeLocked(now time.Time) {
	for domain, until := range t.seen {
		if !until.After(now) {
			delete(t.seen, domain)
		}
	}
}

func (t *DNSTunnelEngine) evictOldestDedupeLocked() {
	oldestKey := ""
	var oldest time.Time
	for domain, until := range t.seen {
		if oldestKey == "" || until.Before(oldest) {
			oldestKey = domain
			oldest = until
		}
	}
	if oldestKey != "" {
		delete(t.seen, oldestKey)
	}
}

// ------------------------------------------------ deterministic signal math

// dnsShannonEntropy returns the Shannon entropy in bits per byte for `text`.
// The empty string and single-symbol strings have entropy 0.
func dnsShannonEntropy(text string) float64 {
	if len(text) == 0 {
		return 0
	}
	var counts [256]int
	for index := 0; index < len(text); index++ {
		counts[text[index]]++
	}
	total := float64(len(text))
	entropy := 0.0
	for _, count := range counts {
		if count == 0 {
			continue
		}
		probability := float64(count) / total
		entropy -= probability * math.Log2(probability)
	}
	return entropy
}

// dnsZipfExpectedDistinct returns the documented deterministic estimator of the
// number of distinct draws expected under a Zipf-like rank distribution for `n`
// observations:
//
//	expected(n) = n / ln(1 + n)        (natural log), clamped to [1, n]
//
// The estimator is the Heaps/Zipf closed form used for the deviation test; it is
// fixed (no fitted parameters) so the signal is reproducible. The clamps keep the
// ratio defined for tiny samples (one observation can never expect more than one
// distinct value).
func dnsZipfExpectedDistinct(observations int) float64 {
	if observations <= 1 {
		return 1
	}
	expected := float64(observations) / math.Log(1+float64(observations))
	if expected < 1 {
		return 1
	}
	if expected > float64(observations) {
		return float64(observations)
	}
	return expected
}

// dnsZipfDeviation returns distinct/expected under the estimator above.
func dnsZipfDeviation(distinct, observations int) float64 {
	expected := dnsZipfExpectedDistinct(observations)
	if expected <= 0 {
		return 0
	}
	return float64(distinct) / expected
}

// dnsNormalizeQName lowercases and validates a transported query name. It never
// repairs: a name with an empty label or an out-of-range label is rejected.
func dnsNormalizeQName(name string) string {
	name = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
	if name == "" || len(name) > 253 {
		return ""
	}
	labels := strings.Split(name, ".")
	for _, label := range labels {
		if label == "" || len(label) > 63 {
			return ""
		}
		for index := 0; index < len(label); index++ {
			character := label[index]
			if (character >= 'a' && character <= 'z') || (character >= '0' && character <= '9') ||
				character == '-' || character == '_' {
				continue
			}
			return ""
		}
	}
	return name
}

// dnsRegistrableDomain applies the documented last-two-labels heuristic and
// returns (domain, subdomain).
//
//   - single-label names: the label is its own domain, subdomain empty
//     (local search domains / pxy-style forwarders),
//   - two-label names: the whole name is the domain,
//   - longer names: last two labels are the domain, everything before them is
//     the subdomain.
//
// It is a heuristic, not a Public Suffix List implementation; the incident
// metadata names the heuristic so an operator can re-group if needed.
func dnsRegistrableDomain(name string) (string, string) {
	labels := strings.Split(name, ".")
	switch len(labels) {
	case 0:
		return "", ""
	case 1:
		return labels[0], ""
	case 2:
		return name, ""
	default:
		domain := labels[len(labels)-2] + "." + labels[len(labels)-1]
		return domain, strings.Join(labels[:len(labels)-2], ".")
	}
}

// dnsQTypeIsTXTOrNull reports the two covert-channel container types.
func dnsQTypeIsTXTOrNull(qtype uint16) bool {
	return qtype == 16 || qtype == 10
}

func dnsHash64(text string) uint64 {
	hasher := fnv.New64a()
	_, _ = hasher.Write([]byte(text))
	return hasher.Sum64()
}

func dnsContainsString(items []string, want string) bool {
	for _, item := range items {
		if item == want {
			return true
		}
	}
	return false
}

func dnsContainsQType(items []uint16, want uint16) bool {
	for _, item := range items {
		if item == want {
			return true
		}
	}
	return false
}
