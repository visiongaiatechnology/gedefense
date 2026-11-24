// STATUS: DIAMANT VGT SUPREME
// IOC/CIDR/domain parsing, ThreatIndex dedupe and JSON/text feed parsers
package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"net/url"
	"sort"
	"strings"
	"sync"
)

func parseThreatLine(line string) (string, bool) {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
		return "", false
	}
	if idx := strings.IndexAny(line, "#;"); idx != -1 {
		line = strings.TrimSpace(line[:idx])
		if line == "" {
			return "", false
		}
	}
	tok := strings.Fields(line)[0]
	tok = strings.TrimRight(tok, ";, ")
	return parseThreatToken(tok)
}

func computeFingerprint(items []string) string {
	if len(items) == 0 {
		return "0000000000000000000000000000000000000000000000000000000000000000"
	}
	sorted := append([]string(nil), items...)
	sort.Strings(sorted)
	hasher := sha256.New()
	for _, item := range sorted {
		hasher.Write([]byte(item))
		hasher.Write([]byte{'\n'})
	}
	return hex.EncodeToString(hasher.Sum(nil))
}

type ThreatIndex struct {
	mu          sync.RWMutex
	v4          map[int]map[[4]byte]struct{}
	v6          map[int]map[[16]byte]struct{}
	v4Lengths   []int
	v6Lengths   []int
	count       int
	generation  uint64
	fingerprint string
}

func NewThreatIndex() *ThreatIndex {
	return &ThreatIndex{
		v4:          make(map[int]map[[4]byte]struct{}),
		v6:          make(map[int]map[[16]byte]struct{}),
		fingerprint: "0000000000000000000000000000000000000000000000000000000000000000",
	}
}

func maskIPv4(ip [4]byte, prefix int) [4]byte {
	for bit := prefix; bit < 32; bit++ {
		byteIndex := bit / 8
		bitIndex := uint(7 - bit%8)
		ip[byteIndex] &^= 1 << bitIndex
	}
	return ip
}

func maskIPv6(ip [16]byte, prefix int) [16]byte {
	for bit := prefix; bit < 128; bit++ {
		byteIndex := bit / 8
		bitIndex := uint(7 - bit%8)
		ip[byteIndex] &^= 1 << bitIndex
	}
	return ip
}

func (t *ThreatIndex) Replace(items []string) {
	v4 := make(map[int]map[[4]byte]struct{})
	v6 := make(map[int]map[[16]byte]struct{})
	for _, raw := range items {
		parsedPrefix, err := netip.ParsePrefix(raw)
		if err != nil {
			continue
		}
		normalized, ok := normalizeThreatPrefix(parsedPrefix)
		if !ok {
			continue
		}
		ones := normalized.Bits()
		addr := normalized.Addr()
		if addr.Is4() {
			var key [4]byte
			copy(key[:], addr.AsSlice())
			if v4[ones] == nil {
				v4[ones] = make(map[[4]byte]struct{})
			}
			v4[ones][key] = struct{}{}
			continue
		}
		var key [16]byte
		copy(key[:], addr.AsSlice())
		if v6[ones] == nil {
			v6[ones] = make(map[[16]byte]struct{})
		}
		v6[ones][key] = struct{}{}
	}
	v4Lengths := make([]int, 0, len(v4))
	v6Lengths := make([]int, 0, len(v6))
	count := 0
	for prefix, entries := range v4 {
		v4Lengths = append(v4Lengths, prefix)
		count += len(entries)
	}
	for prefix, entries := range v6 {
		v6Lengths = append(v6Lengths, prefix)
		count += len(entries)
	}
	sort.Sort(sort.Reverse(sort.IntSlice(v4Lengths)))
	sort.Sort(sort.Reverse(sort.IntSlice(v6Lengths)))
	fp := computeFingerprint(items)

	t.mu.Lock()
	t.v4, t.v6 = v4, v6
	t.v4Lengths, t.v6Lengths = v4Lengths, v6Lengths
	t.count = count
	t.fingerprint = fp
	t.generation++
	t.mu.Unlock()
}

func (t *ThreatIndex) ContainsString(raw string) bool {
	parsedAddr, parseErr := netip.ParseAddr(strings.TrimSpace(raw))
	var ip net.IP
	if parseErr == nil {
		// Central unmap: an IPv4-mapped observation (::ffff:a.b.c.d) must match
		// the same indicators as the plain IPv4 event and the reverse direction
		// (F-17 / CHAIN-015).
		ip = net.IP(parsedAddr.Unmap().AsSlice())
	} else {
		ip = net.ParseIP(raw)
	}
	if ip == nil {
		return false
	}
	t.mu.RLock()
	defer t.mu.RUnlock()
	if four := ip.To4(); four != nil {
		var address [4]byte
		copy(address[:], four)
		for _, prefix := range t.v4Lengths {
			if _, ok := t.v4[prefix][maskIPv4(address, prefix)]; ok {
				return true
			}
		}
		return false
	}
	sixteen := ip.To16()
	if sixteen == nil {
		return false
	}
	var address [16]byte
	copy(address[:], sixteen)
	for _, prefix := range t.v6Lengths {
		if _, ok := t.v6[prefix][maskIPv6(address, prefix)]; ok {
			return true
		}
	}
	return false
}

func (t *ThreatIndex) Count() int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.count
}

func (t *ThreatIndex) Fingerprint() string {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.fingerprint
}

func (t *ThreatIndex) Generation() uint64 {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.generation
}

func parseJSONThreatFeed(r io.Reader, maxEntries int) ([]string, error) {
	set := make(map[string]struct{})
	stats := threatFeedStats{}
	if err := collectJSONThreatEntries(r, maxEntries, ThreatIntelValidationSettings{
		IPv4Enabled: true, IPv6Enabled: true, GenerationPolicy: "bump",
	}, set, &stats); err != nil {
		return nil, err
	}
	items := make([]string, 0, len(set))
	for item := range set {
		items = append(items, item)
	}
	sort.Strings(items)
	return items, nil
}

// collectJSONThreatEntries walks a JSON feed and applies the same
// administrable validation policy as the line-oriented path.
func collectJSONThreatEntries(r io.Reader, maxEntries int, policy ThreatIntelValidationSettings, set map[string]struct{}, stats *threatFeedStats) error {
	dec := json.NewDecoder(r)
	metadata := 0
	for {
		t, err := dec.Token()
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return newFeedTransientError("feed JSON read failed", err)
		}
		str, ok := t.(string)
		if !ok {
			continue
		}
		str = strings.TrimSpace(str)
		if str == "" {
			continue
		}
		// A JSON feed carries more than addresses, and the extra fields are not
		// malformed entries.
		//
		// Every string in the document used to be counted as a candidate, so a feed that
		// pairs each prefix with its metadata scored as though it were corrupt. Spamhaus
		// publishes {"cidr":"1.10.16.0/20","sblid":"SBL256894","rir":"apnic"} - one address
		// to five non-addresses - and was rejected at 833 per mille malformed against a
		// limit of 250. The feed was perfectly healthy; the parser was reading its labels
		// as data, and the integrity guard that exists to catch a feed changing shape was
		// firing on a feed that had not changed at all.
		//
		// A value that cannot be an address is skipped, exactly as a comment line is
		// skipped on the line-oriented path. A value that is address-shaped and still
		// fails validation stays malformed, so the guard keeps its teeth.
		if !couldBeNetworkToken(str) {
			metadata++
			continue
		}
		stats.Candidates++
		item, valid := parseThreatToken(str)
		if !valid {
			stats.Malformed++
			continue
		}
		if !policy.ipv4Allowed(item) || !policy.ipv6Allowed(item) {
			stats.Filtered++
			continue
		}
		stats.Accepted++
		set[item] = struct{}{}
		if len(set) >= maxEntries {
			return nil
		}
	}
	// Skipping non-addresses must not become a way for a feed of pure noise to pass as
	// empty. A document that carried content but yielded not one address is a broken
	// feed, and saying so is the whole point of the validation policy.
	if stats.Candidates == 0 && metadata > 0 {
		return NewThreatIntelValidationException(
			fmt.Sprintf("feed validity failure: %d values were read and none of them was a network address", metadata), nil)
	}
	return nil
}

// couldBeNetworkToken reports whether a value is made only of the characters an address
// or prefix can contain. It is deliberately a character test rather than a parse: the
// question is whether the value was meant to be an address at all, and a value that
// answers no is metadata rather than a corrupt entry.
func couldBeNetworkToken(value string) bool {
	if len(value) > 128 {
		return false
	}
	for _, r := range value {
		switch {
		case r >= '0' && r <= '9':
		case r >= 'a' && r <= 'f':
		case r >= 'A' && r <= 'F':
		case r == '.' || r == ':' || r == '/':
		default:
			return false
		}
	}
	return true
}

// threatFeedStats records how a download behaved so the administrable
// validation policy can reject a corrupt feed without discarding the active
// generation.
type threatFeedStats struct {
	Candidates int
	Accepted   int
	Malformed  int
	Filtered   int
}

func (s threatFeedStats) malformedPermille() int {
	if s.Candidates <= 0 {
		return 0
	}
	return s.Malformed * 1000 / s.Candidates
}

func (s threatFeedStats) acceptedPermille() int {
	if s.Candidates <= 0 {
		return 1000
	}
	return s.Accepted * 1000 / s.Candidates
}

// parseFeedRaw applies one validation policy to one raw payload. It is shared
// by the network path and the local-snapshot path so the indicator set that the
// manifest signs is produced by exactly the same code that later re-derives it.
func parseFeedRaw(src ThreatFeedSource, raw []byte, contentType string, policy ThreatIntelValidationSettings, maxEntries int) ([]string, error) {
	if maxEntries < 1 {
		return nil, NewThreatIntelValidationException("feed entry bound is not configured", nil)
	}
	sourceURL, _ := url.Parse(src.URL)
	isJSON := src.Format == "json" || strings.Contains(strings.ToLower(contentType), "application/json")
	if sourceURL != nil {
		isJSON = isJSON || strings.HasSuffix(strings.ToLower(sourceURL.Path), ".json")
	}

	stats := threatFeedStats{}
	set := make(map[string]struct{})
	if isJSON {
		if err := collectJSONThreatEntries(bytes.NewReader(raw), maxEntries, policy, set, &stats); err != nil {
			return nil, err
		}
	} else {
		sc := bufio.NewScanner(bytes.NewReader(raw))
		sc.Buffer(make([]byte, 4096), 64*1024)
		for sc.Scan() {
			value, kind := classifyThreatLine(sc.Text(), policy)
			switch kind {
			case threatLineAccepted:
				stats.Candidates++
				stats.Accepted++
				set[value] = struct{}{}
			case threatLineMalformed:
				stats.Candidates++
				stats.Malformed++
			case threatLineFiltered:
				stats.Candidates++
				stats.Filtered++
			}
			if len(set) >= maxEntries {
				break
			}
		}
		if err := sc.Err(); err != nil {
			return nil, newFeedTransientError("feed stream read failed", err)
		}
	}
	return finalizeThreatFeed(set, stats, policy)
}

// finalizeThreatFeed applies the validation policy to a completed download. A
// feed that is corrupt beyond the configured malformed threshold, or that
// yields fewer valid entries than the configured ratio, is rejected so the
// active last-known-good generation is preserved.
func finalizeThreatFeed(set map[string]struct{}, stats threatFeedStats, policy ThreatIntelValidationSettings) ([]string, error) {
	if stats.Candidates == 0 {
		return nil, nil
	}
	if stats.Malformed*1000 > policy.MalformedEntryPermille*stats.Candidates {
		return nil, NewThreatIntelValidationException(
			fmt.Sprintf("feed integrity failure: %d of %d entries are malformed (%d per mille, limit %d)",
				stats.Malformed, stats.Candidates, stats.malformedPermille(), policy.MalformedEntryPermille), nil)
	}
	if stats.acceptedPermille() < policy.MinimumValidEntryPermille {
		return nil, NewThreatIntelValidationException(
			fmt.Sprintf("feed validity failure: only %d per mille of entries were usable (minimum %d)",
				stats.acceptedPermille(), policy.MinimumValidEntryPermille), nil)
	}
	items := make([]string, 0, len(set))
	for item := range set {
		items = append(items, item)
	}
	sort.Strings(items)
	return items, nil
}
