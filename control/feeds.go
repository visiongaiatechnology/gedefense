// STATUS: DIAMANT VGT SUPREME
package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// Typed Threat Intelligence Error Hierarchy (Section 1.5.A Compliance)
type ThreatIntelException struct {
	Message string
	Err     error
}

func (e *ThreatIntelException) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("%s: %v", e.Message, e.Err)
	}
	return e.Message
}

func (e *ThreatIntelException) Unwrap() error { return e.Err }

type ThreatIntelValidationException struct{ ThreatIntelException }
type ThreatIntelSecurityException struct{ ThreatIntelException }
type ThreatIntelLockException struct{ ThreatIntelException }
type ThreatIntelKernelSyncException struct{ ThreatIntelException }

func NewThreatIntelValidationException(msg string, err error) *ThreatIntelValidationException {
	return &ThreatIntelValidationException{ThreatIntelException{Message: msg, Err: err}}
}

func NewThreatIntelSecurityException(msg string, err error) *ThreatIntelSecurityException {
	return &ThreatIntelSecurityException{ThreatIntelException{Message: msg, Err: err}}
}

func NewThreatIntelLockException(msg string, err error) *ThreatIntelLockException {
	return &ThreatIntelLockException{ThreatIntelException{Message: msg, Err: err}}
}

func NewThreatIntelKernelSyncException(msg string, err error) *ThreatIntelKernelSyncException {
	return &ThreatIntelKernelSyncException{ThreatIntelException{Message: msg, Err: err}}
}

// FeedAction defines the exact enforcement posture for a Threat Intelligence source.
type FeedAction string

const (
	FeedActionBlock         FeedAction = "BLOCK"
	FeedActionCorrelateOnly FeedAction = "CORRELATE_ONLY"
	FeedActionAnnotateOnly  FeedAction = "ANNOTATE_ONLY"
)

// ThreatFeedSource defines an integrated sovereign feed descriptor.
type ThreatFeedSource struct {
	ID          string     `json:"id"`
	Name        string     `json:"name"`
	URL         string     `json:"url"`
	Action      FeedAction `json:"action"`
	Format      string     `json:"format"` // "json", "lines", "ipsum"
	Description string     `json:"description"`
}

// Default 9 sovereign Threat Intelligence Feeds with explicit action semantics
var DefaultThreatFeedSources = []ThreatFeedSource{
	{
		ID:          "feodo-c2",
		Name:        "Feodo Tracker C2",
		URL:         "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
		Action:      FeedActionBlock,
		Format:      "lines",
		Description: "Botnet C2 IP blocklist from abuse.ch",
	},
	{
		ID:          "spamhaus-drop-v4",
		Name:        "Spamhaus DROP IPv4",
		URL:         "https://www.spamhaus.org/drop/drop_v4.json",
		Action:      FeedActionBlock,
		Format:      "json",
		Description: "Spamhaus Don't Route Or Peer IPv4 list",
	},
	{
		ID:          "spamhaus-drop-v6",
		Name:        "Spamhaus DROP IPv6",
		URL:         "https://www.spamhaus.org/drop/drop_v6.json",
		Action:      FeedActionBlock,
		Format:      "json",
		Description: "Spamhaus Don't Route Or Peer IPv6 list",
	},
	{
		ID:          "cins-badguys",
		Name:        "CINS Army Badguys",
		URL:         "https://cinsscore.com/list/ci-badguys.txt",
		Action:      FeedActionCorrelateOnly,
		Format:      "lines",
		Description: "CINS Army malicious IP list for correlation",
	},
	{
		ID:          "blocklist-de-all",
		Name:        "blocklist.de All",
		URL:         "https://lists.blocklist.de/lists/all.txt",
		Action:      FeedActionCorrelateOnly,
		Format:      "lines",
		Description: "blocklist.de active attack sources for correlation",
	},
	{
		ID:          "emerging-threats-block",
		Name:        "Emerging Threats Block IPs",
		URL:         "https://rules.emergingthreats.net/fwrules/emerging-Block-IPs.txt",
		Action:      FeedActionCorrelateOnly,
		Format:      "lines",
		Description: "Emerging Threats known malicious IPs for correlation",
	},
	{
		ID:          "ipsum-level-1",
		Name:        "IPsum Level 1+",
		URL:         "https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt",
		Action:      FeedActionCorrelateOnly,
		Format:      "ipsum",
		Description: "Aggregated threat intelligence score for correlation",
	},
	{
		ID:          "firehol-level-1",
		Name:        "FireHOL Level 1",
		URL:         "https://iplists.firehol.org/files/firehol_level1.netset",
		Action:      FeedActionCorrelateOnly,
		Format:      "lines",
		Description: "FireHOL level 1 IP list for correlation",
	},
	{
		ID:          "tor-bulk-exit",
		Name:        "Tor Bulk Exit Nodes",
		URL:         "https://check.torproject.org/torbulkexitlist",
		Action:      FeedActionAnnotateOnly,
		Format:      "lines",
		Description: "Tor Project exit nodes for telemetry annotation only",
	},
}

// DefaultThreatFeeds maintains backward compatibility with flat URL string slices.
var DefaultThreatFeeds = func() []string {
	urls := make([]string, len(DefaultThreatFeedSources))
	for i, s := range DefaultThreatFeedSources {
		urls[i] = s.URL
	}
	return urls
}()

const (
	threatIntelLockTTL         = 15 * time.Minute
	threatIntelCronKey         = "vis_threat_intel_cron_sync"
	threatIntelLockKey         = "vis_threat_intel_sync_lock"
	threatIntelStateSchema     = "vgt-gedefense-threat-intel-state-v1"
	threatIntelDefaultStateDir = "/var/lib/vgt/gedefense"
)

// ThreatIntelLock enforces live owner protection. TTL is strictly for crash recovery.
type ThreatIntelLock struct {
	mu          sync.Mutex
	active      bool      // True while the owner goroutine is actively executing Sync()
	ownerID     string    // "operator", "vis_threat_intel_cron_sync"
	acquiredAt  time.Time // In-memory active start time
	persistedAt time.Time // Disk timestamp for post-crash recovery
}

func (l *ThreatIntelLock) TryLock(holder string) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now().UTC()

	// Invariant 6: The sync lock remains owned until the sync completes.
	// As long as active is true, no another sync may begin even if 15m elapsed.
	if l.active {
		elapsed := now.Sub(l.acquiredAt)
		rem := threatIntelLockTTL - (elapsed % threatIntelLockTTL)
		if rem <= 0 {
			rem = threatIntelLockTTL
		}
		return false, rem
	}

	// Crash recovery check across daemon restarts
	if !l.persistedAt.IsZero() && now.Sub(l.persistedAt) < threatIntelLockTTL {
		return false, threatIntelLockTTL - now.Sub(l.persistedAt)
	}

	l.active = true
	l.ownerID = holder
	l.acquiredAt = now
	l.persistedAt = now
	return true, 0
}

func (l *ThreatIntelLock) Unlock() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.active = false
	l.ownerID = ""
	l.persistedAt = time.Time{}
}

func (l *ThreatIntelLock) Status() (bool, time.Time, string, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now().UTC()
	if l.active {
		return true, l.acquiredAt, l.ownerID, threatIntelLockTTL
	}
	if !l.persistedAt.IsZero() && now.Sub(l.persistedAt) < threatIntelLockTTL {
		return true, l.persistedAt, l.ownerID, threatIntelLockTTL - now.Sub(l.persistedAt)
	}
	return false, time.Time{}, "", 0
}

// Strict regex whitelist: eliminates ', ", ;, --, whitespace, tabs, newlines, control characters
var threatTokenRegex = regexp.MustCompile(`^[0-9a-fA-F.:\/]+$`)

func isCloudMetadataNetip(addr netip.Addr) bool {
	if !addr.IsValid() {
		return false
	}
	addr = addr.Unmap()
	if addr.Is4() {
		b := addr.As4()
		// 169.254.0.0/16 Link-Local / IMDS (AWS, GCP, Azure, OCI)
		if b[0] == 169 && b[1] == 254 {
			return true
		}
		// 100.100.100.200 (Alibaba Cloud IMDS)
		if b[0] == 100 && b[1] == 100 && b[2] == 100 && b[3] == 200 {
			return true
		}
		// 168.63.129.16 (Azure WireServer / Host Resolver)
		if b[0] == 168 && b[1] == 63 && b[2] == 129 && b[3] == 16 {
			return true
		}
		return false
	}
	// AWS IMDSv2 IPv6: [fd00:ec2::254]
	awsIMDSv6, _ := netip.ParseAddr("fd00:ec2::254")
	if addr == awsIMDSv6 {
		return true
	}
	if addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast() {
		return true
	}
	return false
}

// parseThreatToken applies strict mathematical length boundary (3 <= len <= 49),
// regex whitelisting, netip validation, and anti-poisoning filtering.
// Invariant 3: Does not discard a threat CIDR merely because an allowlist address falls inside it;
// allowlist precedence is enforced during kernel and Styx evaluation.
func parseThreatToken(tok string) (string, bool) {
	// 1. Length boundary: strictly 3 <= len <= 49
	if len(tok) < 3 || len(tok) > 49 {
		return "", false
	}
	// 2. Regex-Whitelist: ^[0-9a-fA-F.:\/]+$
	if !threatTokenRegex.MatchString(tok) {
		return "", false
	}
	// 3. Validation: Einzel-IPs or CIDR
	var prefix netip.Prefix
	if strings.Contains(tok, "/") {
		parsed, err := netip.ParsePrefix(tok)
		if err != nil {
			return "", false
		}
		// Disallow /0 default route (0.0.0.0/0 or ::/0)
		if parsed.Bits() == 0 {
			return "", false
		}
		if parsed.Addr().Is4() && (parsed.Bits() < 1 || parsed.Bits() > 32) {
			return "", false
		}
		if parsed.Addr().Is6() && (parsed.Bits() < 1 || parsed.Bits() > 128) {
			return "", false
		}
		prefix = parsed.Masked()
	} else {
		addr, err := netip.ParseAddr(tok)
		if err != nil {
			return "", false
		}
		bits := 32
		if addr.Is6() {
			bits = 128
		}
		prefix = netip.PrefixFrom(addr.Unmap(), bits)
	}

	addr := prefix.Addr()
	// 4. Anti-Poisoning: Ausschluss von Loopback, RFC 1918, Multicast, Link-Local, Cloud-Metadata, 0.0.0.0
	if addr.IsLoopback() || addr.IsPrivate() || addr.IsUnspecified() || addr.IsMulticast() || addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast() {
		return "", false
	}
	if isCloudMetadataNetip(addr) {
		return "", false
	}

	return prefix.String(), true
}

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
		ip, network, err := net.ParseCIDR(raw)
		if err != nil {
			continue
		}
		ones, bits := network.Mask.Size()
		if ones < 0 {
			continue
		}
		if bits == 32 {
			four := ip.To4()
			if four == nil {
				continue
			}
			var key [4]byte
			copy(key[:], four)
			key = maskIPv4(key, ones)
			if v4[ones] == nil {
				v4[ones] = make(map[[4]byte]struct{})
			}
			v4[ones][key] = struct{}{}
			continue
		}
		if bits == 128 {
			sixteen := ip.To16()
			if sixteen == nil {
				continue
			}
			var key [16]byte
			copy(key[:], sixteen)
			key = maskIPv6(key, ones)
			if v6[ones] == nil {
				v6[ones] = make(map[[16]byte]struct{})
			}
			v6[ones][key] = struct{}{}
		}
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
	ip := net.ParseIP(raw)
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

// FeedGenerationState tracks the last-known-good state and download history per feed.
type FeedGenerationState struct {
	ID               string     `json:"id"`
	Name             string     `json:"name"`
	Action           FeedAction `json:"action"`
	LastGoodItems    []string   `json:"last_good_items,omitempty"`
	LastGoodCount    int        `json:"last_good_count"`
	LastGoodGen      uint64     `json:"last_good_gen"`
	LastGoodAt       time.Time  `json:"last_good_at,omitempty"`
	LastAttemptAt    time.Time  `json:"last_attempt_at"`
	LastError        string     `json:"last_error,omitempty"`
	ConsecutiveFails int        `json:"consecutive_fails"`
}

type ThreatIntelPersistentState struct {
	Schema               string                          `json:"schema"`
	LastSuccessfulSyncAt time.Time                       `json:"last_successful_sync_at"`
	Generation           uint64                          `json:"generation"`
	Fingerprint          string                          `json:"fingerprint"`
	Feeds                map[string]*FeedGenerationState `json:"feeds"`
}

type FeedManager struct {
	mu                   sync.RWMutex
	cfg                  FeedConfig
	client               *http.Client
	statePath            string
	lock                 ThreatIntelLock
	feedStates           map[string]*FeedGenerationState
	blockIndex           *ThreatIndex // FeedActionBlock -> Kernel XDP + cgroup egress + Styx DROP_THREAT_INTEL
	correlateIndex       *ThreatIndex // FeedActionCorrelateOnly + Block -> XDR Incident Scoring
	annotateIndex        *ThreatIndex // FeedActionAnnotateOnly -> Forensic Flow Tagging
	index                *ThreatIndex // Backward compatibility alias -> blockIndex
	appliedKernelEntries map[string]struct{}
	generation           uint64
	fingerprint          string
	lastSuccessfulSyncAt time.Time
}

func NewFeedManager(cfg FeedConfig, stateDir ...string) *FeedManager {
	dir := threatIntelDefaultStateDir
	if len(stateDir) > 0 && stateDir[0] != "" {
		dir = stateDir[0]
	}
	sFile := filepath.Join(dir, "threat-intel-state.json")

	dialer := &net.Dialer{Timeout: 8 * time.Second, KeepAlive: 30 * time.Second}
	tr := &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(address)
			if err != nil {
				return nil, NewThreatIntelValidationException("invalid feed dial address", err)
			}
			if port != "443" {
				return nil, NewThreatIntelSecurityException("feed destination port refused", nil)
			}
			addresses, err := net.DefaultResolver.LookupIPAddr(ctx, host)
			if err != nil || len(addresses) == 0 {
				return nil, NewThreatIntelSecurityException("feed host resolution failed", err)
			}
			for _, resolved := range addresses {
				if forbiddenFeedIP(resolved.IP) {
					return nil, NewThreatIntelSecurityException("feed host resolved to a forbidden network", nil)
				}
			}
			return dialer.DialContext(ctx, network, net.JoinHostPort(addresses[0].IP.String(), port))
		},
		TLSHandshakeTimeout: 8 * time.Second,
		TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12},
		MaxIdleConns:        4,
		IdleConnTimeout:     30 * time.Second,
		ForceAttemptHTTP2:   true,
	}

	blockIdx := NewThreatIndex()
	corrIdx := NewThreatIndex()
	annotIdx := NewThreatIndex()

	mgr := &FeedManager{
		cfg:                  cfg,
		client:               &http.Client{Transport: tr, Timeout: 20 * time.Second, CheckRedirect: checkFeedRedirect},
		statePath:            sFile,
		feedStates:           make(map[string]*FeedGenerationState),
		blockIndex:           blockIdx,
		correlateIndex:       corrIdx,
		annotateIndex:        annotIdx,
		index:                blockIdx,
		appliedKernelEntries: make(map[string]struct{}),
		fingerprint:          "0000000000000000000000000000000000000000000000000000000000000000",
	}

	for _, src := range DefaultThreatFeedSources {
		mgr.feedStates[src.ID] = &FeedGenerationState{
			ID:     src.ID,
			Name:   src.Name,
			Action: src.Action,
		}
	}

	// Invariant 7: Load persisted last-known-good generation and lastSuccessfulSyncAt
	_ = mgr.loadPersistentState()
	return mgr
}

func checkFeedRedirect(req *http.Request, via []*http.Request) error {
	if len(via) > 2 {
		return NewThreatIntelSecurityException("too many redirects", nil)
	}
	if len(via) > 0 && req.URL.Hostname() != via[0].URL.Hostname() {
		return NewThreatIntelSecurityException("cross-host redirect refused", nil)
	}
	if req.URL.Scheme != "https" {
		return NewThreatIntelSecurityException("non-HTTPS redirect refused", nil)
	}
	return nil
}

func (m *FeedManager) BlockIndex() *ThreatIndex     { return m.blockIndex }
func (m *FeedManager) CorrelateIndex() *ThreatIndex { return m.correlateIndex }
func (m *FeedManager) AnnotateIndex() *ThreatIndex  { return m.annotateIndex }
func (m *FeedManager) Index() *ThreatIndex          { return m.blockIndex }

func (m *FeedManager) Generation() uint64        { m.mu.RLock(); defer m.mu.RUnlock(); return m.generation }
func (m *FeedManager) Fingerprint() string       { m.mu.RLock(); defer m.mu.RUnlock(); return m.fingerprint }
func (m *FeedManager) LastSuccessfulSyncAt() time.Time {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.lastSuccessfulSyncAt
}

func (m *FeedManager) LockStatus() (bool, time.Time, string, time.Duration) {
	return m.lock.Status()
}

func (m *FeedManager) SnapshotFeedStates() []FeedGenerationState {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]FeedGenerationState, 0, len(m.feedStates))
	for _, s := range m.feedStates {
		cloned := *s
		cloned.LastGoodItems = nil // omit raw IP array in telemetry status
		out = append(out, cloned)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func (m *FeedManager) loadPersistentState() error {
	data, err := os.ReadFile(m.statePath)
	if err != nil {
		return err
	}
	var doc ThreatIntelPersistentState
	if err := json.Unmarshal(data, &doc); err != nil {
		return err
	}
	if doc.Schema != threatIntelStateSchema {
		return errors.New("state schema mismatch")
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	m.lastSuccessfulSyncAt = doc.LastSuccessfulSyncAt
	m.generation = doc.Generation
	m.fingerprint = doc.Fingerprint

	var blockItems, corrItems, annotItems []string
	for id, state := range doc.Feeds {
		if existing, ok := m.feedStates[id]; ok {
			existing.LastGoodItems = state.LastGoodItems
			existing.LastGoodCount = len(state.LastGoodItems)
			existing.LastGoodGen = state.LastGoodGen
			existing.LastGoodAt = state.LastGoodAt
			existing.LastAttemptAt = state.LastAttemptAt

			switch existing.Action {
			case FeedActionBlock:
				blockItems = append(blockItems, state.LastGoodItems...)
				corrItems = append(corrItems, state.LastGoodItems...)
			case FeedActionCorrelateOnly:
				corrItems = append(corrItems, state.LastGoodItems...)
			case FeedActionAnnotateOnly:
				annotItems = append(annotItems, state.LastGoodItems...)
			}
		}
	}

	m.blockIndex.Replace(blockItems)
	m.correlateIndex.Replace(corrItems)
	m.annotateIndex.Replace(annotItems)
	return nil
}

func (m *FeedManager) savePersistentStateLocked() error {
	doc := ThreatIntelPersistentState{
		Schema:               threatIntelStateSchema,
		LastSuccessfulSyncAt: m.lastSuccessfulSyncAt,
		Generation:           m.generation,
		Fingerprint:          m.fingerprint,
		Feeds:                m.feedStates,
	}
	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	_ = os.MkdirAll(filepath.Dir(m.statePath), 0o700)
	return os.WriteFile(m.statePath, data, 0o600)
}

// SyncWithLock acquires the lock with live-owner invariant and executes synchronization.
func (m *FeedManager) SyncWithLock(ctx context.Context, holder string) ([]string, map[string]error, error) {
	locked, remaining := m.lock.TryLock(holder)
	if !locked {
		return nil, nil, NewThreatIntelLockException(
			fmt.Sprintf("vis_threat_intel_sync_lock active: held by %s, retry after %s", holder, remaining.Round(time.Second)),
			nil,
		)
	}
	defer m.lock.Unlock()

	items, errs := m.syncInternal(ctx)
	return items, errs, nil
}

func (m *FeedManager) Sync(ctx context.Context) ([]string, map[string]error) {
	items, errs, _ := m.SyncWithLock(ctx, "legacy_sync")
	return items, errs
}

func (m *FeedManager) syncInternal(ctx context.Context) ([]string, map[string]error) {
	type result struct {
		id    string
		url   string
		items []string
		err   error
	}

	sources := DefaultThreatFeedSources
	sem := make(chan struct{}, 3)
	out := make(chan result, len(sources))
	var wg sync.WaitGroup

	now := time.Now().UTC()

	for _, src := range sources {
		src := src
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			items, err := m.fetchSource(ctx, src)
			out <- result{id: src.ID, url: src.URL, items: items, err: err}
		}()
	}

	wg.Wait()
	close(out)

	errs := make(map[string]error)

	m.mu.Lock()
	defer m.mu.Unlock()

	for r := range out {
		feedState := m.feedStates[r.id]
		if feedState == nil {
			feedState = &FeedGenerationState{ID: r.id, Action: FeedActionCorrelateOnly}
			m.feedStates[r.id] = feedState
		}
		feedState.LastAttemptAt = now

		// Invariant 2: Failed, empty, malformed or truncated downloads must NEVER replace
		// the current active generation.
		if r.err != nil {
			errs[r.url] = r.err
			feedState.LastError = r.err.Error()
			feedState.ConsecutiveFails++
			continue
		}
		if len(r.items) == 0 {
			errEmpty := errors.New("empty download rejected: active generation preserved")
			errs[r.url] = errEmpty
			feedState.LastError = errEmpty.Error()
			feedState.ConsecutiveFails++
			continue
		}

		// Valid download: promote to new last-known-good generation
		feedState.LastGoodItems = r.items
		feedState.LastGoodCount = len(r.items)
		feedState.LastGoodGen++
		feedState.LastGoodAt = now
		feedState.LastError = ""
		feedState.ConsecutiveFails = 0
	}

	// Recompose active generations across all sources
	var blockUnion, corrUnion, annotUnion []string
	blockSet := make(map[string]struct{})
	corrSet := make(map[string]struct{})
	annotSet := make(map[string]struct{})

	for _, s := range m.feedStates {
		switch s.Action {
		case FeedActionBlock:
			for _, it := range s.LastGoodItems {
				if len(blockSet) < m.cfg.MaxEntries {
					blockSet[it] = struct{}{}
					corrSet[it] = struct{}{}
				}
			}
		case FeedActionCorrelateOnly:
			for _, it := range s.LastGoodItems {
				if len(corrSet) < m.cfg.MaxEntries {
					corrSet[it] = struct{}{}
				}
			}
		case FeedActionAnnotateOnly:
			for _, it := range s.LastGoodItems {
				if len(annotSet) < m.cfg.MaxEntries {
					annotSet[it] = struct{}{}
				}
			}
		}
	}

	for it := range blockSet {
		blockUnion = append(blockUnion, it)
	}
	for it := range corrSet {
		corrUnion = append(corrUnion, it)
	}
	for it := range annotSet {
		annotUnion = append(annotUnion, it)
	}

	// Update in-memory correlation and annotation indices immediately
	m.correlateIndex.Replace(corrUnion)
	m.annotateIndex.Replace(annotUnion)

	// Update lastSuccessfulSyncAt
	m.lastSuccessfulSyncAt = now
	_ = m.savePersistentStateLocked()

	return blockUnion, errs
}

// Invariant 5: Kernel diff updates must apply additions before deletions and must never
// publish a new userspace generation until the corresponding kernel update succeeded.
func (m *FeedManager) ApplyToKernel(core *CoreClient, allowlist []string) (int, int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Gather target BLOCK items from all active last-good generations of FeedActionBlock feeds
	candidateSet := make(map[string]struct{})
	for _, s := range m.feedStates {
		if s.Action == FeedActionBlock {
			for _, it := range s.LastGoodItems {
				candidateSet[it] = struct{}{}
			}
		}
	}

	// 1. Calculate Additions & Deletions
	toAdd := make([]string, 0)
	toDel := make([]string, 0)

	for it := range candidateSet {
		if _, exists := m.appliedKernelEntries[it]; !exists {
			toAdd = append(toAdd, it)
		}
	}

	for it := range m.appliedKernelEntries {
		if _, exists := candidateSet[it]; !exists {
			toDel = append(toDel, it)
		}
	}

	sort.Strings(toAdd)
	sort.Strings(toDel)

	// 2. Apply ADDITIONS FIRST
	addedItems := make([]string, 0, len(toAdd))
	if core != nil {
		for _, item := range toAdd {
			if err := core.Add(item); err != nil {
				// Addition failed: rollback newly added items immediately and abort publication
				for _, rollbackItem := range addedItems {
					_ = core.Delete(rollbackItem)
				}
				return 0, 0, NewThreatIntelKernelSyncException(
					fmt.Sprintf("kernel block addition failed for %s; rolled back: %v", item, err),
					err,
				)
			}
			addedItems = append(addedItems, item)
		}
	} else {
		addedItems = append(addedItems, toAdd...)
	}

	// 3. Apply DELETIONS SECOND
	deleted := 0
	if core != nil {
		for _, item := range toDel {
			if err := core.Delete(item); err == nil {
				delete(m.appliedKernelEntries, item)
				deleted++
			}
		}
	} else {
		for _, item := range toDel {
			delete(m.appliedKernelEntries, item)
			deleted++
		}
	}

	// 4. Update applied entries with successful additions
	for _, item := range addedItems {
		m.appliedKernelEntries[item] = struct{}{}
	}

	// 5. ONLY upon full kernel success: Publish new userspace generation & fingerprint
	activeBlockList := make([]string, 0, len(candidateSet))
	for it := range candidateSet {
		activeBlockList = append(activeBlockList, it)
	}

	activeCorrSet := make(map[string]struct{})
	activeAnnotSet := make(map[string]struct{})
	for _, s := range m.feedStates {
		for _, it := range s.LastGoodItems {
			switch s.Action {
			case FeedActionBlock, FeedActionCorrelateOnly:
				activeCorrSet[it] = struct{}{}
			case FeedActionAnnotateOnly:
				activeAnnotSet[it] = struct{}{}
			}
		}
	}
	activeCorrList := make([]string, 0, len(activeCorrSet))
	for it := range activeCorrSet {
		activeCorrList = append(activeCorrList, it)
	}
	activeAnnotList := make([]string, 0, len(activeAnnotSet))
	for it := range activeAnnotSet {
		activeAnnotList = append(activeAnnotList, it)
	}

	m.blockIndex.Replace(activeBlockList)
	m.correlateIndex.Replace(activeCorrList)
	m.annotateIndex.Replace(activeAnnotList)
	m.generation++
	m.fingerprint = computeFingerprint(activeBlockList)
	_ = m.savePersistentStateLocked()

	return len(addedItems), deleted, nil
}

func (m *FeedManager) ClearFromKernel(core *CoreClient) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	cleared := 0
	if core != nil {
		for item := range m.appliedKernelEntries {
			if err := core.Delete(item); err == nil {
				cleared++
			}
		}
	}
	m.appliedKernelEntries = make(map[string]struct{})
	m.blockIndex.Replace(nil)
	m.correlateIndex.Replace(nil)
	m.annotateIndex.Replace(nil)
	m.generation++
	m.fingerprint = computeFingerprint(nil)
	_ = m.savePersistentStateLocked()
	return cleared, nil
}

func forbiddenFeedIP(ip net.IP) bool {
	if ip == nil {
		return true
	}
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsUnspecified() || ip.IsMulticast() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast()
}

func validateFeedSourceURL(source string) (*url.URL, error) {
	u, err := url.Parse(source)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Fragment != "" {
		return nil, NewThreatIntelValidationException("invalid HTTPS feed URL", err)
	}
	port := u.Port()
	if port != "" && port != "443" {
		return nil, NewThreatIntelSecurityException("feed destination port refused", nil)
	}
	host := strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
	if host == "localhost" || strings.HasSuffix(host, ".localhost") || strings.HasSuffix(host, ".local") || strings.HasSuffix(host, ".internal") {
		return nil, NewThreatIntelSecurityException("feed hostname is not public", nil)
	}
	if ip := net.ParseIP(host); ip != nil && forbiddenFeedIP(ip) {
		return nil, NewThreatIntelSecurityException("feed IP is not public", nil)
	}
	return u, nil
}

func parseJSONThreatFeed(r io.Reader, maxEntries int) ([]string, error) {
	dec := json.NewDecoder(r)
	set := make(map[string]struct{})
	for {
		t, err := dec.Token()
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, err
		}
		if str, ok := t.(string); ok {
			str = strings.TrimSpace(str)
			if item, valid := parseThreatToken(str); valid {
				set[item] = struct{}{}
				if len(set) >= maxEntries {
					break
				}
			}
		}
	}
	items := make([]string, 0, len(set))
	for x := range set {
		items = append(items, x)
	}
	return items, nil
}

// Invariant 8: Feed fetching requires strict connection/read deadlines, bounded response size,
// bounded token/line size and restricted redirects.
func (m *FeedManager) fetchSource(ctx context.Context, src ThreatFeedSource) ([]string, error) {
	u, err := validateFeedSourceURL(src.URL)
	if err != nil {
		return nil, err
	}
	feedCtx, cancel := context.WithTimeout(ctx, 25*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(feedCtx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "VGT-GeDefense/4.0.1 sovereign-threat-intel")
	req.Header.Set("Accept", "text/plain, application/json, */*")

	resp, err := m.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	lr := io.LimitReader(resp.Body, m.cfg.MaxDownloadBytes+1)

	isJSON := src.Format == "json" || strings.HasSuffix(strings.ToLower(u.Path), ".json") ||
		strings.Contains(strings.ToLower(resp.Header.Get("Content-Type")), "application/json")

	if isJSON {
		return parseJSONThreatFeed(lr, m.cfg.MaxEntries)
	}

	sc := bufio.NewScanner(lr)
	sc.Buffer(make([]byte, 4096), 64*1024)
	set := make(map[string]struct{})
	var read int64
	for sc.Scan() {
		lineBytes := sc.Bytes()
		read += int64(len(lineBytes) + 1)
		if read > m.cfg.MaxDownloadBytes {
			return nil, NewThreatIntelSecurityException("feed exceeds bounded size limit", nil)
		}
		if x, ok := parseThreatLine(string(lineBytes)); ok {
			set[x] = struct{}{}
			if len(set) >= m.cfg.MaxEntries {
				break
			}
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	items := make([]string, 0, len(set))
	for x := range set {
		items = append(items, x)
	}
	return items, nil
}
