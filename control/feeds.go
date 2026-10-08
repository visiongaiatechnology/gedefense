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

	// Priority and TrustWeight decide evaluation order and therefore which
	// entries survive the global entry budget. Lower priority wins; trust
	// weight breaks ties. Both are administrable through Fabric Settings.
	Priority    int `json:"priority,omitempty"`
	TrustWeight int `json:"trust_weight,omitempty"`
	// RefreshMinutes, MaxEntries and MaxDownloadBytes are per-feed overrides.
	// Zero means "inherit the global Threat Intelligence bound".
	RefreshMinutes   int `json:"refresh_minutes,omitempty"`
	MaxEntries       int `json:"max_entries,omitempty"`
	MaxDownloadBytes int `json:"max_download_bytes,omitempty"`
}

// fireholLevelOneFeedID names the one feed whose default action was corrected from
// correlate to block. It is a constant because the settings migration matches on it by
// name, and a typo there would migrate nothing while still reporting success.
const fireholLevelOneFeedID = "firehol-level-1"

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
		ID:   fireholLevelOneFeedID,
		Name: "FireHOL Level 1",
		URL:  "https://iplists.firehol.org/files/firehol_level1.netset",
		// FireHOL level 1 is a curated aggregate of networks already observed attacking
		// or abusing hosts - hijacked netblocks, confirmed attackers and bogons - and
		// upstream documents it as safe to block outright. Correlating it instead meant
		// the engine recorded known-bad sources and then let them through, which is the
		// one outcome a threat feed must not produce.
		Action:      FeedActionBlock,
		Format:      "lines",
		Description: "FireHOL level 1: curated attacker networks and bogons, enforced as a block prefix set",
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
	threatIntelStateSchemaV1   = "vgt-gedefense-threat-intel-state-v1"
	threatIntelStateSchemaV2   = "vgt-gedefense-threat-intel-state-v2"
	threatIntelStateSchemaV3   = "vgt-gedefense-threat-intel-state-v3"
	threatIntelStateSchema     = threatIntelStateSchemaV3
	threatIntelDefaultStateDir = "/var/lib/vgt/gedefense"
	kernelApplyNotApplied      = "NOT_APPLIED"
	kernelApplyApplied         = "APPLIED"
	kernelApplyError           = "ERROR"
	kernelApplyDivergent       = "DIVERGENT"
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
	Status           string     `json:"status,omitempty"` // "OK", "STALE", "CRITICAL", "ERROR", "NEVER_SYNCED"
	// LastGoodFingerprint allows the administrable generation policy to detect a
	// byte-identical re-download without churning the published generation.
	LastGoodFingerprint string `json:"last_good_fingerprint,omitempty"`
}

// computeFeedStatus derives the operational state of one feed. It is
// time-aware: a feed whose last-known-good generation has aged past the
// administrable warning or critical threshold is reported as such instead of
// pretending to be healthy because the last attempt happened to succeed long
// ago.
func computeFeedStatus(s *FeedGenerationState, settings ThreatIntelFabricSettings) string {
	if s == nil || s.LastAttemptAt.IsZero() {
		return "NEVER_SYNCED"
	}
	now := time.Now().UTC()
	if !s.LastGoodAt.IsZero() && settings.StaleCriticalMinutes > 0 {
		if now.Sub(s.LastGoodAt) >= time.Duration(settings.StaleCriticalMinutes)*time.Minute {
			return "CRITICAL"
		}
	}
	if !s.LastGoodAt.IsZero() && settings.StaleWarningMinutes > 0 {
		if now.Sub(s.LastGoodAt) >= time.Duration(settings.StaleWarningMinutes)*time.Minute {
			return "STALE"
		}
	}
	if s.LastError != "" || s.ConsecutiveFails > 0 {
		if s.LastGoodGen > 0 {
			return "STALE"
		}
		return "ERROR"
	}
	return "OK"
}

type ThreatIntelPersistentState struct {
	Schema                      string                          `json:"schema"`
	OverallStatus               string                          `json:"overall_status"`
	LastAttemptAt               time.Time                       `json:"last_attempt_at"`
	LastSuccessfulSyncAt        time.Time                       `json:"last_successful_sync_at"`
	LastPartialSuccessfulSyncAt time.Time                       `json:"last_partial_successful_sync_at,omitempty"`
	LastFullySuccessfulSyncAt   time.Time                       `json:"last_fully_successful_sync_at"`
	KernelApplyLastAt           time.Time                       `json:"kernel_apply_last_at,omitempty"`
	KernelApplyStatus           string                          `json:"kernel_apply_status,omitempty"`
	KernelGeneration            uint64                          `json:"kernel_generation,omitempty"`
	LastKernelAdded             int                             `json:"last_kernel_added"`
	LastKernelDeleted           int                             `json:"last_kernel_deleted"`
	LastKernelError             string                          `json:"last_kernel_error,omitempty"`
	Generation                  uint64                          `json:"generation"`
	Fingerprint                 string                          `json:"fingerprint"`
	Feeds                       map[string]*FeedGenerationState `json:"feeds"`
}

type ThreatIntelTelemetry struct {
	OverallStatus               string                `json:"overall_status"`
	LastAttemptAt               time.Time             `json:"last_attempt_at"`
	LastSuccessfulSyncAt        time.Time             `json:"last_successful_sync_at"`
	LastPartialSuccessfulSyncAt time.Time             `json:"last_partial_successful_sync_at,omitempty"`
	LastFullySuccessfulSyncAt   time.Time             `json:"last_fully_successful_sync_at"`
	KernelApplyLastAt           time.Time             `json:"kernel_apply_last_at,omitempty"`
	KernelApplyStatus           string                `json:"kernel_apply_status,omitempty"`
	KernelGeneration            uint64                `json:"kernel_generation,omitempty"`
	LastKernelAdded             int                   `json:"last_kernel_added"`
	LastKernelDeleted           int                   `json:"last_kernel_deleted"`
	LastKernelError             string                `json:"last_kernel_error,omitempty"`
	Generation                  uint64                `json:"generation"`
	Fingerprint                 string                `json:"fingerprint"`
	BlockVectors                int                   `json:"block_vectors"`
	CorrelateVectors            int                   `json:"correlate_vectors"`
	AnnotateVectors             int                   `json:"annotate_vectors"`
	TotalVectors                int                   `json:"total_vectors"`
	Feeds                       []FeedGenerationState `json:"feeds"`
}

type FeedManager struct {
	mu                          sync.RWMutex
	cfg                         FeedConfig
	live                        *threatIntelRuntime
	client                      *http.Client
	statePath                   string
	lock                        ThreatIntelLock
	feedStates                  map[string]*FeedGenerationState
	blockIndex                  *ThreatIndex // FeedActionBlock -> Kernel XDP + cgroup egress + Styx DROP_THREAT_INTEL
	correlateIndex              *ThreatIndex // FeedActionCorrelateOnly + Block -> XDR Incident Scoring
	annotateIndex               *ThreatIndex // FeedActionAnnotateOnly -> Forensic Flow Tagging
	index                       *ThreatIndex // Backward compatibility alias -> blockIndex
	appliedKernelEntries        map[string]struct{}
	generation                  uint64
	fingerprint                 string
	overallStatus               string
	lastAttemptAt               time.Time
	lastSuccessfulSyncAt        time.Time
	lastPartialSuccessfulSyncAt time.Time
	lastFullySuccessfulSyncAt   time.Time
	kernelApplyLastAt           time.Time
	kernelApplyStatus           string
	kernelGeneration            uint64
	lastKernelAdded             int
	lastKernelDeleted           int
	lastKernelError             string
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

	fabric := defaultThreatIntelFabricSettings(cfg, DefaultThreatFeedSources)

	mgr := &FeedManager{
		cfg:                  cfg,
		live:                 newThreatIntelRuntime(fabric, 0),
		client:               &http.Client{Transport: tr, Timeout: 20 * time.Second, CheckRedirect: checkFeedRedirect},
		statePath:            sFile,
		feedStates:           make(map[string]*FeedGenerationState),
		blockIndex:           blockIdx,
		correlateIndex:       corrIdx,
		annotateIndex:        annotIdx,
		index:                blockIdx,
		appliedKernelEntries: make(map[string]struct{}),
		overallStatus:        "NEVER_SYNCED",
		kernelApplyStatus:    kernelApplyNotApplied,
		fingerprint:          "0000000000000000000000000000000000000000000000000000000000000000",
	}

	for _, src := range DefaultThreatFeedSources {
		mgr.feedStates[src.ID] = &FeedGenerationState{
			ID:     src.ID,
			Name:   src.Name,
			Action: src.Action,
		}
	}

	// Invariant 7: Load persisted last-known-good generation and sync timestamps
	_ = mgr.loadPersistentState()
	return mgr
}

// feedPolicyContextKey carries the configuration snapshot that authorised a
// fetch, so a redirect is always evaluated against the revision that started the
// request rather than against whatever revision is current when the redirect
// arrives.
type feedPolicyContextKey struct{}

// checkFeedRedirect enforces the administrable transport policy. HTTPS, the 443
// destination port, the public-host requirement and resolved-address
// anti-poisoning remain unconditional.
func checkFeedRedirect(req *http.Request, via []*http.Request) error {
	policy, _ := req.Context().Value(feedPolicyContextKey{}).(*threatIntelSnapshot)
	maxRedirects := 2
	allowCrossHost := false
	if policy != nil {
		maxRedirects = policy.settings.Transport.MaxRedirects
		allowCrossHost = policy.settings.Transport.AllowCrossHostRedirect
	}
	if len(via) > maxRedirects {
		return NewThreatIntelSecurityException("too many redirects", nil)
	}
	if req.URL.Scheme != "https" {
		return NewThreatIntelSecurityException("non-HTTPS redirect refused", nil)
	}
	if len(via) > 0 && !strings.EqualFold(req.URL.Hostname(), via[0].URL.Hostname()) && !allowCrossHost {
		return NewThreatIntelSecurityException("cross-host redirect refused", nil)
	}
	if _, err := validateFeedSourceURL(req.URL.String()); err != nil {
		return err
	}
	if policy != nil && !policy.hostAllowed(req.URL.Hostname()) {
		return NewThreatIntelSecurityException("redirect host is outside the configured allowlist", nil)
	}
	return nil
}

func (m *FeedManager) BlockIndex() *ThreatIndex     { return m.blockIndex }
func (m *FeedManager) CorrelateIndex() *ThreatIndex { return m.correlateIndex }
func (m *FeedManager) AnnotateIndex() *ThreatIndex  { return m.annotateIndex }
func (m *FeedManager) Index() *ThreatIndex          { return m.blockIndex }

func (m *FeedManager) Generation() uint64  { m.mu.RLock(); defer m.mu.RUnlock(); return m.generation }
func (m *FeedManager) Fingerprint() string { m.mu.RLock(); defer m.mu.RUnlock(); return m.fingerprint }
func (m *FeedManager) OverallStatus() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.overallStatus != "" {
		return m.overallStatus
	}
	if m.lastAttemptAt.IsZero() {
		return "NEVER_SYNCED"
	}
	return "OK"
}
func (m *FeedManager) LastAttemptAt() time.Time {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.lastAttemptAt
}
func (m *FeedManager) LastSuccessfulSyncAt() time.Time {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.lastSuccessfulSyncAt
}
func (m *FeedManager) LastPartialSuccessfulSyncAt() time.Time {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.lastPartialSuccessfulSyncAt
}
func (m *FeedManager) LastFullySuccessfulSyncAt() time.Time {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.lastFullySuccessfulSyncAt
}
func (m *FeedManager) KernelApplyStatus() (string, time.Time, uint64, string) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	status := m.kernelApplyStatus
	if status == "" {
		status = kernelApplyNotApplied
	}
	return status, m.kernelApplyLastAt, m.kernelGeneration, m.lastKernelError
}

func (m *FeedManager) LockStatus() (bool, time.Time, string, time.Duration) {
	return m.lock.Status()
}

func (m *FeedManager) SnapshotFeedStates() []FeedGenerationState {
	m.mu.RLock()
	defer m.mu.RUnlock()
	settings := m.live.activeSettings()
	out := make([]FeedGenerationState, 0, len(m.feedStates))
	for _, s := range m.feedStates {
		cloned := *s
		cloned.LastGoodItems = nil // omit raw IP array in telemetry status
		cloned.Status = computeFeedStatus(s, settings)
		out = append(out, cloned)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func (m *FeedManager) Telemetry() ThreatIntelTelemetry {
	m.mu.RLock()
	defer m.mu.RUnlock()
	settings := m.live.activeSettings()
	feeds := make([]FeedGenerationState, 0, len(m.feedStates))
	for _, s := range m.feedStates {
		cloned := *s
		cloned.LastGoodItems = nil
		cloned.Status = computeFeedStatus(s, settings)
		feeds = append(feeds, cloned)
	}
	sort.Slice(feeds, func(i, j int) bool { return feeds[i].ID < feeds[j].ID })

	bCount := m.blockIndex.Count()
	cCount := m.correlateIndex.Count()
	aCount := m.annotateIndex.Count()

	status := m.overallStatus
	if status == "" {
		if m.lastAttemptAt.IsZero() {
			status = "NEVER_SYNCED"
		} else if !m.lastFullySuccessfulSyncAt.IsZero() {
			status = "OK"
		} else {
			status = "PARTIAL"
		}
	}

	kernelStatus := m.kernelApplyStatus
	if kernelStatus == "" {
		kernelStatus = kernelApplyNotApplied
	}

	return ThreatIntelTelemetry{
		OverallStatus:               status,
		LastAttemptAt:               m.lastAttemptAt,
		LastSuccessfulSyncAt:        m.lastSuccessfulSyncAt,
		LastPartialSuccessfulSyncAt: m.lastPartialSuccessfulSyncAt,
		LastFullySuccessfulSyncAt:   m.lastFullySuccessfulSyncAt,
		KernelApplyLastAt:           m.kernelApplyLastAt,
		KernelApplyStatus:           kernelStatus,
		KernelGeneration:            m.kernelGeneration,
		LastKernelAdded:             m.lastKernelAdded,
		LastKernelDeleted:           m.lastKernelDeleted,
		LastKernelError:             m.lastKernelError,
		Generation:                  m.generation,
		Fingerprint:                 m.fingerprint,
		BlockVectors:                bCount,
		CorrelateVectors:            cCount,
		AnnotateVectors:             aCount,
		TotalVectors:                bCount + cCount + aCount,
		Feeds:                       feeds,
	}
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
	if doc.Schema != threatIntelStateSchemaV1 && doc.Schema != threatIntelStateSchemaV2 && doc.Schema != threatIntelStateSchemaV3 {
		return errors.New("state schema mismatch")
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if doc.Schema == threatIntelStateSchemaV1 {
		if doc.LastAttemptAt.IsZero() {
			doc.LastAttemptAt = doc.LastSuccessfulSyncAt
		}
		if doc.LastFullySuccessfulSyncAt.IsZero() {
			doc.LastFullySuccessfulSyncAt = doc.LastSuccessfulSyncAt
		}
		if doc.OverallStatus == "" {
			if doc.LastSuccessfulSyncAt.IsZero() {
				doc.OverallStatus = "NEVER_SYNCED"
			} else {
				doc.OverallStatus = "OK"
			}
		}
	}

	m.lastAttemptAt = doc.LastAttemptAt
	m.lastSuccessfulSyncAt = doc.LastSuccessfulSyncAt
	m.lastPartialSuccessfulSyncAt = doc.LastPartialSuccessfulSyncAt
	m.lastFullySuccessfulSyncAt = doc.LastFullySuccessfulSyncAt
	m.overallStatus = doc.OverallStatus
	m.kernelApplyLastAt = doc.KernelApplyLastAt
	// Early 4.1 builds persisted "OK" while the API/UI contract used
	// "APPLIED". Normalize that legacy value during load so operators never see
	// a muted/unknown kernel state after an otherwise successful migration.
	if doc.KernelApplyStatus == "OK" {
		doc.KernelApplyStatus = kernelApplyApplied
	}
	m.kernelApplyStatus = doc.KernelApplyStatus
	if m.kernelApplyStatus == "" {
		m.kernelApplyStatus = kernelApplyNotApplied
	}
	m.kernelGeneration = doc.KernelGeneration
	m.lastKernelAdded = doc.LastKernelAdded
	m.lastKernelDeleted = doc.LastKernelDeleted
	m.lastKernelError = doc.LastKernelError
	m.generation = doc.Generation
	m.fingerprint = doc.Fingerprint

	for id, state := range doc.Feeds {
		if existing, ok := m.feedStates[id]; ok {
			existing.LastGoodItems = state.LastGoodItems
			existing.LastGoodCount = len(state.LastGoodItems)
			existing.LastGoodGen = state.LastGoodGen
			existing.LastGoodAt = state.LastGoodAt
			existing.LastAttemptAt = state.LastAttemptAt
			existing.LastError = state.LastError
			existing.ConsecutiveFails = state.ConsecutiveFails
			existing.LastGoodFingerprint = state.LastGoodFingerprint
			existing.Status = computeFeedStatus(existing, m.live.activeSettings())
		}
	}

	// Recompose through the deterministic, priority-ordered composition so a
	// restart publishes exactly the generation the runtime would have published.
	blockItems, corrItems, annotItems := m.composeGenerationsLocked(m.live.activeSettings())
	m.blockIndex.Replace(blockItems)
	m.correlateIndex.Replace(corrItems)
	m.annotateIndex.Replace(annotItems)
	return nil
}

func (m *FeedManager) savePersistentStateLocked() error {
	doc := ThreatIntelPersistentState{
		Schema:                      threatIntelStateSchema,
		OverallStatus:               m.overallStatus,
		LastAttemptAt:               m.lastAttemptAt,
		LastSuccessfulSyncAt:        m.lastSuccessfulSyncAt,
		LastPartialSuccessfulSyncAt: m.lastPartialSuccessfulSyncAt,
		LastFullySuccessfulSyncAt:   m.lastFullySuccessfulSyncAt,
		KernelApplyLastAt:           m.kernelApplyLastAt,
		KernelApplyStatus:           m.kernelApplyStatus,
		KernelGeneration:            m.kernelGeneration,
		LastKernelAdded:             m.lastKernelAdded,
		LastKernelDeleted:           m.lastKernelDeleted,
		LastKernelError:             m.lastKernelError,
		Generation:                  m.generation,
		Fingerprint:                 m.fingerprint,
		Feeds:                       m.feedStates,
	}
	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(m.statePath), 0o700); err != nil {
		return err
	}
	// Feed state is the record of which indicators were published; it goes through
	// the same symlink-refusing atomic writer as every other store.
	return atomicWriteFile(m.statePath, data, 0o600)
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

	// One sync resolves exactly one configuration snapshot. A revision published
	// while this sync runs is observed by the next sync, never by half of this
	// one.
	snapshot := m.live.current()
	if snapshot == nil {
		return nil, map[string]error{"configuration": errors.New("threat intelligence configuration unavailable")}
	}
	sources := snapshot.orderedSources()
	if len(sources) == 0 {
		return nil, map[string]error{"configuration": errors.New("no threat intelligence source is enabled")}
	}
	concurrency := snapshot.settings.ConcurrentDownloads
	if concurrency < 1 {
		concurrency = 1
	}
	sem := make(chan struct{}, concurrency)
	out := make(chan result, len(sources))
	var wg sync.WaitGroup

	now := time.Now().UTC()
	m.mu.Lock()
	m.lastAttemptAt = now
	m.mu.Unlock()

	for _, src := range sources {
		src := src
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			items, err := m.fetchSource(ctx, src, snapshot)
			out <- result{id: src.ID, url: src.URL, items: items, err: err}
		}()
	}

	wg.Wait()
	close(out)

	errs := make(map[string]error)

	m.mu.Lock()
	defer m.mu.Unlock()

	successCount := 0
	failCount := 0

	for r := range out {
		feedState := m.feedStates[r.id]
		if feedState == nil {
			source, known := snapshot.byID[r.id]
			action := FeedActionCorrelateOnly
			name := r.id
			if known {
				action = source.Action
				name = source.Name
			}
			feedState = &FeedGenerationState{ID: r.id, Name: name, Action: action}
			m.feedStates[r.id] = feedState
		}
		feedState.LastAttemptAt = now

		// Invariant 2: Failed, empty, malformed or truncated downloads must NEVER replace
		// the current active generation.
		if r.err != nil {
			failCount++
			errs[r.url] = r.err
			feedState.LastError = r.err.Error()
			feedState.ConsecutiveFails++
			feedState.Status = computeFeedStatus(feedState, snapshot.settings)
			continue
		}
		if len(r.items) == 0 {
			failCount++
			errEmpty := errors.New("empty download rejected: active generation preserved")
			errs[r.url] = errEmpty
			feedState.LastError = errEmpty.Error()
			feedState.ConsecutiveFails++
			feedState.Status = computeFeedStatus(feedState, snapshot.settings)
			continue
		}

		// Valid download: promote to new last-known-good generation
		successCount++
		feedState.LastGoodItems = r.items
		feedState.LastGoodCount = len(r.items)
		digest := computeFingerprint(r.items)
		// Generation policy: a byte-identical re-download refreshes freshness but
		// does not churn the generation when the operator selected "stable".
		if shouldAdvanceGeneration(feedState, digest, snapshot.settings.Validation) {
			feedState.LastGoodGen++
		}
		feedState.LastGoodFingerprint = digest
		feedState.LastGoodAt = now
		feedState.LastError = ""
		feedState.ConsecutiveFails = 0
		feedState.Status = "OK"
	}

	// Rule 14 / Point 64–67: Correct sync timestamp and status semantics
	if failCount == 0 && successCount == len(sources) {
		m.lastSuccessfulSyncAt = now
		m.lastFullySuccessfulSyncAt = now
		m.overallStatus = "OK"
	} else if successCount > 0 && failCount > 0 {
		m.lastSuccessfulSyncAt = now
		m.lastPartialSuccessfulSyncAt = now
		// Invariant: partial sync does NOT update lastFullySuccessfulSyncAt!
		m.overallStatus = "PARTIAL"
	} else if successCount == 0 {
		// Invariant: total failure updates NEITHER lastSuccessfulSyncAt NOR lastFullySuccessfulSyncAt!
		m.overallStatus = "ERROR"
	}

	// Recompose active generations across all sources in deterministic priority
	// order, then publish the correlation and annotation indices immediately.
	blockUnion, corrUnion, annotUnion := m.composeGenerationsLocked(snapshot.settings)
	m.correlateIndex.Replace(corrUnion)
	m.annotateIndex.Replace(annotUnion)
	_ = m.savePersistentStateLocked()

	return blockUnion, errs
}

// composeGenerationsLocked rebuilds the three published generations from the
// current last-known-good state. Sources are visited in priority order, so the
// global entry budget is spent on the most trusted sources first and the same
// input always produces the same generation. The previous implementation
// iterated a map, which made the surviving subset of a capped union
// non-deterministic between syncs.
func (m *FeedManager) composeGenerationsLocked(settings ThreatIntelFabricSettings) (block, correlate, annotate []string) {
	stateByID := make(map[string]*FeedGenerationState, len(m.feedStates))
	ids := make([]string, 0, len(m.feedStates))
	for id, state := range m.feedStates {
		stateByID[id] = state
		ids = append(ids, id)
	}
	rank := make(map[string]int, len(settings.Feeds))
	for index, feed := range settings.Feeds {
		rank[feed.ID] = index
	}
	sort.Slice(ids, func(i, j int) bool {
		ri, iKnown := rank[ids[i]]
		rj, jKnown := rank[ids[j]]
		if iKnown != jKnown {
			return iKnown
		}
		if iKnown && ri != rj {
			return ri < rj
		}
		return ids[i] < ids[j]
	})

	budget := settings.MaxTotalEntries
	blockSet := make(map[string]struct{})
	corrSet := make(map[string]struct{})
	annotSet := make(map[string]struct{})
	for _, id := range ids {
		state := stateByID[id]
		if state == nil {
			continue
		}
		switch state.Action {
		case FeedActionBlock:
			for _, item := range state.LastGoodItems {
				if budget > 0 && len(blockSet) >= budget {
					break
				}
				blockSet[item] = struct{}{}
				corrSet[item] = struct{}{}
			}
		case FeedActionCorrelateOnly:
			for _, item := range state.LastGoodItems {
				if budget > 0 && len(corrSet) >= budget {
					break
				}
				corrSet[item] = struct{}{}
			}
		case FeedActionAnnotateOnly:
			for _, item := range state.LastGoodItems {
				if budget > 0 && len(annotSet) >= budget {
					break
				}
				annotSet[item] = struct{}{}
			}
		}
	}

	block = make([]string, 0, len(blockSet))
	for item := range blockSet {
		block = append(block, item)
	}
	correlate = make([]string, 0, len(corrSet))
	for item := range corrSet {
		correlate = append(correlate, item)
	}
	annotate = make([]string, 0, len(annotSet))
	for item := range annotSet {
		annotate = append(annotate, item)
	}
	sort.Strings(block)
	sort.Strings(correlate)
	sort.Strings(annotate)
	return block, correlate, annotate
}

// Invariant 5: Kernel diff updates must apply additions before deletions and must never
// publish a new userspace generation until the corresponding kernel update succeeded.
// Rollback on a failed diff is a hard safety invariant and is deliberately not
// administrable.
func (m *FeedManager) ApplyToKernel(core *CoreClient, allowlist []string) (int, int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	settings := m.live.activeSettings()

	// Gather target BLOCK items through the deterministic, priority-ordered
	// composition so the published kernel set does not depend on map iteration
	// order.
	blockItems, _, _ := m.composeGenerationsLocked(settings)
	candidateSet := make(map[string]struct{}, len(blockItems))
	for _, item := range blockItems {
		candidateSet[item] = struct{}{}
	}

	// 1. Calculate Additions & Deletions
	toAdd := make([]string, 0)
	toDel := make([]string, 0)

	for _, it := range blockItems {
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

	// Guard rail: a diff larger than the administrable budget is refused as a
	// whole. A partially applied kernel generation would be worse than none.
	if budget := settings.Kernel.MaximumDiffPerSync; budget > 0 && len(toAdd)+len(toDel) > budget {
		err := NewThreatIntelKernelSyncException(
			fmt.Sprintf("kernel diff of %d entries exceeds the configured budget of %d per sync", len(toAdd)+len(toDel), budget), nil)
		m.kernelApplyLastAt = time.Now().UTC()
		m.kernelApplyStatus = kernelApplyError
		m.lastKernelError = err.Error()
		_ = m.savePersistentStateLocked()
		return 0, 0, err
	}

	previousApplied := make(map[string]struct{}, len(m.appliedKernelEntries))
	for item := range m.appliedKernelEntries {
		previousApplied[item] = struct{}{}
	}

	// 2. Apply ADDITIONS FIRST
	addedItems := make([]string, 0, len(toAdd))
	if core != nil {
		for _, item := range toAdd {
			if err := core.Add(item); err != nil {
				// Addition failed: rollback newly added items immediately and abort publication
				rollbackFailed := false
				for _, rollbackItem := range addedItems {
					if rollbackErr := core.Delete(rollbackItem); rollbackErr != nil {
						rollbackFailed = true
					}
				}
				m.kernelApplyLastAt = time.Now().UTC()
				m.kernelApplyStatus = kernelApplyError
				m.lastKernelError = err.Error()
				if rollbackFailed {
					m.kernelApplyStatus = kernelApplyDivergent
					m.lastKernelError = fmt.Sprintf("%v; addition rollback incomplete", err)
				}
				_ = m.savePersistentStateLocked()
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

	// 3. Apply DELETIONS SECOND. Do not mutate the published in-memory kernel
	// mirror until every deletion succeeds. If one deletion fails, restore the
	// previous generation as far as possible and mark any incomplete rollback as
	// DIVERGENT instead of lying with a successful apply state.
	deletedItems := make([]string, 0, len(toDel))
	if core != nil {
		for _, item := range toDel {
			if err := core.Delete(item); err != nil {
				rollbackFailed := false
				for _, deletedItem := range deletedItems {
					if rollbackErr := core.Add(deletedItem); rollbackErr != nil {
						rollbackFailed = true
					}
				}
				for _, addedItem := range addedItems {
					if rollbackErr := core.Delete(addedItem); rollbackErr != nil {
						rollbackFailed = true
					}
				}
				m.appliedKernelEntries = previousApplied
				m.kernelApplyLastAt = time.Now().UTC()
				m.kernelApplyStatus = kernelApplyError
				m.lastKernelError = err.Error()
				if rollbackFailed {
					m.kernelApplyStatus = kernelApplyDivergent
					m.lastKernelError = fmt.Sprintf("%v; deletion rollback incomplete", err)
				}
				_ = m.savePersistentStateLocked()
				return 0, 0, NewThreatIntelKernelSyncException(
					fmt.Sprintf("kernel block deletion failed for %s; previous generation restored where possible: %v", item, err),
					err,
				)
			}
			deletedItems = append(deletedItems, item)
		}
	} else {
		deletedItems = append(deletedItems, toDel...)
	}

	// 4. Commit the kernel mirror only after the whole diff succeeded.
	m.appliedKernelEntries = make(map[string]struct{}, len(candidateSet))
	for item := range candidateSet {
		m.appliedKernelEntries[item] = struct{}{}
	}

	// 5. ONLY upon full kernel success: Publish new userspace generation & fingerprint
	activeBlockList := make([]string, 0, len(candidateSet))
	for it := range candidateSet {
		activeBlockList = append(activeBlockList, it)
	}

	activeCorrList, activeAnnotList := func() ([]string, []string) {
		_, correlate, annotate := m.composeGenerationsLocked(settings)
		return correlate, annotate
	}()

	m.blockIndex.Replace(activeBlockList)
	m.correlateIndex.Replace(activeCorrList)
	m.annotateIndex.Replace(activeAnnotList)
	m.generation++
	m.fingerprint = computeFingerprint(activeBlockList)
	m.kernelApplyLastAt = time.Now().UTC()
	m.kernelApplyStatus = kernelApplyApplied
	m.kernelGeneration = m.generation
	m.lastKernelAdded = len(addedItems)
	m.lastKernelDeleted = len(deletedItems)
	m.lastKernelError = ""
	_ = m.savePersistentStateLocked()

	return len(addedItems), len(deletedItems), nil
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
	m.kernelApplyLastAt = time.Now().UTC()
	m.kernelApplyStatus = kernelApplyNotApplied
	m.kernelGeneration = m.generation
	m.lastKernelAdded = 0
	m.lastKernelDeleted = cleared
	m.lastKernelError = ""
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

// feedTransientError marks a failure that is worth retrying: a network fault or
// a temporary upstream status. Deterministic rejections (validation or security)
// are never retried.
type feedTransientError struct {
	Message string
	Err     error
}

func (e *feedTransientError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("%s: %v", e.Message, e.Err)
	}
	return e.Message
}

func (e *feedTransientError) Unwrap() error { return e.Err }

func newFeedTransientError(message string, err error) *feedTransientError {
	return &feedTransientError{Message: message, Err: err}
}

// threatFeedRetryable reports whether a failed attempt may be repeated.
func threatFeedRetryable(err error) bool {
	if err == nil {
		return false
	}
	var transient *feedTransientError
	return errors.As(err, &transient)
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

// Invariant 8: Feed fetching requires strict connection/read deadlines, bounded response size,
// bounded token/line size and restricted redirects.
func (m *FeedManager) fetchSource(ctx context.Context, src ThreatFeedSource, snapshot *threatIntelSnapshot) ([]string, error) {
	if snapshot == nil {
		return nil, NewThreatIntelValidationException("threat intelligence configuration unavailable", nil)
	}
	policy := snapshot.settings
	u, err := validateFeedSourceURL(src.URL)
	if err != nil {
		return nil, err
	}
	if !snapshot.hostAllowed(u.Hostname()) {
		return nil, NewThreatIntelSecurityException("feed host is outside the configured allowlist", nil)
	}

	attempts := policy.Retry.Attempts
	if attempts < 1 {
		attempts = 1
	}
	var lastErr error
	for attempt := 1; attempt <= attempts; attempt++ {
		if attempt > 1 {
			backoff := time.Duration(policy.Retry.BackoffSeconds) * time.Second * time.Duration(1<<uint(minInt(attempt-2, 4)))
			timer := time.NewTimer(backoff)
			select {
			case <-ctx.Done():
				timer.Stop()
				return nil, ctx.Err()
			case <-timer.C:
			}
		}
		items, fetchErr := m.fetchSourceOnce(ctx, src, snapshot, u)
		if fetchErr == nil {
			return items, nil
		}
		lastErr = fetchErr
		if !threatFeedRetryable(fetchErr) {
			return nil, fetchErr
		}
	}
	return nil, lastErr
}

func (m *FeedManager) fetchSourceOnce(ctx context.Context, src ThreatFeedSource, snapshot *threatIntelSnapshot, u *url.URL) ([]string, error) {
	policy := snapshot.settings
	maxEntries, maxBytes, timeoutSeconds := snapshot.feedBounds(src)

	feedCtx, cancel := context.WithTimeout(ctx, time.Duration(timeoutSeconds)*time.Second)
	defer cancel()
	feedCtx = context.WithValue(feedCtx, feedPolicyContextKey{}, snapshot)

	req, err := http.NewRequestWithContext(feedCtx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "VGT-GeDefense/4.2.1 sovereign-threat-intel")
	req.Header.Set("Accept", "text/plain, application/json, */*")

	resp, err := m.client.Do(req)
	if err != nil {
		var validation *ThreatIntelValidationException
		var security *ThreatIntelSecurityException
		if errors.As(err, &validation) || errors.As(err, &security) {
			return nil, err
		}
		return nil, newFeedTransientError("feed request failed", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500 {
			return nil, newFeedTransientError(fmt.Sprintf("HTTP %d", resp.StatusCode), nil)
		}
		return nil, NewThreatIntelValidationException(fmt.Sprintf("feed returned HTTP %d", resp.StatusCode), nil)
	}
	if !snapshot.contentAllowed(resp.Header.Get("Content-Type")) {
		return nil, NewThreatIntelSecurityException("feed content type is outside the configured policy", nil)
	}

	lr := io.LimitReader(resp.Body, maxBytes+1)

	isJSON := src.Format == "json" || strings.HasSuffix(strings.ToLower(u.Path), ".json") ||
		strings.Contains(strings.ToLower(resp.Header.Get("Content-Type")), "application/json")

	stats := threatFeedStats{}
	set := make(map[string]struct{})
	if isJSON {
		if err := collectJSONThreatEntries(lr, maxEntries, policy.Validation, set, &stats); err != nil {
			return nil, err
		}
	} else {
		sc := bufio.NewScanner(lr)
		sc.Buffer(make([]byte, 4096), 64*1024)
		var read int64
		for sc.Scan() {
			lineBytes := sc.Bytes()
			read += int64(len(lineBytes) + 1)
			if read > maxBytes {
				return nil, NewThreatIntelSecurityException("feed exceeds bounded size limit", nil)
			}
			value, kind := classifyThreatLine(string(lineBytes), policy.Validation)
			switch kind {
			case threatLineAccepted:
				stats.Candidates++
				stats.Accepted++
				set[value] = struct{}{}
				if len(set) >= maxEntries {
					return finalizeThreatFeed(set, stats, policy.Validation)
				}
			case threatLineMalformed:
				stats.Candidates++
				stats.Malformed++
			case threatLineFiltered:
				stats.Candidates++
				stats.Filtered++
			}
		}
		if err := sc.Err(); err != nil {
			return nil, newFeedTransientError("feed stream read failed", err)
		}
	}
	return finalizeThreatFeed(set, stats, policy.Validation)
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
