// STATUS: DIAMANT VGT SUPREME
// Threat-intelligence types, exceptions, defaults and persisted-state schema
package main

import (
	"fmt"
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

// Persisted threat-intelligence state is the record of the last-known-good
// generation per feed. It carries the anti-rollback floor (ManifestVersion) and
// the exact indicator sets that are served to the kernel, so it is a security
// artifact and not merely telemetry (FIND-023).
//
// The file is therefore written as an authenticated envelope:
//
//   - mode "ed25519": the payload is signed with the operator feed-signing key
//     and verified against the pinned trust anchor on load (local signing
//     deployments, where the private key is present on the host);
//   - mode "manifest-anchor": the payload is bound to a detached, signed feed
//     manifest whose raw bytes are embedded in the envelope. The manifest
//     signature is verified with the pinned key and every per-feed floor, validity
//     window and indicator digest is checked against the authenticated manifest
//     entries (deployments that only verify externally signed manifests).
//
// A plaintext document is only accepted when the whole feed pipeline is
// explicitly unauthenticated (no manifest gate, no pinned key, no local signing):
// in that mode the persisted state cannot weaken an authenticity guarantee that is
// configured off. Every other configuration fails closed on an unsigned or
// unverifiable file, quarantines it and rebuilds the state in memory.
const (
	threatIntelStateEnvelopeSchema = "vgt-gedefense-threat-intel-state-envelope-v1"
	threatIntelStateModeSigned     = "ed25519"
	threatIntelStateModeAnchor     = "manifest-anchor"
	threatIntelStateSignatureTag   = "vgt-gedefense/threat-intel-state/v1\x00"
	// maxThreatIntelStateBytes bounds the state file on read. The state carries
	// the last-known-good item sets, so the bound is generous but not absent:
	// an unbounded os.ReadFile handed an attacker-controlled file straight to the
	// JSON decoder.
	maxThreatIntelStateBytes            = 96 << 20
	threatIntelStateIntegrityEventLimit = 32
	threatIntelStateQuarantineSuffix    = ".untrusted-"
)

// threatIntelStateEnvelope is the authenticated wrapper written for every state
// file in a deployment with a feed trust model. Payload and Manifest are
// base64.StdEncoding encoded JSON documents.
type threatIntelStateEnvelope struct {
	Schema    string `json:"schema"`
	Mode      string `json:"mode"`
	Payload   string `json:"payload,omitempty"`
	Manifest  string `json:"manifest,omitempty"`
	PublicKey string `json:"public_key,omitempty"`
	Signature string `json:"signature,omitempty"`
}

// threatIntelStateIntegrityEvent records one integrity decision about the
// persisted state so the journal, the API and the tests can prove that a
// tampered file was refused instead of silently adopted.
type threatIntelStateIntegrityEvent struct {
	At     time.Time `json:"at"`
	Kind   string    `json:"kind"`
	Detail string    `json:"detail"`
}

// threatIntelStateSignatureMessage domain-separates the state signature from
// feed-manifest signatures so one Ed25519 key can never be confused between the
// two message spaces.
func threatIntelStateSignatureMessage(payload []byte) []byte {
	message := make([]byte, 0, len(threatIntelStateSignatureTag)+len(payload))
	message = append(message, threatIntelStateSignatureTag...)
	message = append(message, payload...)
	return message
}

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

	// Signed-manifest projection (F-03 / CHAIN-009). ManifestVerified is only
	// true for a generation whose detached Ed25519 manifest verified. The hard
	// validity window is the last time this generation may be applied to the
	// kernel; after it the kernel apply is refused and the status degrades.
	ManifestVersion      uint64    `json:"manifest_version,omitempty"`
	ManifestValidUntil   time.Time `json:"manifest_valid_until,omitempty"`
	ManifestVerified     bool      `json:"manifest_verified"`
	ManifestAuthenticity string    `json:"manifest_authenticity,omitempty"` // SIGNED / UNVERIFIED
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
	if !s.ManifestValidUntil.IsZero() && now.After(s.ManifestValidUntil) {
		return "CRITICAL"
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
