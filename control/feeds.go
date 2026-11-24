// STATUS: DIAMANT VGT SUPREME
// Core feed manager wiring: FeedManager, transport/SSRF policy, TUF gate glue
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"log"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

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

	// 3b. IPv4-mapped IPv6 forms (::ffff:a.b.c.d/128) are the same indicator as
	// their IPv4 counterpart. Normalise them to the canonical IPv4 prefix before
	// indexing so feed IOC and observed traffic are evaluated symmetrically
	// (F-17 / CHAIN-015).
	prefix, ok := normalizeThreatPrefix(prefix)
	if !ok {
		return "", false
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

// normalizeThreatPrefix converts an IPv4-mapped IPv6 prefix into the equivalent
// canonical IPv4 prefix and masks the result. A mapped prefix shorter than /96
// has no IPv4 equivalent and is rejected rather than stored as an inert form.
func normalizeThreatPrefix(prefix netip.Prefix) (netip.Prefix, bool) {
	if !prefix.IsValid() {
		return netip.Prefix{}, false
	}
	addr := prefix.Addr()
	bits := prefix.Bits()
	if addr.Is4In6() {
		if bits < 96 {
			return netip.Prefix{}, false
		}
		bits -= 96
		addr = addr.Unmap()
		if !addr.Is4() || bits < 0 || bits > 32 {
			return netip.Prefix{}, false
		}
	}
	prefix = netip.PrefixFrom(addr, bits).Masked()
	if !prefix.IsValid() {
		return netip.Prefix{}, false
	}
	return prefix, true
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
	// AP-9/S09 TUF-grade anti-poisoning projection (capability, epoch,
	// blocked-update counters, R5 isolation mode, bounded rejection ring).
	TUF TUFSecurityStatus `json:"tuf"`
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

	// signingKeys are the operator-pinned Ed25519 keys that authenticate feed
	// manifests. They are bootstrap-only (config file / packaging), never
	// mutable from the dashboard, so a compromised session cannot install a new
	// trust anchor for feed content (F-03 / CHAIN-009).
	signingKeys []ed25519.PublicKey

	// Local operator signing pipeline state (feeds.local_signing). The key is
	// loaded lazily; a load failure is sticky so no sync silently degrades to
	// unsigned operation. feedSigningMu is independent of mu: the key loader
	// performs filesystem I/O and must never run under the manager write lock.
	feedSigningMu        sync.Mutex
	feedSigningKey       *feedSigningKeyPair
	feedSigningErr       error
	localManifestVersion uint64

	// Persisted-state integrity bookkeeping (FIND-023). Everything here is
	// guarded by mu. The events are a bounded audit trail of what happened to the
	// state file (authenticated load, refusal, quarantine, persist refusal) and are
	// exposed through PersistentStateIntegrity so the refusal is observable.
	stateIntegrityEvents []threatIntelStateIntegrityEvent
	stateIntegrityErr    string

	// AP-9/S09 TUF-grade anti-poisoning projection: capability, high-water
	// epoch, Last-Known-Good digest, blocked-update counters and a bounded
	// rejection ring. Guarded by mu; new files own the field layout and logic.
	tuf tufManagerState
	// tufEventSink receives the bounded "feed.poisoning_blocked" state events.
	// It is nil by default (the rejection is still logged and projected through
	// Telemetry); the status/server owner wires state.AddEvent through
	// SetTUFEventSink. Guarded by mu.
	tufEventSink func(Event)
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
	signingKeys, signingKeyErr := parsePinnedFeedSigningKeys(cfg.TrustedSigningKeys)
	if signingKeyErr != nil {
		// Fail closed instead of silently dropping an invalid trust anchor: an
		// unparseable key means no feed can be verified.
		signingKeys = nil
	}
	// Self-heal the documented bootstrap case: local signing is explicitly
	// enabled, the operator key exists, but the public key was not yet pinned.
	// This remains opt-in and rotation-safe (a changed key with an old marker
	// fails closed). The explicit config pin is still preferred.
	if len(signingKeys) == 0 {
		if healedKey, healed, healErr := selfHealFeedSigningPin(cfg, dir); healErr != nil {
			log.Printf("feed signing self-heal refused; feeds fail closed: %v", healErr)
		} else if healed {
			signingKeys = []ed25519.PublicKey{healedKey}
			log.Printf("feed signing self-healed: pinned local operator key %s because feeds.local_signing is enabled and no trust anchor was provisioned", feedSigningFingerprint(healedKey))
		}
	}

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
		signingKeys:          signingKeys,
		fingerprint:          "0000000000000000000000000000000000000000000000000000000000000000",
	}

	for _, src := range DefaultThreatFeedSources {
		mgr.feedStates[src.ID] = &FeedGenerationState{
			ID:     src.ID,
			Name:   src.Name,
			Action: src.Action,
		}
	}

	// The integrity mode of the persisted state follows the feed authenticity
	// configuration. When local signing is enabled the operator key is loaded once
	// here, before the state is read, so a signed state file can be verified during
	// construction and a key-load failure is the same sticky, fail-closed condition
	// the sync pipeline reports.
	if mgr.cfg.LocalSigning {
		if keyFile := strings.TrimSpace(mgr.cfg.SigningKeyFile); keyFile != "" {
			_ = mgr.ensureLocalSigningKey(keyFile)
		}
	}

	// Invariant 7: Load persisted last-known-good generation and sync timestamps.
	// A file that cannot be authenticated is quarantined and never adopted; the
	// manager then starts from its safe defaults instead of trusting the file.
	_ = mgr.loadPersistentState()
	// AP-9/S09: project the persisted TUF high-water register once at startup.
	// A corrupt register is reported here and fails the next sync closed.
	mgr.loadTUFStatusFromRegister()
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

// tufFeedProtectionSnapshot is the S09 semantic-guard adapter for the existing
// feed vocabulary. It maps one parsed feed generation (the indicator list the
// pipeline already produces and promotes into LastGoodItems) onto the
// source-agnostic protection model.
//
// Coverage (honest statement):
//   - Covered: network-indicator feed documents in the ThreatFeedSource
//     vocabulary (line-oriented and JSON IP/CIDR lists, the artifacts that
//     FeedManager fetch/verify/activate handles today). BLOCK entries are the
//     active protection entries and are therefore subject to the 20 % deletion
//     budget, the immutable-zone deletion check and the global-allow check.
//     CORRELATE_ONLY / ANNOTATE_ONLY entries are carried as intel entries so
//     allow/wildcard/regex validation still applies, but they are not counted
//     as protection entries because they never gate traffic.
//   - Not covered by this adapter: regex rule documents, advisory/mitigation
//     documents and allowlist imports. Those pipelines are not wired into
//     FeedManager.syncInternal in this tree; the guard model is generic and
//     ready for them, but connecting them needs an owner outside this file set
//     (reported as an AP-9/S09 integration gap). Feed entries are network
//     indicators, so the path/regex checks structurally find nothing here: for
//     this pipeline the diff budget and wildcard/allow checks are the signal.
func tufFeedProtectionSnapshot(feedID string, action FeedAction, items []string) TUFProtectionSnapshot {
	kind := TUFKindIntel
	if action == FeedActionBlock {
		kind = TUFKindBlockPrefix
	}
	entries := make([]TUFProtectionEntry, 0, len(items))
	for _, item := range items {
		trimmed := strings.TrimSpace(item)
		if trimmed == "" {
			continue
		}
		entries = append(entries, TUFProtectionEntry{
			ID:         "feed:" + feedID + ":" + trimmed,
			Kind:       kind,
			Scope:      trimmed,
			FeedOrigin: feedID,
			Active:     true,
		})
	}
	return TUFProtectionSnapshot{ID: feedID, Origin: "feed", Entries: entries}
}

// tufSyncGateStateLocked resolves the AP-9/S09 threshold envelope, its validity
// window and the anti-rollback epoch against the persisted high-water register
// once for a sync attempt, before any Last-Known Good promotion. A gate
// rejection is fail-closed: every feed keeps serving its previous generation.
func (m *FeedManager) tufSyncGateStateLocked(now time.Time) (tufSyncGate, bool) {
	tufGate := m.tufPrepareSyncGateLocked(now)
	tufGuardBlocked := false
	if tufGate.Active && tufGate.Reject != nil {
		tufGuardBlocked = true
		m.recordTUFBlockedLocked(tufErrorReason(tufGate.Reject), "", now)
	}
	return tufGate, tufGuardBlocked
}

// forbiddenFeedIP delegates to the shared egress destination classifier so the
// feed URL, redirect, dialer and StyX/L7 paths cannot disagree about cloud
// metadata or special-use addresses (F-13 / CHAIN-012).
func forbiddenFeedIP(ip net.IP) bool {
	return IsForbiddenEgressIP(ip)
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
	if ip := net.ParseIP(host); ip != nil {
		if allowed, reason := ClassifyEgressDestination(ip); !allowed {
			return nil, NewThreatIntelSecurityException("feed IP is not public: "+reason, nil)
		}
	} else if ip := parseFlexibleIPv4(host); ip != nil {
		// Alternative integer/hex/octal spellings must not bypass the classifier.
		if allowed, reason := ClassifyEgressDestination(ip); !allowed {
			return nil, NewThreatIntelSecurityException("feed IP is not public: "+reason, nil)
		}
	}
	return u, nil
}
