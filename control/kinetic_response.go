package main

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

var (
	ErrAllowlistProtected   = errors.New("action rejected: target is within immutable management allowlist")
	ErrBroadSectorProtected = errors.New("action rejected: automated /16 or wider CIDR containment is prohibited")
	ErrRateLimitThrottled   = errors.New("action rejected: response token bucket exhausted")
	ErrSubnetEvidenceLow    = errors.New("action rejected: subnet containment requires multi-source evidence")
	ErrEmergencyStopActive  = errors.New("action rejected: emergency stop is active or cannot be verified")
	ErrResponseNotReady     = errors.New("action rejected: kinetic active response is not safely enabled")
	ErrAutoContainDisabled  = errors.New("action rejected: automatic containment is disabled for target scope")
	ErrKernelStateDivergent = errors.New("kernel containment state may be divergent")
)

// NetworkDecision models a proposed network containment action.
type NetworkDecision struct {
	Target           string        `json:"target"`
	RuleIDs          []string      `json:"rule_ids"`
	Score            int           `json:"score"`
	Confidence       float64       `json:"confidence"`
	ContributorCount int           `json:"contributor_count,omitempty"`
	SuggestedAction  string        `json:"suggested_action"` // "observe", "contain", "block"
	BaseTTL          time.Duration `json:"base_ttl"`
	Reason           string        `json:"reason"`
	EvidenceRoot     string        `json:"evidence_root,omitempty"`
	Timestamp        time.Time     `json:"timestamp"`
}

// TargetReputation tracks historical strike count and decay for adaptive TTL backoff.
type TargetReputation struct {
	StrikeCount  int
	LastStrikeAt time.Time
}

type pendingNetworkChange struct {
	previous       *BlockEntry
	kernelAdded    bool
	proposedStrike TargetReputation
}

// KineticResponseEngine executes safe, verified network containment actions.
type KineticResponseEngine struct {
	mu                sync.RWMutex
	cfg               Config
	state             *State
	core              networkBlockCore
	allowlistNets     []*net.IPNet
	allowlistIPs      map[string]bool
	reputation        map[string]*TargetReputation
	pending           map[string]pendingNetworkChange
	tokensAvailable   int
	tokenLastSec      int64
	bansEnforcedTotal uint64
	bansExpiredTotal  uint64
	throttledTotal    uint64
}

// NewKineticResponseEngine initializes the response pipeline with safety guards.
func NewKineticResponseEngine(cfg Config, state *State, core networkBlockCore) *KineticResponseEngine {
	eng := &KineticResponseEngine{
		cfg:             cfg,
		state:           state,
		core:            core,
		allowlistIPs:    make(map[string]bool),
		reputation:      make(map[string]*TargetReputation),
		pending:         make(map[string]pendingNetworkChange),
		tokensAvailable: cfg.Kinetic.MaxStrikesPerSec,
		tokenLastSec:    time.Now().Unix(),
	}

	eng.UpdateAllowlist(cfg.Defense.Allowlist)
	return eng
}

func (r *KineticResponseEngine) validateActiveResponseLocked(decision NetworkDecision) error {
	if r.state == nil {
		return fmt.Errorf("%w: state unavailable", ErrResponseNotReady)
	}
	if decision.SuggestedAction != "contain" && decision.SuggestedAction != "block" {
		return fmt.Errorf("%w: unsupported active action %q", ErrResponseNotReady, decision.SuggestedAction)
	}
	if r.cfg.Kinetic.EnforcementMode == "observe" {
		return fmt.Errorf("%w: kinetic enforcement mode is observe", ErrResponseNotReady)
	}
	if decision.SuggestedAction == "block" && r.cfg.Kinetic.EnforcementMode != "block" {
		return fmt.Errorf("%w: rule requested block while kinetic mode is %s", ErrResponseNotReady, r.cfg.Kinetic.EnforcementMode)
	}

	networkMode, _ := r.state.Modes()
	if networkMode != "enforce" {
		return fmt.Errorf("%w: global network enforcement is %s", ErrResponseNotReady, networkMode)
	}

	snap := r.state.Snapshot()
	if snap.Release.Phase != ReleasePhaseEnforce || !snap.Release.Ready || snap.Release.EmergencyStop {
		return fmt.Errorf("%w: release phase=%s ready=%t emergency_stop=%t", ErrResponseNotReady, snap.Release.Phase, snap.Release.Ready, snap.Release.EmergencyStop)
	}
	if cov, ok := snap.Coverage.Sensors["xdp_ingress"]; !ok || cov.Status != CoverageOnline || !cov.Required {
		return fmt.Errorf("%w: required ingress sensor is not verified online", ErrResponseNotReady)
	}
	if !snap.AllowlistReady {
		return fmt.Errorf("%w: kernel management allowlist is not synchronized", ErrResponseNotReady)
	}
	if r.cfg.Policy.RequireSigned && !snap.Policy.Verified {
		return fmt.Errorf("%w: signed policy is not verified", ErrResponseNotReady)
	}
	if decision.SuggestedAction == "block" {
		if !snap.CoreConnected || r.core == nil {
			return fmt.Errorf("%w: authenticated kernel core is unavailable", ErrResponseNotReady)
		}
	}
	return nil
}

// UpdateAllowlist recompiles allowlisted IP addresses and subnets.
func (r *KineticResponseEngine) UpdateAllowlist(allowlist []string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.allowlistNets = nil
	r.allowlistIPs = make(map[string]bool)

	// Built-in unroutable and loopback addresses
	defaults := []string{"127.0.0.1", "::1", "0.0.0.0", "::"}
	for _, d := range defaults {
		r.allowlistIPs[d] = true
	}

	// Link-local prefix
	_, linkLocalNet, _ := net.ParseCIDR("fe80::/10")
	if linkLocalNet != nil {
		r.allowlistNets = append(r.allowlistNets, linkLocalNet)
	}

	for _, item := range allowlist {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if strings.Contains(item, "/") {
			_, cidrNet, err := net.ParseCIDR(item)
			if err == nil && cidrNet != nil {
				r.allowlistNets = append(r.allowlistNets, cidrNet)
			}
		} else {
			ip := net.ParseIP(item)
			if ip != nil {
				r.allowlistIPs[ip.String()] = true
			}
		}
	}
}

// IsAllowlistProtected verifies if target overlaps with any allowlisted network (Rule 7 & Point 46).
func (r *KineticResponseEngine) IsAllowlistProtected(target string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.isAllowlistProtectedLocked(target)
}

func (r *KineticResponseEngine) isAllowlistProtectedLocked(target string) bool {
	// 1. Single IP check
	if ip := net.ParseIP(target); ip != nil {
		if r.allowlistIPs[ip.String()] {
			return true
		}
		for _, cidr := range r.allowlistNets {
			if cidr.Contains(ip) {
				return true
			}
		}
		return false
	}

	// 2. CIDR check
	_, targetNet, err := net.ParseCIDR(target)
	if err != nil {
		return true // Fail-safe
	}

	// Check if any allowlisted IP falls inside this target CIDR
	for ipStr := range r.allowlistIPs {
		ip := net.ParseIP(ipStr)
		if ip != nil && targetNet.Contains(ip) {
			return true
		}
	}

	// Check CIDR overlap with allowlist subnets
	for _, allowedNet := range r.allowlistNets {
		if targetNet.Contains(allowedNet.IP) || allowedNet.Contains(targetNet.IP) {
			return true
		}
	}

	return false
}

// ExecuteDecision processes a network containment proposal through all safety gates (Points 41–50).
func (r *KineticResponseEngine) ExecuteDecision(decision NetworkDecision) (BlockEntry, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := decision.Timestamp
	if now.IsZero() {
		now = time.Now().UTC()
	}

	// Gate 0: Emergency Stop. Kinetic response must stop creating new bans
	// immediately even if release state is stale or the dashboard is unavailable.
	if path := strings.TrimSpace(r.cfg.Release.EmergencyStopFile); path != "" {
		if _, err := os.Stat(path); err == nil {
			return BlockEntry{}, ErrEmergencyStopActive
		} else if !errors.Is(err, os.ErrNotExist) {
			return BlockEntry{}, fmt.Errorf("%w: %v", ErrEmergencyStopActive, err)
		}
	}

	normalizedTarget, err := normalizeTarget(decision.Target)
	if err != nil {
		return BlockEntry{}, err
	}
	decision.Target = normalizedTarget

	// Gate 1: Management Allowlist Immunity (Point 49)
	if r.isAllowlistProtectedLocked(normalizedTarget) {
		return BlockEntry{}, ErrAllowlistProtected
	}

	// Gate 2: Macro /16 Sector Protective Latch (Point 45)
	if isBroadSectorCIDR(normalizedTarget) {
		return BlockEntry{}, ErrBroadSectorProtected
	}

	// Gate 2.5: Operator-scoped automatic containment controls. Detection remains
	// active when these switches are disabled; only the automatic mutation is
	// suppressed. Safety gates above intentionally win so allowlist and broad-CIDR
	// violations never get hidden behind a softer configuration suppression.
	if !r.autoContainAllowedLocked(normalizedTarget) {
		return BlockEntry{}, ErrAutoContainDisabled
	}

	// Gate 3: Subnet Evidence Verification (Point 43)
	if isSubnetCIDR(normalizedTarget) {
		minimumSources := 2
		if isIPv4Subnet24(normalizedTarget) {
			minimumSources = r.cfg.Kinetic.SubnetMinSources
		} else if isIPv6Subnet64(normalizedTarget) {
			minimumSources = r.cfg.Kinetic.IPv6SubnetMinSources
		}
		if minimumSources < 2 {
			minimumSources = 2
		}
		if decision.Score < 90 || decision.Confidence < 0.90 || decision.ContributorCount < minimumSources {
			return BlockEntry{}, ErrSubnetEvidenceLow
		}
	}

	// Gate 4: Live release/sensor/policy truth. Static config is not enough: a
	// degraded ingress sensor, unsynchronized management allowlist or a release
	// fail-safe transition must stop new automatic containments immediately.
	if err := r.validateActiveResponseLocked(decision); err != nil {
		return BlockEntry{}, err
	}

	// Gate 5: Token Bucket Rate Limiting (Point 49)
	sec := now.Unix()
	if sec != r.tokenLastSec {
		r.tokenLastSec = sec
		r.tokensAvailable = r.cfg.Kinetic.MaxStrikesPerSec
	}
	if r.tokensAvailable <= 0 {
		r.throttledTotal++
		return BlockEntry{}, ErrRateLimitThrottled
	}
	r.tokensAvailable--

	// Gate 6: Reputation Decay & Exponential Backoff TTL (Point 45). Calculate
	// the next reputation state now but commit it only after signed-policy
	// persistence succeeds. Failed kernel/policy transactions must not create
	// phantom repeat offenders.
	targetKey := normalizedTarget
	proposedRep := TargetReputation{StrikeCount: 1, LastStrikeAt: now}
	if rep, exists := r.reputation[targetKey]; exists && rep != nil {
		if now.Sub(rep.LastStrikeAt) <= 48*time.Hour {
			proposedRep.StrikeCount = rep.StrikeCount + 1
		}
	}

	// Calculate adaptive TTL with exponential backoff
	ttl := decision.BaseTTL
	if ttl <= 0 {
		ttl = time.Duration(r.cfg.Kinetic.BanTTLSeconds) * time.Second
	}
	if proposedRep.StrikeCount > 1 {
		multiplier := 1 << (proposedRep.StrikeCount - 1)
		ttl = ttl * time.Duration(multiplier)
	}
	maxTTL := time.Duration(r.cfg.Defense.MaxTTLSeconds) * time.Second
	if maxTTL > 0 && ttl > maxTTL {
		ttl = maxTTL
	}

	// Gate 7: Enforcement Mode check. A global block-capable mode must not
	// silently upgrade a contain-only rule into a kernel DROP. The decision's
	// suggested action is produced by the rule registry eligibility gates.
	mode := r.cfg.Kinetic.EnforcementMode
	enforceInKernel := mode == "block" && decision.SuggestedAction == "block"

	previous, hadPrevious := r.state.BlockByTarget(normalizedTarget)

	// Apply block to State
	maxBlocks := r.cfg.Defense.MaxBlockEntries
	if maxBlocks <= 0 {
		maxBlocks = 250000
	}
	entry, err := r.state.AddBlockAt(normalizedTarget, decision.Reason, "kinetic", ttl, enforceInKernel, maxBlocks, now)
	if err != nil {
		return BlockEntry{}, err
	}

	// Never let an automatic Kinetic update weaken a pre-existing policy. It
	// may extend a Kinetic TTL or add kernel enforcement, but it may not shorten
	// an existing TTL, remove enforcement, or rewrite the provenance/reason of a
	// manual/feed rule that happened to target the same CIDR.
	if hadPrevious {
		if previous.ExpiresAt.After(entry.ExpiresAt) {
			entry.ExpiresAt = previous.ExpiresAt
		}
		entry.Enforced = previous.Enforced || entry.Enforced
		entry.CreatedAt = previous.CreatedAt
		entry.Source = previous.Source
		if previous.Source != "kinetic" {
			entry.Reason = previous.Reason
		}
		r.state.RestoreBlock(entry)
	}

	// Apply to Rust Core LPM Map if enforce mode active and core connected
	kernelAdded := enforceInKernel && (!hadPrevious || !previous.Enforced)
	if kernelAdded {
		if r.core == nil {
			if hadPrevious {
				r.state.RestoreBlock(previous)
			} else {
				r.state.RemoveBlockByID(entry.ID)
			}
			return BlockEntry{}, fmt.Errorf("%w: kernel core is nil", ErrResponseNotReady)
		}
		if err := r.core.Add(entry.Target); err != nil {
			// Compensate a possibly-partial privileged mutation. Restore userspace
			// truth regardless, then surface explicit divergence if compensation
			// cannot prove the kernel clean.
			deleteErr := r.core.Delete(entry.Target)
			if hadPrevious {
				r.state.RestoreBlock(previous)
			} else {
				r.state.RemoveBlockByID(entry.ID)
			}
			if deleteErr != nil {
				return BlockEntry{}, errors.Join(
					fmt.Errorf("kernel LPM trie sync failed: %w", err),
					fmt.Errorf("%w: compensating delete failed: %v", ErrKernelStateDivergent, deleteErr),
				)
			}
			return BlockEntry{}, fmt.Errorf("kernel LPM trie sync failed: %w", err)
		}
	}

	change := pendingNetworkChange{kernelAdded: kernelAdded, proposedStrike: proposedRep}
	if hadPrevious {
		copyPrevious := previous
		change.previous = &copyPrevious
	}
	r.pending[entry.ID] = change

	// Do not publish containment evidence or success counters here. The caller
	// must first persist the signed policy generation. This keeps "enforced"
	// telemetry truthful if durable policy persistence fails and the action has
	// to be rolled back.
	return entry, nil
}

// CommitApplied records a containment only after the signed policy generation
// has been durably persisted. ExecuteDecision intentionally stops before this
// point so failed persistence cannot leave success evidence behind.
func (r *KineticResponseEngine) CommitApplied(decision NetworkDecision, entry BlockEntry) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if change, ok := r.pending[entry.ID]; ok {
		rep := change.proposedStrike
		r.reputation[entry.Target] = &rep
		delete(r.pending, entry.ID)
	}

	now := decision.Timestamp
	if now.IsZero() {
		now = time.Now().UTC()
	}
	ttl := entry.ExpiresAt.Sub(entry.CreatedAt)
	if ttl < 0 {
		ttl = 0
	}
	evidenceErr := r.state.RecordEvidence(EvidenceRecord{
		ID:       entry.ID,
		Time:     now,
		Severity: "high",
		Kind:     "kinetic_containment",
		Source:   "kinetic_response_engine",
		Message:  fmt.Sprintf("Contained target %s for %s (%s, Score: %d)", entry.Target, ttl, decision.Reason, decision.Score),
		Target:   entry.Target,
	})
	r.bansEnforcedTotal++
	if r.state != nil {
		r.state.UpdateKineticTelemetry(func(t *KineticTelemetry) {
			t.BansEnforcedTotal++
			t.ResponseAppliedTotal++
			strike := now.UTC()
			t.LastStrikeAt = &strike
		})
	}
	return evidenceErr
}

// RollbackApplied restores the exact pre-decision userspace state and undoes
// only the kernel rule introduced by this transaction. This is critical when a
// Kinetic decision extends an already-existing manual/feed rule: a later policy
// persistence failure must not delete or weaken that older rule.
func (r *KineticResponseEngine) RollbackApplied(entry BlockEntry) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	change, ok := r.pending[entry.ID]
	if !ok {
		return errors.New("kinetic rollback transaction is unavailable")
	}
	delete(r.pending, entry.ID)

	var kernelErr error
	if change.kernelAdded {
		if r.core == nil {
			kernelErr = errors.New("kernel rollback core is unavailable")
		} else if err := r.core.Delete(entry.Target); err != nil {
			kernelErr = err
		}
	}
	if change.previous != nil {
		r.state.RestoreBlock(*change.previous)
	} else {
		r.state.RemoveBlockByID(entry.ID)
	}
	if kernelErr != nil {
		return fmt.Errorf("%w: rollback delete %s: %v", ErrKernelStateDivergent, entry.Target, kernelErr)
	}
	return nil
}

// RecordApplyRollback makes a failed durable-commit rollback forensically
// explicit without incrementing the successful-ban counter.
func (r *KineticResponseEngine) RecordApplyRollback(decision NetworkDecision, entry BlockEntry, cause error, rollbackErr error) {
	now := decision.Timestamp
	if now.IsZero() {
		now = time.Now().UTC()
	}
	message := fmt.Sprintf("Containment for %s rolled back because policy persistence failed: %v", entry.Target, cause)
	severity := "high"
	if rollbackErr != nil {
		severity = "critical"
		message = fmt.Sprintf("Containment rollback for %s failed after policy persistence error: persist=%v rollback=%v", entry.Target, cause, rollbackErr)
	}
	if r.state != nil {
		r.state.UpdateKineticTelemetry(func(t *KineticTelemetry) {
			t.ResponseRollbackTotal++
			if rollbackErr != nil {
				t.ResponseFailedTotal++
			}
		})
	}
	_ = r.state.RecordEvidence(EvidenceRecord{
		ID:       randomID(),
		Time:     now,
		Severity: severity,
		Kind:     "kinetic_apply_rollback",
		Source:   "kinetic_response_engine",
		Message:  message,
		Target:   entry.Target,
	})
}

func (r *KineticResponseEngine) RecordSuppressed() {
	if r == nil || r.state == nil {
		return
	}
	r.state.UpdateKineticTelemetry(func(t *KineticTelemetry) { t.ResponseSuppressedTotal++ })
}

func (r *KineticResponseEngine) RecordFailure() {
	if r == nil || r.state == nil {
		return
	}
	r.state.UpdateKineticTelemetry(func(t *KineticTelemetry) { t.ResponseFailedTotal++ })
}

func isBroadSectorCIDR(target string) bool {
	if !strings.Contains(target, "/") {
		return false
	}
	_, ipNet, err := net.ParseCIDR(target)
	if err != nil {
		return false
	}
	ones, bits := ipNet.Mask.Size()
	// IPv4 <= /16 or IPv6 <= /48
	if bits == 32 && ones <= 16 {
		return true
	}
	if bits == 128 && ones <= 48 {
		return true
	}
	return false
}

func isSubnetCIDR(target string) bool {
	if !strings.Contains(target, "/") {
		return false
	}
	_, ipNet, err := net.ParseCIDR(target)
	if err != nil {
		return false
	}
	ones, bits := ipNet.Mask.Size()
	// IPv4 /24 or IPv6 /64
	if bits == 32 && ones == 24 {
		return true
	}
	if bits == 128 && ones == 64 {
		return true
	}
	return false
}

func isIPv4Subnet24(target string) bool {
	_, ipNet, err := net.ParseCIDR(target)
	if err != nil {
		return false
	}
	ones, bits := ipNet.Mask.Size()
	return bits == 32 && ones == 24
}

func isIPv6Subnet64(target string) bool {
	_, ipNet, err := net.ParseCIDR(target)
	if err != nil {
		return false
	}
	ones, bits := ipNet.Mask.Size()
	return bits == 128 && ones == 64
}

func (r *KineticResponseEngine) autoContainAllowedLocked(target string) bool {
	if isIPv4Subnet24(target) {
		return r.cfg.Kinetic.AutoContainIPv4Subnet
	}
	if isIPv6Subnet64(target) {
		return r.cfg.Kinetic.AutoContainIPv6Subnet
	}
	// Broad sectors are rejected by the dedicated macro-prefix gate. Any other
	// exact /32-/128 target is governed by the single-IP response control.
	_, network, err := net.ParseCIDR(target)
	if err != nil || network == nil {
		return false
	}
	ones, bits := network.Mask.Size()
	if (bits == 32 && ones == 32) || (bits == 128 && ones == 128) {
		return r.cfg.Kinetic.AutoContainSingleIP
	}
	return false
}

// UpdateConfig atomically refreshes runtime Kinetic and network containment limits.
func (r *KineticResponseEngine) UpdateConfig(kinetic KineticRuntimeSettings, network NetworkRuntimeSettings) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.cfg.Kinetic = kineticConfigFromRuntime(r.cfg.Kinetic, kinetic)
	r.cfg.Defense.DefaultTTLSeconds = network.DefaultTTLSeconds
	r.cfg.Defense.MaxTTLSeconds = network.MaxTTLSeconds
	r.cfg.Defense.MaxBlockEntries = network.MaxBlockEntries
	r.cfg.Defense.StrictASNDrop = network.StrictASNDrop
	if r.tokensAvailable > r.cfg.Kinetic.MaxStrikesPerSec {
		r.tokensAvailable = r.cfg.Kinetic.MaxStrikesPerSec
	}
}
