// STATUS: DIAMANT VGT SUPREME
package main

// GeDefense 6.1.0 Module D: local-privilege-escalation kill-chain handlers and
// apply plan (GET /api/v1/lpe-guard/status, POST /api/v1/lpe-guard/apply).
//
// The socket-deny word reaches the kernel only through CELL_POLICY_SET, the StyX
// profile through the StyX settings/apply path and ASLR through the core sysctl
// compare-set. Anything that cannot be enforced is reported, never assumed.

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/visiongaiatechnology/gedefense/control/internal/lpeguard"
	"github.com/visiongaiatechnology/gedefense/control/internal/workerguard"
)

const (
	lpeGuardHardeningRefresh = 60 * time.Second
	lpeGuardCapabilityProbe  = 30 * time.Second
	lpeGuardMaxApplyWorkers  = 32
	lpeGuardTick             = 5 * time.Second
)

// LPEGuardEngine is the Module D runtime.
type LPEGuardEngine struct {
	settings *SettingsStore
	state    *State
	core     *CoreClient
	xdr      *XDREngine

	mu           sync.Mutex
	hardening    []lpeguard.HardeningCheck
	hardeningAt  time.Time
	capability   string
	capabilityAt time.Time
	reason       string
	applied      map[uint64]uint8
}

// NewLPEGuardEngine constructs the Module D engine.
func NewLPEGuardEngine(settings *SettingsStore, state *State, core *CoreClient, xdr *XDREngine) *LPEGuardEngine {
	return &LPEGuardEngine{
		settings: settings, state: state, core: core, xdr: xdr,
		capability: "unknown", applied: make(map[uint64]uint8),
	}
}

// Run refreshes the host baseline while the module is enabled.
func (e *LPEGuardEngine) Run(ctx context.Context) {
	if e == nil {
		return
	}
	ticker := time.NewTicker(lpeGuardTick)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			e.refreshIfEnabled()
		}
	}
}

// refreshIfEnabled reloads the host facts when the namespace asks for them.
func (e *LPEGuardEngine) refreshIfEnabled() {
	if e == nil || e.settings == nil {
		return
	}
	settings := effectiveLPEGuardSettings(e.settings.Get())
	if !settings.Enabled {
		return
	}
	e.refreshHardening(settings)
	e.refreshCapability()
}

// refreshHardening reloads the bounded host baseline.
func (e *LPEGuardEngine) refreshHardening(settings LPEGuardFabricSettings) {
	e.mu.Lock()
	fresh := time.Since(e.hardeningAt) < lpeGuardHardeningRefresh && len(e.hardening) > 0
	e.mu.Unlock()
	if fresh {
		return
	}
	facts := lpeguard.ReadHostFacts()
	checks := lpeguard.EvaluateHardening(facts, lpeguard.HardeningSettings{
		EnforceASLR: settings.EnforceASLR, BlockLPEModules: settings.BlockLPEModules,
	})
	e.mu.Lock()
	e.hardening, e.hardeningAt = checks, time.Now().UTC()
	e.mu.Unlock()
}

// refreshCapability probes the Cell LSM command family at most every 30 s.
func (e *LPEGuardEngine) refreshCapability() {
	if e.core == nil {
		e.mu.Lock()
		e.capability, e.reason = "inactive", "no privileged core client is attached"
		e.mu.Unlock()
		return
	}
	e.mu.Lock()
	fresh := time.Since(e.capabilityAt) < lpeGuardCapabilityProbe && e.capability != "unknown"
	e.mu.Unlock()
	if fresh {
		return
	}
	capability, reason := "active", ""
	if _, err := e.core.CellPolicyEpoch(); err != nil {
		capability, reason = "inactive", "the privileged core does not implement the Cell LSM policy family: "+err.Error()
	}
	e.mu.Lock()
	e.capability, e.reason, e.capabilityAt = capability, reason, time.Now().UTC()
	e.mu.Unlock()
}

// lpePlan is the complete Module D plan the status and apply endpoints render.
type lpePlan struct {
	socket   []lpeguard.SocketPolicyEntry
	styx     lpeguard.StyxProfilePlan
	checks   []lpeguard.HardeningCheck
	workers  []workerguard.Worker
	settings LPEGuardFabricSettings
}

func (e *LPEGuardEngine) buildPlan() lpePlan {
	settings := effectiveLPEGuardSettings(e.settings.Get())
	lpe := e.settings.Get()
	workerSettings := effectiveWorkerGuardSettings(lpe)
	registry := workerguard.Registry{
		Comms:        append([]string(nil), workerSettings.Comms...),
		UIDs:         append([]uint32(nil), workerSettings.UIDs...),
		ExcludeUnits: append([]string(nil), workerSettings.ExcludeUnits...),
	}
	scan, _ := workerguard.ScanProcesses(registry, true, lpeGuardMaxApplyWorkers)
	workers := scan.Workers
	policyWorkers := make([]lpeguard.PolicyWorker, 0, len(workers))
	for _, worker := range workers {
		policyWorkers = append(policyWorkers, lpeguard.PolicyWorker{CgroupID: worker.CgroupID, Comm: worker.Comm, UID: worker.UID})
	}
	deny := lpeguard.DenySettings{
		AFPacket: settings.DenyAFPacket, AFTIPC: settings.DenyAFTIPC, AFVSOCK: settings.DenyAFVSock,
		SCTP: settings.DenySCTP, DCCP: settings.DenyDCCP, RDS: settings.DenyRDS,
	}
	e.mu.Lock()
	applied := make(map[uint64]uint8, len(e.applied))
	for cgroup, flags := range e.applied {
		applied[cgroup] = flags
	}
	cachedChecks := append([]lpeguard.HardeningCheck(nil), e.hardening...)
	e.mu.Unlock()
	socket := lpeguard.BuildSocketPolicyPlan(policyWorkers, deny)
	for index := range socket {
		if flags, ok := applied[socket[index].CgroupID]; ok && flags == socket[index].Flags {
			socket[index].Applied = true
		}
	}
	styx := lpeguard.BuildStyxWebIngressPlan(lpeguard.StyxProfileSettings{
		Enabled: settings.StyxProfile, BackendCIDRs: settings.StyxBackendCIDRs, DNSServers: settings.StyxDnsServers,
	})
	if len(cachedChecks) == 0 && settings.Enabled {
		e.refreshHardening(settings)
		e.mu.Lock()
		cachedChecks = append([]lpeguard.HardeningCheck(nil), e.hardening...)
		e.mu.Unlock()
	}
	return lpePlan{socket: socket, styx: styx, checks: cachedChecks, workers: workers, settings: settings}
}

// ApplyState maps the persisted revision onto the Fabric Settings vocabulary.
// An enabled revision is live (the plan is rendered per read); the kernel apply
// is always an explicit operator POST.
func (e *LPEGuardEngine) ApplyState(settings RuntimeSettings) string {
	if !effectiveLPEGuardSettings(settings).Enabled {
		return "disabled"
	}
	return "applied"
}

func (e *LPEGuardEngine) Details() map[string]any {
	if e == nil {
		return map[string]any{"runtime": "unavailable"}
	}
	plan := e.buildPlan()
	return map[string]any{"runtime": map[string]any{
		"capability": e.capabilityString(), "reason": e.reasonString(),
		"socket_targets": len(plan.socket), "hardening_checks": len(plan.checks),
		"styx_profile": plan.styx,
	}}
}

func (e *LPEGuardEngine) capabilityString() string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.capability
}

func (e *LPEGuardEngine) reasonString() string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.reason
}

type lpeGuardStatusView struct {
	GeneratedAt  time.Time                    `json:"generated_at"`
	Mode         string                       `json:"mode"`
	Capability   string                       `json:"capability"`
	Reason       string                       `json:"reason"`
	SocketPolicy []lpeguard.SocketPolicyEntry `json:"socket_policy"`
	StyxProfile  lpeguard.StyxProfilePlan     `json:"styx_profile"`
	Hardening    []lpeguard.HardeningCheck    `json:"hardening"`
}

// lpeGuardStatus serves GET /api/v1/lpe-guard/status.
func (s *APIServer) lpeGuardStatus(w http.ResponseWriter, _ *http.Request) {
	view := lpeGuardStatusView{
		GeneratedAt: time.Now().UTC(), Mode: "observe", Capability: "inactive",
		Reason:       "lpe guard engine is not wired on this control plane",
		SocketPolicy: []lpeguard.SocketPolicyEntry{},
		StyxProfile:  lpeguard.StyxProfilePlan{Name: lpeguard.StyxProfileName, Allow: []string{}, DNS: []string{}, Backend: []string{}},
		Hardening:    []lpeguard.HardeningCheck{},
	}
	if s.v61 == nil || s.v61.lpeGuard == nil || s.settings == nil {
		writeJSON(w, http.StatusOK, view)
		return
	}
	engine := s.v61.lpeGuard
	settings := effectiveLPEGuardSettings(s.settings.Get())
	view.Capability = engine.capabilityString()
	view.Reason = engine.reasonString()
	if !settings.Enabled {
		view.Capability = "inactive"
		view.Reason = "lpe guard module is disabled; no plan is applied"
	} else {
		engine.refreshCapability()
		view.Capability = engine.capabilityString()
		view.Reason = engine.reasonString()
	}
	plan := engine.buildPlan()
	view.SocketPolicy = append([]lpeguard.SocketPolicyEntry{}, plan.socket...)
	view.StyxProfile = plan.styx
	view.Hardening = append([]lpeguard.HardeningCheck{}, plan.checks...)
	if !settings.Enabled {
		view.Mode = "disabled"
	} else if view.Capability == "active" {
		appliedAny := false
		for _, row := range plan.socket {
			if row.Applied {
				appliedAny = true
				break
			}
		}
		allHardeningPass := len(plan.checks) > 0
		for _, chk := range plan.checks {
			if chk.State != "pass" {
				allHardeningPass = false
				break
			}
		}
		if appliedAny || allHardeningPass {
			view.Mode = "enforce"
		}
	}
	writeJSON(w, http.StatusOK, view)
}

// lpeGuardApply serves POST /api/v1/lpe-guard/apply: socket policy through
// CELL_POLICY_SET, StyX through its settings path and ASLR through the sysctl
// path. 200 only when every requested path confirmed; 409 for a partial apply,
// 503 when nothing applied, with the concrete per-path error fields.
func (s *APIServer) lpeGuardApply(w http.ResponseWriter, r *http.Request) {
	if s.v61 == nil || s.v61.lpeGuard == nil || s.settings == nil {
		writePublicError(w, http.StatusServiceUnavailable, "lpe guard engine is not wired on this control plane")
		return
	}
	engine := s.v61.lpeGuard
	plan := engine.buildPlan()
	if !plan.settings.Enabled {
		writePublicError(w, http.StatusConflict, "lpe guard module is disabled; enable it in Settings > LPE Guard before applying a plan")
		return
	}
	result := map[string]any{
		"generated_at": time.Now().UTC(), "mode": "observe",
		"socket_policy": plan.socket, "styx_profile": plan.styx, "hardening": plan.checks,
		"capability": engine.capabilityString(), "reason": engine.reasonString(),
	}
	socketRows, socketErr := engine.applySocketPolicy(plan)
	result["socket_policy"] = socketRows
	if socketErr != nil {
		result["socket_error"] = socketErr.Error()
	}
	styxState, styxErr := engine.applyStyxProfile(plan)
	result["styx_apply_state"] = styxState
	if styxErr != nil {
		result["styx_error"] = styxErr.Error()
	} else if plan.settings.StyxProfile && styxState != "applied" {
		result["styx_error"] = "styX web-ingress profile not applied (state " + styxState + ")"
	}
	aslrState, hardeningErr := engine.applyHardening(plan)
	if hardeningErr != nil {
		result["hardening_error"] = hardeningErr.Error()
	}
	// Module blacklisting is a modprobe.d/package-manager action: plan only, manual.
	blockState := "not_requested"
	if plan.settings.BlockLPEModules {
		blockState = "manual_required"
	}
	result["enforcement"] = map[string]string{"aslr": aslrState, "block_lpe_modules": blockState}
	socketOK := socketErr == nil
	socketApplied := false
	for _, row := range socketRows {
		socketApplied = socketApplied || row.Applied
	}
	styxOK := !plan.settings.StyxProfile || (styxErr == nil && styxState == "applied")
	aslrOK := !plan.settings.EnforceASLR || aslrState == "applied" || aslrState == "already_applied"
	if socketOK && styxOK && aslrOK {
		result["mode"] = "enforce"
		if s.state != nil {
			s.state.AddEvent(Event{Severity: "info", Kind: "lpe_guard.applied", Source: "operator",
				Message: "LPE guard plan applied: " + strconv.Itoa(len(socketRows)) + " socket target(s), styx " + styxState + ", aslr " + aslrState})
		}
		writeJSON(w, http.StatusOK, result)
		return
	}
	status := http.StatusServiceUnavailable
	if socketApplied || (styxOK && plan.settings.StyxProfile) || (aslrOK && plan.settings.EnforceASLR) {
		status = http.StatusConflict
	}
	socketState := "refused"
	if socketOK {
		socketState = "applied"
	}
	result["error"] = "lpe guard apply state: socket=" + socketState + " styx=" + styxState + " aslr=" + aslrState
	// Make the concrete failure visible to the operator even though the generic
	// API error wrapper only surfaces a message: the summary names which path
	// failed and why, without hiding it behind the state word.
	if socketErr != nil {
		result["error"] = result["error"].(string) + "; socket_error=" + socketErr.Error()
	}
	if styxErr != nil {
		result["error"] = result["error"].(string) + "; styx_error=" + styxErr.Error()
	}
	if hardeningErr != nil {
		result["error"] = result["error"].(string) + "; hardening_error=" + hardeningErr.Error()
	}
	writeJSON(w, status, result)
}

// applyHardening performs the Module D hardening apply. ASLR is real enforcement
// through the same core SYSCTL_SET compare-set the hardening module uses (profile
// attribution untouched, rollback is an explicit operator action). Module
// blacklisting stays a plan: the caller reports manual_required.
func (e *LPEGuardEngine) applyHardening(plan lpePlan) (string, error) {
	if !plan.settings.EnforceASLR {
		return "manual_required", nil
	}
	if e.core == nil {
		return "unavailable", errors.New("no privileged core client is attached; ASLR was not modified")
	}
	current, err := e.core.SysctlGet("kernel.randomize_va_space")
	if err != nil {
		return "failed", err
	}
	if current == "2" {
		return "already_applied", nil
	}
	if err := e.core.SysctlCompareSet("kernel.randomize_va_space", current, "2"); err != nil {
		return "failed", err
	}
	return "applied", nil
}

// applySocketPolicy sends one CELL_POLICY_SET per worker cgroup.
func (e *LPEGuardEngine) applySocketPolicy(plan lpePlan) ([]lpeguard.SocketPolicyEntry, error) {
	if e.core == nil {
		return plan.socket, errors.New("no privileged core client is attached")
	}
	if len(plan.socket) == 0 {
		return plan.socket, errors.New("no web-worker cgroup is classified; no socket policy target exists")
	}
	if plan.socket[0].Flags == 0 {
		return plan.socket, errors.New("every deny bit is disabled; there is no socket policy to apply")
	}
	if err := lpeguard.ValidateFlags(plan.socket[0].Flags); err != nil {
		return plan.socket, err
	}
	appliedRows := make([]lpeguard.SocketPolicyEntry, 0, len(plan.socket))
	var result error
	e.mu.Lock()
	if e.applied == nil {
		e.applied = make(map[uint64]uint8)
	}
	e.mu.Unlock()
	for _, entry := range plan.socket {
		if entry.Flags == 0 {
			continue
		}
		if err := e.core.lpeCellPolicySet(entry.CgroupID, entry.Flags); err != nil {
			result = errors.Join(result, fmt.Errorf("cgroup %d: %w", entry.CgroupID, err))
			appliedRows = append(appliedRows, entry)
			continue
		}
		entry.Applied = true
		appliedRows = append(appliedRows, entry)
		e.mu.Lock()
		e.applied[entry.CgroupID] = entry.Flags
		e.mu.Unlock()
	}
	return appliedRows, result
}

// applyStyxProfile merges the web-ingress-only profile into the StyX namespace
// and projects it through the existing StyX settings/apply path.
func (e *LPEGuardEngine) applyStyxProfile(plan lpePlan) (string, error) {
	if !plan.settings.StyxProfile {
		return "disabled", nil
	}
	if e.settings == nil || e.xdr == nil {
		return "engine_unavailable", errors.New("styX runtime is not wired")
	}
	current := e.settings.Get()
	styx := effectiveStyxFabricSettings(current)
	if !styx.Enabled || styx.Mode == StyxModeOff {
		return "refused", errors.New("the styX profile requires the styX namespace to be enabled with mode monitor or enforce; enable StyX in Settings > StyX first")
	}
	next := cloneRuntimeSettings(current)
	nextStyx := cloneStyxFabricSettings(styx)
	// Per-cell enforce mode for every classified worker cgroup, replacing an
	// existing entry for the same cgroup only.
	for _, worker := range plan.workers {
		if worker.CgroupID == 0 {
			continue
		}
		replaced := false
		for index := range nextStyx.PerCell {
			if nextStyx.PerCell[index].CgroupID != worker.CgroupID {
				continue
			}
			nextStyx.PerCell[index].Mode = StyxModeEnforce
			nextStyx.PerCell[index].AllowHostAllowlist = true
			replaced = true
		}
		if !replaced {
			nextStyx.PerCell = append(nextStyx.PerCell, StyxCellMode{
				CgroupID: worker.CgroupID, Mode: StyxModeEnforce, AllowHostAllowlist: true,
			})
		}
		for _, allowed := range plan.styx.Allow {
			nextStyx.Allowlist = appendStyxAllow(nextStyx.Allowlist, StyxAllowRule{
				CgroupID: worker.CgroupID, CIDR: allowed, PortLo: 0, PortHi: 65535,
			})
		}
	}
	for _, resolver := range plan.styx.DNS {
		nextStyx.DnsResolvers = appendUniqueString(nextStyx.DnsResolvers, resolver)
	}
	if err := validateStyxFabricSettings(&nextStyx); err != nil {
		return "refused", err
	}
	next.Styx = &nextStyx
	updated, err := e.settings.Update(next)
	if err != nil {
		return "refused", err
	}
	if err := e.xdr.ApplyRuntimeSettings(updated); err != nil {
		return "pending", err
	}
	sync := e.xdr.StyxPolicyStatus()
	switch sync.State {
	case StyxSyncStateApplied:
		return "applied", nil
	case StyxSyncStateCapabilityMissing:
		return "engine_unavailable", nil
	default:
		return "pending", nil
	}
}

// appendStyxAllow adds one allow rule unless the same cgroup+cidr already exists.
func appendStyxAllow(rules []StyxAllowRule, rule StyxAllowRule) []StyxAllowRule {
	for _, existing := range rules {
		if existing.CgroupID == rule.CgroupID && existing.CIDR == rule.CIDR {
			return rules
		}
	}
	if len(rules) >= styxMaxAllowRules {
		return rules
	}
	return append(rules, rule)
}

// appendUniqueString adds a string if it is not already present.
func appendUniqueString(values []string, value string) []string {
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	return append(values, value)
}

// lpeCellPolicySet sends the 6.1.0 socket-deny flag word through the existing
// CELL_POLICY_SET command family. It is a distinct method because the historical
// CellPolicySet client validation accepts only the pre-6.1.0 bit 0.
func (c *CoreClient) lpeCellPolicySet(cgroupID uint64, flags uint8) error {
	if c == nil {
		return errors.New("privileged core client is nil")
	}
	if cgroupID == 0 {
		return errors.New("cell policy identity must be non-zero")
	}
	if flags == 0 {
		return errors.New("cell policy flag word must not be empty")
	}
	if err := lpeguard.ValidateFlags(flags); err != nil {
		return err
	}
	response, err := c.command("CELL_POLICY_SET", strconv.FormatUint(cgroupID, 10), strconv.FormatUint(uint64(flags), 10))
	if err != nil {
		return err
	}
	if response != "applied" {
		return errors.New("core returned an invalid Cell policy state")
	}
	return nil
}
