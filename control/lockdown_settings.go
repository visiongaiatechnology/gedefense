// SPDX-FileCopyrightText: 2026 VisionGaia Technology
// SPDX-License-Identifier: AGPL-3.0-only

package main

// POINT 5 / P5-T3: the operator-facing Emergency Lockdown namespace and the
// bounded status vocabulary shared by the engine (lockdown.go), the trigger
// evaluators (lockdown_triggers.go) and the API (lockdown_api.go).
//
// The namespace is additive and inert by default: Enabled=false is the shipped
// default, no LOCKDOWN_* command is issued and no host behaviour changes on
// upgrade (docs/POINT5-LOCKDOWN.md §7, §9). The Go control plane stays
// unprivileged - it never touches sysfs, eBPF maps or netlink. Every kernel-side
// action is a VGT3 command to the privileged core and every phase reports what
// the kernel/dedicated subsystem actually acknowledged, never an assumption
// (§9 "keine Attrappe").

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

const (
	// lockdownModeLocked/the two administrable arm modes: locked blocks unknown
	// USB/Thunderbolt devices at the core, unlocked only audits (§2).
	lockdownModeLocked   = "locked"
	lockdownModeUnlocked = "unlocked"

	// CellScope values: "all" freezes every live cell, "high-risk" only the
	// untrusted execution substrates (application/microvm). Vault and workspace
	// cells stay usable so an operator keeps the recovery console (§1.4).
	lockdownCellScopeAll      = "all"
	lockdownCellScopeHighRisk = "high-risk"

	// Caps. They are enforced as rejection bounds, never repaired silently
	// (§7 "Caps", same contract as the other namespaces).
	lockdownMaxRequireSources   = 4
	lockdownMaxCooldownSeconds  = 86400
	lockdownMaxTargetsCap       = 1024
	lockdownMaxDuressPathBytes  = 512
	lockdownMaxPhaseDetailBytes = 160
	lockdownMaxTriggerReasonLen = 240
	lockdownMinTriggerReasonLen = 8
)

// lockdownMigrationNote is the one operator-visible migration record a v15
// document receives when it is upgraded to v16. An upgrade must never look like
// it silently changed the operator's configuration.
const lockdownMigrationNote = "lockdown namespace added with enabled=false and auto_arm=false: no LOCKDOWN_* command is issued, no phase runs and host behaviour is unchanged until an operator enables it (docs/POINT5-LOCKDOWN.md §7, §9)"

// LockdownFabricSettings is the operator-facing Emergency Lockdown namespace.
// It is a pointer on RuntimeSettings so a document persisted before it existed
// still serialises byte-identically and keeps authenticating (same contract as
// every other additive namespace).
type LockdownFabricSettings struct {
	Enabled bool `json:"enabled"`
	// AutoArm re-arms the kernel arm mode on start without an operator click.
	// It is off by default: an upgrade must not arm anything by itself.
	AutoArm bool `json:"auto_arm"`
	// TriggerMorpheusCritical/TriggerCanaryUnauthorized/TriggerBootTrustDrift are
	// the three automatic high-confidence trigger switches (§7). They only apply
	// while Enabled is true. TriggerWitnessEquivocation is the additive POINT 4
	// source: the witness engine only calls it when its own namespace asked for it.
	TriggerMorpheusCritical    bool `json:"trigger_morpheus_critical"`
	TriggerCanaryUnauthorized  bool `json:"trigger_canary_unauthorized"`
	TriggerBootTrustDrift      bool `json:"trigger_boot_trust_drift"`
	TriggerWitnessEquivocation bool `json:"trigger_witness_equivocation"`
	// RequireSources is the number of distinct trigger sources that must agree
	// before an automatic trigger fires. 1 means a single source is sufficient.
	RequireSources int `json:"require_sources"`
	// Phase switches. FreezeProcesses freezes the incident-bound process through
	// the existing core response channel; FreezeBrokers freezes the fixed broker
	// name list inside LOCKDOWN_TRIGGER (§5 flags bit2).
	FreezeProcesses bool `json:"freeze_processes"`
	FreezeBrokers   bool `json:"freeze_brokers"`
	NetworkLockdown bool `json:"network_lockdown"`
	// AllowLoopback keeps 127.0.0.1/::1 reachable for the authenticated clear
	// path (§1.4). DropLoopback is the opt-in panic mode that kills loopback too;
	// clearing then only works locally.
	AllowLoopback bool `json:"allow_loopback"`
	DropLoopback  bool `json:"drop_loopback"`
	FreezeCells   bool `json:"freeze_cells"`
	// FreezeParserCells burns (never freezes) managed parser-ephemeral cells
	// through ParserCellManager.BurnForIncident.
	FreezeParserCells bool   `json:"freeze_parser_cells"`
	CellScope         string `json:"cell_scope"`
	// HardeningApply is forwarded as LOCKDOWN_TRIGGER flag bit3. It only ever
	// writes the core's allowlisted reversible sysctls; modules_disabled is never
	// applied automatically (§6.3).
	HardeningApply bool `json:"hardening_apply"`
	// CooldownSeconds is the minimum interval between two automatic triggers.
	CooldownSeconds int `json:"cooldown_seconds"`
	// MaxTargets bounds every per-phase target list (cells, parser cells, PIDs).
	MaxTargets int `json:"max_targets"`
	// ExcludeUID0 refuses to freeze a UID-0 process from the automatic path.
	ExcludeUID0 bool `json:"exclude_uid0"`
	// DuressTokenPath is optional. Empty disables the duress poll entirely; when
	// set, the engine polls the bounded file every second and treats a non-empty
	// token as an operator duress trigger. The path is never exposed by the API.
	DuressTokenPath string `json:"duress_token_path"`
}

// defaultLockdownFabricSettings returns the shipped defaults exactly as §7
// specifies them. Enabled=false is what makes an upgrade inert.
func defaultLockdownFabricSettings() LockdownFabricSettings {
	return LockdownFabricSettings{
		Enabled:                    false,
		AutoArm:                    false,
		TriggerMorpheusCritical:    true,
		TriggerCanaryUnauthorized:  true,
		TriggerBootTrustDrift:      true,
		TriggerWitnessEquivocation: false,
		RequireSources:             1,
		FreezeProcesses:            true,
		FreezeBrokers:              true,
		NetworkLockdown:            true,
		AllowLoopback:              true,
		DropLoopback:               false,
		FreezeCells:                true,
		FreezeParserCells:          true,
		CellScope:                  lockdownCellScopeAll,
		HardeningApply:             false,
		CooldownSeconds:            300,
		MaxTargets:                 256,
		ExcludeUID0:                true,
		DuressTokenPath:            "",
	}
}

func cloneLockdownFabricSettings(in LockdownFabricSettings) LockdownFabricSettings {
	// Every field is a value type; the copy is the clone.
	return in
}

// effectiveLockdownSettings returns the persisted namespace, or the inert
// compiled-in default when a document predates it.
func effectiveLockdownSettings(settings RuntimeSettings) LockdownFabricSettings {
	if settings.Lockdown != nil {
		return cloneLockdownFabricSettings(*settings.Lockdown)
	}
	return defaultLockdownFabricSettings()
}

func lockdownDefaults(defaults RuntimeSettings) LockdownFabricSettings {
	if defaults.Lockdown != nil {
		return cloneLockdownFabricSettings(*defaults.Lockdown)
	}
	return defaultLockdownFabricSettings()
}

// validateLockdownFabricSettings is reject-not-repair: every value outside its
// documented bound is refused with its own error instead of being clamped. A
// silently repaired safety setting would look applied while doing something else.
func validateLockdownFabricSettings(in *LockdownFabricSettings) error {
	if in == nil {
		return errors.New("lockdown settings are required")
	}
	if in.RequireSources < 1 || in.RequireSources > lockdownMaxRequireSources {
		return fmt.Errorf("lockdown require_sources must be between 1 and %d", lockdownMaxRequireSources)
	}
	if in.CooldownSeconds < 0 || in.CooldownSeconds > lockdownMaxCooldownSeconds {
		return fmt.Errorf("lockdown cooldown_seconds must be between 0 and %d", lockdownMaxCooldownSeconds)
	}
	if in.MaxTargets < 1 || in.MaxTargets > lockdownMaxTargetsCap {
		return fmt.Errorf("lockdown max_targets must be between 1 and %d", lockdownMaxTargetsCap)
	}
	switch in.CellScope {
	case lockdownCellScopeAll, lockdownCellScopeHighRisk:
	default:
		// An unknown scope would silently freeze nothing; refuse it instead.
		return fmt.Errorf("lockdown cell_scope must be %q or %q", lockdownCellScopeAll, lockdownCellScopeHighRisk)
	}
	if err := validateLockdownDuressPath(in.DuressTokenPath); err != nil {
		return err
	}
	if in.Enabled {
		// An "enabled" lockdown with no phase would latch and isolate nothing.
		// That is exactly the attrappe §9 forbids, so it is refused as a setting.
		if !in.NetworkLockdown && !in.FreezeProcesses && !in.FreezeBrokers &&
			!in.FreezeCells && !in.FreezeParserCells && !in.HardeningApply {
			return errors.New("lockdown is enabled but every phase is disabled; enable at least one phase or disable lockdown")
		}
	}
	return nil
}

// validateLockdownDuressPath rejects a path the engine could not read safely.
// The content is never trusted; the path is only accepted when it is absolute
// and free of control characters.
func validateLockdownDuressPath(path string) error {
	if path == "" {
		return nil
	}
	if len(path) > lockdownMaxDuressPathBytes {
		return fmt.Errorf("lockdown duress_token_path exceeds %d bytes", lockdownMaxDuressPathBytes)
	}
	if !strings.HasPrefix(path, "/") {
		return errors.New("lockdown duress_token_path must be an absolute path")
	}
	if strings.ContainsAny(path, "\x00\r\n") {
		return errors.New("lockdown duress_token_path contains rejected characters")
	}
	if strings.TrimSpace(path) != path {
		return errors.New("lockdown duress_token_path must not carry leading or trailing whitespace")
	}
	return nil
}

// ------------------------------------------------------------ state vocabulary

// Engine states (§2/§7): disarmed -> armed -> triggering -> active(latched) ->
// clearing.
const (
	lockdownStateDisarmed   = "disarmed"
	lockdownStateArmed      = "armed"
	lockdownStateTriggering = "triggering"
	lockdownStateActive     = "active"
	lockdownStateClearing   = "clearing"
)

// Per-phase outcomes (§9). They are reported verbatim and never collapsed into
// an "enforced" claim.
const (
	lockdownPhaseApplied     = "applied"
	lockdownPhasePartial     = "partial"
	lockdownPhaseUnavailable = "unavailable"
	lockdownPhaseUnsupported = "unsupported"
	lockdownPhaseFailed      = "failed"
)

// Phase names. "sessions", "dm" and "kernel_lockdown" are honest phase-2 /
// boot-parameter facts (§6.6): they are reported unsupported with a reason
// instead of pretending to act.
const (
	lockdownPhaseNameNet            = "net"
	lockdownPhaseNameUSB            = "usb"
	lockdownPhaseNameTB             = "tb"
	lockdownPhaseNameHardening      = "hardening"
	lockdownPhaseNameProcesses      = "processes"
	lockdownPhaseNameBrokers        = "brokers"
	lockdownPhaseNameCells          = "cells"
	lockdownPhaseNameParserCells    = "parser_cells"
	lockdownPhaseNameSessions       = "sessions"
	lockdownPhaseNameDM             = "dm"
	lockdownPhaseNameKernelLockdown = "kernel_lockdown"
)

// lockdownPhaseOrder is the fixed presentation order. Bounded by construction.
var lockdownPhaseOrder = []string{
	lockdownPhaseNameNet, lockdownPhaseNameUSB, lockdownPhaseNameTB,
	lockdownPhaseNameHardening, lockdownPhaseNameProcesses, lockdownPhaseNameBrokers,
	lockdownPhaseNameCells, lockdownPhaseNameParserCells,
	lockdownPhaseNameSessions, lockdownPhaseNameDM, lockdownPhaseNameKernelLockdown,
}

// lockdownCorePhaseNames are the phase tokens the core reports in the
// LOCKDOWN_TRIGGER answer (§5/§6). "cells" is delegated to Go on purpose.
var lockdownCorePhaseNames = []string{
	lockdownPhaseNameNet, lockdownPhaseNameUSB, lockdownPhaseNameTB,
	lockdownPhaseNameHardening, lockdownPhaseNameBrokers,
}

// Trigger source/reason tokens (§3 ABI-1, wire form finalized with P5-T2). They
// are a closed vocabulary: no free-text path, IP or PID ever crosses the VGT3
// wire. The reason tokens are lowercase hyphenated on purpose: the core parses
// exactly these spellings, an uppercase variant is an ERR.
const (
	lockdownSourceManual = "manual"
	lockdownSourceUevent = "uevent"
	lockdownSourcePolicy = "policy"
	lockdownSourceTimer  = "timer"

	lockdownReasonManual      = "manual"
	lockdownReasonUSBUnknown  = "usb-unknown"
	lockdownReasonTBUnknown   = "tb-unknown"
	lockdownReasonScreenLock  = "screen-lock"
	lockdownReasonTamper      = "tamper"
	lockdownReasonXDRCritical = "xdr-critical"
	lockdownReasonBootTrust   = "boot-trust-drift"
	lockdownReasonPolicy      = "policy"
	// lockdownReasonWitnessEquivocation is the additive POINT 4 trigger reason. The
	// frozen P5 core ABI has no witness token, so the wire layer maps it onto the
	// core's "tamper" reason; the local evidence keeps the precise spelling.
	lockdownReasonWitnessEquivocation = "witness-equivocation"

	lockdownConfirmationTrigger = "TRIGGER LOCKDOWN"
	lockdownConfirmationClear   = "CLEAR:LOCKDOWN"
)

func lockdownSourceValid(source string) bool {
	switch source {
	case lockdownSourceManual, lockdownSourceUevent, lockdownSourcePolicy, lockdownSourceTimer:
		return true
	}
	return false
}

func lockdownReasonValid(reason string) bool {
	switch reason {
	case lockdownReasonManual, lockdownReasonUSBUnknown, lockdownReasonTBUnknown,
		lockdownReasonScreenLock, lockdownReasonTamper, lockdownReasonXDRCritical,
		lockdownReasonBootTrust, lockdownReasonPolicy, lockdownReasonWitnessEquivocation:
		return true
	}
	return false
}

// lockdownCorePhaseValid reports the phase tokens the core reports in
// LOCKDOWN_TRIGGER's applied/unsupported csv.
func lockdownCorePhaseValid(phase string) bool {
	for _, candidate := range lockdownCorePhaseNames {
		if candidate == phase {
			return true
		}
	}
	return false
}

// lockdownStatusPhaseValid reports every phase token LOCKDOWN_STATUS may carry:
// the applied kernel phases, the delegated cells phase and the honestly
// unsupported phase-2 facts (sessions, dm).
func lockdownStatusPhaseValid(phase string) bool {
	switch phase {
	case lockdownPhaseNameNet, lockdownPhaseNameUSB, lockdownPhaseNameTB,
		lockdownPhaseNameHardening, lockdownPhaseNameBrokers,
		lockdownPhaseNameCells, lockdownPhaseNameSessions, lockdownPhaseNameDM:
		return true
	}
	return false
}

// lockdownTruncateText bounds one operator-visible detail string of the status
// projection. The API is read-only and bounded; a phase detail is never a place
// for unbounded output.
func lockdownTruncateText(value string, max int) string {
	value = strings.TrimSpace(value)
	if len(value) <= max {
		return value
	}
	return value[:max]
}

// -------------------------------------------------------------- status views

// LockdownPhaseView is one bounded line of the per-phase status projection.
type LockdownPhaseView struct {
	Phase   string `json:"phase"`
	Status  string `json:"status"`
	Detail  string `json:"detail,omitempty"`
	Targets int    `json:"targets,omitempty"`
}

// LockdownTriggerView identifies the trigger that latched the engine. It carries
// closed tokens and the already-redacted fingerprint, never a PID or path.
type LockdownTriggerView struct {
	Source      string    `json:"source"`
	Reason      string    `json:"reason"`
	Mode        string    `json:"mode,omitempty"`
	At          time.Time `json:"at"`
	Epoch       string    `json:"epoch,omitempty"`
	Fingerprint string    `json:"fingerprint,omitempty"`
	Incident    string    `json:"incident,omitempty"`
	Operator    bool      `json:"operator"`
}

// LockdownClearView records the last successful clear for correlation.
type LockdownClearView struct {
	At     time.Time `json:"at"`
	Reason string    `json:"reason"`
	Epoch  string    `json:"epoch,omitempty"`
}

// LockdownCooldownView is the bounded cooldown projection.
type LockdownCooldownView struct {
	Seconds          int        `json:"seconds"`
	Active           bool       `json:"active"`
	RemainingSeconds int        `json:"remaining_seconds"`
	LastAutomaticAt  *time.Time `json:"last_automatic_at,omitempty"`
}

// LockdownSettingsView is the settings summary of the status projection. It
// carries policy values only - never the duress token path or any secret.
type LockdownSettingsView struct {
	Enabled                   bool   `json:"enabled"`
	AutoArm                   bool   `json:"auto_arm"`
	TriggerMorpheusCritical   bool   `json:"trigger_morpheus_critical"`
	TriggerCanaryUnauthorized bool   `json:"trigger_canary_unauthorized"`
	TriggerBootTrustDrift     bool   `json:"trigger_boot_trust_drift"`
	RequireSources            int    `json:"require_sources"`
	FreezeProcesses           bool   `json:"freeze_processes"`
	FreezeBrokers             bool   `json:"freeze_brokers"`
	NetworkLockdown           bool   `json:"network_lockdown"`
	AllowLoopback             bool   `json:"allow_loopback"`
	DropLoopback              bool   `json:"drop_loopback"`
	FreezeCells               bool   `json:"freeze_cells"`
	FreezeParserCells         bool   `json:"freeze_parser_cells"`
	CellScope                 string `json:"cell_scope"`
	HardeningApply            bool   `json:"hardening_apply"`
	CooldownSeconds           int    `json:"cooldown_seconds"`
	MaxTargets                int    `json:"max_targets"`
	ExcludeUID0               bool   `json:"exclude_uid0"`
	DuressConfigured          bool   `json:"duress_configured"`
}

func lockdownSettingsView(settings LockdownFabricSettings) LockdownSettingsView {
	return LockdownSettingsView{
		Enabled: settings.Enabled, AutoArm: settings.AutoArm,
		TriggerMorpheusCritical:   settings.TriggerMorpheusCritical,
		TriggerCanaryUnauthorized: settings.TriggerCanaryUnauthorized,
		TriggerBootTrustDrift:     settings.TriggerBootTrustDrift,
		RequireSources:            settings.RequireSources,
		FreezeProcesses:           settings.FreezeProcesses,
		FreezeBrokers:             settings.FreezeBrokers,
		NetworkLockdown:           settings.NetworkLockdown,
		AllowLoopback:             settings.AllowLoopback,
		DropLoopback:              settings.DropLoopback,
		FreezeCells:               settings.FreezeCells,
		FreezeParserCells:         settings.FreezeParserCells,
		CellScope:                 settings.CellScope,
		HardeningApply:            settings.HardeningApply,
		CooldownSeconds:           settings.CooldownSeconds,
		MaxTargets:                settings.MaxTargets,
		ExcludeUID0:               settings.ExcludeUID0,
		DuressConfigured:          settings.DuressTokenPath != "",
	}
}

// LockdownCoreView is the bounded kernel projection. Capability is a fact
// ("unknown"/"available"/"missing"/"unavailable"), never a claim of enforcement.
type LockdownCoreView struct {
	Capability  string              `json:"capability"`
	State       string              `json:"state,omitempty"`
	Epoch       string              `json:"epoch,omitempty"`
	Flags       uint8               `json:"flags,omitempty"`
	Applied     []string            `json:"applied,omitempty"`
	Unsupported []string            `json:"unsupported,omitempty"`
	Health      *CoreLockdownHealth `json:"health,omitempty"`
	LastError   string              `json:"last_error,omitempty"`
	PolledAt    *time.Time          `json:"polled_at,omitempty"`
}

// LockdownStatusView is the complete bounded, secret-free status document served
// by GET /api/v1/lockdown/status and attached additively to /api/v1/status.
type LockdownStatusView struct {
	Enabled             bool                 `json:"enabled"`
	State               string               `json:"state"`
	Latched             bool                 `json:"latched"`
	Armed               bool                 `json:"armed"`
	Mode                string               `json:"mode"`
	Epoch               string               `json:"epoch,omitempty"`
	Core                LockdownCoreView     `json:"core"`
	Trigger             *LockdownTriggerView `json:"trigger,omitempty"`
	LastClear           *LockdownClearView   `json:"last_clear,omitempty"`
	Phases              []LockdownPhaseView  `json:"phases"`
	Cooldown            LockdownCooldownView `json:"cooldown"`
	Settings            LockdownSettingsView `json:"settings"`
	Evidence            string               `json:"evidence"`
	DuressConfigured    bool                 `json:"duress_configured"`
	PendingSources      int                  `json:"pending_sources"`
	FalsePositiveGuards uint64               `json:"false_positive_guards"`
	DroppedCoreEvents   uint64               `json:"dropped_core_events"`
	Degraded            string               `json:"degraded,omitempty"`
	UpdatedAt           time.Time            `json:"updated_at"`
}
