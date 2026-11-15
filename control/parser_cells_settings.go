// STATUS: DIAMANT VGT SUPREME
package main

// POINT 2 / P2-T3: the ephemeral parser-cell operator namespace
// (docs/POINT2-PARSER-CELLS.md §5, §6, §8).
//
// The unprivileged control plane owns the operator intent only: the privileged
// helper `gedefense-cell-helper` is the only process that spawns, freezes or
// burns a cell. This namespace therefore carries bounds and policy, never a
// binary, an argv, a path or an environment value - those come exclusively from
// the root-owned profile table of the helper (§1.2).
//
// Defaults are Enabled=false: upgrading a node seeds the namespace without
// contacting the helper and without producing a single cell, event or request
// (§8). Enabled=false is also the explicit "nothing is claimed" state, so an
// operator may keep a disabled draft (profiles/limits) in it exactly like the
// additive titan_exec namespace does; there is no separate mode that could make
// a stored rule silently inert.

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

const (
	// parserCellsABI is the only helper ABI this control plane speaks (§3).
	parserCellsABI = "cell-runtime-v1"

	// parserCellsClassEphemeral is the cell class every managed cell carries.
	// CellGuard uses it to decide between burning a parser cell and the legacy
	// freeze/revoke transaction for an ordinary Gaia Cell (§6).
	parserCellsClassEphemeral = "parser-ephemeral"

	// Hard bounds from §3/§6. Values are validated against these caps and are
	// rejected, never clamped, when an operator or import asks for more.
	parserCellsMinTTLSeconds        = 5
	parserCellsMaxTTLSeconds        = 3600
	parserCellsMaxConcurrentCap     = 16
	parserCellsMinInputBytes        = 1 << 10
	parserCellsMaxInputBytesCap     = 8 << 20
	parserCellsMinExportBytes       = 1 << 10
	parserCellsMaxExportBytesCap    = 2 << 20
	parserCellsMaxProfiles          = 16
	parserCellsMaxProfileIDBytes    = 64
	parserCellsMaxCooldownSeconds   = 86400
	parserCellsMaxIncidentScore     = 250
	parserCellsDefaultTTLSeconds    = 120
	parserCellsDefaultMaxConcurrent = 4
	parserCellsDefaultInputBytes    = 8 << 20
	parserCellsDefaultExportBytes   = 2 << 20
	parserCellsDefaultIncidentScore = 80
	parserCellsDefaultCooldownSecs  = 300
	parserCellsErrorMaxBytes        = 240
)

// ParserCellLayerStatus reports the per-layer isolation status of one cell. No
// layer is ever claimed as applied without the owning component attesting it
// (§5 admission gate): L1 by the helper's CELL_CREATE answer, L2/L3/L4 by the
// privileged core's command acknowledgement.
type ParserCellLayerStatus struct {
	Sandbox    string `json:"sandbox"`
	CellLSM    string `json:"cell_lsm"`
	StyxEgress string `json:"styx_egress"`
	TitanExec  string `json:"titan_exec"`
	Required   bool   `json:"required"`
	Satisfied  bool   `json:"satisfied"`
}

// ParserCellExportMeta describes one burned cell export. It is untrusted
// evidence: bounded, imported, hashed and never rendered or executed (§6, §8).
type ParserCellExportMeta struct {
	Size       int64     `json:"size"`
	SHA256     string    `json:"sha256"`
	Kind       string    `json:"kind"`
	Path       string    `json:"path,omitempty"`
	Scan       string    `json:"scan"`
	ImportedAt time.Time `json:"imported_at"`
}

// ParserCellRuntime is the bounded operator view of one ephemeral cell.
type ParserCellRuntime struct {
	UUID        string                `json:"uuid"`
	CellClass   string                `json:"cell_class"`
	Profile     string                `json:"profile"`
	Generation  uint64                `json:"generation"`
	CgroupID    uint64                `json:"cgroup_id"`
	CgroupPath  string                `json:"cgroup_path,omitempty"`
	PID         int                   `json:"pid"`
	State       string                `json:"state"`
	Sandbox     bool                  `json:"sandbox"`
	NetNS       bool                  `json:"netns"`
	TTLSeconds  int                   `json:"ttl_seconds"`
	CreatedAt   time.Time             `json:"created_at"`
	ExpiresAt   time.Time             `json:"expires_at"`
	InputToken  string                `json:"input_token,omitempty"`
	InputSHA256 string                `json:"input_sha256,omitempty"`
	InputSize   int64                 `json:"input_size,omitempty"`
	Layers      ParserCellLayerStatus `json:"layers"`
	Export      *ParserCellExportMeta `json:"export,omitempty"`
	BurnReason  string                `json:"burn_reason,omitempty"`
	EvidenceID  string                `json:"evidence_id,omitempty"`
	LastError   string                `json:"last_error,omitempty"`
	Adopted     bool                  `json:"adopted,omitempty"`
	Terminal    bool                  `json:"terminal"`
}

// ParserCellInput is the answer of the input-staging step: the manager-minted
// token, the document digest and its size. Only these three values reach /open.
type ParserCellInput struct {
	Token  string `json:"input_token"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

// ParserCellResult is one bounded dispatch/lifecycle record for the operator view.
type ParserCellResult struct {
	At     time.Time `json:"at"`
	UUID   string    `json:"uuid,omitempty"`
	Cgroup uint64    `json:"cgroup_id,omitempty"`
	Action string    `json:"action"`
	State  string    `json:"state"`
	Reason string    `json:"reason,omitempty"`
	Detail string    `json:"detail,omitempty"`
}

// ParserCellsStatus is the whole parser-cell runtime projection served by
// /api/v1/parser-cells/status. Enabled=false is answered without touching the
// helper: it is the upgrade default and must stay request-free (§8).
type ParserCellsStatus struct {
	Enabled   bool   `json:"enabled"`
	Available bool   `json:"available"`
	Helper    string `json:"helper"`
	ABI       string `json:"abi,omitempty"`
	Sandbox   bool   `json:"sandbox"`
	// Wayland is the negotiated display capability; phase 1 honestly reports false
	// because a cell runs as the unprivileged parser uid (no session socket).
	Wayland           bool                `json:"wayland"`
	BPFLSM            bool                `json:"bpf_lsm"`
	Profiles          []string            `json:"profiles,omitempty"`
	HelperCells       int                 `json:"helper_active_cells"`
	Active            int                 `json:"active"`
	Burned            int                 `json:"burned"`
	Failed            int                 `json:"failed"`
	Refused           int                 `json:"refused"`
	MaxConcurrent     int                 `json:"max_concurrent"`
	TTLSeconds        int                 `json:"ttl_seconds"`
	MaxInputBytes     int                 `json:"max_input_bytes"`
	MaxExportBytes    int                 `json:"max_export_bytes"`
	BurnOnIncident    bool                `json:"burn_on_incident"`
	IncidentScore     int                 `json:"incident_score"`
	CooldownSeconds   int                 `json:"cooldown_seconds"`
	RequireHostLayers bool                `json:"require_host_layers"`
	LayerCellLSM      string              `json:"layer_cell_lsm"`
	LayerStyxEgress   string              `json:"layer_styx_egress"`
	LayerTitanExec    string              `json:"layer_titan_exec"`
	HelperState       string              `json:"helper_state,omitempty"`
	LastError         string              `json:"last_error,omitempty"`
	DegradedWhy       string              `json:"degraded_reason,omitempty"`
	PolledAt          time.Time           `json:"polled_at,omitempty"`
	Cells             []ParserCellRuntime `json:"cells,omitempty"`
	Recent            []ParserCellResult  `json:"recent,omitempty"`
}

// ParserCellsFabricSettings is the operator-facing parser-cell namespace. It is a
// pointer on RuntimeSettings so a document persisted before it existed still
// serialises byte-identically and keeps authenticating (same contract as every
// other additive namespace).
type ParserCellsFabricSettings struct {
	Enabled           bool     `json:"enabled"`
	Profiles          []string `json:"profiles"`
	TTLSeconds        int      `json:"ttl_seconds"`
	MaxConcurrent     int      `json:"max_concurrent"`
	MaxInputBytes     int      `json:"max_input_bytes"`
	MaxExportBytes    int      `json:"max_export_bytes"`
	BurnOnIncident    bool     `json:"burn_on_incident"`
	IncidentScore     int      `json:"incident_score"`
	CooldownSeconds   int      `json:"cooldown_seconds"`
	RequireHostLayers bool     `json:"require_host_layers"`
}

func defaultParserCellsFabricSettings() ParserCellsFabricSettings {
	return ParserCellsFabricSettings{
		Enabled:           false,
		Profiles:          []string{},
		TTLSeconds:        parserCellsDefaultTTLSeconds,
		MaxConcurrent:     parserCellsDefaultMaxConcurrent,
		MaxInputBytes:     parserCellsDefaultInputBytes,
		MaxExportBytes:    parserCellsDefaultExportBytes,
		BurnOnIncident:    true,
		IncidentScore:     parserCellsDefaultIncidentScore,
		CooldownSeconds:   parserCellsDefaultCooldownSecs,
		RequireHostLayers: false,
	}
}

func cloneParserCellsFabricSettings(in ParserCellsFabricSettings) ParserCellsFabricSettings {
	out := in
	out.Profiles = append(make([]string, 0, len(in.Profiles)), in.Profiles...)
	return out
}

// parserCellsDefaults returns the bootstrap seed for a document that predates the
// namespace, following the other additive namespaces.
func parserCellsDefaults(defaults RuntimeSettings) ParserCellsFabricSettings {
	if defaults.ParserCells != nil {
		return cloneParserCellsFabricSettings(*defaults.ParserCells)
	}
	return defaultParserCellsFabricSettings()
}

// effectiveParserCellsSettings resolves a persisted document into the
// administrable values. Unlike a mode-based namespace there is no derived state:
// Enabled is the master switch and every other field is a bound.
func effectiveParserCellsSettings(settings RuntimeSettings) ParserCellsFabricSettings {
	out := defaultParserCellsFabricSettings()
	if settings.ParserCells != nil {
		out = cloneParserCellsFabricSettings(*settings.ParserCells)
	}
	return out
}

// protocolFieldValid is the shared payload-field charset of the control plane
// (see runtime_settings.go/custom rules); profile ids use the stricter helper
// subset below.
func parserCellProfileValid(profile string) bool {
	if profile == "" || len(profile) > parserCellsMaxProfileIDBytes {
		return false
	}
	for _, character := range profile {
		switch {
		case character >= 'a' && character <= 'z':
		case character >= 'A' && character <= 'Z':
		case character >= '0' && character <= '9':
		case character == '.', character == '_', character == '-':
		default:
			return false
		}
	}
	return true
}

// validateParserCellsFabricSettings validates and canonicalises one namespace.
// It is reject-not-repair: no value is silently clamped, and a list above the cap
// is refused. An empty Profiles list is the documented "all helper profiles"
// default (§6); a disabled namespace may carry a draft, but it can never make a
// stored rule look active - Enabled=false is the explicit nothing-claimed state.
func validateParserCellsFabricSettings(in *ParserCellsFabricSettings) error {
	if in == nil {
		return errors.New("parser cell settings are missing")
	}
	if in.TTLSeconds < parserCellsMinTTLSeconds || in.TTLSeconds > parserCellsMaxTTLSeconds {
		return fmt.Errorf("parser cell ttl_seconds must be between %d and %d", parserCellsMinTTLSeconds, parserCellsMaxTTLSeconds)
	}
	if in.MaxConcurrent < 1 || in.MaxConcurrent > parserCellsMaxConcurrentCap {
		return fmt.Errorf("parser cell max_concurrent must be between 1 and %d", parserCellsMaxConcurrentCap)
	}
	if in.MaxInputBytes < parserCellsMinInputBytes || in.MaxInputBytes > parserCellsMaxInputBytesCap {
		return fmt.Errorf("parser cell max_input_bytes must be between %d and %d", parserCellsMinInputBytes, parserCellsMaxInputBytesCap)
	}
	if in.MaxExportBytes < parserCellsMinExportBytes || in.MaxExportBytes > parserCellsMaxExportBytesCap {
		return fmt.Errorf("parser cell max_export_bytes must be between %d and %d", parserCellsMinExportBytes, parserCellsMaxExportBytesCap)
	}
	if in.IncidentScore < 1 || in.IncidentScore > parserCellsMaxIncidentScore {
		return fmt.Errorf("parser cell incident_score must be between 1 and %d", parserCellsMaxIncidentScore)
	}
	if in.CooldownSeconds < 0 || in.CooldownSeconds > parserCellsMaxCooldownSeconds {
		return fmt.Errorf("parser cell cooldown_seconds must be between 0 and %d", parserCellsMaxCooldownSeconds)
	}
	if len(in.Profiles) > parserCellsMaxProfiles {
		return fmt.Errorf("parser cell profile list exceeds %d entries", parserCellsMaxProfiles)
	}
	seen := make(map[string]struct{}, len(in.Profiles))
	profiles := make([]string, 0, len(in.Profiles))
	for _, profile := range in.Profiles {
		if !parserCellProfileValid(profile) {
			return fmt.Errorf("parser cell profile %q is not a protocol-safe profile id", profile)
		}
		if _, duplicate := seen[profile]; duplicate {
			return fmt.Errorf("parser cell profile %q is duplicated", profile)
		}
		seen[profile] = struct{}{}
		profiles = append(profiles, profile)
	}
	sort.Strings(profiles)
	in.Profiles = profiles
	return nil
}

// parserCellProfileAllowed applies the operator allowlist. An empty list keeps
// the documented default: every profile the helper advertises is usable.
func parserCellProfileAllowed(settings ParserCellsFabricSettings, profile string) bool {
	if len(settings.Profiles) == 0 {
		return true
	}
	for _, allowed := range settings.Profiles {
		if allowed == profile {
			return true
		}
	}
	return false
}

func parserCellBoundedError(err error) string {
	if err == nil {
		return ""
	}
	text := strings.TrimSpace(err.Error())
	if len(text) > parserCellsErrorMaxBytes {
		text = text[:parserCellsErrorMaxBytes]
	}
	return text
}
