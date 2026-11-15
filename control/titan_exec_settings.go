// STATUS: DIAMANT VGT SUPREME
package main

// POINT 1 / P1-T2: the Titan eBPF-LSM exec-gate operator namespace
// (docs/POINT1-TITAN-EXEC-GATE.md §5, §7.1, §7.3).
//
// The unprivileged control plane owns the operator intent only: it validates and
// canonicalises the namespace, compiles a path plan and talks to the privileged
// core through the authenticated VGT3 channel (coreipc.go). It never touches an
// eBPF map, never resolves a policy identity itself and never claims enforcement
// the kernel has not reported.
//
// Defaults are Enabled=false, Mode="off" and empty lists: upgrading a node seeds
// this namespace without changing a single kernel behaviour (§7.1, §12).

import (
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
)

const (
	// TitanExecModeOff/Observe/Contain/Strict are the administrable global modes
	// (§3.1 modes 0..3, §7.1). The kernel value is derived, never stored as text.
	TitanExecModeOff     = "off"
	TitanExecModeObserve = "observe"
	TitanExecModeContain = "contain"
	TitanExecModeStrict  = "strict"

	// titanExecSupportedVersion is the only TitanExec ABI version this control
	// plane speaks (§5 TITAN_EXEC_VERSION).
	titanExecSupportedVersion = "titan-exec-v1"

	// §3.1/§4/§5 ABI mirrors. Go only ever sends these values to the core; the
	// privileged process translates them into map state.
	titanExecActionAllow            uint8 = 1
	titanExecPolicyFlagRequireCtime uint8 = 1 << 0
	titanExecScopeFlagJitAllow      uint8 = 1 << 0
	titanExecGlobalFlagRequireCtime uint8 = 1 << 0

	// Path/entry/scopes ceilings. The kernel maps are sized 65536 policy entries
	// and 4096 per-cgroup scopes (§4); refusing more in the control plane is what
	// keeps a sync from failing halfway through instead of being validated first.
	titanExecMaxPathBytes      = 2048
	titanExecMaxPolicyEntries  = 65536
	titanExecMaxPolicyScopes   = 4096
	titanExecDefaultMaxEntries = 8192
	titanExecDefaultMaxScopes  = 256
	titanExecMaxExecRoots      = 512
	titanExecMaxAllowPaths     = 4096
	titanExecMaxDevRoots       = 512

	titanExecStatusErrorMaxBytes = 240
)

// TitanExecFabricSettings is the operator-facing exec-gate namespace. It is a
// pointer on RuntimeSettings so a document persisted before the namespace existed
// still serialises byte-identically (its MAC must keep authenticating).
type TitanExecFabricSettings struct {
	Enabled bool   `json:"enabled"`
	Mode    string `json:"mode"`
	// ExecRoots are host directories whose regular, executable, non-symlink files
	// are candidates for the kernel allowlist. A candidate only becomes an entry
	// with package/FIM evidence or an explicit AllowPaths listing (§7.2).
	ExecRoots []string `json:"exec_roots"`
	// AllowPaths lists files or directories that are trusted explicitly. A
	// directory is walked with the same bounded rules as an ExecRoot.
	AllowPaths []string `json:"allow_paths"`
	// DevRoots are development roots. Phase 1 only documents them: they never
	// become a kernel allowance and never widen the exec gate (§7.1).
	DevRoots []string `json:"dev_roots"`
	// JitCgroups may execute anonymous JIT memory in the requested global mode
	// (TITAN_EXEC_SCOPE_FLAG_JIT_ALLOW). StrictCgroups pin a cell to strict mode.
	JitCgroups    []uint64 `json:"jit_cgroups"`
	StrictCgroups []uint64 `json:"strict_cgroups"`
	// MaxEntries bounds the compiled allowlist; MaxScopes bounds the per-cgroup
	// scope map. Both are validated against the kernel map sizes.
	MaxEntries   int  `json:"max_entries"`
	MaxScopes    int  `json:"max_scopes"`
	RequireCtime bool `json:"require_ctime"`
}

func defaultTitanExecFabricSettings() TitanExecFabricSettings {
	return TitanExecFabricSettings{
		Enabled:       false,
		Mode:          TitanExecModeOff,
		ExecRoots:     []string{},
		AllowPaths:    []string{},
		DevRoots:      []string{},
		JitCgroups:    []uint64{},
		StrictCgroups: []uint64{},
		MaxEntries:    titanExecDefaultMaxEntries,
		MaxScopes:     titanExecDefaultMaxScopes,
		RequireCtime:  false,
	}
}

func cloneTitanExecFabricSettings(in TitanExecFabricSettings) TitanExecFabricSettings {
	out := in
	out.ExecRoots = append(make([]string, 0, len(in.ExecRoots)), in.ExecRoots...)
	out.AllowPaths = append(make([]string, 0, len(in.AllowPaths)), in.AllowPaths...)
	out.DevRoots = append(make([]string, 0, len(in.DevRoots)), in.DevRoots...)
	out.JitCgroups = append(make([]uint64, 0, len(in.JitCgroups)), in.JitCgroups...)
	out.StrictCgroups = append(make([]uint64, 0, len(in.StrictCgroups)), in.StrictCgroups...)
	return out
}

// titanExecDefaults returns the bootstrap seed for a document that predates the
// namespace, following the other additive namespaces.
func titanExecDefaults(defaults RuntimeSettings) TitanExecFabricSettings {
	if defaults.TitanExec != nil {
		return cloneTitanExecFabricSettings(*defaults.TitanExec)
	}
	return defaultTitanExecFabricSettings()
}

// effectiveTitanExecFabricSettings resolves a persisted document into the
// administrable values. Disabled means mode off: the namespace is the master
// switch, exactly like the StyX default-off contract (§7.1).
func effectiveTitanExecFabricSettings(settings RuntimeSettings) TitanExecFabricSettings {
	out := defaultTitanExecFabricSettings()
	if settings.TitanExec != nil {
		out = cloneTitanExecFabricSettings(*settings.TitanExec)
	}
	// Defensive runtime guards: persisted revisions are validated before they are
	// written, so a documented document always carries a legal bound. A caller that
	// constructs the struct by hand (tests, an out-of-band import) must not be able
	// to hand the plan compiler a zero bound.
	if out.MaxEntries < 1 || out.MaxEntries > titanExecMaxPolicyEntries {
		out.MaxEntries = titanExecDefaultMaxEntries
	}
	if out.MaxScopes < 1 || out.MaxScopes > titanExecMaxPolicyScopes {
		out.MaxScopes = titanExecDefaultMaxScopes
	}
	if !out.Enabled || strings.TrimSpace(out.Mode) == "" {
		out.Mode = TitanExecModeOff
	}
	return out
}

// titanExecModeValue maps the settings text onto the kernel value (§3.1).
func titanExecModeValue(mode string) (uint8, error) {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "", TitanExecModeOff:
		return 0, nil
	case TitanExecModeObserve:
		return 1, nil
	case TitanExecModeContain:
		return 2, nil
	case TitanExecModeStrict:
		return 3, nil
	default:
		return 0, fmt.Errorf("titan exec mode %q must be off, observe, contain or strict", mode)
	}
}

func titanExecModeName(mode uint8) string {
	switch mode {
	case 1:
		return TitanExecModeObserve
	case 2:
		return TitanExecModeContain
	case 3:
		return TitanExecModeStrict
	default:
		return TitanExecModeOff
	}
}

// titanExecGlobalFlags is the SET_GLOBAL flags byte (§5: bit 0 requires the
// i_ctime re-check on every policy hit).
func titanExecGlobalFlags(in TitanExecFabricSettings) uint8 {
	if in.RequireCtime {
		return titanExecGlobalFlagRequireCtime
	}
	return 0
}

// titanExecCanonicalPath enforces the wire path contract of §5: absolute,
// canonical, bounded and free of every character that cannot travel through a
// VGT3 field. Paths are rejected, never repaired: a silently rewritten path would
// allow a different object than the operator named.
func titanExecCanonicalPath(raw string) (string, error) {
	if raw == "" {
		return "", errors.New("path is empty")
	}
	if len(raw) > titanExecMaxPathBytes {
		return "", fmt.Errorf("path exceeds %d bytes", titanExecMaxPathBytes)
	}
	for _, character := range raw {
		// VGT3 fields are whitespace/NUL/0x1f-free (§5); a space inside a path can
		// therefore never be synchronised and must be refused up front.
		if character <= 0x20 || character == 0x7f {
			return "", errors.New("path contains whitespace, control or NUL characters")
		}
	}
	if !filepath.IsAbs(raw) {
		return "", errors.New("path must be absolute")
	}
	if filepath.Clean(raw) != raw {
		return "", fmt.Errorf("path is not canonical (canonical form: %q)", filepath.Clean(raw))
	}
	return raw, nil
}

func canonicalizeTitanExecPaths(raw []string, label string, limit int) ([]string, error) {
	if len(raw) > limit {
		return nil, fmt.Errorf("titan exec %s list exceeds %d entries", label, limit)
	}
	seen := make(map[string]struct{}, len(raw))
	out := make([]string, 0, len(raw))
	for _, item := range raw {
		path, err := titanExecCanonicalPath(item)
		if err != nil {
			return nil, fmt.Errorf("titan exec %s %q: %w", label, item, err)
		}
		if _, duplicate := seen[path]; duplicate {
			return nil, fmt.Errorf("titan exec %s %q is duplicated", label, path)
		}
		seen[path] = struct{}{}
		out = append(out, path)
	}
	sort.Strings(out)
	return out, nil
}

func canonicalizeTitanExecCgroups(raw []uint64, label string, limit int) ([]uint64, error) {
	if len(raw) > limit {
		return nil, fmt.Errorf("titan exec %s list exceeds %d entries", label, limit)
	}
	seen := make(map[uint64]struct{}, len(raw))
	out := make([]uint64, 0, len(raw))
	for _, id := range raw {
		if id == 0 {
			return nil, fmt.Errorf("titan exec %s entry requires a non-zero cgroup id", label)
		}
		if _, duplicate := seen[id]; duplicate {
			return nil, fmt.Errorf("titan exec %s entry for cgroup %d is duplicated", label, id)
		}
		seen[id] = struct{}{}
		out = append(out, id)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out, nil
}

// validateTitanExecFabricSettings validates and canonicalises one namespace.
// Existing migrations never rewrite operator values; this is the same
// reject-not-repair contract the dashboard and the import path use.
func validateTitanExecFabricSettings(in *TitanExecFabricSettings) error {
	if in == nil {
		return errors.New("titan exec settings are missing")
	}
	mode, err := titanExecModeValue(in.Mode)
	if err != nil {
		return err
	}
	in.Mode = titanExecModeName(mode)
	if in.MaxEntries < 1 || in.MaxEntries > titanExecMaxPolicyEntries {
		return fmt.Errorf("titan exec max_entries must be between 1 and %d", titanExecMaxPolicyEntries)
	}
	if in.MaxScopes < 1 || in.MaxScopes > titanExecMaxPolicyScopes {
		return fmt.Errorf("titan exec max_scopes must be between 1 and %d", titanExecMaxPolicyScopes)
	}
	if in.ExecRoots, err = canonicalizeTitanExecPaths(in.ExecRoots, "exec_roots", titanExecMaxExecRoots); err != nil {
		return err
	}
	if in.AllowPaths, err = canonicalizeTitanExecPaths(in.AllowPaths, "allow_paths", titanExecMaxAllowPaths); err != nil {
		return err
	}
	if in.DevRoots, err = canonicalizeTitanExecPaths(in.DevRoots, "dev_roots", titanExecMaxDevRoots); err != nil {
		return err
	}
	if in.JitCgroups, err = canonicalizeTitanExecCgroups(in.JitCgroups, "jit_cgroups", in.MaxScopes); err != nil {
		return err
	}
	if in.StrictCgroups, err = canonicalizeTitanExecCgroups(in.StrictCgroups, "strict_cgroups", in.MaxScopes); err != nil {
		return err
	}
	// The scope map is sized by MaxScopes, not by each list, so the union is what
	// has to fit.
	union := make(map[uint64]struct{}, len(in.JitCgroups)+len(in.StrictCgroups))
	for _, id := range in.JitCgroups {
		union[id] = struct{}{}
	}
	for _, id := range in.StrictCgroups {
		union[id] = struct{}{}
	}
	if len(union) > in.MaxScopes {
		return fmt.Errorf("titan exec scope configuration uses %d cgroups but max_scopes is %d", len(union), in.MaxScopes)
	}
	// §7.1 Inert-Policy-Verbot: with mode off the kernel hook returns before any
	// policy lookup, so an operator-supplied rule would be a silent no-op that
	// looks like enforcement. A disabled namespace is allowed to carry a draft -
	// enabled=false is an explicit "nothing is claimed" state.
	if in.Enabled && mode == 0 && (len(in.ExecRoots) > 0 || len(in.AllowPaths) > 0 || len(in.DevRoots) > 0 || len(in.JitCgroups) > 0 || len(in.StrictCgroups) > 0) {
		return errors.New("titan exec mode=off with exec roots, allow paths or scopes has no effect; set mode=observe, contain or strict")
	}
	// STRICT denies anything not allowlisted, so it is only valid with at least one
	// configured source. An empty strict plan would be a system lockout (§8).
	if mode == 3 && len(in.ExecRoots) == 0 && len(in.AllowPaths) == 0 {
		return errors.New("titan exec mode=strict requires at least one exec root or allow path")
	}
	return nil
}
