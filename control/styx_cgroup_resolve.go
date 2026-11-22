// STATUS: DIAMANT VGT SUPREME
package main

// M3.1/M3.2: stable StyX cell identity.
//
// A numeric cgroup id is a kernel inode number: it changes on reboot and when
// systemd recreates a unit's cgroup. Persisting only that number is what made a
// StyX cell point at the wrong cgroup (or at nothing) after a restart. The
// operator-facing identity is therefore the *path* below the cgroup v2 root
// ("/system.slice/php8.3-fpm.service"); the numeric id is re-resolved from that
// path on every sync and is never treated as durable state.
//
// The resolution layer is deliberately pure on the settings side: it never
// mutates the persisted document, so a resolution failure can only make the
// status honest (degraded) - it can never rewrite a stale id into the store.

import (
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"
)

const (
	// styxCgroupV2Root is the unified cgroup v2 mount point.
	styxCgroupV2Root = "/sys/fs/cgroup"
	// styxCgroupPathMaxBytes bounds one stored logical cgroup path.
	styxCgroupPathMaxBytes = 512
	// styxCgroupPathMaxSegments bounds the directory depth of a logical path.
	styxCgroupPathMaxSegments = 32
	// styxIdentityReportMaxEntries bounds the operator-visible identity list.
	styxIdentityReportMaxEntries = 12
	// styxCgroupReasonMaxBytes bounds one reported resolution reason.
	styxCgroupReasonMaxBytes = 160
)

var (
	// errStyxCgroupV2Unavailable means the host does not expose the unified
	// hierarchy, so a cgroup_path cannot be trusted. A path rule is then reported
	// as unresolved (degraded) instead of being applied to a guessed id.
	errStyxCgroupV2Unavailable = errors.New("cgroup v2 unified hierarchy is not mounted; a cgroup path cannot be resolved")
	// errStyxCgroupPathMissing means the path is syntactically valid but absent.
	errStyxCgroupPathMissing = errors.New("cgroup path is not present in the unified hierarchy")
)

// styxIdentityState is the state of one operator-declared cell identity.
const (
	styxIdentityResolved   = "resolved"
	styxIdentityDrifted    = "drifted"
	styxIdentityUnresolved = "unresolved"
	styxIdentityLegacy     = "legacy"
)

// StyxIdentityState is one bounded, operator-readable identity entry. It carries
// a cgroup path and the freshly resolved kernel id - never a secret and never a
// claim that the kernel accepted the policy.
type StyxIdentityState struct {
	Path     string `json:"path"`
	CgroupID uint64 `json:"cgroup_id,omitempty"`
	State    string `json:"state"`
	Reason   string `json:"reason,omitempty"`
}

// styxIdentityReport summarises one resolution pass.
type styxIdentityReport struct {
	Resolved   int
	Unresolved int
	Drifted    int
	Legacy     int
	Paths      map[string]uint64
	Entries    []StyxIdentityState
}

// degraded reports whether the identity layer lost a cell or a rule.
func (r styxIdentityReport) degraded() bool { return r.Unresolved > 0 }

// degradationReason names the first unresolved identity in one bounded sentence.
func (r styxIdentityReport) degradationReason() string {
	if !r.degraded() {
		return ""
	}
	for _, entry := range r.Entries {
		if entry.State != styxIdentityUnresolved {
			continue
		}
		if entry.Path != "" {
			return fmt.Sprintf("cgroup_path %q could not be resolved: %s", entry.Path, entry.Reason)
		}
		return "cgroup identity could not be resolved: " + entry.Reason
	}
	return fmt.Sprintf("%d cgroup identity(ies) could not be resolved", r.Unresolved)
}

func (r *styxIdentityReport) addEntry(entry StyxIdentityState) {
	if len(r.Entries) >= styxIdentityReportMaxEntries {
		return
	}
	r.Entries = append(r.Entries, entry)
}

func boundedStyxCgroupReason(err error) string {
	if err == nil {
		return ""
	}
	text := strings.TrimSpace(strings.Join(strings.Fields(err.Error()), " "))
	if len(text) > styxCgroupReasonMaxBytes {
		text = text[:styxCgroupReasonMaxBytes]
	}
	return text
}

// styxCgroupResolver resolves one canonical logical cgroup path to the kernel
// cgroup id (the kernfs inode number used by bpf_get_current_cgroup_id). It is an
// interface so the syncer contract is testable without a privileged host.
type styxCgroupResolver interface {
	Resolve(logicalPath string) (uint64, error)
}

// styxSystemCgroupResolver resolves against the local unified hierarchy. On a
// non-Linux host the inode is not observable and every path entry is reported as
// unresolved instead of being guessed.
type styxSystemCgroupResolver struct {
	root string
}

func newStyxSystemCgroupResolver() styxCgroupResolver {
	return styxSystemCgroupResolver{root: styxCgroupV2Root}
}

func (r styxSystemCgroupResolver) Resolve(logicalPath string) (uint64, error) {
	canonical, err := normalizeStyxCgroupPath(logicalPath)
	if err != nil {
		return 0, err
	}
	root := r.root
	if root == "" {
		root = styxCgroupV2Root
	}
	if _, err := os.Stat(filepath.Join(root, "cgroup.controllers")); err != nil {
		return 0, errStyxCgroupV2Unavailable
	}
	target := filepath.Join(root, filepath.FromSlash(canonical))
	info, err := os.Lstat(target)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, fmt.Errorf("%w: %s", errStyxCgroupPathMissing, canonical)
		}
		return 0, fmt.Errorf("cgroup path %q cannot be inspected: %w", canonical, err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return 0, fmt.Errorf("cgroup path %q is not a plain directory", canonical)
	}
	inode, ok := styxCgroupInode(info)
	if !ok || inode == 0 || inode == 1 {
		return 0, fmt.Errorf("cgroup path %q has no usable kernel identity on this platform", canonical)
	}
	return inode, nil
}

// normalizeStyxCgroupPath validates and canonicalises one operator-provided
// cgroup path. Both the documented logical form ("/system.slice/x.service") and
// the explicit form below the mount point ("/sys/fs/cgroup/system.slice/...")
// are accepted; the persisted form is always the logical one. The hierarchy root
// itself, relative paths, empty/dot segments and control characters are rejected
// so a path can never escape the cgroup tree.
func normalizeStyxCgroupPath(raw string) (string, error) {
	text := strings.TrimSpace(raw)
	if text == "" {
		return "", errors.New("styX cgroup path is empty")
	}
	if len(text) > styxCgroupPathMaxBytes {
		return "", fmt.Errorf("styX cgroup path exceeds %d bytes", styxCgroupPathMaxBytes)
	}
	if strings.ContainsAny(text, "\x00\r\n\t ") {
		return "", errors.New("styX cgroup path contains rejected characters")
	}
	if !strings.HasPrefix(text, "/") {
		return "", errors.New("styX cgroup path must be absolute")
	}
	if text == styxCgroupV2Root {
		return "", errors.New("styX cgroup path must name a cgroup below the unified hierarchy root")
	}
	logical := text
	if strings.HasPrefix(logical, styxCgroupV2Root+"/") {
		logical = strings.TrimPrefix(logical, styxCgroupV2Root)
	}
	if path.Clean(logical) != logical {
		return "", fmt.Errorf("styX cgroup path %q is not canonical", raw)
	}
	segments := strings.Split(strings.TrimPrefix(logical, "/"), "/")
	if len(segments) == 0 || len(segments) > styxCgroupPathMaxSegments {
		return "", fmt.Errorf("styX cgroup path %q has an unsupported depth", raw)
	}
	for _, segment := range segments {
		if segment == "" || segment == "." || segment == ".." {
			return "", fmt.Errorf("styX cgroup path %q contains a rejected segment", raw)
		}
		for index := 0; index < len(segment); index++ {
			if !styxCgroupPathByte(segment[index]) {
				return "", fmt.Errorf("styX cgroup path %q contains a rejected character", raw)
			}
		}
	}
	return logical, nil
}

// styxCgroupPathByte accepts the bytes systemd and the kernel actually use in
// cgroup directory names, including systemd's "\x2d"-style escaping.
func styxCgroupPathByte(value byte) bool {
	switch {
	case value >= 'a' && value <= 'z', value >= 'A' && value <= 'Z', value >= '0' && value <= '9':
		return true
	case value == '-', value == '_', value == '.', value == ':', value == '@', value == '+', value == '=', value == '\\':
		return true
	default:
		return false
	}
}

// resolveStyxIdentities re-resolves every path-backed cell and allowlist entry
// against the live hierarchy. Entries whose path cannot be resolved keep
// CgroupID == 0 and are therefore omitted from the kernel plan by the plan
// builder (degraded, never a write to a stale id). Legacy entries that only carry
// a numeric id keep working byte-for-byte but are reported as such.
//
// previous maps a canonical path to the id resolved during the last successful
// sync; it is only used for drift detection.
func resolveStyxIdentities(in StyxFabricSettings, resolver styxCgroupResolver, previous map[string]uint64) (StyxFabricSettings, styxIdentityReport) {
	report := styxIdentityReport{Paths: map[string]uint64{}}
	out := cloneStyxFabricSettings(in)
	if resolver == nil {
		resolver = newStyxSystemCgroupResolver()
	}

	reportedPath := make(map[string]struct{}, len(in.PerCell)+len(in.Allowlist))
	resolveOne := func(rawPath string, storedID uint64) (uint64, string, bool) {
		if strings.TrimSpace(rawPath) == "" {
			if storedID == 0 {
				return 0, "", false
			}
			report.Legacy++
			report.addEntry(StyxIdentityState{State: styxIdentityLegacy, CgroupID: storedID,
				Reason: "numeric cgroup id only; add cgroup_path to survive a reboot or unit restart"})
			return storedID, rawPath, true
		}
		canonical, err := normalizeStyxCgroupPath(rawPath)
		if err != nil {
			report.Unresolved++
			report.addEntry(StyxIdentityState{Path: rawPath, State: styxIdentityUnresolved, Reason: boundedStyxCgroupReason(err)})
			return 0, "", false
		}
		id, err := resolver.Resolve(canonical)
		if err != nil {
			report.Unresolved++
			if _, seen := reportedPath[canonical]; !seen {
				reportedPath[canonical] = struct{}{}
				report.addEntry(StyxIdentityState{Path: canonical, State: styxIdentityUnresolved, Reason: boundedStyxCgroupReason(err)})
			}
			return 0, canonical, false
		}
		report.Resolved++
		report.Paths[canonical] = id
		if _, seen := reportedPath[canonical]; seen {
			// The same cgroup path backs both a cell mode and an allow rule; the
			// identity is one fact and is reported once.
			return id, canonical, true
		}
		reportedPath[canonical] = struct{}{}
		state := styxIdentityResolved
		reason := ""
		if before, known := previous[canonical]; known && before != 0 && before != id {
			report.Drifted++
			state = styxIdentityDrifted
			reason = fmt.Sprintf("cgroup id changed from %d to %d; the cell identity was re-resolved", before, id)
		}
		report.addEntry(StyxIdentityState{Path: canonical, CgroupID: id, State: state, Reason: reason})
		return id, canonical, true
	}

	for index := range out.PerCell {
		cell := &out.PerCell[index]
		id, canonicalPath, ok := resolveOne(cell.CgroupPath, cell.CgroupID)
		cell.CgroupID = id
		if ok && canonicalPath != "" {
			cell.CgroupPath = canonicalPath
		}
	}
	for index := range out.Allowlist {
		rule := &out.Allowlist[index]
		id, canonicalPath, ok := resolveOne(rule.CgroupPath, rule.CgroupID)
		rule.CgroupID = id
		if ok && canonicalPath != "" {
			rule.CgroupPath = canonicalPath
		}
	}
	return out, report
}
