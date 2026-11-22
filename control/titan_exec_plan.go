// STATUS: DIAMANT VGT SUPREME
package main

// POINT 1 / P1-T2: the pure Titan exec-gate plan compiler
// (docs/POINT1-TITAN-EXEC-GATE.md §7.2).
//
// Building a plan is side-effect free: it reads the filesystem, package/FIM
// evidence and the settings, and can therefore never leave a half-written kernel
// policy behind. It decides which paths are *candidates*; the privileged core
// resolves the authoritative (s_dev, i_ino, i_ctime) fd-safely on ALLOW_ADD. The
// observed identity in this plan is used for dedupe and change detection only and
// is never sent over the wire.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
)

const (
	titanExecPlanVersion = "titan-exec-plan-v1"

	// Bounded walk (§7.2): at most 32 directory levels and a hard visit ceiling
	// keep a hostile or accidental root tree from turning one sync into unbounded
	// work. The ceilings are plan errors, not silent truncation, because a partial
	// allowlist in STRICT mode would be a lockout.
	titanExecWalkMaxDepth   = 32
	titanExecWalkVisitLimit = 1 << 17
	// titanExecWalkReadBatch streams a directory instead of materialising all of
	// its entries, so a hostile root cannot force unbounded memory before the visit
	// ceiling applies.
	titanExecWalkReadBatch = 256

	// titanExecPlanHashMaxBytes bounds the FIM digest verification of one file. A
	// larger candidate simply has no FIM evidence (it can still be allowlisted
	// explicitly or be package-owned).
	titanExecPlanHashMaxBytes = 64 << 20
)

// titanExecPlanEntry is one allowlist entry. Action/Flags mirror the kernel policy
// value (§4) for diagnostics and the fingerprint; ObservedDev/ObservedIno/
// ObservedCtimeNS are the unprivileged observation used for hardlink dedupe and
// change detection. ALLOW_ADD sends the Path only.
type titanExecPlanEntry struct {
	Path            string
	ObservedDev     uint32
	ObservedIno     uint64
	ObservedCtimeNS uint64
	Action          uint8
	Flags           uint8
}

// titanExecPlanScope is one per-cgroup override (§4/§5 SCOPE_SET).
type titanExecPlanScope struct {
	CgroupID uint64
	Mode     uint8
	Flags    uint8
}

// titanExecPolicyPlan is the complete, validated desired kernel state. Fingerprint
// is the stable identity of the plan: the syncer pushes only when it changes.
type titanExecPolicyPlan struct {
	Enabled     bool
	ModeName    string
	Mode        uint8
	GlobalFlags uint8
	Entries     []titanExecPlanEntry
	Scopes      []titanExecPlanScope
	Fingerprint string
	// Rejected counts walked files skipped as symlink/non-regular/non-executable
	// (visible in the sync status, never silently swallowed).
	Rejected int
	// Unverified counts executable regular files under an exec root that have
	// neither package nor FIM evidence. They are not allowlisted; STRICT refuses
	// such a plan because the missing entries would be denied at exec time.
	Unverified  int
	WalkVisited int
}

// titanExecPlanDeps are the existing host evidence sources. A nil verifier means
// missing evidence, never implicit trust (titan.go: missing evidence lowers trust).
type titanExecPlanDeps struct {
	Packages titanPackageVerifier
	FIM      titanFIMLookup
}

// compileTitanExecPolicyPlan resolves one validated namespace into a plan. It is
// pure apart from bounded, read-only filesystem and evidence access.
func compileTitanExecPolicyPlan(ctx context.Context, settings TitanExecFabricSettings, deps titanExecPlanDeps) (titanExecPolicyPlan, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	normalized := cloneTitanExecFabricSettings(settings)
	if err := validateTitanExecFabricSettings(&normalized); err != nil {
		return titanExecPolicyPlan{}, fmt.Errorf("titan exec policy is invalid: %w", err)
	}
	mode, err := titanExecModeValue(normalized.Mode)
	if err != nil {
		return titanExecPolicyPlan{}, err
	}
	plan := titanExecPolicyPlan{Enabled: normalized.Enabled, ModeName: titanExecModeName(mode), Mode: mode}
	if !normalized.Enabled {
		// Disabled is the upgrade default. The plan is the documented empty state:
		// the syncer only sends the fail-safe global off and removes stale entries.
		plan.Mode, plan.ModeName = 0, TitanExecModeOff
		plan.Fingerprint = titanExecPlanFingerprint(plan)
		return plan, nil
	}
	plan.GlobalFlags = titanExecGlobalFlags(normalized)

	collector := &titanExecPlanCollector{ctx: ctx, settings: normalized, deps: deps, candidates: map[titanExecCandidateKey]titanExecCandidate{}}
	if err := collector.collect(); err != nil {
		return titanExecPolicyPlan{}, err
	}
	entries, unverified, err := collector.resolve()
	if err != nil {
		return titanExecPolicyPlan{}, err
	}
	plan.Entries, plan.Unverified, plan.Rejected, plan.WalkVisited = entries, unverified, collector.rejected, collector.visited
	plan.Scopes = titanExecCompileScopes(normalized, plan.Mode)
	if len(plan.Entries) > normalized.MaxEntries {
		return titanExecPolicyPlan{}, fmt.Errorf("titan exec plan resolves %d allow entries but max_entries is %d; narrow the roots or raise the bound", len(plan.Entries), normalized.MaxEntries)
	}
	if plan.Mode == 3 {
		// STRICT denies every exec that is not allowlisted. A plan with unverified
		// candidates or no entries would be a system lockout, so it is refused
		// visibly instead of being handed to the kernel (§8).
		if plan.Unverified > 0 {
			return titanExecPolicyPlan{}, fmt.Errorf("titan exec strict plan has %d executable file(s) under the configured roots without package/FIM evidence; add them to allow_paths or verify them first", plan.Unverified)
		}
		if len(plan.Entries) == 0 {
			return titanExecPolicyPlan{}, errors.New("titan exec strict plan resolved no allow entries; refusing a policy that would deny every exec")
		}
	}
	plan.Fingerprint = titanExecPlanFingerprint(plan)
	return plan, nil
}

// titanExecPlanFingerprint is the deterministic SHA-256 identity of one plan. The
// observed identity is part of it: a replaced binary at the same path must force a
// re-sync even though the path string did not change.
func titanExecPlanFingerprint(plan titanExecPolicyPlan) string {
	digest := sha256.New()
	fmt.Fprintf(digest, "%s|%t|%d|%d\n", titanExecPlanVersion, plan.Enabled, plan.Mode, plan.GlobalFlags)
	for _, entry := range plan.Entries {
		fmt.Fprintf(digest, "entry|%s|%d|%d|%d|%d|%d\n",
			entry.Path, entry.ObservedDev, entry.ObservedIno, entry.ObservedCtimeNS, entry.Action, entry.Flags)
	}
	for _, scope := range plan.Scopes {
		fmt.Fprintf(digest, "scope|%d|%d|%d\n", scope.CgroupID, scope.Mode, scope.Flags)
	}
	return hex.EncodeToString(digest.Sum(nil))
}

// titanExecCompileScopes merges the JIT and strict cgroup lists into one scope per
// cgroup. A JIT-only scope keeps the global mode and adds the JIT exception; a
// cgroup in both lists keeps the JIT flag but is pinned to STRICT.
func titanExecCompileScopes(settings TitanExecFabricSettings, globalMode uint8) []titanExecPlanScope {
	type scopeKey = uint64
	modes := make(map[scopeKey]uint8, len(settings.StrictCgroups))
	flags := make(map[scopeKey]uint8, len(settings.JitCgroups))
	union := make(map[scopeKey]struct{}, len(settings.JitCgroups)+len(settings.StrictCgroups))
	for _, cgroupID := range settings.JitCgroups {
		flags[cgroupID] |= titanExecScopeFlagJitAllow
		union[cgroupID] = struct{}{}
	}
	for _, cgroupID := range settings.StrictCgroups {
		modes[cgroupID] = 3
		union[cgroupID] = struct{}{}
	}
	out := make([]titanExecPlanScope, 0, len(union))
	for cgroupID := range union {
		mode, pinned := modes[cgroupID]
		if !pinned {
			mode = globalMode
			// V6.2: TITAN_EXEC_MODE_UNTRUSTED (4) is a global-only mode; the scope
			// ABI keeps 0..3. A JIT scope that inherits the global mode is pinned to
			// STRICT here (the most restrictive scope mode) and keeps its JIT flag,
			// so the new global mode can never send an out-of-range scope mode.
			if mode > 3 {
				mode = 3
			}
		}
		out = append(out, titanExecPlanScope{CgroupID: cgroupID, Mode: mode, Flags: flags[cgroupID]})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CgroupID < out[j].CgroupID })
	return out
}

// --------------------------------------------------------------- collector

type titanExecCandidateKey struct {
	Dev uint32
	Ino uint64
}

type titanExecCandidate struct {
	Entry   titanExecPlanEntry
	Trusted bool
	// Names are every walked path that maps to this kernel identity (hard links).
	// Evidence is looked up per name, because package ownership and the FIM
	// baseline are recorded per path while the kernel policy is per inode.
	Names []string
}

type titanExecPlanCollector struct {
	ctx      context.Context
	settings TitanExecFabricSettings
	deps     titanExecPlanDeps

	candidates map[titanExecCandidateKey]titanExecCandidate
	rejected   int
	visited    int
}

func (c *titanExecPlanCollector) collect() error {
	for _, path := range c.settings.AllowPaths {
		if err := c.collectExplicit(path); err != nil {
			return err
		}
	}
	for _, root := range c.settings.ExecRoots {
		if err := c.collectExecRoot(root); err != nil {
			return err
		}
	}
	// c.settings.DevRoots are deliberately not walked: phase 1 documents them and
	// they never become a kernel allowance (§2, §7.1).
	return nil
}

func (c *titanExecPlanCollector) collectExplicit(raw string) error {
	info, err := c.inspect(raw, "allow path")
	if err != nil {
		return err
	}
	if info.IsDir() {
		return c.walkDirectory(raw, 0, true)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("titan exec allow path %q is not a regular file or directory", raw)
	}
	if info.Mode().Perm()&0o111 == 0 {
		return fmt.Errorf("titan exec allow path %q is not executable", raw)
	}
	identity, ok := titanExecIdentityOf(info)
	if !ok {
		return fmt.Errorf("titan exec allow path %q has no usable inode identity", raw)
	}
	c.addCandidate(raw, identity, true)
	return nil
}

func (c *titanExecPlanCollector) collectExecRoot(raw string) error {
	info, err := c.inspect(raw, "exec root")
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return fmt.Errorf("titan exec exec root %q is not a directory", raw)
	}
	return c.walkDirectory(raw, 0, false)
}

// inspect rejects an explicitly configured path that cannot be trusted as-is: a
// symlink anywhere in the configured path would silently point the walk (and the
// operator's intent) somewhere else (§7.2 "kein stiller Follow").
func (c *titanExecPlanCollector) inspect(raw, label string) (os.FileInfo, error) {
	if _, err := titanExecCanonicalPath(raw); err != nil {
		return nil, fmt.Errorf("titan exec %s %q: %w", label, raw, err)
	}
	if err := titanExecRejectSymlinkComponents(raw); err != nil {
		return nil, fmt.Errorf("titan exec %s %q: %w", label, raw, err)
	}
	info, err := os.Lstat(raw)
	if err != nil {
		return nil, fmt.Errorf("titan exec %s %q cannot be inspected: %w", label, raw, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("titan exec %s %q is a symlink; list the resolved path instead", label, raw)
	}
	return info, nil
}

func (c *titanExecPlanCollector) walkDirectory(dir string, depth int, explicit bool) error {
	if depth > titanExecWalkMaxDepth {
		c.rejected++
		return nil
	}
	if err := c.ctx.Err(); err != nil {
		return err
	}
	directory, err := os.Open(dir)
	if err != nil {
		// A directory that cannot be read means the plan would be incomplete; that
		// is a plan error, never a silent partial allowlist (§7.2).
		return fmt.Errorf("titan exec walk of %q failed: %w", dir, err)
	}
	defer directory.Close()
	for {
		children, readErr := directory.ReadDir(titanExecWalkReadBatch)
		for _, child := range children {
			if err := c.ctx.Err(); err != nil {
				return err
			}
			c.visited++
			if c.visited > titanExecWalkVisitLimit {
				return fmt.Errorf("titan exec walk exceeded the bounded visit limit of %d files", titanExecWalkVisitLimit)
			}
			path := filepath.Join(dir, child.Name())
			if child.Type()&os.ModeSymlink != 0 {
				// Symlinks are skipped, counted, and never followed.
				c.rejected++
				continue
			}
			if child.IsDir() {
				if err := c.walkDirectory(path, depth+1, explicit); err != nil {
					return err
				}
				continue
			}
			info, err := child.Info()
			if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 {
				c.rejected++
				continue
			}
			identity, ok := titanExecIdentityOf(info)
			if !ok {
				return fmt.Errorf("titan exec walk of %q: %q has no usable inode identity", dir, path)
			}
			c.addCandidate(path, identity, explicit)
		}
		if readErr != nil {
			if readErr == io.EOF {
				return nil
			}
			return fmt.Errorf("titan exec walk of %q failed: %w", dir, readErr)
		}
	}
}

// addCandidate stores one candidate per kernel identity. Hard links share
// (dev, ino): one deterministic (lexicographically smallest) path is kept and the
// strongest evidence wins, because the kernel policy is per inode, not per name.
func (c *titanExecPlanCollector) addCandidate(path string, identity titanExecFileIdentity, trusted bool) {
	key := titanExecCandidateKey{Dev: identity.Dev, Ino: identity.Ino}
	entry := titanExecPlanEntry{
		Path: path, ObservedDev: identity.Dev, ObservedIno: identity.Ino, ObservedCtimeNS: identity.CtimeNS,
		Action: titanExecActionAllow, Flags: c.entryFlags(),
	}
	existing, exists := c.candidates[key]
	if !exists {
		c.candidates[key] = titanExecCandidate{Entry: entry, Trusted: trusted, Names: []string{path}}
		return
	}
	merged := existing
	merged.Trusted = existing.Trusted || trusted
	merged.Names = append(merged.Names, path)
	if path < existing.Entry.Path {
		merged.Entry = entry
	}
	c.candidates[key] = merged
}

func (c *titanExecPlanCollector) entryFlags() uint8 {
	if c.settings.RequireCtime {
		return titanExecPolicyFlagRequireCtime
	}
	return 0
}

// resolve applies the documented phase-1 trust ladder to every candidate: a file
// under an exec root becomes an entry only with package ownership or a FIM
// baseline digest match; an explicit allow path is its own authorization (§7.2).
func (c *titanExecPlanCollector) resolve() ([]titanExecPlanEntry, int, error) {
	entries := make([]titanExecPlanEntry, 0, len(c.candidates))
	unverified := 0
	for _, candidate := range c.candidates {
		trusted := candidate.Trusted
		if !trusted {
			for _, name := range candidate.Names {
				verified, err := c.verify(name)
				if err != nil {
					return nil, 0, err
				}
				if verified {
					trusted = true
					break
				}
			}
		}
		if !trusted {
			unverified++
			continue
		}
		entries = append(entries, candidate.Entry)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Path < entries[j].Path })
	return entries, unverified, nil
}

func (c *titanExecPlanCollector) verify(path string) (bool, error) {
	if err := c.ctx.Err(); err != nil {
		return false, err
	}
	if c.deps.Packages != nil {
		owner, owned, err := c.deps.Packages.Owner(c.ctx, path)
		if err == nil && owned && (owner.Package != "" || owner.Manager != "") {
			return true, nil
		}
	}
	if c.deps.FIM != nil {
		record, _, known := c.deps.FIM.TitanBaselineRecord(path)
		if known && titanExecFIMEvidenceMatches(path, record) {
			return true, nil
		}
	}
	return false, nil
}

// titanExecFIMEvidenceMatches requires the real on-disk digest to equal the
// approved baseline; a mere baseline record for the path is not evidence.
func titanExecFIMEvidenceMatches(path string, record FIMRecord) bool {
	if record.SHA256 == "" {
		return false
	}
	identity := readTitanIdentity(path, titanExecPlanHashMaxBytes)
	if identity.Error != "" || !identity.Exists || identity.Symlink || !identity.Regular || identity.SHA256 == "" {
		return false
	}
	if record.Size != 0 && record.Size != identity.Size {
		return false
	}
	return strings.EqualFold(record.SHA256, identity.SHA256)
}

// --------------------------------------------------------------- inode identity

type titanExecFileIdentity struct {
	Dev     uint32
	Ino     uint64
	CtimeNS uint64
}

func titanExecIdentityOf(info os.FileInfo) (titanExecFileIdentity, bool) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat == nil {
		return titanExecFileIdentity{}, false
	}
	seconds := int64(stat.Ctim.Sec)
	nanoseconds := int64(stat.Ctim.Nsec)
	if seconds < 0 || nanoseconds < 0 {
		return titanExecFileIdentity{}, false
	}
	return titanExecFileIdentity{
		Dev:     uint32(stat.Dev),
		Ino:     stat.Ino,
		CtimeNS: uint64(seconds)*1_000_000_000 + uint64(nanoseconds),
	}, true
}

// titanExecRejectSymlinkComponents verifies that no component of an
// operator-configured path is a symlink. Only the configured roots are checked
// this way; entries discovered by the bounded walk are checked per child.
func titanExecRejectSymlinkComponents(path string) error {
	clean := filepath.Clean(path)
	if !filepath.IsAbs(clean) {
		return errors.New("path must be absolute")
	}
	current := string(filepath.Separator)
	for _, part := range strings.Split(strings.TrimPrefix(clean, string(filepath.Separator)), string(filepath.Separator)) {
		if part == "" {
			continue
		}
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if err != nil {
			return fmt.Errorf("path component %q cannot be inspected: %w", current, err)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("path component %q is a symlink", current)
		}
	}
	return nil
}
