// STATUS: DIAMANT VGT SUPREME
package main

import (
	"fmt"
	"sort"
	"strings"
)

// Integrity Fabric administration.
//
// Plan reference: GeDefense 4.2 Security Fabric Control Plane, section 21.
//
// Scope decision: enablement, bounds, intervals and response wiring are
// administrable. Two things are deliberately NOT administrable because exposing
// them would let a configuration change destroy the evidence the fabric exists
// to produce:
//
//   - The evidence ledger cannot be switched off. Operator mutations require a
//     healthy, signed ledger, and that gate is an invariant (plan section 43).
//   - There is no "create a baseline automatically" switch. Blessing whatever
//     happens to be on disk at startup is how an integrity system certifies a
//     compromised host.

// ---------------------------------------------------------------- FIM

type FIMFabricSettings struct {
	Enabled          bool     `json:"enabled"`
	Roots            []string `json:"roots"`
	IntervalSeconds  int      `json:"interval_seconds"`
	MaxFiles         int      `json:"max_files"`
	MaxFileBytes     int64    `json:"max_file_bytes"`
	MaxTotalBytes    int64    `json:"max_total_bytes"`
	MaxBaselineBytes int64    `json:"max_baseline_bytes"`
	MaxFindings      int      `json:"max_findings"`
}

// ------------------------------------------------------------- Chronos

// Chronos runs on the shared integrity cadence (FIM.IntervalSeconds), so the two
// integrity passes can never be scheduled against contradictory intervals.
type ChronosFabricSettings struct {
	Enabled       bool     `json:"enabled"`
	Roots         []string `json:"roots"`
	BatchSize     int      `json:"batch_size"`
	YieldMillis   int      `json:"yield_millis"`
	MaxFiles      int      `json:"max_files"`
	MaxTotalBytes int64    `json:"max_total_bytes"`
}

// ------------------------------------------------------------ Packages

// Package integrity administers *when* verification runs. The bounded walk
// limits remain compiled-in hard safety invariants (plan section 43): they are
// what keeps a hostile or corrupt package database from exhausting the host.
type PackageFabricSettings struct {
	Enabled       bool `json:"enabled"`
	AutoScan      bool `json:"auto_scan"`
	IntervalHours int  `json:"interval_hours"`
}

// ------------------------------------------------------------ Evidence

type EvidenceFabricSettings struct {
	MaxBytes              int64 `json:"max_bytes"`
	VerifyIntervalSeconds int   `json:"verify_interval_seconds"`
	APIRecentDefault      int   `json:"api_recent_default"`
	APIRecentMax          int   `json:"api_recent_max"`
}

// ----------------------------------------------------------- namespace

type IntegrityFabricSettings struct {
	FIM      FIMFabricSettings      `json:"fim"`
	Chronos  ChronosFabricSettings  `json:"chronos"`
	Packages PackageFabricSettings  `json:"packages"`
	Evidence EvidenceFabricSettings `json:"evidence"`
}

const (
	integrityFIMRootLimit     = 256
	integrityChronosRootLimit = 64
	integrityFIMIntervalFloor = 30
)

// defaultIntegrityFabricSettings derives the first Fabric revision from the
// compiled-in behaviour of every integrity engine, so an existing deployment
// keeps exactly its previous posture after migration.
func defaultIntegrityFabricSettings(cfg Config) IntegrityFabricSettings {
	roots := append([]string(nil), cfg.XDR.ProtectedPaths...)
	if len(roots) == 0 {
		roots = []string{"/etc", "/usr/bin", "/usr/sbin"}
	}
	interval := cfg.XDR.IntegrityIntervalSeconds
	if interval < integrityFIMIntervalFloor {
		interval = integrityFIMIntervalFloor
	}
	return IntegrityFabricSettings{
		FIM: FIMFabricSettings{
			Enabled: true, Roots: roots, IntervalSeconds: interval,
			MaxFiles: 8192, MaxFileBytes: 64 << 20, MaxTotalBytes: 512 << 20,
			MaxBaselineBytes: 16 << 20, MaxFindings: 500,
		},
		Chronos: ChronosFabricSettings{
			Enabled: true, Roots: []string{"/usr/bin", "/etc"},
			BatchSize: 100, YieldMillis: 1,
			MaxFiles: 200000, MaxTotalBytes: 64 << 30,
		},
		Packages: PackageFabricSettings{Enabled: true, AutoScan: false, IntervalHours: 24},
		Evidence: EvidenceFabricSettings{
			MaxBytes: 64 << 20, VerifyIntervalSeconds: 900,
			APIRecentDefault: 100, APIRecentMax: 500,
		},
	}
}

func cloneIntegrityFabricSettings(in IntegrityFabricSettings) IntegrityFabricSettings {
	out := in
	out.FIM.Roots = append([]string(nil), in.FIM.Roots...)
	out.Chronos.Roots = append([]string(nil), in.Chronos.Roots...)
	return out
}

// validateIntegrityFabricSettings normalizes and bounds the namespace.
func validateIntegrityFabricSettings(settings *IntegrityFabricSettings) error {
	// ---------------------------------------------------------------- FIM
	if err := validateIntegrityRoots("FIM", settings.FIM.Roots, integrityFIMRootLimit); err != nil {
		return err
	}
	if settings.FIM.Enabled && len(settings.FIM.Roots) == 0 {
		return fmt.Errorf("file integrity monitoring requires at least one protected root while enabled")
	}
	if settings.FIM.IntervalSeconds < integrityFIMIntervalFloor || settings.FIM.IntervalSeconds > 86400 {
		return fmt.Errorf("FIM scan interval must be between %d and 86400 seconds", integrityFIMIntervalFloor)
	}
	if settings.FIM.MaxFiles < 16 || settings.FIM.MaxFiles > 1000000 {
		return fmt.Errorf("FIM file budget must be between 16 and 1000000")
	}
	if settings.FIM.MaxFileBytes < 1<<10 || settings.FIM.MaxFileBytes > 4<<30 {
		return fmt.Errorf("FIM per-file size boundary must be between 1 KiB and 4 GiB")
	}
	if settings.FIM.MaxTotalBytes < 1<<20 || settings.FIM.MaxTotalBytes > 64<<30 {
		return fmt.Errorf("FIM aggregate size boundary must be between 1 MiB and 64 GiB")
	}
	if settings.FIM.MaxTotalBytes < settings.FIM.MaxFileBytes {
		return fmt.Errorf("FIM aggregate size boundary must be at least the per-file boundary")
	}
	if settings.FIM.MaxBaselineBytes < 64<<10 || settings.FIM.MaxBaselineBytes > 256<<20 {
		return fmt.Errorf("FIM baseline boundary must be between 64 KiB and 256 MiB")
	}
	if settings.FIM.MaxFindings < 10 || settings.FIM.MaxFindings > 100000 {
		return fmt.Errorf("FIM finding budget must be between 10 and 100000")
	}

	// ------------------------------------------------------------ Chronos
	if err := validateIntegrityRoots("Chronos", settings.Chronos.Roots, integrityChronosRootLimit); err != nil {
		return err
	}
	if settings.Chronos.Enabled && len(settings.Chronos.Roots) == 0 {
		return fmt.Errorf("Chronos checkpointing requires at least one root while enabled")
	}

	if settings.Chronos.BatchSize < 1 || settings.Chronos.BatchSize > 100000 {
		return fmt.Errorf("Chronos batch size must be between 1 and 100000")
	}
	if settings.Chronos.YieldMillis < 0 || settings.Chronos.YieldMillis > 1000 {
		return fmt.Errorf("Chronos yield must be between 0 and 1000 milliseconds")
	}
	if settings.Chronos.MaxFiles < 16 || settings.Chronos.MaxFiles > 5000000 {
		return fmt.Errorf("Chronos file budget must be between 16 and 5000000")
	}
	if settings.Chronos.MaxTotalBytes < 1<<20 || settings.Chronos.MaxTotalBytes > 1<<40 {
		return fmt.Errorf("Chronos byte budget must be between 1 MiB and 1 TiB")
	}

	// ----------------------------------------------------------- Packages
	if settings.Packages.IntervalHours < 1 || settings.Packages.IntervalHours > 720 {
		return fmt.Errorf("package scan interval must be between 1 and 720 hours")
	}

	// ----------------------------------------------------------- Evidence
	if settings.Evidence.MaxBytes < 1<<20 || settings.Evidence.MaxBytes > 64<<30 {
		return fmt.Errorf("evidence ledger budget must be between 1 MiB and 64 GiB")
	}
	if settings.Evidence.VerifyIntervalSeconds < 30 || settings.Evidence.VerifyIntervalSeconds > 86400 {
		return fmt.Errorf("evidence verification interval must be between 30 and 86400 seconds")
	}
	if settings.Evidence.APIRecentDefault < 1 || settings.Evidence.APIRecentDefault > 500 {
		return fmt.Errorf("evidence page default must be between 1 and 500")
	}
	if settings.Evidence.APIRecentMax < settings.Evidence.APIRecentDefault || settings.Evidence.APIRecentMax > 4096 {
		return fmt.Errorf("evidence page ceiling must be at least the default and at most 4096")
	}
	return nil
}

// validateIntegrityRoots normalizes an absolute, clean, duplicate-free root list.
func validateIntegrityRoots(label string, roots []string, limit int) error {
	if len(roots) > limit {
		return fmt.Errorf("%s root list exceeds %d entries", label, limit)
	}
	seen := make(map[string]struct{}, len(roots))
	out := make([]string, 0, len(roots))
	for _, raw := range roots {
		root := strings.TrimSpace(raw)
		if err := validateAbsoluteCleanPath(label+" root", root); err != nil {
			return err
		}
		if root == "/" {
			return fmt.Errorf("%s root must not be the filesystem root", label)
		}
		if _, exists := seen[root]; exists {
			continue
		}
		seen[root] = struct{}{}
		out = append(out, root)
	}
	sort.Strings(out)
	copy(roots, out)
	return nil
}

// effectiveIntegritySettings returns the persisted Integrity namespace.
func effectiveIntegritySettings(settings RuntimeSettings) IntegrityFabricSettings {
	if settings.Integrity != nil {
		return cloneIntegrityFabricSettings(*settings.Integrity)
	}
	return defaultIntegrityFabricSettings(Config{})
}

// ------------------------------------------------------------ FIM policy

type fimPolicy struct {
	enabled          bool
	intervalSeconds  int
	maxFiles         int
	maxFileBytes     int64
	maxTotalBytes    int64
	maxBaselineBytes int64
	maxFindings      int
}

func (s FIMFabricSettings) policy() fimPolicy {
	return fimPolicy{
		enabled: s.Enabled, intervalSeconds: s.IntervalSeconds,
		maxFiles: s.MaxFiles, maxFileBytes: s.MaxFileBytes, maxTotalBytes: s.MaxTotalBytes,
		maxBaselineBytes: s.MaxBaselineBytes, maxFindings: s.MaxFindings,
	}
}

func (e *FIMEngine) policySnapshot() fimPolicy {
	e.mu.RLock()
	defer e.mu.RUnlock()
	policy := e.policy
	if policy.maxFiles <= 0 {
		policy = defaultIntegrityFabricSettings(Config{}).FIM.policy()
	}
	return policy
}

// ApplyPolicy republishes the administrable FIM bounds. Roots and the baseline
// path remain restart-class because the stored baseline is bound to them: a
// different root set would silently invalidate the baseline that anchors every
// comparison.
func (e *FIMEngine) ApplyPolicy(settings FIMFabricSettings) error {
	if e == nil {
		return nil
	}
	if len(settings.Roots) > 0 && !equalStringSlices(settings.Roots, e.Roots()) {
		return fmt.Errorf("FIM protected roots are restart-class: the stored baseline is bound to the current root set")
	}
	e.mu.Lock()
	e.policy = settings.policy()
	e.mu.Unlock()
	return nil
}

// Enabled reports whether periodic and on-demand scanning participates.
func (e *FIMEngine) Enabled() bool {
	if e == nil {
		return false
	}
	return e.policySnapshot().enabled
}

// Roots returns the protected root set the engine was constructed with.
func (e *FIMEngine) Roots() []string {
	if e == nil {
		return nil
	}
	e.mu.RLock()
	defer e.mu.RUnlock()
	return append([]string(nil), e.roots...)
}

func equalStringSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	sorted := append([]string(nil), a...)
	sort.Strings(sorted)
	other := append([]string(nil), b...)
	sort.Strings(other)
	for i := range sorted {
		if sorted[i] != other[i] {
			return false
		}
	}
	return true
}

// ------------------------------------------------------- Chronos policy

type chronosPolicy struct {
	enabled       bool
	batchSize     int
	yieldMillis   int
	maxFiles      int
	maxTotalBytes int64
}

func (s ChronosFabricSettings) policy() chronosPolicy {
	return chronosPolicy{
		enabled: s.Enabled, batchSize: s.BatchSize,
		yieldMillis: s.YieldMillis, maxFiles: s.MaxFiles, maxTotalBytes: s.MaxTotalBytes,
	}
}

func (c *ChronosScanner) policySnapshot() chronosPolicy {
	c.mu.Lock()
	defer c.mu.Unlock()
	policy := c.policy
	if policy.maxFiles <= 0 {
		policy = defaultIntegrityFabricSettings(Config{}).Chronos.policy()
	}
	return policy
}

// ApplyPolicy republishes the administrable Chronos bounds. Roots and the
// checkpoint path remain restart-class because the resumable checkpoint is
// bound to the root set it was produced from.
func (c *ChronosScanner) ApplyPolicy(settings ChronosFabricSettings) error {
	if c == nil {
		return nil
	}
	if len(settings.Roots) > 0 && !equalStringSlices(settings.Roots, c.Roots()) {
		return fmt.Errorf("Chronos roots are restart-class: the resumable checkpoint is bound to the current root set")
	}
	c.mu.Lock()
	c.policy = settings.policy()
	c.mu.Unlock()
	return nil
}

// Enabled reports whether periodic checkpointing participates.
func (c *ChronosScanner) Enabled() bool {
	if c == nil {
		return false
	}
	return c.policySnapshot().enabled
}

// Roots returns the root set the scanner was constructed with.
func (c *ChronosScanner) Roots() []string {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.roots...)
}

// ------------------------------------------------------ Packages policy

type packagePolicy struct {
	enabled     bool
	autoScan    bool
	intervalHrs int
}

func (s PackageFabricSettings) policy() packagePolicy {
	return packagePolicy{enabled: s.Enabled, autoScan: s.AutoScan, intervalHrs: s.IntervalHours}
}

func (p *PackageIntegrityScanner) policySnapshot() packagePolicy {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.policy
}

// ApplyPolicy republishes the administrable package verification schedule. The
// database and filesystem roots are bootstrap values: the scanner jails every
// read against them and re-rooting a running scan would be a policy change
// disguised as a setting.
func (p *PackageIntegrityScanner) ApplyPolicy(settings PackageFabricSettings) error {
	if p == nil {
		return nil
	}
	p.mu.Lock()
	p.policy = settings.policy()
	p.mu.Unlock()
	return nil
}

// Enabled reports whether periodic package verification participates.
func (p *PackageIntegrityScanner) Enabled() bool {
	if p == nil {
		return false
	}
	return p.policySnapshot().enabled
}

// ------------------------------------------------- integrity distribution

// applyIntegrityPolicies projects the Integrity namespace onto the engines that
// consume it from one choke point, so a revision can never reach one integrity
// engine and not the others.
func applyIntegrityPolicies(settings IntegrityFabricSettings, fim *FIMEngine, chronos *ChronosScanner, packages *PackageIntegrityScanner, evidence *EvidenceLedger) error {
	if fim != nil {
		// Keep baseline-bound roots active until restart; hot budgets still apply.
		settings.FIM.Roots = fim.Roots()
		if err := fim.ApplyPolicy(settings.FIM); err != nil {
			return fmt.Errorf("apply FIM policy: %w", err)
		}
	}
	if chronos != nil {
		settings.Chronos.Roots = chronos.Roots()
		if err := chronos.ApplyPolicy(settings.Chronos); err != nil {
			return fmt.Errorf("apply Chronos policy: %w", err)
		}
	}
	if packages != nil {
		if err := packages.ApplyPolicy(settings.Packages); err != nil {
			return fmt.Errorf("apply package integrity policy: %w", err)
		}
	}
	if evidence != nil {
		if err := evidence.ApplyPolicy(settings.Evidence); err != nil {
			return fmt.Errorf("apply evidence policy: %w", err)
		}
	}
	return nil
}
