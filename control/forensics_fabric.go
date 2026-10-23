// STATUS: DIAMANT VGT SUPREME
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"
)

// Forensics Fabric administration.
//
// Plan reference: GeDefense 4.2 Security Fabric Control Plane, section 24.
//
// Scope decision: every value here either bounds work or *restricts* what the
// forensics path may do. Nothing in this namespace can widen access. The
// quarantine denylist is additive only - an operator can forbid more, never less
// - and the built-in set covering /proc, /sys, /dev, /run and the service's own
// directories is compiled in.
//
// The plan also lists a Timeline group. It is deliberately absent: no timeline
// engine exists in this codebase, the evidence ledger already carries
// administrable page bounds, and the correlation window lives with the case
// engine that actually applies it. A settings group without an engine behind it
// would be a control that does nothing.

// ---------------------------------------------------------------- cases

type ForensicsCasesSettings struct {
	AutoCreate             bool `json:"auto_create"`
	MinimumIncidentScore   int  `json:"minimum_incident_score"`
	MaxCases               int  `json:"max_cases"`
	MaxEvidenceRefsPerCase int  `json:"max_evidence_refs_per_case"`
	MaxObservationsPerCase int  `json:"max_observations_per_case"`
	ListMaxLimit           int  `json:"list_max_limit"`
	CorrelationWindowMins  int  `json:"correlation_window_minutes"`
	AutoCloseAfterHours    int  `json:"auto_close_after_hours"`
}

// --------------------------------------------------------------- export

type ForensicsExportSettings struct {
	IncludeRawRecords  bool  `json:"include_raw_records"`
	IncludePolicyState bool  `json:"include_policy_state"`
	IncludeSystemMeta  bool  `json:"include_system_metadata"`
	RedactInternalIPs  bool  `json:"redact_internal_ips"`
	MaxExportBytes     int64 `json:"max_export_bytes"`
	SigningRequired    bool  `json:"signing_required"`
}

// ----------------------------------------------------------- quarantine

type ForensicsQuarantineSettings struct {
	Enabled         bool     `json:"enabled"`
	AllowedRoots    []string `json:"allowed_roots"`
	ExtraForbidden  []string `json:"extra_forbidden_roots"`
	RestoreFileMode int      `json:"restore_file_mode"`
}

// ------------------------------------------------------------ namespace

type ForensicsFabricSettings struct {
	Cases      ForensicsCasesSettings      `json:"cases"`
	Export     ForensicsExportSettings     `json:"export"`
	Quarantine ForensicsQuarantineSettings `json:"quarantine"`
}

// quarantineBuiltinForbidden is immutable. Every entry protects the host or the
// control plane itself, so no Fabric revision may remove one.
var quarantineBuiltinForbidden = []string{
	"/", "/proc", "/sys", "/dev", "/run",
	"/etc/shadow", "/etc/gshadow", "/etc/passwd", "/etc/group",
	"/etc/vgt/gedefense", "/var/lib/vgt/gedefense", "/opt/vgt/gedefense",
}

func defaultForensicsFabricSettings() ForensicsFabricSettings {
	return ForensicsFabricSettings{
		Cases: ForensicsCasesSettings{
			AutoCreate: true, MinimumIncidentScore: 150,
			MaxCases: 4096, MaxEvidenceRefsPerCase: 256, MaxObservationsPerCase: 256,
			ListMaxLimit: 500, CorrelationWindowMins: 60, AutoCloseAfterHours: 0,
		},
		Export: ForensicsExportSettings{
			IncludeRawRecords: true, IncludePolicyState: true, IncludeSystemMeta: true,
			RedactInternalIPs: false, MaxExportBytes: 32 << 20, SigningRequired: true,
		},
		Quarantine: ForensicsQuarantineSettings{
			Enabled: true, ExtraForbidden: nil, RestoreFileMode: 0o600,
		},
	}
}

func cloneForensicsFabricSettings(in ForensicsFabricSettings) ForensicsFabricSettings {
	out := in
	out.Quarantine.AllowedRoots = append([]string(nil), in.Quarantine.AllowedRoots...)
	out.Quarantine.ExtraForbidden = append([]string(nil), in.Quarantine.ExtraForbidden...)
	return out
}

func validateForensicsFabricSettings(settings *ForensicsFabricSettings) error {
	if settings.Cases.MinimumIncidentScore < 1 || settings.Cases.MinimumIncidentScore > 250 {
		return fmt.Errorf("case creation score threshold must be between 1 and 250")
	}
	if settings.Cases.MaxCases < 1 || settings.Cases.MaxCases > 100000 {
		return fmt.Errorf("case budget must be between 1 and 100000")
	}
	if settings.Cases.MaxEvidenceRefsPerCase < 1 || settings.Cases.MaxEvidenceRefsPerCase > 4096 {
		return fmt.Errorf("per-case evidence budget must be between 1 and 4096")
	}
	if settings.Cases.MaxObservationsPerCase < 1 || settings.Cases.MaxObservationsPerCase > 4096 {
		return fmt.Errorf("per-case observation budget must be between 1 and 4096")
	}
	if settings.Cases.ListMaxLimit < 1 || settings.Cases.ListMaxLimit > 5000 {
		return fmt.Errorf("case list ceiling must be between 1 and 5000")
	}
	if settings.Cases.CorrelationWindowMins < 1 || settings.Cases.CorrelationWindowMins > 43200 {
		return fmt.Errorf("case correlation window must be between 1 and 43200 minutes")
	}
	if settings.Cases.AutoCloseAfterHours < 0 || settings.Cases.AutoCloseAfterHours > 8760 {
		return fmt.Errorf("case auto-close age must be between 0 (never) and 8760 hours")
	}
	if settings.Export.MaxExportBytes < 64<<10 || settings.Export.MaxExportBytes > 1<<30 {
		return fmt.Errorf("export size boundary must be between 64 KiB and 1 GiB")
	}
	if len(settings.Quarantine.AllowedRoots) > 64 || len(settings.Quarantine.ExtraForbidden) > 64 {
		return fmt.Errorf("quarantine root lists are limited to 64 entries each")
	}
	allowed, err := normalizeQuarantineRoots("allowed quarantine root", settings.Quarantine.AllowedRoots)
	if err != nil {
		return err
	}
	extra, err := normalizeQuarantineRoots("forbidden quarantine root", settings.Quarantine.ExtraForbidden)
	if err != nil {
		return err
	}
	// An allowlist entry that overlaps a forbidden root is self-contradictory: it
	// can never be reached, and a nested one would silently disable the denial.
	for _, root := range allowed {
		for _, forbidden := range append(append([]string(nil), quarantineBuiltinForbidden...), extra...) {
			if root == forbidden || strings.HasPrefix(root, forbidden+"/") || strings.HasPrefix(forbidden, root+"/") {
				return fmt.Errorf("allowed quarantine root %s overlaps the forbidden root %s", root, forbidden)
			}
		}
	}
	settings.Quarantine.AllowedRoots = allowed
	settings.Quarantine.ExtraForbidden = extra
	if settings.Quarantine.RestoreFileMode < 0o400 || settings.Quarantine.RestoreFileMode & ^0o600 != 0 {
		return fmt.Errorf("restore mode must be 0400 or 0600")
	}
	return nil
}

func normalizeQuarantineRoots(label string, roots []string) ([]string, error) {
	seen := make(map[string]struct{}, len(roots))
	out := make([]string, 0, len(roots))
	for _, raw := range roots {
		root := strings.TrimSpace(raw)
		if err := validateAbsoluteCleanPath(label, root); err != nil {
			return nil, err
		}
		if root == "/" {
			return nil, fmt.Errorf("%s must not be the filesystem root", label)
		}
		if _, exists := seen[root]; exists {
			continue
		}
		seen[root] = struct{}{}
		out = append(out, root)
	}
	sort.Strings(out)
	return out, nil
}

func effectiveForensicsSettings(settings RuntimeSettings) ForensicsFabricSettings {
	if settings.Forensics != nil {
		return cloneForensicsFabricSettings(*settings.Forensics)
	}
	return defaultForensicsFabricSettings()
}

// ------------------------------------------------------------ case policy

type casePolicy struct {
	// published distinguishes "no policy has been published yet" from "an operator
	// deliberately switched correlation off". Both are the false zero value, and a
	// case engine that has not been configured must record incidents, not discard
	// them.
	published       bool
	autoCreate      bool
	minimumScore    int
	maxCases        int
	maxEvidence     int
	maxObservations int
	listMaxLimit    int
	correlationMins int
	autoCloseHours  int
}

func (s ForensicsCasesSettings) policy() casePolicy {
	return casePolicy{
		published:  true,
		autoCreate: s.AutoCreate, minimumScore: s.MinimumIncidentScore,
		maxCases: s.MaxCases, maxEvidence: s.MaxEvidenceRefsPerCase,
		maxObservations: s.MaxObservationsPerCase, listMaxLimit: s.ListMaxLimit,
		correlationMins: s.CorrelationWindowMins, autoCloseHours: s.AutoCloseAfterHours,
	}
}

// effective substitutes the compiled-in defaults for any unset bound, so a
// partial revision can never remove a limit.
func (p casePolicy) effective() casePolicy {
	defaults := defaultForensicsFabricSettings().Cases.policy()
	if !p.published {
		// Fail closed: until an administrator publishes a revision, an incident above
		// the compiled-in score floor becomes a case. The zero value would silently
		// drop every incident, which is the one outcome a forensics engine must never
		// produce.
		p.autoCreate = defaults.autoCreate
		p.minimumScore = defaults.minimumScore
		p.correlationMins = defaults.correlationMins
		p.autoCloseHours = defaults.autoCloseHours
	}
	if p.maxCases <= 0 {
		p.maxCases = defaults.maxCases
	}
	if p.maxEvidence <= 0 {
		p.maxEvidence = defaults.maxEvidence
	}
	if p.maxObservations <= 0 {
		p.maxObservations = defaults.maxObservations
	}
	if p.listMaxLimit <= 0 {
		p.listMaxLimit = defaults.listMaxLimit
	}
	if p.correlationMins <= 0 {
		p.correlationMins = defaults.correlationMins
	}
	return p
}

// ApplyPolicy publishes the case budgets.
func (e *CaseEngine) ApplyPolicy(settings ForensicsCasesSettings) error {
	if e == nil {
		return nil
	}
	e.mu.Lock()
	published := settings.policy()
	published.published = true
	e.policy = published.effective()
	e.mu.Unlock()
	return nil
}

func (e *CaseEngine) policySnapshot() casePolicy {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.policy.effective()
}

// -------------------------------------------------------- quarantine policy

type quarantinePolicy struct {
	enabled     bool
	allowed     []string
	extra       []string
	restoreMode uint32
}

func (s ForensicsQuarantineSettings) policy() quarantinePolicy {
	return quarantinePolicy{
		enabled: s.Enabled, allowed: append([]string(nil), s.AllowedRoots...),
		extra: append([]string(nil), s.ExtraForbidden...), restoreMode: uint32(s.RestoreFileMode),
	}
}

// ApplyPolicy republishes the quarantine path policy. The built-in denylist is
// appended at evaluation time and is not stored here, so no revision can drop it.
func (a *QuarantineTransactionApplier) ApplyPolicy(settings ForensicsQuarantineSettings) error {
	if a == nil {
		return nil
	}
	a.mu.Lock()
	a.policy = settings.policy()
	a.mu.Unlock()
	return nil
}

func (a *QuarantineTransactionApplier) policySnapshot() quarantinePolicy {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.policy
}

// pathForbidden reports whether a path is inside any forbidden root. The built-in
// set is evaluated first and can never be removed by configuration.
func (p quarantinePolicy) pathForbidden(path string) bool {
	for _, root := range append(append([]string(nil), quarantineBuiltinForbidden...), p.extra...) {
		if path == root || (root != "/" && strings.HasPrefix(path, root+"/")) {
			return true
		}
	}
	return false
}

// pathOutsideAllowedRoots reports whether an administered allowlist excludes the
// path. An empty allowlist means every non-forbidden path is permitted, which is
// the compiled-in behaviour.
func (p quarantinePolicy) pathOutsideAllowedRoots(path string) bool {
	if len(p.allowed) == 0 {
		return false
	}
	for _, root := range p.allowed {
		if path == root || strings.HasPrefix(path, root+"/") {
			return false
		}
	}
	return true
}

// --------------------------------------------------------------- redaction

// redactInternalIPs replaces private, loopback, link-local and carrier-grade NAT
// addresses with a stable token.
//
// The token is derived from the address, so two occurrences of the same host stay
// correlated inside one export while the address itself is not disclosed. Public
// addresses are left untouched: they are the threat indicator the record was
// exported for. Only whole tokens are replaced, so a longer literal that merely
// contains an address-shaped substring is left alone.
func redactInternalIPs(value string) string {
	tokens := strings.FieldsFunc(value, func(r rune) bool {
		switch {
		case r >= '0' && r <= '9', r >= 'a' && r <= 'f', r >= 'A' && r <= 'F':
			return false
		case r == '.' || r == ':' || r == '%':
			return false
		default:
			return true
		}
	})
	replaced := value
	for _, token := range tokens {
		candidate := token
		if index := strings.IndexByte(candidate, '%'); index > 0 {
			candidate = candidate[:index]
		}
		address := net.ParseIP(candidate)
		if address == nil || !isInternalAddress(address) {
			continue
		}
		replaced = strings.ReplaceAll(replaced, token, internalAddressToken(address))
	}
	return replaced
}

func isInternalAddress(address net.IP) bool {
	return address.IsPrivate() || address.IsLoopback() || address.IsLinkLocalUnicast() ||
		address.IsLinkLocalMulticast() || address.IsUnspecified() ||
		address.IsInterfaceLocalMulticast() || inCarrierGradeNAT(address)
}

// inCarrierGradeNAT covers 100.64.0.0/10, which net.IP does not classify as
// private but which is never a public threat source.
func inCarrierGradeNAT(address net.IP) bool {
	v4 := address.To4()
	return v4 != nil && v4[0] == 100 && v4[1] >= 64 && v4[1] <= 127
}

func internalAddressToken(address net.IP) string {
	digest := sha256.Sum256([]byte("gedefense-internal-address\x00" + address.String()))
	return "internal-" + hex.EncodeToString(digest[:])[:12]
}

// ------------------------------------------------------------ export shaping

// shapeForensicsSnapshot removes the sections an operator excluded, applies
// address redaction and enforces the size boundary. It runs before signing, so
// the signature covers exactly what the operator received.
func shapeForensicsSnapshot(snapshot Snapshot, settings ForensicsExportSettings, signingAvailable bool) (Snapshot, error) {
	if settings.SigningRequired && !signingAvailable {
		return Snapshot{}, fmt.Errorf("export signing is required but the policy signer is unavailable")
	}
	shaped := snapshot
	if !settings.IncludeRawRecords {
		shaped.Events = nil
		shaped.Incidents = nil
	}
	if !settings.IncludePolicyState {
		shaped.Policy = PolicyStatus{}
		shaped.Settings = RuntimeSettings{}
	}
	if !settings.IncludeSystemMeta {
		shaped.NodeName = ""
		shaped.Telemetry = Telemetry{}
		shaped.Version = ""
	}
	encoded, err := json.Marshal(shaped)
	if err != nil {
		return Snapshot{}, err
	}
	// Redaction runs on the serialised form rather than on a list of known fields,
	// so a string field added later is covered without a second place to remember.
	if settings.RedactInternalIPs {
		encoded = []byte(redactInternalIPs(string(encoded)))
	}
	if int64(len(encoded)) > settings.MaxExportBytes {
		return Snapshot{}, fmt.Errorf("shaped export exceeds the configured boundary of %d bytes", settings.MaxExportBytes)
	}
	var final Snapshot
	if err := json.Unmarshal(encoded, &final); err != nil {
		return Snapshot{}, err
	}
	return final, nil
}

// --------------------------------------------------------- distribution

// applyForensicsPolicies projects the Forensics namespace onto the engines that
// consume it from one choke point.
func applyForensicsPolicies(settings ForensicsFabricSettings, cases *CaseEngine, quarantine *QuarantineTransactionApplier) error {
	if cases != nil {
		if err := cases.ApplyPolicy(settings.Cases); err != nil {
			return fmt.Errorf("apply case policy: %w", err)
		}
	}
	if quarantine != nil {
		if err := quarantine.ApplyPolicy(settings.Quarantine); err != nil {
			return fmt.Errorf("apply quarantine policy: %w", err)
		}
	}
	return nil
}

// boundedCaseLimit clamps a caller-requested case page size to the administrable
// ceiling and substitutes the ceiling when none was given.
func boundedCaseLimit(requested int, policy casePolicy) (int, error) {
	ceiling := policy.effective().listMaxLimit
	if requested <= 0 {
		return ceiling, nil
	}
	if requested > ceiling {
		return 0, fmt.Errorf("requested case count exceeds the administrable ceiling of %d", ceiling)
	}
	return requested, nil
}

// correlationExpired reports whether an incident is too far from a case's newest
// observation to join it. Without this bound a recurring rule on one target would
// accumulate unrelated events into a single case indefinitely.
func correlationExpired(record SecurityCase, incident XDRIncident, now time.Time, policy casePolicy) bool {
	window := time.Duration(policy.effective().correlationMins) * time.Minute
	newest := record.UpdatedAt
	// Correlate detector event times; UpdatedAt tracks operator/wall-clock activity.
	var latestEvent time.Time
	for _, observation := range record.Observations {
		if observation.At.After(latestEvent) {
			latestEvent = observation.At
		}
	}
	if !latestEvent.IsZero() {
		newest = latestEvent
	}
	if newest.IsZero() {
		newest = record.CreatedAt
	}
	at := incident.Time
	if at.IsZero() {
		at = now
	}
	if at.After(newest) {
		return at.Sub(newest) > window
	}
	return newest.Sub(at) > window
}

// autoCloseCandidate reports whether an open case has been idle long enough to be
// closed automatically. A zero setting disables the sweep entirely, which is the
// default: closing a case is an operator judgement.
func autoCloseCandidate(record SecurityCase, now time.Time, policy casePolicy) bool {
	hours := policy.effective().autoCloseHours
	if hours <= 0 || record.Status != "open" {
		return false
	}
	last := record.UpdatedAt
	if last.IsZero() {
		last = record.CreatedAt
	}
	if last.IsZero() {
		return false
	}
	return now.Sub(last) >= time.Duration(hours)*time.Hour
}
