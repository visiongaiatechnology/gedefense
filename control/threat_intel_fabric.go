// STATUS: DIAMANT VGT SUPREME
package main

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync/atomic"
)

// Threat Intelligence Fabric administration.
//
// Plan reference: GeDefense 4.2 Security Fabric Control Plane, section 18
// (Threat Intelligence settings) plus section 49 (settings are compiled into a
// compact immutable snapshot that the runtime reads).
//
// Design invariants:
//
//  1. One sync resolves exactly one snapshot. A feed mutation published while a
//     sync is running can never produce a half-old source set.
//  2. Transport safety, anti-poisoning filtering and kernel rollback are hard
//     safety invariants. They are enforced unconditionally and are deliberately
//     NOT exposed as toggles (plan section 43).
//  3. Source ordering is deterministic. Priority and trust weight decide which
//     entries survive the global entry budget, so the same input always
//     produces the same generation.

// ThreatFeedSourceSettings is the administrable descriptor of one feed source.
type ThreatFeedSourceSettings struct {
	ID               string `json:"id"`
	Name             string `json:"name"`
	Enabled          bool   `json:"enabled"`
	URL              string `json:"url"`
	Format           string `json:"format"`
	Action           string `json:"action"`
	Priority         int    `json:"priority"`
	TrustWeight      int    `json:"trust_weight"`
	RefreshMinutes   int    `json:"refresh_minutes"`
	MaxEntries       int    `json:"max_entries"`
	MaxDownloadBytes int    `json:"max_download_bytes"`
}

// ThreatIntelTransportSettings is the administrable transport policy. HTTPS,
// certificate verification, the 443 destination port and the resolved-address
// anti-poisoning check are enforced unconditionally and are not listed here.
type ThreatIntelTransportSettings struct {
	AllowedHosts           []string `json:"allowed_hosts"`
	MaxRedirects           int      `json:"max_redirects"`
	AllowCrossHostRedirect bool     `json:"allow_cross_host_redirect"`
	RequireContentType     bool     `json:"require_content_type"`
	AllowedContentTypes    []string `json:"allowed_content_types"`
}

// ThreatIntelValidationSettings bounds what a download may contribute.
type ThreatIntelValidationSettings struct {
	IPv4Enabled               bool   `json:"ipv4_enabled"`
	IPv6Enabled               bool   `json:"ipv6_enabled"`
	MinimumValidEntryPermille int    `json:"minimum_valid_entry_permille"`
	MalformedEntryPermille    int    `json:"malformed_entry_permille"`
	GenerationPolicy          string `json:"generation_policy"`
}

// ThreatIntelRetrySettings controls bounded retry with exponential backoff.
type ThreatIntelRetrySettings struct {
	Attempts       int `json:"attempts"`
	BackoffSeconds int `json:"backoff_seconds"`
}

// ThreatIntelKernelSettings controls how a validated generation reaches the
// kernel. Rollback on a failed diff is a hard invariant, not a setting.
type ThreatIntelKernelSettings struct {
	AutoApply          bool `json:"auto_apply"`
	MaximumDiffPerSync int  `json:"maximum_diff_per_sync"`
	DivergenceDegrades bool `json:"divergence_degrades_release"`
}

// ThreatIntelFabricSettings is the administrable Threat Intelligence surface.
type ThreatIntelFabricSettings struct {
	Enabled        bool `json:"enabled"`
	AutoSync       bool `json:"auto_sync"`
	RefreshMinutes int  `json:"refresh_minutes"`

	StaleWarningMinutes  int `json:"stale_warning_minutes"`
	StaleCriticalMinutes int `json:"stale_critical_minutes"`

	MaxDownloadBytesPerFeed int `json:"max_download_bytes_per_feed"`
	MaxEntriesPerFeed       int `json:"max_entries_per_feed"`
	MaxTotalEntries         int `json:"max_total_entries"`
	DownloadTimeoutSeconds  int `json:"download_timeout_seconds"`
	ConcurrentDownloads     int `json:"concurrent_downloads"`

	Transport  ThreatIntelTransportSettings  `json:"transport"`
	Validation ThreatIntelValidationSettings `json:"validation"`
	Retry      ThreatIntelRetrySettings      `json:"retry"`
	Kernel     ThreatIntelKernelSettings     `json:"kernel_apply"`

	Feeds []ThreatFeedSourceSettings `json:"feeds"`
}

const (
	threatIntelFeedLimit          = 256
	threatIntelConcurrentLimit    = 16
	threatIntelRedirectLimit      = 10
	threatIntelRetryLimit         = 5
	threatIntelBackoffLimit       = 300
	threatIntelRefreshFloor       = 5
	threatIntelRefreshCeiling     = 1440
	threatIntelDownloadFloorBytes = 1 << 10
	threatIntelDownloadCeilBytes  = 64 << 20
)

// defaultThreatIntelFabricSettings derives the first Fabric revision from the
// static bootstrap configuration and the compiled-in sovereign feed set, so an
// existing deployment keeps exactly its previous behaviour after migration.
func defaultThreatIntelFabricSettings(cfg FeedConfig, sources []ThreatFeedSource) ThreatIntelFabricSettings {
	refresh := cfg.RefreshMinutes
	if refresh < threatIntelRefreshFloor || refresh > threatIntelRefreshCeiling {
		refresh = 720
	}
	maxDownload := cfg.MaxDownloadBytes
	if maxDownload < threatIntelDownloadFloorBytes {
		maxDownload = 16 << 20
	}
	maxEntries := cfg.MaxEntries
	if maxEntries < 1 {
		maxEntries = 250000
	}
	out := ThreatIntelFabricSettings{
		Enabled: cfg.Enabled, AutoSync: false, RefreshMinutes: refresh,
		StaleWarningMinutes:  refresh * 2,
		StaleCriticalMinutes: refresh * 6,

		MaxDownloadBytesPerFeed: int(maxDownload),
		MaxEntriesPerFeed:       maxEntries,
		MaxTotalEntries:         maxEntries,
		DownloadTimeoutSeconds:  25,
		ConcurrentDownloads:     3,

		Transport: ThreatIntelTransportSettings{
			AllowedHosts:        []string{},
			MaxRedirects:        2,
			RequireContentType:  false,
			AllowedContentTypes: []string{"text/plain", "application/json", "application/octet-stream", "text/"},
		},
		Validation: ThreatIntelValidationSettings{
			IPv4Enabled: true, IPv6Enabled: true,
			MinimumValidEntryPermille: 0,
			MalformedEntryPermille:    250,
			GenerationPolicy:          "bump",
		},
		Retry:  ThreatIntelRetrySettings{Attempts: 2, BackoffSeconds: 5},
		Kernel: ThreatIntelKernelSettings{AutoApply: true, MaximumDiffPerSync: 0, DivergenceDegrades: true},
		Feeds:  make([]ThreatFeedSourceSettings, 0, len(sources)),
	}
	for index, source := range sources {
		out.Feeds = append(out.Feeds, ThreatFeedSourceSettings{
			ID: source.ID, Name: source.Name, Enabled: true, URL: source.URL,
			Format: source.Format, Action: string(source.Action),
			Priority: (index + 1) * 10, TrustWeight: 100,
			RefreshMinutes: 0, MaxEntries: 0, MaxDownloadBytes: 0,
		})
	}
	return out
}

func cloneThreatIntelFabricSettings(in ThreatIntelFabricSettings) ThreatIntelFabricSettings {
	out := in
	out.Transport.AllowedHosts = append([]string(nil), in.Transport.AllowedHosts...)
	out.Transport.AllowedContentTypes = append([]string(nil), in.Transport.AllowedContentTypes...)
	out.Feeds = append([]ThreatFeedSourceSettings(nil), in.Feeds...)
	return out
}

// validateThreatIntelFabricSettings normalizes and bounds the whole namespace.
// Anything the dashboard can express but the runtime cannot honour safely is
// rejected here rather than being silently clamped.
func validateThreatIntelFabricSettings(settings *ThreatIntelFabricSettings) error {
	if settings.RefreshMinutes < threatIntelRefreshFloor || settings.RefreshMinutes > threatIntelRefreshCeiling {
		return fmt.Errorf("threat intelligence refresh interval must be between %d and %d minutes", threatIntelRefreshFloor, threatIntelRefreshCeiling)
	}
	if settings.StaleWarningMinutes < 1 || settings.StaleWarningMinutes > 100000 {
		return fmt.Errorf("threat intelligence stale warning interval is outside safe bounds")
	}
	if settings.StaleCriticalMinutes < settings.StaleWarningMinutes || settings.StaleCriticalMinutes > 100000 {
		return fmt.Errorf("threat intelligence stale critical interval must be at least the warning interval")
	}
	if settings.MaxDownloadBytesPerFeed < threatIntelDownloadFloorBytes || settings.MaxDownloadBytesPerFeed > threatIntelDownloadCeilBytes {
		return fmt.Errorf("threat intelligence download bound must be between 1 KiB and 64 MiB")
	}
	if settings.MaxEntriesPerFeed < 1 || settings.MaxEntriesPerFeed > 5000000 {
		return fmt.Errorf("threat intelligence per-feed entry bound is outside safe bounds")
	}
	if settings.MaxTotalEntries < 1 || settings.MaxTotalEntries > 5000000 {
		return fmt.Errorf("threat intelligence total entry bound is outside safe bounds")
	}
	if settings.DownloadTimeoutSeconds < 5 || settings.DownloadTimeoutSeconds > 300 {
		return fmt.Errorf("threat intelligence download timeout must be between 5 and 300 seconds")
	}
	if settings.ConcurrentDownloads < 1 || settings.ConcurrentDownloads > threatIntelConcurrentLimit {
		return fmt.Errorf("threat intelligence concurrency must be between 1 and %d", threatIntelConcurrentLimit)
	}
	if settings.Transport.MaxRedirects < 0 || settings.Transport.MaxRedirects > threatIntelRedirectLimit {
		return fmt.Errorf("threat intelligence redirect budget must be between 0 and %d", threatIntelRedirectLimit)
	}
	if len(settings.Transport.AllowedHosts) > 512 {
		return fmt.Errorf("threat intelligence host allowlist exceeds 512 entries")
	}
	seenHosts := make(map[string]struct{}, len(settings.Transport.AllowedHosts))
	hosts := make([]string, 0, len(settings.Transport.AllowedHosts))
	for _, raw := range settings.Transport.AllowedHosts {
		host := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(raw)), ".")
		if host == "" {
			continue
		}
		if strings.ContainsAny(host, "/*: \t\r\n\x00") {
			return fmt.Errorf("threat intelligence host allowlist entry %q must be a bare hostname", raw)
		}
		if _, exists := seenHosts[host]; exists {
			continue
		}
		seenHosts[host] = struct{}{}
		hosts = append(hosts, host)
	}
	sort.Strings(hosts)
	settings.Transport.AllowedHosts = hosts
	if len(settings.Transport.AllowedContentTypes) > 32 {
		return fmt.Errorf("threat intelligence content type policy exceeds 32 entries")
	}
	if settings.Transport.RequireContentType && len(settings.Transport.AllowedContentTypes) == 0 {
		return fmt.Errorf("threat intelligence content type policy is required but empty")
	}
	seenTypes := make(map[string]struct{}, len(settings.Transport.AllowedContentTypes))
	types := make([]string, 0, len(settings.Transport.AllowedContentTypes))
	for _, raw := range settings.Transport.AllowedContentTypes {
		media := strings.ToLower(strings.TrimSpace(raw))
		if media == "" {
			continue
		}
		if strings.ContainsAny(media, " \t\r\n\x00,;") {
			return fmt.Errorf("threat intelligence content type %q must be a bare media type or prefix", raw)
		}
		if _, exists := seenTypes[media]; exists {
			continue
		}
		seenTypes[media] = struct{}{}
		types = append(types, media)
	}
	sort.Strings(types)
	settings.Transport.AllowedContentTypes = types
	if settings.Validation.MinimumValidEntryPermille < 0 || settings.Validation.MinimumValidEntryPermille > 1000 {
		return fmt.Errorf("threat intelligence minimum entry ratio must be between 0 and 1000 per mille")
	}
	if settings.Validation.MalformedEntryPermille < 0 || settings.Validation.MalformedEntryPermille > 1000 {
		return fmt.Errorf("threat intelligence malformed entry threshold must be between 0 and 1000 per mille")
	}
	switch settings.Validation.GenerationPolicy {
	case "bump", "stable":
	default:
		return fmt.Errorf("threat intelligence generation policy must be bump or stable")
	}
	if !settings.Validation.IPv4Enabled && !settings.Validation.IPv6Enabled {
		return fmt.Errorf("threat intelligence must accept at least one address family")
	}
	if settings.Retry.Attempts < 0 || settings.Retry.Attempts > threatIntelRetryLimit {
		return fmt.Errorf("threat intelligence retry attempts must be between 0 and %d", threatIntelRetryLimit)
	}
	if settings.Retry.BackoffSeconds < 1 || settings.Retry.BackoffSeconds > threatIntelBackoffLimit {
		return fmt.Errorf("threat intelligence retry backoff must be between 1 and %d seconds", threatIntelBackoffLimit)
	}
	if settings.Kernel.MaximumDiffPerSync < 0 || settings.Kernel.MaximumDiffPerSync > 1000000 {
		return fmt.Errorf("threat intelligence kernel diff budget is outside safe bounds")
	}
	if len(settings.Feeds) > threatIntelFeedLimit {
		return fmt.Errorf("threat intelligence feed limit of %d exceeded", threatIntelFeedLimit)
	}
	if settings.AutoSync && !settings.Enabled {
		return errors.New("automatic feed synchronisation requires threat intelligence to be enabled")
	}
	if settings.Enabled && len(settings.Feeds) == 0 {
		return errors.New("threat intelligence requires at least one feed definition")
	}

	seenIDs := make(map[string]struct{}, len(settings.Feeds))
	seenURLs := make(map[string]struct{}, len(settings.Feeds))
	feeds := make([]ThreatFeedSourceSettings, 0, len(settings.Feeds))
	for index := range settings.Feeds {
		feed := &settings.Feeds[index]
		feed.ID = strings.ToLower(strings.TrimSpace(feed.ID))
		feed.Name = strings.TrimSpace(feed.Name)
		feed.URL = strings.TrimSpace(feed.URL)
		feed.Format = strings.ToLower(strings.TrimSpace(feed.Format))
		feed.Action = strings.ToUpper(strings.TrimSpace(feed.Action))
		if feed.ID == "" || len(feed.ID) > 64 || !protocolFieldValid(feed.ID) || strings.Contains(feed.ID, ".") {
			return fmt.Errorf("feed %d identifier must be a protocol-safe identifier of at most 64 characters", index)
		}
		if _, exists := seenIDs[feed.ID]; exists {
			return fmt.Errorf("duplicate feed identifier %q", feed.ID)
		}
		seenIDs[feed.ID] = struct{}{}
		if len(feed.Name) < 1 || len(feed.Name) > 96 || strings.ContainsAny(feed.Name, "\r\n\x00") {
			return fmt.Errorf("feed %s name must contain 1-96 single-line characters", feed.ID)
		}
		switch feed.Format {
		case "lines", "json", "ipsum":
		default:
			return fmt.Errorf("feed %s format must be lines, json or ipsum", feed.ID)
		}
		switch FeedAction(feed.Action) {
		case FeedActionBlock, FeedActionCorrelateOnly, FeedActionAnnotateOnly:
		default:
			return fmt.Errorf("feed %s action must be BLOCK, CORRELATE_ONLY or ANNOTATE_ONLY", feed.ID)
		}
		if feed.Priority < 0 || feed.Priority > 1000000 {
			return fmt.Errorf("feed %s priority is outside safe bounds", feed.ID)
		}
		if feed.TrustWeight < 1 || feed.TrustWeight > 1000 {
			return fmt.Errorf("feed %s trust weight must be between 1 and 1000", feed.ID)
		}
		if feed.RefreshMinutes != 0 && (feed.RefreshMinutes < threatIntelRefreshFloor || feed.RefreshMinutes > threatIntelRefreshCeiling) {
			return fmt.Errorf("feed %s refresh override must be 0 or between %d and %d minutes", feed.ID, threatIntelRefreshFloor, threatIntelRefreshCeiling)
		}
		if feed.MaxEntries != 0 && (feed.MaxEntries < 1 || feed.MaxEntries > 5000000) {
			return fmt.Errorf("feed %s entry override is outside safe bounds", feed.ID)
		}
		if feed.MaxDownloadBytes != 0 && (feed.MaxDownloadBytes < threatIntelDownloadFloorBytes || feed.MaxDownloadBytes > threatIntelDownloadCeilBytes) {
			return fmt.Errorf("feed %s download override must be 0 or between 1 KiB and 64 MiB", feed.ID)
		}
		if !feed.Enabled {
			feeds = append(feeds, *feed)
			continue
		}
		if _, err := validateFeedSourceURL(feed.URL); err != nil {
			return fmt.Errorf("feed %s: %w", feed.ID, err)
		}
		if _, exists := seenURLs[feed.URL]; exists {
			return fmt.Errorf("feed %s duplicates another feed URL", feed.ID)
		}
		seenURLs[feed.URL] = struct{}{}
		feeds = append(feeds, *feed)
	}
	sort.Slice(feeds, func(i, j int) bool {
		if feeds[i].Priority != feeds[j].Priority {
			return feeds[i].Priority < feeds[j].Priority
		}
		return feeds[i].ID < feeds[j].ID
	})
	settings.Feeds = feeds
	return nil
}

// toSource compiles one administrable entry into the runtime descriptor.
func (f ThreatFeedSourceSettings) toSource() ThreatFeedSource {
	return ThreatFeedSource{
		ID: f.ID, Name: f.Name, URL: f.URL, Action: FeedAction(f.Action), Format: f.Format,
		Priority: f.Priority, TrustWeight: f.TrustWeight, RefreshMinutes: f.RefreshMinutes,
		MaxEntries: f.MaxEntries, MaxDownloadBytes: f.MaxDownloadBytes,
	}
}

// effectiveFeedConfig projects the namespace onto the bounded download
// configuration used by the state store and the kernel diff.
func (f ThreatIntelFabricSettings) effectiveFeedConfig(base FeedConfig) FeedConfig {
	out := base
	out.Enabled = f.Enabled
	out.AutoApply = f.Kernel.AutoApply
	out.RefreshMinutes = f.RefreshMinutes
	out.MaxDownloadBytes = int64(f.MaxDownloadBytesPerFeed)
	out.MaxEntries = f.MaxTotalEntries
	out.Sources = out.Sources[:0]
	for _, feed := range f.Feeds {
		if feed.Enabled {
			out.Sources = append(out.Sources, feed.URL)
		}
	}
	return out
}

// threatIntelSnapshot is the immutable configuration view read by one sync.
type threatIntelSnapshot struct {
	revision uint64
	settings ThreatIntelFabricSettings
	sources  []ThreatFeedSource
	byID     map[string]ThreatFeedSource
	hosts    map[string]struct{}
}

type threatIntelRuntime struct {
	ptr atomic.Pointer[threatIntelSnapshot]
}

func buildThreatIntelSnapshot(settings ThreatIntelFabricSettings, revision uint64) *threatIntelSnapshot {
	effective := cloneThreatIntelFabricSettings(settings)
	snapshot := &threatIntelSnapshot{
		revision: revision,
		settings: effective,
		byID:     make(map[string]ThreatFeedSource, len(effective.Feeds)),
		hosts:    make(map[string]struct{}, len(effective.Transport.AllowedHosts)),
	}
	for _, host := range effective.Transport.AllowedHosts {
		snapshot.hosts[host] = struct{}{}
	}
	for _, feed := range effective.Feeds {
		source := feed.toSource()
		snapshot.byID[source.ID] = source
		if feed.Enabled {
			snapshot.sources = append(snapshot.sources, source)
		}
	}
	return snapshot
}

func newThreatIntelRuntime(settings ThreatIntelFabricSettings, revision uint64) *threatIntelRuntime {
	runtime := &threatIntelRuntime{}
	runtime.ptr.Store(buildThreatIntelSnapshot(settings, revision))
	return runtime
}

func (r *threatIntelRuntime) current() *threatIntelSnapshot {
	if r == nil {
		return nil
	}
	return r.ptr.Load()
}

func (r *threatIntelRuntime) publish(snapshot *threatIntelSnapshot) {
	if r == nil || snapshot == nil {
		return
	}
	r.ptr.Store(snapshot)
}

func (r *threatIntelRuntime) activeSettings() ThreatIntelFabricSettings {
	snapshot := r.current()
	if snapshot == nil {
		return ThreatIntelFabricSettings{}
	}
	return cloneThreatIntelFabricSettings(snapshot.settings)
}

// hostAllowed reports whether a feed host is inside the administrable allowlist.
// An empty allowlist means "any public host": the unconditional public-host and
// anti-poisoning checks still apply.
func (s *threatIntelSnapshot) hostAllowed(host string) bool {
	if s == nil || len(s.hosts) == 0 {
		return true
	}
	_, ok := s.hosts[strings.TrimSuffix(strings.ToLower(host), ".")]
	return ok
}

// contentAllowed enforces the administrable content type policy.
func (s *threatIntelSnapshot) contentAllowed(header string) bool {
	if s == nil {
		return true
	}
	media := strings.ToLower(strings.TrimSpace(header))
	if idx := strings.IndexByte(media, ';'); idx >= 0 {
		media = strings.TrimSpace(media[:idx])
	}
	if media == "" {
		return !s.settings.Transport.RequireContentType
	}
	for _, allowed := range s.settings.Transport.AllowedContentTypes {
		if media == allowed || strings.HasPrefix(media, allowed) {
			return true
		}
	}
	return false
}

// feedBounds resolves the effective per-feed bounds with global fallback.
func (s *threatIntelSnapshot) feedBounds(source ThreatFeedSource) (maxEntries int, maxBytes int64, timeoutSeconds int) {
	maxEntries = s.settings.MaxEntriesPerFeed
	if source.MaxEntries > 0 {
		maxEntries = source.MaxEntries
	}
	maxBytes = int64(s.settings.MaxDownloadBytesPerFeed)
	if source.MaxDownloadBytes > 0 {
		maxBytes = int64(source.MaxDownloadBytes)
	}
	timeoutSeconds = s.settings.DownloadTimeoutSeconds
	return maxEntries, maxBytes, timeoutSeconds
}

// orderedSources returns the enabled sources in deterministic priority order.
// Trust weight breaks priority ties, so the highest-trust source is evaluated
// first and therefore wins the global entry budget.
func (s *threatIntelSnapshot) orderedSources() []ThreatFeedSource {
	if s == nil {
		return nil
	}
	out := append([]ThreatFeedSource(nil), s.sources...)
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Priority != out[j].Priority {
			return out[i].Priority < out[j].Priority
		}
		if out[i].TrustWeight != out[j].TrustWeight {
			return out[i].TrustWeight > out[j].TrustWeight
		}
		return out[i].ID < out[j].ID
	})
	return out
}

// applyThreatIntelSettings validates and publishes a committed Fabric revision.
// Source-set and per-feed changes are reload-class: a sync already in flight
// keeps its snapshot and the next sync observes the new one.
func (m *FeedManager) applyThreatIntelSettings(settings ThreatIntelFabricSettings, revision uint64) error {
	if m == nil || m.live == nil {
		return nil
	}
	candidate := cloneThreatIntelFabricSettings(settings)
	if err := validateThreatIntelFabricSettings(&candidate); err != nil {
		return err
	}
	snapshot := buildThreatIntelSnapshot(candidate, revision)
	m.live.publish(snapshot)
	m.applyRuntimeConfig(snapshot.settings)
	m.reconcileSourceStates(snapshot)
	return nil
}

// reconcileSourceStates projects the published revision onto the per-feed
// generation state and republishes the active generations. Without this a feed
// whose action or name changed would keep serving the previous classification
// until the next successful download.
func (m *FeedManager) reconcileSourceStates(snapshot *threatIntelSnapshot) {
	if snapshot == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, source := range snapshot.sources {
		state, exists := m.feedStates[source.ID]
		if !exists {
			m.feedStates[source.ID] = &FeedGenerationState{ID: source.ID, Name: source.Name, Action: source.Action}
			continue
		}
		state.Name = source.Name
		state.Action = source.Action
		state.Status = computeFeedStatus(state, snapshot.settings)
	}
	m.composeGenerationsLocked(snapshot.settings)
	_ = m.savePersistentStateLocked()
}

// applyRuntimeConfig projects the published revision onto the bounded download
// configuration. The existing value is read under the same lock that replaces
// it, so no caller can observe a torn configuration.
func (m *FeedManager) applyRuntimeConfig(settings ThreatIntelFabricSettings) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.cfg = settings.effectiveFeedConfig(m.cfg)
}

// LiveSettings returns the Threat Intelligence revision that is active.
func (m *FeedManager) LiveSettings() ThreatIntelFabricSettings {
	if m == nil || m.live == nil {
		return ThreatIntelFabricSettings{}
	}
	return m.live.activeSettings()
}

// LiveRevision returns the Fabric revision projected onto the running manager.
func (m *FeedManager) LiveRevision() uint64 {
	if m == nil || m.live == nil {
		return 0
	}
	snapshot := m.live.current()
	if snapshot == nil {
		return 0
	}
	return snapshot.revision
}

// KernelDivergent reports a userspace/kernel mismatch that must never be
// presented as a healthy state (plan section 39, configuration drift).
func (m *FeedManager) KernelDivergent() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.kernelApplyStatus == kernelApplyDivergent
}

// ThreatIntelModuleDetails is the presentation payload the Settings surface
// shows next to the administrable fields. It reports only what the runtime can
// prove about itself.
type ThreatIntelModuleDetails struct {
	ActiveRevision   uint64                `json:"active_revision"`
	EnabledSources   int                   `json:"enabled_sources"`
	DisabledSources  int                   `json:"disabled_sources"`
	TotalVectors     int                   `json:"total_vectors"`
	BlockVectors     int                   `json:"block_vectors"`
	CorrelateVectors int                   `json:"correlate_vectors"`
	AnnotateVectors  int                   `json:"annotate_vectors"`
	KernelStatus     string                `json:"kernel_apply_status"`
	KernelDivergent  bool                  `json:"kernel_divergent"`
	LastKernelError  string                `json:"last_kernel_error,omitempty"`
	Feeds            []FeedGenerationState `json:"feeds"`
}

// ModuleDetails builds the module presentation payload without exposing raw
// indicator arrays.
func (m *FeedManager) ModuleDetails() ThreatIntelModuleDetails {
	if m == nil {
		return ThreatIntelModuleDetails{}
	}
	settings := m.LiveSettings()
	details := ThreatIntelModuleDetails{
		ActiveRevision:   m.LiveRevision(),
		BlockVectors:     m.blockIndex.Count(),
		CorrelateVectors: m.correlateIndex.Count(),
		AnnotateVectors:  m.annotateIndex.Count(),
		KernelDivergent:  m.KernelDivergent(),
	}
	details.TotalVectors = details.BlockVectors + details.CorrelateVectors + details.AnnotateVectors
	for _, feed := range settings.Feeds {
		if feed.Enabled {
			details.EnabledSources++
		} else {
			details.DisabledSources++
		}
	}
	details.KernelStatus, _, _, details.LastKernelError = m.KernelApplyStatus()
	details.Feeds = m.SnapshotFeedStates()
	return details
}

// threaIntelValidationOutcome classifies one downloaded line so the validation
// policy can distinguish "the feed is corrupt" from "the feed contains a family
// this deployment does not accept".
type threatLineKind int

const (
	threatLineAccepted threatLineKind = iota
	threatLineMalformed
	threatLineSkipped
	threatLineFiltered
)

// classifyThreatLine applies the administrable validation policy on top of the
// unconditional token whitelist and anti-poisoning filter.
func classifyThreatLine(line string, policy ThreatIntelValidationSettings) (string, threatLineKind) {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, ";") {
		return "", threatLineSkipped
	}
	body := trimmed
	if idx := strings.IndexAny(body, "#;"); idx != -1 {
		body = strings.TrimSpace(body[:idx])
		if body == "" {
			return "", threatLineSkipped
		}
	}
	tok := strings.TrimRight(strings.Fields(body)[0], ";, ")
	value, ok := parseThreatToken(tok)
	if !ok {
		return "", threatLineMalformed
	}
	if !policy.ipv4Allowed(value) || !policy.ipv6Allowed(value) {
		return "", threatLineFiltered
	}
	return value, threatLineAccepted
}

func (p ThreatIntelValidationSettings) ipv4Allowed(value string) bool {
	if p.IPv4Enabled || strings.Contains(value, ":") {
		return true
	}
	return false
}

func (p ThreatIntelValidationSettings) ipv6Allowed(value string) bool {
	if p.IPv6Enabled || !strings.Contains(value, ":") {
		return true
	}
	return false
}

// shouldAdvanceGeneration implements the administrable generation policy. Under
// "stable" a byte-identical re-download refreshes freshness without advancing
// the published generation, which stops feeds that rarely change from churning
// the generation on every sync.
func shouldAdvanceGeneration(state *FeedGenerationState, digest string, policy ThreatIntelValidationSettings) bool {
	if state == nil {
		return true
	}
	if policy.GenerationPolicy == "stable" && state.LastGoodGen > 0 && digest == state.LastGoodFingerprint {
		return false
	}
	return true
}
