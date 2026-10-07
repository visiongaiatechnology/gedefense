// STATUS: DIAMANT VGT SUPREME
package main

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// System Fabric administration.
//
// Plan reference: GeDefense 4.2 Security Fabric Control Plane, sections 26 and 27.
//
// Scope decision: this namespace administers the control plane's *own* resource
// bounds and exposure. Every value either limits work or reduces exposure, and the
// payload ceiling can only tighten a handler's own limit, never loosen it.
//
// Several values the plan lists are absent because nothing would consume them, and
// a switch that does nothing is worse than a missing one:
//
//   - Listen address, TLS paths and the core/cell sockets are bootstrap material.
//     Re-binding a listening socket or swapping a host key is a restart operation,
//     not a settings change, and a "setting" that silently needs a restart is a
//     lie the operator only discovers later.
//   - There is no log level because the control plane has no levelled logger; there
//     is a signed evidence ledger instead, which is the stronger record.
//   - There is no clock-drift setting because nothing measures clock drift yet.

// ------------------------------------------------------------- dashboard

type SystemDashboardSettings struct {
	RateLimitPerMinute int  `json:"rate_limit_per_minute"`
	RateLimitBurst     int  `json:"rate_limit_burst"`
	MaxSSEClients      int  `json:"max_sse_clients"`
	MetricsEnabled     bool `json:"metrics_enabled"`
}

// ---------------------------------------------------------------- events

type SystemEventSettings struct {
	MaxEventCache int   `json:"max_event_cache"`
	MaxAPIPayload int64 `json:"max_api_payload_bytes"`
}

// ------------------------------------------------------------------ core

type SystemCoreSettings struct {
	RequestTimeoutMillis int `json:"request_timeout_millis"`
}

// ------------------------------------------------------------- namespace

type SystemFabricSettings struct {
	Dashboard SystemDashboardSettings `json:"dashboard"`
	Events    SystemEventSettings     `json:"events"`
	Core      SystemCoreSettings      `json:"core"`
}

func defaultSystemFabricSettings(cfg Config) SystemFabricSettings {
	rateLimit := cfg.Dashboard.RateLimitPerMinute
	if rateLimit <= 0 {
		rateLimit = 240
	}
	burst := cfg.Dashboard.RateLimitBurst
	if burst <= 0 {
		burst = 40
	}
	sseClients := cfg.Dashboard.MaxSSEClients
	if sseClients <= 0 {
		sseClients = 16
	}
	coreTimeout := cfg.Core.RequestTimeoutMillis
	if coreTimeout <= 0 {
		coreTimeout = 2000
	}
	return SystemFabricSettings{
		Dashboard: SystemDashboardSettings{
			RateLimitPerMinute: rateLimit, RateLimitBurst: burst,
			MaxSSEClients: sseClients, MetricsEnabled: true,
		},
		Events: SystemEventSettings{MaxEventCache: 250, MaxAPIPayload: 1 << 20},
		Core:   SystemCoreSettings{RequestTimeoutMillis: coreTimeout},
	}
}

func validateSystemFabricSettings(settings *SystemFabricSettings) error {
	if settings.Dashboard.RateLimitPerMinute < 1 || settings.Dashboard.RateLimitPerMinute > 60000 {
		return fmt.Errorf("API rate limit must be between 1 and 60000 requests per minute")
	}
	if settings.Dashboard.RateLimitBurst < 1 || settings.Dashboard.RateLimitBurst > 10000 {
		return fmt.Errorf("API burst allowance must be between 1 and 10000")
	}
	if settings.Dashboard.RateLimitBurst > settings.Dashboard.RateLimitPerMinute {
		// A burst larger than the per-minute allowance would let a caller exceed the
		// stated rate for the whole first minute, which makes the limit meaningless.
		return fmt.Errorf("API burst allowance must not exceed the per-minute rate limit")
	}
	if settings.Dashboard.MaxSSEClients < 1 || settings.Dashboard.MaxSSEClients > 512 {
		return fmt.Errorf("stream client ceiling must be between 1 and 512")
	}
	if settings.Events.MaxEventCache < 16 || settings.Events.MaxEventCache > 100000 {
		return fmt.Errorf("event cache budget must be between 16 and 100000")
	}
	if settings.Events.MaxAPIPayload < 64<<10 || settings.Events.MaxAPIPayload > 64<<20 {
		return fmt.Errorf("API payload ceiling must be between 64 KiB and 64 MiB")
	}
	if settings.Core.RequestTimeoutMillis < 100 || settings.Core.RequestTimeoutMillis > 60000 {
		return fmt.Errorf("core request timeout must be between 100 and 60000 milliseconds")
	}
	return nil
}

func effectiveSystemSettings(settings RuntimeSettings) SystemFabricSettings {
	if settings.System != nil {
		return *settings.System
	}
	return defaultSystemFabricSettings(Config{})
}

// ------------------------------------------------------------- live wiring

// Configure republishes the rate limit. The limiter is owned by the HTTP server
// and read on every request, so a revision takes effect on the next request
// without a restart.
func (l *RateLimiter) Configure(perMinute, burst int) error {
	if l == nil {
		return nil
	}
	if perMinute < 1 || burst < 1 || burst > perMinute {
		return fmt.Errorf("rate limit configuration is invalid")
	}
	l.mu.Lock()
	l.rate = float64(perMinute) / 60.0
	l.burst = float64(burst)
	// A tightening revision must not leave buckets that already exceed the new
	// allowance, so every existing bucket is clamped to the new burst.
	for identity, bucket := range l.visitors {
		if bucket.tokens > l.burst {
			bucket.tokens = l.burst
		}
		l.visitors[identity] = bucket
	}
	l.mu.Unlock()
	return nil
}

// SetEventCap republishes the event ring budget and trims the ring immediately,
// so a tightened budget takes effect on the current state rather than only on the
// next event.
func (s *State) SetEventCap(cap int) {
	if s == nil || cap <= 0 {
		return
	}
	s.mu.Lock()
	s.eventCap = cap
	if len(s.events) > cap {
		s.events = append([]Event(nil), s.events[len(s.events)-cap:]...)
	}
	s.mu.Unlock()
}

// EventCap reports the active ring budget.
func (s *State) EventCap() int {
	if s == nil {
		return 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.eventCap
}

// SetTimeout republishes the core IPC deadline. The client reads it on every call,
// so a revision takes effect on the next command.
func (c *CoreClient) SetTimeout(timeout time.Duration) error {
	if c == nil {
		return nil
	}
	if timeout < 100*time.Millisecond || timeout > time.Minute {
		return fmt.Errorf("core request timeout is outside the permitted range")
	}
	c.timeoutNanos.Store(int64(timeout))
	return nil
}

// apiPayloadLimit returns the ceiling applied to every mutating request body.
//
// It is a ceiling over the handler's own limit, not a replacement for it: a
// handler that accepts less still accepts less, and the administrable value can
// only tighten. Without this a single revision could widen every endpoint at once.
func (s *APIServer) apiPayloadLimit() int64 {
	if s == nil || s.settings == nil {
		return defaultSystemFabricSettings(Config{}).Events.MaxAPIPayload
	}
	limit := effectiveSystemSettings(s.settings.Get()).Events.MaxAPIPayload
	if limit <= 0 {
		return defaultSystemFabricSettings(Config{}).Events.MaxAPIPayload
	}
	return limit
}

// sseClientLimit returns the administrable stream client ceiling.
func (s *APIServer) sseClientLimit() int32 {
	if s == nil || s.settings == nil {
		return int32(defaultSystemFabricSettings(Config{}).Dashboard.MaxSSEClients)
	}
	limit := effectiveSystemSettings(s.settings.Get()).Dashboard.MaxSSEClients
	if limit <= 0 {
		return int32(defaultSystemFabricSettings(Config{}).Dashboard.MaxSSEClients)
	}
	return int32(limit)
}

// metricsAllowed reports whether the metrics exposition participates at all.
func (s *APIServer) metricsAllowed() bool {
	if s == nil || s.settings == nil {
		return true
	}
	return effectiveSystemSettings(s.settings.Get()).Dashboard.MetricsEnabled
}

// --------------------------------------------------------- distribution

// applySystemPolicies projects the System namespace onto the components that
// consume it from one choke point. Every target is optional, so a partially
// assembled server still applies what it has.
func applySystemPolicies(settings SystemFabricSettings, limiter *RateLimiter, state *State, core *CoreClient) error {
	if limiter != nil {
		if err := limiter.Configure(settings.Dashboard.RateLimitPerMinute, settings.Dashboard.RateLimitBurst); err != nil {
			return fmt.Errorf("apply rate limit: %w", err)
		}
	}
	if state != nil {
		state.SetEventCap(settings.Events.MaxEventCache)
	}
	if core != nil {
		if err := core.SetTimeout(time.Duration(settings.Core.RequestTimeoutMillis) * time.Millisecond); err != nil {
			return fmt.Errorf("apply core timeout: %w", err)
		}
	}
	return nil
}

// ------------------------------------------------------------- audit view

// systemBudgetAudit reports which compiled-in hard caps the administrable values
// sit underneath. The dashboard renders it so an operator can see that a setting
// is not the last line of defence.
func systemBudgetAudit(settings SystemFabricSettings) []map[string]any {
	type hardCap struct {
		name     string
		value    string
		setting  string
		adminVal string
	}
	caps := []hardCap{
		{"api-payload", "handler maximum", "events.max_api_payload_bytes", formatBytes(settings.Events.MaxAPIPayload)},
		{"event-cache", "100000 events", "events.max_event_cache", fmt.Sprintf("%d events", settings.Events.MaxEventCache)},
		{"stream-clients", "512 clients", "dashboard.max_sse_clients", fmt.Sprintf("%d clients", settings.Dashboard.MaxSSEClients)},
	}
	out := make([]map[string]any, 0, len(caps))
	for _, entry := range caps {
		out = append(out, map[string]any{
			"resource": entry.name, "hard_cap": entry.value,
			"setting": entry.setting, "administered": entry.adminVal,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		return strings.Compare(out[i]["resource"].(string), out[j]["resource"].(string)) < 0
	})
	return out
}

func formatBytes(value int64) string {
	switch {
	case value >= 1<<20:
		return fmt.Sprintf("%d MiB", value>>20)
	case value >= 1<<10:
		return fmt.Sprintf("%d KiB", value>>10)
	default:
		return fmt.Sprintf("%d bytes", value)
	}
}
