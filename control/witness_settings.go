package main

// POINT 4 / P4-T2: the operator-facing Out-of-Band Witness namespace
// (docs/POINT4-WITNESS.md §7).
//
// The namespace is additive and inert by default: Enabled=false and Mode="off"
// mean no checkpoint is created, no request is sent, no export is produced and no
// event is written. An upgrade from v16 therefore keeps the exact host behaviour
// of 5.2.0. Validation is reject-not-repair: an "enabled" witness without a
// hardened transport anchor is refused instead of being silently clamped into
// something the engine would then have to guess about.

import (
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"path/filepath"
	"strings"
)

var witnessEC2MetadataV6 = netip.MustParseAddr("fd00:ec2::254")

const (
	// Witness modes. off is the shipped default; http is Mode A (hardened HTTPS
	// client); export is Mode B (air-gapped vgtw1 export/import).
	witnessModeOff    = "off"
	witnessModeHTTP   = "http"
	witnessModeExport = "export"
)

const (
	// witnessMaxEndpointBytes bounds the configured endpoint URL.
	witnessMaxEndpointBytes = 512
	// witnessMaxPathBytes bounds every configured file path.
	witnessMaxPathBytes = 512
	// witnessMaxSPKIPinBytes is the 32-byte SHA-256 SPKI pin in lowercase hex.
	witnessMaxSPKIPinBytes = 64
	// witnessOutboxCeilingBytes is the hard upper bound an operator may configure.
	witnessOutboxCeilingBytes = 64 << 20
	// witnessOutboxFloorBytes keeps an outbox large enough for a few checkpoints.
	witnessOutboxFloorBytes = 64 << 10
	witnessMaxOutboxEntries = 65536
	witnessMinOutboxEntries = 16
)

// witnessMigrationNote is the one operator-visible migration record a v16
// document receives when it is upgraded to v17. An upgrade must never look like
// it silently changed the operator's configuration.
const witnessMigrationNote = "witness namespace added with enabled=false and mode=off: no checkpoint is created, no witness request is sent and no export is produced; host behaviour is unchanged until an operator enables it (docs/POINT4-WITNESS.md §7)"

// WitnessFabricSettings is the operator-facing Out-of-Band Witness namespace.
// It is a pointer on RuntimeSettings so a document persisted before it existed
// still serialises byte-identically and keeps authenticating (same contract as
// every other additive namespace).
type WitnessFabricSettings struct {
	Enabled bool   `json:"enabled"`
	Mode    string `json:"mode"`
	// Endpoint is the base URL of the external witness in Mode A. It must be an
	// absolute https URL on port 443; the client appends /v1/challenge and
	// /v1/checkpoint. It is never a secret.
	Endpoint string `json:"endpoint"`
	// PinnedServerKeyFile is the pinned Ed25519 receipt-verification key the
	// witness signs receipts with (0600, format like the feed signing key).
	PinnedServerKeyFile string `json:"pinned_server_key_file"`
	// PinnedServerSPKI is the SHA-256 over the server certificate's
	// RawSubjectPublicKeyInfo as 64 lowercase hex characters.
	PinnedServerSPKI string `json:"pinned_server_spki"`
	// ClientCertFile/ClientKeyFile are optional mTLS material. Both are required
	// together; the key file must be 0600.
	ClientCertFile string `json:"client_cert_file"`
	ClientKeyFile  string `json:"client_key_file"`
	// AuthTokenFile is an optional bearer token file (0600). The token never lives
	// in the settings document.
	AuthTokenFile string `json:"auth_token_file"`
	// CheckpointIntervalSeconds is the ticker cadence of the engine.
	CheckpointIntervalSeconds int `json:"checkpoint_interval_seconds"`
	// NonceTTLSeconds is the client-side lifetime of an accepted witness nonce.
	NonceTTLSeconds int `json:"nonce_ttl_seconds"`
	// RequestTimeoutSeconds bounds one HTTP round trip.
	RequestTimeoutSeconds int `json:"request_timeout_seconds"`
	// OutboxMaxBytes/OutboxMaxEntries bound the encrypted outbox.
	OutboxMaxBytes   int64 `json:"outbox_max_bytes"`
	OutboxMaxEntries int   `json:"outbox_max_entries"`
	// RetryAttempts/RetryBackoffSeconds bound the automatic retry of a push.
	RetryAttempts       int `json:"retry_attempts"`
	RetryBackoffSeconds int `json:"retry_backoff_seconds"`
	// RequireAck makes a missing receipt a degraded condition instead of a
	// successful delivery. Phase 1 always requires a receipt.
	RequireAck bool `json:"require_ack"`
	// DegradeAfterFailures is the consecutive failure count that flips the status
	// to degraded. It never triggers a lockdown; unreachable is not equivocation.
	DegradeAfterFailures int `json:"degrade_after_failures"`
	// EquivocationAlarm enables the critical evidence/incident path.
	EquivocationAlarm bool `json:"equivocation_alarm"`
	// TriggerLockdownOnEquivocation calls the optional P5 lockdown trigger.
	TriggerLockdownOnEquivocation bool `json:"trigger_lockdown_on_equivocation"`
}

// defaultWitnessFabricSettings returns the shipped defaults exactly as §7
// specifies them. Enabled=false is what makes an upgrade inert.
func defaultWitnessFabricSettings() WitnessFabricSettings {
	return WitnessFabricSettings{
		Enabled:                       false,
		Mode:                          witnessModeOff,
		Endpoint:                      "",
		PinnedServerKeyFile:           "",
		PinnedServerSPKI:              "",
		ClientCertFile:                "",
		ClientKeyFile:                 "",
		AuthTokenFile:                 "",
		CheckpointIntervalSeconds:     300,
		NonceTTLSeconds:               120,
		RequestTimeoutSeconds:         10,
		OutboxMaxBytes:                4 << 20,
		OutboxMaxEntries:              1024,
		RetryAttempts:                 3,
		RetryBackoffSeconds:           30,
		RequireAck:                    true,
		DegradeAfterFailures:          3,
		EquivocationAlarm:             true,
		TriggerLockdownOnEquivocation: false,
	}
}

func cloneWitnessFabricSettings(in WitnessFabricSettings) WitnessFabricSettings {
	// Every field is a value type; the copy is the clone.
	return in
}

// effectiveWitnessSettings returns the persisted namespace, or the inert
// compiled-in default when a document predates it.
func effectiveWitnessSettings(settings RuntimeSettings) WitnessFabricSettings {
	if settings.Witness != nil {
		return cloneWitnessFabricSettings(*settings.Witness)
	}
	return defaultWitnessFabricSettings()
}

func witnessDefaults(defaults RuntimeSettings) WitnessFabricSettings {
	if defaults.Witness != nil {
		return cloneWitnessFabricSettings(*defaults.Witness)
	}
	return defaultWitnessFabricSettings()
}

// validateWitnessFabricSettings is reject-not-repair: every value outside its
// documented bound is refused with its own error instead of being clamped.
func validateWitnessFabricSettings(in *WitnessFabricSettings) error {
	if in == nil {
		return errors.New("witness settings are required")
	}
	switch in.Mode {
	case witnessModeOff, witnessModeHTTP, witnessModeExport:
	default:
		return fmt.Errorf("witness mode must be %q, %q or %q", witnessModeOff, witnessModeHTTP, witnessModeExport)
	}
	if err := validateWitnessEndpoint(in.Endpoint); err != nil {
		return err
	}
	if in.PinnedServerSPKI != "" {
		if len(in.PinnedServerSPKI) != witnessMaxSPKIPinBytes {
			return fmt.Errorf("witness pinned_server_spki must be %d lowercase hex characters", witnessMaxSPKIPinBytes)
		}
		if _, err := hex.DecodeString(in.PinnedServerSPKI); err != nil || strings.ToLower(in.PinnedServerSPKI) != in.PinnedServerSPKI {
			return errors.New("witness pinned_server_spki must be lowercase hex")
		}
	}
	for name, value := range map[string]string{
		"pinned_server_key_file": in.PinnedServerKeyFile,
		"client_cert_file":       in.ClientCertFile,
		"client_key_file":        in.ClientKeyFile,
		"auth_token_file":        in.AuthTokenFile,
	} {
		if err := validateWitnessPath("witness "+name, value); err != nil {
			return err
		}
	}
	if (in.ClientCertFile == "") != (in.ClientKeyFile == "") {
		return errors.New("witness client_cert_file and client_key_file must be configured together")
	}
	if in.CheckpointIntervalSeconds < 30 || in.CheckpointIntervalSeconds > 86400 {
		return errors.New("witness checkpoint_interval_seconds must be between 30 and 86400")
	}
	if in.NonceTTLSeconds < 10 || in.NonceTTLSeconds > 900 {
		return errors.New("witness nonce_ttl_seconds must be between 10 and 900")
	}
	if in.RequestTimeoutSeconds < 1 || in.RequestTimeoutSeconds > 60 {
		return errors.New("witness request_timeout_seconds must be between 1 and 60")
	}
	if in.OutboxMaxBytes < witnessOutboxFloorBytes || in.OutboxMaxBytes > witnessOutboxCeilingBytes {
		return fmt.Errorf("witness outbox_max_bytes must be between %d and %d", witnessOutboxFloorBytes, witnessOutboxCeilingBytes)
	}
	if in.OutboxMaxEntries < witnessMinOutboxEntries || in.OutboxMaxEntries > witnessMaxOutboxEntries {
		return fmt.Errorf("witness outbox_max_entries must be between %d and %d", witnessMinOutboxEntries, witnessMaxOutboxEntries)
	}
	if in.RetryAttempts < 0 || in.RetryAttempts > 10 {
		return errors.New("witness retry_attempts must be between 0 and 10")
	}
	if in.RetryBackoffSeconds < 1 || in.RetryBackoffSeconds > 3600 {
		return errors.New("witness retry_backoff_seconds must be between 1 and 3600")
	}
	if in.DegradeAfterFailures < 1 || in.DegradeAfterFailures > 100 {
		return errors.New("witness degrade_after_failures must be between 1 and 100")
	}
	if in.Enabled {
		switch in.Mode {
		case witnessModeHTTP:
			// §8: an enabled HTTP witness without an endpoint or without a pinned
			// transport anchor would send evidence anywhere or trust anyone.
			if in.Endpoint == "" {
				return errors.New("witness http mode requires an endpoint")
			}
			if in.PinnedServerKeyFile == "" && in.PinnedServerSPKI == "" {
				return errors.New("witness http mode requires a pinned server SPKI or a pinned receipt key")
			}
		case witnessModeExport:
			// Mode B is deliberately air-gapped: no endpoint, no transport anchor.
		case witnessModeOff:
			return errors.New("witness is enabled but mode is off")
		}
	}
	return nil
}

// validateWitnessEndpoint accepts only an absolute https URL on port 443 without
// userinfo, query or fragment. The client appends the protocol paths, so an
// ambiguous base URL is refused here instead of being repaired.
func validateWitnessEndpoint(endpoint string) error {
	if endpoint == "" {
		return nil
	}
	if len(endpoint) > witnessMaxEndpointBytes || strings.ContainsAny(endpoint, "\x00\r\n") {
		return errors.New("witness endpoint is empty, oversized or contains control characters")
	}
	if strings.TrimSpace(endpoint) != endpoint {
		return errors.New("witness endpoint must not carry leading or trailing whitespace")
	}
	parsed, err := url.Parse(endpoint)
	if err != nil || !parsed.IsAbs() || parsed.Host == "" {
		return errors.New("witness endpoint must be an absolute URL")
	}
	if parsed.Scheme != "https" {
		return errors.New("witness endpoint must use https")
	}
	if parsed.User != nil {
		return errors.New("witness endpoint must not contain userinfo")
	}
	if parsed.Fragment != "" || parsed.RawQuery != "" {
		return errors.New("witness endpoint must not contain a query or fragment")
	}
	if parsed.Hostname() == "" {
		return errors.New("witness endpoint has no host")
	}
	if err := validateWitnessHost(parsed.Hostname()); err != nil {
		return err
	}
	if port := parsed.Port(); port != "" && port != "443" {
		return errors.New("witness endpoint must use port 443")
	}
	return nil
}

// witnessIPAllowed rejects loopback, unspecified, link-local, multicast and
// cloud metadata addresses while still permitting explicit RFC1918 LAN targets
// for self-hosted witness relays.
func witnessIPAllowed(ip netip.Addr) bool {
	ip = ip.Unmap()
	return ip.IsValid() &&
		!ip.IsLoopback() &&
		!ip.IsUnspecified() &&
		!ip.IsMulticast() &&
		!ip.IsLinkLocalUnicast() &&
		!ip.IsLinkLocalMulticast() &&
		ip != witnessEC2MetadataV6
}

func validateWitnessHost(host string) error {
	lower := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	if lower == "" || lower == "localhost" || strings.HasSuffix(lower, ".localhost") ||
		lower == "metadata.google.internal" || lower == "metadata" || lower == "instance-data" {
		return errors.New("witness endpoint host is forbidden")
	}
	if addr, err := netip.ParseAddr(lower); err == nil && !witnessIPAllowed(addr) {
		return errors.New("witness endpoint IP address is forbidden")
	}
	return nil
}

// validateWitnessPath rejects a path the engine could not read safely: it must be
// absolute, canonical and free of control characters. The 0600 requirement is
// enforced when the file is opened, where its mode can actually be observed.
func validateWitnessPath(name, path string) error {
	if path == "" {
		return nil
	}
	if len(path) > witnessMaxPathBytes || strings.ContainsAny(path, "\x00\r\n") {
		return fmt.Errorf("%s must be a bounded path without control characters", name)
	}
	if strings.TrimSpace(path) != path {
		return fmt.Errorf("%s must not carry leading or trailing whitespace", name)
	}
	if !filepath.IsAbs(path) {
		return fmt.Errorf("%s must be an absolute path", name)
	}
	if filepath.Clean(path) != path {
		return fmt.Errorf("%s must be a canonical path", name)
	}
	return nil
}

// witnessModeActive reports whether the namespace would do anything at all.
func witnessModeActive(settings WitnessFabricSettings) bool {
	return settings.Enabled && settings.Mode != witnessModeOff
}
