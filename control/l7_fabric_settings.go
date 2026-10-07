// STATUS: DIAMANT VGT SUPREME
package main

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
)

// Application Defense (L7) Fabric administration.
//
// Plan reference: GeDefense 4.2 Security Fabric Control Plane, section 16
// (Application Defense / L7 settings) and section 49 (settings must be
// compiled into compact immutable runtime snapshots; the inspection hot path
// reads one atomic snapshot and never a mutable JSON structure).
//
// Design invariants:
//
//  1. The persisted revision is the only authority. The runtime keeps an
//     immutable snapshot published with a single atomic store, so one
//     inspection always observes one consistent configuration.
//  2. Restart-class values are persisted but never silently activated. The
//     live snapshot keeps the boot value until the process is restarted and
//     the module reports restart_required.
//  3. Operator rule overrides can suppress detections and adjust scores, but
//     an alert-only rule can never contribute to a block decision.

const l7RuleOverrideLimit = 128

// L7RuleOverride is the administrable view of one built-in L7 detection rule.
type L7RuleOverride struct {
	ID         string `json:"id"`
	Enabled    bool   `json:"enabled"`
	Score      int    `json:"score"`
	Confidence int    `json:"confidence"`
	AlertOnly  bool   `json:"alert_only"`
}

// supportedL7RuleOverrides is the closed allowlist of built-in L7 rules whose
// enablement, score, confidence and block eligibility may be administered.
// The detection patterns themselves are read-only: an operator can tune a
// signature, never invent one.
var supportedL7RuleOverrides = map[string]struct{}{
	"L7.SQLI.UNION_SELECT": {}, "L7.SQLI.BOOLEAN_TAUTOLOGY": {}, "L7.SQLI.TIME_DELAY": {}, "L7.SQLI.STACKED_QUERY": {},
	"L7.XSS.SCRIPT_TAG": {}, "L7.XSS.EVENT_HANDLER": {}, "L7.XSS.ACTIVE_URI": {}, "L7.XSS.IFRAME_SRCDOC": {},
	"L7.CMD.SHELL_CHAIN": {}, "L7.CMD.SUBSTITUTION": {}, "L7.CMD.WINDOWS_CHAIN": {},
	"L7.PATH.TRAVERSAL": {}, "L7.FILE.STREAM_WRAPPER": {}, "L7.SSTI.TEMPLATE_EXPR": {},
	"L7.XXE.DECLARATION": {}, "L7.XXE.EXTERNAL_SYSTEM": {},
	"L7.DESERIALIZE.PHP": {}, "L7.DESERIALIZE.JAVA": {},
	"L7.SCANNER.PROBE": {}, "L7.CRLF.HEADER_SPLIT": {}, "L7.CODE.PHP_TAG": {}, "L7.JNDI.LOOKUP": {},
	"L7.SSRF.DANGEROUS_SCHEME": {}, "L7.SSRF.INTERNAL_TARGET": {},
	"L7.HTTP.DUPLICATE_CONTENT_LENGTH": {}, "L7.HTTP.INVALID_CONTENT_LENGTH": {}, "L7.HTTP.CL_TE_AMBIGUITY": {},
	"L7.HTTP.INVALID_TRANSFER_ENCODING": {}, "L7.HTTP.TRACE_METHOD": {},
	"L7.UPLOAD.INVALID_MULTIPART": {}, "L7.UPLOAD.PART_BUDGET": {}, "L7.UPLOAD.SIZE_BUDGET": {}, "L7.UPLOAD": {},
	"L7.RATE_LIMIT.CLIENT": {}, "L7.RATE_LIMIT.SENSITIVE_ROUTE": {}, "L7.RATE_LIMIT.SENSITIVE_ROUTE_GLOBAL": {}, "L7.RATE_LIMIT": {},
	"L7.RESPONSE.SQL_ERROR": {}, "L7.RESPONSE.SOURCE_CODE": {}, "L7.RESPONSE.STACK_TRACE": {},
	"L7.RESPONSE.DIRECTORY_INDEX": {}, "L7.RESPONSE.PRIVATE_KEY": {}, "L7.RESPONSE.TECHNOLOGY_DISCLOSURE": {},
	"TLS.CLIENTHELLO.MALFORMED": {}, "TLS.CLIENT_IP.INVALID": {}, "TLS.JA3.MALICIOUS": {}, "TLS.JA3.STRUCTURAL_SPOOF": {},
	"TLS.JA3.UNKNOWN": {}, "TLS.SNI.MISSING": {}, "TLS.SNI.INVALID": {}, "TLS.SNI.FOREIGN": {},
	"TLS.SNI.REPEATED_INVALID": {}, "TLS.HANDSHAKE.FLOOD": {}, "TLS.HOST_MISMATCH": {},
}

// l7RuleFamilyPrefixes lists allowlisted identifiers that act as a family
// prefix over runtime-generated rule identifiers, for example
// "L7.RATE_LIMIT" covering "L7.RATE_LIMIT.CLIENT".
var l7RuleFamilyPrefixes = []string{"L7.RATE_LIMIT", "L7.UPLOAD"}

func l7RuleOverrideIDAllowed(id string) bool {
	_, ok := supportedL7RuleOverrides[id]
	return ok
}

// L7FabricSettings is the administrable Application Defense surface. It is a
// strict mirror of the mutable part of L7Config plus the rule registry.
type L7FabricSettings struct {
	Enabled bool   `json:"enabled"`
	Mode    string `json:"mode"`
	Socket  string `json:"socket"`

	MaxConcurrent        int `json:"max_concurrent"`
	RequestTimeoutMillis int `json:"request_timeout_millis"`

	MaxEnvelopeBytes   int `json:"max_envelope_bytes"`
	MaxBodyBytes       int `json:"max_body_bytes"`
	MaxUploadBytes     int `json:"max_upload_bytes"`
	MaxURIBytes        int `json:"max_uri_bytes"`
	MaxHeaderBytes     int `json:"max_header_bytes"`
	MaxHeaders         int `json:"max_headers"`
	MaxValueBytes      int `json:"max_value_bytes"`
	MaxInspectionBytes int `json:"max_inspection_bytes"`
	MaxDecodedValues   int `json:"max_decoded_values"`
	MaxDecodeDepth     int `json:"max_decode_depth"`
	MaxJSONDepth       int `json:"max_json_depth"`
	MaxFormFields      int `json:"max_form_fields"`
	MaxMultipartParts  int `json:"max_multipart_parts"`

	AlertScore int `json:"alert_score"`
	BlockScore int `json:"block_score"`

	ClientRatePerMinute          int      `json:"client_rate_per_minute"`
	ClientRateBurst              int      `json:"client_rate_burst"`
	SensitiveRatePerMinute       int      `json:"sensitive_rate_per_minute"`
	SensitiveRateBurst           int      `json:"sensitive_rate_burst"`
	SensitiveGlobalRatePerMinute int      `json:"sensitive_global_rate_per_minute"`
	SensitiveGlobalRateBurst     int      `json:"sensitive_global_rate_burst"`
	MaxTrackedClients            int      `json:"max_tracked_clients"`
	SensitivePaths               []string `json:"sensitive_paths"`

	RequirePeerCredentials bool     `json:"require_peer_credentials"`
	AllowedPeerUIDs        []uint32 `json:"allowed_peer_uids"`
	AllowedPeerGIDs        []uint32 `json:"allowed_peer_gids"`
	SocketGroup            string   `json:"socket_group"`

	InlineEnabled          bool   `json:"inline_enabled"`
	InlineSocket           string `json:"inline_socket"`
	InlineUpstream         string `json:"inline_upstream"`
	InlineMaxResponseBytes int    `json:"inline_max_response_bytes"`

	TLSEnabled                 bool     `json:"tls_enabled"`
	TLSAllowedDomains          []string `json:"tls_allowed_domains"`
	TLSFloodThreshold          int      `json:"tls_flood_threshold"`
	TLSSNIStrikeThreshold      int      `json:"tls_sni_strike_threshold"`
	TLSAntiSpoof               bool     `json:"tls_anti_spoof"`
	TLSMaxClientHelloBytes     int      `json:"tls_max_client_hello_bytes"`
	TLSJA3File                 string   `json:"tls_ja3_file"`
	TLSJA3Reload               bool     `json:"tls_ja3_reload"`
	TLSUnknownFingerprint      string   `json:"tls_unknown_fingerprint"`
	TLSUnknownFingerprintScore int      `json:"tls_unknown_fingerprint_score"`

	Rules []L7RuleOverride `json:"rules,omitempty"`
}

// defaultL7FabricSettings derives the first Fabric revision from the static
// bootstrap configuration so an existing deployment keeps its effective
// behaviour after the v2 settings migration.
func defaultL7FabricSettings(cfg L7Config) L7FabricSettings {
	return L7FabricSettings{
		Enabled: cfg.Enabled, Mode: cfg.Mode, Socket: cfg.Socket,
		MaxConcurrent: cfg.MaxConcurrent, RequestTimeoutMillis: cfg.RequestTimeoutMillis,
		MaxEnvelopeBytes: cfg.MaxEnvelopeBytes, MaxBodyBytes: cfg.MaxBodyBytes, MaxUploadBytes: cfg.MaxUploadBytes,
		MaxURIBytes: cfg.MaxURIBytes, MaxHeaderBytes: cfg.MaxHeaderBytes, MaxHeaders: cfg.MaxHeaders,
		MaxValueBytes: cfg.MaxValueBytes, MaxInspectionBytes: cfg.MaxInspectionBytes, MaxDecodedValues: cfg.MaxDecodedValues,
		MaxDecodeDepth: cfg.MaxDecodeDepth, MaxJSONDepth: cfg.MaxJSONDepth, MaxFormFields: cfg.MaxFormFields,
		MaxMultipartParts: cfg.MaxMultipartParts,
		AlertScore:        cfg.AlertScore, BlockScore: cfg.BlockScore,
		ClientRatePerMinute: cfg.ClientRatePerMinute, ClientRateBurst: cfg.ClientRateBurst,
		SensitiveRatePerMinute: cfg.SensitiveRatePerMinute, SensitiveRateBurst: cfg.SensitiveRateBurst,
		SensitiveGlobalRatePerMinute: cfg.SensitiveGlobalRatePerMinute, SensitiveGlobalRateBurst: cfg.SensitiveGlobalRateBurst,
		MaxTrackedClients: cfg.MaxTrackedClients, SensitivePaths: append([]string(nil), cfg.SensitivePaths...),
		RequirePeerCredentials: cfg.RequirePeerCredentials,
		AllowedPeerUIDs:        append([]uint32(nil), cfg.AllowedPeerUIDs...),
		AllowedPeerGIDs:        append([]uint32(nil), cfg.AllowedPeerGIDs...),
		SocketGroup:            cfg.SocketGroup,
		InlineEnabled:          cfg.InlineEnabled, InlineSocket: cfg.InlineSocket, InlineUpstream: cfg.InlineUpstream,
		InlineMaxResponseBytes: cfg.InlineMaxResponseBytes,
		TLSEnabled:             cfg.TLSEnabled, TLSAllowedDomains: append([]string(nil), cfg.TLSAllowedDomains...),
		TLSFloodThreshold: cfg.TLSFloodThreshold, TLSSNIStrikeThreshold: cfg.TLSSNIStrikeThreshold,
		TLSAntiSpoof: cfg.TLSAntiSpoof, TLSMaxClientHelloBytes: cfg.TLSMaxClientHelloBytes, TLSJA3File: cfg.TLSJA3File,
		TLSUnknownFingerprint: "allow", TLSUnknownFingerprintScore: 35,
		Rules: []L7RuleOverride{},
	}
}

func cloneL7FabricSettings(in L7FabricSettings) L7FabricSettings {
	out := in
	out.SensitivePaths = append([]string(nil), in.SensitivePaths...)
	out.AllowedPeerUIDs = append([]uint32(nil), in.AllowedPeerUIDs...)
	out.AllowedPeerGIDs = append([]uint32(nil), in.AllowedPeerGIDs...)
	out.TLSAllowedDomains = append([]string(nil), in.TLSAllowedDomains...)
	out.Rules = append([]L7RuleOverride(nil), in.Rules...)
	return out
}

// withSocketPaths re-attaches the previously active socket paths when a
// revision omits them, so an incomplete dashboard payload can never blank a
// listener path and silently disable a socket.
func (f L7FabricSettings) withSocketPaths(previous L7FabricSettings) L7FabricSettings {
	out := f
	if strings.TrimSpace(out.Socket) == "" {
		out.Socket = previous.Socket
	}
	if strings.TrimSpace(out.InlineSocket) == "" {
		out.InlineSocket = previous.InlineSocket
	}
	return out
}

// toConfig compiles the administrable surface into the runtime configuration
// consumed by the inspection engine.
func (f L7FabricSettings) toConfig() L7Config {
	return L7Config{
		Enabled: f.Enabled, Mode: f.Mode, Socket: f.Socket, SocketGroup: f.SocketGroup,
		RequestTimeoutMillis: f.RequestTimeoutMillis, MaxConcurrent: f.MaxConcurrent,
		MaxEnvelopeBytes: f.MaxEnvelopeBytes, MaxBodyBytes: f.MaxBodyBytes, MaxUploadBytes: f.MaxUploadBytes,
		MaxURIBytes: f.MaxURIBytes, MaxHeaderBytes: f.MaxHeaderBytes, MaxHeaders: f.MaxHeaders,
		MaxValueBytes: f.MaxValueBytes, MaxInspectionBytes: f.MaxInspectionBytes, MaxDecodedValues: f.MaxDecodedValues,
		MaxDecodeDepth: f.MaxDecodeDepth, MaxJSONDepth: f.MaxJSONDepth, MaxFormFields: f.MaxFormFields,
		MaxMultipartParts: f.MaxMultipartParts,
		AlertScore:        f.AlertScore, BlockScore: f.BlockScore,
		ClientRatePerMinute: f.ClientRatePerMinute, ClientRateBurst: f.ClientRateBurst,
		SensitiveRatePerMinute: f.SensitiveRatePerMinute, SensitiveRateBurst: f.SensitiveRateBurst,
		SensitiveGlobalRatePerMinute: f.SensitiveGlobalRatePerMinute, SensitiveGlobalRateBurst: f.SensitiveGlobalRateBurst,
		MaxTrackedClients: f.MaxTrackedClients, SensitivePaths: append([]string(nil), f.SensitivePaths...),
		RequirePeerCredentials: f.RequirePeerCredentials,
		AllowedPeerUIDs:        append([]uint32(nil), f.AllowedPeerUIDs...),
		AllowedPeerGIDs:        append([]uint32(nil), f.AllowedPeerGIDs...),
		InlineEnabled:          f.InlineEnabled, InlineSocket: f.InlineSocket, InlineUpstream: f.InlineUpstream,
		InlineMaxResponseBytes: f.InlineMaxResponseBytes,
		TLSEnabled:             f.TLSEnabled, TLSAllowedDomains: append([]string(nil), f.TLSAllowedDomains...),
		TLSFloodThreshold: f.TLSFloodThreshold, TLSSNIStrikeThreshold: f.TLSSNIStrikeThreshold,
		TLSAntiSpoof: f.TLSAntiSpoof, TLSMaxClientHelloBytes: f.TLSMaxClientHelloBytes, TLSJA3File: f.TLSJA3File,
	}
}

// l7RestartClassKeys lists every fabric key that cannot be activated in a
// running process. Persisted values are honoured on the next service start.
var l7RestartClassKeys = []string{
	"enabled", "max_concurrent", "request_timeout_millis", "socket", "max_tracked_clients",
	"require_peer_credentials", "allowed_peer_uids", "allowed_peer_gids", "socket_group",
	"inline_enabled", "inline_socket", "inline_upstream", "tls_enabled",
}

// l7RestartClassChanged reports whether a revision requires a service restart
// before it can become the effective runtime configuration.
func l7RestartClassChanged(previous, next L7FabricSettings) bool {
	if previous.Enabled != next.Enabled ||
		previous.MaxConcurrent != next.MaxConcurrent ||
		previous.RequestTimeoutMillis != next.RequestTimeoutMillis ||
		previous.Socket != next.Socket ||
		previous.MaxTrackedClients != next.MaxTrackedClients ||
		previous.RequirePeerCredentials != next.RequirePeerCredentials ||
		previous.SocketGroup != next.SocketGroup ||
		previous.InlineEnabled != next.InlineEnabled ||
		previous.InlineSocket != next.InlineSocket ||
		previous.InlineUpstream != next.InlineUpstream ||
		previous.TLSEnabled != next.TLSEnabled {
		return true
	}
	return !equalUint32Slice(previous.AllowedPeerUIDs, next.AllowedPeerUIDs) ||
		!equalUint32Slice(previous.AllowedPeerGIDs, next.AllowedPeerGIDs)
}

func equalUint32Slice(a, b []uint32) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// l7RuleWiringChanged reports whether a revision changes detection wiring that
// must not be mutated while the fabric is enforcing.
func l7RuleWiringChanged(previous, next L7FabricSettings) bool {
	return !equalL7RuleOverrides(previous.Rules, next.Rules)
}

func equalL7RuleOverrides(a, b []L7RuleOverride) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// validateL7FabricSettings enforces the same safety relations as the static
// configuration validator, plus the rule registry contract. Hard safety limits
// are never bypassable from the dashboard.
func validateL7FabricSettings(settings *L7FabricSettings) error {
	if settings.Mode != "observe" && settings.Mode != "block" {
		return fmt.Errorf("l7 mode must be observe or block")
	}
	if settings.MaxConcurrent < 1 || settings.MaxConcurrent > 1024 {
		return fmt.Errorf("l7 max concurrent inspections must be between 1 and 1024")
	}
	if settings.RequestTimeoutMillis < 50 || settings.RequestTimeoutMillis > 10000 {
		return fmt.Errorf("l7 request timeout must be between 50 and 10000 milliseconds")
	}
	if settings.MaxBodyBytes < 0 || settings.MaxUploadBytes < 0 || settings.MaxUploadBytes > settings.MaxBodyBytes {
		return fmt.Errorf("l7 upload bound must not exceed the body bound")
	}
	if settings.MaxBodyBytes > 16<<20 || settings.MaxEnvelopeBytes < 4096 || settings.MaxEnvelopeBytes > 32<<20 {
		return fmt.Errorf("l7 body and envelope bounds are outside safe limits")
	}
	requiredInspection := settings.MaxBodyBytes + settings.MaxHeaderBytes + (2 * settings.MaxURIBytes) + (64 << 10)
	if settings.MaxInspectionBytes < requiredInspection {
		return fmt.Errorf("l7 inspection budget must cover body, header and URI budgets")
	}
	requiredEnvelope := ((settings.MaxBodyBytes + 2) / 3 * 4) + settings.MaxHeaderBytes + (64 << 10)
	if settings.MaxEnvelopeBytes < requiredEnvelope {
		return fmt.Errorf("l7 envelope bound must cover the base64 body, header and URI budgets")
	}
	if settings.MaxURIBytes < 256 || settings.MaxHeaderBytes < 1024 || settings.MaxHeaders < 8 ||
		settings.MaxValueBytes < 256 || settings.MaxDecodedValues < 16 || settings.MaxFormFields < 1 {
		return fmt.Errorf("l7 request bounds are below the safe minimum")
	}
	if settings.MaxDecodeDepth < 1 || settings.MaxDecodeDepth > 16 || settings.MaxJSONDepth < 1 || settings.MaxJSONDepth > 256 {
		return fmt.Errorf("l7 decode budgets are outside safe bounds")
	}
	if settings.MaxMultipartParts < 1 || settings.MaxMultipartParts > 4096 {
		return fmt.Errorf("l7 multipart part budget is outside safe bounds")
	}
	if settings.AlertScore < 1 || settings.BlockScore > 250 || settings.AlertScore >= settings.BlockScore {
		return fmt.Errorf("l7 scores must satisfy 1 <= alert < block <= 250")
	}
	if settings.ClientRatePerMinute < 1 || settings.ClientRateBurst < 1 ||
		settings.SensitiveRatePerMinute < 1 || settings.SensitiveRateBurst < 1 ||
		settings.SensitiveGlobalRatePerMinute < 1 || settings.SensitiveGlobalRateBurst < 1 {
		return fmt.Errorf("l7 rate limits must be positive")
	}
	if settings.MaxTrackedClients < 64 || settings.MaxTrackedClients > 1000000 {
		return fmt.Errorf("l7 tracked client bound must be between 64 and 1000000")
	}
	if settings.InlineMaxResponseBytes < 0 || settings.InlineMaxResponseBytes > 16<<20 {
		return fmt.Errorf("l7 inline response bound is outside safe limits")
	}
	if len(settings.SensitivePaths) > 512 {
		return fmt.Errorf("l7 sensitive path list exceeds 512 entries")
	}
	seenPaths := make(map[string]struct{}, len(settings.SensitivePaths))
	normalizedPaths := make([]string, 0, len(settings.SensitivePaths))
	for _, raw := range settings.SensitivePaths {
		path := strings.TrimSpace(raw)
		if path == "" || path[0] != '/' || strings.ContainsAny(path, "?#\x00") || len(path) > settings.MaxURIBytes {
			return fmt.Errorf("l7 sensitive path %q must be an absolute request path", raw)
		}
		if _, exists := seenPaths[path]; exists {
			continue
		}
		seenPaths[path] = struct{}{}
		normalizedPaths = append(normalizedPaths, path)
	}
	sort.Strings(normalizedPaths)
	settings.SensitivePaths = normalizedPaths
	if settings.RequirePeerCredentials && len(settings.AllowedPeerUIDs) == 0 && len(settings.AllowedPeerGIDs) == 0 {
		return fmt.Errorf("l7 peer credentials require at least one allowed UID or GID")
	}
	if len(settings.AllowedPeerUIDs) > 128 || len(settings.AllowedPeerGIDs) > 128 {
		return fmt.Errorf("l7 peer identity lists exceed 128 entries")
	}
	settings.AllowedPeerUIDs = normalizeUIDList(settings.AllowedPeerUIDs)
	settings.AllowedPeerGIDs = normalizeUIDList(settings.AllowedPeerGIDs)
	if settings.SocketGroup != "" && !isSafeUnixIdentityName(settings.SocketGroup) {
		return fmt.Errorf("l7 socket group name is invalid")
	}
	if settings.InlineEnabled && !settings.Enabled {
		return fmt.Errorf("l7 inline edge requires the Application Defense engine")
	}
	if settings.InlineEnabled && settings.InlineSocket == settings.Socket {
		return fmt.Errorf("l7 inline socket must differ from the inspection socket")
	}
	if settings.InlineEnabled {
		if err := validateL7InlineUpstream(settings.InlineUpstream); err != nil {
			return err
		}
	}
	if settings.MaxEnvelopeBytes*settings.MaxConcurrent > 256<<20 {
		return fmt.Errorf("l7 envelope budget times concurrency exceeds 256 MiB")
	}
	if settings.MaxInspectionBytes*settings.MaxConcurrent > 256<<20 {
		return fmt.Errorf("l7 inspection budget times concurrency exceeds 256 MiB")
	}
	perInspection := int64(settings.MaxEnvelopeBytes) + int64(settings.MaxBodyBytes) + int64(settings.MaxInspectionBytes) + int64(settings.InlineMaxResponseBytes)
	if perInspection*int64(settings.MaxConcurrent) > 384<<20 {
		return fmt.Errorf("l7 aggregate inspection memory budget exceeds 384 MiB")
	}
	if settings.TLSEnabled {
		if settings.TLSFloodThreshold < 2 || settings.TLSFloodThreshold > 100000 {
			return fmt.Errorf("l7 TLS flood threshold is outside safe bounds")
		}
		if settings.TLSSNIStrikeThreshold < 2 || settings.TLSSNIStrikeThreshold > 1000 {
			return fmt.Errorf("l7 SNI strike threshold is outside safe bounds")
		}
		if settings.TLSMaxClientHelloBytes < 1024 || settings.TLSMaxClientHelloBytes > 1<<20 {
			return fmt.Errorf("l7 ClientHello bound must be between 1024 and 1048576 bytes")
		}
	}
	if settings.TLSUnknownFingerprint != "allow" && settings.TLSUnknownFingerprint != "alert" {
		return fmt.Errorf("l7 unknown fingerprint behaviour must be allow or alert")
	}
	if settings.TLSUnknownFingerprintScore < 1 || settings.TLSUnknownFingerprintScore > 250 {
		return fmt.Errorf("l7 unknown fingerprint score must be between 1 and 250")
	}
	if len(settings.TLSAllowedDomains) > 4096 {
		return fmt.Errorf("l7 TLS allowed domain list exceeds 4096 entries")
	}
	seenDomains := make(map[string]struct{}, len(settings.TLSAllowedDomains))
	normalizedDomains := make([]string, 0, len(settings.TLSAllowedDomains))
	for _, raw := range settings.TLSAllowedDomains {
		domain, err := normalizeAllowedTLSHostname(raw)
		if err != nil {
			return err
		}
		if _, exists := seenDomains[domain]; exists {
			continue
		}
		seenDomains[domain] = struct{}{}
		normalizedDomains = append(normalizedDomains, domain)
	}
	sort.Strings(normalizedDomains)
	settings.TLSAllowedDomains = normalizedDomains
	if settings.TLSJA3File != "" {
		if err := validateAbsoluteCleanPath("l7 JA3 fingerprint file", settings.TLSJA3File); err != nil {
			return err
		}
	}
	if len(settings.Rules) > l7RuleOverrideLimit {
		return fmt.Errorf("l7 rule override limit of %d exceeded", l7RuleOverrideLimit)
	}
	seenRules := make(map[string]struct{}, len(settings.Rules))
	for i := range settings.Rules {
		rule := &settings.Rules[i]
		rule.ID = strings.ToUpper(strings.TrimSpace(rule.ID))
		if !l7RuleOverrideIDAllowed(rule.ID) {
			return fmt.Errorf("l7 rule override %q is not a supported built-in rule", rule.ID)
		}
		if _, exists := seenRules[rule.ID]; exists {
			return fmt.Errorf("duplicate l7 rule override %q", rule.ID)
		}
		seenRules[rule.ID] = struct{}{}
		if rule.Score < 1 || rule.Score > 250 {
			return fmt.Errorf("l7 rule override %s score must be between 1 and 250", rule.ID)
		}
		if rule.Confidence < 1 || rule.Confidence > 100 {
			return fmt.Errorf("l7 rule override %s confidence must be between 1 and 100", rule.ID)
		}
	}
	sort.Slice(settings.Rules, func(i, j int) bool { return settings.Rules[i].ID < settings.Rules[j].ID })
	settings.TLSJA3Reload = false
	return nil
}

func normalizeUIDList(values []uint32) []uint32 {
	if len(values) == 0 {
		return []uint32{}
	}
	sort.Slice(values, func(i, j int) bool { return values[i] < values[j] })
	out := values[:0]
	var previous uint32
	for i, value := range values {
		if i > 0 && value == previous {
			continue
		}
		previous = value
		out = append(out, value)
	}
	return out
}

// validateAbsoluteCleanPath rejects relative, unclean and oversized paths so a
// settings revision can never widen a filesystem read.
func validateAbsoluteCleanPath(label, path string) error {
	if !strings.HasPrefix(path, "/") || strings.Contains(path, "//") || strings.ContainsAny(path, "\x00\r\n") {
		return fmt.Errorf("%s must be a clean absolute path", label)
	}
	if path != "/" && strings.HasSuffix(path, "/") {
		return fmt.Errorf("%s must be a clean absolute path", label)
	}
	for _, component := range strings.Split(path, "/") {
		if component == "." || component == ".." {
			return fmt.Errorf("%s must not contain relative components", label)
		}
	}
	if len(path) > 512 {
		return fmt.Errorf("%s exceeds 512 bytes", label)
	}
	return nil
}

// l7RuntimeSnapshot is the immutable configuration view read by the
// inspection hot path. It is published with one atomic store.
type l7RuntimeSnapshot struct {
	cfg      L7Config
	revision uint64
	active   L7FabricSettings

	sensitiveExact map[string]struct{}
	sensitiveRoots []string

	unknownFingerprint      string
	unknownFingerprintScore int

	ruleExact    map[string]L7RuleOverride
	ruleFamilies []string
	ruleByFamily map[string]L7RuleOverride
}

// l7Runtime owns the published snapshot.
type l7Runtime struct {
	ptr atomic.Pointer[l7RuntimeSnapshot]
}

func buildL7RuntimeSnapshot(settings L7FabricSettings, revision uint64) *l7RuntimeSnapshot {
	effective := cloneL7FabricSettings(settings)
	cfg := effective.toConfig()
	snapshot := &l7RuntimeSnapshot{
		cfg: cfg, revision: revision, active: effective,
		sensitiveExact:          make(map[string]struct{}, len(effective.SensitivePaths)),
		unknownFingerprint:      effective.TLSUnknownFingerprint,
		unknownFingerprintScore: effective.TLSUnknownFingerprintScore,
		ruleExact:               make(map[string]L7RuleOverride, len(effective.Rules)),
		ruleByFamily:            make(map[string]L7RuleOverride, len(l7RuleFamilyPrefixes)),
	}
	for _, path := range effective.SensitivePaths {
		snapshot.sensitiveExact[path] = struct{}{}
	}
	for _, path := range effective.SensitivePaths {
		if path == "/" {
			continue
		}
		snapshot.sensitiveRoots = append(snapshot.sensitiveRoots, path+"/")
	}
	sort.Slice(snapshot.sensitiveRoots, func(i, j int) bool {
		return len(snapshot.sensitiveRoots[i]) > len(snapshot.sensitiveRoots[j])
	})
	for _, rule := range effective.Rules {
		if isL7RuleFamily(rule.ID) {
			snapshot.ruleByFamily[rule.ID] = rule
			snapshot.ruleFamilies = append(snapshot.ruleFamilies, rule.ID)
			continue
		}
		snapshot.ruleExact[rule.ID] = rule
	}
	sort.Slice(snapshot.ruleFamilies, func(i, j int) bool {
		return len(snapshot.ruleFamilies[i]) > len(snapshot.ruleFamilies[j])
	})
	return snapshot
}

func isL7RuleFamily(id string) bool {
	for _, family := range l7RuleFamilyPrefixes {
		if id == family {
			return true
		}
	}
	return false
}

func newL7Runtime(settings L7FabricSettings, revision uint64) *l7Runtime {
	runtime := &l7Runtime{}
	runtime.ptr.Store(buildL7RuntimeSnapshot(settings, revision))
	return runtime
}

func (r *l7Runtime) current() *l7RuntimeSnapshot {
	if r == nil {
		return nil
	}
	snapshot := r.ptr.Load()
	if snapshot == nil {
		return nil
	}
	return snapshot
}

func (r *l7Runtime) publish(snapshot *l7RuntimeSnapshot) {
	if r == nil || snapshot == nil {
		return
	}
	r.ptr.Store(snapshot)
}

// config returns the effective L7 configuration of the active snapshot.
func (r *l7Runtime) config() L7Config {
	snapshot := r.current()
	if snapshot == nil {
		return L7Config{}
	}
	return snapshot.cfg
}

// activeFabric returns the fabric view that is actually live. Restart-class
// keys inside this view keep their boot value until the service restarts.
func (r *l7Runtime) activeFabric() L7FabricSettings {
	snapshot := r.current()
	if snapshot == nil {
		return L7FabricSettings{}
	}
	return cloneL7FabricSettings(snapshot.active)
}

func (s *l7RuntimeSnapshot) sensitivePath(path string) bool {
	if s == nil || path == "" {
		return false
	}
	if _, ok := s.sensitiveExact[path]; ok {
		return true
	}
	for _, root := range s.sensitiveRoots {
		if len(path) > len(root) && strings.HasPrefix(path, root) {
			return true
		}
	}
	return false
}

// overrideFor resolves the operator override that applies to a rule id. An
// exact override always wins over a family override.
func (s *l7RuntimeSnapshot) overrideFor(ruleID string) (L7RuleOverride, bool) {
	if s == nil {
		return L7RuleOverride{}, false
	}
	if override, ok := s.ruleExact[ruleID]; ok {
		return override, true
	}
	for _, family := range s.ruleFamilies {
		if strings.HasPrefix(ruleID, family+".") {
			return s.ruleByFamily[family], true
		}
	}
	return L7RuleOverride{}, false
}

// applyRuleOverrides rewrites findings according to the operator registry and
// returns the findings that remain block-eligible. Disabled rules are removed
// entirely; alert-only rules still contribute to the aggregated alert score
// but can never cross the block threshold on their own.
func (s *l7RuntimeSnapshot) applyRuleOverrides(findings []L7Finding) ([]L7Finding, []L7Finding) {
	if s == nil || len(findings) == 0 {
		return findings, findings
	}
	if len(s.ruleExact) == 0 && len(s.ruleByFamily) == 0 {
		return findings, findings
	}
	kept := make([]L7Finding, 0, len(findings))
	blockable := make([]L7Finding, 0, len(findings))
	for _, finding := range findings {
		override, ok := s.overrideFor(finding.RuleID)
		if !ok {
			kept = append(kept, finding)
			blockable = append(blockable, finding)
			continue
		}
		if !override.Enabled {
			continue
		}
		if override.Score > 0 && override.Score != finding.Score {
			finding.Score = clampScore(override.Score)
		}
		if override.Confidence > 0 && override.Confidence != finding.Confidence {
			finding.Confidence = clampPercent(override.Confidence)
		}
		kept = append(kept, finding)
		if !override.AlertOnly {
			blockable = append(blockable, finding)
		}
	}
	return kept, blockable
}

// normalizeAllowedTLSHostname lowercases and structurally validates one
// administrable TLS domain entry. Wildcards are not accepted: the TLS engine
// matches authoritative hostnames only.
func normalizeAllowedTLSHostname(raw string) (string, error) {
	domain := strings.ToLower(strings.TrimSpace(raw))
	domain = strings.TrimSuffix(domain, ".")
	if domain == "" || len(domain) > 253 {
		return "", fmt.Errorf("l7 TLS allowed domain %q is invalid", raw)
	}
	if strings.ContainsAny(domain, "*/\x00 \t\r\n") {
		return "", fmt.Errorf("l7 TLS allowed domain %q must be an exact hostname", raw)
	}
	labels := strings.Split(domain, ".")
	for _, label := range labels {
		if label == "" || len(label) > 63 {
			return "", fmt.Errorf("l7 TLS allowed domain %q is invalid", raw)
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_' {
				continue
			}
			return "", fmt.Errorf("l7 TLS allowed domain %q contains an invalid character", raw)
		}
	}
	return domain, nil
}

// l7FabricApplyResult reports how a committed revision was projected onto the
// running process.
type l7FabricApplyResult struct {
	RestartRequired bool
	Ja3Reloaded     bool
}

// applyL7FabricSettings projects a committed revision onto the running L7
// components. Restart-class values never activate silently: the published
// snapshot keeps the previously active values for those keys and the module
// reports restart_required until the process is restarted.
func applyL7FabricSettings(engine *L7Engine, settings L7FabricSettings, revision uint64) (l7FabricApplyResult, error) {
	result := l7FabricApplyResult{}
	if engine == nil || engine.live == nil {
		return result, nil
	}
	desired := cloneL7FabricSettings(settings)
	active := engine.live.activeFabric()
	if l7RestartClassChanged(active, desired) {
		result.RestartRequired = true
		desired.Enabled = active.Enabled
		desired.MaxConcurrent = active.MaxConcurrent
		desired.RequestTimeoutMillis = active.RequestTimeoutMillis
		desired.Socket = active.Socket
		desired.MaxTrackedClients = active.MaxTrackedClients
		desired.RequirePeerCredentials = active.RequirePeerCredentials
		desired.AllowedPeerUIDs = append([]uint32(nil), active.AllowedPeerUIDs...)
		desired.AllowedPeerGIDs = append([]uint32(nil), active.AllowedPeerGIDs...)
		desired.SocketGroup = active.SocketGroup
		desired.InlineEnabled = active.InlineEnabled
		desired.InlineSocket = active.InlineSocket
		desired.InlineUpstream = active.InlineUpstream
		desired.TLSEnabled = active.TLSEnabled
	}
	if err := validateL7EngineConfig(desired.toConfig()); err != nil {
		return result, err
	}
	snapshot := buildL7RuntimeSnapshot(desired, revision)
	if snapshot.cfg.TLSEnabled && desired.TLSJA3Reload && snapshot.cfg.TLSJA3File != "" {
		if engine.tls == nil {
			return result, fmt.Errorf("reload l7 TLS fingerprint set: TLS sensor is not active in this process")
		}
		if err := engine.tls.LoadFingerprintFile(snapshot.cfg.TLSJA3File); err != nil {
			return result, fmt.Errorf("reload l7 TLS fingerprint set: %w", err)
		}
		result.Ja3Reloaded = true
	}
	engine.live.publish(snapshot)
	if engine.tls != nil {
		engine.tls.UpdatePolicy(snapshot.cfg.TLSAllowedDomains, snapshot.cfg.TLSFloodThreshold, snapshot.cfg.TLSSNIStrikeThreshold, snapshot.cfg.TLSAntiSpoof)
	}
	return result, nil
}

// l7FabricView is the module view returned by the Fabric Settings API.
type l7FabricView struct {
	Settings L7FabricSettings `json:"settings"`
	Active   L7FabricSettings `json:"active"`
	Rules    []l7RuleView     `json:"rule_registry"`
	Memory   l7MemoryBudget   `json:"memory_budget"`
}

type l7RuleView struct {
	ID            string `json:"id"`
	Category      string `json:"category"`
	Summary       string `json:"summary"`
	Score         int    `json:"score"`
	Confidence    int    `json:"confidence"`
	Enabled       bool   `json:"enabled"`
	AlertOnly     bool   `json:"alert_only"`
	Administrable bool   `json:"administrable"`
}

// l7MemoryBudget is the computed worst-case inspection memory requirement that
// the dashboard shows next to the request limits (plan section 16).
type l7MemoryBudget struct {
	PerInspectionBytes int64 `json:"per_inspection_bytes"`
	AggregateBytes     int64 `json:"aggregate_bytes"`
	LimitBytes         int64 `json:"limit_bytes"`
}

func computeL7MemoryBudget(settings L7FabricSettings) l7MemoryBudget {
	perInspection := int64(settings.MaxEnvelopeBytes) + int64(settings.MaxBodyBytes) + int64(settings.MaxInspectionBytes) + int64(settings.InlineMaxResponseBytes)
	return l7MemoryBudget{
		PerInspectionBytes: perInspection,
		AggregateBytes:     perInspection * int64(settings.MaxConcurrent),
		LimitBytes:         384 << 20,
	}
}

// l7RuleCatalog describes every built-in rule the operator can administer.
func l7RuleCatalog() []l7RuleView {
	entries := make([]l7RuleView, 0, len(supportedL7RuleOverrides))
	for id := range supportedL7RuleOverrides {
		entries = append(entries, l7RuleView{ID: id, Administrable: true})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].ID < entries[j].ID })
	return entries
}

// describeL7RuleCatalog enriches the administrable rule catalogue with the
// compiled built-in detection metadata, so the dashboard never has to
// hard-code rule properties. The pattern set itself is read-only.
func describeL7RuleCatalog() []l7RuleView {
	metadata := make(map[string]l7RuleView, len(l7PatternDefinitions))
	for _, definition := range l7PatternDefinitions {
		metadata[definition.id] = l7RuleView{
			ID: definition.id, Category: definition.category, Summary: definition.summary,
			Score: definition.score, Confidence: definition.confidence, Enabled: true, Administrable: true,
		}
	}
	catalog := l7RuleCatalog()
	out := make([]l7RuleView, 0, len(catalog))
	for _, entry := range catalog {
		if detail, ok := metadata[entry.ID]; ok {
			out = append(out, detail)
			continue
		}
		out = append(out, entry)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// parseServicePortList normalizes a comma-separated service port list. It is
// shared with the settings validation contract.
func parseServicePortList(raw string) ([]uint16, error) {
	fields := strings.Split(raw, ",")
	out := make([]uint16, 0, len(fields))
	for _, field := range fields {
		field = strings.TrimSpace(field)
		if field == "" {
			continue
		}
		value, err := strconv.ParseUint(field, 10, 16)
		if err != nil || value == 0 {
			return nil, fmt.Errorf("invalid service port %q", field)
		}
		out = append(out, uint16(value))
	}
	return out, nil
}
