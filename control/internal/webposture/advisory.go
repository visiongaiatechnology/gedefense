package webposture

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// Advisory is one version-range rule from the compiled catalogue or from the
// operator-supplied `extra_advisories_json` setting.
//
// The catalogue is deliberately small and explicit: this is a posture report,
// not a CVE feed. A version range that cannot be parsed never matches, and an
// advisory only becomes an "affected" hit when the host is actually reachable
// for the affected feature (see MatchAdvisories).
type Advisory struct {
	ID      string `json:"id"`
	Product string `json:"product"`
	// MinVersion/MaxVersion are inclusive bounds. Empty means unbounded.
	// Versions are compared component-wise as dotted numbers.
	MinVersion string `json:"min_version"`
	MaxVersion string `json:"max_version"`
	Severity   string `json:"severity"`
	Summary    string `json:"summary"`
	Workaround string `json:"workaround"`
	// RequiresALPN names the negotiated protocol the advisory depends on
	// ("h2", "http/1.1", "quic" or empty). Empty means no protocol gate.
	RequiresALPN string `json:"requires_alpn"`
	// RequiresReachable requires a non-loopback listener before the hit counts
	// as exposure.
	RequiresReachable bool `json:"requires_reachable"`
	// RequiresHTTP2 requires that the server advertises HTTP/2 support.
	RequiresHTTP2 bool `json:"requires_http2"`
	// RequiresQUIC requires that the server advertises QUIC support.
	RequiresQUIC bool `json:"requires_quic"`
}

// catalogueAdvisories is the shipped advisory catalogue. It covers the three
// CVEs named in the 6.1.0 mission plus the OpenSSL signature used by the
// version-range unit test; operators add their own through settings.
var catalogueAdvisories = []Advisory{
	{
		ID: "CVE-2026-123007", Product: "nginx",
		MinVersion: "1.29.0", MaxVersion: "1.30.6",
		Severity:     "high",
		Summary:      "HTTP/2 request smuggling through a crafted header block on nginx 1.29.x",
		Workaround:   "http2 off / patch >= 1.30.7",
		RequiresALPN: "h2", RequiresHTTP2: true,
	},
	{
		ID: "CVE-2026-123633", Product: "nginx",
		MinVersion: "1.28.0", MaxVersion: "1.30.9",
		Severity:     "medium",
		Summary:      "QUIC/HTTP3 stream reset handling can leak request context between streams",
		Workaround:   "disable http_v3 or patch >= 1.31.0",
		RequiresALPN: "quic", RequiresQUIC: true,
	},
	{
		ID: "CVE-2026-121810", Product: "openssl",
		MinVersion: "3.0.0", MaxVersion: "3.5.2",
		Severity:          "critical",
		Summary:           "TLS 1.3 session ticket handling allows a stale key to encrypt a resumed session",
		Workaround:        "upgrade OpenSSL to >= 3.5.3 or disable session tickets on the listening server",
		RequiresReachable: true,
	},
	{
		ID: "CVE-2025-1974", Product: "nginx",
		MinVersion: "1.0.0", MaxVersion: "1.27.4",
		Severity:      "high",
		Summary:       "A memory disclosure in the HTTP/1.1 chunked body parser can be triggered by a crafted request",
		Workaround:    "patch >= 1.27.5",
		RequiresHTTP2: true,
	},
}

// Catalogue returns a copy of the compiled-in advisory catalogue.
func Catalogue() []Advisory {
	out := make([]Advisory, len(catalogueAdvisories))
	copy(out, catalogueAdvisories)
	return out
}

// ParseExtraAdvisories decodes the operator-supplied JSON array. It is strict:
// unknown fields are refused so a typo cannot silently weaken an advisory.
func ParseExtraAdvisories(raw json.RawMessage) ([]Advisory, error) {
	if len(raw) == 0 || string(raw) == "null" || string(raw) == "[]" {
		return nil, nil
	}
	var entries []Advisory
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&entries); err != nil {
		return nil, fmt.Errorf("extra advisories are not a valid JSON array: %w", err)
	}
	if len(entries) > 128 {
		return nil, errors.New("extra advisories exceed the 128-entry bound")
	}
	for index := range entries {
		entry := &entries[index]
		entry.ID = strings.TrimSpace(entry.ID)
		entry.Product = strings.ToLower(strings.TrimSpace(entry.Product))
		entry.Severity = strings.ToLower(strings.TrimSpace(entry.Severity))
		entry.Summary = strings.TrimSpace(entry.Summary)
		entry.Workaround = strings.TrimSpace(entry.Workaround)
		if !validAdvisoryID(entry.ID) {
			return nil, fmt.Errorf("extra advisory %d has an invalid id", index)
		}
		switch entry.Product {
		case "nginx", "openssl", "apache", "httpd":
		default:
			return nil, fmt.Errorf("extra advisory %s has an unsupported product", entry.ID)
		}
		switch entry.Severity {
		case "low", "medium", "high", "critical":
		default:
			return nil, fmt.Errorf("extra advisory %s has an invalid severity", entry.ID)
		}
		if entry.Summary == "" || entry.Summary == "null" || len(entry.Summary) > 300 {
			return nil, fmt.Errorf("extra advisory %s summary must contain 1-300 characters", entry.ID)
		}
		if entry.MinVersion != "" && !validVersion(entry.MinVersion) {
			return nil, fmt.Errorf("extra advisory %s min_version is invalid", entry.ID)
		}
		if entry.MaxVersion != "" && !validVersion(entry.MaxVersion) {
			return nil, fmt.Errorf("extra advisory %s max_version is invalid", entry.ID)
		}
	}
	return entries, nil
}

func validAdvisoryID(id string) bool {
	if id == "" || len(id) > 64 {
		return false
	}
	for _, r := range id {
		switch {
		case r >= 'A' && r <= 'Z', r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-', r == '.', r == '_':
		default:
			return false
		}
	}
	return true
}

func validVersion(version string) bool {
	parts := strings.Split(version, ".")
	if len(parts) == 0 || len(parts) > 5 {
		return false
	}
	for _, part := range parts {
		if part == "" || len(part) > 6 {
			return false
		}
		if _, err := strconv.Atoi(part); err != nil {
			return false
		}
	}
	return true
}

// CompareVersions compares two dotted numeric versions component-wise. Missing
// components count as zero. It returns -1, 0 or 1.
func CompareVersions(left, right string) (int, error) {
	if !validVersion(left) || !validVersion(right) {
		return 0, fmt.Errorf("invalid version comparison %q / %q", left, right)
	}
	leftParts := strings.Split(left, ".")
	rightParts := strings.Split(right, ".")
	count := len(leftParts)
	if len(rightParts) > count {
		count = len(rightParts)
	}
	for index := 0; index < count; index++ {
		leftValue, rightValue := 0, 0
		if index < len(leftParts) {
			leftValue, _ = strconv.Atoi(leftParts[index])
		}
		if index < len(rightParts) {
			rightValue, _ = strconv.Atoi(rightParts[index])
		}
		switch {
		case leftValue < rightValue:
			return -1, nil
		case leftValue > rightValue:
			return 1, nil
		}
	}
	return 0, nil
}

// versionInRange reports whether version lies inside the inclusive advisory
// range. An unparseable range or version never matches: a malformed catalogue
// entry must not turn into a fake finding.
func versionInRange(version string, advisory Advisory) bool {
	if version == "" {
		return false
	}
	if advisory.MinVersion != "" {
		cmp, err := CompareVersions(version, advisory.MinVersion)
		if err != nil || cmp < 0 {
			return false
		}
	}
	if advisory.MaxVersion != "" {
		cmp, err := CompareVersions(version, advisory.MaxVersion)
		if err != nil || cmp > 0 {
			return false
		}
	}
	return true
}

// MatchAdvisories returns the advisory hits for one observed server under the
// "affected only when reachable" contract:
//
//   - a version-range match is necessary but not sufficient;
//   - an advisory that names a protocol is only a hit when that protocol is
//     actually offered by the server;
//   - an advisory that requires HTTP/2 or QUIC is only a hit when the build
//     advertises it;
//   - an advisory that requires reachability is only a hit when a non-loopback
//     listener exists.
//
// This is the rule the mission's "affected only when reachable" test locks in:
// a patched-but-unreachable server is not "exposed", and an h2 CVE on a
// loopback-only HTTP/1.1 server is not an exposure either.
func MatchAdvisories(server Server, catalogue []Advisory) []AdvisoryHit {
	hits := make([]AdvisoryHit, 0)
	for _, advisory := range catalogue {
		if !strings.Contains(strings.ToLower(server.Comm), advisory.Product) &&
			!strings.Contains(strings.ToLower(server.Binary), advisory.Product) &&
			advisory.Product != "openssl" {
			continue
		}
		observed := productVersion(server, advisory.Product)
		if !versionInRange(observed, advisory) {
			continue
		}
		if advisory.RequiresHTTP2 && !server.HTTP2 {
			continue
		}
		if advisory.RequiresQUIC && !server.QUIC {
			continue
		}
		if advisory.RequiresReachable && !server.Reachable {
			continue
		}
		if advisory.RequiresALPN != "" && !serverOffersProtocol(server, advisory.RequiresALPN) {
			continue
		}
		hits = append(hits, AdvisoryHit{
			ID: advisory.ID, Severity: advisory.Severity, Summary: advisory.Summary, Workaround: advisory.Workaround,
		})
	}
	return hits
}

// productVersion resolves the version string the advisory range applies to.
func productVersion(server Server, product string) string {
	switch product {
	case "openssl":
		return opensslVersion(server.OpenSSL)
	default:
		return server.Version
	}
}

// opensslVersion extracts "3.5.2" from "OpenSSL 3.5.2 5 Jul 2025".
func opensslVersion(raw string) string {
	fields := strings.Fields(raw)
	for _, field := range fields {
		candidate := strings.TrimSuffix(field, ",")
		if validVersion(candidate) {
			return candidate
		}
	}
	return ""
}

// serverOffersProtocol reports whether the negotiated/offered protocol matches.
func serverOffersProtocol(server Server, protocol string) bool {
	if protocol == "quic" {
		return server.QUIC
	}
	if server.ALPN.Protocol == protocol {
		return true
	}
	for _, offered := range server.ALPN.Offered {
		if offered == protocol {
			return true
		}
	}
	if protocol == "h2" {
		return server.HTTP2
	}
	return false
}
