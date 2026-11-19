// Package webposture is Module A of GeDefense 6.1.0: bounded, exec-free
// discovery of the local web server posture (binary build flags, listening
// sockets, configuration lines) and advisory matching against the observed
// version and its real reachability.
//
// Everything in this package is pure or uses read-only filesystem access. No
// process is started, no shell is spawned and no network connection is made
// except the explicitly configured loopback ALPN probe.
package webposture

import (
	"sort"
	"strings"
	"time"
)

// Server is one discovered web server process.
type Server struct {
	PID       int      `json:"pid"`
	Comm      string   `json:"comm"`
	Binary    string   `json:"binary"`
	Version   string   `json:"version"`
	Modules   []string `json:"modules"`
	OpenSSL   string   `json:"openssl"`
	TLSStatic bool     `json:"tls_static"`
	// Configs is the bounded configuration evidence collected for this server.
	Configs []ConfigHit `json:"configs"`
	// Listen lists the local listening endpoints of the process.
	Listen []string `json:"listen"`
	// ALPN is the loopback probe result. Checked=false means no probe was run.
	ALPN  ALPNResult `json:"alpn"`
	QUIC  bool       `json:"quic"`
	HTTP2 bool       `json:"http2"`
	// Reachable reports whether a non-loopback listener exists.
	Reachable bool          `json:"reachable"`
	Affected  []AdvisoryHit `json:"affected"`
	Posture   string        `json:"posture"`
	fdInaccessible bool
}

// ConfigHit is one operator-meaningful configuration line.
type ConfigHit struct {
	Path      string   `json:"path"`
	Line      int      `json:"line"`
	Directive string   `json:"directive"`
	Flags     []string `json:"flags"`
}

// ALPNResult is the bounded result of the loopback TLS probe.
type ALPNResult struct {
	Checked    bool     `json:"checked"`
	Protocol   string   `json:"protocol"`
	Offered    []string `json:"offered"`
	SNI        string   `json:"sni"`
	TLSVersion string   `json:"tls_version"`
	Cipher     string   `json:"cipher"`
	Error      string   `json:"error"`
}

// AdvisoryHit is one advisory that applies to an observed version and is
// reachable on this host. Non-reachable advisories are not reported as
// "affected": the operator sees exposure only where traffic can arrive.
type AdvisoryHit struct {
	ID         string `json:"id"`
	Severity   string `json:"severity"`
	Summary    string `json:"summary"`
	Workaround string `json:"workaround"`
}

// Summary is the aggregate posture of all discovered servers.
type Summary struct {
	Servers      int    `json:"servers"`
	Exposed      int    `json:"exposed"`
	AffectedCVEs int    `json:"affected_cves"`
	Grade        string `json:"grade"`
	Score        int    `json:"score"`
}

// Options are the administrable scan bounds and switches.
type Options struct {
	// ProbeLoopback enables the localhost ALPN probe.
	ProbeLoopback bool
	// ProbeTimeout bounds one probe dial and handshake.
	ProbeTimeout time.Duration
	// ConfigRoots are the directories searched for nginx/apache configuration.
	ConfigRoots []string
	// ExtraAdvisories are operator-supplied advisory entries (already validated).
	ExtraAdvisories []Advisory
	// MaxServers bounds the number of servers reported.
	MaxServers int
	// MaxConfigFiles/MaxConfigBytes bound the configuration walk.
	MaxConfigFiles int
	MaxConfigBytes int
	// Now makes the scan deterministic in tests.
	Now time.Time
}

// Report is the complete Module A measurement. The main package caches it.
type Report struct {
	GeneratedAt time.Time `json:"generated_at"`
	Scanned     bool      `json:"scanned"`
	Reason      string    `json:"reason"`
	Servers     []Server  `json:"servers"`
	Summary     Summary   `json:"summary"`
	Evidence    []string  `json:"evidence"`
}

// Posture classes reported per server.
const (
	PostureExposed  = "exposed"
	PostureInternal = "internal"
	PostureLoopback = "loopback"
	PostureUnknown  = "unknown"
	PostureNotWeb   = "not-web"
)

// Defaults for the scan bounds. They mirror the administrable defaults.
const (
	DefaultMaxServers     = 32
	DefaultMaxConfigFiles = 2048
	DefaultMaxConfigBytes = 1 << 20
	DefaultProbeTimeout   = 3 * time.Second
	// maxELFBytes bounds the .rodata section read from one binary.
	maxELFBytes = 32 << 20
)

// NormalizeOptions fills the compiled-in bounds for values the caller left at
// zero. Pure: it never reaches the filesystem.
func NormalizeOptions(in Options) Options {
	out := in
	if out.ProbeTimeout <= 0 {
		out.ProbeTimeout = DefaultProbeTimeout
	}
	if out.ProbeTimeout > 10*time.Second {
		out.ProbeTimeout = 10 * time.Second
	}
	if out.MaxServers <= 0 {
		out.MaxServers = DefaultMaxServers
	}
	if out.MaxServers > 128 {
		out.MaxServers = 128
	}
	if out.MaxConfigFiles <= 0 {
		out.MaxConfigFiles = DefaultMaxConfigFiles
	}
	if out.MaxConfigBytes <= 0 {
		out.MaxConfigBytes = DefaultMaxConfigBytes
	}
	if out.Now.IsZero() {
		out.Now = time.Now().UTC()
	}
	roots := make([]string, 0, len(out.ConfigRoots))
	seen := make(map[string]struct{}, len(out.ConfigRoots))
	for _, root := range out.ConfigRoots {
		root = strings.TrimSpace(root)
		if root == "" || !strings.HasPrefix(root, "/") {
			continue
		}
		if _, ok := seen[root]; ok {
			continue
		}
		seen[root] = struct{}{}
		roots = append(roots, root)
	}
	out.ConfigRoots = roots
	return out
}

// ComputeSummary grades the discovered set. A host whose only server is bound
// to loopback is less exposed than one answering on a public address; a server
// with reachable affected CVEs is the worst case and drives the grade down.
func ComputeSummary(servers []Server) Summary {
	summary := Summary{Servers: len(servers)}
	score := 100
	seenService := make(map[string]struct{}, len(servers))
	seenCVEs := make(map[string]struct{}, 8)
	for _, server := range servers {
		switch server.Posture {
		case PostureExposed:
			summary.Exposed++
			summary.AffectedCVEs += len(server.Affected)
		case PostureInternal:
			summary.AffectedCVEs += len(server.Affected)
		}
		// Score unique (binary/comm, version, posture) service units so N prefork
		// workers do not multiply a listener penalty N times down to Grade F.
		serviceKey := strings.TrimSpace(server.Comm) + "|" + strings.TrimSpace(server.Binary) + "|" + strings.TrimSpace(server.Version) + "|" + server.Posture
		if _, dup := seenService[serviceKey]; dup {
			continue
		}
		seenService[serviceKey] = struct{}{}
		switch server.Posture {
		case PostureExposed:
			if len(server.Affected) > 0 {
				score -= 15
			} else {
				score -= 5
			}
			for _, hit := range server.Affected {
				cveKey := serviceKey + "|" + hit.ID
				if _, seen := seenCVEs[cveKey]; seen {
					continue
				}
				seenCVEs[cveKey] = struct{}{}
				switch strings.ToLower(hit.Severity) {
				case "critical":
					score -= 15
				case "high":
					score -= 10
				case "medium":
					score -= 5
				default:
					score -= 2
				}
			}
		case PostureInternal:
			if len(server.Affected) > 0 {
				score -= 8
			} else {
				score -= 2
			}
		}
	}
	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}
	summary.Score = score
	switch {
	case score >= 90:
		summary.Grade = "A"
	case score >= 80:
		summary.Grade = "B"
	case score >= 70:
		summary.Grade = "C"
	case score >= 60:
		summary.Grade = "D"
	default:
		summary.Grade = "F"
	}
	return summary
}

// sortServers orders the report deterministically by binary then PID, so two
// scans of an unchanged host compare byte-for-byte.
func sortServers(servers []Server) {
	sort.Slice(servers, func(i, j int) bool {
		if servers[i].Binary != servers[j].Binary {
			return servers[i].Binary < servers[j].Binary
		}
		return servers[i].PID < servers[j].PID
	})
}

// isLoopbackEndpoint reports whether a listener string is loopback-only.
func isLoopbackEndpoint(endpoint string) bool {
	host := endpoint
	if index := strings.LastIndex(endpoint, ":"); index >= 0 {
		host = endpoint[:index]
	}
	host = strings.Trim(host, "[]")
	switch host {
	case "127.0.0.1", "::1", "localhost":
		return true
	}
	return strings.HasPrefix(host, "127.")
}
