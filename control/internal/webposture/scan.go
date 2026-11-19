package webposture

import (
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// maxScannedFiles bounds how many configuration files are read per scan.
const maxScannedFiles = DefaultMaxConfigFiles

// Scan performs one complete Module A measurement. It is the only entry point
// the control plane uses; every bound is applied here so a hostile filesystem
// cannot stall the caller.
func Scan(ctx context.Context, opts Options) Report {
	options := NormalizeOptions(opts)
	report := Report{GeneratedAt: options.Now.UTC(), Servers: []Server{}, Evidence: []string{}}
	if ctx == nil {
		ctx = context.Background()
	}
	servers, discoveryEvidence, reason := discoverServers(ctx, options.MaxServers)
	report.Evidence = append(report.Evidence, discoveryEvidence...)
	if reason != "" {
		report.Evidence = append(report.Evidence, "discovery: "+reason)
	}
	nginxConfigs, apacheConfigs, configEvidence, configReason := walkConfigRoots(options)
	report.Evidence = append(report.Evidence, configEvidence...)
	if configReason != "" {
		report.Evidence = append(report.Evidence, "config: "+configReason)
	}
	for index := range servers {
		server := &servers[index]
		lower := strings.ToLower(server.Comm + " " + server.Binary)
		if strings.Contains(lower, "nginx") {
			server.Configs = append(server.Configs, configHits(nginxConfigs)...)
			mergeConfigFacts(server, nginxConfigs)
			fillListenersFromProcNet(server, nginxConfigs)
		} else if strings.Contains(lower, "apache") || strings.Contains(lower, "httpd") {
			server.Configs = append(server.Configs, configHits(apacheConfigs)...)
			mergeConfigFacts(server, apacheConfigs)
			fillListenersFromProcNet(server, apacheConfigs)
		}
		server.Reachable = anyReachable(server.Listen)
		server.Posture = classifyPosture(*server)
		if server.ALPN.Offered == nil {
			server.ALPN.Offered = []string{}
		}
		if options.ProbeLoopback {
			probeServer(ctx, options, server)
		}
		server.Affected = MatchAdvisories(*server, append(Catalogue(), options.ExtraAdvisories...))
	}
	sortServers(servers)
	report.Servers = servers
	report.Summary = ComputeSummary(servers)
	report.Scanned = true
	if len(servers) == 0 && len(nginxConfigs) == 0 && len(apacheConfigs) == 0 {
		report.Evidence = append(report.Evidence, "no web server process and no configuration file was found in the configured roots")
	}
	return report
}

// probeServer runs at most one loopback probe for the server and attaches the
// result. The probe target is the first listening TLS port, or 443/8443 when the
// server listens there, or the first listening port as a last resort.
func probeServer(ctx context.Context, options Options, server *Server) {
	port := probePort(*server)
	if port == 0 {
		server.ALPN = ALPNResult{Checked: false, Offered: []string{}, Error: "no listening port to probe"}
		return
	}
	sni := "localhost"
	server.ALPN = ProbeALPN(ctx, port, sni, options.ProbeTimeout)
	if server.ALPN.Protocol == "h2" {
		server.HTTP2 = true
	}
}

// probePort chooses the loopback port for one probe.
func probePort(server Server) int {
	ports := make([]int, 0, len(server.Listen))
	for _, endpoint := range server.Listen {
		index := strings.LastIndex(endpoint, ":")
		if index < 0 {
			continue
		}
		port := 0
		for _, r := range endpoint[index+1:] {
			if r < '0' || r > '9' {
				port = 0
				break
			}
			port = port*10 + int(r-'0')
		}
		if port > 0 && port <= 65535 {
			ports = append(ports, port)
		}
	}
	for _, preferred := range []int{443, 8443} {
		for _, port := range ports {
			if port == preferred {
				return port
			}
		}
	}
	if len(ports) > 0 {
		return ports[0]
	}
	return 0
}

// classifyPosture derives the operator-facing posture class from the listeners.
func classifyPosture(server Server) string {
	if len(server.Listen) == 0 {
		return PostureUnknown
	}
	reachable := false
	public := false
	for _, endpoint := range server.Listen {
		if isLoopbackEndpoint(endpoint) {
			continue
		}
		reachable = true
		if !isPrivateEndpoint(endpoint) {
			public = true
		}
	}
	switch {
	case public:
		return PostureExposed
	case reachable:
		return PostureInternal
	default:
		return PostureLoopback
	}
}

// isPrivateEndpoint reports whether a listener host is a private/link-local
// address. A private listener is still reachable from the local network but is
// not internet-facing, which the grade distinguishes. An unspecified wildcard
// address (0.0.0.0 / ::) is NOT private: it accepts traffic on every interface
// and is the most exposed listener there is.
func isPrivateEndpoint(endpoint string) bool {
	host := endpoint
	if index := strings.LastIndex(endpoint, ":"); index >= 0 {
		host = endpoint[:index]
	}
	host = strings.Trim(host, "[]")
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	return addr.IsPrivate() || addr.IsLoopback() || addr.IsLinkLocalUnicast()
}

// anyReachable reports whether at least one listener is not loopback-only.
func anyReachable(listeners []string) bool {
	for _, endpoint := range listeners {
		if !isLoopbackEndpoint(endpoint) {
			return true
		}
	}
	return false
}

func configHits(files []ConfigFile) []ConfigHit {
	out := make([]ConfigHit, 0, 16)
	for _, file := range files {
		for _, hit := range file.Hits {
			if len(out) >= 64 {
				return out
			}
			out = append(out, hit)
		}
	}
	return out
}

// mergeConfigFacts folds build/config evidence into the server record.
func mergeConfigFacts(server *Server, files []ConfigFile) {
	for _, file := range files {
		if file.TLS {
			server.TLSStatic = server.TLSStatic || strings.Contains(strings.ToLower(server.OpenSSL), "openssl")
		}
		if file.HTTP2 {
			server.HTTP2 = true
		}
		if file.QUIC {
			server.QUIC = true
		}
	}
}

// walkConfigRoots reads the configured roots with bounded recursion. Symlinks are
// never followed: a link out of the root would let a local process feed the
// posture report with arbitrary files.
func walkConfigRoots(options Options) ([]ConfigFile, []ConfigFile, []string, string) {
	var nginxFiles, apacheFiles []ConfigFile
	evidence := make([]string, 0, 8)
	filesRead := 0
	bytesRead := 0
	reason := ""
	for _, root := range options.ConfigRoots {
		if filesRead >= maxScannedFiles || bytesRead >= options.MaxConfigBytes*8 {
			reason = "configuration walk budget exhausted"
			break
		}
		info, err := os.Lstat(root)
		if err != nil || !info.IsDir() {
			continue
		}
		reason = walkRoot(root, options, &nginxFiles, &apacheFiles, &filesRead, &bytesRead, &evidence)
		if reason != "" {
			break
		}
	}
	evidence = append(evidence, "configuration roots searched: "+strings.Join(options.ConfigRoots, ", "))
	return nginxFiles, apacheFiles, evidence, reason
}

func walkRoot(root string, options Options, nginxFiles, apacheFiles *[]ConfigFile, filesRead, bytesRead *int, evidence *[]string) string {
	stack := []string{root}
	for len(stack) > 0 {
		if *filesRead >= maxScannedFiles || *bytesRead >= options.MaxConfigBytes*8 {
			return "configuration walk budget exhausted"
		}
		dir := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		if len(entries) > 512 {
			entries = entries[:512]
		}
		for _, entry := range entries {
			path := filepath.Join(dir, entry.Name())
			if entry.Type()&os.ModeSymlink != 0 {
				continue
			}
			if entry.IsDir() {
				if len(stack) < 64 {
					stack = append(stack, path)
				}
				continue
			}
			if !entry.Type().IsRegular() {
				continue
			}
			name := strings.ToLower(entry.Name())
			if !strings.HasSuffix(name, ".conf") && !strings.HasSuffix(name, ".vhost") {
				continue
			}
			if *filesRead >= maxScannedFiles {
				return "configuration walk budget exhausted"
			}
			data, readErr := readBoundedFile(path, options.MaxConfigBytes)
			if readErr != nil {
				continue
			}
			*filesRead++
			*bytesRead += len(data)
			product := "nginx"
			if strings.Contains(path, "apache") || strings.Contains(path, "httpd") {
				product = "apache"
			}
			file := ParseConfig(path, data, product)
			if product == "apache" {
				*apacheFiles = append(*apacheFiles, file)
			} else {
				*nginxFiles = append(*nginxFiles, file)
			}
			if len(*evidence) < 8 {
				*evidence = append(*evidence, path)
			}
		}
	}
	return ""
}

// readBoundedFile reads at most limit bytes from a regular file. It refuses
// non-regular files and never follows a symlink.
func readBoundedFile(path string, limit int) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return nil, os.ErrInvalid
	}
	if limit <= 0 || limit > DefaultMaxConfigBytes {
		limit = DefaultMaxConfigBytes
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	buffer := make([]byte, 0, 64<<10)
	chunk := make([]byte, 64<<10)
	for len(buffer) < limit {
		remaining := limit - len(buffer)
		if remaining > len(chunk) {
			remaining = len(chunk)
		}
		read, readErr := file.Read(chunk[:remaining])
		buffer = append(buffer, chunk[:read]...)
		if readErr != nil {
			break
		}
		if read == 0 {
			break
		}
	}
	return buffer, nil
}

// sortedPorts is a small helper used by tests and the report projection.
func sortedPorts(ports []int) []int {
	out := append([]int(nil), ports...)
	sort.Ints(out)
	return out
}
