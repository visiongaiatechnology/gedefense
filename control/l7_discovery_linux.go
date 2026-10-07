//go:build linux

// STATUS: DIAMANT VGT SUPREME
package main

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Web-surface discovery.
//
// The purpose is narrow and diagnostic: tell the operator whether a web server is
// running on this host and on which ports, so Application Defense can state that
// HTTP traffic exists while L7 is not in its path. Detection is not protection, and
// nothing here may be presented as such.
//
// Everything is read-only and bounded. No file larger than l7DiscoveryMaxLineBytes is
// parsed, the socket tables are capped at l7DiscoveryMaxSockets entries, the process
// walk at l7DiscoveryMaxPIDs, and a read failure degrades to "not detected" rather
// than failing the status path - but never to "detected", because claiming coverage
// that was not observed is the failure mode this whole area exists to prevent.

const (
	l7DiscoveryMaxSockets  = 4096
	l7DiscoveryMaxPIDs     = 8192
	l7DiscoveryMaxLineRead = 512
)

// l7WebServerNames is a closed allowlist. A process is reported only by a name in
// this set, so an unexpected executable can never be labelled a web server.
var l7WebServerNames = map[string]string{
	"nginx":       "nginx",
	"apache2":     "apache",
	"httpd":       "apache",
	"caddy":       "caddy",
	"lighttpd":    "lighttpd",
	"haproxy":     "haproxy",
	"traefik":     "traefik",
	"php-fpm":     "php-fpm",
	"php-fpm8.1":  "php-fpm",
	"php-fpm8.2":  "php-fpm",
	"php-fpm8.3":  "php-fpm",
	"php-fpm8.4":  "php-fpm",
	"openresty":   "openresty",
	"varnishd":    "varnish",
	"envoy":       "envoy",
	"wordpress":   "wordpress",
	"wp-cron.php": "wordpress",
}

// l7WebPorts is the set of listening ports that indicate plain web surface. It is a
// display filter, not a policy: any listening port is reported, these are marked.
var l7WebPorts = map[int]bool{80: true, 443: true, 8080: true, 8443: true, 8000: true, 8888: true}

// WebSurface is what discovery found. It is deliberately separate from coverage: a
// detected server with no L7 attachment is the miswiring case, and the two facts must
// stay distinguishable in every consumer.
type WebSurface struct {
	Servers     []WebServer `json:"servers"`
	WebPorts    []int       `json:"web_ports"`
	AllPorts    []int       `json:"all_ports"`
	Detected    bool        `json:"detected"`
	Scanned     bool        `json:"scanned"`
	Reason      string      `json:"reason,omitempty"`
	Listeners   int         `json:"listeners"`
	ExpectsHTTP bool        `json:"expects_http"`
}

// WebServer is one recognised process, named by the allowlist rather than by the
// executable path, so no filesystem detail reaches a client.
type WebServer struct {
	Name  string `json:"name"`
	Count int    `json:"count"`
}

// discoverWebSurface reads the running system. It never returns an error: a host
// where /proc is unavailable reports scanned=false with a reason, which the UI shows
// as "not scanned" rather than as "nothing running".
func discoverWebSurface() WebSurface {
	surface := WebSurface{}

	ports, ok := listeningPorts()
	if ok {
		surface.Scanned = true
		surface.AllPorts = ports
		for _, port := range ports {
			if l7WebPorts[port] {
				surface.WebPorts = append(surface.WebPorts, port)
			}
		}
		surface.Listeners = len(ports)
	} else {
		surface.Reason = "the kernel socket tables could not be read"
	}

	servers, ok := webServerProcesses()
	if ok && len(servers) > 0 {
		surface.Servers = servers
		surface.Detected = true
	} else if !ok && surface.Reason == "" {
		surface.Reason = "the process table could not be read"
	}

	// A host is treated as expecting HTTP if a web port is listening or a recognised
	// server is running. Both are observations; neither implies L7 sees the traffic.
	if !surface.Detected && len(surface.WebPorts) > 0 {
		surface.ExpectsHTTP = true
	}
	if surface.Detected {
		surface.ExpectsHTTP = true
	}
	return surface
}

// listeningPorts parses the IPv4 and IPv6 socket tables for sockets in LISTEN state.
func listeningPorts() ([]int, bool) {
	seen := make(map[int]bool, 16)
	anyRead := false
	for _, name := range []string{"tcp", "tcp6"} {
		file, err := os.Open(filepath.Join("/proc/net", name))
		if err != nil {
			continue
		}
		anyRead = true
		scanner := bufio.NewScanner(file)
		scanner.Buffer(make([]byte, 0, l7DiscoveryMaxLineRead), l7DiscoveryMaxLineRead)
		first := true
		count := 0
		for scanner.Scan() && count < l7DiscoveryMaxSockets {
			if first {
				// Header row.
				first = false
				continue
			}
			count++
			fields := strings.Fields(scanner.Text())
			// sl local_address rem_address st ...
			if len(fields) < 4 || fields[3] != "0A" {
				continue
			}
			colon := strings.LastIndex(fields[1], ":")
			if colon < 0 || colon+1 >= len(fields[1]) {
				continue
			}
			port, err := strconv.ParseInt(fields[1][colon+1:], 16, 32)
			if err != nil || port <= 0 || port > 65535 {
				continue
			}
			seen[int(port)] = true
		}
		_ = file.Close()
	}
	if !anyRead {
		return nil, false
	}
	return sortedPorts(seen), true
}

func sortedPorts(set map[int]bool) []int {
	out := make([]int, 0, len(set))
	for port := range set {
		out = append(out, port)
	}
	// Insertion sort over a bounded set: the socket count is capped and this avoids
	// pulling in a sort dependency for a few dozen entries.
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j] < out[j-1]; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}

// webServerProcesses walks the process table and counts recognised server names.
func webServerProcesses() ([]WebServer, bool) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, false
	}
	counts := make(map[string]int, 8)
	visited := 0
	for _, entry := range entries {
		if visited >= l7DiscoveryMaxPIDs {
			break
		}
		if !entry.IsDir() {
			continue
		}
		pid := entry.Name()
		if pid == "" || pid[0] < '0' || pid[0] > '9' {
			continue
		}
		visited++
		raw, err := os.ReadFile(filepath.Join("/proc", pid, "comm"))
		if err != nil {
			continue
		}
		comm := strings.TrimSpace(string(raw))
		if len(comm) > l7DiscoveryMaxLineRead {
			comm = comm[:l7DiscoveryMaxLineRead]
		}
		if label, known := l7WebServerNames[strings.ToLower(comm)]; known {
			counts[label]++
		}
	}
	out := make([]WebServer, 0, len(counts))
	for name, count := range counts {
		out = append(out, WebServer{Name: name, Count: count})
	}
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j].Name < out[j-1].Name; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out, true
}

// describeWebSurface renders the finding as one operator sentence. It is used by the
// status projection so the reason an operator reads and the reason written to the log
// are the same text.
func describeWebSurface(surface WebSurface, attached bool) string {
	if !surface.Scanned {
		return "web surface not scanned: " + surface.Reason
	}
	if !surface.ExpectsHTTP {
		return "no web server or web port detected on this host"
	}
	if attached {
		return fmt.Sprintf("web surface detected (%d listening port(s)) and an L7 traffic path is attached", surface.Listeners)
	}
	return fmt.Sprintf("web surface detected (%d listening port(s)) but no L7 traffic path is attached; HTTP traffic is not being inspected", surface.Listeners)
}
