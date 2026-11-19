package webposture

import (
	"bufio"
	"bytes"
	"strconv"
	"strings"
)

// ConfigFile is the bounded parse result of one nginx/apache configuration
// file. Only operator-meaningful directives are retained; the raw content is
// never published.
type ConfigFile struct {
	Path        string
	Product     string
	Hits        []ConfigHit
	ServerNames []string
	ListenPorts []int
	TLS         bool
	HTTP2       bool
	QUIC        bool
}

// maxHitsPerFile bounds how many directives one file contributes.
const maxHitsPerFile = 64

// ParseConfig parses one configuration file. It never executes or resolves
// anything; a malformed line is skipped and counted, not guessed at.
func ParseConfig(path string, data []byte, product string) ConfigFile {
	file := ConfigFile{Path: path, Product: product}
	if len(data) > DefaultMaxConfigBytes {
		data = data[:DefaultMaxConfigBytes]
	}
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 0, 64<<10), 64<<10)
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		if len(file.Hits) >= maxHitsPerFile {
			break
		}
		line := stripConfigComment(scanner.Text())
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		tokens := strings.Fields(line)
		if len(tokens) == 0 {
			continue
		}
		directive := strings.ToLower(tokens[0])
		switch directive {
		case "listen":
			hit, ports, tls, http2, quic, ok := parseListenLine(path, lineNumber, line, tokens)
			if ok {
				file.Hits = append(file.Hits, hit)
				file.ListenPorts = appendUniquePorts(file.ListenPorts, ports...)
				file.TLS = file.TLS || tls
				file.HTTP2 = file.HTTP2 || http2
				file.QUIC = file.QUIC || quic
			}
		case "server_name":
			for _, token := range tokens[1:] {
				token = strings.TrimSuffix(token, ";")
				token = strings.Trim(token, "\"'")
				if token == "" || token == "_" || strings.HasPrefix(token, "~") || strings.HasPrefix(token, "*") {
					// A wildcard/regex server name is not a usable SNI value.
					continue
				}
				file.ServerNames = appendUniqueString(file.ServerNames, token, 8)
			}
		case "ssl_certificate", "ssl", "ssl_protocols", "ssl_ciphers":
			file.TLS = true
			file.Hits = append(file.Hits, ConfigHit{Path: path, Line: lineNumber, Directive: strings.TrimSuffix(line, ";"), Flags: []string{}})
		case "http2", "http3", "quic", "listen_http2":
			// Legacy option blocks; keep the evidence line.
			if directive == "http2" {
				file.HTTP2 = true
			}
			if directive == "http3" || directive == "quic" {
				file.QUIC = true
			}
			file.Hits = append(file.Hits, ConfigHit{Path: path, Line: lineNumber, Directive: strings.TrimSuffix(line, ";"), Flags: []string{}})
		case "<virtualhost", "<directory", "<location":
			// Apache container directives are evidence only.
			file.Hits = append(file.Hits, ConfigHit{Path: path, Line: lineNumber, Directive: strings.TrimSuffix(line, ">") + ">", Flags: []string{}})
		case "sslcertificatefile", "sslengine", "sslprotocol":
			file.TLS = true
			file.Hits = append(file.Hits, ConfigHit{Path: path, Line: lineNumber, Directive: strings.TrimSuffix(line, ";"), Flags: []string{}})
		}
	}
	return file
}

// parseListenLine turns a `listen` directive into the published evidence shape.
// The published directive keeps the address and the recognized flags; the raw
// rest of the line (paths, timeouts) is not published.
func parseListenLine(path string, lineNumber int, line string, tokens []string) (ConfigHit, []int, bool, bool, bool, bool) {
	flags := make([]string, 0, 4)
	var ports []int
	tls, http2, quic := false, false, false
	address := ""
	for index, token := range tokens[1:] {
		token = strings.TrimSuffix(token, ";")
		switch {
		case token == "ssl":
			tls = true
			flags = append(flags, "ssl")
		case token == "http2":
			http2 = true
			flags = append(flags, "http2")
		case token == "http3":
			quic = true
			flags = append(flags, "http3")
		case token == "quic":
			quic = true
			flags = append(flags, "quic")
		case token == "reuseport", token == "default_server", token == "proxy_protocol", token == "ipv6only=on", token == "backlog=511":
			flags = append(flags, token)
		case index == 0 && !strings.ContainsAny(token, "/"):
			address = token
		}
		if port := listenPort(token); port > 0 {
			if !containsPort(ports, port) {
				ports = append(ports, port)
			}
		}
	}
	directive := "listen"
	if address != "" {
		directive = "listen " + address
	}
	// Append the recognized flags to the evidence directive, mirroring the
	// operator-facing example in the blueprint.
	for _, flag := range flags {
		if strings.HasPrefix(flag, "listen") {
			continue
		}
		directive += " " + flag
	}
	return ConfigHit{Path: path, Line: lineNumber, Directive: directive, Flags: flags}, ports, tls, http2, quic, true
}

// listenPort extracts a port from a listen token ("443", "127.0.0.1:443",
// "[::]:443", "unix:/run/nginx.sock" -> 0).
func listenPort(token string) int {
	if strings.HasPrefix(token, "unix:") {
		return 0
	}
	if index := strings.LastIndex(token, ":"); index >= 0 {
		token = token[index+1:]
	}
	token = strings.Trim(token, "[]")
	port, err := strconv.Atoi(token)
	if err != nil || port < 1 || port > 65535 {
		return 0
	}
	return port
}

// stripConfigComment removes a trailing '#' comment outside a quoted string.
func stripConfigComment(line string) string {
	inSingle, inDouble := false, false
	for index, r := range line {
		switch r {
		case '\'':
			if !inDouble {
				inSingle = !inSingle
			}
		case '"':
			if !inSingle {
				inDouble = !inDouble
			}
		case '#':
			if !inSingle && !inDouble {
				return line[:index]
			}
		}
	}
	return line
}

func appendUniquePorts(dst []int, ports ...int) []int {
	for _, port := range ports {
		if !containsPort(dst, port) {
			dst = append(dst, port)
		}
	}
	return dst
}

func containsPort(ports []int, port int) bool {
	for _, existing := range ports {
		if existing == port {
			return true
		}
	}
	return false
}

func appendUniqueString(dst []string, value string, limit int) []string {
	if len(dst) >= limit {
		return dst
	}
	for _, existing := range dst {
		if existing == value {
			return dst
		}
	}
	return append(dst, value)
}
