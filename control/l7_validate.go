// STATUS: DIAMANT VGT SUPREME
package main

import (
	"fmt"
	"net"
	"net/url"
	pathpkg "path"
	"strconv"
	"strings"
)

func safeLocationKey(value string) string {
	value = strings.TrimSpace(value)
	if len(value) > 64 {
		value = value[:64]
	}
	var b strings.Builder
	b.Grow(len(value))
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' || r == '-' || r == '.' {
			b.WriteRune(r)
		} else {
			b.WriteByte('_')
		}
	}
	if b.Len() == 0 {
		return "field"
	}
	return b.String()
}

func safeProcessName(value string) string {
	value = strings.TrimSpace(value)
	if len(value) > 64 {
		value = value[:64]
	}
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return ""
		}
	}
	return value
}

func isHTTPToken(value string, maxLen int) bool {
	if value == "" || len(value) > maxLen {
		return false
	}
	for i := 0; i < len(value); i++ {
		b := value[i]
		if (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9') {
			continue
		}
		switch b {
		case '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~':
			continue
		default:
			return false
		}
	}
	return true
}

func normalizeL7Host(raw string) (string, error) {
	host := strings.TrimSpace(raw)
	if host == "" || len(host) > 255 || strings.ContainsAny(host, "\r\n\x00 /?#@") {
		return "", fmt.Errorf("%w: invalid host", ErrL7InvalidRequest)
	}
	parsed, err := url.Parse("http://" + host)
	if err != nil || parsed.Host != host || parsed.User != nil || parsed.Hostname() == "" {
		return "", fmt.Errorf("%w: invalid host", ErrL7InvalidRequest)
	}
	port := parsed.Port()
	if port != "" {
		value, parseErr := strconv.Atoi(port)
		if parseErr != nil || value < 1 || value > 65535 {
			return "", fmt.Errorf("%w: invalid host port", ErrL7InvalidRequest)
		}
	}
	hostname := strings.ToLower(strings.TrimSuffix(parsed.Hostname(), "."))
	if hostname == "" {
		return "", fmt.Errorf("%w: invalid host", ErrL7InvalidRequest)
	}
	if ip := net.ParseIP(hostname); ip != nil {
		hostname = ip.String()
		if port != "" {
			return net.JoinHostPort(hostname, port), nil
		}
		if strings.Contains(hostname, ":") {
			return "[" + hostname + "]", nil
		}
		return hostname, nil
	}
	if !validDNSHostname(hostname) {
		return "", fmt.Errorf("%w: invalid host name", ErrL7InvalidRequest)
	}
	if port != "" {
		return net.JoinHostPort(hostname, port), nil
	}
	return hostname, nil
}

func canonicalL7RoutePath(decodedPath string, asterisk bool) string {
	if asterisk {
		return "*"
	}
	if decodedPath == "" {
		return "/"
	}
	cleaned := pathpkg.Clean(decodedPath)
	if !strings.HasPrefix(cleaned, "/") {
		cleaned = "/" + cleaned
	}
	return cleaned
}

func validDNSHostname(host string) bool {
	if len(host) > 253 {
		return false
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) < 1 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := 0; i < len(label); i++ {
			b := label[i]
			if (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9') || b == '-' {
				continue
			}
			return false
		}
	}
	return true
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
