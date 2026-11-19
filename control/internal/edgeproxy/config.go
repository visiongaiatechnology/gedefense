package edgeproxy

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"path"
	"strings"
)

// Config is the Module E edge terminator configuration. It is derived from the
// persisted fabric namespace of the same name; the package never reads files or
// settings on its own.
type Config struct {
	Enabled              bool
	Listen               string
	Upstream             string
	CertFile             string
	KeyFile              string
	MinTLSVersion        string
	MaxConcurrentStreams int
	MaxHeaderBytes       int
	MaxBodyBytes         int64
	IdleTimeoutSeconds   int
	RequestTimeoutSecond int
	AllowedMethods       []string
	WAFInline            bool
	RateLimitPerMinute   int
}

// DefaultConfig mirrors the fabric defaults: disabled, loopback only.
func DefaultConfig() Config {
	return Config{
		Listen:               "127.0.0.1:8443",
		Upstream:             "http://127.0.0.1:8080",
		MinTLSVersion:        "TLS1.3",
		MaxConcurrentStreams: 128,
		MaxHeaderBytes:       32 << 10,
		MaxBodyBytes:         8 << 20,
		IdleTimeoutSeconds:   60,
		RequestTimeoutSecond: 30,
		AllowedMethods:       []string{"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"},
		WAFInline:            true,
		RateLimitPerMinute:   600,
	}
}

// Validate enforces every bound the server and the dashboard rely on. It is
// intentionally strict about the listen address: the phase-1 terminator is a
// loopback edge in front of the local web server, never a public listener.
func (c Config) Validate() error {
	host, port, err := net.SplitHostPort(strings.TrimSpace(c.Listen))
	if err != nil {
		return fmt.Errorf("listen address: %w", err)
	}
	if port == "" {
		return errors.New("listen address requires a port")
	}
	if !loopbackHost(host) {
		return errors.New("listen address must be a loopback address")
	}
	upstream, err := url.Parse(strings.TrimSpace(c.Upstream))
	if err != nil {
		return fmt.Errorf("upstream: %w", err)
	}
	switch upstream.Scheme {
	case "http":
		if upstream.Host == "" || !loopbackHost(upstream.Hostname()) {
			return errors.New("http upstream must target loopback")
		}
		if upstream.Path != "" && upstream.Path != "/" {
			return errors.New("http upstream must not carry a path")
		}
	case "unix":
		if upstream.Path == "" || !strings.HasPrefix(upstream.Path, "/") {
			return errors.New("unix upstream requires an absolute socket path")
		}
		if path.Clean(upstream.Path) != upstream.Path || strings.Contains(upstream.Path, "..") {
			return errors.New("unix upstream path must be clean and traversal-free")
		}
	default:
		return errors.New("upstream scheme must be http or unix")
	}
	if c.MaxConcurrentStreams < 16 || c.MaxConcurrentStreams > 1024 {
		return errors.New("max concurrent streams must be 16..1024")
	}
	if c.MaxHeaderBytes < 8<<10 || c.MaxHeaderBytes > 128<<10 {
		return errors.New("max header bytes must be 8192..131072")
	}
	if c.MaxBodyBytes < 64<<10 || c.MaxBodyBytes > 64<<20 {
		return errors.New("max body bytes must be 65536..67108864")
	}
	if c.IdleTimeoutSeconds < 5 || c.IdleTimeoutSeconds > 600 {
		return errors.New("idle timeout must be 5..600 seconds")
	}
	if c.RequestTimeoutSecond < 5 || c.RequestTimeoutSecond > 300 {
		return errors.New("request timeout must be 5..300 seconds")
	}
	if c.RateLimitPerMinute < 10 || c.RateLimitPerMinute > 100000 {
		return errors.New("rate limit must be 10..100000 requests per minute")
	}
	switch strings.ToUpper(strings.TrimSpace(c.MinTLSVersion)) {
	case "TLS1.2", "TLS1.3":
	default:
		return errors.New("min TLS version must be TLS1.2 or TLS1.3")
	}
	if len(c.AllowedMethods) == 0 {
		return errors.New("at least one allowed method is required")
	}
	for _, method := range c.AllowedMethods {
		if !validMethod(method) {
			return fmt.Errorf("invalid allowed method %q", method)
		}
	}
	if c.Enabled && (strings.TrimSpace(c.CertFile) == "" || strings.TrimSpace(c.KeyFile) == "") {
		return errors.New("enabled edge proxy requires a certificate and key file")
	}
	return nil
}

func loopbackHost(host string) bool {
	trimmed := strings.Trim(strings.ToLower(strings.TrimSpace(host)), "[]")
	if trimmed == "localhost" {
		return true
	}
	ip := net.ParseIP(trimmed)
	return ip != nil && ip.IsLoopback()
}

func validMethod(method string) bool {
	if method == "" || len(method) > 16 {
		return false
	}
	for index := 0; index < len(method); index++ {
		character := method[index]
		if (character < 'A' || character > 'Z') && character != '-' {
			return false
		}
	}
	return true
}

// Normalize canonicalises the method list and TLS selector before the config is
// stored in the manager, so status and restart act on identical values.
func (c Config) Normalize() Config {
	out := c
	out.Listen = strings.TrimSpace(c.Listen)
	out.Upstream = strings.TrimSpace(c.Upstream)
	out.CertFile = strings.TrimSpace(c.CertFile)
	out.KeyFile = strings.TrimSpace(c.KeyFile)
	out.MinTLSVersion = strings.ToUpper(strings.TrimSpace(c.MinTLSVersion))
	out.AllowedMethods = make([]string, 0, len(c.AllowedMethods))
	seen := make(map[string]struct{}, len(c.AllowedMethods))
	for _, method := range c.AllowedMethods {
		method = strings.ToUpper(strings.TrimSpace(method))
		if method == "" {
			continue
		}
		if _, ok := seen[method]; ok {
			continue
		}
		seen[method] = struct{}{}
		out.AllowedMethods = append(out.AllowedMethods, method)
	}
	return out
}
