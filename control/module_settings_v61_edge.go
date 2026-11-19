// STATUS: DIAMANT VGT SUPREME
package main

// GeDefense 6.1.0 edge proxy namespace (Module E settings). The runtime engine
// is owned by control/edge_proxy.go; this file only provides the settings
// contract the engine consumes, exactly like every other additive namespace.
//
// The object is inert by default: Enabled=false means no listener is opened.

import (
	"errors"
	"net"
	"net/netip"
	"net/url"
	"strings"
)

const edgeProxyMigrationNote = "edge_proxy namespace added with enabled=false and a loopback listener (127.0.0.1:8443): no listener is opened and host behaviour is unchanged until an operator enables it (docs/V6.1.0-BLUEPRINT.md §3.3, §4E)"

// EdgeProxyFabricSettings is the Module E operator namespace.
type EdgeProxyFabricSettings struct {
	Enabled               bool     `json:"enabled"`
	Listen                string   `json:"listen"`
	Upstream              string   `json:"upstream"`
	CertFile              string   `json:"cert_file"`
	KeyFile               string   `json:"key_file"`
	MinTLSVersion         string   `json:"min_tls_version"`
	MaxConcurrentStreams  int      `json:"max_concurrent_streams"`
	MaxHeaderBytes        int      `json:"max_header_bytes"`
	MaxBodyBytes          int      `json:"max_body_bytes"`
	IdleTimeoutSeconds    int      `json:"idle_timeout_seconds"`
	RequestTimeoutSeconds int      `json:"request_timeout_seconds"`
	AllowedMethods        []string `json:"allowed_methods"`
	WAFInline             bool     `json:"waf_inline"`
	RateLimitPerMinute    int      `json:"rate_limit_per_minute"`
}

// edgeProxyAllowedMethods is the closed method vocabulary.
var edgeProxyAllowedMethods = []string{"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}

func defaultEdgeProxyFabricSettings() EdgeProxyFabricSettings {
	return EdgeProxyFabricSettings{
		Enabled:               false,
		Listen:                "127.0.0.1:8443",
		Upstream:              "http://127.0.0.1:8080",
		CertFile:              "",
		KeyFile:               "",
		MinTLSVersion:         "TLS1.3",
		MaxConcurrentStreams:  128,
		MaxHeaderBytes:        32768,
		MaxBodyBytes:          8388608,
		IdleTimeoutSeconds:    60,
		RequestTimeoutSeconds: 30,
		AllowedMethods:        append([]string(nil), edgeProxyAllowedMethods...),
		WAFInline:             true,
		RateLimitPerMinute:    600,
	}
}

func cloneEdgeProxyFabricSettings(in EdgeProxyFabricSettings) EdgeProxyFabricSettings {
	out := in
	out.AllowedMethods = append(make([]string, 0, len(in.AllowedMethods)), in.AllowedMethods...)
	return out
}

func effectiveEdgeProxySettings(settings RuntimeSettings) EdgeProxyFabricSettings {
	if settings.EdgeProxy != nil {
		return cloneEdgeProxyFabricSettings(*settings.EdgeProxy)
	}
	return defaultEdgeProxyFabricSettings()
}

func edgeProxyDefaults(defaults RuntimeSettings) EdgeProxyFabricSettings {
	if defaults.EdgeProxy != nil {
		return cloneEdgeProxyFabricSettings(*defaults.EdgeProxy)
	}
	return defaultEdgeProxyFabricSettings()
}

func validateEdgeProxyFabricSettings(in *EdgeProxyFabricSettings) error {
	if in == nil {
		return errors.New("edge proxy settings are required")
	}
	if err := validateLoopbackListen(in.Listen); err != nil {
		return err
	}
	if err := validateLoopbackUpstream(in.Upstream); err != nil {
		return err
	}
	for name, path := range map[string]string{"cert_file": in.CertFile, "key_file": in.KeyFile} {
		if path == "" {
			continue
		}
		if !strings.HasPrefix(path, "/") || strings.ContainsAny(path, "\x00\r\n") || len(path) > 1024 {
			return errors.New("edge proxy " + name + " must be an absolute single-line path")
		}
	}
	if (in.CertFile == "") != (in.KeyFile == "") {
		return errors.New("edge proxy cert_file and key_file must be configured together")
	}
	switch in.MinTLSVersion {
	case "TLS1.2", "TLS1.3":
	default:
		return errors.New("edge proxy min_tls_version must be TLS1.2 or TLS1.3")
	}
	if in.MaxConcurrentStreams < 16 || in.MaxConcurrentStreams > 1024 {
		return errors.New("edge proxy max_concurrent_streams must be between 16 and 1024")
	}
	if in.MaxHeaderBytes < 8192 || in.MaxHeaderBytes > 131072 {
		return errors.New("edge proxy max_header_bytes must be between 8192 and 131072")
	}
	if in.MaxBodyBytes < 65536 || in.MaxBodyBytes > 67108864 {
		return errors.New("edge proxy max_body_bytes must be between 65536 and 67108864")
	}
	if in.IdleTimeoutSeconds < 5 || in.IdleTimeoutSeconds > 600 {
		return errors.New("edge proxy idle_timeout_seconds must be between 5 and 600")
	}
	if in.RequestTimeoutSeconds < 5 || in.RequestTimeoutSeconds > 300 {
		return errors.New("edge proxy request_timeout_seconds must be between 5 and 300")
	}
	if in.RateLimitPerMinute < 10 || in.RateLimitPerMinute > 100000 {
		return errors.New("edge proxy rate_limit_per_minute must be between 10 and 100000")
	}
	if len(in.AllowedMethods) == 0 || len(in.AllowedMethods) > len(edgeProxyAllowedMethods) {
		return errors.New("edge proxy allowed_methods must contain between 1 and 7 methods")
	}
	methodSeen := make(map[string]struct{}, len(in.AllowedMethods))
	methods := make([]string, 0, len(in.AllowedMethods))
	for _, method := range in.AllowedMethods {
		method = strings.ToUpper(strings.TrimSpace(method))
		allowed := false
		for _, candidate := range edgeProxyAllowedMethods {
			if method == candidate {
				allowed = true
				break
			}
		}
		if !allowed {
			return errors.New("edge proxy allowed_methods contains an unsupported method")
		}
		if _, dup := methodSeen[method]; dup {
			continue
		}
		methodSeen[method] = struct{}{}
		methods = append(methods, method)
	}
	in.AllowedMethods = methods
	if in.Enabled && in.WAFInline && in.MaxBodyBytes > 16<<20 {
		// The inline WAF inspects the body before forwarding; a multi-megabyte
		// body would turn the terminator into a memory amplifier.
		return errors.New("edge proxy inline WAF requires max_body_bytes at or below 16 MiB")
	}
	return nil
}

// validateLoopbackListen refuses anything but a loopback listener. The edge
// terminator exists to be fronted by the gateway, never to bind a public port
// behind the operator's back.
func validateLoopbackListen(listen string) error {
	host, port, err := net.SplitHostPort(strings.TrimSpace(listen))
	if err != nil {
		return errors.New("edge proxy listen must be host:port")
	}
	ip, parseErr := netip.ParseAddr(host)
	if parseErr != nil || !ip.IsLoopback() {
		return errors.New("edge proxy listen must be a loopback address")
	}
	if port == "" || port == "0" {
		return errors.New("edge proxy listen port must be non-zero")
	}
	return nil
}

// validateLoopbackUpstream refuses a non-loopback upstream for the same reason.
// Phase 1 of the engine implements plain HTTP/1.1 to the local web server; an
// https upstream would have to be refused later as engine_unavailable, so it is
// refused at save time instead of being persisted as a policy the engine cannot
// honour.
func validateLoopbackUpstream(upstream string) error {
	parsed, err := url.Parse(strings.TrimSpace(upstream))
	if err != nil || parsed.Scheme != "http" {
		return errors.New("edge proxy upstream must be an http:// URL")
	}
	host := parsed.Hostname()
	ip, parseErr := netip.ParseAddr(host)
	if parseErr != nil || !ip.IsLoopback() {
		return errors.New("edge proxy upstream must be a loopback address")
	}
	if parsed.Port() == "" {
		return errors.New("edge proxy upstream must carry an explicit port")
	}
	return nil
}

// edgeProxySettingsStateSource is the optional runtime hook the Module E engine
// may implement (control/edge_proxy.go) so the settings module can report what
// actually runs instead of a fake state.
type edgeProxySettingsStateSource interface {
	EdgeProxySettingsApplyState() string
	EdgeProxyModuleDetails() map[string]any
}
