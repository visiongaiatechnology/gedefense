// STATUS: DIAMANT VGT SUPREME
package main

import (
	"fmt"
	"net/url"
	"path/filepath"
	"sort"
	"strings"
)

// Guided web-server integration.
//
// This module generates configuration text. It never writes to a web server's
// configuration, never reloads a service, and never claims that a generated snippet is
// in effect. The operator applies it, and the self-test then observes whether it
// worked. Generation without observation is a suggestion, not a control.
//
// Injection is the whole risk of a generator like this: the output is a configuration
// file for a privileged daemon, so every interpolated value is validated against a
// closed grammar before it reaches the template. A socket path containing a newline
// or a semicolon would otherwise be able to append arbitrary directives to an nginx
// server block.
//
// Every interpolation below is either:
//   - a validated absolute path (no control characters, no quotes, no semicolons,
//     no whitespace, cleaned and confirmed absolute), or
//   - a validated upstream authority (parsed, loopback, known scheme, numeric port), or
//   - a validated hostname (letters, digits, dots, hyphens only), or
//   - a numeric literal from a bounded range.

const (
	integrationMaxLineBytes = 512
	integrationMaxServers   = 32
)

// IntegrationRequest is the operator's input. Empty fields fall back to the compiled-in
// configuration, so a caller can ask for "the integration for this host" without
// repeating what the service already knows.
type IntegrationRequest struct {
	ServerName string `json:"server_name,omitempty"`
	ListenPort int    `json:"listen_port,omitempty"`
	Upstream   string `json:"upstream,omitempty"`
}

// IntegrationSnippet is one ready-to-apply artefact.
type IntegrationSnippet struct {
	Target       string   `json:"target"`
	Title        string   `json:"title"`
	Body         string   `json:"body"`
	Steps        []string `json:"steps"`
	Notes        []string `json:"notes"`
	ApplyHint    string   `json:"apply_hint"`
	VerifyHint   string   `json:"verify_hint"`
	RequiresRoot bool     `json:"requires_root"`
}

// IntegrationPlan is everything the operator needs for one host.
type IntegrationPlan struct {
	Generated    bool                 `json:"generated"`
	Socket       string               `json:"socket"`
	InlineSocket string               `json:"inline_socket"`
	Upstream     string               `json:"upstream"`
	ServerName   string               `json:"server_name"`
	ListenPort   int                  `json:"listen_port"`
	Snippets     []IntegrationSnippet `json:"snippets"`
	Reason       string               `json:"reason,omitempty"`
	Surface      WebSurface           `json:"web_surface"`
	Detection    []string             `json:"detection"`
	Warnings     []string             `json:"warnings"`
	SelfTestHint string               `json:"self_test_hint"`
}

// ------------------------------------------------------------------ validation

// validateIntegrationPath accepts only an absolute, cleaned path built from a closed
// character set. It is the single gate between operator configuration and a privileged
// configuration file, so it rejects rather than escapes: escaping is how injection
// bugs are born.
func validateIntegrationPath(label, value string) (string, error) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return "", fmt.Errorf("%s must not be empty", label)
	}
	if len(trimmed) > 256 {
		return "", fmt.Errorf("%s exceeds 256 bytes", label)
	}
	if !filepath.IsAbs(trimmed) {
		return "", fmt.Errorf("%s must be an absolute path", label)
	}
	cleaned := filepath.Clean(trimmed)
	if cleaned != trimmed {
		return "", fmt.Errorf("%s must already be in cleaned form", label)
	}
	for _, r := range cleaned {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '/' || r == '.' || r == '_' || r == '-':
		default:
			// Whitespace, quotes, semicolons, braces, newlines and every other
			// metacharacter a config grammar could interpret are refused here.
			return "", fmt.Errorf("%s contains a character that is not allowed in a socket path", label)
		}
	}
	if strings.Contains(cleaned, "..") {
		return "", fmt.Errorf("%s must not contain a parent reference", label)
	}
	return cleaned, nil
}

// validateIntegrationHost accepts a Host header value or server name.
func validateIntegrationHost(label, value string) (string, error) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return "", fmt.Errorf("%s must not be empty", label)
	}
	if len(trimmed) > 253 {
		return "", fmt.Errorf("%s exceeds 253 bytes", label)
	}
	for _, r := range trimmed {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '.' || r == '-' || r == '_':
		default:
			return "", fmt.Errorf("%s must be a bare hostname", label)
		}
	}
	if strings.HasPrefix(trimmed, ".") || strings.HasSuffix(trimmed, ".") || strings.Contains(trimmed, "..") {
		return "", fmt.Errorf("%s is not a well-formed hostname", label)
	}
	// Each label must begin and end with an alphanumeric character. A leading or
	// trailing hyphen is not a valid hostname, and a configuration grammar is free to
	// read it as an option marker.
	for _, part := range strings.Split(trimmed, ".") {
		if part == "" {
			return "", fmt.Errorf("%s contains an empty label", label)
		}
		if strings.HasPrefix(part, "-") || strings.HasSuffix(part, "-") {
			return "", fmt.Errorf("%s contains a label that begins or ends with a hyphen", label)
		}
	}
	return trimmed, nil
}

// validateIntegrationUpstream accepts a loopback HTTP upstream. A remote upstream is
// refused: the inline edge exists to inspect traffic on this host, and pointing it at
// another machine would make GeDefense a proxy for traffic it cannot account for.
func validateIntegrationUpstream(value string) (scheme, authority string, port int, err error) {
	trimmed := strings.TrimSpace(value)
	parsed, parseErr := url.Parse(trimmed)
	if parseErr != nil {
		return "", "", 0, fmt.Errorf("upstream is not a valid URL")
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return "", "", 0, fmt.Errorf("upstream scheme must be http or https")
	}
	if parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", "", 0, fmt.Errorf("upstream must not carry credentials, a query or a fragment")
	}
	if parsed.Path != "" && parsed.Path != "/" {
		return "", "", 0, fmt.Errorf("upstream must not carry a path")
	}
	host := parsed.Hostname()
	if host != "127.0.0.1" && host != "::1" && host != "localhost" {
		return "", "", 0, fmt.Errorf("upstream must be a loopback address")
	}
	portText := parsed.Port()
	if portText == "" {
		return "", "", 0, fmt.Errorf("upstream must name an explicit port")
	}
	portValue := 0
	for _, r := range portText {
		if r < '0' || r > '9' {
			return "", "", 0, fmt.Errorf("upstream port must be numeric")
		}
		portValue = portValue*10 + int(r-'0')
		if portValue > 65535 {
			return "", "", 0, fmt.Errorf("upstream port is out of range")
		}
	}
	if portValue < 1 {
		return "", "", 0, fmt.Errorf("upstream port is out of range")
	}
	return parsed.Scheme, parsed.Host, portValue, nil
}

// ------------------------------------------------------------------ generation

// BuildIntegrationPlan produces the artefacts for this host. It returns a plan with
// Generated=false and a reason instead of an error when the inputs are unusable, so a
// caller always receives something displayable.
func (s *L7Service) BuildIntegrationPlan(request IntegrationRequest) IntegrationPlan {
	plan := IntegrationPlan{Surface: discoverWebSurface()}

	if s == nil || !s.cfg.Enabled {
		plan.Reason = "L7 is disabled by configuration, so there is nothing to integrate"
		return plan
	}

	inlineSocket, err := validateIntegrationPath("inline socket", s.cfg.InlineSocket)
	if err != nil {
		plan.Reason = "the inline socket path is not usable for a generated configuration: " + err.Error()
		return plan
	}
	producerSocket, err := validateIntegrationPath("inspection socket", s.cfg.Socket)
	if err != nil {
		plan.Reason = "the inspection socket path is not usable for a generated configuration: " + err.Error()
		return plan
	}

	upstreamValue := strings.TrimSpace(request.Upstream)
	if upstreamValue == "" {
		upstreamValue = s.cfg.InlineUpstream
	}
	_, upstreamAuthority, upstreamPort, err := validateIntegrationUpstream(upstreamValue)
	if err != nil {
		plan.Reason = "the upstream is not usable: " + err.Error()
		return plan
	}

	serverName := strings.TrimSpace(request.ServerName)
	if serverName == "" {
		serverName = "_"
	}
	listenPort := request.ListenPort
	if listenPort == 0 {
		listenPort = 443
	}
	if listenPort < 1 || listenPort > 65535 {
		plan.Reason = "the listen port is out of range"
		return plan
	}
	// A literal underscore is nginx's default-server marker and is valid there, but it
	// is not a hostname, so it is allowed only for nginx.
	nginxServerName := serverName
	if serverName != "_" {
		validated, hostErr := validateIntegrationHost("server name", serverName)
		if hostErr != nil {
			plan.Reason = "the server name is not usable: " + hostErr.Error()
			return plan
		}
		nginxServerName = validated
	}
	hostName := serverName
	if hostName == "_" {
		hostName = "localhost"
	}

	plan.Generated = true
	plan.Socket = producerSocket
	plan.InlineSocket = inlineSocket
	plan.Upstream = upstreamAuthority
	plan.ServerName = nginxServerName
	plan.ListenPort = listenPort
	plan.Detection = describeDetectedSurface(plan.Surface)

	plan.Snippets = []IntegrationSnippet{
		buildNginxDirectSnippet(nginxServerName, listenPort, inlineSocket),
		buildNginxPHPFPMSnippet(nginxServerName, listenPort, inlineSocket, upstreamAuthority, upstreamPort),
		buildApacheSnippet(hostName, listenPort, inlineSocket, upstreamAuthority, upstreamPort),
		buildCaddySnippet(hostName, listenPort, inlineSocket),
		buildProducerSnippet(producerSocket),
	}

	if !s.cfg.InlineEnabled {
		plan.Warnings = append(plan.Warnings,
			"inline_enabled is false, so the generated inline snippets would point at a socket nobody is listening on. Enable the inline edge and restart before applying them.")
	}
	if port := upstreamPort; port > 0 {
		plan.Warnings = append(plan.Warnings,
			fmt.Sprintf("the upstream %s must be listening on %s before the inline snippets will forward successfully.", upstreamAuthority, "this host"))
	}
	if plan.Surface.ExpectsHTTP && !plan.Surface.Detected {
		plan.Warnings = append(plan.Warnings,
			"web ports are listening but no recognised web server process was found; the snippets are still valid, but confirm which server owns those ports.")
	}
	plan.SelfTestHint = "After applying a snippet and reloading the web server, run the L7 self-test. It sends one synthetic request through the configured path and reports whether the inspection counter moved."
	return plan
}

func describeDetectedSurface(surface WebSurface) []string {
	out := make([]string, 0, 4)
	if !surface.Scanned {
		return append(out, "web surface not scanned: "+surface.Reason)
	}
	for _, server := range surface.Servers {
		out = append(out, fmt.Sprintf("%s (%d process(es))", server.Name, server.Count))
	}
	if len(surface.WebPorts) > 0 {
		out = append(out, fmt.Sprintf("listening web ports: %s", joinInts(surface.WebPorts)))
	}
	if len(out) == 0 {
		out = append(out, "no web server or web port detected on this host")
	}
	return out
}

func joinInts(values []int) string {
	parts := make([]string, 0, len(values))
	for _, value := range values {
		parts = append(parts, fmt.Sprintf("%d", value))
	}
	return strings.Join(parts, ", ")
}

// buildNginxDirectSnippet is the plain case: nginx already speaks HTTP to the
// application, so the edge socket simply replaces the upstream.
func buildNginxDirectSnippet(serverName string, listenPort int, inlineSocket string) IntegrationSnippet {
	// The first version of this artefact was a complete server block with `listen %d ssl`
	// and a comment where the certificate directives belong. It could not work: nginx
	// refuses a TLS listener without a certificate, so the documented workflow - copy to
	// conf.d, then nginx -t - failed at the first step. It was wrong in a second way too:
	// a conf.d file naming a host that already has a server block creates a conflicting
	// server name, and nginx silently keeps only one of them.
	//
	// The second version was correct about placement but written entirely as comments, so
	// the operator had to retype the directives out of a comment block. The body now
	// carries the real directives with the placement stated above each piece, which is
	// what makes it copyable and what lets a test feed it to nginx.
	body := fmt.Sprintf(`# piece 1 of 2 - place at http level, for example in
# /etc/nginx/conf.d/gedefense-l7-upstream.conf
upstream gedefense_l7_edge {
    server unix:%s;
    keepalive 16;
}

# piece 2 of 2 - place inside the EXISTING server block that already terminates TLS
# for %s. Do not add a second server block for this name: nginx warns about a
# conflicting server name and keeps only one of them.
location / {
    proxy_http_version 1.1;
    proxy_set_header Host $host;
    proxy_set_header X-Gedefense-Client-Ip $remote_addr;
    proxy_set_header X-Gedefense-Original-Scheme $scheme;
    proxy_set_header Connection "";
    proxy_pass http://gedefense_l7_edge;
}

# The listen port stays as it is: %d keeps its own certificate directives. nginx hands
# the request to GeDefense, which inspects it and forwards it to the upstream set in
# gedefense.toml (l7.inline_upstream). The application does not move or change.`, inlineSocket, serverName, listenPort)

	return IntegrationSnippet{
		Target: "nginx",
		Title:  "nginx — inline edge in front of the application",
		Body:   body,
		Steps: []string{
			"Confirm the inline edge is enabled: l7.inline_enabled = true, then restart the control plane.",
			"Write the upstream block to /etc/nginx/conf.d/gedefense-l7-upstream.conf.",
			"Add the location block inside the existing TLS server block for this host.",
			"Run `nginx -t` and fix anything it reports before reloading.",
			"Reload with `systemctl reload nginx`.",
			"Run the L7 self-test and confirm the outcome is PASS.",
		},
		Notes: []string{
			"nginx must run as a user that may write to the socket's group. The socket group is configured as l7.socket_group.",
			"Do not create a second server block for this host name. nginx keeps only one of two blocks with the same server_name, and the other is dropped without an error.",
			"This snippet assumes the application already answers HTTP on the configured upstream. If nginx speaks FastCGI to PHP-FPM instead, use the PHP-FPM snippet.",
		},
		ApplyHint: "write the upstream block to /etc/nginx/conf.d/, add the location inside the existing server block, then `nginx -t && systemctl reload nginx`",
		// Both halves of verification, in the order that fails cheapest: the parser first,
		// because a configuration error is found without touching a running site, and the
		// self-test second, because a configuration that parses can still route around the
		// engine.
		VerifyHint:   "run `nginx -t` first, then run the L7 self-test; the outcome must be PASS and the inspection counter must move",
		RequiresRoot: true,
	}
}

// buildNginxPHPFPMSnippet is the case the direct snippet cannot serve: nginx speaks
// FastCGI to PHP-FPM, and GeDefense speaks HTTP. A second, loopback-only server block
// is inserted so the request path becomes
//
//	internet :443 -> nginx (TLS) -> edge.sock -> GeDefense -> 127.0.0.1:8080
//	  -> internal nginx server block -> PHP-FPM
//
// The internal block is bound to loopback so it is not reachable from outside and
// cannot be used to bypass inspection.
func buildNginxPHPFPMSnippet(serverName string, listenPort int, inlineSocket, upstreamAuthority string, upstreamPort int) IntegrationSnippet {
	body := fmt.Sprintf(`# GeDefense inline L7 path for nginx fronting PHP-FPM.
#
# Why two server blocks: GeDefense inspects HTTP, while php-fpm is reached over
# FastCGI. The public block terminates TLS and hands the request to GeDefense; the
# internal block, bound to loopback only, turns it back into FastCGI for php-fpm.
#
# Request path:
#   internet -> :%d (this block) -> unix:%s -> GeDefense -> %s
#            -> 127.0.0.1 the internal block -> php-fpm

upstream gedefense_l7_edge {
    server unix:%s;
    keepalive 16;
}

server {
    listen %d ssl;
    server_name %s;

    # Your existing TLS certificate directives stay here.

    location / {
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Gedefense-Client-Ip $remote_addr;
        proxy_set_header X-Gedefense-Original-Scheme $scheme;
        proxy_set_header Connection "";
        proxy_pass http://gedefense_l7_edge;
    }
}

# Internal origin. Bound to loopback, never reachable from outside, so inspection
# cannot be bypassed by addressing it directly.
server {
    listen 127.0.0.1:%d;
    server_name %s;
    root /var/www/html;
    index index.php index.html;

    location / {
        try_files $uri $uri/ /index.php?$args;
    }

    location ~ \.php$ {
        include fastcgi_params;
        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
        fastcgi_pass unix:/run/php/php-fpm.sock;
    }

    # The origin must not be reachable through the public listener.
    location = /__gedefense_origin_guard { return 444; }
}
`, listenPort, inlineSocket, upstreamAuthority, inlineSocket, listenPort, serverName, upstreamPort, serverName)

	return IntegrationSnippet{
		Target: "nginx-php-fpm",
		Title:  "nginx + PHP-FPM — inline edge with an internal loopback origin",
		Body:   body,
		Steps: []string{
			"Set l7.inline_enabled = true and start the control plane so the edge socket exists.",
			"Confirm the upstream in gedefense.toml is the INTERNAL port, not the public one.",
			"Write the snippet to /etc/nginx/conf.d/gedefense-l7.conf.",
			"Create the internal document root and check the FastCGI socket path matches your php-fpm pool.",
			"Run `nginx -t`, then `systemctl reload nginx`.",
			"Run the L7 self-test and confirm PASS.",
		},
		Notes: []string{
			fmt.Sprintf("The upstream must be %s. If gedefense.toml still points at the public listener, the request loops back into GeDefense.", upstreamAuthority),
			"The internal block listens on loopback only. Do not change it to 0.0.0.0: that would expose an uninspected origin.",
			"Adjust `root` and the FastCGI socket path to your installation; they are placeholders for your layout, not detected values.",
		},
		ApplyHint:    "copy the body to /etc/nginx/conf.d/gedefense-l7.conf, then `nginx -t && systemctl reload nginx`",
		VerifyHint:   "run the L7 self-test; a FAIL with 'upstream not reachable' means l7.inline_upstream still points at the wrong port",
		RequiresRoot: true,
	}
}

// buildApacheSnippet uses mod_proxy to the same edge socket. Apache cannot proxy to a
// Unix socket through a plain ProxyPass, so the socket is declared with
// ProxyPassMatch-free UDS syntax that Apache 2.4.7 and later support.
func buildApacheSnippet(serverName string, listenPort int, inlineSocket, upstreamAuthority string, upstreamPort int) IntegrationSnippet {
	body := fmt.Sprintf(`# GeDefense inline L7 path for Apache httpd (2.4.7+).
# Requires: a2enmod proxy proxy_http ssl headers
#
# Apache reaches the edge over a Unix socket through the UDS form of ProxyPass.

<VirtualHost *:%d>
    ServerName %s

    # Your existing TLS configuration and certificates stay here.

    ProxyRequests Off
    ProxyPreserveHost On

    # The edge socket is the only origin Apache knows about.
    ProxyPass / "unix:%s|http://%s/"
    ProxyPassReverse / "http://%s/"

    RequestHeader set X-Gedefense-Client-Ip "%%{REMOTE_ADDR}s"
    RequestHeader set X-Gedefense-Original-Scheme "https"

    ErrorLog  ${APACHE_LOG_DIR}/gedefense-error.log
    CustomLog ${APACHE_LOG_DIR}/gedefense-access.log combined
</VirtualHost>

# The application keeps its own virtual host, bound to loopback so it can only be
# reached through GeDefense and never directly from outside.
<VirtualHost 127.0.0.1:%d>
    ServerName %s
    DocumentRoot /var/www/html

    <FilesMatch \.php$>
        SetHandler "proxy:unix:/run/php/php-fpm.sock|fcgi://localhost/"
    </FilesMatch>

    # Deny anything that did not come through the edge.
    <Location />
        Require local
    </Location>
</VirtualHost>
`, listenPort, serverName, inlineSocket, upstreamAuthority, upstreamAuthority, upstreamPort, serverName)

	return IntegrationSnippet{
		Target: "apache",
		Title:  "Apache httpd — inline edge with a loopback origin",
		Body:   body,
		Steps: []string{
			"Enable the modules: `a2enmod proxy proxy_http ssl headers`.",
			"Set l7.inline_enabled = true and restart the control plane.",
			"Write the snippet to /etc/apache2/sites-available/gedefense-l7.conf and enable it with a2ensite.",
			"Adjust the internal origin's port and DocumentRoot to your layout.",
			"Run `apachectl configtest`, then `systemctl reload apache2`.",
			"Run the L7 self-test and confirm PASS.",
		},
		Notes: []string{
			"The internal origin port is a placeholder: it must match l7.inline_upstream, and it must differ from the public listener.",
			"`Require local` on the origin is what stops a direct request from bypassing inspection. Do not remove it.",
			"Verify your Apache version supports the UDS form of ProxyPass; 2.4.7 or later does.",
		},
		ApplyHint:    "write to /etc/apache2/sites-available/, `a2ensite`, then `apachectl configtest && systemctl reload apache2`",
		VerifyHint:   "run the L7 self-test; the outcome must be PASS",
		RequiresRoot: true,
	}
}

// buildCaddySnippet uses Caddy's reverse_proxy with a Unix socket dial address, which
// is the whole integration: no extra module and no internal origin needed, because
// Caddy speaks HTTP to the application like nginx does.
func buildCaddySnippet(serverName string, listenPort int, inlineSocket string) IntegrationSnippet {
	body := fmt.Sprintf(`# GeDefense inline L7 path for Caddy 2.
# Add to your Caddyfile and reload.

%s:%d {
    # Your existing TLS settings stay here.

    reverse_proxy unix/%s {
        # Preserve the client identity for the inspection layer.
        header_up X-Gedefense-Client-Ip {remote_host}
        header_up X-Gedefense-Original-Scheme {scheme}
    }
}
`, serverName, listenPort, inlineSocket)

	return IntegrationSnippet{
		Target: "caddy",
		Title:  "Caddy 2 — inline edge as the reverse proxy target",
		Body:   body,
		Steps: []string{
			"Set l7.inline_enabled = true and restart the control plane.",
			"Add the site block to your Caddyfile.",
			"Run `caddy validate --config /etc/caddy/Caddyfile`.",
			"Reload with `systemctl reload caddy`.",
			"Run the L7 self-test and confirm PASS.",
		},
		Notes: []string{
			"Caddy needs permission to open the socket; place the Caddy service user in l7.socket_group.",
			"Caddy speaks HTTP to the application, so no internal origin block is required.",
		},
		ApplyHint:    "add the block to the Caddyfile, then `caddy validate` and `systemctl reload caddy`",
		VerifyHint:   "run the L7 self-test; the outcome must be PASS",
		RequiresRoot: true,
	}
}

// buildProducerSnippet covers the other supported topology: a producer that is not a
// reverse proxy posts inspection envelopes itself.
func buildProducerSnippet(producerSocket string) IntegrationSnippet {
	body := fmt.Sprintf(`# GeDefense producer integration.
#
# Use this when the web server cannot act as a reverse proxy - for example a custom
# application server. The producer posts one inspection envelope per request and acts
# on the verdict.
#
# Socket: %s
# Endpoint: POST /v1/inspect
#
# Request body (JSON):
# {
#   "version": 1,
#   "request_id": "<unique per request>",
#   "method": "GET",
#   "scheme": "https",
#   "host": "example.test",
#   "uri": "/path?query=1",
#   "remote_ip": "203.0.113.10",
#   "headers": [{"name": "User-Agent", "value": "..."}],
#   "body_base64": "<optional, bounded by l7.max_body_bytes>",
#   "server_process": "your-server"
# }
#
# Response: the verdict document. `+"`action`"+` is the decision to apply.
#
# Requirements:
#   - The producer must run as a user or group listed in l7.allowed_peer_gids.
#   - The envelope is size-bounded by l7.max_envelope_bytes.
#   - The engine answers 403 on a peer it does not trust and 503 when saturated;
#     both must be treated as failures by the producer, never as an allow.
`, producerSocket)

	return IntegrationSnippet{
		Target: "producer",
		Title:  "Custom producer — post inspection envelopes",
		Body:   body,
		Steps: []string{
			"Add the producer's service group to l7.allowed_peer_gids.",
			"Restart the control plane so the socket group and peer list are applied.",
			"Implement one POST /v1/inspect per request over the Unix socket.",
			"Treat any non-200 answer as a failure: never continue as though it were an allow.",
			"Run the L7 self-test and confirm PASS.",
		},
		Notes: []string{
			"A producer that fails open is worse than no producer at all: a 403 or 503 must deny the request.",
			"The inspection socket is a local trust boundary; do not expose it over the network.",
		},
		ApplyHint:    "implement the envelope contract in your server and grant its group access to the socket",
		VerifyHint:   "run the L7 self-test; the outcome must be PASS and the producer counter must move",
		RequiresRoot: false,
	}
}

// IntegrationTargets lists the targets a plan can contain, in a stable order.
func IntegrationTargets() []string {
	targets := []string{"nginx", "nginx-php-fpm", "apache", "caddy", "producer"}
	sort.Strings(targets)
	return targets
}
