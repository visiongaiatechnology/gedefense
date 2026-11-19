package webposture

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"time"
)

// LoopbackProbeAddress is the only address the probe dials. The probe exists to
// learn what a local web server actually negotiates, not to reach remote hosts.
const LoopbackProbeAddress = "127.0.0.1"

// ProbeALPN performs the bounded loopback ALPN probe described in the 6.1.0
// blueprint: dial 127.0.0.1:<port>, offer ["h2","http/1.1"], use the first
// server_name as SNI (falling back to localhost), accept any certificate (the
// probe only reads the negotiated parameters) and give up after timeout.
func ProbeALPN(ctx context.Context, port int, sni string, timeout time.Duration) ALPNResult {
	result := ALPNResult{Checked: true, Offered: []string{"h2", "http/1.1"}}
	if port < 1 || port > 65535 {
		result.Error = "invalid probe port"
		return result
	}
	if timeout <= 0 || timeout > 10*time.Second {
		timeout = DefaultProbeTimeout
	}
	if sni == "" {
		sni = "localhost"
	}
	result.SNI = sni
	dialCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	dialer := &net.Dialer{}
	conn, err := dialer.DialContext(dialCtx, "tcp", fmt.Sprintf("%s:%d", LoopbackProbeAddress, port))
	if err != nil {
		result.Error = "listener unreachable on loopback"
		return result
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	client := tls.Client(conn, &tls.Config{
		ServerName: sni,
		NextProtos: []string{"h2", "http/1.1"},
		MinVersion: tls.VersionTLS12,
		// The probe reads the negotiated parameters of the local server only; it
		// never sends application data and never uses the certificate as trust.
		InsecureSkipVerify: true,
	})
	if err := client.HandshakeContext(dialCtx); err != nil {
		result.Error = "TLS handshake failed"
		return result
	}
	state := client.ConnectionState()
	result.Protocol = state.NegotiatedProtocol
	result.TLSVersion = tlsVersionName(state.Version)
	result.Cipher = tls.CipherSuiteName(state.CipherSuite)
	if len(state.PeerCertificates) == 0 {
		result.Error = "server presented no certificate"
	}
	return result
}

// tlsVersionName maps the wire version to the operator-facing name.
func tlsVersionName(version uint16) string {
	switch version {
	case tls.VersionTLS13:
		return "TLS1.3"
	case tls.VersionTLS12:
		return "TLS1.2"
	case tls.VersionTLS11:
		return "TLS1.1"
	case tls.VersionTLS10:
		return "TLS1.0"
	default:
		return ""
	}
}
