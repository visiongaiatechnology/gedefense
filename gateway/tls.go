// STATUS: DIAMANT VGT SUPREME
package main

import (
	"crypto/tls"
	"errors"
	"net"
	"strings"
)

func hardenedTLSConfig(loopbackListener bool) *tls.Config {
	// Post-quantum hybrid key exchange is prioritized (ML-KEM), followed by
	// standard TLS 1.3 curves (X25519, CurveP384) as a secure fallback for
	// classical browsers and system tools.
	curves := []tls.CurveID{
		tls.SecP384r1MLKEM1024,
		tls.X25519MLKEM768,
		tls.X25519,
		tls.CurveP384,
	}
	return &tls.Config{
		MinVersion:       tls.VersionTLS13,
		CurvePreferences: curves,
	}
}

func canonicalHostPort(public, listen string) (string, error) {
	if strings.Contains(public, "://") || strings.ContainsAny(public, "/?#@") {
		return "", errors.New("public-host must be host[:port], without scheme or path")
	}
	host, port, err := net.SplitHostPort(public)
	if err == nil {
		if host == "" || port == "" {
			return "", errors.New("invalid public-host")
		}
		return net.JoinHostPort(strings.Trim(host, "[]"), port), nil
	}
	if strings.Count(public, ":") > 1 {
		return "", errors.New("IPv6 public-host requires brackets and port")
	}
	_, listenPort, err := net.SplitHostPort(listen)
	if err != nil {
		return "", errors.New("invalid listen address")
	}
	return net.JoinHostPort(public, listenPort), nil
}

func sameHost(a, b string) bool {
	ah, ap := splitHostDefault(a)
	bh, bp := splitHostDefault(b)
	return strings.EqualFold(strings.Trim(ah, "[]"), strings.Trim(bh, "[]")) && ap == bp
}

func (g *gateway) allowHost(host string) bool {
	if sameHost(host, g.publicHost) {
		return true
	}
	ah, ap := splitHostDefault(host)
	_, expectedPort := splitHostDefault(g.publicHost)
	return isLoopbackHost(strings.Trim(ah, "[]")) && ap == expectedPort
}

func splitHostDefault(value string) (string, string) {
	h, p, err := net.SplitHostPort(value)
	if err == nil {
		return h, p
	}
	return value, "443"
}

func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
