package flowguard

import "testing"

// buildClientHello assembles a minimal valid TLS ClientHello with the
// supported_versions and ALPN extensions so the hint parser can be tested
// without a network capture.
func buildClientHello(versions []uint16, alpn []string) []byte {
	body := make([]byte, 0, 128)
	body = append(body, 0x03, 0x03)             // legacy version
	body = append(body, make([]byte, 32)...)    // random
	body = append(body, 0x00)                   // no session id
	body = append(body, 0x00, 0x02, 0x13, 0x01) // one cipher suite
	body = append(body, 0x01, 0x00)             // null compression
	extensions := make([]byte, 0, 64)
	versionData := []byte{byte(len(versions) * 2)}
	for _, version := range versions {
		versionData = append(versionData, byte(version>>8), byte(version))
	}
	extensions = append(extensions, 0x00, 0x2b, byte(len(versionData)>>8), byte(len(versionData)))
	extensions = append(extensions, versionData...)
	alpnList := make([]byte, 0, 16)
	for _, protocol := range alpn {
		alpnList = append(alpnList, byte(len(protocol)))
		alpnList = append(alpnList, []byte(protocol)...)
	}
	alpnData := []byte{byte(len(alpnList) >> 8), byte(len(alpnList))}
	alpnData = append(alpnData, alpnList...)
	extensions = append(extensions, 0x00, 0x10, byte(len(alpnData)>>8), byte(len(alpnData)))
	extensions = append(extensions, alpnData...)
	body = append(body, byte(len(extensions)>>8), byte(len(extensions)))
	body = append(body, extensions...)
	handshake := []byte{0x01, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}
	handshake = append(handshake, body...)
	record := []byte{0x16, 0x03, 0x01, byte(len(handshake) >> 8), byte(len(handshake))}
	return append(record, handshake...)
}

// TestClientHelloHints covers the supported_versions and ALPN extraction.
func TestClientHelloHints(t *testing.T) {
	t.Parallel()
	hints := ParseClientHelloHints(buildClientHello([]uint16{0x0304, 0x0303}, []string{"h2", "http/1.1"}))
	if len(hints.Versions) != 2 || hints.Versions[0] != 0x0304 || hints.Versions[1] != 0x0303 {
		t.Fatalf("versions = %v", hints.Versions)
	}
	if len(hints.ALPN) != 2 || hints.ALPN[0] != "h2" || hints.ALPN[1] != "http/1.1" {
		t.Fatalf("alpn = %v", hints.ALPN)
	}
	if hints.Cipher != 0x1301 {
		t.Fatalf("cipher = %#x", hints.Cipher)
	}
	// A malformed or truncated record yields no hints instead of a panic.
	if hints := ParseClientHelloHints([]byte{0x16, 0x03, 0x01}); len(hints.ALPN) != 0 {
		t.Fatalf("truncated record produced ALPN hints: %v", hints.ALPN)
	}
	if hints := ParseClientHelloHints(make([]byte, 4096)); len(hints.Versions) != 0 {
		t.Fatalf("oversized zero record produced hints")
	}
}
