package flowguard

// ClientHello hints the TLS sensor needs in addition to the shared
// ParseClientHello summary: the supported TLS versions and the offered ALPN
// protocols. The parser is bounded, allocation-light and never retains payload
// bytes; a malformed extension simply yields no hint.

// maxClientHelloBytes bounds the ClientHello the hint parser walks.
const maxClientHelloBytes = 2048

// ClientHelloHints is the extra metadata extracted from one ClientHello record.
type ClientHelloHints struct {
	// Versions lists the supported_versions extension values in order. A
	// ClientHello without that extension reports the record version instead.
	Versions []uint16
	// ALPN lists the offered protocol names in order.
	ALPN []string
	// Cipher is the first offered cipher suite (0 when absent).
	Cipher uint16
}

// ParseClientHelloHints reads the TLS record version, the supported_versions
// extension, the ALPN extension and the first cipher suite.
func ParseClientHelloHints(payload []byte) ClientHelloHints {
	hints := ClientHelloHints{Versions: []uint16{}, ALPN: []string{}}
	if len(payload) < 6 || len(payload) > maxClientHelloBytes {
		return hints
	}
	// TLS record header: type(1) version(2) length(2).
	if payload[0] != 0x16 {
		return hints
	}
	recordVersion := uint16(payload[1])<<8 | uint16(payload[2])
	hints.Versions = append(hints.Versions, recordVersion)
	handshake := payload[5:]
	if len(handshake) < 4 || handshake[0] != 0x01 {
		return hints
	}
	body, ok := handshakeBody(handshake)
	if !ok || len(body) < 34 {
		return hints
	}
	cursor := 34 // version(2) + random(32)
	if len(body) < cursor+1 {
		return hints
	}
	sessionLen := int(body[cursor])
	cursor += 1 + sessionLen
	if len(body) < cursor+2 {
		return hints
	}
	cipherLen := int(body[cursor])<<8 | int(body[cursor+1])
	cursor += 2
	if cipherLen > 0 && len(body) > cursor {
		hints.Cipher = uint16(body[cursor])<<8 | uint16(body[cursor+1])
	}
	cursor += cipherLen
	if len(body) < cursor+1 {
		return hints
	}
	compressionLen := int(body[cursor])
	cursor += 1 + compressionLen
	if len(body) < cursor+2 {
		return hints
	}
	extensionsLen := int(body[cursor])<<8 | int(body[cursor+1])
	cursor += 2
	end := cursor + extensionsLen
	if end > len(body) {
		end = len(body)
	}
	for cursor+4 <= end {
		extensionType := uint16(body[cursor])<<8 | uint16(body[cursor+1])
		extensionLen := int(body[cursor+2])<<8 | int(body[cursor+3])
		cursor += 4
		if cursor+extensionLen > end {
			break
		}
		extension := body[cursor : cursor+extensionLen]
		switch extensionType {
		case 0x002b: // supported_versions
			hints.Versions = parseSupportedVersions(extension)
		case 0x0010: // ALPN
			hints.ALPN = parseALPNList(extension)
		}
		cursor += extensionLen
	}
	if len(hints.ALPN) > 8 {
		hints.ALPN = hints.ALPN[:8]
	}
	return hints
}

// handshakeBody validates the handshake header and returns the body slice.
func handshakeBody(handshake []byte) ([]byte, bool) {
	if len(handshake) < 4 {
		return nil, false
	}
	length := int(handshake[1])<<16 | int(handshake[2])<<8 | int(handshake[3])
	if length < 0 || length > len(handshake)-4 {
		return nil, false
	}
	return handshake[4 : 4+length], true
}

// parseSupportedVersions decodes the version list extension. The wire format is
// one byte of list length in bytes followed by 2-byte protocol versions.
func parseSupportedVersions(extension []byte) []uint16 {
	if len(extension) < 3 {
		return []uint16{}
	}
	listLength := int(extension[0])
	if listLength == 0 || listLength%2 != 0 || len(extension) < 1+listLength {
		return []uint16{}
	}
	count := listLength / 2
	versions := make([]uint16, 0, count)
	for index := 0; index < count; index++ {
		versions = append(versions, uint16(extension[1+index*2])<<8|uint16(extension[2+index*2]))
	}
	if len(versions) > 8 {
		versions = versions[:8]
	}
	return versions
}

// parseALPNList decodes the protocol name list extension. Only printable
// protocol names are kept; the published payload is operator-facing data.
func parseALPNList(extension []byte) []string {
	if len(extension) < 2 {
		return []string{}
	}
	listLength := int(extension[0])<<8 | int(extension[1])
	if listLength <= 0 || len(extension) < 2+listLength {
		return []string{}
	}
	protocols := make([]string, 0, 4)
	cursor := 2
	end := 2 + listLength
	for cursor < end {
		nameLength := int(extension[cursor])
		cursor++
		if nameLength == 0 || nameLength > 32 || cursor+nameLength > end {
			break
		}
		name := extension[cursor : cursor+nameLength]
		if printableASCII(name) {
			protocols = append(protocols, string(name))
		}
		cursor += nameLength
	}
	return protocols
}

// printableASCII reports whether the bytes are safe to publish as a protocol
// name (no control characters that could forge a log line).
func printableASCII(data []byte) bool {
	for _, value := range data {
		if value < 0x20 || value > 0x7e {
			return false
		}
	}
	return true
}
