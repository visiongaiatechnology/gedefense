package main

import (
	"crypto/md5"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	maxTLSFingerprintFileBytes = 4 << 20
	tlsBehaviorWindow          = 10 * time.Second
	tlsHostCorrelationWindow   = 60 * time.Second
	tlsSNIStrikeWindow         = 5 * time.Minute
	maxTLSCipherSuites         = 512
	maxTLSExtensions           = 256
	maxTLSGroups               = 256
	maxTLSPointFormats         = 64
)

// TLSClientHelloSummary is the bounded metadata extracted from one TLS
// ClientHello. Payload bytes are never retained after inspection.
type TLSClientHelloSummary struct {
	JA3Hash         string   `json:"ja3_hash"`
	RawJA3String    string   `json:"raw_ja3_string"`
	SNI             string   `json:"sni,omitempty"`
	HasALPN         bool     `json:"has_alpn"`
	HasGREASE       bool     `json:"has_grease"`
	CipherSuites    []uint16 `json:"cipher_suites,omitempty"`
	Extensions      []uint16 `json:"extensions,omitempty"`
	Curves          []uint16 `json:"curves,omitempty"`
	PointFormats    []uint8  `json:"point_formats,omitempty"`
	Malformed       bool     `json:"malformed"`
	DirectIPInSNI   bool     `json:"direct_ip_in_sni"`
	StructuralSpoof bool     `json:"structural_spoof"`
	MaliciousThreat string   `json:"malicious_threat,omitempty"`
}

type TLSBehaviorState struct {
	Handshakes      int
	Requests        int
	LastReset       time.Time
	FirstSeen       time.Time
	LastSeen        time.Time
	LastTLS         time.Time
	LastSNI         string
	LastJA3         string
	LastFloodAt     time.Time
	SNIViolations   int
	SNIWindowStart  time.Time
	LastSNIStrikeAt time.Time
}

type TLSFingerprintSignature struct {
	JA3      string `json:"ja3"`
	Name     string `json:"name"`
	Severity string `json:"severity,omitempty"`
}

type TLSFingerprintProfile struct {
	JA3           string `json:"ja3"`
	Name          string `json:"name"`
	RequireALPN   bool   `json:"require_alpn"`
	RequireGREASE bool   `json:"require_grease"`
}

type TLSFingerprintSet struct {
	Version    int                       `json:"version"`
	Signatures []TLSFingerprintSignature `json:"signatures"`
	Profiles   []TLSFingerprintProfile   `json:"profiles"`
}

// TLSSecurityEngine provides native, bounded TLS/SNI/JA3 telemetry. JA3 data
// is operator supplied from a local file. GeDefense deliberately ships no
// made-up "malicious" hashes and never performs a network lookup here.
type TLSSecurityEngine struct {
	mu                 sync.RWMutex
	allowedDomains     map[string]struct{}
	maliciousJA3       map[string]TLSFingerprintSignature
	profiles           map[string]TLSFingerprintProfile
	behavior           map[string]*TLSBehaviorState
	behaviorRing       []string
	behaviorNext       int
	floodThreshold     int
	sniStrikeThreshold int
	antiSpoof          bool
	maxTrackedClients  int
	fingerprintVersion int
	fingerprintSource  string
}

func NewTLSSecurityEngine(allowedDomains []string, floodThreshold, sniStrikeThreshold int, antiSpoof bool, maxTracked ...int) *TLSSecurityEngine {
	if floodThreshold <= 0 {
		floodThreshold = 15
	}
	if sniStrikeThreshold <= 0 {
		sniStrikeThreshold = 10
	}
	limit := 65536
	if len(maxTracked) > 0 && maxTracked[0] > 0 {
		limit = maxTracked[0]
	}
	eng := &TLSSecurityEngine{
		allowedDomains:     make(map[string]struct{}),
		maliciousJA3:       make(map[string]TLSFingerprintSignature),
		profiles:           make(map[string]TLSFingerprintProfile),
		behavior:           make(map[string]*TLSBehaviorState),
		behaviorRing:       make([]string, 0, limit),
		floodThreshold:     floodThreshold,
		sniStrikeThreshold: sniStrikeThreshold,
		antiSpoof:          antiSpoof,
		maxTrackedClients:  limit,
	}
	for _, d := range allowedDomains {
		d = normalizeTLSHostname(d)
		if d != "" {
			eng.allowedDomains[d] = struct{}{}
		}
	}
	return eng
}

// UpdatePolicy republishes the administrable TLS detection policy. The write
// lock guarantees that a handshake in flight observes either the previous
// policy or the new one, never a mixture of the two.
func (e *TLSSecurityEngine) UpdatePolicy(allowedDomains []string, floodThreshold, sniStrikeThreshold int, antiSpoof bool) {
	if e == nil {
		return
	}
	if floodThreshold <= 0 {
		floodThreshold = 15
	}
	if sniStrikeThreshold <= 0 {
		sniStrikeThreshold = 10
	}
	domains := make(map[string]struct{}, len(allowedDomains))
	for _, domain := range allowedDomains {
		domain = normalizeTLSHostname(domain)
		if domain != "" {
			domains[domain] = struct{}{}
		}
	}
	e.mu.Lock()
	e.allowedDomains = domains
	e.floodThreshold = floodThreshold
	e.sniStrikeThreshold = sniStrikeThreshold
	e.antiSpoof = antiSpoof
	e.mu.Unlock()
}

// KnowsFingerprint reports whether a JA3 hash is present in the local signature
// set or the local behavioural profile set. It is the only authority for the
// administrable unknown-fingerprint behaviour.
func (e *TLSSecurityEngine) KnowsFingerprint(ja3 string) bool {
	if e == nil || ja3 == "" {
		return false
	}
	e.mu.RLock()
	defer e.mu.RUnlock()
	if _, ok := e.maliciousJA3[ja3]; ok {
		return true
	}
	_, ok := e.profiles[ja3]
	return ok
}

func isValidJA3Hash(v string) bool {
	if len(v) != 32 {
		return false
	}
	_, err := hex.DecodeString(v)
	return err == nil
}

// LoadFingerprintFile replaces the complete local JA3 signature/profile set
// atomically after strict validation. Symlinks and oversized files are rejected.
func (e *TLSSecurityEngine) LoadFingerprintFile(path string) error {
	if e == nil || strings.TrimSpace(path) == "" {
		return nil
	}
	path = filepath.Clean(path)
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("open TLS fingerprint set: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return errors.New("TLS fingerprint set must be a regular non-symlink file")
	}
	if info.Size() <= 0 || info.Size() > maxTLSFingerprintFileBytes {
		return fmt.Errorf("TLS fingerprint set size must be 1..%d bytes", maxTLSFingerprintFileBytes)
	}
	if info.Mode().Perm()&0o022 != 0 {
		return errors.New("TLS fingerprint set must not be group- or world-writable")
	}
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open TLS fingerprint set: %w", err)
	}
	defer f.Close()
	openedInfo, err := f.Stat()
	if err != nil {
		return fmt.Errorf("stat opened TLS fingerprint set: %w", err)
	}
	if !os.SameFile(info, openedInfo) {
		return errors.New("TLS fingerprint set changed between validation and open")
	}
	dec := json.NewDecoder(io.LimitReader(f, maxTLSFingerprintFileBytes+1))
	dec.DisallowUnknownFields()
	var set TLSFingerprintSet
	if err := dec.Decode(&set); err != nil {
		return fmt.Errorf("decode TLS fingerprint set: %w", err)
	}
	if err := ensureJSONEOF(dec); err != nil {
		return fmt.Errorf("decode TLS fingerprint set: %w", err)
	}
	if set.Version != 1 {
		return fmt.Errorf("unsupported TLS fingerprint set version %d", set.Version)
	}
	if len(set.Signatures) > 10000 || len(set.Profiles) > 10000 {
		return errors.New("TLS fingerprint set exceeds 10000 signatures/profiles")
	}

	sigs := make(map[string]TLSFingerprintSignature, len(set.Signatures))
	for _, sig := range set.Signatures {
		sig.JA3 = strings.ToLower(strings.TrimSpace(sig.JA3))
		sig.Name = strings.TrimSpace(sig.Name)
		if !isValidJA3Hash(sig.JA3) || sig.Name == "" || len(sig.Name) > 200 {
			return fmt.Errorf("invalid TLS JA3 signature entry %q", sig.JA3)
		}
		switch sig.Severity {
		case "", "low", "medium", "high", "critical":
		default:
			return fmt.Errorf("invalid TLS JA3 severity %q", sig.Severity)
		}
		if _, exists := sigs[sig.JA3]; exists {
			return fmt.Errorf("duplicate TLS JA3 signature %q", sig.JA3)
		}
		sigs[sig.JA3] = sig
	}
	profiles := make(map[string]TLSFingerprintProfile, len(set.Profiles))
	for _, profile := range set.Profiles {
		profile.JA3 = strings.ToLower(strings.TrimSpace(profile.JA3))
		profile.Name = strings.TrimSpace(profile.Name)
		if !isValidJA3Hash(profile.JA3) || profile.Name == "" || len(profile.Name) > 200 {
			return fmt.Errorf("invalid TLS JA3 profile entry %q", profile.JA3)
		}
		if _, exists := profiles[profile.JA3]; exists {
			return fmt.Errorf("duplicate TLS JA3 profile %q", profile.JA3)
		}
		profiles[profile.JA3] = profile
	}

	e.mu.Lock()
	e.maliciousJA3 = sigs
	e.profiles = profiles
	e.fingerprintVersion = set.Version
	e.fingerprintSource = path
	e.mu.Unlock()
	return nil
}

func (e *TLSSecurityEngine) FingerprintStatus() (version int, source string, signatures, profiles int) {
	if e == nil {
		return 0, "", 0, 0
	}
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.fingerprintVersion, e.fingerprintSource, len(e.maliciousJA3), len(e.profiles)
}

func isGREASE(v uint16) bool { return (v&0x0f0f) == 0x0a0a && byte(v>>8) == byte(v) }

// ParseClientHello parses one complete TLS ClientHello record. It uses only
// length-checked slices, strips GREASE values from JA3 as required by JA3, and
// does not retain packet payloads.
func ParseClientHello(payload []byte) (TLSClientHelloSummary, error) {
	summary := TLSClientHelloSummary{}
	malformed := func(msg string) (TLSClientHelloSummary, error) {
		summary.Malformed = true
		return summary, errors.New(msg)
	}
	if len(payload) < 43 || payload[0] != 22 || payload[5] != 1 {
		return malformed("not a TLS ClientHello record")
	}
	recordLen := int(binary.BigEndian.Uint16(payload[3:5]))
	recordEnd := 5 + recordLen
	if recordLen < 4 || recordEnd > len(payload) {
		return malformed("truncated TLS record")
	}
	handshakeLen := int(payload[6])<<16 | int(payload[7])<<8 | int(payload[8])
	handshakeEnd := 9 + handshakeLen
	if handshakeLen < 34 || handshakeEnd > recordEnd {
		return malformed("truncated TLS ClientHello")
	}

	clientVersion := binary.BigEndian.Uint16(payload[9:11])
	offset := 43
	if offset >= handshakeEnd {
		return malformed("truncated session id")
	}
	sessionIDLen := int(payload[offset])
	offset++
	if offset+sessionIDLen+2 > handshakeEnd {
		return malformed("truncated session id")
	}
	offset += sessionIDLen

	cipherLen := int(binary.BigEndian.Uint16(payload[offset : offset+2]))
	offset += 2
	cipherCount := cipherLen / 2
	if cipherLen == 0 || cipherLen%2 != 0 || cipherCount > maxTLSCipherSuites || offset+cipherLen > handshakeEnd {
		return malformed("invalid cipher suite list")
	}
	cipherStrs := make([]string, 0, cipherCount)
	for i := 0; i < cipherLen; i += 2 {
		v := binary.BigEndian.Uint16(payload[offset+i : offset+i+2])
		if isGREASE(v) {
			summary.HasGREASE = true
			continue
		}
		summary.CipherSuites = append(summary.CipherSuites, v)
		cipherStrs = append(cipherStrs, fmt.Sprintf("%d", v))
	}
	offset += cipherLen

	if offset >= handshakeEnd {
		return malformed("truncated compression list")
	}
	compLen := int(payload[offset])
	offset++
	if compLen == 0 || offset+compLen > handshakeEnd {
		return malformed("invalid compression list")
	}
	offset += compLen

	extStrs := make([]string, 0, 16)
	curveStrs := make([]string, 0, 16)
	pointStrs := make([]string, 0, 4)
	if offset < handshakeEnd {
		if offset+2 > handshakeEnd {
			return malformed("truncated extension length")
		}
		extLen := int(binary.BigEndian.Uint16(payload[offset : offset+2]))
		offset += 2
		end := offset + extLen
		if end != handshakeEnd {
			return malformed("extension block length does not match ClientHello")
		}
		seenExtensions := make(map[uint16]struct{}, 16)
		extensionCount := 0
		for offset < end {
			if offset+4 > end {
				return malformed("truncated extension header")
			}
			extType := binary.BigEndian.Uint16(payload[offset : offset+2])
			extDataLen := int(binary.BigEndian.Uint16(payload[offset+2 : offset+4]))
			offset += 4
			if offset+extDataLen > end {
				return malformed("truncated extension value")
			}
			extensionCount++
			if extensionCount > maxTLSExtensions {
				return malformed("too many TLS extensions")
			}
			extData := payload[offset : offset+extDataLen]
			offset += extDataLen
			if isGREASE(extType) {
				summary.HasGREASE = true
				continue
			}
			if _, duplicate := seenExtensions[extType]; duplicate {
				return malformed("duplicate TLS extension")
			}
			seenExtensions[extType] = struct{}{}
			summary.Extensions = append(summary.Extensions, extType)
			extStrs = append(extStrs, fmt.Sprintf("%d", extType))

			switch extType {
			case 0: // server_name
				if len(extData) < 5 {
					return malformed("invalid SNI extension")
				}
				listLen := int(binary.BigEndian.Uint16(extData[0:2]))
				if listLen+2 != len(extData) || listLen < 3 {
					return malformed("invalid SNI list")
				}
				pos := 2
				hostNameSeen := false
				for pos < len(extData) {
					if pos+3 > len(extData) {
						return malformed("truncated SNI entry")
					}
					nameType := extData[pos]
					nameLen := int(binary.BigEndian.Uint16(extData[pos+1 : pos+3]))
					pos += 3
					if nameLen == 0 || pos+nameLen > len(extData) {
						return malformed("truncated SNI hostname")
					}
					if nameType == 0 {
						if hostNameSeen {
							return malformed("duplicate SNI host_name")
						}
						host, directIP, err := parseTLSWireHostname(extData[pos : pos+nameLen])
						if err != nil {
							return malformed("invalid SNI hostname: " + err.Error())
						}
						summary.SNI = host
						summary.DirectIPInSNI = directIP
						hostNameSeen = true
					}
					pos += nameLen
				}
			case 16: // ALPN
				if err := validateALPNExtension(extData); err != nil {
					return malformed("invalid ALPN extension: " + err.Error())
				}
				summary.HasALPN = true
			case 10: // supported_groups
				if len(extData) < 4 {
					return malformed("invalid supported groups extension")
				}
				groupsLen := int(binary.BigEndian.Uint16(extData[:2]))
				if groupsLen == 0 || groupsLen%2 != 0 || groupsLen+2 != len(extData) || groupsLen/2 > maxTLSGroups {
					return malformed("invalid supported groups list")
				}
				for pos := 2; pos < len(extData); pos += 2 {
					v := binary.BigEndian.Uint16(extData[pos : pos+2])
					if isGREASE(v) {
						summary.HasGREASE = true
						continue
					}
					summary.Curves = append(summary.Curves, v)
					curveStrs = append(curveStrs, fmt.Sprintf("%d", v))
				}
			case 11: // ec_point_formats
				if len(extData) < 2 {
					return malformed("invalid EC point formats")
				}
				pointCount := int(extData[0])
				if pointCount == 0 || pointCount+1 != len(extData) || pointCount > maxTLSPointFormats {
					return malformed("invalid EC point formats")
				}
				for pos := 1; pos < len(extData); pos++ {
					summary.PointFormats = append(summary.PointFormats, extData[pos])
					pointStrs = append(pointStrs, fmt.Sprintf("%d", extData[pos]))
				}
			}
		}
	}

	summary.RawJA3String = fmt.Sprintf("%d,%s,%s,%s,%s", clientVersion,
		strings.Join(cipherStrs, "-"), strings.Join(extStrs, "-"),
		strings.Join(curveStrs, "-"), strings.Join(pointStrs, "-"))
	sum := md5.Sum([]byte(summary.RawJA3String)) // JA3 is defined as MD5; this is a fingerprint, not evidence integrity.
	summary.JA3Hash = hex.EncodeToString(sum[:])
	return summary, nil
}

func validateALPNExtension(extData []byte) error {
	if len(extData) < 3 {
		return errors.New("protocol list is missing")
	}
	listLen := int(binary.BigEndian.Uint16(extData[:2]))
	if listLen == 0 || listLen+2 != len(extData) {
		return errors.New("protocol list length mismatch")
	}
	pos := 2
	protocols := 0
	for pos < len(extData) {
		nameLen := int(extData[pos])
		pos++
		if nameLen == 0 || pos+nameLen > len(extData) {
			return errors.New("invalid protocol name")
		}
		pos += nameLen
		protocols++
		if protocols > 64 {
			return errors.New("too many ALPN protocols")
		}
	}
	if protocols == 0 {
		return errors.New("empty protocol list")
	}
	return nil
}

func parseTLSWireHostname(raw []byte) (string, bool, error) {
	if len(raw) == 0 || len(raw) > 255 {
		return "", false, errors.New("hostname length out of bounds")
	}
	for _, b := range raw {
		if b <= 0x20 || b >= 0x7f {
			return "", false, errors.New("hostname contains non-ASCII or control bytes")
		}
	}
	host := string(raw)
	if host != strings.TrimSpace(host) {
		return "", false, errors.New("hostname contains surrounding whitespace")
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.String(), true, nil
	}
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if host == "" || len(host) > 253 {
		return "", false, errors.New("DNS name length out of bounds")
	}
	for _, label := range strings.Split(host, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", false, errors.New("invalid DNS label")
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-') {
				return "", false, errors.New("invalid DNS label character")
			}
		}
	}
	return host, false, nil
}

func normalizeTLSHostname(host string) string {
	host = strings.ToLower(strings.TrimSpace(host))
	host = strings.TrimSuffix(host, ".")
	return host
}

func normalizeTLSAllowedPattern(pattern string) (string, error) {
	pattern = normalizeTLSHostname(pattern)
	if pattern == "" {
		return "", errors.New("TLS allowed domain is empty")
	}
	wildcard := strings.HasPrefix(pattern, "*.")
	host := pattern
	if wildcard {
		host = strings.TrimPrefix(pattern, "*.")
		if host == "" || strings.Contains(host, "*") {
			return "", errors.New("invalid TLS wildcard domain")
		}
	} else if strings.Contains(pattern, "*") {
		return "", errors.New("TLS wildcard is only allowed as leading '*.'")
	}
	normalized, directIP, err := parseTLSWireHostname([]byte(host))
	if err != nil {
		return "", err
	}
	if directIP {
		return "", errors.New("TLS allowed domain must be a DNS name, not an IP literal")
	}
	if wildcard {
		return "*." + normalized, nil
	}
	return normalized, nil
}

func allowedTLSHostname(allowed map[string]struct{}, host string) bool {
	if len(allowed) == 0 {
		return true
	}
	host = normalizeTLSHostname(host)
	if _, ok := allowed[host]; ok {
		return true
	}
	for pattern := range allowed {
		if strings.HasPrefix(pattern, "*.") {
			suffix := strings.TrimPrefix(pattern, "*")
			if strings.HasSuffix(host, suffix) && len(host) > len(suffix) {
				return true
			}
		}
	}
	return false
}

func (e *TLSSecurityEngine) ensureBehaviorLocked(clientIP string, now time.Time) *TLSBehaviorState {
	if state, ok := e.behavior[clientIP]; ok {
		state.LastSeen = now
		return state
	}
	if len(e.behaviorRing) < e.maxTrackedClients {
		e.behaviorRing = append(e.behaviorRing, clientIP)
	} else if e.maxTrackedClients > 0 {
		if e.behaviorNext >= len(e.behaviorRing) {
			e.behaviorNext = 0
		}
		victim := e.behaviorRing[e.behaviorNext]
		delete(e.behavior, victim)
		e.behaviorRing[e.behaviorNext] = clientIP
		e.behaviorNext = (e.behaviorNext + 1) % e.maxTrackedClients
	}
	state := &TLSBehaviorState{FirstSeen: now, LastSeen: now, LastReset: now, SNIWindowStart: now}
	e.behavior[clientIP] = state
	return state
}

func (e *TLSSecurityEngine) InspectHandshakeDetailed(clientIP string, payload []byte, now time.Time) (TLSClientHelloSummary, []L7Finding) {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	summary, err := ParseClientHello(payload)
	if err != nil {
		return summary, []L7Finding{{
			RuleID: "TLS.CLIENTHELLO.MALFORMED", Category: "protocol_anomaly", Severity: "medium",
			Score: 45, Confidence: 95, Location: "tls.client_hello", Summary: "Malformed or truncated TLS ClientHello: " + err.Error(),
		}}
	}
	ip := net.ParseIP(clientIP)
	if ip == nil {
		return summary, []L7Finding{{
			RuleID: "TLS.CLIENT_IP.INVALID", Category: "telemetry_integrity", Severity: "medium",
			Score: 40, Confidence: 100, Location: "tls.client_ip", Summary: "TLS telemetry supplied an invalid client IP",
		}}
	}
	clientIP = ip.String()

	e.mu.Lock()
	defer e.mu.Unlock()
	state := e.ensureBehaviorLocked(clientIP, now)
	if now.Sub(state.LastReset) > tlsBehaviorWindow {
		state.Handshakes = 0
		state.Requests = 0
		state.LastReset = now
	}
	state.Handshakes++
	state.LastTLS = now
	state.LastSNI = summary.SNI
	state.LastJA3 = summary.JA3Hash

	findings := make([]L7Finding, 0, 5)
	if sig, ok := e.maliciousJA3[summary.JA3Hash]; ok {
		summary.MaliciousThreat = sig.Name
		severity := sig.Severity
		if severity == "" {
			severity = "critical"
		}
		findings = append(findings, L7Finding{
			RuleID: "TLS.JA3.MALICIOUS", Category: "threat_signature", Severity: severity,
			Score: 150, Confidence: 100, Location: "tls.client_hello.ja3", FingerprintType: "ja3", Fingerprint: summary.JA3Hash,
			Summary: fmt.Sprintf("Local TLS fingerprint set matched %s (%s)", sig.Name, summary.JA3Hash),
		})
	}
	if e.antiSpoof {
		if profile, ok := e.profiles[summary.JA3Hash]; ok {
			missingALPN := profile.RequireALPN && !summary.HasALPN
			missingGREASE := profile.RequireGREASE && !summary.HasGREASE
			if missingALPN || missingGREASE {
				summary.StructuralSpoof = true
				findings = append(findings, L7Finding{
					RuleID: "TLS.JA3.STRUCTURAL_SPOOF", Category: "evasion_detection", Severity: "high",
					Score: 90, Confidence: 90, Location: "tls.client_hello.extensions", FingerprintType: "ja3", Fingerprint: summary.JA3Hash,
					Summary: fmt.Sprintf("TLS fingerprint profile %s is structurally inconsistent with its required extensions", profile.Name),
				})
			}
		}
	}
	sniViolation := false
	if summary.SNI == "" {
		sniViolation = true
		findings = append(findings, L7Finding{
			RuleID: "TLS.SNI.MISSING", Category: "protocol_anomaly", Severity: "low",
			Score: 25, Confidence: 100, Location: "tls.client_hello.sni", Summary: "TLS ClientHello did not contain SNI",
		})
	} else if summary.DirectIPInSNI {
		sniViolation = true
		findings = append(findings, L7Finding{
			RuleID: "TLS.SNI.INVALID", Category: "protocol_anomaly", Severity: "medium",
			Score: 60, Confidence: 95, Location: "tls.client_hello.sni", Summary: fmt.Sprintf("IP literal presented in TLS SNI: %s", summary.SNI),
		})
	} else if !allowedTLSHostname(e.allowedDomains, summary.SNI) {
		sniViolation = true
		findings = append(findings, L7Finding{
			RuleID: "TLS.SNI.FOREIGN", Category: "domain_spoofing", Severity: "high",
			Score: 85, Confidence: 95, Location: "tls.client_hello.sni", Summary: fmt.Sprintf("SNI requested domain outside configured server scope: %s", summary.SNI),
		})
	}
	if now.Sub(state.SNIWindowStart) > tlsSNIStrikeWindow {
		state.SNIViolations = 0
		state.SNIWindowStart = now
	}
	if sniViolation {
		state.SNIViolations++
		if state.SNIViolations >= e.sniStrikeThreshold && (state.LastSNIStrikeAt.IsZero() || now.Sub(state.LastSNIStrikeAt) >= tlsSNIStrikeWindow) {
			state.LastSNIStrikeAt = now
			findings = append(findings, L7Finding{
				RuleID: "TLS.SNI.REPEATED_INVALID", Category: "protocol_anomaly", Severity: "high",
				Score: 100, Confidence: 95, Location: "tls.client_hello.sni",
				Summary: fmt.Sprintf("Client generated %d invalid, missing, or out-of-scope SNI values within %s", state.SNIViolations, tlsSNIStrikeWindow),
			})
		}
	}
	handshakeFlood := state.Handshakes > e.floodThreshold && (state.Requests == 0 || state.Handshakes > (state.Requests*4)+e.floodThreshold)
	if handshakeFlood && (state.LastFloodAt.IsZero() || now.Sub(state.LastFloodAt) >= tlsBehaviorWindow) {
		state.LastFloodAt = now
		findings = append(findings, L7Finding{
			RuleID: "TLS.HANDSHAKE.FLOOD", Category: "resource_exhaustion", Severity: "high",
			Score: 95, Confidence: 90, Location: "tls.handshake_ratio",
			Summary: fmt.Sprintf("Client generated %d TLS handshakes versus %d correlated HTTP requests in %s", state.Handshakes, state.Requests, tlsBehaviorWindow),
		})
	}
	return summary, findings
}

func (e *TLSSecurityEngine) InspectHandshake(clientIP string, payload []byte, now time.Time) []L7Finding {
	_, findings := e.InspectHandshakeDetailed(clientIP, payload, now)
	return findings
}

// RecordHTTPRequest preserves the original Auto-Punisher-style accounting API.
// Rich Host/SNI correlation is performed by RecordHTTPRequestForHost.
func (e *TLSSecurityEngine) RecordHTTPRequest(clientIP string) {
	_ = e.RecordHTTPRequestForHost(clientIP, "", time.Now().UTC())
}

// RecordHTTPRequestForHost correlates application traffic with the most recent
// TLS ClientHello from the same source. It never authorizes process response.
func (e *TLSSecurityEngine) RecordHTTPRequestForHost(clientIP, host string, now time.Time) []L7Finding {
	if e == nil {
		return nil
	}
	ip := net.ParseIP(clientIP)
	if ip == nil {
		return nil
	}
	clientIP = ip.String()
	host = normalizeTLSHostname(host)
	e.mu.Lock()
	defer e.mu.Unlock()
	state := e.ensureBehaviorLocked(clientIP, now)
	if now.Sub(state.LastReset) > tlsBehaviorWindow {
		state.Handshakes = 0
		state.Requests = 0
		state.LastReset = now
	}
	state.Requests++
	if host == "" || state.LastSNI == "" || now.Sub(state.LastTLS) > tlsHostCorrelationWindow {
		return nil
	}
	if state.LastSNI == host || (allowedTLSHostname(e.allowedDomains, state.LastSNI) && allowedTLSHostname(e.allowedDomains, host)) {
		return nil
	}
	return []L7Finding{{
		RuleID: "TLS.HOST_MISMATCH", Category: "domain_spoofing", Severity: "medium",
		Score: 60, Confidence: 80, Location: "http.host", FingerprintType: "ja3", Fingerprint: state.LastJA3,
		Summary: fmt.Sprintf("HTTP Host %s did not match recent TLS SNI %s for the same source", host, state.LastSNI),
	}}
}

// SnapshotBehavior returns a bounded diagnostic view sorted by recent activity.
func (e *TLSSecurityEngine) SnapshotBehavior(limit int) []TLSBehaviorState {
	if e == nil {
		return nil
	}
	if limit <= 0 || limit > 256 {
		limit = 64
	}
	e.mu.RLock()
	out := make([]TLSBehaviorState, 0, minInt(limit, len(e.behavior)))
	for _, state := range e.behavior {
		out = append(out, *state)
	}
	e.mu.RUnlock()
	sort.Slice(out, func(i, j int) bool { return out[i].LastSeen.After(out[j].LastSeen) })
	if len(out) > limit {
		out = out[:limit]
	}
	return out
}

// l7SelfTestEvidenceWindow bounds how long a passing self-test speaks for the path.
//
// The measurement is authoritative while it is recent: it drove a real request through
// the listener and confirmed the engine's own counter moved. It must not speak forever,
// or a path that broke an hour after the test would still be reported as verified.
const l7SelfTestEvidenceWindow = 15 * time.Minute

// InlinePathVerifiedBySelfTest reports whether a recent self-test measured this path
// working. It is the second opinion to InlineHealthy, which is only ever inferred from
// events and can therefore be stale in either direction.
func InlinePathVerifiedBySelfTest(status L7Status, now time.Time) bool {
	if status.SelfTestOutcome != "PASS" || status.SelfTestAt == nil {
		return false
	}
	age := now.Sub(*status.SelfTestAt)
	if age < 0 {
		// A clock that moved backwards is not evidence of anything.
		return false
	}
	return age <= l7SelfTestEvidenceWindow
}

// EvaluateL7Coverage distinguishes service health from verified traffic path.
func EvaluateL7Coverage(status L7Status, uptimeSeconds int64) string {
	if !status.Enabled {
		return "DISABLED"
	}
	if !status.Healthy {
		return "OFFLINE"
	}
	if status.InlineEnabled && !status.InlineHealthy {
		// The flag is cleared but the path was measured working more recently than the
		// event that cleared it. The measurement wins: it is a direct observation, the
		// flag is an inference, and reporting a verified path as degraded is what made a
		// passing self-test contradict the coverage on the same screen.
		if !InlinePathVerifiedBySelfTest(status, time.Now().UTC()) {
			return "INLINE_DEGRADED"
		}
	}
	httpTraffic := status.RequestsTotal + status.InlineRequestsTotal
	traffic := httpTraffic + status.TLSHandshakesTotal
	// Nothing is wired into the engine: no inline listener, and not one request has
	// ever arrived. That is a deliberate or not-yet-finished deployment, and it is a
	// different fact from "something is attached and silent". Reporting the first as
	// NO_TRAFFIC_WARNING is what made an intentionally idle engine degrade the whole
	// platform.
	if !status.InlineEnabled && httpTraffic == 0 && status.TLSHandshakesTotal == 0 {
		return "READY_NOT_ATTACHED"
	}
	// TLS telemetry is only absent if it was required. Reporting TLS_NOT_IN_PATH for
	// a host that never intended to feed ClientHellos made a deliberate configuration
	// look like a broken path - the same mistake as treating an idle engine as a
	// mandatory sensor. CoverageRequired carries the decision; a host that wants TLS
	// visibility sets it, and only then is silence a finding.
	if status.TLSEnabled && status.CoverageRequired && uptimeSeconds > 300 && httpTraffic > 0 && status.TLSHandshakesTotal == 0 {
		return "TLS_NOT_IN_PATH"
	}
	if traffic == 0 && uptimeSeconds > 300 {
		return "NO_TRAFFIC_WARNING"
	}
	if traffic > 0 {
		return "TRAFFIC_ACTIVE"
	}
	return "HEALTHY_AWAITING_TRAFFIC"
}
