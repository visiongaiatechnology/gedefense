// STATUS: DIAMANT VGT SUPREME
package main

// V6.3.0 AP-7: unified PermitV1 trust object.
//
// A PermitV1 is a bounded, signed statement about one executable identity
// (SHA-256 and inode), the lineage it may appear in and the finding scope it
// explains. It is consumed by the PermitBroker before an active response is
// planned and can only ever suppress or downgrade — never create, elevate or
// authorise a response.
//
// Serialization is strict: unknown fields, unknown trust levels, unknown
// auto-invalidation kinds, malformed hashes, unbounded TTLs and empty required
// fields are rejected. Signature semantics are honest: an object without a
// reachable signing key is stored as `signature = "absent"` and is demoted to
// ANALYST_MODE instead of pretending to be authorised.

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
)

const (
	permitSchemaV1 = "vgt-gedefense-permit-v1"

	// trust levels, ordered from strongest to weakest handling.
	permitTrustAuthorized = "AUTHORIZED"
	permitTrustTolerated  = "TOLERATED"
	permitTrustAnalyst    = "ANALYST_MODE"

	// permitSignatureAbsent is the explicit, non-fake signature state of a
	// permit that could not be signed. It is never accepted as AUTHORIZED.
	permitSignatureAbsent = "absent"

	permitMaxObjectBytes = 256 << 10
	// The plaintext bound is what the broker may persist; the file bound leaves
	// room for the AES-GCM/HMAC envelope encoding so a full store always loads.
	permitMaxStorePlaintextBytes = 4 << 20
	permitMaxStoreFileBytes      = 8 << 20
	permitMaxStorePermits        = 512
	permitMaxIDLength            = 64
	permitMaxParents             = 8
	permitMaxScopeRules          = 64
	permitMaxScopeCats           = 16
	permitMaxScopePaths          = 16
	permitMaxInvalidateOn        = 4
	permitMaxPathBytes           = 4096
	permitMaxFieldBytes          = 512
	permitHashHexBytes           = sha256.Size * 2
	permitSignatureHexBytes      = ed25519.SignatureSize * 2
	permitPublicKeyHexBytes      = ed25519.PublicKeySize * 2

	permitMaxTTLTolerated      = 24 * time.Hour
	permitMaxTTLAnalyst        = 24 * time.Hour
	permitMaxTTLAuthorized     = 30 * 24 * time.Hour
	permitDefaultTTLTolerated  = 30 * time.Minute
	permitDefaultTTLAuthorized = 24 * time.Hour

	permitStorePurpose     = "xdr-permit-broker"
	permitStoreSchema      = "vgt-gedefense-permit-store-v1"
	permitStoreHMACSchema  = "vgt-gedefense-permit-store-hmac-v1"
	permitSignatureDomain  = "VGT-GEDEFENSE-PERMIT-V1\x00"
	permitStoreFileName    = "permits.json"
	permitStoreKeyFileName = "permits.key"
)

// permitAutoInvalidateKinds is the closed set of events a stored permit may be
// invalidated by. An unknown kind makes the object invalid.
var permitAutoInvalidateKinds = map[string]struct{}{
	"binary_changed":      {},
	"baseline_rebaseline": {},
	"policy_update":       {},
	"rule_update":         {},
}

// permitTrustLevels is the closed set of trust levels.
var permitTrustLevels = map[string]struct{}{
	permitTrustAuthorized: {},
	permitTrustTolerated:  {},
	permitTrustAnalyst:    {},
}

// nonSuppressibleRuleIDs and nonSuppressibleRulePrefixes name findings that no
// permit may ever suppress. They are kernel-proven or integrity events whose
// entire purpose is to reach the operator even when a toolchain profile
// matches: a permit can explain a development workflow, never a credential
// read the kernel already denied or a self-tamper of the product itself.
var nonSuppressibleRuleIDs = map[string]struct{}{
	"XDR.CREDENTIAL_READ_BLOCKED": {},
	"XDR.SELF_TAMPER":             {},
	"XDR.BPF_ROOTKIT_HELPER":      {},
}

var nonSuppressibleRulePrefixes = []string{
	"MALWARE.",
	"XDR.RANSOM_",
}

// PermitInode pins the executable file identity (device + inode). Name and path
// are spoofable; the inode is what the kernel already uses for the trust gates.
type PermitInode struct {
	Device uint64 `json:"dev"`
	Inode  uint64 `json:"ino"`
}

// PermitScope bounds what a permit may explain: rule patterns, finding
// categories and executable path prefixes. An empty scope is invalid; a permit
// may never match every finding by accident.
type PermitScope struct {
	// Rules holds exact rule IDs or prefix patterns ending in "." or "*".
	Rules []string `json:"rules,omitempty"`
	// Categories holds finding categories that must all be present.
	Categories []string `json:"categories,omitempty"`
	// PathPrefixes restricts the executable path of the permitted process.
	PathPrefixes []string `json:"path_prefixes,omitempty"`
}

// PermitV1 is the persisted trust object. Path is an additive extension: it
// names the executable whose SHA-256/inode the permit pins so that
// auto_invalidate_on=binary_changed can be re-verified periodically. It is
// required exactly when binary_changed invalidation is requested.
type PermitV1 struct {
	Schema           string      `json:"schema"`
	PermitID         string      `json:"permit_id"`
	TrustLevel       string      `json:"trust_level"`
	SHA256           string      `json:"sha256"`
	Inode            PermitInode `json:"inode"`
	Path             string      `json:"path,omitempty"`
	AllowedParents   []string    `json:"allowed_parents,omitempty"`
	Scope            PermitScope `json:"scope"`
	ValidFrom        time.Time   `json:"valid_from"`
	ValidUntil       time.Time   `json:"valid_until"`
	AutoInvalidateOn []string    `json:"auto_invalidate_on,omitempty"`
	Signer           string      `json:"signer,omitempty"`
	Signature        string      `json:"signature"`
}

// PermitReport is the bounded read-only projection of the broker store state.
// It never includes permit paths or signatures that an operator surface would
// have to sanitise again.
type PermitReport struct {
	Loaded          bool              `json:"loaded"`
	StorePath       string            `json:"store_path,omitempty"`
	Corrupt         bool              `json:"corrupt"`
	Degraded        bool              `json:"degraded,omitempty"`
	DegradedReason  string            `json:"degraded_reason,omitempty"`
	Stored          int               `json:"stored"`
	BuiltinProfiles int               `json:"builtin_profiles"`
	Expired         int               `json:"expired,omitempty"`
	Authorized      int               `json:"authorized"`
	Tolerated       int               `json:"tolerated"`
	AnalystOnly     int               `json:"analyst_only"`
	Dropped         map[string]uint64 `json:"dropped,omitempty"`
	NextExpiry      *time.Time        `json:"next_expiry,omitempty"`
	// SignatureStatus is "attached" when an Ed25519 verification key is bound
	// and "absent" when no key is reachable. It never claims a signature the
	// broker could not verify.
	SignatureStatus string `json:"signature_status"`
}

// permitSigningDocument is the canonical byte source of a permit signature.
// Integers are used for the validity window so a timezone or monotonic-clock
// representation can never change the bytes a signature covers.
type permitSigningDocument struct {
	Schema           string      `json:"schema"`
	PermitID         string      `json:"permit_id"`
	TrustLevel       string      `json:"trust_level"`
	SHA256           string      `json:"sha256"`
	Inode            PermitInode `json:"inode"`
	Path             string      `json:"path,omitempty"`
	AllowedParents   []string    `json:"allowed_parents,omitempty"`
	Scope            PermitScope `json:"scope"`
	ValidFromNanos   int64       `json:"valid_from_unix_nano"`
	ValidUntilNanos  int64       `json:"valid_until_unix_nano"`
	AutoInvalidateOn []string    `json:"auto_invalidate_on,omitempty"`
	Signer           string      `json:"signer"`
}

func permitIsHex(value string, wantBytes int) bool {
	if len(value) != wantBytes*2 {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == wantBytes
}

// validPermitID accepts 16 to 32 random bytes rendered as lowercase hex. The
// width is an explicit contract with the evidence ledger and the API.
func validPermitID(value string) bool {
	if len(value) < 32 || len(value) > permitMaxIDLength || len(value)%2 != 0 {
		return false
	}
	for _, character := range value {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}

// newPermitID mints a 32-hex-character (128 bit) unpinned broker identifier.
func newPermitID() (string, error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", errors.New("permit identifier random source unavailable")
	}
	return hex.EncodeToString(raw), nil
}

// permitMaxTTL returns the bounded maximum validity window for one trust level.
func permitMaxTTL(trustLevel string) time.Duration {
	switch trustLevel {
	case permitTrustAuthorized:
		return permitMaxTTLAuthorized
	case permitTrustTolerated:
		return permitMaxTTLTolerated
	case permitTrustAnalyst:
		return permitMaxTTLAnalyst
	default:
		return 0
	}
}

func validPermitPath(value string) bool {
	if value == "" || len(value) > permitMaxPathBytes || !strings.HasPrefix(value, "/") ||
		strings.ContainsRune(value, '\x00') || strings.Contains(value, "..") {
		return false
	}
	return true
}

func validPermitField(value string) bool {
	if value == "" || len(value) > permitMaxFieldBytes {
		return false
	}
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return false
		}
	}
	return true
}

// validatePermitV1 enforces the structural contract of one persisted permit.
// It does not verify the signature (the store loader does that with the bound
// verifier) and it does not reject an already-expired window: an expired permit
// is structurally valid and is pruned by the maintenance pass with a counted
// reason instead of being silently dropped at read time.
func validatePermitV1(p *PermitV1, now time.Time) error {
	if p == nil {
		return errors.New("permit object is missing")
	}
	if p.Schema != permitSchemaV1 {
		return errors.New("permit schema is invalid")
	}
	if !validPermitID(p.PermitID) {
		return errors.New("permit identifier is invalid")
	}
	if _, ok := permitTrustLevels[p.TrustLevel]; !ok {
		return errors.New("permit trust level is invalid")
	}
	if !permitIsHex(p.SHA256, sha256.Size) {
		return errors.New("permit executable hash is invalid")
	}
	if p.Inode.Inode == 0 {
		return errors.New("permit inode identity is missing")
	}
	if p.Path != "" && !validPermitPath(p.Path) {
		return errors.New("permit executable path is invalid")
	}
	if len(p.AllowedParents) > permitMaxParents {
		return errors.New("permit parent lineage exceeds its bound")
	}
	for _, parent := range p.AllowedParents {
		if !validPermitField(parent) || strings.ContainsAny(parent, " \t") {
			return errors.New("permit parent lineage entry is invalid")
		}
	}
	if err := validatePermitScope(p.Scope); err != nil {
		return err
	}
	if p.ValidFrom.IsZero() || p.ValidUntil.IsZero() {
		return errors.New("permit validity window is missing")
	}
	ttl := p.ValidUntil.Sub(p.ValidFrom)
	if ttl <= 0 {
		return errors.New("permit validity window is inverted")
	}
	maxTTL := permitMaxTTL(p.TrustLevel)
	if maxTTL <= 0 || ttl > maxTTL {
		return errors.New("permit validity window exceeds the trust-level bound")
	}
	// A permit that claims a validity start far in the future is a mistake in
	// the signing workflow, not a trust statement; refuse instead of keeping a
	// dormant object that suddenly becomes active.
	if p.ValidFrom.After(now.Add(24 * time.Hour)) {
		return errors.New("permit validity start is implausibly far in the future")
	}
	if len(p.AutoInvalidateOn) > permitMaxInvalidateOn {
		return errors.New("permit auto-invalidation list exceeds its bound")
	}
	seenInvalidation := make(map[string]struct{}, len(p.AutoInvalidateOn))
	for _, kind := range p.AutoInvalidateOn {
		if _, ok := permitAutoInvalidateKinds[kind]; !ok {
			return errors.New("permit auto-invalidation kind is invalid")
		}
		if _, duplicate := seenInvalidation[kind]; duplicate {
			return errors.New("permit auto-invalidation kind is duplicated")
		}
		seenInvalidation[kind] = struct{}{}
	}
	if p.Signature != permitSignatureAbsent && !permitIsHex(p.Signature, ed25519.SignatureSize) {
		return errors.New("permit signature is malformed")
	}
	if p.Signature != permitSignatureAbsent && !permitIsHex(p.Signer, ed25519.PublicKeySize) {
		return errors.New("permit signer is malformed")
	}
	if p.Signature == permitSignatureAbsent && p.Signer != "" {
		return errors.New("permit carries a signer without a signature")
	}
	if len(p.AutoInvalidateOn) > 0 {
		for _, kind := range p.AutoInvalidateOn {
			if kind == "binary_changed" && p.Path == "" {
				return errors.New("permit requests binary re-validation without an executable path")
			}
		}
	}
	return nil
}

func validatePermitScope(scope PermitScope) error {
	if len(scope.Rules) == 0 && len(scope.Categories) == 0 && len(scope.PathPrefixes) == 0 {
		return errors.New("permit scope is empty")
	}
	if len(scope.Rules) > permitMaxScopeRules || len(scope.Categories) > permitMaxScopeCats ||
		len(scope.PathPrefixes) > permitMaxScopePaths {
		return errors.New("permit scope exceeds its bounds")
	}
	for _, rule := range scope.Rules {
		if !validPermitField(rule) || strings.ContainsAny(rule, " \t") {
			return errors.New("permit scope rule is invalid")
		}
	}
	for _, category := range scope.Categories {
		if !validPermitField(category) || strings.ContainsAny(category, " \t") {
			return errors.New("permit scope category is invalid")
		}
	}
	for _, prefix := range scope.PathPrefixes {
		if !validPermitPath(prefix) {
			return errors.New("permit scope path prefix is invalid")
		}
	}
	return nil
}

// permitCanonicalBytes returns the deterministic byte source of the Ed25519
// signature. encoding/json writes struct fields in declaration order and the
// object contains no maps, so the bytes are stable across processes.
func permitCanonicalBytes(p *PermitV1) ([]byte, error) {
	if p == nil {
		return nil, errors.New("permit object is missing")
	}
	document := permitSigningDocument{
		Schema:           p.Schema,
		PermitID:         p.PermitID,
		TrustLevel:       p.TrustLevel,
		SHA256:           p.SHA256,
		Inode:            p.Inode,
		Path:             p.Path,
		AllowedParents:   append([]string(nil), p.AllowedParents...),
		Scope:            PermitScope{Rules: append([]string(nil), p.Scope.Rules...), Categories: append([]string(nil), p.Scope.Categories...), PathPrefixes: append([]string(nil), p.Scope.PathPrefixes...)},
		ValidFromNanos:   p.ValidFrom.UTC().UnixNano(),
		ValidUntilNanos:  p.ValidUntil.UTC().UnixNano(),
		AutoInvalidateOn: append([]string(nil), p.AutoInvalidateOn...),
		Signer:           p.Signer,
	}
	return json.Marshal(document)
}

// SignPermitObject signs a permit with the existing Ed25519 signing key and
// records the signer public key in the object. It never fabricates a signature:
// without a usable private key the caller must leave signature="absent" and the
// object is treated as ANALYST_MODE-only by the store loader.
func SignPermitObject(p *PermitV1, privateKey ed25519.PrivateKey) error {
	if p == nil || len(privateKey) != ed25519.PrivateKeySize {
		return errors.New("permit signing key is invalid")
	}
	publicKey, ok := privateKey.Public().(ed25519.PublicKey)
	if !ok || len(publicKey) != ed25519.PublicKeySize {
		return errors.New("permit signing key is invalid")
	}
	p.Signer = hex.EncodeToString(publicKey)
	payload, err := permitCanonicalBytes(p)
	if err != nil {
		return err
	}
	message := make([]byte, 0, len(permitSignatureDomain)+len(payload))
	message = append(message, permitSignatureDomain...)
	message = append(message, payload...)
	p.Signature = hex.EncodeToString(ed25519.Sign(privateKey, message))
	return nil
}

// verifyPermitObject checks the Ed25519 signature over the canonical bytes.
func verifyPermitObject(p *PermitV1, publicKey ed25519.PublicKey) error {
	if p == nil || len(publicKey) != ed25519.PublicKeySize {
		return errors.New("permit verification key is unavailable")
	}
	if p.Signature == permitSignatureAbsent {
		return errors.New("permit is unsigned")
	}
	signature, err := hex.DecodeString(p.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return errors.New("permit signature is malformed")
	}
	signer, err := hex.DecodeString(p.Signer)
	if err != nil || len(signer) != ed25519.PublicKeySize {
		return errors.New("permit signer is malformed")
	}
	if !strings.EqualFold(hex.EncodeToString(signer), hex.EncodeToString(publicKey)) {
		return errors.New("permit was signed by an unknown signer")
	}
	payload, err := permitCanonicalBytes(p)
	if err != nil {
		return err
	}
	message := make([]byte, 0, len(permitSignatureDomain)+len(payload))
	message = append(message, permitSignatureDomain...)
	message = append(message, payload...)
	if !ed25519.Verify(publicKey, message, signature) {
		return errors.New("permit signature verification failed")
	}
	return nil
}

// decodePermitObject strictly decodes one permit object. It is the shared
// parser behind the store loader and FuzzPermitV1Decode: unknown fields,
// trailing data and every structural violation are refused.
func decodePermitObject(raw []byte, now time.Time) (*PermitV1, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return nil, errors.New("permit object is empty")
	}
	if len(trimmed) > permitMaxObjectBytes {
		return nil, errors.New("permit object exceeds its size bound")
	}
	decoder := json.NewDecoder(bytes.NewReader(trimmed))
	decoder.DisallowUnknownFields()
	var permit PermitV1
	if err := decoder.Decode(&permit); err != nil {
		return nil, fmt.Errorf("permit object: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, errors.New("permit object contains trailing data")
	}
	if err := validatePermitV1(&permit, now); err != nil {
		return nil, err
	}
	return &permit, nil
}
