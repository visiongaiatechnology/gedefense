// SPDX-FileCopyrightText: 2026 VisionGaia Technology
// SPDX-License-Identifier: AGPL-3.0-only

package main

// Local boot-trust fallback for hosts without UEFI Secure Boot, a TPM or the
// AstraeaOS measured-boot attestation.
//
// On such a host the boot chain cannot be verified by firmware evidence, but it
// can still be verified by the operator: a signed baseline over the exact boot
// artifacts (kernel image digest, kernel command line digest, lockdown mode and
// Secure Boot expectation). The baseline is signed with an Ed25519 operator key
// pinned at a fixed path; the probe verifies the signature before it compares a
// single field, and the claim level stays strictly below a platform attestation.
//
// When neither a platform attestation nor a signed baseline exists, the module
// reports NOT_SUPPORTED together with the host facts it observed. That is a
// platform property, not a failure: the boot layer is not red on a host that
// has no hardware root of trust to offer.

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
)

const (
	bootTrustStatusVerified     = "VERIFIED"
	bootTrustStatusObserve      = "OBSERVE"
	bootTrustStatusNotSupported = "NOT_SUPPORTED"

	bootClaimEvidenceOnly  = "evidence-only"
	bootClaimLocalBaseline = "local-signed-baseline"
	bootClaimAttestation   = "local-attestation"

	localBootBaselinePath   = "/var/lib/vgt/gedefense/boot-baseline.json"
	localBootSignaturePath  = "/var/lib/vgt/gedefense/boot-baseline.json.sig"
	localBootPublicKeyPath  = "/etc/vgt/gedefense/boot-baseline.ed25519.pub"
	localBootBaselineSchema = "vgt-gedefense-boot-baseline-v1"
	localBootMaxBytes       = int64(32 << 10)
	localBootMaxKeyBytes    = int64(4 << 10)
)

// localSignedBootBaseline is the signed operator document. It is intentionally
// small and versioned: a verifier that cannot read it exactly refuses it.
type localSignedBootBaseline struct {
	Schema        string    `json:"schema"`
	CreatedAt     time.Time `json:"created_at"`
	KernelSHA256  string    `json:"kernel_sha256"`
	KernelSource  string    `json:"kernel_source,omitempty"`
	CmdlineSHA256 string    `json:"cmdline_sha256"`
	Lockdown      string    `json:"lockdown"`
	SecureBoot    bool      `json:"secure_boot,omitempty"`
	Operator      string    `json:"operator,omitempty"`
	Note          string    `json:"note,omitempty"`
}

// finishBootTrustReport derives the claim level, the hardware root-of-trust
// verdict and the honest module status from the collected evidence.
func finishBootTrustReport(report *BootTrustReport, attestation, baseline BootTrustEvidence) {
	secureBoot := bootReportItem(report.Items, "secure-boot")
	tpm := bootReportItem(report.Items, "tpm")
	report.HardwareRootOfTrust = secureBoot.State == bootStateEnabled || tpm.State == bootStateObserved

	switch {
	case attestation.State == bootStateEnabled:
		report.ClaimLevel = bootClaimAttestation
	case baseline.State == bootStateEnabled:
		report.ClaimLevel = bootClaimLocalBaseline
	default:
		report.ClaimLevel = bootClaimEvidenceOnly
	}

	reasons := make([]string, 0, 3)
	if secureBoot.State != bootStateEnabled {
		reasons = append(reasons, "no-uefi-secure-boot")
	}
	if tpm.State != bootStateObserved {
		reasons = append(reasons, "no-tpm")
	}
	if !report.AstraeaOS {
		reasons = append(reasons, "no-astraeaos")
	}
	report.NotSupportedReasons = reasons

	switch {
	case report.ClaimLevel != bootClaimEvidenceOnly:
		report.Status = bootTrustStatusVerified
	case baseline.State == bootStateWarning || attestation.State == bootStateWarning:
		// A configured operator baseline exists but its signature or the observed
		// boot artifacts do not match. That is a visible OBSERVE condition, not a
		// platform without a root of trust: hiding it as NOT_SUPPORTED would make
		// a tampered boot chain look like absent hardware.
		report.Status = bootTrustStatusObserve
	case !report.HardwareRootOfTrust:
		// No firmware root of trust and no signed operator baseline: the module
		// cannot verify anything on this host. Report the platform fact.
		report.Status = bootTrustStatusNotSupported
	default:
		report.Status = bootTrustStatusObserve
	}
}

func bootReportItem(items []BootTrustEvidence, id string) BootTrustEvidence {
	for _, item := range items {
		if item.ID == id {
			return item
		}
	}
	return BootTrustEvidence{}
}

// localBootBaselineEvidence verifies the operator-signed local boot baseline
// against the evidence already collected for this boot. It never returns an
// enabled state without a valid signature and a field-by-field match.
func (p bootTrustProbe) localBootBaselineEvidence(items []BootTrustEvidence) BootTrustEvidence {
	const id = "local-boot-baseline"
	raw, err := p.readBounded(localBootBaselinePath, localBootMaxBytes)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return BootTrustEvidence{
				ID: id, State: bootStateNotAvailable,
				Summary: "No operator-signed local boot baseline is provisioned; an attestation or signed baseline is required to verify this boot chain.",
				Source:  localBootBaselinePath,
			}
		}
		return BootTrustEvidence{
			ID: id, State: bootStateUnknown,
			Summary: "The local boot baseline is present but could not be read safely.",
			Source:  localBootBaselinePath,
		}
	}
	if err := p.checkOperatorSignedFile(localBootBaselinePath); err != nil {
		return localBootWarning(id, "The local boot baseline is not owned by root or is writable by another account.")
	}
	publicRaw, err := p.readBounded(localBootPublicKeyPath, localBootMaxKeyBytes)
	if err != nil {
		return localBootWarning(id, "The operator public key for the local boot baseline is missing or unreadable.")
	}
	signatureRaw, err := p.readBounded(localBootSignaturePath, localBootMaxKeyBytes)
	if err != nil {
		return localBootWarning(id, "The local boot baseline has no readable detached signature.")
	}
	if err := p.checkOperatorSignedFile(localBootPublicKeyPath); err != nil {
		return localBootWarning(id, "The operator public key is not owned by root or is writable by another account.")
	}
	publicKey, err := decodeEd25519PublicKey(string(publicRaw))
	if err != nil {
		return localBootWarning(id, "The operator public key is not a valid Ed25519 key.")
	}
	signature, err := decodeEd25519Signature(string(signatureRaw))
	if err != nil {
		return localBootWarning(id, "The detached boot-baseline signature is malformed.")
	}
	if !ed25519.Verify(publicKey, raw, signature) {
		return localBootWarning(id, "The detached boot-baseline signature does not verify against the pinned operator key.")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var baseline localSignedBootBaseline
	if err := decoder.Decode(&baseline); err != nil {
		return localBootWarning(id, "The signed local boot baseline is not valid JSON in the expected schema.")
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return localBootWarning(id, "The signed local boot baseline contains trailing data.")
	}
	if baseline.Schema != localBootBaselineSchema || baseline.CreatedAt.IsZero() ||
		!validSHA256(baseline.KernelSHA256) || !validSHA256(baseline.CmdlineSHA256) ||
		baselineLockdownRank(baseline.Lockdown) < 0 {
		return localBootWarning(id, "The signed local boot baseline is structurally invalid.")
	}

	kernel := bootReportItem(items, "kernel-image")
	if !strings.EqualFold(kernel.Digest, baseline.KernelSHA256) {
		return localBootWarning(id, fmt.Sprintf(
			"The kernel image does not match the signed local baseline (signed=%s observed=%s).",
			shortDigest(baseline.KernelSHA256), shortDigest(kernel.Digest)))
	}
	cmdline := bootReportItem(items, "kernel-cmdline")
	if !strings.EqualFold(cmdline.Digest, baseline.CmdlineSHA256) {
		return localBootWarning(id, fmt.Sprintf(
			"The kernel command line does not match the signed local baseline (signed=%s observed=%s).",
			shortDigest(baseline.CmdlineSHA256), shortDigest(cmdline.Digest)))
	}
	lockdownMode, lockdownKnown := bootLockdownMode(items)
	if !lockdownKnown || baselineLockdownRank(lockdownMode) < baselineLockdownRank(baseline.Lockdown) {
		return localBootWarning(id, fmt.Sprintf(
			"Kernel lockdown is %q but the signed local baseline requires at least %q.", lockdownMode, baseline.Lockdown))
	}
	if baseline.SecureBoot && bootReportItem(items, "secure-boot").State != bootStateEnabled {
		return localBootWarning(id, "The signed local boot baseline requires UEFI Secure Boot, but it is not enabled.")
	}
	digest := sha256.Sum256(raw)
	return BootTrustEvidence{
		ID: id, State: bootStateEnabled,
		Summary: "The operator-signed local boot baseline matches the current kernel image, command line and lockdown mode.",
		Source:  localBootBaselinePath,
		Evidence: fmt.Sprintf("kernel=%s cmdline=%s lockdown=%s secure_boot=%t",
			shortDigest(baseline.KernelSHA256), shortDigest(baseline.CmdlineSHA256), baseline.Lockdown, baseline.SecureBoot),
		Digest: hex.EncodeToString(digest[:]),
	}
}

func localBootWarning(id, summary string) BootTrustEvidence {
	return BootTrustEvidence{
		ID: id, State: bootStateWarning, Summary: summary, Source: localBootBaselinePath,
	}
}

func shortDigest(digest string) string {
	digest = strings.ToLower(strings.TrimSpace(digest))
	if digest == "" {
		return "none"
	}
	if len(digest) > 12 {
		return digest[:12]
	}
	return digest
}

func baselineLockdownRank(mode string) int {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "none":
		return 0
	case "integrity":
		return 1
	case "confidentiality":
		return 2
	default:
		return -1
	}
}

// bootLockdownMode extracts the active lockdown mode from the collected
// kernel-lockdown evidence (the kernel publishes it bracketed, e.g.
// "none integrity [confidentiality]").
func bootLockdownMode(items []BootTrustEvidence) (string, bool) {
	evidence := bootReportItem(items, "kernel-lockdown")
	for _, field := range strings.Fields(evidence.Evidence) {
		candidate := strings.Trim(field, "[]")
		if baselineLockdownRank(candidate) >= 0 {
			if strings.HasPrefix(field, "[") {
				return strings.ToLower(candidate), true
			}
		}
	}
	return "", false
}

// checkOperatorSignedFile refuses to trust a signing input that a non-root
// account could have written. Tests use a re-rooted probe and skip the check.
func (p bootTrustProbe) checkOperatorSignedFile(unixPath string) error {
	if p.root != "" {
		return nil
	}
	info, err := os.Lstat(p.resolve(unixPath))
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return errors.New("operator-signed file is not a regular file")
	}
	if info.Mode().Perm()&0o022 != 0 {
		return errors.New("operator-signed file is group or world writable")
	}
	if os.Geteuid() == 0 {
		stat, ok := fileInfoUid(info)
		if !ok || stat != 0 {
			return errors.New("operator-signed file is not owned by root")
		}
	}
	return nil
}

// decodeEd25519PublicKey accepts the two shapes an operator tool produces: the
// raw 32-byte key as 64 lowercase hex characters, or an OpenSSH
// "ssh-ed25519 AAAA..." public key line.
func decodeEd25519PublicKey(raw string) (ed25519.PublicKey, error) {
	value := strings.TrimSpace(raw)
	if len(value) == ed25519.PublicKeySize*2 {
		decoded, err := hex.DecodeString(strings.ToLower(value))
		if err != nil {
			return nil, err
		}
		return ed25519.PublicKey(decoded), nil
	}
	fields := strings.Fields(value)
	if len(fields) >= 2 && fields[0] == "ssh-ed25519" {
		blob, err := base64.StdEncoding.DecodeString(fields[1])
		if err != nil {
			return nil, err
		}
		// OpenSSH wire format: uint32 len("ssh-ed25519"), type, uint32 len(32), key.
		keyType, rest, ok := readSSHString(blob)
		if !ok || string(keyType) != "ssh-ed25519" {
			return nil, errors.New("not an ssh-ed25519 key")
		}
		keyBytes, _, ok := readSSHString(rest)
		if !ok || len(keyBytes) != ed25519.PublicKeySize {
			return nil, errors.New("ssh-ed25519 key has an invalid length")
		}
		return ed25519.PublicKey(keyBytes), nil
	}
	return nil, errors.New("unsupported Ed25519 public key encoding")
}

func readSSHString(blob []byte) ([]byte, []byte, bool) {
	if len(blob) < 4 {
		return nil, nil, false
	}
	length := int(blob[0])<<24 | int(blob[1])<<16 | int(blob[2])<<8 | int(blob[3])
	if length < 1 || length > len(blob)-4 {
		return nil, nil, false
	}
	return blob[4 : 4+length], blob[4+length:], true
}

// decodeEd25519Signature accepts 128 hex characters or standard/base64url
// encoded 64-byte signatures.
func decodeEd25519Signature(raw string) ([]byte, error) {
	value := strings.TrimSpace(raw)
	if len(value) == ed25519.SignatureSize*2 {
		decoded, err := hex.DecodeString(strings.ToLower(value))
		if err == nil {
			return decoded, nil
		}
	}
	for _, encoding := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if decoded, err := encoding.DecodeString(value); err == nil && len(decoded) == ed25519.SignatureSize {
			return decoded, nil
		}
	}
	return nil, errors.New("signature must be 64 bytes in hex or base64")
}
