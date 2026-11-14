// STATUS: DIAMANT VGT SUPREME

package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	bootStateObserved     = "OBSERVED"
	bootStateEnabled      = "ENABLED"
	bootStateDisabled     = "DISABLED"
	bootStateWarning      = "WARNING"
	bootStateUnknown      = "UNKNOWN"
	bootStateNotAvailable = "NOT_AVAILABLE"

	maxBootTextBytes = 64 << 10
	maxKernelBytes   = 256 << 20

	// Signed AstraeaOS boot attestation contract (FIND-008). Every path is an
	// explicit trust boundary: the pinned Ed25519 key, the detached signature, the
	// systemd TPM PCR signature file and the operator-signed fs-verity manifest.
	bootAttestationSchema          = "astraeaos.boot-attestation.v2"
	bootVerityManifestSchema       = "astraeaos.fsverity-manifest.v1"
	bootAttestationSource          = "/run/astraeaos/boot-attestation.json"
	bootAttestationSignatureSource = "/run/astraeaos/boot-attestation.sig"
	bootAttestationPublicKeySource = "/usr/share/astraeaos/boot-trust/attestation-public.pem"
	bootPCRPublicKeySource         = "/usr/share/astraeaos/boot-trust/pcr-public.pem"
	bootPCRPolicySource            = "/run/systemd/tpm2-pcr-signature.json"
	bootPCRSysfsRoot               = "/sys/class/tpm/tpm0/pcr-sha256"
	bootVerityManifestSource       = "/usr/share/astraeaos/boot-trust/fsverity-manifest.json"
	bootVeritySignatureSource      = "/usr/share/astraeaos/boot-trust/fsverity-manifest.json.sig"

	bootAttestationMaxBytes          = int64(128 << 10)
	bootAttestationSignatureMaxBytes = int64(4 << 10)
	bootVerityManifestMaxBytes       = int64(1 << 20)
	bootVerityMaxFiles               = 512
	bootPolicyPCRCommand             = uint32(0x0000017F)

	bootAttestationFutureSkew = 5 * time.Minute
	bootAttestationBootSkew   = 5 * time.Minute
)

var requiredPCRSelection = [...]int{0, 2, 4, 7, 9, 11, 12}

// The signed AstraeaOS boot attestation is a versioned document produced by the
// root-owned astraeaos-boot-attestation service. The probe refuses to derive any
// positive boot-trust claim from the JSON shape alone (FIND-008): the document
// must carry a detached Ed25519 signature over its SHA-256 digest, verified
// against a pinned public key before a single field is trusted. The signed
// measurement payload is then re-validated against the live TPM sysfs PCR values,
// the pinned TPM policy key fingerprint and the signed fs-verity manifest.
//
// astraeaos.boot-attestation.v2 contract:
//
//	{
//	  "schema": "astraeaos.boot-attestation.v2",
//	  "status": "verified" | "degraded" | "unavailable" | "live-recovery",
//	  "boot_identity": "runtime-A" | "runtime-B" | "live",
//	  "boot_id": "<uuid>", "generated_at": "<RFC3339 UTC>", "nonce": "<64 hex>",
//	  "boot_epoch": <kernel btime seconds>,
//	  "signing_mode": "<mode>", "secure_boot": <bool>,
//	  "hardware_attestation": "verified" | "degraded" | "unavailable",
//	  "attestation_reason": <string|null>, "kernel_command_line": "<normalized>",
//	  "pcr": {"public_key_sha256": "<64 hex>", "signature_sha256": "<64 hex>",
//	          "selection": [0,2,...], "policy_digest": "<64 hex>",
//	          "values": {"0": "<64 hex>", ...}, "source": "sysfs"|"tpm2_pcrread"},
//	  "filesystem_integrity": {"status": "verified"|"degraded"|"unavailable"|"not-applicable",
//	          "method": "FS_IOC_MEASURE_VERITY", "manifest_sha256": "<64 hex>",
//	          "files_measured": <int>, "measurement_digest": "<64 hex>"}
//	}
type localBootAttestation struct {
	Schema              string                       `json:"schema"`
	Status              string                       `json:"status"`
	BootIdentity        string                       `json:"boot_identity"`
	BootID              string                       `json:"boot_id"`
	GeneratedAt         string                       `json:"generated_at"`
	Nonce               string                       `json:"nonce"`
	BootEpoch           int64                        `json:"boot_epoch"`
	SigningMode         string                       `json:"signing_mode"`
	SecureBoot          bool                         `json:"secure_boot"`
	HardwareAttestation string                       `json:"hardware_attestation"`
	AttestationReason   *string                      `json:"attestation_reason"`
	KernelCommandLine   string                       `json:"kernel_command_line"`
	PCR                 *localBootPCR                `json:"pcr"`
	FilesystemIntegrity localBootFilesystemIntegrity `json:"filesystem_integrity"`
}

type localBootPCR struct {
	PublicKeySHA256 string            `json:"public_key_sha256"`
	SignatureSHA256 string            `json:"signature_sha256"`
	Selection       []int             `json:"selection"`
	PolicyDigest    string            `json:"policy_digest"`
	Values          map[string]string `json:"values"`
	Source          string            `json:"source"`
}

type localBootFilesystemIntegrity struct {
	Status            string `json:"status"`
	Method            string `json:"method"`
	ManifestSHA256    string `json:"manifest_sha256"`
	FilesMeasured     int    `json:"files_measured"`
	MeasurementDigest string `json:"measurement_digest"`
}

// localBootVerityManifest is the operator-signed fs-verity expectation manifest.
// Entries are compared one-by-one with FS_IOC_MEASURE_VERITY by the attestation
// service; this probe re-verifies the manifest signature and the attested
// measurement digest so a forged attestation cannot smuggle in its own manifest.
type localBootVerityManifest struct {
	Schema    string                `json:"schema"`
	CreatedAt string                `json:"created_at,omitempty"`
	Files     []localBootVerityFile `json:"files"`
}

type localBootVerityFile struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

type BootTrustEvidence struct {
	ID       string `json:"id"`
	State    string `json:"state"`
	Summary  string `json:"summary"`
	Source   string `json:"source"`
	Evidence string `json:"evidence,omitempty"`
	Digest   string `json:"digest,omitempty"`
}

type BootTrustReport struct {
	GeneratedAt time.Time `json:"generated_at"`
	ClaimLevel  string    `json:"claim_level"`
	// Status is the honest verdict for the UI: VERIFIED when a verifiable boot
	// chain exists (platform attestation or an operator-signed local baseline),
	// OBSERVE when only evidence was collected, NOT_SUPPORTED when the host has
	// no hardware root of trust to verify at all. NOT_SUPPORTED is a platform
	// fact, not a failure and not a red alert.
	Status              string              `json:"status"`
	HardwareRootOfTrust bool                `json:"hardware_root_of_trust"`
	NotSupportedReasons []string            `json:"not_supported_reasons,omitempty"`
	Platform            string              `json:"platform"`
	DistroID            string              `json:"distro_id,omitempty"`
	DistroName          string              `json:"distro_name,omitempty"`
	VersionID           string              `json:"version_id,omitempty"`
	AstraeaOS           bool                `json:"astraeaos"`
	Summary             string              `json:"summary"`
	Items               []BootTrustEvidence `json:"items"`
}

type bootTrustProbe struct {
	root   string
	linux  bool
	now    func() time.Time
	policy bootTrustPolicy
}

type BootTrustCollector struct {
	mu       sync.Mutex
	probe    bootTrustProbe
	ttl      time.Duration
	expires  time.Time
	cached   BootTrustReport
	settings BootTrustFabricSettings
}

func NewBootTrustCollector(ttl time.Duration) *BootTrustCollector {
	if ttl < time.Second {
		ttl = 5 * time.Minute
	}
	settings := defaultBootTrustFabricSettings()
	settings.TTLSeconds = int(ttl / time.Second)
	return &BootTrustCollector{
		probe:    bootTrustProbe{linux: runtime.GOOS == "linux", now: time.Now},
		ttl:      ttl,
		settings: settings,
	}
}

func newBootTrustCollectorForTest(root string, linux bool, now func() time.Time) *BootTrustCollector {
	return &BootTrustCollector{
		probe:    bootTrustProbe{root: root, linux: linux, now: now},
		ttl:      5 * time.Minute,
		settings: defaultBootTrustFabricSettings(),
	}
}

func (c *BootTrustCollector) Collect() BootTrustReport {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := c.probe.now().UTC()
	if !c.expires.IsZero() && now.Before(c.expires) {
		return cloneBootTrustReport(c.cached)
	}
	// The published requirement set is projected onto the probe for this pass, so
	// a re-probe always evaluates the current policy rather than the one that was
	// active when the collector was constructed.
	probe := c.probe
	probe.policy = c.settings.policy().effective()
	report := probe.collect(now)
	c.cached = cloneBootTrustReport(report)
	c.expires = now.Add(c.ttl)
	return report
}

func cloneBootTrustReport(in BootTrustReport) BootTrustReport {
	out := in
	out.Items = append([]BootTrustEvidence(nil), in.Items...)
	out.NotSupportedReasons = append([]string(nil), in.NotSupportedReasons...)
	return out
}

func (p bootTrustProbe) collect(now time.Time) BootTrustReport {
	report := BootTrustReport{
		GeneratedAt: now,
		ClaimLevel:  "evidence-only",
		Platform:    runtime.GOOS,
		Items:       make([]BootTrustEvidence, 0, 12),
	}
	if !p.linux {
		report.Items = append(report.Items, BootTrustEvidence{
			ID: "platform", State: bootStateNotAvailable,
			Summary: "Linux boot evidence is unavailable on this platform.",
			Source:  "runtime",
		})
		report.Summary = "Boot evidence unavailable"
		report.Status = bootTrustStatusNotSupported
		report.NotSupportedReasons = []string{"non-linux-platform"}
		return report
	}
	report.Platform = "linux"

	osRelease := p.readOSRelease()
	report.DistroID = osRelease["ID"]
	report.DistroName = osRelease["NAME"]
	report.VersionID = osRelease["VERSION_ID"]
	report.AstraeaOS = strings.EqualFold(report.DistroID, "astraeaos")
	report.Items = append(report.Items, distroEvidence(report))
	report.Items = append(report.Items, p.secureBootEvidence())
	report.Items = append(report.Items, p.lockdownEvidence())
	report.Items = append(report.Items, p.cmdlineEvidence())
	report.Items = append(report.Items, p.tpmEvidence())
	attestation := p.attestationEvidence()
	report.Items = append(report.Items, attestation)
	report.Items = append(report.Items, p.cgroupEvidence())
	report.Items = append(report.Items, p.gaiaCellsEvidence())
	report.Items = append(report.Items, p.kernelImageEvidence())
	localBaseline := p.localBootBaselineEvidence(report.Items)
	report.Items = append(report.Items, localBaseline)
	finishBootTrustReport(&report, attestation, localBaseline)
	report.Summary = summarizeBootEvidence(report.Items)
	return report
}

func distroEvidence(report BootTrustReport) BootTrustEvidence {
	if report.DistroID == "" {
		return BootTrustEvidence{
			ID: "distribution", State: bootStateUnknown,
			Summary: "Distribution identity could not be observed.",
			Source:  "/etc/os-release",
		}
	}
	summary := "Linux distribution identity observed."
	if report.AstraeaOS {
		summary = "AstraeaOS distribution identity observed."
	}
	return BootTrustEvidence{
		ID: "distribution", State: bootStateObserved, Summary: summary,
		Source: "/etc/os-release", Evidence: report.DistroID,
	}
}

func (p bootTrustProbe) readOSRelease() map[string]string {
	data, err := p.readBounded("/etc/os-release", p.policy.effective().maxEvidenceText)
	if err != nil {
		return map[string]string{}
	}
	allowed := map[string]bool{"ID": true, "NAME": true, "VERSION_ID": true}
	values := make(map[string]string, len(allowed))
	for _, line := range strings.Split(string(data), "\n") {
		key, value, ok := strings.Cut(line, "=")
		key = strings.TrimSpace(key)
		if !ok || !allowed[key] {
			continue
		}
		value = strings.TrimSpace(value)
		if len(value) >= 2 && value[0] == '"' && value[len(value)-1] == '"' {
			value = strings.ReplaceAll(value[1:len(value)-1], `\"`, `"`)
		}
		if len(value) <= 256 && !strings.ContainsRune(value, '\x00') {
			values[key] = value
		}
	}
	return values
}

func (p bootTrustProbe) secureBootEvidence() BootTrustEvidence {
	candidates := []string{
		"/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c",
		"/sys/firmware/efi/vars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c/data",
	}
	for _, candidate := range candidates {
		data, err := p.readBounded(candidate, 4096)
		if err != nil {
			continue
		}
		var value byte
		switch {
		case strings.Contains(candidate, "/efivars/") && len(data) >= 5:
			value = data[4]
		case len(data) >= 1:
			value = data[0]
		default:
			continue
		}
		state := bootStateDisabled
		summary := "UEFI Secure Boot reports disabled."
		if value == 1 {
			state = bootStateEnabled
			summary = "UEFI Secure Boot variable reports enabled; signature-chain measurement is separate evidence."
		} else if p.policy.effective().requireSecureBoot {
			// A disabled anchor the operator declared mandatory is a policy
			// violation, so it is reported as WARNING rather than as a neutral
			// platform observation.
			state = bootStateWarning
			summary = "UEFI Secure Boot is disabled but is required by policy."
		}
		return BootTrustEvidence{
			ID: "secure-boot", State: state, Summary: summary,
			Source: candidate, Evidence: fmt.Sprintf("value=%d", value),
		}
	}
	if p.exists("/sys/firmware/efi") {
		return BootTrustEvidence{
			ID: "secure-boot", State: bootStateUnknown,
			Summary: "UEFI is present, but its Secure Boot variable is unreadable.",
			Source:  "efivarfs",
		}
	}
	return BootTrustEvidence{
		ID: "secure-boot", State: bootStateNotAvailable,
		Summary: "No UEFI firmware evidence is exposed.",
		Source:  "/sys/firmware/efi",
	}
}

func (p bootTrustProbe) lockdownEvidence() BootTrustEvidence {
	data, err := p.readBounded("/sys/kernel/security/lockdown", 4096)
	if err != nil {
		policy := p.policy.effective()
		if policy.requireLockdown {
			// The requirement cannot be proven, so it must not be reported as a
			// neutral platform gap.
			return BootTrustEvidence{
				ID: "kernel-lockdown", State: bootStateWarning,
				Summary: "Kernel lockdown is required by policy but its state cannot be observed.",
				Source:  "/sys/kernel/security/lockdown",
			}
		}
		return BootTrustEvidence{
			ID: "kernel-lockdown", State: bootStateUnknown,
			Summary: "Kernel lockdown state is unavailable.",
			Source:  "/sys/kernel/security/lockdown",
		}
	}
	value := strings.TrimSpace(string(data))
	state := bootStateWarning
	summary := "Kernel lockdown runtime state observed."
	if strings.Contains(value, "[integrity]") || strings.Contains(value, "[confidentiality]") {
		state = bootStateEnabled
	} else if p.policy.effective().requireLockdown {
		summary = "Kernel lockdown is inactive but is required by policy."
	}
	return BootTrustEvidence{
		ID: "kernel-lockdown", State: state, Summary: summary,
		Source: "/sys/kernel/security/lockdown", Evidence: truncateBootEvidence(value, 128),
	}
}

func (p bootTrustProbe) cmdlineEvidence() BootTrustEvidence {
	data, err := p.readBounded("/proc/cmdline", p.policy.effective().maxEvidenceText)
	if err != nil {
		return BootTrustEvidence{
			ID: "kernel-cmdline", State: bootStateUnknown,
			Summary: "Kernel command line is unavailable.",
			Source:  "/proc/cmdline",
		}
	}
	sum := sha256.Sum256(data)
	required := make(map[string]bool, len(p.policy.effective().requiredArguments))
	for _, argument := range p.policy.effective().requiredArguments {
		required[argument] = false
	}
	for _, token := range strings.Fields(string(data)) {
		if _, ok := required[token]; ok {
			required[token] = true
		}
	}
	present := make([]string, 0, len(required))
	for token, found := range required {
		if found {
			present = append(present, token)
		}
	}
	sort.Strings(present)
	state := bootStateWarning
	if len(present) == len(required) {
		state = bootStateEnabled
	}
	return BootTrustEvidence{
		ID: "kernel-cmdline", State: state,
		Summary: "Security-relevant boot parameters observed; raw command line is intentionally redacted.",
		Source:  "/proc/cmdline", Evidence: strings.Join(present, ","),
		Digest: hex.EncodeToString(sum[:]),
	}
}

func (p bootTrustProbe) tpmEvidence() BootTrustEvidence {
	for _, candidate := range []string{"/sys/class/tpm/tpm0", "/sys/class/tpmrm/tpmrm0", "/dev/tpmrm0", "/dev/tpm0"} {
		if p.exists(candidate) {
			return BootTrustEvidence{
				ID: "tpm", State: bootStateObserved,
				Summary: "A TPM interface is present; measured-boot verification has not been claimed.",
				Source:  candidate,
			}
		}
	}
	return BootTrustEvidence{
		ID: "tpm", State: bootStateNotAvailable,
		Summary: "No TPM interface was observed.",
		Source:  "sysfs/devfs",
	}
}

func (p bootTrustProbe) attestationEvidence() BootTrustEvidence {
	const id = "measured-boot-attestation"
	raw, err := p.readBounded(bootAttestationSource, bootAttestationMaxBytes)
	if err != nil {
		// When the operator declared attestation required, an absent attestation is
		// a policy violation rather than a platform property.
		if p.policy.effective().requireAttestation {
			return BootTrustEvidence{
				ID: "measured-boot-attestation", State: bootStateWarning,
				Summary: "Local TPM2 boot attestation is required by policy but is not available.",
				Source:  bootAttestationSource,
			}
		}
		return BootTrustEvidence{
			ID: "measured-boot-attestation", State: bootStateNotAvailable,
			Summary: "No verified local TPM2 boot attestation is available.",
			Source:  bootAttestationSource,
		}
	}
	warning := func(summary string) BootTrustEvidence {
		return BootTrustEvidence{
			ID: id, State: bootStateWarning, Summary: summary, Source: bootAttestationSource,
		}
	}

	// FIND-008: the JSON shape and its 64-character hex fields are not a trust
	// anchor. The detached Ed25519 signature over the document digest is verified
	// against the pinned public key before any field is used.
	publicKeyRaw, err := p.readBounded(bootAttestationPublicKeySource, bootAttestationSignatureMaxBytes)
	if err != nil {
		return warning("The pinned Ed25519 attestation key is unavailable; the local boot attestation cannot be verified (fail-closed).")
	}
	publicKey, err := decodeBootEd25519PublicKey(publicKeyRaw)
	if err != nil {
		return warning("The pinned attestation public key is not a valid Ed25519 key (fail-closed).")
	}
	signatureRaw, err := p.readBounded(bootAttestationSignatureSource, bootAttestationSignatureMaxBytes)
	if err != nil {
		return warning("The detached signature of the local boot attestation is unavailable (fail-closed).")
	}
	signature, err := decodeBootDetachedSignature(signatureRaw)
	if err != nil {
		return warning("The detached signature of the local boot attestation is malformed (fail-closed).")
	}
	documentDigest := sha256.Sum256(raw)
	if !ed25519.Verify(publicKey, documentDigest[:], signature) {
		return warning("The local boot attestation signature does not verify against the pinned key (fail-closed).")
	}

	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var value localBootAttestation
	if err := decoder.Decode(&value); err != nil {
		return warning("The signed local boot attestation is not valid JSON in the expected schema.")
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return warning("The signed local boot attestation contains trailing data.")
	}
	if value.Schema != bootAttestationSchema {
		return warning("The signed local boot attestation uses an unsupported schema.")
	}
	currentBootID, err := p.readBounded("/proc/sys/kernel/random/boot_id", 128)
	if err != nil {
		return BootTrustEvidence{
			ID: id, State: bootStateUnknown,
			Summary: "The current boot identity cannot be compared with the signed attestation.",
			Source:  bootAttestationSource,
		}
	}
	if !validBootUUID(strings.TrimSpace(value.BootID)) ||
		strings.TrimSpace(value.BootID) != strings.TrimSpace(string(currentBootID)) {
		return warning("The signed local boot attestation does not belong to the current boot.")
	}
	commandLineRaw, err := p.readBounded("/proc/cmdline", p.policy.effective().maxEvidenceText)
	if err != nil {
		return warning("The current kernel command line cannot be compared with the signed attestation.")
	}
	actualCommandLine := normalizeBootCommandLine(string(commandLineRaw))
	if normalizeBootCommandLine(value.KernelCommandLine) != actualCommandLine {
		return warning("The signed boot attestation does not describe the running kernel command line.")
	}
	if identity := bootIdentityFromCommandLine(actualCommandLine); identity == "" || identity != value.BootIdentity {
		return warning("The signed boot attestation does not match the running AstraeaOS boot identity.")
	}
	if !validSHA256(value.Nonce) {
		return warning("The signed boot attestation carries no valid freshness nonce.")
	}
	if err := p.verifyAttestationFreshness(value, p.now()); err != nil {
		return warning("The signed boot attestation is stale: " + err.Error() + ".")
	}
	if value.Status != "verified" {
		if value.Status == "live-recovery" {
			return warning("The local boot attestation reports live recovery mode without a hardware measurement; no verified boot claim is made.")
		}
		return warning("The local boot attestation reports status " + truncateBootEvidence(value.Status, 32) + " instead of verified (fail-closed).")
	}
	if !value.SecureBoot {
		return warning("UEFI Secure Boot is not confirmed by the signed boot attestation (fail-closed).")
	}
	if value.HardwareAttestation != "verified" {
		return warning("The signed boot attestation does not claim a verified TPM2 hardware measurement (fail-closed).")
	}
	if value.AttestationReason != nil && strings.TrimSpace(*value.AttestationReason) != "" {
		return warning("The signed boot attestation reports a degraded hardware measurement: " +
			truncateBootEvidence(strings.TrimSpace(*value.AttestationReason), 96) + " (fail-closed).")
	}
	policy := p.policy.effective()
	if err := p.verifyAttestedPCR(value.PCR, policy.requiredPCRs); err != nil {
		return warning("The signed TPM2 PolicyPCR measurement does not verify against the live platform: " + err.Error() + ".")
	}
	if err := p.verifyAttestedFilesystemIntegrity(value.FilesystemIntegrity, publicKey); err != nil {
		return warning("The signed fs-verity measurement does not verify: " + err.Error() + ".")
	}
	return BootTrustEvidence{
		ID: id, State: bootStateEnabled,
		Summary: "Signed boot attestation verified: Ed25519 signature, live TPM2 PolicyPCR measurement and fs-verity manifest all match.",
		Source:  bootAttestationSource,
		Evidence: fmt.Sprintf("PCRs %s; policy=%s; verity=%d files; nonce=%s",
			formatPCRSelection(policy.requiredPCRs), shortDigest(value.PCR.PolicyDigest),
			value.FilesystemIntegrity.FilesMeasured, shortDigest(value.Nonce)),
		Digest: hex.EncodeToString(documentDigest[:]),
	}
}

// verifyAttestedPCR binds the signed attestation to the live platform: the pinned
// TPM policy key fingerprint, the actual systemd PCR-signature file digest, the
// live kernel TPM sysfs PCR values and the recomputed TPM2 PolicyPCR digest must
// all agree with the signed document. A merely well-formed hex digest never
// passes this check.
func (p bootTrustProbe) verifyAttestedPCR(pcr *localBootPCR, required []int) error {
	if pcr == nil {
		return errors.New("the attestation carries no TPM PCR measurement")
	}
	if len(pcr.Selection) != len(required) {
		return errors.New("the attested PCR selection does not match the required policy")
	}
	for index, expected := range required {
		if pcr.Selection[index] != expected {
			return errors.New("the attested PCR selection does not match the required policy")
		}
	}
	publicKeyRaw, err := p.readBounded(bootPCRPublicKeySource, bootAttestationSignatureMaxBytes)
	if err != nil {
		return errors.New("the pinned TPM PCR public key is unavailable")
	}
	pinnedFingerprint, err := pemPublicKeyDERDigest(publicKeyRaw)
	if err != nil {
		return errors.New("the pinned TPM PCR public key is malformed")
	}
	if !validSHA256(pcr.PublicKeySHA256) || !strings.EqualFold(pcr.PublicKeySHA256, pinnedFingerprint) {
		return errors.New("the pinned TPM PCR public key fingerprint does not match the attestation")
	}
	policyRaw, err := p.readBounded(bootPCRPolicySource, bootAttestationMaxBytes)
	if err != nil {
		return errors.New("the systemd TPM PCR signature file is unavailable")
	}
	policyDigest := sha256.Sum256(policyRaw)
	if !validSHA256(pcr.SignatureSHA256) || !strings.EqualFold(pcr.SignatureSHA256, hex.EncodeToString(policyDigest[:])) {
		return errors.New("the attestation does not bind the actual TPM PCR signature file")
	}
	values := make(map[int][]byte, len(required))
	for _, index := range required {
		encoded, exists := pcr.Values[strconv.Itoa(index)]
		if !exists || !validSHA256(encoded) {
			return fmt.Errorf("the attested PCR %d value is missing or malformed", index)
		}
		decoded, err := hex.DecodeString(encoded)
		if err != nil || len(decoded) != sha256.Size {
			return fmt.Errorf("the attested PCR %d value is malformed", index)
		}
		values[index] = decoded
	}
	if len(pcr.Values) != len(required) {
		return errors.New("the attestation carries PCR values outside the required selection")
	}
	// The live TPM readout, exposed by the kernel, must equal the signed values.
	for _, index := range required {
		liveRaw, err := p.readBounded(fmt.Sprintf("%s/%d", bootPCRSysfsRoot, index), 256)
		if err != nil {
			return errors.New("the live TPM PCR readout is unavailable")
		}
		live := strings.ToLower(strings.TrimSpace(string(liveRaw)))
		if !validSHA256(live) {
			return fmt.Errorf("the live PCR %d readout is malformed", index)
		}
		if !strings.EqualFold(live, pcr.Values[strconv.Itoa(index)]) {
			return fmt.Errorf("the live PCR %d value differs from the signed attestation", index)
		}
	}
	recomputed, err := bootPolicyPCRDigest(required, values, nil)
	if err != nil {
		return err
	}
	if !validSHA256(pcr.PolicyDigest) || !strings.EqualFold(hex.EncodeToString(recomputed), pcr.PolicyDigest) {
		return errors.New("the TPM2 PolicyPCR digest does not match the signed policy")
	}
	if pcr.Source != "sysfs" && pcr.Source != "tpm2_pcrread" {
		return errors.New("the attestation names an unsupported PCR measurement source")
	}
	return nil
}

// verifyAttestedFilesystemIntegrity re-verifies the operator-signed fs-verity
// manifest and ties the attested kernel measurement digest back to exactly that
// manifest. The attestation service performs the real FS_IOC_MEASURE_VERITY ioctl;
// this check ensures the signed claim cannot point at an unrelated manifest.
func (p bootTrustProbe) verifyAttestedFilesystemIntegrity(fs localBootFilesystemIntegrity, attestationKey ed25519.PublicKey) error {
	if fs.Status != "verified" {
		return errors.New("the attestation does not report a verified fs-verity measurement")
	}
	if fs.Method != "FS_IOC_MEASURE_VERITY" {
		return errors.New("the attestation names an unsupported fs-verity measurement method")
	}
	if !validSHA256(fs.ManifestSHA256) || !validSHA256(fs.MeasurementDigest) ||
		fs.FilesMeasured < 1 || fs.FilesMeasured > bootVerityMaxFiles {
		return errors.New("the attested fs-verity measurement fields are malformed")
	}
	manifestRaw, err := p.readBounded(bootVerityManifestSource, bootVerityManifestMaxBytes)
	if err != nil {
		return errors.New("the signed fs-verity manifest is unavailable")
	}
	manifestDigest := sha256.Sum256(manifestRaw)
	if !strings.EqualFold(hex.EncodeToString(manifestDigest[:]), fs.ManifestSHA256) {
		return errors.New("the attested fs-verity manifest digest does not match the pinned manifest")
	}
	signatureRaw, err := p.readBounded(bootVeritySignatureSource, bootAttestationSignatureMaxBytes)
	if err != nil {
		return errors.New("the detached fs-verity manifest signature is unavailable")
	}
	signature, err := decodeBootDetachedSignature(signatureRaw)
	if err != nil {
		return errors.New("the detached fs-verity manifest signature is malformed")
	}
	if !ed25519.Verify(attestationKey, manifestDigest[:], signature) {
		return errors.New("the fs-verity manifest signature does not verify against the pinned key")
	}
	decoder := json.NewDecoder(bytes.NewReader(manifestRaw))
	decoder.DisallowUnknownFields()
	var manifest localBootVerityManifest
	if err := decoder.Decode(&manifest); err != nil {
		return errors.New("the signed fs-verity manifest is not valid JSON in the expected schema")
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("the signed fs-verity manifest contains trailing data")
	}
	if manifest.Schema != bootVerityManifestSchema {
		return errors.New("the signed fs-verity manifest uses an unsupported schema")
	}
	if len(manifest.Files) < 1 || len(manifest.Files) > bootVerityMaxFiles {
		return errors.New("the signed fs-verity manifest has an invalid file count")
	}
	if manifest.CreatedAt != "" {
		if _, err := time.Parse(time.RFC3339, manifest.CreatedAt); err != nil {
			return errors.New("the signed fs-verity manifest has an invalid creation timestamp")
		}
	}
	for _, file := range manifest.Files {
		if err := validBootVerityPath(file.Path); err != nil {
			return err
		}
		if !validSHA256(file.SHA256) {
			return errors.New("the signed fs-verity manifest contains a malformed digest")
		}
	}
	if len(manifest.Files) != fs.FilesMeasured {
		return errors.New("the attestation file count does not match the signed manifest")
	}
	expected, err := bootVerityMeasurementDigest(manifest.Files)
	if err != nil {
		return err
	}
	if !strings.EqualFold(expected, fs.MeasurementDigest) {
		return errors.New("the attested fs-verity measurement digest does not match the signed manifest")
	}
	return nil
}

func (p bootTrustProbe) verifyAttestationFreshness(value localBootAttestation, now time.Time) error {
	generatedAt, err := time.Parse(time.RFC3339, value.GeneratedAt)
	if err != nil {
		return errors.New("generated_at is not RFC3339")
	}
	statRaw, err := p.readBounded("/proc/stat", maxBootTextBytes)
	if err != nil {
		return errors.New("the kernel boot time is unavailable")
	}
	bootTime, ok := parseBootEpoch(statRaw)
	if !ok {
		return errors.New("the kernel boot time is unavailable")
	}
	if value.BootEpoch != bootTime.Unix() {
		return errors.New("boot_epoch does not describe the running kernel")
	}
	if generatedAt.Before(bootTime.Add(-bootAttestationBootSkew)) {
		return errors.New("generated_at predates the running kernel boot")
	}
	if generatedAt.After(now.Add(bootAttestationFutureSkew)) {
		return errors.New("generated_at is in the future")
	}
	return nil
}

func parseBootEpoch(stat []byte) (time.Time, bool) {
	for _, line := range strings.Split(string(stat), "\n") {
		if !strings.HasPrefix(line, "btime ") {
			continue
		}
		seconds, err := strconv.ParseInt(strings.TrimSpace(strings.TrimPrefix(line, "btime ")), 10, 64)
		if err != nil || seconds <= 0 {
			return time.Time{}, false
		}
		return time.Unix(seconds, 0), true
	}
	return time.Time{}, false
}

func normalizeBootCommandLine(value string) string {
	return strings.Join(strings.Fields(value), " ")
}

func bootIdentityFromCommandLine(cmdline string) string {
	hasLive := false
	hasRuntime := false
	slot := ""
	for _, token := range strings.Fields(cmdline) {
		switch token {
		case "astraeaos.mode=live":
			hasLive = true
		case "astraeaos.mode=runtime":
			hasRuntime = true
		case "astraeaos.slot=A":
			slot = "A"
		case "astraeaos.slot=B":
			slot = "B"
		}
	}
	switch {
	case hasLive && !hasRuntime:
		return "live"
	case hasRuntime && !hasLive && slot == "A":
		return "runtime-A"
	case hasRuntime && !hasLive && slot == "B":
		return "runtime-B"
	default:
		return ""
	}
}

func validBootUUID(value string) bool {
	if len(value) != 36 {
		return false
	}
	for index := 0; index < len(value); index++ {
		character := value[index]
		switch index {
		case 8, 13, 18, 23:
			if character != '-' {
				return false
			}
		default:
			if !((character >= '0' && character <= '9') || (character >= 'a' && character <= 'f')) {
				return false
			}
		}
	}
	return true
}

func validBootVerityPath(path string) error {
	if path == "" || len(path) > 4096 || !filepath.IsAbs(path) || strings.ContainsRune(path, '\x00') {
		return errors.New("the signed fs-verity manifest contains an invalid file path")
	}
	if filepath.Clean(path) != path || strings.Contains(path, "..") {
		return errors.New("the signed fs-verity manifest contains a non-canonical file path")
	}
	return nil
}

func decodeBootEd25519PublicKey(raw []byte) (ed25519.PublicKey, error) {
	block, _ := pem.Decode(raw)
	if block != nil {
		parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		key, ok := parsed.(ed25519.PublicKey)
		if !ok {
			return nil, errors.New("pinned attestation key is not an Ed25519 key")
		}
		return key, nil
	}
	// Compatibility with the operator tooling that writes raw hex or OpenSSH keys.
	return decodeEd25519PublicKey(string(raw))
}

func decodeBootDetachedSignature(raw []byte) ([]byte, error) {
	value := strings.ToLower(strings.TrimSpace(string(raw)))
	if len(value) != ed25519.SignatureSize*2 {
		return nil, errors.New("detached signature must be 128 lowercase hex characters")
	}
	decoded, err := hex.DecodeString(value)
	if err != nil {
		return nil, err
	}
	if len(decoded) != ed25519.SignatureSize {
		return nil, errors.New("detached signature has an invalid length")
	}
	return decoded, nil
}

func pemPublicKeyDERDigest(raw []byte) (string, error) {
	block, _ := pem.Decode(raw)
	if block == nil {
		return "", errors.New("no PEM block")
	}
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return "", err
	}
	der, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(der)
	return hex.EncodeToString(digest[:]), nil
}

// bootPolicyPCRDigest recomputes the TPM2 PolicyPCR policy digest exactly as the
// TPM and systemd-measure calculate it:
//
//	HMAC/extension step: SHA256(previous || TPM_CC_PolicyPCR || TPML_PCR_SELECTION || SHA256(PCR values))
//
// The formula is pinned by the official systemd test vectors exercised in
// boot_trust_test.go, so a signature over this digest is a signature over the
// expected PCR values for the selected registers.
func bootPolicyPCRDigest(selection []int, values map[int][]byte, previous []byte) ([]byte, error) {
	if len(selection) == 0 {
		return nil, errors.New("empty PCR selection")
	}
	oldDigest := make([]byte, sha256.Size)
	if previous != nil {
		if len(previous) != sha256.Size {
			return nil, errors.New("previous policy digest must be 32 bytes")
		}
		copy(oldDigest, previous)
	}
	pcrHash := sha256.New()
	mask := make([]byte, 3)
	last := -1
	for _, index := range selection {
		if index < 0 || index > 23 {
			return nil, fmt.Errorf("PCR index %d is outside 0-23", index)
		}
		if index <= last {
			return nil, errors.New("PCR selection must be strictly ascending")
		}
		last = index
		value, exists := values[index]
		if !exists || len(value) != sha256.Size {
			return nil, fmt.Errorf("missing value for PCR %d", index)
		}
		pcrHash.Write(value)
		mask[index/8] |= 1 << (index % 8)
	}
	// TPM_CC_PolicyPCR (big endian) followed by the marshalled TPML_PCR_SELECTION
	// (count=1, hashAlg=TPM2_ALG_SHA256, sizeofSelect=3, pcrSelect mask).
	header := make([]byte, 4+4+2+1+len(mask))
	binary.BigEndian.PutUint32(header[0:4], bootPolicyPCRCommand)
	binary.BigEndian.PutUint32(header[4:8], 1)
	binary.BigEndian.PutUint16(header[8:10], 0x000B)
	header[10] = byte(len(mask))
	copy(header[11:], mask)
	extended := sha256.New()
	extended.Write(oldDigest)
	extended.Write(header)
	extended.Write(pcrHash.Sum(nil))
	return extended.Sum(nil), nil
}

func bootVerityMeasurementDigest(files []localBootVerityFile) (string, error) {
	if len(files) == 0 {
		return "", errors.New("empty fs-verity manifest")
	}
	hash := sha256.New()
	for _, file := range files {
		digest, err := hex.DecodeString(strings.ToLower(file.SHA256))
		if err != nil || len(digest) != sha256.Size {
			return "", errors.New("the signed fs-verity manifest contains a malformed digest")
		}
		hash.Write([]byte(file.Path))
		hash.Write([]byte{0})
		hash.Write(digest)
		hash.Write([]byte{'\n'})
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func validSHA256(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil && value == strings.ToLower(value)
}

func (p bootTrustProbe) cgroupEvidence() BootTrustEvidence {
	data, err := p.readBounded("/sys/fs/cgroup/cgroup.controllers", 4096)
	if err != nil {
		return BootTrustEvidence{
			ID: "cgroup-v2", State: bootStateNotAvailable,
			Summary: "A unified cgroup v2 hierarchy was not observed.",
			Source:  "/sys/fs/cgroup/cgroup.controllers",
		}
	}
	controllers := strings.Fields(string(data))
	sort.Strings(controllers)
	return BootTrustEvidence{
		ID: "cgroup-v2", State: bootStateObserved,
		Summary:  "Unified cgroup v2 isolation substrate observed.",
		Source:   "/sys/fs/cgroup/cgroup.controllers",
		Evidence: strings.Join(controllers, ","),
	}
}

func (p bootTrustProbe) gaiaCellsEvidence() BootTrustEvidence {
	path := p.resolve("/run/gaia-cells/control.sock")
	info, err := os.Lstat(path)
	if err == nil && info.Mode()&os.ModeSocket != 0 {
		return BootTrustEvidence{
			ID: "gaia-cells", State: bootStateObserved,
			Summary: "Gaia Cells runtime socket observed; protocol authentication remains required.",
			Source:  "/run/gaia-cells/control.sock",
		}
	}
	return BootTrustEvidence{
		ID: "gaia-cells", State: bootStateNotAvailable,
		Summary: "Gaia Cells runtime is not installed or has not exposed its versioned control socket.",
		Source:  "/run/gaia-cells/control.sock",
	}
}

func (p bootTrustProbe) kernelImageEvidence() BootTrustEvidence {
	releaseData, _ := p.readBounded("/proc/sys/kernel/osrelease", 4096)
	release := strings.TrimSpace(string(releaseData))
	candidates := []string{"/boot/vmlinuz-linux-hardened", "/boot/vmlinuz-linux"}
	if release != "" && !strings.ContainsAny(release, `/\`+"\x00") {
		// Ubuntu/Debian keep the running image under the versioned name, not
		// behind /boot/vmlinuz (which is a symlink the probe deliberately
		// refuses). Without this candidate a standard Ubuntu host could never
		// produce kernel-image evidence for the operator-signed baseline.
		candidates = append(candidates,
			"/boot/vmlinuz-"+release,
			"/usr/lib/modules/"+release+"/vmlinuz")
	}
	for _, candidate := range candidates {
		digest, size, err := p.hashRegular(candidate, p.policy.effective().maxKernelImageBytes)
		if err != nil {
			continue
		}
		return BootTrustEvidence{
			ID: "kernel-image", State: bootStateObserved,
			Summary: "Kernel image digest observed; trust requires comparison with a signed release manifest.",
			Source:  candidate, Evidence: fmt.Sprintf("size=%d", size), Digest: digest,
		}
	}
	return BootTrustEvidence{
		ID: "kernel-image", State: bootStateUnknown,
		Summary: "No bounded regular kernel image could be read.",
		Source:  "/boot or /usr/lib/modules",
	}
}

func (p bootTrustProbe) readBounded(path string, max int64) ([]byte, error) {
	if max <= 0 {
		return nil, errors.New("invalid read limit")
	}
	resolved := p.resolve(path)
	info, err := os.Lstat(resolved)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return nil, errors.New("evidence source is not a regular non-symlink file")
	}
	file, err := os.Open(resolved)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > max {
		return nil, errors.New("evidence source exceeds limit")
	}
	return data, nil
}

func (p bootTrustProbe) hashRegular(path string, max int64) (string, int64, error) {
	resolved := p.resolve(path)
	info, err := os.Lstat(resolved)
	if err != nil {
		return "", 0, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > max {
		return "", 0, errors.New("kernel image is outside the regular-file boundary")
	}
	file, err := os.Open(resolved)
	if err != nil {
		return "", 0, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return "", 0, errors.New("kernel image identity changed")
	}
	hash := sha256.New()
	written, err := io.Copy(hash, io.LimitReader(file, max+1))
	if err != nil {
		return "", 0, err
	}
	if written != info.Size() || written > max {
		return "", 0, errors.New("kernel image changed while hashing")
	}
	return hex.EncodeToString(hash.Sum(nil)), written, nil
}

func (p bootTrustProbe) exists(path string) bool {
	_, err := os.Lstat(p.resolve(path))
	return err == nil
}

func (p bootTrustProbe) resolve(path string) string {
	clean := filepath.Clean(filepath.FromSlash(path))
	if p.root == "" {
		return clean
	}
	volume := filepath.VolumeName(clean)
	clean = strings.TrimPrefix(clean, volume)
	clean = strings.TrimLeft(clean, `/\`)
	return filepath.Join(p.root, clean)
}

func truncateBootEvidence(value string, max int) string {
	if len(value) <= max {
		return value
	}
	return value[:max]
}

func summarizeBootEvidence(items []BootTrustEvidence) string {
	observed, warnings, unavailable := 0, 0, 0
	for _, item := range items {
		switch item.State {
		case bootStateEnabled, bootStateObserved:
			observed++
		case bootStateWarning, bootStateDisabled:
			warnings++
		default:
			unavailable++
		}
	}
	return fmt.Sprintf("%d observed/enabled, %d disabled/warning, %d unknown/unavailable; evidence-only", observed, warnings, unavailable)
}
