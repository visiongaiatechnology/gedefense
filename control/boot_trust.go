// STATUS: DIAMANT VGT SUPREME

package main

import (
	"runtime"
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
