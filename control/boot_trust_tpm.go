// STATUS: DIAMANT VGT SUPREME
// SPDX-FileCopyrightText: 2026 VisionGaia Technology
// SPDX-License-Identifier: AGPL-3.0-only

// TPM-2.0 quote/attestation helpers split out of boot_trust.go (refactoring
// wave 1b, structure-only): the TPM presence probe, the signed AstraeaOS
// boot-attestation verifier (Ed25519 signature, live TPM2 PolicyPCR digest,
// freshness), the fs-verity manifest/manifest-digest verification and the
// pinned-key/signature decoders. The collector, report types and posture
// evaluation stay in boot_trust.go / boot_trust_eval.go.

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
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

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
