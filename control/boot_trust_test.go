// STATUS: DIAMANT VGT SUPREME

package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

const (
	bootTrustTestBootID      = "018f1f4e-3362-7d02-b6b9-1eebbc15f001"
	bootTrustTestCommandLine = "quiet init_on_alloc=1 init_on_free=1 randomize_kstack_offset=on module.sig_enforce=1 astraeaos.mode=runtime astraeaos.slot=A"
)

func bootTrustTestKey(seed byte) ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, ed25519.SeedSize))
}

func bootTrustSHA256(value []byte) []byte {
	digest := sha256.Sum256(value)
	return digest[:]
}

func TestBootTrustCollectsAstraeaOSEvidenceWithoutLeakingCmdline(t *testing.T) {
	root := t.TempDir()
	writeBootTestFile(t, root, "/etc/os-release", "ID=astraeaos\nNAME=\"AstraeaOS\"\nVERSION_ID=\"0.1\"\n")
	writeBootTestFile(t, root, "/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c", string([]byte{7, 0, 0, 0, 1}))
	writeBootTestFile(t, root, "/sys/kernel/security/lockdown", "none integrity [confidentiality]\n")
	writeBootTestFile(t, root, "/proc/cmdline", "root=UUID=123 rd.luks.key=supersecret init_on_alloc=1 init_on_free=1 randomize_kstack_offset=on module.sig_enforce=1\n")
	writeBootTestFile(t, root, "/proc/sys/kernel/osrelease", "6.12.1-gaia\n")
	writeBootTestFile(t, root, "/sys/fs/cgroup/cgroup.controllers", "cpu io memory pids\n")
	writeBootTestFile(t, root, "/boot/vmlinuz-linux-hardened", "signed-kernel-image")
	if err := os.MkdirAll(filepath.Join(root, "sys", "class", "tpm", "tpm0"), 0o700); err != nil {
		t.Fatal(err)
	}

	now := time.Date(2026, 7, 28, 15, 0, 0, 0, time.UTC)
	collector := newBootTrustCollectorForTest(root, true, func() time.Time { return now })
	report := collector.Collect()
	if !report.AstraeaOS || report.DistroID != "astraeaos" || report.ClaimLevel != "evidence-only" {
		t.Fatalf("unexpected report identity: %+v", report)
	}
	if got := bootEvidenceState(report, "secure-boot"); got != bootStateEnabled {
		t.Fatalf("secure boot state=%s", got)
	}
	if got := bootEvidenceState(report, "kernel-lockdown"); got != bootStateEnabled {
		t.Fatalf("lockdown state=%s", got)
	}
	if got := bootEvidenceState(report, "cgroup-v2"); got != bootStateObserved {
		t.Fatalf("cgroup state=%s", got)
	}
	if got := bootEvidenceState(report, "gaia-cells"); got != bootStateNotAvailable {
		t.Fatalf("Gaia Cells must not be inferred from unrelated host state: %s", got)
	}
	encoded, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "supersecret") || strings.Contains(string(encoded), "rd.luks.key") {
		t.Fatal("raw kernel command line leaked into report")
	}
	cmdline := bootEvidence(report, "kernel-cmdline")
	if cmdline.Digest == "" || !strings.Contains(cmdline.Evidence, "module.sig_enforce=1") {
		t.Fatalf("cmdline evidence incomplete: %+v", cmdline)
	}
	if got := bootEvidenceState(report, "measured-boot-attestation"); got != bootStateNotAvailable {
		t.Fatalf("absent attestation must not be reported as trusted evidence: %s", got)
	}
}

// TestBootTrustVerifiesSignedAttestation is the positive regression for FIND-008:
// a correctly Ed25519-signed attestation whose live TPM PolicyPCR digest (read
// from the kernel sysfs PCR files) and signed fs-verity manifest both match the
// signed document is the only way the probe may raise the local-attestation claim
// level.
func TestBootTrustVerifiesSignedAttestation(t *testing.T) {
	root := t.TempDir()
	writeBootTrustBaseEvidence(t, root)
	now := time.Date(2026, 8, 13, 12, 0, 0, 0, time.UTC)
	writeBootTrustAttestationEvidence(t, root, bootTrustTestBootID, now, []int{0, 2, 4, 7, 9, 11, 12})

	report := newBootTrustCollectorForTest(root, true, func() time.Time { return now }).Collect()
	if report.ClaimLevel != bootClaimAttestation {
		t.Fatalf("claim level=%s want=%s", report.ClaimLevel, bootClaimAttestation)
	}
	if report.Status != bootTrustStatusVerified {
		t.Fatalf("report status=%s", report.Status)
	}
	evidence := bootEvidence(report, "measured-boot-attestation")
	if evidence.State != bootStateEnabled || evidence.Digest == "" {
		t.Fatalf("attestation evidence=%+v", evidence)
	}
	marshaled, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(marshaled), strings.Repeat("a", 64)) {
		t.Fatal("attested PCR readout leaked into the API report")
	}
}

// TestBootTrustRejectsUnsignedAttestation covers requirement (a): a syntactically
// valid document with valid 64-character hex digests but without a detached
// signature must never be reported as ENABLED.
func TestBootTrustRejectsUnsignedAttestation(t *testing.T) {
	root := t.TempDir()
	writeBootTrustBaseEvidence(t, root)
	now := time.Date(2026, 8, 13, 12, 0, 0, 0, time.UTC)
	writeBootTrustAttestationEvidence(t, root, bootTrustTestBootID, now, []int{0, 2, 4, 7, 9, 11, 12})
	if err := os.Remove(filepath.Join(root, "run", "astraeaos", "boot-attestation.sig")); err != nil {
		t.Fatal(err)
	}
	report := newBootTrustCollectorForTest(root, true, func() time.Time { return now }).Collect()
	requireBootTrustAttestationState(t, report, bootStateWarning)
	if report.ClaimLevel == bootClaimAttestation {
		t.Fatal("unsigned attestation raised the local-attestation claim level")
	}
}

// TestBootTrustRejectsWrongAttestationSignature covers the forged-signature half
// of requirement (a).
func TestBootTrustRejectsWrongAttestationSignature(t *testing.T) {
	root := t.TempDir()
	writeBootTrustBaseEvidence(t, root)
	now := time.Date(2026, 8, 13, 12, 0, 0, 0, time.UTC)
	writeBootTrustAttestationEvidence(t, root, bootTrustTestBootID, now, []int{0, 2, 4, 7, 9, 11, 12})
	writeBootTestFile(t, root, bootAttestationSignatureSource, strings.Repeat("00", ed25519.SignatureSize)+"\n")
	report := newBootTrustCollectorForTest(root, true, func() time.Time { return now }).Collect()
	requireBootTrustAttestationState(t, report, bootStateWarning)
	if report.ClaimLevel == bootClaimAttestation {
		t.Fatal("wrongly signed attestation raised the local-attestation claim level")
	}
}

// TestBootTrustRejectsTamperedPCRReadout covers requirement (c): a validly signed
// document whose PCR values no longer match the live TPM readout is FAILED.
func TestBootTrustRejectsTamperedPCRReadout(t *testing.T) {
	root := t.TempDir()
	writeBootTrustBaseEvidence(t, root)
	now := time.Date(2026, 8, 13, 12, 0, 0, 0, time.UTC)
	writeBootTrustAttestationEvidence(t, root, bootTrustTestBootID, now, []int{0, 2, 4, 7, 9, 11, 12})
	replacement := bootTrustSHA256([]byte("tampered-live-pcr"))
	writeBootTestFile(t, root, "/sys/class/tpm/tpm0/pcr-sha256/4", hex.EncodeToString(replacement)+"\n")
	report := newBootTrustCollectorForTest(root, true, func() time.Time { return now }).Collect()
	requireBootTrustAttestationState(t, report, bootStateWarning)
	if report.ClaimLevel == bootClaimAttestation {
		t.Fatal("attestation with a diverging live PCR was accepted")
	}
}

// TestBootTrustRejectsResignedPCRTampering proves that even an attacker who holds
// the pinned attestation signing key cannot substitute TPM measurements: the live
// kernel PCR readout must still match.
func TestBootTrustRejectsResignedPCRTampering(t *testing.T) {
	root := t.TempDir()
	writeBootTrustBaseEvidence(t, root)
	now := time.Date(2026, 8, 13, 12, 0, 0, 0, time.UTC)
	writeBootTrustAttestationEvidence(t, root, bootTrustTestBootID, now, []int{0, 2, 4, 7, 9, 11, 12})
	tamperBootTrustAttestation(t, root, func(document map[string]any) {
		pcr, ok := document["pcr"].(map[string]any)
		if !ok {
			t.Fatal("attestation fixture has no PCR object")
		}
		values, ok := pcr["values"].(map[string]any)
		if !ok {
			t.Fatal("attestation fixture has no PCR values")
		}
		values["0"] = hex.EncodeToString(bootTrustSHA256([]byte("forged-pcr-0")))
	})
	report := newBootTrustCollectorForTest(root, true, func() time.Time { return now }).Collect()
	requireBootTrustAttestationState(t, report, bootStateWarning)
	if report.ClaimLevel == bootClaimAttestation {
		t.Fatal("re-signed but tampered PCR evidence raised the local-attestation claim level")
	}
}

// TestBootTrustRejectsTamperedVerityManifest proves the signed fs-verity manifest
// is part of the trust chain: changing the manifest breaks both the detached
// signature and the attested measurement digest.
func TestBootTrustRejectsTamperedVerityManifest(t *testing.T) {
	root := t.TempDir()
	writeBootTrustBaseEvidence(t, root)
	now := time.Date(2026, 8, 13, 12, 0, 0, 0, time.UTC)
	writeBootTrustAttestationEvidence(t, root, bootTrustTestBootID, now, []int{0, 2, 4, 7, 9, 11, 12})
	manifestPath := filepath.Join(root, filepath.FromSlash(strings.TrimPrefix(bootVerityManifestSource, "/")))
	raw, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	tampered := strings.Replace(string(raw), "/usr/share/astraeaos/boot-trust/pcr-public.pem", "/usr/share/astraeaos/boot-trust/pcr-public-evil.pem", 1)
	if tampered == string(raw) {
		t.Fatal("manifest fixture could not be tampered")
	}
	if err := os.WriteFile(manifestPath, []byte(tampered), 0o600); err != nil {
		t.Fatal(err)
	}
	report := newBootTrustCollectorForTest(root, true, func() time.Time { return now }).Collect()
	requireBootTrustAttestationState(t, report, bootStateWarning)
	if report.ClaimLevel == bootClaimAttestation {
		t.Fatal("a tampered fs-verity manifest raised the local-attestation claim level")
	}
}

func TestBootTrustRejectsAttestationFromAnotherBoot(t *testing.T) {
	root := t.TempDir()
	writeBootTrustBaseEvidence(t, root)
	now := time.Date(2026, 8, 13, 12, 0, 0, 0, time.UTC)
	writeBootTrustAttestationEvidence(t, root, bootTrustTestBootID, now, []int{0, 2, 4, 7, 9, 11, 12})
	writeBootTestFile(t, root, "/proc/sys/kernel/random/boot_id", "018f1f4e-3362-7d02-b6b9-1eebbc15f002\n")
	report := newBootTrustCollectorForTest(root, true, func() time.Time { return now }).Collect()
	requireBootTrustAttestationState(t, report, bootStateWarning)
	if report.ClaimLevel != "evidence-only" {
		t.Fatalf("unexpected claim level=%s", report.ClaimLevel)
	}
}

func TestBootTrustRejectsStaleAttestation(t *testing.T) {
	root := t.TempDir()
	writeBootTrustBaseEvidence(t, root)
	now := time.Date(2026, 8, 13, 12, 0, 0, 0, time.UTC)
	writeBootTrustAttestationEvidence(t, root, bootTrustTestBootID, now, []int{0, 2, 4, 7, 9, 11, 12})
	tamperBootTrustAttestation(t, root, func(document map[string]any) {
		document["generated_at"] = now.Add(-2 * time.Hour).Format(time.RFC3339)
	})
	report := newBootTrustCollectorForTest(root, true, func() time.Time { return now }).Collect()
	requireBootTrustAttestationState(t, report, bootStateWarning)
}

func TestBootTrustRejectsAttestationWithoutPinnedKey(t *testing.T) {
	root := t.TempDir()
	writeBootTrustBaseEvidence(t, root)
	now := time.Date(2026, 8, 13, 12, 0, 0, 0, time.UTC)
	writeBootTrustAttestationEvidence(t, root, bootTrustTestBootID, now, []int{0, 2, 4, 7, 9, 11, 12})
	if err := os.Remove(filepath.Join(root, filepath.FromSlash(strings.TrimPrefix(bootAttestationPublicKeySource, "/")))); err != nil {
		t.Fatal(err)
	}
	report := newBootTrustCollectorForTest(root, true, func() time.Time { return now }).Collect()
	requireBootTrustAttestationState(t, report, bootStateWarning)
}

// TestBootTrustPolicyPCRDigestMatchesSystemdVectors pins the TPM2 PolicyPCR digest
// computation to the official systemd test vectors (src/test/test-tpm2.c,
// TEST(calculate_policy_pcr)). A wrong formula would silently never verify a
// genuine signed PCR policy.
func TestBootTrustPolicyPCRDigestMatchesSystemdVectors(t *testing.T) {
	vectors := map[int]string{
		0:  "2124793cbbe60c3a8637d3b84a5d054e87c351e1469a285acc04755e8b204dec",
		1:  "bf7592f18adcfdc549fc0b94939f5069a24697f9cff4a0dca29014767b97559d",
		2:  "4b00cff9dee3a364979b2dc241b34568a8ad49fcf2713df259e47dff8875feed",
		3:  "3d458cfe55cc03ea1f443f1562beec8df51c75e14a9fcf9a7234a13f198e7969",
		4:  "368f85b3013041dfe203faaa364f00b07c5da7b1e5f1dbf2efb06fa6b9bd92de",
		5:  "c97c40369691c8e4aa78fb3a52655cd193b780a838b8e23f5f476576919db5e5",
		6:  "3d458cfe55cc03ea1f443f1562beec8df51c75e14a9fcf9a7234a13f198e7969",
		7:  "aa1154c9e0a774854ccbed4c8ce7e9b906b3d700a1a8db1772d0341a62dbe51b",
		8:  "cfde439a2c06af3479ca6bdc60429b90553d65300c5cfcc40004a08c6b5ad81a",
		9:  "9c2bac22ef5ec84fcdb71c3ebf776cba1247e5da980e5ee08e45666a2edf0b8b",
		10: "9885873f4d7348199ad286f8f2476d4f866940950f6f9fb9f945ed352dbdcbd2",
		11: "42400ab950d21aa79d12cc4fdef67d1087a39ad64900619831c0974dbae54e44",
		12: "767d064382e56ca1ad3bdcc6bc596112e6c2008b593d3570d24c2bfa64c4628c",
		13: "30c16133175959408c9745d8dafadef5daf4b39cb2be04df0d60089bd46d3cc4",
		14: "e3991b7ddd47be7e92726a832d6874c5349b52b789fa0db8b558c69fea29574e",
		15: "852dae3ecb992bdeb13d6002fefeeffdd90feca8b378d56681ef2c885d0e5137",
	}
	values := make(map[int][]byte, len(vectors))
	for index, encoded := range vectors {
		decoded, err := hex.DecodeString(encoded)
		if err != nil {
			t.Fatal(err)
		}
		values[index] = decoded
	}
	first, err := bootPolicyPCRDigest([]int{4, 7, 8}, values, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := hex.EncodeToString(first), "76532a0e16f7e6bf6b02918c11f75d99d729fab0cc81d0df2c4284a2c4fe6e05"; got != want {
		t.Fatalf("PolicyPCR vector 1=%s want=%s", got, want)
	}
	second, err := bootPolicyPCRDigest([]int{4, 7, 8}, values, first)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := hex.EncodeToString(second), "97e64bcabb64c1fa4b726528644926c8029f5b4458b0575c98c04fe225629a0b"; got != want {
		t.Fatalf("PolicyPCR extended vector=%s want=%s", got, want)
	}
	all := make([]int, 0, 16)
	for index := 0; index < 16; index++ {
		all = append(all, index)
	}
	first, err = bootPolicyPCRDigest(all, values, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := hex.EncodeToString(first), "22be4f1674f792d6345cea9427701068f0e8d9f42755dcc0e927e545a68f9c13"; got != want {
		t.Fatalf("PolicyPCR 16-PCR vector=%s want=%s", got, want)
	}
	second, err = bootPolicyPCRDigest(all, values, first)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := hex.EncodeToString(second), "7481fd1b116078eb3ac2456e4ad542c9b46b9b8eb891335771ca8e7c8f8e4415"; got != want {
		t.Fatalf("PolicyPCR 16-PCR extended vector=%s want=%s", got, want)
	}
}

func TestBootTrustCacheReturnsDefensiveCopy(t *testing.T) {
	root := t.TempDir()
	writeBootTestFile(t, root, "/etc/os-release", "ID=astraeaos\n")
	now := time.Date(2026, 7, 28, 15, 0, 0, 0, time.UTC)
	collector := newBootTrustCollectorForTest(root, true, func() time.Time { return now })
	first := collector.Collect()
	first.Items[0].Summary = "tampered by caller"
	second := collector.Collect()
	if second.Items[0].Summary == "tampered by caller" {
		t.Fatal("cached report alias exposed mutable internal state")
	}
	if !second.GeneratedAt.Equal(now) {
		t.Fatalf("unexpected cached timestamp: %s", second.GeneratedAt)
	}
}

func TestBootTrustRejectsSymlinkEvidence(t *testing.T) {
	root := t.TempDir()
	outside := filepath.Join(root, "outside")
	if err := os.WriteFile(outside, []byte("ID=astraeaos\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(root, "etc", "os-release")
	if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, target); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	now := time.Date(2026, 7, 28, 15, 0, 0, 0, time.UTC)
	report := newBootTrustCollectorForTest(root, true, func() time.Time { return now }).Collect()
	if report.AstraeaOS || report.DistroID != "" {
		t.Fatalf("symlink evidence must be rejected: %+v", report)
	}
}

// writeBootTrustBaseEvidence lays out the host evidence the probe always collects.
func writeBootTrustBaseEvidence(t *testing.T, root string) {
	t.Helper()
	writeBootTestFile(t, root, "/etc/os-release", "ID=astraeaos\nNAME=\"AstraeaOS\"\nVERSION_ID=\"0.1\"\n")
	writeBootTestFile(t, root, "/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c", string([]byte{7, 0, 0, 0, 1}))
	writeBootTestFile(t, root, "/sys/kernel/security/lockdown", "none integrity [confidentiality]\n")
	writeBootTestFile(t, root, "/proc/cmdline", bootTrustTestCommandLine+"\n")
	writeBootTestFile(t, root, "/proc/sys/kernel/osrelease", "6.12.1-gaia\n")
	writeBootTestFile(t, root, "/sys/fs/cgroup/cgroup.controllers", "cpu io memory pids\n")
	writeBootTestFile(t, root, "/boot/vmlinuz-linux-hardened", "signed-kernel-image")
}

// writeBootTrustAttestationEvidence lays out a complete, cryptographically valid
// signed attestation fixture: pinned Ed25519 keys, live TPM sysfs PCR values, the
// systemd PCR-signature file, the signed fs-verity manifest and the canonical
// attestation document with its detached signature.
func writeBootTrustAttestationEvidence(t *testing.T, root, bootID string, now time.Time, selection []int) ed25519.PrivateKey {
	t.Helper()
	attestationKey := bootTrustTestKey(0x11)
	pcrPolicyKey := bootTrustTestKey(0x22)
	writeBootTrustPublicKey(t, root, bootAttestationPublicKeySource, attestationKey.Public().(ed25519.PublicKey))
	writeBootTrustPublicKey(t, root, bootPCRPublicKeySource, pcrPolicyKey.Public().(ed25519.PublicKey))

	commandLine := bootTrustTestCommandLine
	if existing, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(strings.TrimPrefix("/proc/cmdline", "/")))); err == nil {
		commandLine = normalizeBootCommandLine(string(existing))
	}
	if !strings.Contains(commandLine, "astraeaos.mode=") {
		commandLine = normalizeBootCommandLine(commandLine + " astraeaos.mode=runtime astraeaos.slot=A")
	}
	writeBootTestFile(t, root, "/proc/cmdline", commandLine+"\n")
	writeBootTestFile(t, root, "/proc/sys/kernel/random/boot_id", bootID+"\n")
	bootTime := now.Add(-time.Hour)
	writeBootTestFile(t, root, "/proc/stat", fmt.Sprintf("cpu  1 2 3 4 5 6 7 8\nbtime %d\n", bootTime.Unix()))

	values := make(map[int][]byte, len(selection))
	pcrValues := make(map[string]any, len(selection))
	for _, index := range selection {
		digest := bootTrustSHA256([]byte(fmt.Sprintf("gedefense-pcr-%d", index)))
		values[index] = digest
		pcrValues[strconv.Itoa(index)] = hex.EncodeToString(digest)
		writeBootTestFile(t, root, fmt.Sprintf("/sys/class/tpm/tpm0/pcr-sha256/%d", index), hex.EncodeToString(digest)+"\n")
	}
	policySignatureRaw := []byte(`{"sha256":[{"pcrs":[149,26,0],"pkfp":"0000","pol":"0000","sig":""}]}`)
	writeBootTestFile(t, root, bootPCRPolicySource, string(policySignatureRaw))
	policyDigest, err := bootPolicyPCRDigest(selection, values, nil)
	if err != nil {
		t.Fatal(err)
	}

	generatedAt := now.Add(-time.Minute).UTC()
	verityFiles := []localBootVerityFile{
		{Path: "/usr/lib/astraeaos/astraeaos-boot-attestation", SHA256: strings.Repeat("1", 64)},
		{Path: "/usr/share/astraeaos/boot-trust/pcr-public.pem", SHA256: strings.Repeat("2", 64)},
	}
	manifest := map[string]any{
		"schema":     bootVerityManifestSchema,
		"created_at": generatedAt.Format(time.RFC3339),
		"files": []any{
			map[string]any{"path": verityFiles[0].Path, "sha256": verityFiles[0].SHA256},
			map[string]any{"path": verityFiles[1].Path, "sha256": verityFiles[1].SHA256},
		},
	}
	manifestRaw, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	writeBootTestFile(t, root, bootVerityManifestSource, string(manifestRaw))
	writeBootTestFile(t, root, bootVeritySignatureSource,
		hex.EncodeToString(ed25519.Sign(attestationKey, bootTrustSHA256(manifestRaw)))+"\n")
	measurementDigest, err := bootVerityMeasurementDigest(verityFiles)
	if err != nil {
		t.Fatal(err)
	}

	pcrPublicKeyRaw, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(strings.TrimPrefix(bootPCRPublicKeySource, "/"))))
	if err != nil {
		t.Fatal(err)
	}
	pcrPublicKeyFingerprint, err := pemPublicKeyDERDigest(pcrPublicKeyRaw)
	if err != nil {
		t.Fatal(err)
	}

	document := map[string]any{
		"schema":               bootAttestationSchema,
		"status":               "verified",
		"boot_identity":        "runtime-A",
		"boot_id":              bootID,
		"generated_at":         generatedAt.Format(time.RFC3339),
		"nonce":                strings.Repeat("a", 64),
		"boot_epoch":           bootTime.Unix(),
		"signing_mode":         "external-hsm",
		"secure_boot":          true,
		"hardware_attestation": "verified",
		"attestation_reason":   nil,
		"kernel_command_line":  commandLine,
		"pcr": map[string]any{
			"public_key_sha256": pcrPublicKeyFingerprint,
			"signature_sha256":  hex.EncodeToString(bootTrustSHA256(policySignatureRaw)),
			"selection":         selection,
			"policy_digest":     hex.EncodeToString(policyDigest),
			"values":            pcrValues,
			"source":            "sysfs",
		},
		"filesystem_integrity": map[string]any{
			"status":             "verified",
			"method":             "FS_IOC_MEASURE_VERITY",
			"manifest_sha256":    hex.EncodeToString(bootTrustSHA256(manifestRaw)),
			"files_measured":     len(verityFiles),
			"measurement_digest": measurementDigest,
		},
	}
	writeBootTrustSignedAttestation(t, root, document, attestationKey)
	return attestationKey
}

func writeBootTrustSignedAttestation(t *testing.T, root string, document map[string]any, key ed25519.PrivateKey) {
	t.Helper()
	raw, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	writeBootTestFile(t, root, bootAttestationSource, string(raw))
	writeBootTestFile(t, root, bootAttestationSignatureSource,
		hex.EncodeToString(ed25519.Sign(key, bootTrustSHA256(raw)))+"\n")
}

func tamperBootTrustAttestation(t *testing.T, root string, mutate func(map[string]any)) {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(strings.TrimPrefix(bootAttestationSource, "/")))
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := json.Unmarshal(raw, &document); err != nil {
		t.Fatal(err)
	}
	mutate(document)
	writeBootTrustSignedAttestation(t, root, document, bootTrustTestKey(0x11))
}

func writeBootTrustPublicKey(t *testing.T, root, unixPath string, public ed25519.PublicKey) {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	writeBootTestFile(t, root, unixPath, string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})))
}

func requireBootTrustAttestationState(t *testing.T, report BootTrustReport, state string) {
	t.Helper()
	evidence := bootEvidence(report, "measured-boot-attestation")
	if evidence.State != state {
		t.Fatalf("attestation state=%s want=%s (summary=%q)", evidence.State, state, evidence.Summary)
	}
}

func writeBootTestFile(t *testing.T, root, unixPath, content string) {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(strings.TrimPrefix(unixPath, "/")))
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func bootEvidence(report BootTrustReport, id string) BootTrustEvidence {
	for _, item := range report.Items {
		if item.ID == id {
			return item
		}
	}
	return BootTrustEvidence{}
}

func bootEvidenceState(report BootTrustReport, id string) string {
	return bootEvidence(report, id).State
}
