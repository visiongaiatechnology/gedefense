// STATUS: DIAMANT VGT SUPREME
package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func trustFixture(t *testing.T) (*APIServer, *SettingsStore, Config, *PolicyStore) {
	t.Helper()
	cfg, state, policy, release := betaReleaseFixture(t)
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "runtime.key")
	if err := os.WriteFile(keyPath, make([]byte, 32), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg.Runtime.StorageKeyFile = ""
	cfg.XDR.IncidentLog = filepath.Join(dir, "incidents.jsonl")
	settings, err := NewSettingsStore(filepath.Join(dir, "runtime.json"), keyPath, cfg)
	if err != nil {
		t.Fatal(err)
	}
	release.settings = settings
	server := NewAPIServer(cfg, state, nil, nil, policy, nil, release, settings, fabricTestToken)
	return server, settings, cfg, policy
}

func trustPayload(t *testing.T, module string, settings *SettingsStore, mutate func(map[string]any)) []byte {
	t.Helper()
	current := settings.Get()
	flat := map[string]any{}
	switch module {
	case "boot_trust":
		raw, err := json.Marshal(effectiveBootTrustSettings(current))
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(raw, &flat); err != nil {
			t.Fatal(err)
		}
	case "policy_trust":
		raw, err := json.Marshal(effectivePolicyTrustSettings(current))
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(raw, &flat); err != nil {
			t.Fatal(err)
		}
	default:
		t.Fatalf("unknown module %q", module)
	}
	if mutate != nil {
		mutate(flat)
	}
	payload, err := json.Marshal(map[string]any{"expected_revision": current.Revision, "settings": flat})
	if err != nil {
		t.Fatal(err)
	}
	return payload
}

// bootTrustProbeFixture lays out a synthetic boot evidence tree under a temporary
// root so the administrable requirements can be exercised without a real TPM.
func bootTrustProbeFixture(t *testing.T, attestation any) (*BootTrustCollector, string) {
	t.Helper()
	root := t.TempDir()
	write := func(relative string, data []byte) {
		path := filepath.Join(root, filepath.FromSlash(relative))
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("etc/os-release", []byte("ID=astraeaos\nNAME=\"AstraeaOS\"\nVERSION_ID=\"4.2\"\n"))
	write("proc/cmdline", []byte("quiet init_on_alloc=1 init_on_free=1 randomize_kstack_offset=on module.sig_enforce=1\n"))
	write("proc/sys/kernel/random/boot_id", []byte("boot-id-fixture\n"))
	write("sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c",
		append([]byte{0x06, 0x00, 0x00, 0x00}, 0x01))
	write("sys/kernel/security/lockdown", []byte("none [integrity] confidentiality\n"))
	if attestation != nil {
		raw, err := json.Marshal(attestation)
		if err != nil {
			t.Fatal(err)
		}
		write("run/astraeaos/boot-attestation.json", raw)
	}
	collector := newBootTrustCollectorForTest(root, true, func() time.Time { return time.Unix(1700000000, 0).UTC() })
	return collector, root
}

func attestationFor(pcrs []int) map[string]any {
	digest := hex.EncodeToString(bytesOf(0x11))
	return map[string]any{
		"schema": "astraeaos.boot-attestation.v1", "status": "verified", "secure_boot": true,
		"boot_id": "boot-id-fixture", "pcr_selection": pcrs,
		"pcr_signature_sha256": digest, "pcr_public_key_sha256": digest, "pcr_readout": "base64-readout",
	}
}

func bytesOf(value byte) []byte {
	out := make([]byte, sha256.Size)
	for index := range out {
		out[index] = value
	}
	return out
}

func bootTrustItem(t *testing.T, report BootTrustReport, id string) BootTrustEvidence {
	t.Helper()
	for _, item := range report.Items {
		if item.ID == id {
			return item
		}
	}
	t.Fatalf("boot evidence item %q is missing from the report", id)
	return BootTrustEvidence{}
}

// TestBootTrustPCRPolicyDecidesTheAttestationVerdict proves the administrable PCR
// selection is the authority: an attestation that matches the compiled-in default
// is accepted, and the same document is rejected once the requirement narrows.
func TestBootTrustPCRPolicyDecidesTheAttestationVerdict(t *testing.T) {
	collector, _ := bootTrustProbeFixture(t, attestationFor([]int{0, 2, 4, 7, 9, 11, 12}))

	report := collector.Collect()
	if item := bootTrustItem(t, report, "measured-boot-attestation"); item.State != bootStateEnabled {
		t.Fatalf("baseline attestation was not accepted: %+v", item)
	}
	if report.ClaimLevel != "local-attestation" {
		t.Fatalf("claim level was not raised: %q", report.ClaimLevel)
	}

	// Narrowing the required selection must invalidate the same document, because
	// the attestation reports a different register set.
	settings := defaultBootTrustFabricSettings()
	settings.RequiredPCRSelection = []int{0, 1, 2}
	if err := collector.ApplyPolicy(settings); err != nil {
		t.Fatal(err)
	}
	report = collector.Collect()
	item := bootTrustItem(t, report, "measured-boot-attestation")
	if item.State != bootStateWarning {
		t.Fatalf("an attestation outside the required PCR policy was accepted: %+v", item)
	}
	if report.ClaimLevel == "local-attestation" {
		t.Fatal("claim level stayed raised after the PCR policy rejected the attestation")
	}

	// Widening it back is accepted again, proving the policy is live in both
	// directions rather than latched.
	settings.RequiredPCRSelection = []int{0, 2, 4, 7, 9, 11, 12}
	if err := collector.ApplyPolicy(settings); err != nil {
		t.Fatal(err)
	}
	if item := bootTrustItem(t, collector.Collect(), "measured-boot-attestation"); item.State != bootStateEnabled {
		t.Fatalf("restoring the PCR policy did not restore the verdict: %+v", item)
	}
}

// TestBootTrustDeclaredAnchorsBecomeViolations covers the three requirement
// switches: a missing anchor the operator declared mandatory must not be reported
// as a neutral platform property.
func TestBootTrustDeclaredAnchorsBecomeViolations(t *testing.T) {
	collector, root := bootTrustProbeFixture(t, nil)
	baseline := collector.Collect()
	if item := bootTrustItem(t, baseline, "measured-boot-attestation"); item.State != bootStateNotAvailable {
		t.Fatalf("absent attestation was misreported: %+v", item)
	}

	settings := defaultBootTrustFabricSettings()
	settings.RequireAttestation = true
	settings.RequiredKernelArguments = []string{"init_on_alloc=1", "locking_not_present=1"}
	if err := collector.ApplyPolicy(settings); err != nil {
		t.Fatal(err)
	}
	report := collector.Collect()
	if item := bootTrustItem(t, report, "measured-boot-attestation"); item.State != bootStateWarning {
		t.Fatalf("required-but-absent attestation was not flagged: %+v", item)
	}
	cmdline := bootTrustItem(t, report, "kernel-cmdline")
	if cmdline.State != bootStateWarning {
		t.Fatalf("a required boot argument that is absent was not flagged: %+v", cmdline)
	}
	if cmdline.Evidence != "init_on_alloc=1" {
		t.Fatalf("kernel command line evidence leaked or mismatched: %q", cmdline.Evidence)
	}

	// Removing the unobtainable requirement restores ENABLED.
	settings.RequiredKernelArguments = []string{"init_on_alloc=1", "init_on_free=1", "randomize_kstack_offset=on", "module.sig_enforce=1"}
	if err := collector.ApplyPolicy(settings); err != nil {
		t.Fatal(err)
	}
	if item := bootTrustItem(t, collector.Collect(), "kernel-cmdline"); item.State != bootStateEnabled {
		t.Fatalf("satisfied boot arguments were not accepted: %+v", item)
	}

	// An unobservable lockdown requirement is reported as a violation, not as an
	// unknown platform property.
	if err := os.Remove(filepath.Join(root, "sys/kernel/security/lockdown")); err != nil {
		t.Fatal(err)
	}
	settings.RequireKernelLockdown = true
	settings.TTLSeconds = 5
	if err := collector.ApplyPolicy(settings); err != nil {
		t.Fatal(err)
	}
	if item := bootTrustItem(t, collector.Collect(), "kernel-lockdown"); item.State != bootStateWarning {
		t.Fatalf("required-but-unobservable lockdown was not flagged: %+v", item)
	}
}

func TestFabricBootTrustRejectsUnsafeConfiguration(t *testing.T) {
	server, settings, _, _ := trustFixture(t)
	cases := []struct {
		name   string
		mutate func(flat map[string]any)
	}{
		{"pcr above the register range", func(f map[string]any) { f["required_pcr_selection"] = []int{0, 24} }},
		{"empty pcr selection", func(f map[string]any) { f["required_pcr_selection"] = []int{} }},
		{"evidence cache below the floor", func(f map[string]any) { f["ttl_seconds"] = 1 }},
		{"evidence read bound too small", func(f map[string]any) { f["max_evidence_text_bytes"] = 16 }},
		{"kernel image bound too large", func(f map[string]any) { f["max_kernel_image_bytes"] = int64(1) << 40 }},
		{"kernel argument with whitespace", func(f map[string]any) { f["required_kernel_arguments"] = []string{"init_on_alloc=1 extra"} }},
		{"kernel argument without a value", func(f map[string]any) { f["required_kernel_arguments"] = []string{"quiet"} }},
		{"too many kernel arguments", func(f map[string]any) {
			arguments := make([]string, 0, 40)
			for index := 0; index < 40; index++ {
				arguments = append(arguments, "arg"+string(rune('a'+index))+"=1")
			}
			f["required_kernel_arguments"] = arguments
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			payload := trustPayload(t, "boot_trust", settings, tc.mutate)
			rec := fabricRequest(t, server, http.MethodPost, "/api/v1/settings/boot_trust/preview", payload)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("unsafe configuration accepted: %d %s", rec.Code, rec.Body.String())
			}
		})
	}
}

// TestBootTrustPCRSelectionIsNormalized verifies that duplicates are collapsed and
// the list is sorted, because the attestation contract compares it in order.
func TestBootTrustPCRSelectionIsNormalized(t *testing.T) {
	server, settings, _, _ := trustFixture(t)
	payload := trustPayload(t, "boot_trust", settings, func(f map[string]any) {
		f["required_pcr_selection"] = []int{12, 7, 7, 0}
	})
	rec := fabricRequest(t, server, http.MethodPut, "/api/v1/settings/boot_trust", payload)
	if rec.Code != http.StatusOK {
		t.Fatalf("apply status=%d body=%s", rec.Code, rec.Body.String())
	}
	stored := effectiveBootTrustSettings(settings.Get()).RequiredPCRSelection
	expected := []int{0, 7, 12}
	if len(stored) != len(expected) {
		t.Fatalf("normalized selection=%v", stored)
	}
	for index, pcr := range expected {
		if stored[index] != pcr {
			t.Fatalf("normalized selection=%v want=%v", stored, expected)
		}
	}
}

// TestPolicyTrustRollbackIsRefused covers the replay protection: a document older
// than the administrable floor is refused instead of silently downgrading the
// enforcement posture.
func TestPolicyTrustRollbackIsRefused(t *testing.T) {
	server, settings, _, policy := trustFixture(t)
	if err := policy.Persist("rollback-node", "block", "enforce", nil); err != nil {
		t.Fatal(err)
	}
	loaded, err := policy.Load()
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Generation == 0 {
		t.Fatal("persisted policy did not advance its generation")
	}

	trust := defaultPolicyTrustFabricSettings()
	trust.MinimumGeneration = loaded.Generation + 1
	if err := policy.ApplyPolicy(trust); err != nil {
		t.Fatal(err)
	}
	if _, err := policy.Load(); err == nil {
		t.Fatal("a policy document below the pinned minimum generation was accepted")
	}
	status := policy.Status()
	if status.Verified {
		t.Fatal("status still reports a verified policy after a rollback was refused")
	}
	if status.Error == "" {
		t.Fatal("rollback refusal is not visible in the policy status")
	}

	// Lowering the floor restores the document.
	trust.MinimumGeneration = 0
	if err := policy.ApplyPolicy(trust); err != nil {
		t.Fatal(err)
	}
	if _, err := policy.Load(); err != nil {
		t.Fatalf("the document was not accepted after the floor was lowered: %v", err)
	}
	if !policy.Status().Verified {
		t.Fatal("status did not return to verified")
	}

	// The namespace round-trips through the Fabric surface.
	payload := trustPayload(t, "policy_trust", settings, func(f map[string]any) { f["minimum_generation"] = float64(3) })
	rec := fabricRequest(t, server, http.MethodPut, "/api/v1/settings/policy_trust", payload)
	if rec.Code != http.StatusOK {
		t.Fatalf("apply status=%d body=%s", rec.Code, rec.Body.String())
	}
	if got := effectivePolicyTrustSettings(settings.Get()).MinimumGeneration; got != 3 {
		t.Fatalf("minimum generation was not persisted: %d", got)
	}
}

// TestPolicyTrustSignatureRequirementIsLive proves the signature requirement is
// administrable rather than frozen at construction: the same document is refused
// while required and tolerated when the operator accepts unsigned policy state.
func TestPolicyTrustSignatureRequirementIsLive(t *testing.T) {
	_, _, _, policy := trustFixture(t)
	envelope := PolicyEnvelope{Version: policyDocumentVersion, Generation: 7, UpdatedAt: time.Now().UTC()}
	// A document whose signature is structurally valid but cryptographically wrong.
	document := PolicyDocument{Envelope: envelope, Signature: base64.RawURLEncoding.EncodeToString(make([]byte, 64))}
	if err := policy.writeDocument(document); err != nil {
		t.Fatal(err)
	}

	trust := defaultPolicyTrustFabricSettings()
	trust.RequireSigned = true
	if err := policy.ApplyPolicy(trust); err != nil {
		t.Fatal(err)
	}
	if _, err := policy.Load(); err == nil {
		t.Fatal("an unsigned policy document was accepted while signatures are required")
	}
	if policy.Status().Verified {
		t.Fatal("status reports verified for a refused document")
	}

	trust.RequireSigned = false
	if err := policy.ApplyPolicy(trust); err != nil {
		t.Fatal(err)
	}
	if _, err := policy.Load(); err != nil {
		t.Fatalf("an unsigned document was refused while signatures are optional: %v", err)
	}
}

func TestFabricPolicyTrustRejectsUnsafeConfiguration(t *testing.T) {
	server, settings, _, _ := trustFixture(t)
	cases := []struct {
		name   string
		mutate func(flat map[string]any)
	}{
		{"verification interval below the floor", func(f map[string]any) { f["verify_interval_seconds"] = 5 }},
		{"state read bound too small", func(f map[string]any) { f["max_state_bytes"] = 1024 }},
		{"state read bound too large", func(f map[string]any) { f["max_state_bytes"] = int64(1) << 40 }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			payload := trustPayload(t, "policy_trust", settings, tc.mutate)
			rec := fabricRequest(t, server, http.MethodPost, "/api/v1/settings/policy_trust/preview", payload)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("unsafe configuration accepted: %d %s", rec.Code, rec.Body.String())
			}
		})
	}
}

// TestFabricTrustDocumentWithoutNamespaceStillAuthenticates guards the migration
// path for a settings document written before the trust namespaces existed.
func TestFabricTrustDocumentWithoutNamespaceStillAuthenticates(t *testing.T) {
	cfg := defaultConfig()
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "runtime.key")
	if err := os.WriteFile(keyPath, make([]byte, 32), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg.Runtime.StorageKeyFile = ""
	path := filepath.Join(dir, "runtime.json")
	seeded, err := NewSettingsStore(path, keyPath, cfg)
	if err != nil {
		t.Fatal(err)
	}
	legacy := seeded.Get()
	legacy.FabricVersion = 6
	legacy.BootTrust = nil
	legacy.PolicyTrust = nil
	legacy.Kinetic.VelocityLimit = 987
	mac, err := seeded.mac(legacy)
	if err != nil {
		t.Fatal(err)
	}
	document := runtimeSettingsEnvelope{Schema: runtimeSettingsSchema, Settings: legacy, MAC: hex.EncodeToString(mac)}
	data, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(data, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	reloaded, err := NewSettingsStore(path, keyPath, cfg)
	if err != nil {
		t.Fatalf("a pre-trust settings document was rejected: %v", err)
	}
	upgraded := reloaded.Get()
	if upgraded.FabricVersion != fabricSettingsVersion {
		t.Fatalf("schema version not upgraded: %d", upgraded.FabricVersion)
	}
	if upgraded.BootTrust == nil || upgraded.PolicyTrust == nil {
		t.Fatal("trust namespaces were not seeded during the upgrade")
	}
	if upgraded.Kinetic.VelocityLimit != 987 {
		t.Fatal("existing operator tuning was lost during the upgrade")
	}
	if !upgraded.PolicyTrust.RequireSigned {
		t.Fatal("the bootstrap signature requirement was not seeded")
	}
}

func TestFabricTrustSchemaRegistryCoversEveryAdvertisedKey(t *testing.T) {
	server, _, _, _ := trustFixture(t)
	rec := fabricRequest(t, server, http.MethodGet, "/api/v1/settings/schema", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("schema status=%d body=%s", rec.Code, rec.Body.String())
	}
	var schema struct {
		Modules  []string                `json:"modules"`
		Settings []FabricSettingMetadata `json:"settings"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &schema); err != nil {
		t.Fatal(err)
	}
	for _, module := range []string{"boot_trust", "policy_trust"} {
		if !containsString(schema.Modules, module) {
			t.Fatalf("schema does not advertise %q: %v", module, schema.Modules)
		}
	}
	registered := map[string]map[string]FabricSettingMetadata{}
	for _, meta := range schema.Settings {
		if meta.Module != "boot_trust" && meta.Module != "policy_trust" {
			continue
		}
		if registered[meta.Module] == nil {
			registered[meta.Module] = map[string]FabricSettingMetadata{}
		}
		registered[meta.Module][meta.Key] = meta
	}
	for module, keys := range map[string][]string{
		"boot_trust": {"ttl_seconds", "required_pcr_selection", "required_kernel_arguments", "require_secure_boot",
			"require_kernel_lockdown", "require_attestation", "max_kernel_image_bytes", "max_evidence_text_bytes"},
		"policy_trust": {"require_signed", "minimum_generation", "verify_interval_seconds", "max_state_bytes"},
	} {
		for _, key := range keys {
			if _, exists := registered[module][key]; !exists {
				t.Fatalf("administrable key %s.%s has no schema metadata", module, key)
			}
		}
	}

	// The module view must carry live evidence rather than a static description.
	view := fabricRequest(t, server, http.MethodGet, "/api/v1/settings/boot_trust", nil)
	if view.Code != http.StatusOK {
		t.Fatalf("boot trust view status=%d body=%s", view.Code, view.Body.String())
	}
	if decoded := decodeFabricView(t, view.Body.Bytes()); decoded.Details["claim_level"] == nil {
		t.Fatalf("boot trust view carries no claim level: %+v", decoded.Details)
	}
}
