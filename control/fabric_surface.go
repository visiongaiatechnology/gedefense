// STATUS: DIAMANT VGT SUPREME
package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
)

// Fabric control-plane surface: search, export, two-stage import and drift
// detection.
//
// Plan reference: GeDefense 4.2 Security Fabric Control Plane, sections 36 to 39.
//
// The export bundle carries administration, never identity: it is built from the
// administrable namespaces, which hold no private keys, no secrets and no runtime
// tokens, and a test asserts that property rather than trusting it.

const (
	settingsBundleSchema   = "gedefense.fabric-settings-bundle.v1"
	settingsBundleDomain   = "VGT-GEDEFENSE-SETTINGS-BUNDLE-V1\x00"
	settingsSearchLimit    = 60
	settingsSearchMinChars = 2
	settingsImportMaxBytes = 4 << 20
)

// ---------------------------------------------------------------- search

// FabricSearchHit is one administrable key, addressed the way the operator sees
// it: module, group, label.
type FabricSearchHit struct {
	Module    string `json:"module"`
	Group     string `json:"group"`
	Key       string `json:"key"`
	Label     string `json:"label"`
	Kind      string `json:"kind"`
	Apply     string `json:"apply_class"`
	Risk      string `json:"risk"`
	Value     any    `json:"value"`
	Highlight string `json:"highlight"`
}

// searchFabricSettings matches a query against the schema registry and returns
// each hit with its current effective value, so a search result is actionable
// instead of a table of contents.
//
// Matching is deliberately simple and deterministic: case-insensitive substring
// over key, label, group, module and description, ordered by a fixed relevance
// score and then alphabetically. No fuzzy ranking, so the same query always
// produces the same order.
func searchFabricSettings(query string, values map[string]map[string]any) []FabricSearchHit {
	needle := strings.ToLower(strings.TrimSpace(query))
	if len([]rune(needle)) < settingsSearchMinChars {
		return nil
	}
	type scored struct {
		hit   FabricSearchHit
		score int
	}
	results := make([]scored, 0, settingsSearchLimit)
	for _, meta := range fabricSettingDefinitions {
		score := fabricSearchScore(meta, needle)
		if score == 0 {
			continue
		}
		hit := FabricSearchHit{
			Module: meta.module, Group: meta.group, Key: meta.key, Label: meta.label,
			Kind: string(meta.kind), Apply: string(meta.class), Risk: string(meta.risk),
			Highlight: fabricSearchHighlight(meta, needle),
		}
		if moduleValues, ok := values[meta.module]; ok {
			hit.Value = moduleValues[meta.key]
			if hit.Value == nil {
				hit.Value = moduleValues[strings.TrimPrefix(meta.key, meta.module+".")]
			}
		}
		results = append(results, scored{hit: hit, score: score})
	}
	sort.Slice(results, func(i, j int) bool {
		if results[i].score != results[j].score {
			return results[i].score > results[j].score
		}
		if results[i].hit.Module != results[j].hit.Module {
			return results[i].hit.Module < results[j].hit.Module
		}
		return results[i].hit.Key < results[j].hit.Key
	})
	if len(results) > settingsSearchLimit {
		results = results[:settingsSearchLimit]
	}
	out := make([]FabricSearchHit, 0, len(results))
	for _, entry := range results {
		out = append(out, entry.hit)
	}
	return out
}

// fabricSearchScore ranks a field hit above a description hit, so a query that
// names a key or a label is never buried under prose matches.
func fabricSearchScore(meta fabricSettingDefinition, needle string) int {
	switch {
	case strings.Contains(strings.ToLower(meta.key), needle):
		return 40
	case strings.Contains(strings.ToLower(meta.label), needle):
		return 30
	case strings.Contains(strings.ToLower(meta.group), needle):
		return 20
	case strings.Contains(strings.ToLower(meta.module), needle):
		return 15
	case strings.Contains(strings.ToLower(meta.desc), needle):
		return 10
	case strings.Contains(strings.ToLower(meta.unit), needle) && meta.unit != "":
		return 5
	}
	return 0
}

// fabricSearchHighlight names the field that matched, so the dashboard can say
// why a result appeared.
func fabricSearchHighlight(meta fabricSettingDefinition, needle string) string {
	switch {
	case strings.Contains(strings.ToLower(meta.key), needle):
		return "key"
	case strings.Contains(strings.ToLower(meta.label), needle):
		return "label"
	case strings.Contains(strings.ToLower(meta.group), needle):
		return "group"
	case strings.Contains(strings.ToLower(meta.module), needle):
		return "module"
	case strings.Contains(strings.ToLower(meta.desc), needle):
		return "description"
	}
	return "unit"
}

// ---------------------------------------------------------------- export

// SettingsBundle is the sanitized, signed administration export.
type SettingsBundle struct {
	Schema        string                     `json:"schema"`
	Node          string                     `json:"node"`
	Revision      uint64                     `json:"revision"`
	FabricVersion int                        `json:"fabric_version"`
	ExportedAt    time.Time                  `json:"exported_at"`
	Modules       map[string]json.RawMessage `json:"modules"`
	// Digest binds the bundle content. A verifier must recompute it.
	Digest string `json:"digest"`
	// Signature is the Ed25519 signature over the canonical payload.
	Signature string `json:"signature"`
	// Signer is the fingerprint of the signing key, never the key itself.
	Signer string `json:"signer"`
}

// settingsBundlePayload is the canonical byte string a bundle signature covers:
// the content fields in a fixed order, with the digest and signature excluded.
func settingsBundlePayload(bundle SettingsBundle) ([]byte, error) {
	modules := make([]string, 0, len(bundle.Modules))
	for module := range bundle.Modules {
		modules = append(modules, module)
	}
	sort.Strings(modules)
	ordered := make(map[string]json.RawMessage, len(modules))
	for _, module := range modules {
		ordered[module] = bundle.Modules[module]
	}
	canonical := struct {
		Schema        string                     `json:"schema"`
		Node          string                     `json:"node"`
		Revision      uint64                     `json:"revision"`
		FabricVersion int                        `json:"fabric_version"`
		ExportedAt    string                     `json:"exported_at"`
		Modules       map[string]json.RawMessage `json:"modules"`
	}{
		Schema: bundle.Schema, Node: bundle.Node, Revision: bundle.Revision,
		FabricVersion: bundle.FabricVersion,
		ExportedAt:    bundle.ExportedAt.UTC().Format(time.RFC3339Nano),
		Modules:       ordered,
	}
	encoded, err := json.Marshal(canonical)
	if err != nil {
		return nil, err
	}
	return append([]byte(settingsBundleDomain), encoded...), nil
}

// buildSettingsBundle assembles and signs an export from the administrable
// namespaces only.
func buildSettingsBundle(node string, settings RuntimeSettings, signer *PolicyStore, at time.Time) (SettingsBundle, error) {
	modules := make(map[string]json.RawMessage, len(fabricModuleSnapshotOrder))
	for _, module := range fabricModuleSnapshotOrder {
		snapshot, err := fabricModuleSnapshot(settings, module)
		if err != nil {
			return SettingsBundle{}, fmt.Errorf("export %s: %w", module, err)
		}
		encoded, err := json.Marshal(snapshot)
		if err != nil {
			return SettingsBundle{}, fmt.Errorf("export %s: %w", module, err)
		}
		modules[module] = encoded
	}
	bundle := SettingsBundle{
		Schema: settingsBundleSchema, Node: node, Revision: settings.Revision,
		FabricVersion: settings.FabricVersion, ExportedAt: at.UTC(), Modules: modules,
	}
	payload, err := settingsBundlePayload(bundle)
	if err != nil {
		return SettingsBundle{}, err
	}
	digest := sha256.Sum256(payload)
	bundle.Digest = hex.EncodeToString(digest[:])
	if signer != nil {
		signature, err := signer.SignBytes(payload)
		if err != nil {
			return SettingsBundle{}, err
		}
		bundle.Signature = base64.RawURLEncoding.EncodeToString(signature)
		bundle.Signer = signer.Status().Signer
	}
	return bundle, nil
}

// verifySettingsBundle checks the digest, the schema tag and the signature. An
// unsigned bundle is refused outright: an import is a privileged operation and
// there is no legitimate reason to accept one from an unauthenticated source.
func verifySettingsBundle(raw []byte, trusted ed25519.PublicKey) (SettingsBundle, error) {
	if len(raw) == 0 || len(raw) > settingsImportMaxBytes {
		return SettingsBundle{}, fmt.Errorf("bundle size %d is outside the accepted range", len(raw))
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var bundle SettingsBundle
	if err := decoder.Decode(&bundle); err != nil {
		return SettingsBundle{}, fmt.Errorf("bundle is not a valid settings bundle: %w", err)
	}
	if bundle.Schema != settingsBundleSchema {
		return SettingsBundle{}, fmt.Errorf("unsupported bundle schema %q", bundle.Schema)
	}
	if len(bundle.Modules) == 0 {
		return SettingsBundle{}, fmt.Errorf("bundle carries no modules")
	}
	for module := range bundle.Modules {
		if _, ok := fabricModuleGroups[module]; !ok {
			return SettingsBundle{}, fmt.Errorf("bundle references unknown module %q", module)
		}
	}
	payload, err := settingsBundlePayload(bundle)
	if err != nil {
		return SettingsBundle{}, err
	}
	digest := sha256.Sum256(payload)
	if !hmac.Equal([]byte(hex.EncodeToString(digest[:])), []byte(bundle.Digest)) {
		return SettingsBundle{}, fmt.Errorf("bundle digest does not match its content")
	}
	signature, err := base64.RawURLEncoding.DecodeString(bundle.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return SettingsBundle{}, fmt.Errorf("bundle signature is malformed")
	}
	if trusted == nil || !ed25519.Verify(trusted, payload, signature) {
		return SettingsBundle{}, fmt.Errorf("bundle signature verification failed")
	}
	return bundle, nil
}

// decodeSettingsBundle turns a verified bundle into a candidate revision. It never
// touches the store: the candidate only becomes active through the apply stage.
func decodeSettingsBundle(bundle SettingsBundle, current RuntimeSettings) (RuntimeSettings, []FabricSettingDiff, error) {
	candidate := cloneRuntimeSettings(current)
	// A bundle is applied onto the running revision, so a module it does not carry
	// keeps its current value. Every decoded module still passes the same validator
	// a dashboard edit passes, which is what makes dependency validation meaningful
	// rather than decorative.
	for module, raw := range bundle.Modules {
		if err := decodeModuleSettings(raw, module, &candidate); err != nil {
			return RuntimeSettings{}, nil, fmt.Errorf("bundle module %s: %w", module, err)
		}
	}
	if err := validateRuntimeSettings(&candidate); err != nil {
		return RuntimeSettings{}, nil, fmt.Errorf("bundle dependency validation failed: %w", err)
	}
	diff, err := fabricRevisionDiff(current, candidate)
	if err != nil {
		return RuntimeSettings{}, nil, err
	}
	return candidate, diff, nil
}

// fabricModuleSnapshotOrder is the deterministic module order used by the export
// and the drift report, so both produce a stable sequence.
var fabricModuleSnapshotOrder = []string{
	"kinetic", "network", "protection", "xdr", "l7",
	"threat_intel", "hardening", "integrity", "boot_trust", "policy_trust", "forensics", "system",
}

// fabricRevisionDiff diffs two full revisions module by module, keeping only the
// modules that actually differ.
func fabricRevisionDiff(current, candidate RuntimeSettings) ([]FabricSettingDiff, error) {
	diff := make([]FabricSettingDiff, 0, 32)
	for _, module := range fabricModuleSnapshotOrder {
		oldValue, err := fabricModuleSnapshot(current, module)
		if err != nil {
			return nil, err
		}
		newValue, err := fabricModuleSnapshot(candidate, module)
		if err != nil {
			return nil, err
		}
		moduleChanges, _, _, err := moduleDiff(module, oldValue, newValue)
		if err != nil {
			return nil, err
		}
		if len(moduleChanges) == 0 {
			continue
		}
		diff = append(diff, moduleChanges...)
	}
	return diff, nil
}

// importNonce binds a preview to the exact bytes and revision it was computed
// against, so an apply can neither be replayed onto a changed revision nor
// applied to a different bundle than the one that was reviewed.
func importNonce(secret []byte, raw []byte, revision uint64, expires time.Time) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte("fabric-import\x00"))
	mac.Write(raw)
	mac.Write([]byte(fmt.Sprintf("\x00%d\x00", revision)))
	mac.Write([]byte(expires.UTC().Format(time.RFC3339Nano)))
	return hex.EncodeToString(mac.Sum(nil))
}

// ---------------------------------------------------------------- drift

// FabricDriftFinding is one module whose published revision is not the revision
// the live engine is enforcing.
type FabricDriftFinding struct {
	Module      string `json:"module"`
	ApplyState  string `json:"apply_state"`
	Detail      string `json:"detail"`
	Restartable bool   `json:"restartable"`
}

// driftReport compares the stored revision against the effective engine state of
// every module. The rule from the plan is explicit: a mismatch reports CONFIG
// DRIFT and never SYSTEM NOMINAL.
func (s *APIServer) driftReport(settings RuntimeSettings) (string, []FabricDriftFinding) {
	findings := make([]FabricDriftFinding, 0, len(fabricModuleSnapshotOrder))
	for _, module := range fabricModuleSnapshotOrder {
		state := s.fabricModuleApplyState(settings, module)
		if state == "applied" {
			continue
		}
		detail := "the stored revision has not reached the engine"
		restartable := false
		switch state {
		case "restart_required":
			detail = "the stored revision requires a controlled service restart before it takes effect"
			restartable = true
		case "reload_pending":
			detail = "the stored revision has not been published to the running pipeline yet"
		case "engine_unavailable":
			detail = "the engine that owns this namespace is not attached"
		case "rejected":
			detail = "the engine refused the stored revision"
		}
		findings = append(findings, FabricDriftFinding{Module: module, ApplyState: state, Detail: detail, Restartable: restartable})
	}
	if len(findings) == 0 {
		return "SYSTEM_NOMINAL", findings
	}
	return "CONFIG_DRIFT", findings
}

// driftSummary is the event text raised when drift appears or clears.
func driftSummary(findings []FabricDriftFinding) string {
	if len(findings) == 0 {
		return ""
	}
	parts := make([]string, 0, len(findings))
	for _, finding := range findings {
		parts = append(parts, fmt.Sprintf("%s(%s)", finding.Module, finding.ApplyState))
	}
	return strings.Join(parts, ", ")
}
