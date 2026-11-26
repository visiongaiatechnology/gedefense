// STATUS: DIAMANT VGT SUPREME
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// signedReleaseFixture builds the two directory trees a signed package update touches: the
// staging directory the release manifest signs, and the installed release root this process
// protects. It returns both plus the manifest material.
func signedReleaseFixture(t *testing.T) (installRoot, artifactDir, manifestPath, publicPath string) {
	t.Helper()
	root := t.TempDir()
	installRoot = filepath.Join(root, "release")
	artifactDir = filepath.Join(root, "dist")
	if err := os.MkdirAll(artifactDir, 0o700); err != nil {
		t.Fatal(err)
	}
	artifacts := map[string]string{
		"gedefense-control":     "signed-control-v2",
		"gedefense-access":      "signed-access-v2",
		"gedefense-core":        "signed-core-v2",
		"gedefense-cell-helper": "signed-cell-helper-v2",
		"gedefense-ebpf":        "signed-ebpf-v2",
		"sbom.spdx.json":        `{"spdx": "v2"}`,
		"build-provenance.json": `{"builder": "test"}`,
	}
	for name, body := range artifacts {
		if err := os.WriteFile(filepath.Join(artifactDir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	privatePath := filepath.Join(root, "release.key")
	publicPath = filepath.Join(root, "release.pub")
	if err := os.WriteFile(privatePath, privateKey, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(publicPath, publicKey, 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SOURCE_DATE_EPOCH", "1784246400")
	manifestPath = filepath.Join(artifactDir, "release-manifest.signed.json")
	if err := SignReleaseDirectory(artifactDir, privatePath, publicPath, manifestPath); err != nil {
		t.Fatal(err)
	}
	installed := map[string]string{
		filepath.Join("bin", "gedefense-control"):           "old-control-v1",
		filepath.Join("bin", "gedefense-access"):            "old-access-v1",
		filepath.Join("libexec", "gedefense-core"):          "old-core-v1",
		filepath.Join("libexec", "gedefense-cell-helper"):   "old-cell-helper-v1",
		filepath.Join("lib", "gedefense", "gedefense-ebpf"): "old-ebpf-v1",
	}
	for relative, body := range installed {
		path := filepath.Join(installRoot, relative)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("VGT_RELEASE_ROOT", installRoot)
	return installRoot, artifactDir, manifestPath, publicPath
}

func installSignedReleaseArtifacts(t *testing.T, installRoot, artifactDir string) {
	t.Helper()
	targets := map[string]string{
		"gedefense-control":     filepath.Join(installRoot, "bin", "gedefense-control"),
		"gedefense-access":      filepath.Join(installRoot, "bin", "gedefense-access"),
		"gedefense-core":        filepath.Join(installRoot, "libexec", "gedefense-core"),
		"gedefense-cell-helper": filepath.Join(installRoot, "libexec", "gedefense-cell-helper"),
		"gedefense-ebpf":        filepath.Join(installRoot, "lib", "gedefense", "gedefense-ebpf"),
	}
	for artifact, target := range targets {
		body, err := os.ReadFile(filepath.Join(artifactDir, artifact))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(target, body, 0o755); err != nil {
			t.Fatal(err)
		}
	}
}

func newUpdateWindowEngine(t *testing.T) (*XDREngine, *State) {
	t.Helper()
	cfg := defaultConfig()
	state := NewState("update-window-test", cfg)
	engine := &XDREngine{
		cfg:           cfg,
		state:         state,
		selfPID:       -1,
		protected:     map[string]protectedObject{},
		degradeCauses: map[string]string{},
		tamperSeen:    map[string]string{},
	}
	return engine, state
}

func incidentsWithRule(state *State, ruleID string) []XDRIncident {
	var found []XDRIncident
	for _, incident := range state.Snapshot().Incidents {
		if containsString(incident.RuleIDs, ruleID) {
			found = append(found, incident)
		}
	}
	return found
}

// TestUnauthorizedOwnComponentReplacementIsSelfTamper is the FIND-025 regression test.
//
// Replacing one of this installation's own binaries outside a signed update window used to be
// recorded as AlertOnly with Action "none" and no degradation. It now has to be a critical
// XDR.SELF_TAMPER incident with an active-response shutdown and a release-blocking degradation.
func TestUnauthorizedOwnComponentReplacementIsSelfTamper(t *testing.T) {
	root := t.TempDir()
	t.Setenv("VGT_RELEASE_ROOT", root)
	core := filepath.Join(root, "libexec", "gedefense-core")
	if err := os.MkdirAll(filepath.Dir(core), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(core, []byte("release-v1"), 0o755); err != nil {
		t.Fatal(err)
	}
	engine, state := newUpdateWindowEngine(t)
	engine.protected[core] = protectedObject{path: core, digest: "stale-digest", mode: 0o755, size: 10}

	// An attacker swaps the component. No operator update window was opened.
	if err := os.WriteFile(core, []byte("attacker-v2"), 0o755); err != nil {
		t.Fatal(err)
	}
	engine.checkProtected()

	if degraded, reason := engine.degradedState(); !degraded {
		t.Fatalf("an unauthorized own-component replacement did not degrade XDR (reason=%q)", reason)
	}
	selfTampered := incidentsWithRule(state, "XDR.SELF_TAMPER")
	if len(selfTampered) != 1 {
		t.Fatalf("expected exactly one XDR.SELF_TAMPER incident, got %d", len(selfTampered))
	}
	incident := selfTampered[0]
	if incident.Decision != "degrade" || incident.Action != "disable-response" {
		t.Fatalf("the tamper was not fail-closed: decision=%s action=%s", incident.Decision, incident.Action)
	}
	if incident.Severity != "critical" {
		t.Fatalf("the tamper was not reported at critical severity: %s", incident.Severity)
	}
	for _, other := range state.Snapshot().Incidents {
		if other.Action == "none" && strings.Contains(other.Summary, "protected object changed") {
			t.Fatalf("an own-component change was downgraded to a recorded-only incident: %+v", other)
		}
	}
	if !state.Snapshot().XDR.Degraded {
		t.Fatal("the published XDR status does not report the degradation")
	}

	// The same observed state is one fact, not a repeating event.
	before := len(state.Snapshot().Incidents)
	engine.checkProtected()
	if after := len(state.Snapshot().Incidents); after != before {
		t.Fatalf("an unremediated tamper was announced again: %d -> %d incidents", before, after)
	}
}

// TestSignedUpdateWindowAllowsTheDeployment is the sanctioned counterpart: a verified signed
// release manifest opens a bounded window, and the exact bytes it names may replace the own
// components without being recorded as tampering.
func newUpdateWindowEnginePinned(t *testing.T, publicPath string) (*XDREngine, *State) {
	t.Helper()
	engine, state := newUpdateWindowEngine(t)
	if publicPath != "" {
		raw, err := os.ReadFile(publicPath)
		if err != nil {
			t.Fatal(err)
		}
		engine.pinnedReleaseKey = ed25519.PublicKey(raw)
	}
	return engine, state
}

func TestSignedUpdateWindowAllowsTheDeployment(t *testing.T) {
	installRoot, artifactDir, manifestPath, publicPath := signedReleaseFixture(t)
	engine, state := newUpdateWindowEnginePinned(t, publicPath)
	engine.captureProtected(productArtifactPaths())
	if len(engine.protected) != 5 {
		t.Fatalf("expected five protected release artifacts, got %d", len(engine.protected))
	}

	if err := engine.BeginSignedUpdateWindow(manifestPath, publicPath, artifactDir, "planned 5.2 package update", time.Minute); err != nil {
		t.Fatalf("a verified signed release manifest was refused: %v", err)
	}
	if !engine.SignedUpdateWindowActive() {
		t.Fatal("the update window was not open after a successful verification")
	}

	installSignedReleaseArtifacts(t, installRoot, artifactDir)
	engine.checkProtected()

	if degraded, reason := engine.degradedState(); degraded {
		t.Fatalf("a signed update window deployment degraded XDR: %s", reason)
	}
	if len(incidentsWithRule(state, "XDR.SELF_TAMPER")) != 0 {
		t.Fatal("a signed update window deployment was recorded as tampering")
	}
	if len(incidentsWithRule(state, "XDR.SELF_ARTIFACT")) != 0 {
		t.Fatal("the removed alert-only artifact rule is still emitted")
	}
	if engine.SignedUpdateWindowActive() {
		t.Fatal("the update window stayed open after every signed artifact was observed")
	}
	applied := 0
	for _, event := range state.Snapshot().Events {
		if event.Kind == "xdr.update_window_artifact_applied" {
			applied++
		}
	}
	if applied != 5 {
		t.Fatalf("expected one deployment record per signed artifact, got %d", applied)
	}

	// The in-memory baseline moved with the deployment, so the next check is quiet.
	before := len(state.Snapshot().Incidents)
	engine.checkProtected()
	if after := len(state.Snapshot().Incidents); after != before {
		t.Fatalf("the re-baselined deployment was reported again: %d -> %d incidents", before, after)
	}
}

// TestUpdateWindowRejectsUnpinnedReleaseKey proves F-01 is closed: even if a caller passes a
// freshly generated keypair matching a manifest they signed themselves, BeginSignedUpdateWindow
// verifies exclusively against the pinned release trust anchor.
func TestUpdateWindowRejectsUnpinnedReleaseKey(t *testing.T) {
	_, artifactDir, manifestPath, publicPath := signedReleaseFixture(t)
	engine, _ := newUpdateWindowEngine(t)
	if err := engine.BeginSignedUpdateWindow(manifestPath, publicPath, artifactDir, "attacker key attempt", time.Minute); err == nil {
		t.Fatal("an unpinned caller-supplied release key opened the update window")
	}
	if engine.SignedUpdateWindowActive() {
		t.Fatal("a rejected unpinned manifest left an open update window")
	}
}

// TestSignedUpdateWindowRefusesAnUnverifiedManifest keeps the window itself untamperable.
func TestSignedUpdateWindowRefusesAnUnverifiedManifest(t *testing.T) {
	_, artifactDir, manifestPath, publicPath := signedReleaseFixture(t)
	engine, _ := newUpdateWindowEnginePinned(t, publicPath)

	// A file that is not a signed release manifest must not open anything.
	bogus := filepath.Join(t.TempDir(), "bogus.json")
	if err := os.WriteFile(bogus, []byte(`{"schema":"vgt.gedefense.release.v1"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := engine.BeginSignedUpdateWindow(bogus, publicPath, artifactDir, "bogus", time.Minute); err == nil {
		t.Fatal("an unsigned document opened an update window")
	}
	if engine.SignedUpdateWindowActive() {
		t.Fatal("a refused manifest left an open update window")
	}

	// A validly signed manifest becomes invalid as soon as one staged artifact is modified:
	// the window must follow the bytes, not the signature alone.
	if err := os.WriteFile(filepath.Join(artifactDir, "gedefense-core"), []byte("swapped-after-signing"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := engine.BeginSignedUpdateWindow(manifestPath, publicPath, artifactDir, "tampered staging", time.Minute); err == nil {
		t.Fatal("a manifest whose artifacts no longer match its signature opened an update window")
	}
	if engine.SignedUpdateWindowActive() {
		t.Fatal("a refused manifest left an open update window")
	}
}

// TestUpdateWindowDoesNotAuthorizeOtherBytes makes the window an allow-list of exact digests,
// not a general suspension of detection.
func TestUpdateWindowDoesNotAuthorizeOtherBytes(t *testing.T) {
	installRoot, artifactDir, manifestPath, publicPath := signedReleaseFixture(t)
	core := filepath.Join(installRoot, "libexec", "gedefense-core")
	engine, state := newUpdateWindowEnginePinned(t, publicPath)
	engine.captureProtected(productArtifactPaths())
	if err := engine.BeginSignedUpdateWindow(manifestPath, publicPath, artifactDir, "planned update", time.Minute); err != nil {
		t.Fatal(err)
	}
	// Not the bytes the signed manifest names.
	if err := os.WriteFile(core, []byte("neither-old-nor-signed"), 0o755); err != nil {
		t.Fatal(err)
	}
	engine.checkProtected()

	if degraded, _ := engine.degradedState(); !degraded {
		t.Fatal("bytes that the signed manifest does not name were accepted inside the update window")
	}
	if len(incidentsWithRule(state, "XDR.SELF_TAMPER")) != 1 {
		t.Fatal("the swapped component was not recorded as XDR.SELF_TAMPER")
	}
}

// TestAnExpiredUpdateWindowNoLongerCoversChanges proves the window is bounded in time.
func TestAnExpiredUpdateWindowNoLongerCoversChanges(t *testing.T) {
	installRoot, artifactDir, manifestPath, publicPath := signedReleaseFixture(t)
	engine, state := newUpdateWindowEnginePinned(t, publicPath)
	engine.captureProtected(productArtifactPaths())
	if err := engine.BeginSignedUpdateWindow(manifestPath, publicPath, artifactDir, "planned update", time.Minute); err != nil {
		t.Fatal(err)
	}
	engine.mu.Lock()
	engine.updateWindow.ExpiresAt = time.Now().Add(-time.Minute)
	engine.mu.Unlock()

	installSignedReleaseArtifacts(t, installRoot, artifactDir)
	engine.checkProtected()

	if degraded, _ := engine.degradedState(); !degraded {
		t.Fatal("an expired update window still authorized a component replacement")
	}
	if len(incidentsWithRule(state, "XDR.SELF_TAMPER")) == 0 {
		t.Fatal("an expired update window did not produce XDR.SELF_TAMPER")
	}
}

// TestTamperedOwnComponentBlocksTheReleaseGate is the release-degradation half of FIND-025.
func TestTamperedOwnComponentBlocksTheReleaseGate(t *testing.T) {
	cfg, state, release := updateWindowReleaseFixture(t)
	if _, err := release.Transition(ReleasePhaseCanary, "PROMOTE:CANARY", "enter canary before the artifact swap"); err != nil {
		t.Fatal(err)
	}
	if _, err := state.AddBlock("203.0.113.77/32", "block before the artifact swap", "test", time.Hour, false, cfg.Defense.MaxBlockEntries); err != nil {
		t.Fatal(err)
	}
	if _, err := release.Transition(ReleasePhaseEnforce, "PROMOTE:ENFORCE", "arm enforcement before the artifact swap"); err != nil {
		t.Fatal(err)
	}

	root := t.TempDir()
	t.Setenv("VGT_RELEASE_ROOT", root)
	core := filepath.Join(root, "libexec", "gedefense-core")
	if err := os.MkdirAll(filepath.Dir(core), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(core, []byte("release-v1"), 0o755); err != nil {
		t.Fatal(err)
	}
	engine := &XDREngine{cfg: cfg, state: state, selfPID: -1, protected: map[string]protectedObject{
		core: {path: core, digest: "stale-digest", mode: 0o755, size: 10},
	}, degradeCauses: map[string]string{}, tamperSeen: map[string]string{}}
	if err := os.WriteFile(core, []byte("attacker-v2"), 0o755); err != nil {
		t.Fatal(err)
	}
	engine.checkProtected()
	if len(incidentsWithRule(state, "XDR.SELF_TAMPER")) != 1 {
		t.Fatal("the unauthorized own-component replacement left no XDR.SELF_TAMPER record")
	}

	release.Evaluate()
	status := release.Status()
	if status.Phase != ReleasePhaseDegraded {
		t.Fatalf("a tampered own component did not degrade the release gate: phase=%s blockers=%v", status.Phase, status.Blockers)
	}
	blockerFound := false
	for _, blocker := range status.Blockers {
		if strings.Contains(blocker, "XDR is degraded") {
			blockerFound = true
		}
	}
	if !blockerFound {
		t.Fatalf("the degraded XDR state is not a release blocker: %v", status.Blockers)
	}
}

// updateWindowReleaseCore is the kernel side of the release fixture; it accepts every
// reconciliation the fail-safe path performs.
type updateWindowReleaseCore struct{}

func (updateWindowReleaseCore) Add(string) error            { return nil }
func (updateWindowReleaseCore) Delete(string) error         { return nil }
func (updateWindowReleaseCore) ClearBlocklist() error       { return nil }
func (updateWindowReleaseCore) VerifyBlocklistEmpty() error { return nil }

func updateWindowReleaseFixture(t *testing.T) (Config, *State, *ReleaseController) {
	t.Helper()
	dir := t.TempDir()
	cfg := defaultConfig()
	cfg.Policy.StorageKeyFile = ""
	cfg.Node.Name = "update-window-release-test"
	cfg.Defense.Allowlist = []string{"192.0.2.10/32"}
	cfg.Release.MinimumObserveSeconds = 0
	cfg.Release.MinimumCanarySeconds = 0
	cfg.Release.EmergencyStopFile = filepath.Join(dir, "EMERGENCY_STOP")
	cfg.Policy.StateFile = filepath.Join(dir, "policy.json")
	cfg.Policy.SigningKeyFile = filepath.Join(dir, "policy.key")
	cfg.Policy.PublicKeyFile = filepath.Join(dir, "policy.pub")
	state := NewState("test", cfg)
	verifiedAt := time.Now().UTC()
	state.SetSensorCoverage(SensorCoverage{
		Name: "xdp_ingress", Layer: LayerIngressNetwork, Status: CoverageOnline, Required: true,
		LastOK: &verifiedAt, SelfTest: "pass", CoverageReason: "verified update-window fixture",
	})
	policy, err := NewPolicyStore(cfg.Policy)
	if err != nil {
		t.Fatal(err)
	}
	state.SetPolicyStatus(policy.Status())
	state.SetCore(true, "native")
	state.SetAllowlistReady(true)
	state.UpdateXDRScan(1, 0, state.started, false, "", 1)
	release := NewReleaseController(cfg, state, updateWindowReleaseCore{}, policy, nil)
	if err := release.InitializeStartup("observe", true); err != nil {
		t.Fatal(err)
	}
	return cfg, state, release
}
