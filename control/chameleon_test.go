// V6.3.0 AP-8: Chameleon control-plane profile tests (manifest parser,
// configuration application, evidence commitment and the default-off identity).
package main

import (
	"os"
	"reflect"
	"strings"
	"testing"
	"time"
)

const chameleonTestSalt = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func chameleonTestManifest(stateDir, configDir string) string {
	return chameleonManifestSchema + "\n" +
		"install_id=gd-ap8-test-install-0001\n" +
		"bpf_name_salt=" + chameleonTestSalt + "\n" +
		"core_socket=/run/chameleon/core.sock\n" +
		"scan_socket=/run/chameleon/scan.sock\n" +
		"bpf_pin_root=/sys/fs/bpf/chameleon\n" +
		"state_dir=" + stateDir + "\n" +
		"config_dir=" + configDir + "\n" +
		"public_port=39000\n" +
		"backend_port=39001\n" +
		"neutral_unit_prefix=cham\n"
}

func writeChameleonManifest(t *testing.T, contents string, mode uint32) string {
	t.Helper()
	path := t.TempDir() + "/manifest.conf"
	if err := writeChameleonTestFile(path, contents, mode); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
	return path
}

func writeChameleonTestFile(path, contents string, mode uint32) error {
	if err := os.WriteFile(path, []byte(contents), os.FileMode(mode)); err != nil {
		return err
	}
	return os.Chmod(path, os.FileMode(mode))
}

func TestChameleonProfileInactiveByDefault(t *testing.T) {
	profile, err := NewChameleonProfile("")
	if err != nil {
		t.Fatalf("empty manifest path must disable the profile: %v", err)
	}
	if profile.Active() {
		t.Fatal("empty manifest path must not activate Chameleon")
	}
	cfg := defaultConfig()
	if applied := profile.Apply(cfg); !reflect.DeepEqual(applied, cfg) {
		t.Fatal("inactive profile must be an identity transform")
	}
	if _, ok := profile.AuditMapping(); ok {
		t.Fatal("inactive profile must not produce an audit mapping")
	}
	// Process-wide helpers are the documented public identity.
	installChameleonProfile(nil)
	t.Cleanup(func() { installChameleonProfile(nil) })
	if socket := chameleonScanSocket(); socket != chameleonDefaultScanSocket {
		t.Fatalf("inactive scan socket = %q, want %q", socket, chameleonDefaultScanSocket)
	}
	if root := chameleonBpfPinRoot(); root != chameleonDefaultBpfPinRoot {
		t.Fatalf("inactive bpf pin root = %q, want %q", root, chameleonDefaultBpfPinRoot)
	}
}

func TestChameleonProfileParsesAndAppliesTheNeutralIdentity(t *testing.T) {
	root := t.TempDir()
	stateDir := root + "/state"
	configDir := root + "/config"
	path := writeChameleonManifest(t, chameleonTestManifest(stateDir, configDir), 0o600)
	profile, err := NewChameleonProfile(path)
	if err != nil {
		t.Fatalf("valid manifest rejected: %v", err)
	}
	if !profile.Active() {
		t.Fatal("valid manifest must activate the profile")
	}
	manifest, ok := profile.Manifest()
	if !ok || manifest.InstallID != "gd-ap8-test-install-0001" {
		t.Fatalf("manifest not parsed: %+v", manifest)
	}
	installChameleonProfile(profile)
	t.Cleanup(func() { installChameleonProfile(nil) })
	if socket := chameleonScanSocket(); socket != "/run/chameleon/scan.sock" {
		t.Fatalf("active scan socket = %q", socket)
	}
	if root := chameleonBpfPinRoot(); root != "/sys/fs/bpf/chameleon" {
		t.Fatalf("active bpf pin root = %q", root)
	}
	cfg := defaultConfig()
	applied := profile.Apply(cfg)
	if applied.Core.Socket != "/run/chameleon/core.sock" {
		t.Fatalf("core socket = %q", applied.Core.Socket)
	}
	if applied.Dashboard.Listen != "127.0.0.1:39001" {
		t.Fatalf("dashboard listen = %q", applied.Dashboard.Listen)
	}
	if !reflect.DeepEqual(applied.Dashboard.AllowedHosts, cfg.Dashboard.AllowedHosts) {
		t.Fatal("dashboard allowed hosts must stay the loopback-only default")
	}
	for label, got := range map[string]string{
		"policy state":      applied.Policy.StateFile,
		"xdr incident log":  applied.XDR.IncidentLog,
		"behavior profile":  applied.XDR.BehaviorProfileFile,
		"runtime settings":  applied.Runtime.SettingsFile,
		"emergency stop":    applied.Release.EmergencyStopFile,
		"feed manifest":     applied.Feeds.ManifestPath,
		"feed snapshot dir": applied.Feeds.SnapshotDir,
	} {
		if !strings.HasPrefix(got, stateDir+"/") {
			t.Fatalf("%s path %q is not under the neutral state dir %q", label, got, stateDir)
		}
	}
	// Security-relevant material stays where it was provisioned; the profile
	// must never move a key, token or trust anchor on its own. The runtime
	// settings key stays put because the settings store refuses to start without
	// an existing key; only the (regenerated) settings document moves.
	if applied.Core.AuthKeyFile != cfg.Core.AuthKeyFile ||
		applied.Policy.SigningKeyFile != cfg.Policy.SigningKeyFile ||
		applied.Policy.StorageKeyFile != cfg.Policy.StorageKeyFile ||
		applied.Runtime.KeyFile != cfg.Runtime.KeyFile ||
		applied.Runtime.StorageKeyFile != cfg.Runtime.StorageKeyFile ||
		applied.Dashboard.TokenFile != cfg.Dashboard.TokenFile ||
		applied.Dashboard.TLSCertFile != cfg.Dashboard.TLSCertFile {
		t.Fatal("Chameleon Apply must not move key/token/TLS files")
	}
	if applied.Defense.Enforcement != cfg.Defense.Enforcement || applied.L7.Enabled != cfg.L7.Enabled {
		t.Fatal("Chameleon Apply must not change enforcement or feature toggles")
	}
}

func TestChameleonManifestRejectsInvalidDocuments(t *testing.T) {
	root := t.TempDir()
	base := chameleonTestManifest(root+"/state", root+"/config")
	mutations := map[string]string{
		"missing key": strings.Replace(base, "backend_port=39001\n", "", 1),
		"unknown key": base + "unexpected_key=value\n",
		"duplicate":   base + "public_port=39000\n",
		"schema":      "wrong-schema\n" + base,
		"bad install id": strings.Replace(base, "install_id=gd-ap8-test-install-0001",
			"install_id=short", 1),
		"bad salt": strings.Replace(base, chameleonTestSalt, "zz"+chameleonTestSalt[2:], 1),
		"relative socket": strings.Replace(base, "core_socket=/run/chameleon/core.sock",
			"core_socket=core.sock", 1),
		"dotdot path": strings.Replace(base, "state_dir="+root+"/state",
			"state_dir="+root+"/../state", 1),
		"equal ports": strings.Replace(base, "backend_port=39001", "backend_port=39000", 1),
		"low port":    strings.Replace(base, "public_port=39000", "public_port=80", 1),
		"equal socket": strings.Replace(base, "scan_socket=/run/chameleon/scan.sock",
			"scan_socket=/run/chameleon/core.sock", 1),
		"bad unit prefix": strings.Replace(base, "neutral_unit_prefix=cham",
			"neutral_unit_prefix=Cham", 1),
		"control character": base + "admin_audit_path=/var/lib/x\x01y\n",
		"crlf":              strings.ReplaceAll(base, "\n", "\r\n"),
	}
	for label, document := range mutations {
		path := writeChameleonManifest(t, document, 0o600)
		if _, err := NewChameleonProfile(path); err == nil {
			t.Fatalf("%s: invalid manifest accepted", label)
		}
	}
}

func TestChameleonManifestFilePolicy(t *testing.T) {
	root := t.TempDir()
	stateDir, configDir := root+"/state", root+"/config"
	valid := chameleonTestManifest(stateDir, configDir)
	// Group/world writable manifest is rejected.
	readable := root + "/world-readable.conf"
	if err := writeChameleonTestFile(readable, valid, 0o666); err != nil {
		t.Fatal(err)
	}
	if _, err := NewChameleonProfile(readable); err == nil ||
		!strings.Contains(err.Error(), "group/world writable") {
		t.Fatalf("world-writable manifest accepted: %v", err)
	}
	// Symlinked manifest is rejected (O_NOFOLLOW).
	real := root + "/real.conf"
	if err := writeChameleonTestFile(real, valid, 0o600); err != nil {
		t.Fatal(err)
	}
	link := root + "/link.conf"
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	if _, err := NewChameleonProfile(link); err == nil {
		t.Fatal("symlinked manifest accepted")
	}
	// Oversized manifest is rejected by the file bound.
	oversized := root + "/oversized.conf"
	if err := writeChameleonTestFile(oversized, chameleonManifestSchema+"\n"+
		strings.Repeat("#", chameleonManifestMaxBytes+1), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewChameleonProfile(oversized); err == nil {
		t.Fatal("oversized manifest accepted")
	}
	// Missing and relative paths are errors.
	if _, err := NewChameleonProfile(root + "/missing.conf"); err == nil {
		t.Fatal("missing manifest accepted")
	}
	if _, err := NewChameleonProfile("relative.conf"); err == nil {
		t.Fatal("relative manifest path accepted")
	}
}

func TestChameleonAuditMappingCommitment(t *testing.T) {
	root := t.TempDir()
	manifest := chameleonTestManifest(root+"/state", root+"/config")
	first, err := NewChameleonProfile(writeChameleonManifest(t, manifest, 0o600))
	if err != nil {
		t.Fatal(err)
	}
	second, err := NewChameleonProfile(writeChameleonManifest(t, manifest, 0o600))
	if err != nil {
		t.Fatal(err)
	}
	mapping, ok := first.AuditMapping()
	if !ok {
		t.Fatal("active profile must expose an audit mapping")
	}
	otherMapping, ok := second.AuditMapping()
	if !ok || mapping != otherMapping {
		t.Fatal("the mapping commitment must be deterministic")
	}
	if mapping.InstallID != "gd-ap8-test-install-0001" || len(mapping.SaltFingerprint) != 64 ||
		len(mapping.MappingHash) != 64 {
		t.Fatalf("unexpected mapping commitment: %+v", mapping)
	}
	if strings.Contains(mapping.MappingHash, chameleonTestSalt) ||
		strings.Contains(mapping.SaltFingerprint, chameleonTestSalt) {
		t.Fatal("the audit commitment must not carry the raw salt")
	}
	// Another salt derives a different commitment.
	otherSalt := strings.Replace(manifest, chameleonTestSalt,
		"fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210", 1)
	third, err := NewChameleonProfile(writeChameleonManifest(t, otherSalt, 0o600))
	if err != nil {
		t.Fatal(err)
	}
	thirdMapping, ok := third.AuditMapping()
	if !ok || thirdMapping.MappingHash == mapping.MappingHash {
		t.Fatal("different salts must commit to different mappings")
	}
}

func TestChameleonUserMalwareScanRejectsNonNeutralEndpoints(t *testing.T) {
	installChameleonProfile(nil)
	t.Cleanup(func() { installChameleonProfile(nil) })
	// Inactive profile with an invalid file path: the packaged UserMalwareScan
	// path validation still rejects it.
	if _, err := chameleonUserMalwareScan("/etc/passwd", 5*time.Second); err == nil ||
		!strings.Contains(err.Error(), "path rejected") {
		t.Fatalf("invalid scan path accepted: %v", err)
	}
	// An active profile pointing at a socket outside /run is rejected before any
	// connection is attempted.
	installChameleonProfile(&ChameleonProfile{
		enabled:  true,
		manifest: ChameleonManifest{ScanSocket: "/tmp/chameleon-scan.sock"},
	})
	if _, err := chameleonUserMalwareScan("/etc/passwd", 5*time.Second); err == nil ||
		!strings.Contains(err.Error(), "endpoint rejected") {
		t.Fatalf("non-runtime socket accepted: %v", err)
	}
	// An active profile with a valid neutral runtime socket keeps the same path
	// validation: a forbidden path is rejected without dialing.
	installChameleonProfile(&ChameleonProfile{
		enabled:  true,
		manifest: ChameleonManifest{ScanSocket: "/run/chameleon/scan.sock"},
	})
	if _, err := chameleonUserMalwareScan("/etc/passwd", 5*time.Second); err == nil ||
		!strings.Contains(err.Error(), "path rejected") {
		t.Fatalf("forbidden path accepted: %v", err)
	}
}

func TestChameleonManifestKeysAreStable(t *testing.T) {
	keys := chameleonManifestKeys()
	expected := []string{
		"admin_audit_path", "backend_port", "bpf_name_salt", "bpf_pin_root", "config_dir",
		"core_socket", "install_id", "neutral_unit_prefix", "public_port", "scan_socket",
		"state_dir",
	}
	if !reflect.DeepEqual(keys, expected) {
		t.Fatalf("manifest key set drifted: %v", keys)
	}
}
