// STATUS: DIAMANT VGT SUPREME
// SPDX-FileCopyrightText: 2026 VisionGaia Technology
// SPDX-License-Identifier: AGPL-3.0-only

//go:build linux

package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func titanTestVerifier(cfg titanPackageDBConfig) *titanLocalPackageVerifier {
	return &titanLocalPackageVerifier{cfg: cfg, now: func() time.Time { return time.Date(2026, 10, 22, 21, 0, 0, 0, time.UTC) }}
}

func titanWriteFixtureFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func newTitanDPKGFixture(t *testing.T) (titanPackageDBConfig, string) {
	t.Helper()
	base := t.TempDir()
	dpkgRoot := filepath.Join(base, "dpkg")
	titanWriteFixtureFile(t, filepath.Join(dpkgRoot, "status"), `Package: openssl
Status: install ok installed
Architecture: amd64

Package: base-files
Status: install ok installed
Architecture: amd64

Package: removed-pkg
Status: deinstall ok config-files
Architecture: amd64
`)
	titanWriteFixtureFile(t, filepath.Join(dpkgRoot, "info", "openssl.list"), "/usr/bin/openssl\n/usr/lib/x86_64-linux-gnu/libssl.so.3\n/etc/ssl/openssl.cnf\n\nrelative/path\n/usr/bin/../bin/evil\n")
	titanWriteFixtureFile(t, filepath.Join(dpkgRoot, "info", "base-files:amd64.list"), "/etc/os-release\n/usr/share/base-files/\n")
	titanWriteFixtureFile(t, filepath.Join(dpkgRoot, "info", "removed-pkg.list"), "/usr/lib/removed-pkg.so\n")
	cfg := defaultTitanPackageDBConfig()
	cfg.dpkgRoot = dpkgRoot
	cfg.pacmanRoot = filepath.Join(base, "pacman")
	cfg.rpmRoot = filepath.Join(base, "rpm")
	cfg.ttl = time.Hour
	return cfg, base
}

func TestTitanDPKGOwnershipReader(t *testing.T) {
	cfg, _ := newTitanDPKGFixture(t)
	verifier := titanTestVerifier(cfg)
	ctx := context.Background()
	cases := map[string]string{
		"/usr/bin/openssl":                      "openssl",
		"/usr/lib/x86_64-linux-gnu/libssl.so.3": "openssl",
		"/etc/ssl/openssl.cnf":                  "openssl",
		"/etc/os-release":                       "base-files",
		"/usr/share/base-files":                 "base-files",
	}
	for path, want := range cases {
		owner, found, err := verifier.Owner(ctx, path)
		if err != nil {
			t.Fatalf("owner(%q) error: %v", path, err)
		}
		if !found || owner.Manager != "dpkg" || owner.Package != want {
			t.Fatalf("owner(%q) = %+v found=%t, want package %q", path, owner, found, want)
		}
	}
	// A path inside the readable database but not listed is no evidence, not an
	// authorization.
	if _, found, err := verifier.Owner(ctx, "/usr/bin/not-installed"); err != nil || found {
		t.Fatalf("unowned path = found=%t err=%v", found, err)
	}
	// Malformed database lines never become ownership evidence.
	if _, found, _ := verifier.Owner(ctx, "/usr/bin/evil"); found {
		t.Fatal("malformed list line produced ownership evidence")
	}
	if _, found, _ := verifier.Owner(ctx, "/usr/lib/removed-pkg.so"); found {
		t.Fatal("non-installed package list was trusted")
	}
	for _, invalid := range []string{"", "relative/path", "../etc/passwd", "/", "/tmp/../etc/passwd", strings.Repeat("/a", 3000)} {
		if _, _, err := verifier.Owner(ctx, invalid); err == nil {
			t.Fatalf("invalid ownership path accepted: %q", invalid)
		}
	}
}

func TestTitanPackageIndexCacheRebuildsAfterTTL(t *testing.T) {
	cfg, base := newTitanDPKGFixture(t)
	cfg.ttl = 10 * time.Minute
	now := time.Date(2026, 10, 22, 21, 0, 0, 0, time.UTC)
	verifier := &titanLocalPackageVerifier{cfg: cfg, now: func() time.Time { return now }}
	ctx := context.Background()
	if _, found, err := verifier.Owner(ctx, "/usr/bin/openssl"); err != nil || !found {
		t.Fatalf("initial index build failed: found=%t err=%v", found, err)
	}
	// Extend the fixture without changing the cache window.
	titanWriteFixtureFile(t, filepath.Join(base, "dpkg", "info", "openssl.list"), "/usr/bin/openssl\n/opt/pilot/new-tool\n")
	if _, found, err := verifier.Owner(ctx, "/opt/pilot/new-tool"); err != nil || found {
		t.Fatalf("cache served a rebuilt index before its TTL: found=%t err=%v", found, err)
	}
	now = now.Add(11 * time.Minute)
	owner, found, err := verifier.Owner(ctx, "/opt/pilot/new-tool")
	if err != nil || !found || owner.Package != "openssl" {
		t.Fatalf("index did not rebuild after TTL: %+v found=%t err=%v", owner, found, err)
	}
}

func TestTitanDPKGDatabaseFailuresAreUnavailable(t *testing.T) {
	ctx := context.Background()
	t.Run("missing database", func(t *testing.T) {
		base := t.TempDir()
		cfg := defaultTitanPackageDBConfig()
		cfg.dpkgRoot = filepath.Join(base, "no-dpkg")
		cfg.pacmanRoot = filepath.Join(base, "no-pacman")
		cfg.rpmRoot = filepath.Join(base, "no-rpm")
		if _, _, err := titanTestVerifier(cfg).Owner(ctx, "/usr/bin/openssl"); err == nil || !strings.Contains(err.Error(), "package manager ownership evidence unavailable") {
			t.Fatalf("missing database error = %v", err)
		}
	})
	t.Run("rpm only is explicitly unavailable", func(t *testing.T) {
		base := t.TempDir()
		cfg := defaultTitanPackageDBConfig()
		cfg.dpkgRoot = filepath.Join(base, "no-dpkg")
		cfg.pacmanRoot = filepath.Join(base, "no-pacman")
		cfg.rpmRoot = filepath.Join(base, "rpm")
		titanWriteFixtureFile(t, filepath.Join(base, "rpm", "rpmdb.sqlite"), "rpm")
		if _, _, err := titanTestVerifier(cfg).Owner(ctx, "/usr/bin/openssl"); err == nil || !strings.Contains(err.Error(), "rpm database cannot be read") {
			t.Fatalf("rpm-only error = %v", err)
		}
	})
	t.Run("corrupt status", func(t *testing.T) {
		base := t.TempDir()
		cfg := defaultTitanPackageDBConfig()
		cfg.dpkgRoot = filepath.Join(base, "dpkg")
		cfg.pacmanRoot = filepath.Join(base, "no-pacman")
		cfg.rpmRoot = filepath.Join(base, "no-rpm")
		titanWriteFixtureFile(t, filepath.Join(base, "dpkg", "status"), "this is not a dpkg status document\n")
		if _, _, err := titanTestVerifier(cfg).Owner(ctx, "/usr/bin/openssl"); err == nil || !strings.Contains(err.Error(), "no installed packages") {
			t.Fatalf("corrupt status error = %v", err)
		}
	})
	t.Run("symlinked status is not followed", func(t *testing.T) {
		base := t.TempDir()
		cfg := defaultTitanPackageDBConfig()
		cfg.dpkgRoot = filepath.Join(base, "dpkg")
		cfg.pacmanRoot = filepath.Join(base, "no-pacman")
		cfg.rpmRoot = filepath.Join(base, "no-rpm")
		realStatus := filepath.Join(base, "real-status")
		titanWriteFixtureFile(t, realStatus, "Package: openssl\nStatus: install ok installed\nArchitecture: amd64\n")
		if err := os.MkdirAll(filepath.Join(base, "dpkg"), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(realStatus, filepath.Join(base, "dpkg", "status")); err != nil {
			t.Skipf("symlink not available: %v", err)
		}
		if _, _, err := titanTestVerifier(cfg).Owner(ctx, "/usr/bin/openssl"); err == nil {
			t.Fatal("symlinked dpkg status was trusted")
		}
	})
	t.Run("symlinked info directory is rejected", func(t *testing.T) {
		cfg, base := newTitanDPKGFixture(t)
		realInfo := filepath.Join(base, "dpkg", "info")
		movedInfo := filepath.Join(base, "moved-info")
		if err := os.Rename(realInfo, movedInfo); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(movedInfo, realInfo); err != nil {
			t.Skipf("symlink not available: %v", err)
		}
		if _, _, err := titanTestVerifier(cfg).Owner(ctx, "/usr/bin/openssl"); err == nil || !strings.Contains(err.Error(), "dpkg info directory") {
			t.Fatalf("symlinked info directory error = %v", err)
		}
	})
	t.Run("oversized status is rejected", func(t *testing.T) {
		cfg, base := newTitanDPKGFixture(t)
		cfg.maxStatusBytes = 64
		titanWriteFixtureFile(t, filepath.Join(base, "dpkg", "status"), strings.Repeat("Package: padding\n", 20))
		if _, _, err := titanTestVerifier(cfg).Owner(ctx, "/usr/bin/openssl"); err == nil || !strings.Contains(err.Error(), "dpkg status cannot be read safely") {
			t.Fatalf("oversized status error = %v", err)
		}
	})
}

func TestTitanPackageIndexIsBounded(t *testing.T) {
	cfg, base := newTitanDPKGFixture(t)
	cfg.maxEntries = 2
	titanWriteFixtureFile(t, filepath.Join(base, "dpkg", "info", "openssl.list"), "/a/one\n/b/two\n/c/three\n")
	if _, _, err := titanTestVerifier(cfg).Owner(context.Background(), "/a/one"); err == nil || !strings.Contains(err.Error(), "exceeds the bound") {
		t.Fatalf("unbounded index was not rejected: %v", err)
	}
}

func newTitanPacmanFixture(t *testing.T) titanPackageDBConfig {
	t.Helper()
	base := t.TempDir()
	pacmanRoot := filepath.Join(base, "pacman")
	packageDir := filepath.Join(pacmanRoot, "local", "openssl-3.0.13-1")
	titanWriteFixtureFile(t, filepath.Join(packageDir, "desc"), `%NAME%
openssl

%VERSION%
3.0.13-1

%ARCH%
x86_64
`)
	titanWriteFixtureFile(t, filepath.Join(packageDir, "files"), `%FILES%
usr/bin/openssl
usr/lib/libssl.so.3
etc/ssl/openssl.cnf
usr/share/doc/openssl/

%BACKUP%
etc/ssl/openssl.cnf
`)
	cfg := defaultTitanPackageDBConfig()
	cfg.dpkgRoot = filepath.Join(base, "no-dpkg")
	cfg.pacmanRoot = pacmanRoot
	cfg.rpmRoot = filepath.Join(base, "no-rpm")
	cfg.ttl = time.Hour
	return cfg
}

func TestTitanPacmanOwnershipReader(t *testing.T) {
	cfg := newTitanPacmanFixture(t)
	verifier := titanTestVerifier(cfg)
	ctx := context.Background()
	for _, path := range []string{"/usr/bin/openssl", "/usr/lib/libssl.so.3", "/etc/ssl/openssl.cnf", "/usr/share/doc/openssl"} {
		owner, found, err := verifier.Owner(ctx, path)
		if err != nil {
			t.Fatalf("owner(%q) error: %v", path, err)
		}
		if !found || owner.Manager != "pacman" || owner.Package != "openssl" {
			t.Fatalf("owner(%q) = %+v found=%t", path, owner, found)
		}
	}
	// The %BACKUP% section must never become a file list.
	if _, found, _ := verifier.Owner(ctx, "/usr/share/doc/openssl"); !found {
		t.Fatal("directory entry lost")
	}
	if _, found, err := verifier.Owner(ctx, "/etc/ssl/openssl.cnf/extra"); err != nil || found {
		t.Fatalf("unlisted pacman path = found=%t err=%v", found, err)
	}
}

func TestTitanPacmanMalformedDatabase(t *testing.T) {
	cfg := newTitanPacmanFixture(t)
	base := filepath.Dir(cfg.pacmanRoot)
	titanWriteFixtureFile(t, filepath.Join(cfg.pacmanRoot, "local", "openssl-3.0.13-1", "files"), "%FILES%\nnot/../an/escape\n\n%BACKUP%\n")
	if _, _, err := titanTestVerifier(cfg).Owner(context.Background(), "/usr/bin/openssl"); err == nil || !strings.Contains(err.Error(), "no ownership entries") {
		t.Fatalf("malformed pacman database error = %v", err)
	}
	_ = base
}

func TestTitanPackageVerifierConstructor(t *testing.T) {
	verifier := newTitanPackageVerifier()
	if verifier == nil {
		t.Fatal("newTitanPackageVerifier returned nil")
	}
	// The default verifier must never execute a package manager; this only
	// asserts the type, not the host database.
	if _, ok := verifier.(*titanLocalPackageVerifier); !ok {
		t.Fatalf("unexpected verifier type %T", verifier)
	}
}
