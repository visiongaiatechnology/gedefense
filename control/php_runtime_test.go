// STATUS: DIAMANT VGT SUPREME
package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writePHPFixture(t *testing.T, root, relative, content string) {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(relative))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func phpPostureCollector(root string) *HardeningCollector {
	return newHardeningCollectorForTest(root, func() time.Time { return time.Now().UTC() })
}

func TestPHPUploadProgressCheckProtectsExplicitOff(t *testing.T) {
	root := t.TempDir()
	writePHPFixture(t, root, "www/server/php/83/etc/php.ini", "[PHP]\n;session.upload_progress.enabled = On\nsession.upload_progress.enabled = Off\n")
	check := phpPostureCollector(root).phpUploadProgressCheck()
	if check.State != hardeningStateProtected {
		t.Fatalf("expected PROTECTED, got %s (%s)", check.State, check.Evidence)
	}
	if !strings.Contains(check.Evidence, "explicit off=1") {
		t.Fatalf("evidence does not name the explicit Off: %q", check.Evidence)
	}
}

func TestPHPUploadProgressCheckFlagsPHPDefaultOn(t *testing.T) {
	root := t.TempDir()
	// The PHP default is On; an ini file that never mentions the directive is exposure.
	writePHPFixture(t, root, "etc/php/8.3/fpm/php.ini", "[PHP]\nmemory_limit = 256M\n")
	check := phpPostureCollector(root).phpUploadProgressCheck()
	if check.State != hardeningStateUnprotected {
		t.Fatalf("expected UNPROTECTED for the PHP default On, got %s (%s)", check.State, check.Evidence)
	}
	if check.Recommendation == "" {
		t.Fatal("exposure must carry a recommendation")
	}
}

func TestPHPUploadProgressCheckFlagsPerDirectoryOverride(t *testing.T) {
	root := t.TempDir()
	writePHPFixture(t, root, "www/server/php/83/etc/php.ini", "session.upload_progress.enabled = Off\n")
	writePHPFixture(t, root, "www/wwwroot/example.test/.user.ini", "open_basedir=/www/wwwroot/example.test/\nsession.upload_progress.enabled = On\n")
	check := phpPostureCollector(root).phpUploadProgressCheck()
	if check.State != hardeningStateUnprotected {
		t.Fatalf("expected UNPROTECTED for a per-directory override, got %s (%s)", check.State, check.Evidence)
	}
	if !strings.Contains(check.Evidence, "override on=") {
		t.Fatalf("override is not visible in evidence: %q", check.Evidence)
	}
}

func TestPHPUploadProgressCheckFlagsPoolAdminOverride(t *testing.T) {
	root := t.TempDir()
	writePHPFixture(t, root, "etc/php/8.3/fpm/php.ini", "session.upload_progress.enabled = Off\n")
	writePHPFixture(t, root, "etc/php/8.3/fpm/pool.d/www.conf", "[www]\nphp_admin_value[session.upload_progress.enabled] = On\n")
	check := phpPostureCollector(root).phpUploadProgressCheck()
	if check.State != hardeningStateUnprotected {
		t.Fatalf("expected UNPROTECTED for a pool admin override, got %s (%s)", check.State, check.Evidence)
	}
}

func TestPHPUploadProgressCheckHonoursScanDirOrder(t *testing.T) {
	root := t.TempDir()
	writePHPFixture(t, root, "etc/php/8.3/fpm/php.ini", "session.upload_progress.enabled = Off\n")
	writePHPFixture(t, root, "etc/php/8.3/fpm/conf.d/10-upload-progress.ini", "session.upload_progress.enabled = On\n")
	check := phpPostureCollector(root).phpUploadProgressCheck()
	if check.State != hardeningStateUnprotected {
		t.Fatalf("a scanned ini file must override the main php.ini, got %s (%s)", check.State, check.Evidence)
	}
}

func TestPHPUploadProgressCheckUnavailableWithoutWebPHP(t *testing.T) {
	root := t.TempDir()
	check := phpPostureCollector(root).phpUploadProgressCheck()
	if check.State != hardeningStateUnavailable {
		t.Fatalf("a host without a web PHP SAPI has nothing to protect, got %s (%s)", check.State, check.Evidence)
	}
}

func TestHardeningPostureIncludesPHPUploadProgressDomain(t *testing.T) {
	root := t.TempDir()
	writePHPFixture(t, root, "www/server/php/83/etc/php.ini", "session.upload_progress.enabled = Off\n")
	posture := phpPostureCollector(root).Collect(Snapshot{}, BootTrustReport{})
	foundCheck := false
	for _, check := range posture.Checks {
		if check.ID == phpUploadProgressCheckID {
			foundCheck = true
			if check.State != hardeningStateProtected {
				t.Fatalf("unexpected state in posture: %s", check.State)
			}
		}
	}
	if !foundCheck {
		t.Fatal("the PHP upload-progress control is missing from the posture inventory")
	}
	foundDomain := false
	for _, domain := range posture.Domains {
		if domain.ID == "web" {
			foundDomain = true
		}
	}
	if !foundDomain {
		t.Fatal("the web domain is missing from the posture summary")
	}
}
