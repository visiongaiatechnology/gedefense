//go:build linux

// STATUS: DIAMANT VGT SUPREME
package main

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

func TestPackageIntegrityUsesPacmanSHA256Manifest(t *testing.T) {
	root := t.TempDir()
	dbRoot := filepath.Join(t.TempDir(), "local")
	packageDir := filepath.Join(dbRoot, "gaia-test-1.0-1")
	if err := os.MkdirAll(filepath.Join(root, "usr", "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(packageDir, 0o700); err != nil {
		t.Fatal(err)
	}
	trusted := []byte("trusted payload")
	modified := []byte("modified payload")
	if err := os.WriteFile(filepath.Join(root, "usr", "bin", "trusted"), trusted, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "usr", "bin", "modified"), modified, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(packageDir, "desc"), []byte("%NAME%\ngaia-test\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	manifest := ".#mtree\n" +
		"./usr/bin/trusted sha256digest=" + sha256Hex(trusted) + "\n" +
		"./usr/bin/modified sha256digest=" + sha256Hex([]byte("original payload")) + "\n" +
		"./usr/bin/missing sha256digest=" + sha256Hex([]byte("missing payload")) + "\n"
	if err := writeGzipFixture(filepath.Join(packageDir, "mtree"), []byte(manifest)); err != nil {
		t.Fatal(err)
	}

	status, err := scanPackageIntegrity(dbRoot, root)
	if err != nil {
		t.Fatalf("scan rejected: %v", err)
	}
	if status.Packages != 1 || status.Files != 3 || status.Verified != 1 ||
		status.Modified != 1 || status.Missing != 1 || status.Errors != 0 {
		t.Fatalf("unexpected package integrity result: %#v", status)
	}
}

func TestPackageIntegrityPathJailRejectsTraversal(t *testing.T) {
	root := t.TempDir()
	if _, err := jailedPackagePath(root, "../../etc/shadow"); err == nil {
		t.Fatal("package traversal escaped the filesystem jail")
	}
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(root, "escape")); err != nil {
		t.Fatal(err)
	}
	if _, err := jailedPackagePath(root, "escape/payload"); err == nil {
		t.Fatal("symlinked package parent escaped the filesystem jail")
	}
}

func sha256Hex(value []byte) string {
	digest := sha256.Sum256(value)
	return hex.EncodeToString(digest[:])
}

func writeGzipFixture(path string, value []byte) error {
	var output bytes.Buffer
	writer := gzip.NewWriter(&output)
	if _, err := writer.Write(value); err != nil {
		return err
	}
	if err := writer.Close(); err != nil {
		return err
	}
	return os.WriteFile(path, output.Bytes(), 0o600)
}
