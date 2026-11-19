//go:build linux

package webposture

import (
	"os"
	"path/filepath"
	"testing"
)

func TestBinaryPathFromCmdlineFallback(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	nginxBin := filepath.Join(dir, "nginx")
	httpdBin := filepath.Join(dir, "httpd")
	for _, p := range []string{nginxBin, httpdBin} {
		if err := os.WriteFile(p, []byte("stub"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if got := binaryPathFromCmdline("nginx: master process " + nginxBin + " -c /etc/nginx/nginx.conf\x00"); got != nginxBin {
		t.Fatalf("nginx cmdline fallback = %q, want %q", got, nginxBin)
	}
	if got := binaryPathFromCmdline(httpdBin + "\x00-k\x00restart\x00"); got != httpdBin {
		t.Fatalf("httpd cmdline fallback = %q, want %q", got, httpdBin)
	}
	if got := binaryPathFromCmdline("nginx: worker process\x00"); got != "" {
		t.Fatalf("worker title without path unexpectedly resolved %q", got)
	}
}
