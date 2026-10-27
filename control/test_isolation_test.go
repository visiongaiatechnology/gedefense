// STATUS: DIAMANT VGT SUPREME
// SPDX-FileCopyrightText: 2026 VisionGaia Technology
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"os"
	"path/filepath"
	"testing"
)

// isolatedTokenConfig returns a configuration whose dashboard token lives in a private temporary file
// carrying exactly the given token.
//
// Tests must never let the platform read the host's own token file. A suite that behaves differently
// depending on whether GeDefense happens to be installed on the build machine goes red for the wrong
// reason - and a red suite that everyone learns to ignore is worse than no suite. The platform treats
// the file as authoritative (that is what makes a token rotation take effect without a restart), so a
// test that supplies a token must also supply the file that holds it.
func init() { defaultDashboardTokenFile = "/tmp/gedefense-dashboard-test.token" }

func isolatedTokenConfig(t *testing.T, token string) Config {
	t.Helper()
	path := filepath.Join(t.TempDir(), "dashboard.token")
	if err := os.WriteFile(path, []byte(token+"\n"), 0o600); err != nil {
		t.Fatalf("write isolated dashboard token: %v", err)
	}
	cfg := defaultConfig()
	cfg.Dashboard.TokenFile = path
	return cfg
}
