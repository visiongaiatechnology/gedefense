// STATUS: DIAMANT VGT SUPREME
// SPDX-FileCopyrightText: 2026 VisionGaia Technology
// SPDX-License-Identifier: AGPL-3.0-only

package main

import "testing"

// TestAnEmptyStorageKeyPathIsRefusedAtStartup is the permanent guard for a finding that was HIGH in
// the audit: an empty `storage_key_file` used to disable the storage cipher silently, which left the
// policy signing key, the evidence signing key and the evidence and incident records in plaintext on
// disk - a configuration value that quietly removed a protection instead of a mode that has to be
// chosen.
//
// The guard lives in validateConfig rather than in the cipher constructor on purpose: the production
// start must refuse, while test fixtures may still build a plaintext store deliberately. Should this
// test ever fail, the vulnerability is back - not a formatting problem.
func TestAnEmptyStorageKeyPathIsRefusedAtStartup(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*Config)
	}{
		{"xdr namespace", func(c *Config) { c.XDR.StorageKeyFile = "" }},
		{"policy namespace", func(c *Config) { c.Policy.StorageKeyFile = "" }},
		{"xdr namespace, relative path", func(c *Config) { c.XDR.StorageKeyFile = "secrets/storage-master.key" }},
		{"policy namespace, relative path", func(c *Config) { c.Policy.StorageKeyFile = "secrets/policy.key" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := defaultConfig()
			tc.mutate(&cfg)
			if err := validateConfig(&cfg); err == nil {
				t.Fatal("a configuration that cannot encrypt was accepted; the platform would store keys in plaintext")
			}
		})
	}

	// The shipped configuration must stay valid - otherwise the guard would stop every installation.
	cfg := defaultConfig()
	if err := validateConfig(&cfg); err != nil {
		t.Fatalf("the default configuration must remain startable: %v", err)
	}
	if cfg.XDR.StorageKeyFile == "" || cfg.Policy.StorageKeyFile == "" {
		t.Fatal("the default configuration no longer names a storage key; the guard would be vacuous")
	}
}
