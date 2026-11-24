package main

// Canonical shipped port topology (G-RUST-06 / CHAIN-005):
//   - public access listener: 0.0.0.0:9843 (gedefense-access in packaging/ and
//     the AstraeaOS drop-in bind 127.0.0.1:9843),
//   - internal control backend: loopback 9844, reached by the access unit.
//
// The control-plane default must be the internal 9844 address; 9843 belongs to
// the public access front end.
const (
	canonicalDashboardInternalListen = "127.0.0.1:9844"
	canonicalAccessPublicPort        = "9843"
	canonicalAccessBackendTarget     = "http://127.0.0.1:9844"
)

func defaultTitanConfig() TitanConfig {
	return TitanConfig{
		Enabled: true, Mode: "observe", Armed: false, AutoContain: false,
		PolicyFile: "/var/lib/vgt/gedefense/titan-policy.json", JournalFile: "/var/lib/vgt/gedefense/titan-journal.json",
		MaxFileBytes: 16 << 20, MaxEvents: 500, JournalMaxBytes: 4 << 20,
	}
}

// defaultDashboardTokenFile is the packaged dashboard credential path. Tests
// override it through the package init in test_isolation_test.go so a test
// binary never reads the live host credential by accident.
var defaultDashboardTokenFile = "/var/lib/vgt/gedefense/dashboard.token"
