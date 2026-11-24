// STATUS: DIAMANT VGT SUPREME
package main

// V6.3.0 AP-7: rejecting-decoder fuzz targets for the PermitV1 and review-queue
// parsers. The Makefile fuzz-smoke gate names FuzzPermitV1Decode explicitly.

import (
	"testing"
	"time"
)

func seedPermitV1JSON() []byte {
	return []byte(`{"schema":"vgt-gedefense-permit-v1","permit_id":"0123456789abcdef0123456789abcdef","trust_level":"TOLERATED","sha256":"` +
		"abababababababababababababababababababababababababababababababab" +
		`","inode":{"dev":8,"ino":42},"path":"/usr/bin/tool","scope":{"rules":["XDR.TEMP_EXEC"]},"valid_from":"2026-11-24T12:00:00Z","valid_until":"2026-11-24T13:00:00Z","signature":"absent"}`)
}

func seedReviewEntryJSON() []byte {
	return []byte(`{"id":"` +
		"abababababababababababababababababababababababababababababababab" +
		`","finding_hash":"` +
		"abababababababababababababababababababababababababababababababab" +
		`","time":"2026-11-24T12:00:00Z","first_seen":"2026-11-24T12:00:00Z","last_seen":"2026-11-24T12:00:00Z","repeat_count":1,"severity":"high","score":120,"decision":"alert","action":"none","expires_at":"2026-12-01T12:00:00Z","acknowledged":false,"bytes":1}`)
}

func FuzzPermitV1Decode(f *testing.F) {
	now := time.Date(2026, 11, 24, 12, 0, 0, 0, time.UTC)
	f.Add(seedPermitV1JSON())
	f.Add(seedReviewEntryJSON())
	f.Add([]byte(`{}`))
	f.Add([]byte(`null`))
	f.Add([]byte(``))
	f.Add([]byte(`{"schema":"vgt-gedefense-permit-v1","permit_id":"../etc/passwd"}`))
	f.Add([]byte(`{"schema":"vgt-gedefense-permit-v1","unknown_field":true}`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		// None of these parsers may panic, allocate unbounded memory or accept
		// trailing data; every rejection is a nil permit/entry plus an error.
		permit, err := decodePermitObject(raw, now)
		if err == nil && permit == nil {
			t.Fatal("permit decoder returned neither a permit nor an error")
		}
		if permit != nil {
			if err := validatePermitV1(permit, now); err != nil {
				t.Fatalf("decoder accepted a structurally invalid permit: %v", err)
			}
			if len(permit.PermitID) > permitMaxIDLength || len(permit.Scope.Rules) > permitMaxScopeRules {
				t.Fatalf("decoder accepted an unbounded permit: %+v", permit)
			}
		}
		if _, err := decodeReviewEntry(raw, now); err != nil {
			// Rejection is the expected outcome for arbitrary bytes.
			_ = err
		}
		if _, err := decodePermitStoreTransport(raw); err != nil {
			_ = err
		}
		if _, err := permitStoreOpenHMAC(make([]byte, permitStoreKeyBytes), raw); err != nil {
			_ = err
		}
	})
}
