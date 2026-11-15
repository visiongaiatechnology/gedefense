// STATUS: DIAMANT VGT SUPREME
package main

// POINT 1 / P1-T2 tests: the additive TITAN_EXEC_* client surface in coreipc.go.
// The authenticated VGT3 round trip is exercised against the in-process fake core
// used by the StyX client tests; hostile payloads must be rejected, never half-read.

import (
	"encoding/base64"
	"errors"
	"strings"
	"testing"
)

// ---------------------------------------------------------- coreipc client

func titanExecClientCall(t *testing.T, respond func([]string) (string, string), call func(*CoreClient) error) error {
	t.Helper()
	client, socketPath := newStyxFakeClient(t)
	done := startStyxFakeCore(t, client, socketPath, respond)
	callErr := call(client)
	if err := <-done; err != nil {
		t.Fatalf("fake core: %v", err)
	}
	return callErr
}

func TestTitanExecClientRoundTrips(t *testing.T) {
	version, err := func() (string, error) {
		var got string
		err := titanExecClientCall(t, func(fields []string) (string, string) {
			if fields[3] != "TITAN_EXEC_VERSION" {
				return "ERR", "unexpected"
			}
			return "OK", "titan-exec-v1"
		}, func(c *CoreClient) error {
			var callErr error
			got, callErr = c.TitanExecVersion()
			return callErr
		})
		return got, err
	}()
	if err != nil || version != titanExecSupportedVersion {
		t.Fatalf("version round trip failed: %q %v", version, err)
	}

	var status TitanExecCoreStatus
	err = titanExecClientCall(t, func(fields []string) (string, string) {
		return "OK", "status=applied;mode=2;flags=1;path=bpf-lsm;lsm=active;offsets=valid;entries=3;scopes=1;epoch=0123456789ABCDEF"
	}, func(c *CoreClient) error {
		var callErr error
		status, callErr = c.TitanExecStatus()
		return callErr
	})
	if err != nil || status.Mode != 2 || status.Flags != 1 || status.Entries != 3 || status.Scopes != 1 || status.Epoch != "0123456789abcdef" || status.Path != "bpf-lsm" {
		t.Fatalf("status round trip failed: %+v %v", status, err)
	}

	var identity TitanExecAllowIdentity
	err = titanExecClientCall(t, func(fields []string) (string, string) {
		if fields[3] != "TITAN_EXEC_ALLOW_ADD" || fields[4] != "/usr/bin/tool" {
			return "ERR", "unexpected"
		}
		return "OK", "added:7:4242"
	}, func(c *CoreClient) error {
		var callErr error
		identity, callErr = c.TitanExecAllowAdd("/usr/bin/tool")
		return callErr
	})
	if err != nil || identity.State != "added" || identity.Dev != 7 || identity.Ino != 4242 {
		t.Fatalf("allow add round trip failed: %+v %v", identity, err)
	}

	var batch TitanExecBatchResult
	var decoded string
	err = titanExecClientCall(t, func(fields []string) (string, string) {
		if fields[3] != "TITAN_EXEC_ALLOW_ADD_BATCH" {
			return "ERR", "unexpected"
		}
		raw, decodeErr := base64.RawURLEncoding.DecodeString(fields[4])
		if decodeErr != nil {
			return "ERR", "bad encoding"
		}
		decoded = string(raw)
		return "OK", "added:2;rejected:0;error=none"
	}, func(c *CoreClient) error {
		var callErr error
		batch, callErr = c.TitanExecAllowAddBatch([]string{"/usr/bin/a", "/usr/bin/b"})
		return callErr
	})
	if err != nil || batch.Added != 2 || batch.Rejected != 0 || batch.Error != "none" || decoded != "/usr/bin/a\n/usr/bin/b" {
		t.Fatalf("batch round trip failed: decoded=%q result=%+v err=%v", decoded, batch, err)
	}

	var health CoreTitanExecHealth
	err = titanExecClientCall(t, func([]string) (string, string) { return "OK", "1:2:3:4:5:6" }, func(c *CoreClient) error {
		var callErr error
		health, callErr = c.TitanExecHealth()
		return callErr
	})
	if err != nil || health.Emitted != 1 || health.RingDrops != 2 || health.ReadFailures != 3 || health.Denies != 4 || health.Audits != 5 || health.CtimeRejects != 6 {
		t.Fatalf("health round trip failed: %+v %v", health, err)
	}

	var events string
	err = titanExecClientCall(t, func([]string) (string, string) { return "OK", "empty" }, func(c *CoreClient) error {
		var callErr error
		events, callErr = c.TitanExecEvents()
		return callErr
	})
	if err != nil || events != "empty" {
		t.Fatalf("events round trip failed: %q %v", events, err)
	}
}

func TestTitanExecClientCapabilityAndMalformedReplies(t *testing.T) {
	if err := titanExecClientCall(t, func([]string) (string, string) { return "ERR", "unknown command" }, func(c *CoreClient) error {
		_, callErr := c.TitanExecVersion()
		return callErr
	}); !errors.Is(err, ErrTitanExecUnavailable) {
		t.Fatalf("old core must map to ErrTitanExecUnavailable, got %v", err)
	}
	malformed := []struct {
		name    string
		payload string
		call    func(*CoreClient) error
	}{
		{"version", "titan-exec-v2", func(c *CoreClient) error { _, err := c.TitanExecVersion(); return err }},
		{"epoch", "short", func(c *CoreClient) error { _, err := c.TitanExecEpoch(); return err }},
		{"status-order", "mode=1;status=applied;flags=0;path=bpf-lsm;lsm=active;offsets=valid;entries=0;scopes=0;epoch=0123456789abcdef",
			func(c *CoreClient) error { _, err := c.TitanExecStatus(); return err }},
		{"status-bad-lsm", "status=applied;mode=1;flags=0;path=bpf-lsm;lsm=maybe;offsets=valid;entries=0;scopes=0;epoch=0123456789abcdef",
			func(c *CoreClient) error { _, err := c.TitanExecStatus(); return err }},
		{"identity-zero", "added:0:1", func(c *CoreClient) error { _, err := c.TitanExecAllowAdd("/usr/bin/tool"); return err }},
		{"batch-inconsistent", "added:1;rejected:0;error=symlink", func(c *CoreClient) error {
			_, err := c.TitanExecAllowAddBatch([]string{"/usr/bin/tool"})
			return err
		}},
		{"batch-empty-token", "added:1;rejected:0;error=", func(c *CoreClient) error {
			_, err := c.TitanExecAllowAddBatch([]string{"/usr/bin/tool"})
			return err
		}},
		{"batch-unknown-token", "added:1;rejected:0;error=weird", func(c *CoreClient) error {
			_, err := c.TitanExecAllowAddBatch([]string{"/usr/bin/tool"})
			return err
		}},
		{"batch-rejected-without-reason", "added:0;rejected:1;error=none", func(c *CoreClient) error {
			_, err := c.TitanExecAllowAddBatch([]string{"/usr/bin/tool"})
			return err
		}},
		{"batch-overflow", "added:300;rejected:0;error=", func(c *CoreClient) error {
			_, err := c.TitanExecAllowAddBatch([]string{"/usr/bin/tool"})
			return err
		}},
		{"health", "1:2:3:4:5", func(c *CoreClient) error { _, err := c.TitanExecHealth(); return err }},
	}
	for _, testCase := range malformed {
		t.Run(testCase.name, func(t *testing.T) {
			payload := testCase.payload
			err := titanExecClientCall(t, func([]string) (string, string) { return "OK", payload }, testCase.call)
			if err == nil {
				t.Fatalf("malformed payload %q was accepted", payload)
			}
		})
	}
}

func TestTitanExecClientValidatesArgumentsBeforeDial(t *testing.T) {
	client, _ := newStyxFakeClient(t)
	cases := map[string]error{
		"set-global-mode":    client.TitanExecSetGlobal(4, 0),
		"set-global-flags":   client.TitanExecSetGlobal(1, 2),
		"allow-relative":     func() error { _, err := client.TitanExecAllowAdd("usr/bin/tool"); return err }(),
		"allow-noncanonical": func() error { _, err := client.TitanExecAllowAdd("/usr//bin/tool"); return err }(),
		"allow-space":        func() error { _, err := client.TitanExecAllowAdd("/usr/bin/my tool"); return err }(),
		"batch-empty":        func() error { _, err := client.TitanExecAllowAddBatch(nil); return err }(),
		"batch-too-many": func() error {
			_, err := client.TitanExecAllowAddBatch(make([]string, titanExecMaxBatchPaths+1))
			return err
		}(),
		"batch-too-large": func() error {
			_, err := client.TitanExecAllowAddBatch([]string{"/" + strings.Repeat("a", 1400), "/" + strings.Repeat("b", 1400)})
			return err
		}(),
		"delete-zero":       client.TitanExecAllowDel(0, 1),
		"scope-zero-cgroup": client.TitanExecScopeSet(0, 1, 0),
		"scope-bad-flags":   client.TitanExecScopeSet(7, 1, 2),
		"scope-del-zero":    client.TitanExecScopeDel(0),
	}
	for name, err := range cases {
		if err == nil {
			t.Fatalf("%s was accepted before dial", name)
		}
	}
}
