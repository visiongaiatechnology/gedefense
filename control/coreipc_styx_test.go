// STATUS: DIAMANT VGT SUPREME
package main

import (
	"bufio"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const (
	styxValidIPv4Record = "0000000000001234:1700000000000000000:1024:0:4242:1000:cb007109:443:51000:7:4:6:1:18:0:6375726c"
	styxValidIPv6Record = "0000000000000002:1700000000000000001:2048:0:99:0:20010db8000000000000000000000001:53:40000:3:6:17:1:0:2:"
)

func TestParseCoreStyxFlowEventsAcceptsValidBatch(t *testing.T) {
	events, dropped, err := parseCoreStyxFlowEvents("3|" + styxValidIPv4Record + "," + styxValidIPv6Record)
	if err != nil {
		t.Fatalf("valid batch rejected: %v", err)
	}
	if dropped != 3 || len(events) != 2 {
		t.Fatalf("unexpected batch shape: dropped=%d events=%d", dropped, len(events))
	}
	ipv4 := events[0]
	if ipv4.CgroupID != 0x1234 || ipv4.TimestampNS != 1700000000000000000 ||
		ipv4.TxBytes != 1024 || ipv4.RxBytes != 0 || ipv4.PID != 4242 || ipv4.UID != 1000 ||
		ipv4.DstPort != 443 || ipv4.SrcPort != 51000 || ipv4.Packets != 7 ||
		ipv4.Family != 4 || ipv4.Proto != 6 || ipv4.Direction != 1 ||
		ipv4.TCPFlags != 18 || ipv4.Verdict != 0 || ipv4.Comm != "curl" ||
		len(ipv4.DstIP) != 4 || ipv4.DstIP.String() != "203.0.113.9" {
		t.Fatalf("unexpected IPv4 record: %#v", ipv4)
	}
	ipv6 := events[1]
	if ipv6.CgroupID != 2 || ipv6.Proto != 17 || ipv6.Family != 6 ||
		len(ipv6.DstIP) != 16 || ipv6.DstIP.String() != "2001:db8::1" ||
		ipv6.DstPort != 53 || ipv6.SrcPort != 40000 || ipv6.Comm != "" {
		t.Fatalf("unexpected IPv6 record: %#v", ipv6)
	}
}

func TestParseCoreStyxFlowEventsEmptyAndDroppedOnly(t *testing.T) {
	for _, response := range []string{"empty", "0|", "9|"} {
		events, dropped, err := parseCoreStyxFlowEvents(response)
		if err != nil {
			t.Fatalf("%q rejected: %v", response, err)
		}
		if len(events) != 0 {
			t.Fatalf("%q produced events", response)
		}
		if response == "9|" && dropped != 9 {
			t.Fatalf("drop counter lost: %d", dropped)
		}
	}
}

func TestParseCoreStyxFlowEventsRejectsHostileInput(t *testing.T) {
	replace := func(record string, index int, value string) string {
		fields := strings.Split(record, ":")
		fields[index] = value
		return strings.Join(fields, ":")
	}
	tooManyRecords := strings.Repeat(styxValidIPv4Record+",", maxStyxFlowEventsPerResponse+1)
	tooManyRecords = strings.TrimSuffix(tooManyRecords, ",")
	cases := map[string]string{
		"field-count":           replace(styxValidIPv4Record, 1, "1") + ":extra",
		"short-cgroup-hex":      replace(styxValidIPv4Record, 0, "000000000000123"),
		"non-hex-cgroup":        replace(styxValidIPv4Record, 0, "zzzzzzzzzzzz1234"),
		"zero-timestamp":        replace(styxValidIPv4Record, 1, "0"),
		"zero-packets":          replace(styxValidIPv4Record, 9, "0"),
		"bad-family":            replace(styxValidIPv4Record, 10, "5"),
		"bad-proto":             replace(styxValidIPv4Record, 11, "1"),
		"bad-direction":         replace(styxValidIPv4Record, 12, "0"),
		"bad-verdict":           replace(styxValidIPv4Record, 14, "6"),
		"tcpflags-on-udp":       replace(styxValidIPv4Record, 11, "17"),
		"ports-with-proto-zero": replace(replace(styxValidIPv4Record, 11, "0"), 7, "443"),
		"ipv4-mapped-noncanon":  replace(styxValidIPv4Record, 6, "00000000000000000000ffffcb007109"),
		"ipv6-with-ipv4-bytes":  replace(replace(styxValidIPv4Record, 10, "6"), 6, "cb007109"),
		"unspecified-ipv4":      replace(styxValidIPv4Record, 6, "00000000"),
		"oversized-comm":        replace(styxValidIPv4Record, 15, strings.Repeat("61", 17)),
		"nul-in-comm":           replace(styxValidIPv4Record, 15, "610062"),
		"space-in-comm":         replace(styxValidIPv4Record, 15, "612062"),
		"odd-comm-hex":          replace(styxValidIPv4Record, 15, "616"),
		"negative-counter":      replace(styxValidIPv4Record, 2, "-1"),
		"overflowing-counter":   replace(styxValidIPv4Record, 2, "18446744073709551616"),
		"leading-space":         " " + styxValidIPv4Record,
		"trailing-newline":      styxValidIPv4Record + "\n",
		"missing-drop-prefix":   styxValidIPv4Record,
		"non-numeric-dropped":   "x|" + styxValidIPv4Record,
		"too-many-records":      "0|" + tooManyRecords,
		"oversized-payload":     "0|" + styxValidIPv4Record + strings.Repeat("0", maxStyxFlowPayloadBytes),
	}
	if len(cases) < 8 {
		t.Fatalf("hostile matrix too small: %d", len(cases))
	}
	for name, response := range cases {
		if events, dropped, err := parseCoreStyxFlowEvents(response); err == nil || events != nil || dropped != 0 {
			t.Fatalf("%s accepted: events=%d dropped=%d err=%v", name, len(events), dropped, err)
		}
	}
	// All-or-nothing: one bad record poisons the whole batch.
	if events, _, err := parseCoreStyxFlowEvents("0|" + styxValidIPv4Record + ",broken"); err == nil || events != nil {
		t.Fatal("partially invalid batch was accepted")
	}
}

func TestParseCoreStyxFlowHealth(t *testing.T) {
	health, err := parseCoreStyxFlowHealth("11:22:33:44:55:66")
	if err != nil {
		t.Fatalf("valid health rejected: %v", err)
	}
	if health.Emitted != 11 || health.RingDrops != 22 || health.AggInsertFailures != 33 ||
		health.ParseErrors != 44 || health.DropsTotal != 55 || health.PolicyDrops != 66 {
		t.Fatalf("unexpected health: %#v", health)
	}
	for _, malformed := range []string{"", "1:2:3:4:5", "1:2:3:4:5:6:7", "1:2:3:4:5:x", "1:2:3:4:5:18446744073709551616", strings.Repeat("1", 200)} {
		if _, err := parseCoreStyxFlowHealth(malformed); err == nil {
			t.Fatalf("malformed health accepted: %q", malformed)
		}
	}
}

// startStyxFakeCore answers exactly one authenticated VGT3 request. respond
// receives the full request field slice (including the leading command) and
// returns the status/payload pair the fake core wants to send.
func startStyxFakeCore(t *testing.T, client *CoreClient, socketPath string, respond func(fields []string) (string, string)) chan error {
	t.Helper()
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("fake core listener: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	done := make(chan error, 1)
	go func() {
		connection, acceptErr := listener.Accept()
		if acceptErr != nil {
			done <- acceptErr
			return
		}
		defer connection.Close()
		line, readErr := bufio.NewReader(connection).ReadString('\n')
		if readErr != nil {
			done <- readErr
			return
		}
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) < 5 || fields[0] != coreProtocol {
			done <- fmt.Errorf("malformed request")
			return
		}
		if fields[len(fields)-1] != coreMAC(client.key, fields[:len(fields)-1]...) {
			done <- fmt.Errorf("bad client MAC")
			return
		}
		status, payload := respond(fields)
		tag := coreProtocol + "R"
		encoded := base64.RawURLEncoding.EncodeToString([]byte(payload))
		mac := coreMAC(client.key, tag, fields[2], status, encoded)
		_, writeErr := connection.Write([]byte(strings.Join([]string{tag, fields[2], status, encoded, mac}, " ") + "\n"))
		done <- writeErr
	}()
	return done
}

func newStyxFakeClient(t *testing.T) (*CoreClient, string) {
	t.Helper()
	directory := t.TempDir()
	socketPath := filepath.Join(directory, "core.sock")
	client, err := NewCoreClient(socketPath, filepath.Join(directory, "core.key"), time.Second)
	if err != nil {
		t.Fatalf("fake client: %v", err)
	}
	return client, socketPath
}

func TestStyxFlowEventsRoundTripAndUnknownCommandSentinel(t *testing.T) {
	client, socketPath := newStyxFakeClient(t)
	done := startStyxFakeCore(t, client, socketPath, func(fields []string) (string, string) {
		if fields[3] != "STYX_FLOW_EVENTS" {
			return "ERR", "unexpected command"
		}
		return "OK", "2|" + styxValidIPv4Record
	})
	events, dropped, err := client.StyxFlowEvents()
	if err != nil {
		t.Fatalf("flow events round trip failed: %v", err)
	}
	if len(events) != 1 || dropped != 2 || events[0].Comm != "curl" {
		t.Fatalf("unexpected decoded batch: dropped=%d events=%#v", dropped, events)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}

	client, socketPath = newStyxFakeClient(t)
	done = startStyxFakeCore(t, client, socketPath, func(fields []string) (string, string) {
		return "ERR", "unknown command"
	})
	if _, _, err := client.StyxFlowEvents(); !errors.Is(err, ErrStyxUnavailable) {
		t.Fatalf("old core must map to ErrStyxUnavailable, got %v", err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}

	client, socketPath = newStyxFakeClient(t)
	done = startStyxFakeCore(t, client, socketPath, func(fields []string) (string, string) {
		return "ERR", "unknown command"
	})
	if _, err := client.StyxCapabilities(); !errors.Is(err, ErrStyxUnavailable) {
		t.Fatalf("capability probe must map to ErrStyxUnavailable, got %v", err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestStyxCommandErrorsAreNotCapabilityMissing(t *testing.T) {
	client, socketPath := newStyxFakeClient(t)
	done := startStyxFakeCore(t, client, socketPath, func(fields []string) (string, string) {
		return "ERR", "cgroup 0 is invalid"
	})
	if err := client.StyxModeDel(7); err == nil || errors.Is(err, ErrStyxUnavailable) || !strings.Contains(err.Error(), "cgroup 0 is invalid") {
		t.Fatalf("core validation error was misclassified: %v", err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}

	// A response with a forged MAC is an authentication failure, never a
	// capability fact, and must not panic.
	client, socketPath = newStyxFakeClient(t)
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		connection, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		defer connection.Close()
		line, _ := bufio.NewReader(connection).ReadString('\n')
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) < 5 {
			return
		}
		tag := coreProtocol + "R"
		encoded := base64.RawURLEncoding.EncodeToString([]byte("empty"))
		_, _ = connection.Write([]byte(strings.Join([]string{tag, fields[2], "OK", encoded, strings.Repeat("00", 32)}, " ") + "\n"))
	}()
	if _, _, err := client.StyxFlowEvents(); err == nil || errors.Is(err, ErrStyxUnavailable) {
		t.Fatalf("forged response was not rejected: %v", err)
	}
}

func TestStyxClientMethodsValidateBeforeDial(t *testing.T) {
	client, _ := newStyxFakeClient(t)
	cases := map[string]error{
		"global-mode":              client.StyxGlobal(3, 0),
		"mode-set-zero-cgroup":     client.StyxModeSet(0, 1, 0),
		"mode-set-bad-mode":        client.StyxModeSet(7, 3, 0),
		"mode-del-zero-cgroup":     client.StyxModeDel(0),
		"allow-bad-family":         client.StyxAllowAdd(5, "cell", 7, "10.0.0.0/8", 0, 0, 0),
		"allow-bad-scope":          client.StyxAllowAdd(4, "host", 7, "10.0.0.0/8", 0, 0, 0),
		"allow-cell-without-id":    client.StyxAllowAdd(4, "cell", 0, "10.0.0.0/8", 0, 0, 0),
		"allow-global-with-id":     client.StyxAllowAdd(4, "global", 7, "10.0.0.0/8", 0, 0, 0),
		"allow-noncanonical":       client.StyxAllowAdd(4, "cell", 7, "10.0.0.1/8", 0, 0, 0),
		"allow-mapped-ipv6":        client.StyxAllowAdd(6, "cell", 7, "::ffff:10.0.0.1/128", 0, 0, 0),
		"allow-inverted-ports":     client.StyxAllowAdd(4, "cell", 7, "10.0.0.0/8", 80, 70, 0),
		"allow-bad-proto-mask":     client.StyxAllowAdd(4, "cell", 7, "10.0.0.0/8", 0, 0, 4),
		"block-family-mismatch":    client.StyxBlockAdd(6, "10.0.0.0/8"),
		"resolver-unspecified":     client.StyxResolverAdd(6, "::/0"),
		"resolver-family-mismatch": client.StyxResolverAdd(4, "2001:db8::1/128"),
	}
	for name, err := range cases {
		if err == nil {
			t.Fatalf("%s was accepted before dial", name)
		}
	}
}

func TestStyxValidArgumentsReachTheAuthenticatedCore(t *testing.T) {
	client, socketPath := newStyxFakeClient(t)
	done := startStyxFakeCore(t, client, socketPath, func(fields []string) (string, string) {
		if fields[3] != "STYX_ALLOW_ADD" || len(fields) != 12 {
			return "ERR", "bad allow command shape"
		}
		// VGT3 ts nonce STYX_ALLOW_ADD family scope cgroup cidr portLo portHi protoMask mac
		if fields[4] != "4" || fields[5] != "cell" || fields[6] != "4242" ||
			fields[7] != "10.0.0.0/8" || fields[8] != "0" || fields[9] != "65535" || fields[10] != "3" {
			return "ERR", "bad allow arguments"
		}
		return "OK", "added"
	})
	if err := client.StyxAllowAdd(4, "cell", 4242, "10.0.0.0/8", 0, 65535, 3); err != nil {
		t.Fatalf("valid allow rule rejected: %v", err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	client, socketPath = newStyxFakeClient(t)
	done = startStyxFakeCore(t, client, socketPath, func(fields []string) (string, string) {
		if fields[3] != "STYX_VERSION" {
			return "ERR", "unexpected command"
		}
		return "OK", "styx-v1"
	})
	version, err := client.StyxVersion()
	if err != nil || version != "styx-v1" {
		t.Fatalf("version negotiation failed: version=%q err=%v", version, err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestStyxEpochValidation(t *testing.T) {
	client, socketPath := newStyxFakeClient(t)
	done := startStyxFakeCore(t, client, socketPath, func(fields []string) (string, string) {
		return "OK", "0123456789ABCDEF"
	})
	epoch, err := client.StyxEpoch()
	if err != nil || epoch != "0123456789abcdef" {
		t.Fatalf("epoch normalisation failed: epoch=%q err=%v", epoch, err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	client, socketPath = newStyxFakeClient(t)
	done = startStyxFakeCore(t, client, socketPath, func(fields []string) (string, string) {
		return "OK", "short"
	})
	if _, err := client.StyxEpoch(); err == nil {
		t.Fatal("malformed epoch was accepted")
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestStyxFlowHealthRoundTrip(t *testing.T) {
	client, socketPath := newStyxFakeClient(t)
	done := startStyxFakeCore(t, client, socketPath, func(fields []string) (string, string) {
		if fields[3] != "STYX_FLOW_HEALTH" {
			return "ERR", "unexpected command"
		}
		return "OK", "1:2:3:4:5:6"
	})
	health, err := client.StyxFlowHealth()
	if err != nil {
		t.Fatalf("flow health round trip failed: %v", err)
	}
	if health.Emitted != 1 || health.RingDrops != 2 || health.AggInsertFailures != 3 ||
		health.ParseErrors != 4 || health.DropsTotal != 5 || health.PolicyDrops != 6 {
		t.Fatalf("unexpected health: %#v", health)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestStyxFlowEvents64RecordWireRoundTripExceeds2048Bytes(t *testing.T) {
	records := make([]string, maxStyxFlowEventsPerResponse)
	for i := range records {
		records[i] = styxValidIPv4Record
	}
	wire := "0|" + strings.Join(records, ",")
	if len(wire) <= 2048 || len(wire) > maxStyxFlowPayloadBytes {
		t.Fatalf("unexpected 64-record wire length: %d", len(wire))
	}
	client, socketPath := newStyxFakeClient(t)
	done := startStyxFakeCore(t, client, socketPath, func(fields []string) (string, string) {
		if fields[3] != "STYX_FLOW_EVENTS" {
			return "ERR", "unexpected command"
		}
		return "OK", wire
	})
	events, dropped, err := client.StyxFlowEvents()
	if err != nil {
		t.Fatalf("64-record STYX_FLOW_EVENTS wire round trip failed: %v", err)
	}
	if dropped != 0 || len(events) != maxStyxFlowEventsPerResponse {
		t.Fatalf("unexpected count=%d dropped=%d", len(events), dropped)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
