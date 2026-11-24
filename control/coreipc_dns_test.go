// STATUS: DIAMANT VGT SUPREME
package main

// V6.3.0 AP-6 regression tests: the strict DNS_EVENTS/DNS_STATUS transport
// parsers (all-or-nothing, bounded) and the FuzzCoreDnsParser smoke target that
// the Makefile fuzz-smoke gate expects.

import (
	"encoding/hex"
	"errors"
	"strings"
	"testing"
)

func dnsTestRecord(ts uint64, pid, tgid int, uid uint32, qtype uint16, comm, qname string, fqdnLen int) string {
	return strings.Join([]string{
		formatUint(ts),
		formatUint(uint64(pid)),
		formatUint(uint64(tgid)),
		formatUint(uint64(uid)),
		formatUint(uint64(qtype)),
		hex.EncodeToString([]byte(comm)),
		hex.EncodeToString([]byte(qname)),
		formatUint(uint64(fqdnLen)),
	}, ":")
}

func formatUint(value uint64) string {
	if value == 0 {
		return "0"
	}
	var buffer [20]byte
	index := len(buffer)
	for value > 0 {
		index--
		buffer[index] = byte('0' + value%10)
		value /= 10
	}
	return string(buffer[index:])
}

func TestCoreDnsStatusParserStrict(t *testing.T) {
	status, err := parseCoreDnsStatus("enabled=1:attached=3:events=42:drops=2:read_failures=7")
	if err != nil {
		t.Fatalf("valid status rejected: %v", err)
	}
	if !status.Enabled || !status.Attached || status.AttachMask != 3 || status.Events != 42 || status.Drops != 2 || status.ReadFailures != 7 {
		t.Fatalf("status projection wrong: %+v", status)
	}
	partial, err := parseCoreDnsStatus("enabled=1:attached=1:events=0:drops=0:read_failures=0")
	if err != nil || !partial.Attached || partial.AttachMask != 1 {
		t.Fatalf("partial attach mask not reported honestly: %+v err=%v", partial, err)
	}
	disarmed, err := parseCoreDnsStatus("enabled=0:attached=2:events=9:drops=0:read_failures=0")
	if err != nil || disarmed.Enabled || !disarmed.Attached {
		t.Fatalf("disarmed status wrong: %+v err=%v", disarmed, err)
	}

	malformed := []string{
		"",
		"enabled=1",
		"enabled=1:attached=0:events=0:drops=0",
		"enabled=1:attached=0:events=0:drops=0:read_failures=0:extra=1",
		"attached=0:enabled=1:events=0:drops=0:read_failures=0",
		"enabled=2:attached=0:events=0:drops=0:read_failures=0",
		"enabled=1:attached=4:events=0:drops=0:read_failures=0",
		"enabled=1:attached=x:events=0:drops=0:read_failures=0",
		"enabled=1:attached=0:events=-1:drops=0:read_failures=0",
		" enabled=1:attached=0:events=0:drops=0:read_failures=0",
		"enabled=1:attached=0:events=0:drops=0:read_failures=0 ",
		"enabled=1:attached=0:events=0:drops=0:read_failures=18446744073709551616",
	}
	for _, response := range malformed {
		if _, err := parseCoreDnsStatus(response); err == nil {
			t.Fatalf("malformed status accepted: %q", response)
		}
	}
	oversized := "enabled=1:attached=0:events=0:drops=0:read_failures=0" + strings.Repeat("0", maxDnsStatusBytes)
	if _, err := parseCoreDnsStatus(oversized); err == nil {
		t.Fatal("oversized status accepted")
	}
}

func TestCoreDnsEventsParserRoundTrip(t *testing.T) {
	if events, dropped, err := parseCoreDnsEvents("empty"); err != nil || len(events) != 0 || dropped != 0 {
		t.Fatalf("empty batch: %v %v %v", events, dropped, err)
	}
	if events, dropped, err := parseCoreDnsEvents("9|"); err != nil || len(events) != 0 || dropped != 9 {
		t.Fatalf("drop-only batch: %v %v %v", events, dropped, err)
	}

	record := dnsTestRecord(1_700_000_000_000_000_000, 4242, 4241, 1000, 28, "curl", "www.example.com", 15)
	events, dropped, err := parseCoreDnsEvents("3|" + record)
	if err != nil || dropped != 3 || len(events) != 1 {
		t.Fatalf("single record batch: %v %v %v", events, dropped, err)
	}
	event := events[0]
	if event.TsNS != 1_700_000_000_000_000_000 || event.PID != 4242 || event.TGID != 4241 ||
		event.UID != 1000 || event.QType != 28 || event.QName != "www.example.com" ||
		event.Comm != "curl" || event.FQDNLen != 15 || !event.Resolved {
		t.Fatalf("record projection wrong: %+v", event)
	}

	// A clipped capture is honest: the reconstructed name is shorter than the
	// full FQDN length and Resolved is false.
	clipped := dnsTestRecord(2, 7, 7, 0, 16, "dnscat2", "aGVsbG8gd29y.tunnel.example", 60)
	events, _, err = parseCoreDnsEvents("0|" + clipped)
	if err != nil || len(events) != 1 {
		t.Fatalf("clipped record rejected: %v %v", events, err)
	}
	if events[0].Resolved || events[0].FQDNLen != 60 || events[0].QName != "aGVsbG8gd29y.tunnel.example" {
		t.Fatalf("clipped record projected dishonestly: %+v", events[0])
	}

	second := dnsTestRecord(3, 8, 8, 1000, 16, "dig", "x.example.com", 13)
	events, dropped, err = parseCoreDnsEvents("0|" + record + "," + second)
	if err != nil || dropped != 0 || len(events) != 2 {
		t.Fatalf("multi-record batch: %v %v %v", events, dropped, err)
	}

	tooMany := make([]string, maxDnsEventsPerResponse+1)
	for index := range tooMany {
		tooMany[index] = record
	}
	if _, _, err := parseCoreDnsEvents("0|" + strings.Join(tooMany, ",")); err == nil {
		t.Fatal("batch above the record bound accepted")
	}
	oversizedPayload := "0|" + strings.Repeat(record+",", 60)
	if _, _, err := parseCoreDnsEvents(oversizedPayload); err == nil {
		t.Fatal("oversized payload accepted")
	}
}

func TestCoreDnsEventsParserRejectsMalformed(t *testing.T) {
	valid := dnsTestRecord(1_700_000_000_000_000_000, 4242, 4241, 1000, 28, "curl", "www.example.com", 15)
	malformed := []string{
		"",
		"0",
		"0|,",
		"-1|" + valid,
		"x|" + valid,
		"0|" + strings.Replace(valid, ":", "|", 1),
		"0|" + valid + ",", // trailing empty record
	}
	for _, response := range malformed {
		if _, _, err := parseCoreDnsEvents(response); err == nil {
			t.Fatalf("malformed batch accepted: %q", response)
		}
	}

	// Per-field rejections: every mutation of one otherwise valid record must be
	// rejected (the parser never repairs a field).
	mutations := []struct {
		name   string
		record string
	}{
		{"ts zero", dnsTestRecord(0, 4242, 4241, 1000, 28, "curl", "www.example.com", 15)},
		{"pid zero", dnsTestRecord(1, 0, 4241, 1000, 28, "curl", "www.example.com", 15)},
		{"tgid zero", dnsTestRecord(1, 4242, 0, 1000, 28, "curl", "www.example.com", 15)},
		{"qtype zero", dnsTestRecord(1, 4242, 4241, 1000, 0, "curl", "www.example.com", 15)},
		{"qtype overflow", strings.Replace(valid, ":28:", ":65536:", 1)},
		{"comm empty", dnsTestRecord(1, 4242, 4241, 1000, 28, "", "www.example.com", 15)},
		{"comm odd hex", "1:4242:4241:1000:28:abc:7777772e6578616d706c652e636f6d:15"},
		{"comm control", "1:4242:4241:1000:28:01:7777772e6578616d706c652e636f6d:15"},
		{"qname empty", dnsTestRecord(1, 4242, 4241, 1000, 28, "curl", "", 15)},
		{"qname odd hex", "1:4242:4241:1000:28:6375726c:777:15"},
		{"qname bad byte", dnsTestRecord(1, 4242, 4241, 1000, 28, "curl", "www.ex ample.com", 15)},
		{"qname leading dot", dnsTestRecord(1, 4242, 4241, 1000, 28, "curl", ".example.com", 12)},
		{"qname double dot", dnsTestRecord(1, 4242, 4241, 1000, 28, "curl", "www..example.com", 16)},
		{"fqdn zero", dnsTestRecord(1, 4242, 4241, 1000, 28, "curl", "www.example.com", 0)},
		{"fqdn too long", dnsTestRecord(1, 4242, 4241, 1000, 28, "curl", "www.example.com", 63)},
		{"qname longer than fqdn", dnsTestRecord(1, 4242, 4241, 1000, 28, "curl", "www.example.com", 10)},
		{"seven fields", "1:4242:4241:1000:28:6375726c:7777772e6578616d706c652e636f6d"},
		{"nine fields", valid + ":0"},
	}
	for _, mutation := range mutations {
		if _, _, err := parseCoreDnsEvents("0|" + mutation.record); err == nil {
			t.Fatalf("malformed record accepted (%s): %q", mutation.name, mutation.record)
		}
	}

	// Non-zero QTYPE values are preserved rather than rejected: a tunnel can
	// abuse any record type. 65535 is a valid raw u16.
	unknownType := dnsTestRecord(1, 4242, 4241, 1000, 65535, "curl", "www.example.com", 15)
	events, _, err := parseCoreDnsEvents("0|" + unknownType)
	if err != nil || len(events) != 1 || events[0].QType != 65535 {
		t.Fatalf("unknown qtype was not preserved: %v %v", events, err)
	}
}

func TestCoreDnsUnavailableIsCapabilityFact(t *testing.T) {
	if !errors.Is(ErrDnsUnavailable, ErrDnsUnavailable) {
		t.Fatal("ErrDnsUnavailable is not a sentinel")
	}
	wrapped := errors.Join(errors.New("context"), ErrDnsUnavailable)
	if !errors.Is(wrapped, ErrDnsUnavailable) {
		t.Fatal("errors.Is cannot see the wrapped dns capability sentinel")
	}
}

// FuzzCoreDnsParser is the Makefile fuzz-smoke target for the AP-6 DNS
// transport. It must never panic and every accepted batch must stay inside the
// documented bounds.
func FuzzCoreDnsParser(f *testing.F) {
	f.Add("empty")
	f.Add("0|")
	f.Add("3|" + dnsTestRecord(1_700_000_000_000_000_000, 4242, 4241, 1000, 28, "curl", "www.example.com", 15))
	f.Add("0|" + dnsTestRecord(1, 7, 7, 0, 16, "dnscat2", "aGVsbG8gd29y.tunnel.example", 60))
	f.Add("enabled=1:attached=3:events=42:drops=2:read_failures=7")
	f.Add("garbage")
	f.Fuzz(func(t *testing.T, response string) {
		events, dropped, err := parseCoreDnsEvents(response)
		if err == nil {
			if len(events) > maxDnsEventsPerResponse {
				t.Fatalf("accepted %d events above the bound", len(events))
			}
			if dropped > 0 && len(response) > maxDnsPayloadBytes {
				t.Fatal("accepted an oversized payload")
			}
			for _, event := range events {
				if event.TsNS == 0 || event.PID <= 0 || event.TGID <= 0 || event.QType == 0 {
					t.Fatalf("accepted invalid event fields: %+v", event)
				}
				if len(event.QName) > maxDnsQueryNameBytes || len(event.Comm) > maxDnsCommBytes {
					t.Fatalf("accepted an oversized field: %+v", event)
				}
				if event.FQDNLen < 1 || event.FQDNLen > maxDnsFQDNLength || len(event.QName) > event.FQDNLen {
					t.Fatalf("accepted inconsistent fqdn data: %+v", event)
				}
			}
		}
		status, statusErr := parseCoreDnsStatus(response)
		if statusErr == nil {
			if status.AttachMask > 3 {
				t.Fatalf("accepted attach mask %d", status.AttachMask)
			}
			if status.Attached != (status.AttachMask != 0) {
				t.Fatalf("attach projection inconsistent: %+v", status)
			}
		}
	})
}
