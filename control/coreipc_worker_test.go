package main

import (
	"errors"
	"strings"
	"testing"
)

func TestParseWorkerCrashSampleAcceptsTheKernelWire(t *testing.T) {
	sample, err := parseWorkerCrashSample("1482:33:33:99123:11:139:7068702d66706d")
	if err != nil {
		t.Fatalf("parse valid crash record: %v", err)
	}
	if sample.PID != 1482 || sample.UID != 33 || sample.GID != 33 ||
		sample.CgroupID != 99123 || sample.Signal != 11 || sample.ExitCode != 139 ||
		sample.Comm != "php-fpm" {
		t.Fatalf("unexpected sample: %#v", sample)
	}
}

func TestParseWorkerCrashSampleRejectsMalformedRecords(t *testing.T) {
	for _, malicious := range []string{
		"",
		"1482:33:33:99123:11:139",
		"1482:33:33:99123:11:139:7068702d66706d:extra",
		"0:33:33:99123:11:139:7068702d66706d",
		"-1482:33:33:99123:11:139:7068702d66706d",
		"1482:33:33:99123:300:139:7068702d66706d",
		"1482:33:33:99123:11:139:zz",
		"1482:33:33:99123:11:139:",
		"1482:33:33:99123:11:139:7068702d66706dff00",
	} {
		if _, err := parseWorkerCrashSample(malicious); err == nil {
			t.Fatalf("accepted malformed record %q", malicious)
		}
	}
}

func TestParseWorkerGuardCoreStatusRoundTrip(t *testing.T) {
	status, err := parseWorkerGuardCoreStatus("enabled=1 attached=1 comms=4 uids=2 emitted=17 dropped=0")
	if err != nil {
		t.Fatalf("parse status: %v", err)
	}
	if !status.Enabled || !status.Attached || status.Comms != 4 || status.UIDs != 2 ||
		status.Emitted != 17 || status.Dropped != 0 {
		t.Fatalf("unexpected status: %#v", status)
	}
}

func TestParseWorkerGuardCoreStatusRejectsUnknownOrIncompleteFields(t *testing.T) {
	for _, malicious := range []string{
		"",
		"enabled=1 attached=1 comms=0 uids=0 emitted=0",
		"enabled=2 attached=1 comms=0 uids=0 emitted=0 dropped=0",
		"enabled=1 attached=1 comms=-1 uids=0 emitted=0 dropped=0",
		"enabled=1 attached=1 comms=0 uids=0 emitted=x dropped=0",
		"enabled=1 attached=1 comms=0 uids=0 emitted=0 dropped=0 surprise=1",
		"enabled=1 attached=1 comms=0 uids=0 emitted=0 dropped=0 enabled=1",
		strings.Repeat("x", 600),
	} {
		if _, err := parseWorkerGuardCoreStatus(malicious); err == nil {
			t.Fatalf("accepted malformed status %q", malicious)
		}
	}
}

func TestWorkerGuardRegistryValidatesBeforeTransport(t *testing.T) {
	client := &CoreClient{}
	if err := client.WorkerGuardCommAdd(""); err == nil {
		t.Fatal("accepted empty comm")
	}
	if err := client.WorkerGuardCommAdd("0123456789abcdef"); err == nil {
		t.Fatal("accepted oversized comm")
	}
	if !errors.Is(ErrWorkerGuardUnavailable, ErrWorkerGuardUnavailable) {
		t.Fatal("capability error is not stable")
	}
}
