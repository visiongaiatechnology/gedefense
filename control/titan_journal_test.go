// STATUS: DIAMANT VGT SUPREME
// SPDX-FileCopyrightText: 2026 VisionGaia Technology
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestTitanJournalBoundsPaginationAndReload(t *testing.T) {
	rig := newTitanTestRig(t, func(rig *titanTestRig) {
		rig.cfg.MaxEvents = titanMinJournalEvents
	})
	for index := 0; index < 60; index++ {
		rig.observe(rig.write(filepath.Join("bulk", "file-"+twoDigits(index)+".bin"), "x"), TitanChangeCreated)
	}
	status := rig.engine.Status()
	if status.EventsTotal != 60 {
		t.Fatalf("events_total = %d, want 60", status.EventsTotal)
	}
	if got := status.Trust.Unexpected + status.Trust.Authorized + status.Trust.Tolerated + status.Trust.Compromised; got != titanMinJournalEvents {
		t.Fatalf("retained trust counts = %d, want %d", got, titanMinJournalEvents)
	}
	if got := status.OpenFindings; got != titanMinJournalEvents {
		t.Fatalf("open findings = %d, want %d", got, titanMinJournalEvents)
	}
	// Pagination walks the retained window exactly once, newest-first.
	seen := make(map[string]struct{}, titanMinJournalEvents)
	cursor := ""
	firstBatch, next, err := rig.engine.Events(10, "")
	if err != nil {
		t.Fatalf("events page failed: %v", err)
	}
	if len(firstBatch) != 10 || next == "" {
		t.Fatalf("first page = %d events next=%q", len(firstBatch), next)
	}
	for _, event := range firstBatch {
		seen[event.ID] = struct{}{}
	}
	cursor = next
	for cursor != "" {
		batch, nextCursor, pageErr := rig.engine.Events(10, cursor)
		if pageErr != nil {
			t.Fatalf("page cursor %q failed: %v", cursor, pageErr)
		}
		for _, event := range batch {
			if _, duplicate := seen[event.ID]; duplicate {
				t.Fatalf("pagination returned duplicate event %s", event.ID)
			}
			seen[event.ID] = struct{}{}
		}
		cursor = nextCursor
	}
	if len(seen) != titanMinJournalEvents {
		t.Fatalf("pagination covered %d events, want %d", len(seen), titanMinJournalEvents)
	}
	// The limit is capped, never expanded by the caller.
	capped, _, err := rig.engine.Events(500, "")
	if err != nil || len(capped) > titanMaxLimit {
		t.Fatalf("event limit not capped: %d %v", len(capped), err)
	}
	if _, _, err := rig.engine.Events(10, "%%%not-base64%%%"); err == nil {
		t.Fatal("malformed cursor accepted")
	}
	// Journal file stays inside its byte budget.
	info, err := os.Stat(rig.cfg.JournalFile)
	if err != nil {
		t.Fatalf("journal file missing: %v", err)
	}
	if info.Size() > rig.cfg.JournalMaxBytes {
		t.Fatalf("journal size %d exceeds budget %d", info.Size(), rig.cfg.JournalMaxBytes)
	}
	// A restart restores the retained window and continues the sequence.
	restarted := newTitanTestRigForCfg(t, rig.cfg, rig.stateDir)
	restartedStatus := restarted.engine.Status()
	if restartedStatus.EventsTotal != 60 || restartedStatus.OpenFindings != titanMinJournalEvents {
		t.Fatalf("journal restart state wrong: %+v", restartedStatus)
	}
	events, _, err := restarted.engine.Events(titanMaxLimit, "")
	if err != nil || len(events) != titanMinJournalEvents {
		t.Fatalf("journal restart events = %d err=%v", len(events), err)
	}
	for index := 1; index < len(events); index++ {
		if events[index-1].JournalSequence <= events[index].JournalSequence {
			t.Fatalf("events are not newest-first: %d then %d", events[index-1].JournalSequence, events[index].JournalSequence)
		}
	}
}

func TestTitanJournalByteBudgetTrimming(t *testing.T) {
	rig := newTitanTestRig(t, func(rig *titanTestRig) {
		rig.cfg.MaxEvents = 300
		rig.cfg.JournalMaxBytes = titanMinJournalBytes
	})
	deep := filepath.Join("trim", strings.Repeat("d", 180), strings.Repeat("e", 180))
	if err := os.MkdirAll(rig.path(deep), 0o700); err != nil {
		t.Fatal(err)
	}
	for index := 0; index < 400; index++ {
		name := "f" + threeDigits(index)
		rig.write(filepath.Join(deep, name), "x")
		rig.engine.observe(titanObservation{Path: rig.path(filepath.Join(deep, name)), ChangeType: TitanChangeCreated, ObservedUTC: rig.now, Sensor: "test", Live: true})
	}
	info, err := os.Stat(rig.cfg.JournalFile)
	if err != nil {
		t.Fatalf("journal file missing: %v", err)
	}
	if info.Size() > titanMinJournalBytes {
		t.Fatalf("journal size %d exceeds bounded budget %d", info.Size(), titanMinJournalBytes)
	}
	rig.engine.mu.RLock()
	retained := len(rig.engine.events)
	rig.engine.mu.RUnlock()
	if retained < titanMinJournalEvents || retained > 400 {
		t.Fatalf("retained events = %d after byte trimming", retained)
	}
}

func TestTitanCorruptJournalFallsBack(t *testing.T) {
	rig := newTitanTestRig(t, nil)
	rig.observe(rig.write("one.bin", "x"), TitanChangeCreated)
	corrupt := []byte("{corrupt journal")
	if err := os.WriteFile(rig.cfg.JournalFile, corrupt, 0o600); err != nil {
		t.Fatal(err)
	}
	restarted := newTitanTestRigForCfg(t, rig.cfg, rig.stateDir)
	if restarted.engine.loadWarning == "" {
		t.Fatal("corrupt journal was not surfaced")
	}
	if got := restarted.engine.Status().EventsTotal; got != 0 {
		t.Fatalf("corrupt journal produced events_total=%d", got)
	}
	preserved, err := os.ReadFile(rig.cfg.JournalFile)
	if err != nil || string(preserved) != string(corrupt) {
		t.Fatalf("corrupt journal was modified: %v", err)
	}
}

func twoDigits(value int) string {
	if value < 10 {
		return "0" + string(rune('0'+value))
	}
	return string(rune('0'+value/10)) + string(rune('0'+value%10))
}

func threeDigits(value int) string {
	return string([]rune{'0' + rune(value/100), '0' + rune((value/10)%10), '0' + rune(value%10)})
}
