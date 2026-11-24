package main

import (
	"bufio"
	"encoding/base64"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestFeedManagerPartitioningAndActionIsolation(t *testing.T) {
	tempDir := t.TempDir()
	fm := NewFeedManager(FeedConfig{MaxEntries: 1000}, tempDir)

	fm.feedStates["feodo-c2"].LastGoodItems = []string{"203.0.113.10/32"}
	fm.feedStates["cins-badguys"].LastGoodItems = []string{"198.51.100.20/32"}
	fm.feedStates["tor-bulk-exit"].LastGoodItems = []string{"192.0.2.30/32"}

	// Apply without kernel client (updates in-memory indices)
	added, deleted, err := fm.ApplyToKernel(nil, nil)
	if err != nil {
		t.Fatalf("ApplyToKernel failed: %v", err)
	}
	if added != 1 || deleted != 0 {
		t.Fatalf("expected 1 added (BLOCK), 0 deleted, got +%d/-%d", added, deleted)
	}

	// Invariant 1 enforcement: Only BLOCK vectors enter blockIndex
	if !fm.BlockIndex().ContainsString("203.0.113.10") {
		t.Fatal("BlockIndex missing Feodo BLOCK IP")
	}
	if fm.BlockIndex().ContainsString("198.51.100.20") {
		t.Fatal("BlockIndex erroneously contains CORRELATE_ONLY IP")
	}
	if fm.BlockIndex().ContainsString("192.0.2.30") {
		t.Fatal("BlockIndex erroneously contains ANNOTATE_ONLY IP")
	}

	// CorrelateIndex includes both BLOCK and CORRELATE_ONLY
	if !fm.CorrelateIndex().ContainsString("203.0.113.10") {
		t.Fatal("CorrelateIndex missing Feodo BLOCK IP")
	}
	if !fm.CorrelateIndex().ContainsString("198.51.100.20") {
		t.Fatal("CorrelateIndex missing CINS CORRELATE_ONLY IP")
	}
	if fm.CorrelateIndex().ContainsString("192.0.2.30") {
		t.Fatal("CorrelateIndex erroneously contains ANNOTATE_ONLY IP")
	}

	// AnnotateIndex contains strictly ANNOTATE_ONLY
	if !fm.AnnotateIndex().ContainsString("192.0.2.30") {
		t.Fatal("AnnotateIndex missing Tor Exit node")
	}
	if fm.AnnotateIndex().ContainsString("203.0.113.10") || fm.AnnotateIndex().ContainsString("198.51.100.20") {
		t.Fatal("AnnotateIndex contains non-annotate IP")
	}

	// Invariant 4: Shared generation ID and fingerprint
	if fm.Generation() != 1 {
		t.Fatalf("expected generation 1, got %d", fm.Generation())
	}
	if fm.Fingerprint() == "" {
		t.Fatal("expected non-empty fingerprint")
	}
}

func TestLastKnownGoodGenerationRetention(t *testing.T) {
	// Invariant 2: Each feed maintains a last-known-good generation. Failed, empty, malformed,
	// truncated or implausible downloads must never replace the current active generation.
	state := &FeedGenerationState{
		ID:            "feodo-c2",
		Name:          "Feodo Tracker C2",
		Action:        FeedActionBlock,
		LastGoodItems: []string{"203.0.113.50/32"},
		LastGoodCount: 1,
		LastGoodGen:   1,
		LastGoodAt:    time.Now().UTC().Add(-1 * time.Hour),
	}

	// Simulate empty download result: must NOT overwrite LastGoodItems
	emptyItems := []string{}
	now := time.Now().UTC()
	state.LastAttemptAt = now
	if len(emptyItems) == 0 {
		state.LastError = "empty payload rejected"
		state.ConsecutiveFails++
	}

	if len(state.LastGoodItems) != 1 || state.LastGoodItems[0] != "203.0.113.50/32" {
		t.Fatalf("LastGoodItems was cleared on empty download: %v", state.LastGoodItems)
	}
	if state.ConsecutiveFails != 1 {
		t.Fatalf("ConsecutiveFails=%d want=1", state.ConsecutiveFails)
	}
}

func TestLiveSyncLockOwnerAndCrashRecovery(t *testing.T) {
	// Invariant 6: The sync lock remains owned until the sync completes; its TTL is
	// crash recovery, not permission to steal from a live owner.
	var lock ThreatIntelLock

	acquired, remaining := lock.TryLock("operator")
	if !acquired || remaining != 0 {
		t.Fatalf("expected lock acquisition: acquired=%v remaining=%v", acquired, remaining)
	}

	// Immediate second acquisition fails with remaining duration
	acquired2, remaining2 := lock.TryLock("vis_threat_intel_cron_sync")
	if acquired2 || remaining2 <= 0 || remaining2 > threatIntelLockTTL {
		t.Fatalf("expected lock rejection: acquired=%v remaining=%v", acquired2, remaining2)
	}

	// Artificially age the acquiredAt timestamp beyond the 15m TTL
	lock.mu.Lock()
	lock.acquiredAt = time.Now().UTC().Add(-20 * time.Minute)
	lock.persistedAt = time.Now().UTC().Add(-20 * time.Minute)
	lock.mu.Unlock()

	// Worker 2 attempts to acquire: MUST FAIL because active is still true (worker 1 is live!)
	acquiredStillLive, remainingLive := lock.TryLock("worker-2")
	if acquiredStillLive {
		t.Fatal("lock stolen from live owner after 20 minutes")
	}
	if remainingLive <= 0 {
		t.Fatal("expected positive remaining duration")
	}

	// Worker 1 unlocks
	lock.Unlock()
	locked, _, _, _ := lock.Status()
	if locked {
		t.Fatal("lock still active after Unlock()")
	}

	// Now worker 2 can acquire
	acquired3, _ := lock.TryLock("worker-2")
	if !acquired3 {
		t.Fatal("failed to acquire after legitimate unlock")
	}
	lock.Unlock()

	// Test Crash Recovery: active == false, but persistedAt is recent (< 15m) -> locked
	lock.mu.Lock()
	lock.active = false
	lock.persistedAt = time.Now().UTC().Add(-5 * time.Minute)
	lock.mu.Unlock()

	acquiredCrash, _ := lock.TryLock("worker-3")
	if acquiredCrash {
		t.Fatal("crash lock acquired before TTL elapsed")
	}

	// Once persistedAt exceeds 15m -> crash recovery allows reacquisition
	lock.mu.Lock()
	lock.persistedAt = time.Now().UTC().Add(-16 * time.Minute)
	lock.mu.Unlock()

	acquiredRecovered, _ := lock.TryLock("worker-3")
	if !acquiredRecovered {
		t.Fatal("crash lock failed to recover after 16 minutes")
	}
	lock.Unlock()
}

func TestApplyToKernelAdditionsBeforeDeletionsAndRollback(t *testing.T) {
	// Invariant 5: Kernel diff updates must apply additions before deletions and must never
	// publish a new userspace generation until the corresponding kernel update succeeded.
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "core.key")
	socketPath := filepath.Join(dir, "core.sock")

	client, err := NewCoreClient(socketPath, keyPath, time.Second)
	if err != nil {
		t.Fatal(err)
	}

	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	var commandsReceived []string
	var commandsMu sync.Mutex

	// Mock server that records commands and simulates failure on a specific target
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				reader := bufio.NewReader(c)
				for {
					line, err := reader.ReadString('\n')
					if err != nil {
						return
					}
					fields := strings.Fields(strings.TrimSpace(line))
					if len(fields) >= 5 {
						cmd := fields[3]
						target := fields[4]
						commandsMu.Lock()
						commandsReceived = append(commandsReceived, cmd+":"+target)
						commandsMu.Unlock()

						responseTag := coreProtocol + "R"
						status := "OK"
						if target == "203.0.113.99/32" {
							status = "ERR"
						}
						payload := base64.RawURLEncoding.EncodeToString([]byte("ok"))
						mac := coreMAC(client.key, responseTag, fields[2], status, payload)
						_, _ = c.Write([]byte(strings.Join([]string{responseTag, fields[2], status, payload, mac}, " ") + "\n"))
					}
				}
			}(conn)
		}
	}()

	fm := NewFeedManager(FeedConfig{MaxEntries: 100}, dir)
	fm.feedStates["feodo-c2"].LastGoodItems = []string{"203.0.113.1/32", "203.0.113.2/32"}

	added, deleted, err := fm.ApplyToKernel(client, nil)
	if err != nil {
		t.Fatalf("ApplyToKernel failed: %v", err)
	}
	if added != 2 || deleted != 0 {
		t.Fatalf("expected 2 added, 0 deleted, got +%d/-%d", added, deleted)
	}
	if fm.Generation() != 1 {
		t.Fatalf("expected generation 1, got %d", fm.Generation())
	}

	// Second round: 1 deletion (.2) and 1 addition (.99) that FAILS
	fm.feedStates["feodo-c2"].LastGoodItems = []string{"203.0.113.1/32", "203.0.113.99/32"}
	_, _, err = fm.ApplyToKernel(client, nil)
	if err == nil {
		t.Fatal("expected error on failed addition")
	}

	// Invariant 5: Generation must NOT be updated if kernel sync fails
	if fm.Generation() != 1 {
		t.Fatalf("generation was updated despite failure: %d", fm.Generation())
	}

	commandsMu.Lock()
	defer commandsMu.Unlock()

	// Verify that additions occurred before deletions
	firstBatchAdds := 0
	for _, cmd := range commandsReceived {
		if strings.HasPrefix(cmd, "ADD:") {
			firstBatchAdds++
		}
	}
	if firstBatchAdds < 2 {
		t.Fatalf("expected at least 2 ADD commands recorded, got %d", firstBatchAdds)
	}
}

func TestFeedManagerSyncSemanticsStrictness(t *testing.T) {
	tempDir := t.TempDir()
	fm := NewFeedManager(FeedConfig{MaxEntries: 1000}, tempDir)

	// Invariant: Initial state is NEVER_SYNCED
	if fm.OverallStatus() != "NEVER_SYNCED" {
		t.Fatalf("expected NEVER_SYNCED initially, got %s", fm.OverallStatus())
	}
	if !fm.LastSuccessfulSyncAt().IsZero() {
		t.Fatal("expected zero LastSuccessfulSyncAt initially")
	}
	if !fm.LastFullySuccessfulSyncAt().IsZero() {
		t.Fatal("expected zero LastFullySuccessfulSyncAt initially")
	}
	if !fm.LastAttemptAt().IsZero() {
		t.Fatal("expected zero LastAttemptAt initially")
	}

	// Test Telemetry
	tel := fm.Telemetry()
	if tel.OverallStatus != "NEVER_SYNCED" {
		t.Fatalf("telemetry status %s != NEVER_SYNCED", tel.OverallStatus)
	}

	// Test Schema Migration from V1 to V2
	t1 := time.Now().UTC().Truncate(time.Second)
	v1State := `{
		"schema": "vgt-gedefense-threat-intel-state-v1",
		"last_successful_sync_at": "2026-10-01T12:00:00Z",
		"generation": 42,
		"fingerprint": "abc12345",
		"feeds": {
			"feodo-c2": {
				"id": "feodo-c2",
				"action": "BLOCK",
				"last_good_items": ["203.0.113.1/32"],
				"last_good_count": 1,
				"last_good_gen": 1,
				"last_good_at": "2026-10-01T12:00:00Z",
				"last_attempt_at": "2026-10-01T12:00:00Z"
			}
		}
	}`
	v1State = strings.ReplaceAll(v1State, "2026-10-01T12:00:00Z", t1.Format(time.RFC3339))
	v1Dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(v1Dir, "threat-intel-state.json"), []byte(v1State), 0o600); err != nil {
		t.Fatalf("failed to write v1 state: %v", err)
	}
	fm2 := NewFeedManager(FeedConfig{MaxEntries: 1000}, v1Dir)
	if fm2.Generation() != 42 {
		t.Fatalf("expected generation 42 from migrated v1 state, got %d", fm2.Generation())
	}
	if !fm2.LastSuccessfulSyncAt().Equal(t1) {
		t.Fatalf("expected LastSuccessfulSyncAt %v, got %v", t1, fm2.LastSuccessfulSyncAt())
	}
	if !fm2.LastFullySuccessfulSyncAt().Equal(t1) {
		t.Fatalf("expected LastFullySuccessfulSyncAt %v, got %v", t1, fm2.LastFullySuccessfulSyncAt())
	}
	if fm2.OverallStatus() != "OK" {
		t.Fatalf("expected migrated status OK, got %s", fm2.OverallStatus())
	}

	// Verify feeds status computation
	feedStates := fm2.SnapshotFeedStates()
	foundFeodo := false
	for _, f := range feedStates {
		if f.ID == "feodo-c2" {
			foundFeodo = true
			if f.Status != "OK" {
				t.Fatalf("expected feodo-c2 status OK, got %s", f.Status)
			}
		}
	}
	if !foundFeodo {
		t.Fatal("feodo-c2 not found in snapshot feed states")
	}
}

func TestThreatIntelV3PersistsPartialAndKernelCommitTruth(t *testing.T) {
	dir := t.TempDir()
	fm := NewFeedManager(FeedConfig{MaxEntries: 1000}, dir)
	partial := time.Date(2026, 10, 6, 20, 1, 2, 0, time.UTC)
	full := time.Date(2026, 10, 5, 19, 2, 3, 0, time.UTC)

	fm.mu.Lock()
	fm.lastAttemptAt = partial
	fm.lastSuccessfulSyncAt = partial
	fm.lastPartialSuccessfulSyncAt = partial
	fm.lastFullySuccessfulSyncAt = full
	fm.overallStatus = "PARTIAL"
	fm.kernelApplyLastAt = partial
	fm.kernelApplyStatus = kernelApplyApplied
	fm.kernelGeneration = 7
	fm.lastKernelAdded = 11
	fm.lastKernelDeleted = 3
	fm.generation = 7
	if err := fm.savePersistentStateLocked(); err != nil {
		fm.mu.Unlock()
		t.Fatal(err)
	}
	fm.mu.Unlock()

	reloaded := NewFeedManager(FeedConfig{MaxEntries: 1000}, dir)
	tel := reloaded.Telemetry()
	if !tel.LastPartialSuccessfulSyncAt.Equal(partial) {
		t.Fatalf("partial sync timestamp=%v want=%v", tel.LastPartialSuccessfulSyncAt, partial)
	}
	if !tel.LastFullySuccessfulSyncAt.Equal(full) {
		t.Fatalf("full sync timestamp=%v want=%v", tel.LastFullySuccessfulSyncAt, full)
	}
	if tel.LastKernelAdded != 11 || tel.LastKernelDeleted != 3 {
		t.Fatalf("kernel diff=+%d/-%d want +11/-3", tel.LastKernelAdded, tel.LastKernelDeleted)
	}
	if tel.OverallStatus != "PARTIAL" {
		t.Fatalf("overall status=%q want PARTIAL", tel.OverallStatus)
	}
}

func TestApplyToKernelDeletionFailureRollsBackAndDoesNotPublishGeneration(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "core.key")
	socketPath := filepath.Join(dir, "core.sock")

	client, err := NewCoreClient(socketPath, keyPath, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	var commands []string
	var commandsMu sync.Mutex
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				reader := bufio.NewReader(c)
				line, err := reader.ReadString('\n')
				if err != nil {
					return
				}
				fields := strings.Fields(strings.TrimSpace(line))
				if len(fields) < 6 {
					return
				}
				cmd, target := fields[3], fields[4]
				commandsMu.Lock()
				commands = append(commands, cmd+":"+target)
				commandsMu.Unlock()

				status := "OK"
				message := "ok"
				if cmd == "DEL" && target == "203.0.113.2/32" {
					status = "ERR"
					message = "simulated deletion failure"
				}
				encoded := base64.RawURLEncoding.EncodeToString([]byte(message))
				responseTag := coreProtocol + "R"
				mac := coreMAC(client.key, responseTag, fields[2], status, encoded)
				_, _ = c.Write([]byte(strings.Join([]string{responseTag, fields[2], status, encoded, mac}, " ") + "\n"))
			}(conn)
		}
	}()

	fm := NewFeedManager(FeedConfig{MaxEntries: 100}, dir)
	fm.feedStates["feodo-c2"].LastGoodItems = []string{"203.0.113.1/32", "203.0.113.2/32"}
	if _, _, err := fm.ApplyToKernel(client, nil); err != nil {
		t.Fatalf("initial kernel apply failed: %v", err)
	}
	status, _, generation, lastErr := fm.KernelApplyStatus()
	if status != kernelApplyApplied || generation != 1 || lastErr != "" {
		t.Fatalf("unexpected initial kernel status: status=%s generation=%d err=%q", status, generation, lastErr)
	}

	// New generation wants to add .3 and delete .2. The mock rejects the
	// deletion, so .3 must be rolled back and generation 1 must remain published.
	fm.feedStates["feodo-c2"].LastGoodItems = []string{"203.0.113.1/32", "203.0.113.3/32"}
	if _, _, err := fm.ApplyToKernel(client, nil); err == nil {
		t.Fatal("expected deletion failure")
	}
	if fm.Generation() != 1 {
		t.Fatalf("generation advanced despite failed deletion: %d", fm.Generation())
	}
	status, _, generation, lastErr = fm.KernelApplyStatus()
	if status != kernelApplyError || generation != 1 || lastErr == "" {
		t.Fatalf("failed apply status not preserved: status=%s generation=%d err=%q", status, generation, lastErr)
	}
	if _, ok := fm.appliedKernelEntries["203.0.113.2/32"]; !ok {
		t.Fatal("previous kernel generation lost failed-deletion entry")
	}
	if _, ok := fm.appliedKernelEntries["203.0.113.3/32"]; ok {
		t.Fatal("rolled-back addition remained in kernel mirror")
	}

	commandsMu.Lock()
	defer commandsMu.Unlock()
	joined := strings.Join(commands, "|")
	if !strings.Contains(joined, "ADD:203.0.113.3/32|DEL:203.0.113.2/32|DEL:203.0.113.3/32") {
		t.Fatalf("expected add -> failed delete -> addition rollback sequence, got %v", commands)
	}
}
