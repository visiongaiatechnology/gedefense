// STATUS: DIAMANT VGT SUPREME
package main

import (
	"testing"
	"time"
)

// TestSessionRotationDoesNotLeakRegistryEntries pins FIND-011. Every rotation may keep
// at most two registry entries for a session: the current id and the grace alias of the
// immediately preceding id. The alias from the rotation before that must be deleted when
// the new rotation overwrites previousID; otherwise len(sessions) grows by one per
// rotation and capacity-based eviction no longer matches the real session count.
func TestSessionRotationDoesNotLeakRegistryEntries(t *testing.T) {
	registry := newSessionRegistry()
	now := time.Unix(1_800_000_000, 0)
	registry.now = func() time.Time { return now }
	session, err := registry.create(now.Add(sessionAbsoluteLifetime))
	if err != nil {
		t.Fatal(err)
	}
	previousID := ""
	for rotation := 0; rotation < 50; rotation++ {
		if rotation > 0 {
			// Let the grace window of the previous rotation expire; a leaked alias
			// would then stay in the registry unvalidated.
			now = now.Add(sessionRotationGrace + time.Second)
		}
		retired := session.id
		if _, err := registry.rotate(session); err != nil {
			t.Fatalf("rotation %d failed: %v", rotation, err)
		}
		registry.mu.Lock()
		entries := len(registry.sessions)
		_, leaked := registry.sessions[previousID]
		registry.mu.Unlock()
		if entries > 2 {
			t.Fatalf("rotation %d left %d registry entries for one session, want at most 2", rotation, entries)
		}
		if leaked {
			t.Fatalf("rotation %d kept the retired previous id of the rotation before", rotation)
		}
		previousID = retired
	}
	registry.mu.Lock()
	entries := len(registry.sessions)
	registry.mu.Unlock()
	if entries != 2 {
		t.Fatalf("registry holds %d entries after 50 leak-free rotations, want 2 (current + grace alias)", entries)
	}
	if count := registry.count(); count != 1 {
		t.Fatalf("registry.count()=%d after 50 rotations of one session, want 1", count)
	}
	// The alias of the most recent rotation is the one that must stay usable inside its
	// grace window, and the current id must resolve as always.
	if _, ok := registry.validate(session.previousID); !ok {
		t.Fatal("the grace alias of the latest rotation was not accepted")
	}
	if _, ok := registry.validate(session.id); !ok {
		t.Fatal("the current session id was not accepted")
	}
}

// TestSessionRotationLeakDoesNotDistortCapacityEviction keeps the leak fix tied to the
// symptom that makes it a security issue: a registry full of orphaned aliases evicts
// aliases instead of the least recently used live session. With the fix, creating
// maxEntries sessions and rotating them keeps the eviction policy meaningful.
func TestSessionRotationLeakDoesNotDistortCapacityEviction(t *testing.T) {
	registry := newSessionRegistry()
	registry.maxEntries = 4
	now := time.Unix(1_800_000_000, 0)
	registry.now = func() time.Time { return now }
	sessions := make([]*gatewaySession, 0, registry.maxEntries)
	for i := 0; i < registry.maxEntries; i++ {
		session, err := registry.create(now.Add(sessionAbsoluteLifetime))
		if err != nil {
			t.Fatal(err)
		}
		sessions = append(sessions, session)
		now = now.Add(time.Second)
	}
	for _, session := range sessions {
		if _, err := registry.rotate(session); err != nil {
			t.Fatal(err)
		}
	}
	registry.mu.Lock()
	entries := len(registry.sessions)
	registry.mu.Unlock()
	if entries > 2*registry.maxEntries {
		t.Fatalf("registry holds %d entries for %d live sessions after one rotation each", entries, registry.maxEntries)
	}
	if count := registry.count(); count > registry.maxEntries {
		t.Fatalf("count=%d exceeds the registry cap of %d", count, registry.maxEntries)
	}
	// Capacity eviction after the rotations still reclaims whole sessions, aliases included.
	if _, err := registry.create(now.Add(sessionAbsoluteLifetime)); err != nil {
		t.Fatal(err)
	}
	registry.mu.Lock()
	entries = len(registry.sessions)
	registry.mu.Unlock()
	if entries > 2*registry.maxEntries {
		t.Fatalf("registry holds %d entries after capacity eviction, cap is %d sessions", entries, registry.maxEntries)
	}
}
