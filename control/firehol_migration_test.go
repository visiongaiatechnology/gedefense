// STATUS: DIAMANT VGT SUPREME
package main

import (
	"strings"
	"testing"
)

// TestFireholMigrationRaisesExactlyOneFeed covers why the feed correction never reached
// an existing installation.
//
// The compiled-in default was changed from correlate to block, but a default only seeds
// a fresh document: an installed node keeps whatever its persisted settings say forever.
// The migration on schema version 10 is what actually reaches those nodes, so what it
// touches - and what it must not touch - is asserted here rather than assumed.
func TestFireholMigrationRaisesExactlyOneFeed(t *testing.T) {
	document := legacyDocumentWithFeeds(t, 9, []ThreatFeedSourceSettings{
		{ID: fireholLevelOneFeedID, Name: "FireHOL Level 1", Action: string(FeedActionCorrelateOnly)},
		{ID: "feodo-c2", Name: "Feodo Tracker C2", Action: string(FeedActionBlock)},
		{ID: "tor-bulk-exit", Name: "Tor exit relays", Action: string(FeedActionAnnotateOnly)},
		{ID: "cins-badguys", Name: "CINS", Action: string(FeedActionCorrelateOnly)},
	})

	before := document.ThreatIntel.Feeds[0].Action

	if !upgradeRuntimeSettings(&document, RuntimeSettings{}) {
		t.Fatal("the migration reported no change for an outdated document")
	}

	// The one intended value moved.
	if got := document.ThreatIntel.Feeds[0].Action; got != string(FeedActionBlock) {
		t.Fatalf("firehol action is %q after migration, want %q (was %q)", got, FeedActionBlock, before)
	}
	// Every other feed kept its operator value, including the correlate-only one. A
	// migration that raised every feed would be a different, much larger change.
	want := []string{"BLOCK", "BLOCK", "ANNOTATE_ONLY", "CORRELATE_ONLY"}
	for index, feed := range document.ThreatIntel.Feeds {
		if feed.Action != want[index] {
			t.Errorf("feed %s action is %q after migration, want %q", feed.ID, feed.Action, want[index])
		}
	}
	if len(document.ThreatIntel.Feeds) != 4 {
		t.Fatalf("the migration changed the number of feeds: %d", len(document.ThreatIntel.Feeds))
	}

	// The change is named, so an upgrade is never a silent edit.
	if len(document.Migrations) == 0 {
		t.Fatal("the migration changed an operator value without recording what it changed")
	}
	note := strings.Join(document.Migrations, " ")
	if !strings.Contains(note, fireholLevelOneFeedID) {
		t.Fatalf("the migration note does not name the feed it changed: %q", note)
	}
	if !strings.Contains(note, "BLOCK") {
		t.Fatalf("the migration note does not name the value it applied: %q", note)
	}
	if document.FabricVersion != fabricSettingsVersion {
		t.Fatalf("the document was left at version %d, want %d", document.FabricVersion, fabricSettingsVersion)
	}
}

// TestFireholMigrationNeverLowersAChoice is the guard in the other direction. A node
// whose operator deliberately escalated the feed further must not be walked back, and a
// document already at the current version must not be touched at all.
func TestFireholMigrationNeverLowersAChoice(t *testing.T) {
	// Already current: no migration runs, so nothing is rewritten and nothing is noted.
	current := legacyDocumentWithFeeds(t, fabricSettingsVersion, []ThreatFeedSourceSettings{
		{ID: fireholLevelOneFeedID, Name: "FireHOL Level 1", Action: string(FeedActionBlock)},
	})
	if upgradeRuntimeSettings(&current, RuntimeSettings{}) {
		t.Fatal("a current document was migrated")
	}
	if len(current.Migrations) != 0 {
		t.Fatalf("a current document accumulated migration notes: %v", current.Migrations)
	}

	// Outdated, and the operator had already set the value we would apply: the migration
	// must not claim credit for a change it did not make.
	already := legacyDocumentWithFeeds(t, 9, []ThreatFeedSourceSettings{
		{ID: fireholLevelOneFeedID, Name: "FireHOL Level 1", Action: string(FeedActionBlock)},
	})
	upgradeRuntimeSettings(&already, RuntimeSettings{})
	if len(already.Migrations) != 0 {
		t.Fatalf("the migration reported a change it did not make: %v", already.Migrations)
	}

	// A document with no threat-intel namespace at all must survive the step.
	empty := RuntimeSettings{FabricVersion: 9}
	if !upgradeRuntimeSettings(&empty, RuntimeSettings{}) {
		t.Fatal("a document without a threat-intel namespace was not upgraded")
	}
	if empty.ThreatIntel == nil {
		t.Fatal("the upgrade did not seed the threat-intel namespace")
	}
}

// TestFireholDefaultIsBlockAndReachableFromTheCompiledDefault pins both halves: the
// shipped default, and the fact that the migration matches the same identifier the
// default uses. A drift between the two would make the migration silently match nothing.
func TestFireholDefaultIsBlockAndReachableFromTheCompiledDefault(t *testing.T) {
	found := false
	for _, source := range DefaultThreatFeedSources {
		if source.ID != fireholLevelOneFeedID {
			continue
		}
		found = true
		if source.Action != FeedActionBlock {
			t.Fatalf("the shipped default for %s is %q, want %q", source.ID, source.Action, FeedActionBlock)
		}
	}
	if !found {
		t.Fatalf("no shipped feed carries the id %q that the migration matches on", fireholLevelOneFeedID)
	}
}

// legacyDocumentWithFeeds builds a document at the given schema version carrying the
// supplied feed list, so the migration is exercised against realistic input.
func legacyDocumentWithFeeds(t *testing.T, version int, feeds []ThreatFeedSourceSettings) RuntimeSettings {
	t.Helper()
	return RuntimeSettings{
		FabricVersion: version,
		ThreatIntel:   &ThreatIntelFabricSettings{Feeds: append([]ThreatFeedSourceSettings(nil), feeds...)},
	}
}
