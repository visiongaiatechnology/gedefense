// STATUS: DIAMANT VGT SUPREME
package main

// V6.3.0 AP-7: types for the persistent, bounded operator review queue.
//
// The queue replaces the in-memory 4,096-entry ring whose overflow silently
// discarded false-positive triage evidence. It is TTL-bounded, capacity-bounded
// (bytes and entries), disk-reserve aware, deduplicated by finding hash and
// stores only the already-redacted preview fields an incident carries.

import (
	"encoding/json"
	"time"
)

const (
	reviewQueueSchema     = "vgt-gedefense-review-queue-v1"
	reviewQueueHMACSchema = "vgt-gedefense-review-queue-hmac-v1"

	reviewQueueStoreFileName = "review-queue.json"
	reviewQueueKeyFileName   = "review-queue.key"
	reviewQueuePurpose       = "xdr-review-queue"

	reviewQueueDefaultTTL = 7 * 24 * time.Hour
	reviewQueueMaxTTL     = 30 * 24 * time.Hour

	reviewQueueDefaultMaxEntries = 4096
	reviewQueueDefaultMaxBytes   = 8 << 20
	reviewQueueStoreReadBytes    = 16 << 20
	reviewQueueEntryMaxBytes     = 8 << 10
	reviewQueueDiskReserveBytes  = 256 << 20

	reviewQueueFlushInterval = 30 * time.Second
	// A bounded burst may dirty this many entries before an immediate flush, so
	// the crash window stays small without an fsync per incident.
	reviewQueueForceFlushAdds = 128

	reviewQueueMaxFieldBytes    = 512
	reviewQueueMaxPreviewBytes  = 512
	reviewQueueMaxRules         = 16
	reviewQueueMaxCategories    = 8
	reviewQueueIDHexBytes       = 32
	reviewQueueHMACDomainString = "VGT-GEDEFENSE-REVIEW-QUEUE-HMAC-V1\x00"
)

// ReviewEntry is one bounded finding waiting for operator triage. It never
// carries raw command lines, request bodies or credentials: only the fields the
// incident producer already redacted and bounded.
type ReviewEntry struct {
	// ID is the finding hash; it is also the stable ack/delete handle.
	ID               string     `json:"id"`
	FindingHash      string     `json:"finding_hash"`
	Time             time.Time  `json:"time"`
	FirstSeen        time.Time  `json:"first_seen"`
	LastSeen         time.Time  `json:"last_seen"`
	RepeatCount      int        `json:"repeat_count"`
	Severity         string     `json:"severity"`
	Score            int        `json:"score"`
	Decision         string     `json:"decision"`
	Action           string     `json:"action"`
	Process          string     `json:"process,omitempty"`
	Executable       string     `json:"executable,omitempty"`
	Parent           string     `json:"parent,omitempty"`
	Remote           string     `json:"remote,omitempty"`
	CommandPreview   string     `json:"command_preview,omitempty"`
	RuleIDs          []string   `json:"rule_ids,omitempty"`
	Categories       []string   `json:"categories,omitempty"`
	PermitTrustLevel string     `json:"permit_trust_level,omitempty"`
	PermitID         string     `json:"permit_id,omitempty"`
	ExpiresAt        time.Time  `json:"expires_at"`
	Acknowledged     bool       `json:"acknowledged"`
	AcknowledgedAt   *time.Time `json:"acknowledged_at,omitempty"`
	// Bytes is the canonical serialized size used for the byte budget.
	Bytes int `json:"bytes"`
}

// ReviewQueueReport is the bounded queue projection exposed by the API.
type ReviewQueueReport struct {
	Loaded         bool       `json:"loaded"`
	StorePath      string     `json:"store_path,omitempty"`
	Corrupt        bool       `json:"corrupt"`
	Degraded       bool       `json:"degraded,omitempty"`
	DegradedReason string     `json:"degraded_reason,omitempty"`
	Entries        int        `json:"entries"`
	Bytes          int        `json:"bytes"`
	MaxEntries     int        `json:"max_entries"`
	MaxBytes       int        `json:"max_bytes"`
	TTLSeconds     int64      `json:"ttl_seconds"`
	DiskReserve    int64      `json:"disk_reserve_bytes"`
	Acknowledged   int        `json:"acknowledged"`
	Rejected       uint64     `json:"rejected"`
	Deduped        uint64     `json:"deduped"`
	Expired        uint64     `json:"expired"`
	InvalidDropped uint64     `json:"invalid_dropped"`
	LastFlush      *time.Time `json:"last_flush,omitempty"`
}

// ReviewQueueView is the GET /api/v1/xdr/review payload.
type ReviewQueueView struct {
	Report  ReviewQueueReport `json:"report"`
	Entries []ReviewEntry     `json:"entries"`
	Limit   int               `json:"limit"`
}

// reviewQueueBinding is the engine-derived store configuration.
type reviewQueueBinding struct {
	StorageDir  string
	Cipher      *StorageCipher
	TTL         time.Duration
	MaxEntries  int
	MaxBytes    int
	DiskReserve int64
}

// reviewQueueStoreDocument is the authenticated inner store payload.
type reviewQueueStoreDocument struct {
	Schema   string            `json:"schema"`
	Sequence uint64            `json:"sequence"`
	Entries  []json.RawMessage `json:"entries"`
}
