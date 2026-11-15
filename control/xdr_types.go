package main

import "time"

type XDRIncident struct {
	ID               string            `json:"id"`
	Time             time.Time         `json:"time"`
	Severity         string            `json:"severity"`
	Score            int               `json:"score"`
	ResponseScore    int               `json:"response_score,omitempty"`
	KillSignals      int               `json:"kill_signals,omitempty"`
	PID              int               `json:"pid,omitempty"`
	PPID             int               `json:"ppid,omitempty"`
	StartTicks       uint64            `json:"start_ticks,omitempty"`
	UID              uint32            `json:"uid,omitempty"`
	CellCgroupID     uint64            `json:"cell_cgroup_id,omitempty"`
	SocketFamily     int32             `json:"socket_family,omitempty"`
	Process          string            `json:"process,omitempty"`
	Executable       string            `json:"executable,omitempty"`
	Parent           string            `json:"parent,omitempty"`
	Remote           string            `json:"remote,omitempty"`
	CommandPreview   string            `json:"command_preview,omitempty"`
	CommandSHA256    string            `json:"command_sha256,omitempty"`
	RequestID        string            `json:"request_id,omitempty"`
	HTTPMethod       string            `json:"http_method,omitempty"`
	HTTPHost         string            `json:"http_host,omitempty"`
	HTTPPath         string            `json:"http_path,omitempty"`
	BodySHA256       string            `json:"body_sha256,omitempty"`
	RuleIDs          []string          `json:"rule_ids"`
	Categories       []string          `json:"categories"`
	Summary          string            `json:"summary"`
	Decision         string            `json:"decision"`
	Action           string            `json:"action"`
	Outcome          string            `json:"outcome"`
	Acknowledged     bool              `json:"acknowledged"`
	EvidenceRoot     string            `json:"evidence_root,omitempty"`
	RecordHash       string            `json:"record_hash,omitempty"`
	ExecutionChainID string            `json:"execution_chain_id,omitempty"`
	AttackStory      []AttackStoryNode `json:"attack_story,omitempty"`
}

type BehaviorSummary struct {
	Profiles            int        `json:"profiles"`
	WarmProfiles        int        `json:"warm_profiles"`
	MaxProfiles         int        `json:"max_profiles"`
	Saturated           bool       `json:"saturated"`
	DroppedObservations uint64     `json:"dropped_observations"`
	LastSaved           *time.Time `json:"last_saved,omitempty"`
	IntegrityOK         bool       `json:"integrity_ok"`
	Error               string     `json:"error,omitempty"`
}

type XDRStatus struct {
	Enabled          bool            `json:"enabled"`
	Mode             string          `json:"mode"`
	Degraded         bool            `json:"degraded"`
	DegradedReason   string          `json:"degraded_reason,omitempty"`
	Processes        int             `json:"processes"`
	OpenConnections  int             `json:"open_connections"`
	IncidentsTotal   uint64          `json:"incidents_total"`
	ActionsTotal     uint64          `json:"actions_total"`
	LastScan         *time.Time      `json:"last_scan,omitempty"`
	Sensor           string          `json:"sensor"`
	ProtectedObjects int             `json:"protected_objects"`
	QueueDepth       int             `json:"queue_depth"`
	QueueCapacity    int             `json:"queue_capacity"`
	EvaluationDrops  uint64          `json:"evaluation_drops"`
	EvaluationsTotal uint64          `json:"evaluations_total"`
	AnomaliesTotal   uint64          `json:"anomalies_total"`
	Behavior         BehaviorSummary `json:"behavior"`
}

type ProcessSample struct {
	PID         int
	PPID        int
	StartTicks  uint64
	UID         uint32
	GID         uint32
	Comm        string
	Exe         string
	ParentExe   string
	Cmdline     string
	CmdSHA256   string
	Cgroup      string
	Connections []NetConnection
}

type NetConnection struct {
	Protocol   string
	RemoteIP   string
	RemotePort uint16
	State      string
	Inode      string
}

type RuleMatch struct {
	ID              string
	Category        string
	Score           int
	Summary         string
	KillEligible    bool
	OperatorDefined bool
	AlertOnly       bool
	Remote          string
}

type XDRDecision struct {
	Score         int
	ResponseScore int
	RuleIDs       []string
	Categories    []string
	Summary       string
	Decision      string
	KillSignals   int
	Remote        string
}

// ------------------------------------------------------- Titan exec gate views
//
// POINT 1 / P1-T5: the bounded read-only projections of the kernel exec gate.
// Every field is a kernel or sync fact; none of them is derived from a secret,
// and every list is capped by the producer (event history: 64). The types live
// here because they describe XDR-visible state, not the ingestion machinery.

// TitanExecStatus is the small Titan exec-gate projection attached to
// GET /api/v1/status. It never claims enforcement: sensor_state is derived from
// the syncer state and the kernel facts the core reported.
type TitanExecStatus struct {
	State       string `json:"state"`
	SensorState string `json:"sensor_state"`
	Capability  string `json:"capability"`
	Enabled     bool   `json:"enabled"`
	Mode        string `json:"mode"`
	Path        string `json:"path"`
	LSM         string `json:"lsm"`
	Offsets     string `json:"offsets"`
	Entries     int    `json:"entries"`
	Scopes      int    `json:"scopes"`
	EventsTotal uint64 `json:"events_total"`
	Denies      uint64 `json:"denies"`
	Audits      uint64 `json:"audits"`
	Dropped     uint64 `json:"dropped"`
	ParseErrors uint64 `json:"parse_errors"`
	Incidents   uint64 `json:"incidents"`
}

// TitanExecKernelView carries the kernel-side facts and the last health sample.
// HealthAt is nil until a TITAN_EXEC_HEALTH answer arrived; HealthError and
// DrainError name a failure instead of hiding it behind a zero counter row.
type TitanExecKernelView struct {
	Path        string              `json:"path"`
	LSM         string              `json:"lsm"`
	Offsets     string              `json:"offsets"`
	Entries     int                 `json:"entries"`
	Scopes      int                 `json:"scopes"`
	Health      CoreTitanExecHealth `json:"health"`
	HealthAt    *time.Time          `json:"health_at,omitempty"`
	HealthError string              `json:"health_error,omitempty"`
	DrainError  string              `json:"drain_error,omitempty"`
}

// TitanExecEventCountersView is the bounded ingestion counter projection.
type TitanExecEventCountersView struct {
	EventsTotal uint64 `json:"events_total"`
	Denies      uint64 `json:"denies"`
	Audits      uint64 `json:"audits"`
	Dropped     uint64 `json:"dropped"`
	ParseErrors uint64 `json:"parse_errors"`
	Incidents   uint64 `json:"incidents"`
}

// TitanExecStatusView is the GET /api/v1/titan/exec/status payload: the sync
// state, the kernel facts and health, and the ingestion counters in one read.
type TitanExecStatusView struct {
	State        string                     `json:"state"`
	SensorState  string                     `json:"sensor_state"`
	Capability   string                     `json:"capability"`
	Sync         TitanExecSyncStatus        `json:"sync"`
	Kernel       TitanExecKernelView        `json:"kernel"`
	Counters     TitanExecEventCountersView `json:"counters"`
	HistoryLimit int                        `json:"history_limit"`
}

// TitanExecEventView is one decoded §3.3 record as the read-only API exposes it.
// The comm is already validated to printable ASCII by the parser, so it cannot
// forge separators or lines in an operator surface.
type TitanExecEventView struct {
	CgroupID   uint64 `json:"cgroup_id"`
	TsNS       uint64 `json:"ts_ns"`
	Dev        uint32 `json:"dev"`
	InodeMode  uint32 `json:"inode_mode"`
	Ino        uint64 `json:"ino"`
	Generation uint32 `json:"generation"`
	PID        uint32 `json:"pid"`
	TGID       uint32 `json:"tgid"`
	UID        uint32 `json:"uid"`
	GID        uint32 `json:"gid"`
	Prot       uint32 `json:"prot"`
	FFlags     uint32 `json:"f_flags"`
	Hook       uint8  `json:"hook"`
	Action     uint8  `json:"action"`
	Reason     uint8  `json:"reason"`
	Flags      uint8  `json:"flags"`
	Comm       string `json:"comm"`
	RuleID     string `json:"rule_id"`
}

// TitanExecEventsView is the bounded GET /api/v1/titan/exec/events payload. It
// carries the most recent events (newest first) and never more than the history
// limit; Available names how many events the bounded history currently holds.
type TitanExecEventsView struct {
	Events       []TitanExecEventView       `json:"events"`
	Limit        int                        `json:"limit"`
	Available    int                        `json:"available"`
	HistoryLimit int                        `json:"history_limit"`
	Counters     TitanExecEventCountersView `json:"counters"`
}
