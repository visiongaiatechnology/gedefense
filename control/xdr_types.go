package main

import "time"

type XDRIncident struct {
	ID             string    `json:"id"`
	Time           time.Time `json:"time"`
	Severity       string    `json:"severity"`
	Score          int       `json:"score"`
	ResponseScore  int       `json:"response_score,omitempty"`
	KillSignals    int       `json:"kill_signals,omitempty"`
	PID            int       `json:"pid,omitempty"`
	PPID           int       `json:"ppid,omitempty"`
	StartTicks     uint64    `json:"start_ticks,omitempty"`
	UID            uint32    `json:"uid,omitempty"`
	Process        string    `json:"process,omitempty"`
	Executable     string    `json:"executable,omitempty"`
	Parent         string    `json:"parent,omitempty"`
	Remote         string    `json:"remote,omitempty"`
	CommandPreview string    `json:"command_preview,omitempty"`
	CommandSHA256  string    `json:"command_sha256,omitempty"`
	RuleIDs        []string  `json:"rule_ids"`
	Categories     []string  `json:"categories"`
	Summary        string    `json:"summary"`
	Decision       string    `json:"decision"`
	Action         string    `json:"action"`
	Outcome        string    `json:"outcome"`
	Acknowledged   bool      `json:"acknowledged"`
	RecordHash     string    `json:"record_hash,omitempty"`
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
