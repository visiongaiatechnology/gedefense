// STATUS: DIAMANT VGT SUPREME
package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Typed Deception Error Hierarchy (Section 1.5.A Compliance)
type DeceptionException struct {
	Message string
	Err     error
}

func (e *DeceptionException) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("%s: %v", e.Message, e.Err)
	}
	return e.Message
}

func (e *DeceptionException) Unwrap() error { return e.Err }

type DeceptionValidationException struct{ DeceptionException }
type DeceptionSecurityException struct{ DeceptionException }

func NewDeceptionValidationException(msg string, err error) *DeceptionValidationException {
	return &DeceptionValidationException{DeceptionException{Message: msg, Err: err}}
}

func NewDeceptionSecurityException(msg string, err error) *DeceptionSecurityException {
	return &DeceptionSecurityException{DeceptionException{Message: msg, Err: err}}
}

type CanaryType string

const (
	CanarySSHKey    CanaryType = "SSH_KEY"
	CanaryCloudCred CanaryType = "CLOUD_CRED"
	CanaryShadow    CanaryType = "SHADOW_BAK"
	CanaryDotEnv    CanaryType = "DOTENV"
)

// CanaryToken defines an authentic decoy deployed to trap unauthorized host access.
type CanaryToken struct {
	ID               string     `json:"id"`
	Path             string     `json:"path"`
	Type             CanaryType `json:"type"`
	CreatedAt        time.Time  `json:"created_at"`
	PayloadSignature string     `json:"payload_signature"`
	OwnerUID         uint32     `json:"owner_uid"`
	FileMode         uint32     `json:"file_mode"`
}

// DeceptionAccessEvent encapsulates the kernel-level event when a canary is accessed.
type DeceptionAccessEvent struct {
	CanaryPath         string    `json:"canary_path"`
	AccessorPID        int       `json:"accessor_pid"`
	AccessorStartTicks uint64    `json:"accessor_start_ticks,omitempty"`
	AccessorUID        uint32    `json:"accessor_uid"`
	AccessorComm       string    `json:"accessor_comm"`
	RemoteIP           string    `json:"remote_ip,omitempty"`
	Timestamp          time.Time `json:"timestamp"`
}

// DeceptionEngine orchestrates honeypot decoys, canary validation and high-confidence deception telemetry.
type DeceptionEngine struct {
	mu             sync.RWMutex
	hmacKey        []byte
	canaries       map[string]CanaryToken // normalized path -> token
	canariesByID   map[string]CanaryToken // token ID -> token
	responseEngine *ResponseEngine
	correlator     *IncidentCorrelator
	incidentSink   func(XDRIncident) error
}

func NewDeceptionEngine(
	hmacKey []byte,
	responseEngine *ResponseEngine,
	correlator *IncidentCorrelator,
	incidentSink func(XDRIncident) error,
) (*DeceptionEngine, error) {
	if len(hmacKey) < 16 {
		return nil, NewDeceptionSecurityException("deception master HMAC key too short (min 16 bytes)", nil)
	}
	keyCopy := make([]byte, len(hmacKey))
	copy(keyCopy, hmacKey)

	return &DeceptionEngine{
		hmacKey:        keyCopy,
		canaries:       make(map[string]CanaryToken),
		canariesByID:   make(map[string]CanaryToken),
		responseEngine: responseEngine,
		correlator:     correlator,
		incidentSink:   incidentSink,
	}, nil
}

// JailedPath validates that a target file stays strictly confined within a root jail (Section 1.5.E Compliance).
func (d *DeceptionEngine) JailedPath(rootDir, filename string) (string, error) {
	cleanRoot := filepath.Clean(rootDir)
	cleanFile := filepath.Clean(filename)

	if strings.Contains(cleanFile, "..") {
		return "", NewDeceptionSecurityException("path traversal detected in decoy path", nil)
	}

	destination := filepath.Join(cleanRoot, cleanFile)
	if !strings.HasPrefix(destination, cleanRoot+string(filepath.Separator)) && destination != cleanRoot {
		return "", NewDeceptionSecurityException("decoy escaped designated root jail", nil)
	}
	return destination, nil
}

// SignCanaryPayload generates a constant-time HMAC-SHA256 signature for decoy validation.
func (d *DeceptionEngine) SignCanaryPayload(path string, canaryType CanaryType, createdAt time.Time) string {
	mac := hmac.New(sha256.New, d.hmacKey)
	mac.Write([]byte("VGT-CANARY-TOKEN-V1|"))
	mac.Write([]byte(filepath.Clean(path) + "|"))
	mac.Write([]byte(string(canaryType) + "|"))
	mac.Write([]byte(fmt.Sprintf("%d", createdAt.UnixNano())))
	return hex.EncodeToString(mac.Sum(nil))
}

// RegisterCanary adds a designated decoy path to the active deception grid.
func (d *DeceptionEngine) RegisterCanary(path string, canaryType CanaryType, ownerUID uint32, mode uint32) (*CanaryToken, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	normPath := filepath.Clean(path)
	if strings.TrimSpace(normPath) == "" || normPath == "." || normPath == "/" {
		return nil, NewDeceptionValidationException("invalid empty or root canary path", nil)
	}

	now := time.Now().UTC()
	sig := d.SignCanaryPayload(normPath, canaryType, now)
	tokenID := sig[:24]

	token := CanaryToken{
		ID:               tokenID,
		Path:             normPath,
		Type:             canaryType,
		CreatedAt:        now,
		PayloadSignature: sig,
		OwnerUID:         ownerUID,
		FileMode:         mode,
	}

	d.canaries[normPath] = token
	d.canariesByID[tokenID] = token
	return &token, nil
}

// IsCanaryPath checks if a path is actively monitored by the deception grid.
func (d *DeceptionEngine) IsCanaryPath(path string) bool {
	d.mu.RLock()
	defer d.mu.RUnlock()
	_, found := d.canaries[filepath.Clean(path)]
	return found
}

// DeployCanaryFile deploys a realistic decoy file on disk if it does not exist with 0600 permissions.
func DeployCanaryFile(path string, canaryType CanaryType) error {
	normPath := filepath.Clean(path)
	if strings.TrimSpace(path) == "" || normPath == "." || normPath == "/" || normPath == "\\" || path == "/" || path == "\\" || filepath.Dir(normPath) == normPath {
		return NewDeceptionValidationException("invalid empty or root canary deployment path", nil)
	}

	// If file already exists, leave it untouched
	if _, err := os.Stat(normPath); err == nil {
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return NewDeceptionSecurityException("failed to inspect canary deployment path", err)
	}

	// Ensure parent directory exists
	dir := filepath.Dir(normPath)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return NewDeceptionSecurityException(fmt.Sprintf("failed to create directory for canary %s", normPath), err)
	}

	var content []byte
	switch canaryType {
	case CanaryCloudCred:
		content = []byte("[default]\naws_access_key_id = " + "AKIA_DECOY_CANARY_CREDENTIAL_01" + "\n" +
			"aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n" +
			"region = us-east-1\n" +
			"# Canary decoy credentials managed by VGT Nemesis Deception Grid\n")
	case CanaryShadow:
		content = []byte(`root:$6$vgt$99zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz:19700:0:99999:7:::
daemon:*:19700:0:99999:7:::
bin:*:19700:0:99999:7:::
sys:*:19700:0:99999:7:::
backup-admin:$6$vgt$X8K2j9LmNoPqRsTuVwXyZ0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ01:19700:0:99999:7:::
`)
	case CanarySSHKey:
		header := fmt.Sprintf("-----%s %s-----\n", "BEGIN OPENSSH PRIVATE", "KEY")
		footer := fmt.Sprintf("-----%s %s-----\n", "END OPENSSH PRIVATE", "KEY")
		body := "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\n" +
			"QyNTUxOQAAACD3V1fH8FkE8/3qI0mK7tL2P9vQ0xY1z8dE4kL7a9X6wAAAAJgb/V+mG/1f\n" +
			"pgAAAAtzc2gtZWQyNTUxOQAAACD3V1fH8FkE8/3qI0mK7tL2P9vQ0xY1z8dE4kL7a9X6\n" +
			"wAAAEEBfV3/7z+s3h1K7m6Q4p5d1k8V2n5f9z7b6t0k3vQ1+FvdXV8fwWQTz/eojSYru\n" +
			"0vY/29DTFjXPx0TiQvtr1frAAAAEWNhbmFyeUB2Z3QtZGVjb3kBAgMEBQ==\n"
		content = []byte(header + body + footer)
	case CanaryDotEnv:
		content = []byte(`# Production Environment Secrets
DATABASE_URL="postgres://app_user:VGT_SecretPass_8921x@127.0.0.1:5432/production_db"
JWT_SECRET="vgt_jwt_sec_99482710485720194857201938472910"
STRIPE_API_KEY="vgt_decoy_stripe_token_999888777"
REDIS_PASSWORD="redis_prod_auth_token_884129"
`)
	default:
		content = []byte(fmt.Sprintf("# Decoy canary token (%s)\nTOKEN=vgt_decoy_%s\n", canaryType, strings.ToLower(string(canaryType))))
	}

	tmpPath := normPath + ".tmp"
	if err := os.WriteFile(tmpPath, content, 0o600); err != nil {
		return NewDeceptionSecurityException(fmt.Sprintf("failed to write decoy canary %s", normPath), err)
	}
	if err := os.Rename(tmpPath, normPath); err != nil {
		_ = os.Remove(tmpPath)
		return NewDeceptionSecurityException(fmt.Sprintf("failed to rename decoy canary %s", normPath), err)
	}
	return nil
}

// DeployCanaryFile deploys a realistic decoy file on disk if it does not exist with 0600 permissions.
func (d *DeceptionEngine) DeployCanaryFile(path string, canaryType CanaryType) error {
	return DeployCanaryFile(path, canaryType)
}

// isSystemOrScannerAccessor determines whether an accessor is a system identity or known maintenance scanner.
func isSystemOrScannerAccessor(uid uint32, comm string) bool {
	if uid == 0 {
		return true
	}
	trimmed := strings.TrimSpace(comm)
	if fields := strings.Fields(trimmed); len(fields) > 0 {
		trimmed = fields[0]
	}
	base := strings.ToLower(filepath.Base(trimmed))
	base = strings.TrimSuffix(base, ".exe")
	if base == "updatedb" || base == "find" || strings.Contains(base, "backup") ||
		base == "locate" || base == "plocate" || base == "mlocate" ||
		base == "rsync" || base == "tar" || base == "borg" || base == "restic" {
		return true
	}
	return false
}

// HandleCanaryAccess processes an intercepted canary access, calibrating confidence based on accessor context and mitigating the threat.
func (d *DeceptionEngine) HandleCanaryAccess(
	ctx context.Context,
	event DeceptionAccessEvent,
) (*XDRIncident, *ResponseRecord, error) {
	d.mu.RLock()
	normPath := filepath.Clean(event.CanaryPath)
	token, registered := d.canaries[normPath]
	d.mu.RUnlock()

	if !registered {
		return nil, nil, NewDeceptionValidationException("accessed path is not an enrolled canary token", nil)
	}

	now := event.Timestamp
	if now.IsZero() {
		now = time.Now().UTC()
	}

	actor := fmt.Sprintf("UID:%d|%s", event.AccessorUID, event.AccessorComm)
	incidentID := fmt.Sprintf("INC-NEMESIS-%s-%d", token.ID[:8], now.Unix())

	severity := "CRITICAL"
	confidence := 98
	reason := "CANARY_UNAUTHORIZED_PROBE"
	score := 200

	if isSystemOrScannerAccessor(event.AccessorUID, event.AccessorComm) {
		severity = "HIGH"
		confidence = 85
		reason = "CANARY_SUSPICIOUS_SYSTEM_ACCESS"
		score = 160
	}

	// Construct Attack Story Node
	storyNode := AttackStoryNode{
		NodeID:     fmt.Sprintf("node-nemesis-%s", token.ID[:12]),
		Timestamp:  now,
		Sensor:     "DECEPTION_GHOST_TRAP",
		Category:   "CREDENTIAL_ACCESS",
		EventType:  "CANARY_HIT",
		EntityID:   normPath,
		Actor:      actor,
		Severity:   severity,
		Confidence: confidence,
		CausalEdge: EdgeCanaryTriggered,
		EventUUID:  incidentID,
		Metadata: map[string]string{
			"canary_type":    string(token.Type),
			"accessor_pid":   strconv.Itoa(event.AccessorPID),
			"accessor_comm":  event.AccessorComm,
			"target_path":    normPath,
			"trigger_reason": reason,
			"confidence":     strconv.Itoa(confidence),
		},
	}

	// Correlate into TRINITY DAG
	var evidenceRoot string
	var storyNodes []AttackStoryNode
	if d.correlator != nil {
		graph, _, err := d.correlator.IngestEvent(now, actor, "HONEYTOKEN", "DECEPTION", storyNode)
		if err == nil && graph != nil {
			evidenceRoot = graph.EvidenceRoot()
			storyNodes = graph.CloneNodes()
		}
	}
	if len(storyNodes) == 0 {
		storyNodes = []AttackStoryNode{storyNode}
		evidenceRoot = storyNode.ComputeNodeDigest()
	}

	incident := XDRIncident{
		ID:               incidentID,
		Time:             now,
		Severity:         severity,
		Score:            score,
		ResponseScore:    score,
		KillSignals:      1,
		PID:              event.AccessorPID,
		UID:              event.AccessorUID,
		Process:          event.AccessorComm,
		CommandPreview:   fmt.Sprintf("[CANARY ACCESS] %s accessed decoy %s (%s)", event.AccessorComm, normPath, reason),
		RuleIDs:          []string{"KD.LINUX.CANARY_ACCESS", fmt.Sprintf("NEMESIS.%s", token.Type)},
		Categories:       []string{"credential", "deception"},
		Summary:          fmt.Sprintf("Honeypot token triggered: %s access to %s by PID %d (%s) [%s]", strings.ToLower(severity), normPath, event.AccessorPID, event.AccessorComm, reason),
		Decision:         "CONTAIN",
		Action:           "FREEZE_EXECUTION",
		Outcome:          "SUSPENDED",
		Acknowledged:     false,
		ExecutionChainID: storyNode.NodeID,
		AttackStory:      storyNodes,
		EvidenceRoot:     evidenceRoot,
	}

	// Notify sink
	if d.incidentSink != nil {
		_ = d.incidentSink(incident)
	}

	// Immediate Reversible Response: Freeze offending process via ResponseEngine
	var responseRec *ResponseRecord
	if d.responseEngine != nil && event.AccessorPID > 0 {
		targetID := strconv.Itoa(event.AccessorPID)
		if event.AccessorStartTicks > 0 {
			targetID = fmt.Sprintf("%d:%d", event.AccessorPID, event.AccessorStartTicks)
		}
		rec, err := d.responseEngine.ApplyResponse(
			ctx,
			now,
			incidentID,
			ActionFreezeExecution,
			"PID",
			targetID,
			confidence,
			reason,
			evidenceRoot,
		)
		if err == nil {
			responseRec = rec
		}
	}

	// Optional IP containment if remote IP was captured
	if d.responseEngine != nil && event.RemoteIP != "" {
		_, _ = d.responseEngine.ApplyResponse(
			ctx,
			now,
			incidentID,
			ActionContainIP,
			"IP",
			event.RemoteIP,
			confidence,
			reason,
			evidenceRoot,
		)
	}

	return &incident, responseRec, nil
}
