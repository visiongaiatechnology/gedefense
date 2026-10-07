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
	"sort"
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
// deceptionPolicy is the administrable response posture of the canary grid.
type deceptionPolicy struct {
	enabled             bool
	containment         string
	correlateRemoteIP   bool
	unauthorizedScore   int
	systemAccessorScore int
}

type DeceptionEngine struct {
	mu             sync.RWMutex
	hmacKey        []byte
	canaries       map[string]CanaryToken // normalized path -> token
	canariesByID   map[string]CanaryToken // token ID -> token
	responseEngine *ResponseEngine
	correlator     *IncidentCorrelator
	incidentSink   func(XDRIncident) error
	policy         deceptionPolicy
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
		policy: deceptionPolicy{
			enabled: true, containment: deceptionContainmentContainAndBlock, correlateRemoteIP: true,
			unauthorizedScore: 200, systemAccessorScore: 160,
		},
	}, nil
}

// policySnapshot returns a consistent copy of the administrable response posture.
func (d *DeceptionEngine) policySnapshot() deceptionPolicy {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.policy
}

// CanaryInventory is the operator-facing view of the enrolled decoy grid.
type CanaryInventory struct {
	Path      string `json:"path"`
	Type      string `json:"type"`
	TokenID   string `json:"token_id"`
	CreatedAt string `json:"created_at"`
	OwnerUID  uint32 `json:"owner_uid"`
	FileMode  uint32 `json:"file_mode"`
}

// ListCanaries returns the enrolled canaries in deterministic path order.
func (d *DeceptionEngine) ListCanaries() []CanaryInventory {
	if d == nil {
		return nil
	}
	d.mu.RLock()
	out := make([]CanaryInventory, 0, len(d.canaries))
	for _, token := range d.canaries {
		out = append(out, CanaryInventory{
			Path: token.Path, Type: string(token.Type), TokenID: token.ID,
			CreatedAt: token.CreatedAt.UTC().Format(time.RFC3339), OwnerUID: token.OwnerUID, FileMode: token.FileMode,
		})
	}
	d.mu.RUnlock()
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out
}

// UnregisterCanary removes one decoy from the active grid. The decoy file on
// disk is deliberately left in place: removing it would destroy forensic
// evidence that a canary was ever deployed.
func (d *DeceptionEngine) UnregisterCanary(path string) error {
	if d == nil {
		return nil
	}
	normPath := filepath.Clean(path)
	d.mu.Lock()
	defer d.mu.Unlock()
	token, exists := d.canaries[normPath]
	if !exists {
		return os.ErrNotExist
	}
	delete(d.canaries, normPath)
	delete(d.canariesByID, token.ID)
	return nil
}

// ApplyPolicy reconciles the enrolled grid with an administrable revision and
// publishes the response posture. A canary whose type, owner or mode changed is
// re-enrolled so its signed token matches the new definition.
func (d *DeceptionEngine) ApplyPolicy(settings DeceptionFabricSettings) (int, int, error) {
	if d == nil {
		return 0, 0, nil
	}
	desired := make(map[string]CanarySettings, len(settings.Canaries))
	for _, canary := range settings.Canaries {
		if !canary.Enabled {
			continue
		}
		desired[filepath.Clean(canary.Path)] = canary
	}

	type reEnroll struct{ need bool }
	actions := make(map[string]reEnroll, len(desired))
	d.mu.RLock()
	for path := range desired {
		token, exists := d.canaries[path]
		canary := desired[path]
		actions[path] = reEnroll{need: !exists || string(token.Type) != canary.Type || token.OwnerUID != canary.OwnerUID || token.FileMode != canary.FileMode}
	}
	removed := make([]string, 0, len(d.canaries))
	for path := range d.canaries {
		if _, keep := desired[path]; !keep {
			removed = append(removed, path)
		}
	}
	d.mu.RUnlock()

	registered := 0
	for path, action := range actions {
		if !action.need {
			continue
		}
		if err := d.UnregisterCanary(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return registered, 0, err
		}
		canary := desired[path]
		if _, err := d.RegisterCanary(path, CanaryType(canary.Type), canary.OwnerUID, canary.FileMode); err != nil {
			return registered, 0, err
		}
		if err := DeployCanaryFile(path, CanaryType(canary.Type)); err != nil {
			return registered, 0, err
		}
		registered++
	}
	for _, path := range removed {
		if err := d.UnregisterCanary(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return registered, 0, err
		}
	}

	d.mu.Lock()
	d.policy = deceptionPolicy{
		enabled: settings.Enabled, containment: settings.ContainmentLevel,
		correlateRemoteIP: settings.CorrelateRemoteIP,
		unauthorizedScore: settings.UnauthorizedScore, systemAccessorScore: settings.SystemAccessorScore,
	}
	d.mu.Unlock()
	return registered, len(removed), nil
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
	dir := filepath.Dir(normPath)
	// Validate every ancestor even when the decoy already exists.
	if err := ensureCanaryDirectory(dir); err != nil {
		return NewDeceptionSecurityException("failed to prepare canary directory", err)
	}

	// Lstat, not Stat: the deployment path must never be followed through a
	// symbolic link. A decoy whose path is a link would otherwise let the write
	// land wherever the link points, which turns a decoy deployment into an
	// arbitrary file write with the service identity.
	if info, err := os.Lstat(normPath); err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return NewDeceptionSecurityException("canary deployment path is a symbolic link", nil)
		}
		if !info.Mode().IsRegular() {
			return NewDeceptionSecurityException("canary deployment path is not a regular file", nil)
		}
		// A present decoy is left exactly as it is.
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return NewDeceptionSecurityException("failed to inspect canary deployment path", err)
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

	// O_CREATE|O_EXCL refuses an existing path and a symbolic link in one step, so
	// the write cannot be redirected between the check above and this call. The
	// staging file is then flushed to stable storage before the atomic replace, so
	// a crash leaves either the previous state or the complete decoy and never a
	// truncated file that a later baseline would record as authentic.
	// Every component of the path is resolved relative to an already-open
	// descriptor, so neither the staging file nor the final rename can be
	// redirected through a symlinked parent directory.
	if err := deployCanaryBeneath(filepath.Dir(normPath), filepath.Base(normPath), content); err != nil {
		return err
	}
	return nil
}

// deployCanaryBeneath writes the decoy and replaces the target inside one
// directory jail.
func deployCanaryBeneath(dir, base string, content []byte) error {
	staging := base + ".tmp"
	file, err := openBeneath(dir, staging, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			if info, inspectErr := os.Lstat(filepath.Join(dir, staging)); inspectErr != nil || !info.Mode().IsRegular() {
				return NewDeceptionSecurityException("canary staging file is not a regular file", inspectErr)
			}
			// A stale staging file is cleared through the same jail and retried once.
			if removeErr := removeBeneath(dir, staging); removeErr != nil {
				return NewDeceptionSecurityException("failed to clear stale canary staging file", removeErr)
			}
			file, err = openBeneath(dir, staging, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		}
		if err != nil {
			return NewDeceptionSecurityException("failed to open decoy canary staging file", err)
		}
	}
	if _, err := file.Write(content); err != nil {
		_ = file.Close()
		_ = removeBeneath(dir, staging)
		return NewDeceptionSecurityException("failed to write decoy canary", err)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		_ = removeBeneath(dir, staging)
		return NewDeceptionSecurityException("failed to flush decoy canary", err)
	}
	if err := file.Close(); err != nil {
		_ = removeBeneath(dir, staging)
		return NewDeceptionSecurityException("failed to close decoy canary", err)
	}
	// The staging file becomes the decoy through a rename inside the same jail, so
	// the decoy is never observable as a partial file.
	if err := renameBeneath(dir, staging, base); err != nil {
		_ = removeBeneath(dir, staging)
		return NewDeceptionSecurityException(fmt.Sprintf("failed to rename decoy canary %s", base), err)
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

	policy := d.policySnapshot()
	if !policy.enabled {
		return nil, nil, NewDeceptionValidationException("deception grid is disabled by policy", nil)
	}

	severity := "CRITICAL"
	confidence := 98
	reason := "CANARY_UNAUTHORIZED_PROBE"
	score := policy.unauthorizedScore

	if isSystemOrScannerAccessor(event.AccessorUID, event.AccessorComm) {
		severity = "HIGH"
		confidence = 85
		reason = "CANARY_SUSPICIOUS_SYSTEM_ACCESS"
		score = policy.systemAccessorScore
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

	// Immediate Reversible Response: freeze the offending process through the
	// ResponseEngine. The administrable containment level decides whether any
	// response is applied at all, and whether a captured remote IP is contained
	// alongside the process.
	var responseRec *ResponseRecord
	responsePolicy := d.policySnapshot()
	if responsePolicy.containment != deceptionContainmentObserve && d.responseEngine != nil && event.AccessorPID > 0 {
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

	// Optional IP containment if a remote IP was captured and policy allows it.
	if responsePolicy.containment == deceptionContainmentContainAndBlock && responsePolicy.correlateRemoteIP && d.responseEngine != nil && event.RemoteIP != "" {
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
