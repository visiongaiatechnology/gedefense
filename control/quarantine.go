// STATUS: DIAMANT VGT SUPREME
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	quarantineTransactionType = "response.quarantine-file"
	quarantineSchema          = "vgt-gedefense-quarantine-v1"
)

type QuarantineCore interface {
	QuarantineInspect(path string) (QuarantineIdentity, error)
	QuarantineApply(path, objectID string, identity QuarantineIdentity) error
	QuarantineVerify(objectID string, identity QuarantineIdentity) error
	QuarantineRestore(path, objectID string, identity QuarantineIdentity) error
}

type QuarantineTransactionApplier struct {
	mu     sync.Mutex
	core   QuarantineCore
	policy quarantinePolicy
}

type quarantineRequest struct {
	Path string `json:"path"`
}

type quarantinePlan struct {
	Schema   string             `json:"schema"`
	Path     string             `json:"path"`
	ObjectID string             `json:"object_id"`
	Identity QuarantineIdentity `json:"identity"`
}

type quarantineAfter struct {
	Schema   string             `json:"schema"`
	ObjectID string             `json:"object_id"`
	Identity QuarantineIdentity `json:"identity"`
}

type QuarantineItem struct {
	TransactionID string             `json:"transaction_id"`
	ObjectID      string             `json:"object_id"`
	Path          string             `json:"path"`
	Status        string             `json:"status"`
	Size          uint64             `json:"size"`
	SHA256        string             `json:"sha256"`
	Reason        string             `json:"reason"`
	CreatedAt     time.Time          `json:"created_at"`
	AppliedAt     *time.Time         `json:"applied_at,omitempty"`
	Identity      QuarantineIdentity `json:"identity"`
}

type QuarantineStatus struct {
	Healthy bool             `json:"healthy"`
	Count   int              `json:"count"`
	Items   []QuarantineItem `json:"items"`
}

func NewQuarantineTransactionApplier(core QuarantineCore) *QuarantineTransactionApplier {
	return &QuarantineTransactionApplier{core: core}
}

func (a *QuarantineTransactionApplier) Type() string {
	return quarantineTransactionType
}

func (a *QuarantineTransactionApplier) ExclusiveTransactionType() bool {
	return false
}

func (a *QuarantineTransactionApplier) Preview(
	payload json.RawMessage,
) (json.RawMessage, json.RawMessage, error) {
	if a.core == nil {
		return nil, nil, errors.New("privileged quarantine core is unavailable")
	}
	request, err := decodeQuarantineRequest(payload, a.policySnapshot())
	if err != nil {
		return nil, nil, err
	}
	identity, err := a.core.QuarantineInspect(request.Path)
	if err != nil {
		return nil, nil, err
	}
	objectID := "QV-" + randomID()
	if !validQuarantineObjectID(objectID) {
		return nil, nil, errors.New("secure quarantine object ID generation failed")
	}
	plan := quarantinePlan{
		Schema: quarantineSchema, Path: request.Path,
		ObjectID: objectID, Identity: identity,
	}
	encoded, err := json.Marshal(plan)
	if err != nil {
		return nil, nil, err
	}
	return encoded, append(json.RawMessage(nil), encoded...), nil
}

func (a *QuarantineTransactionApplier) Apply(
	planRaw json.RawMessage,
	beforeRaw json.RawMessage,
) (json.RawMessage, error) {
	plan, err := decodeQuarantinePlan(planRaw, a.policySnapshot())
	if err != nil {
		return nil, err
	}
	before, err := decodeQuarantinePlan(beforeRaw, a.policySnapshot())
	if err != nil || plan != before {
		return nil, errors.New("quarantine pre-state does not match the authorized plan")
	}
	if err := a.core.QuarantineApply(plan.Path, plan.ObjectID, plan.Identity); err != nil {
		return nil, err
	}
	return json.Marshal(quarantineAfter{
		Schema: quarantineSchema, ObjectID: plan.ObjectID, Identity: plan.Identity,
	})
}

func (a *QuarantineTransactionApplier) Verify(
	planRaw json.RawMessage,
	afterRaw json.RawMessage,
) error {
	plan, err := decodeQuarantinePlan(planRaw, a.policySnapshot())
	if err != nil {
		return err
	}
	after, err := decodeQuarantineAfter(afterRaw)
	if err != nil || after.ObjectID != plan.ObjectID || after.Identity != plan.Identity {
		return errors.New("quarantine post-state does not match the authorized plan")
	}
	return a.core.QuarantineVerify(plan.ObjectID, plan.Identity)
}

func (a *QuarantineTransactionApplier) Reverse(
	beforeRaw json.RawMessage,
	afterRaw json.RawMessage,
) error {
	before, err := decodeQuarantinePlan(beforeRaw, a.policySnapshot())
	if err != nil {
		return err
	}
	if len(bytes.TrimSpace(afterRaw)) > 0 {
		after, err := decodeQuarantineAfter(afterRaw)
		if err != nil || after.ObjectID != before.ObjectID || after.Identity != before.Identity {
			return errors.New("quarantine reverse-state does not match the captured object")
		}
	}
	return a.core.QuarantineRestore(before.Path, before.ObjectID, before.Identity)
}

func decodeQuarantineRequest(raw json.RawMessage, policy quarantinePolicy) (quarantineRequest, error) {
	var request quarantineRequest
	if err := decodeQuarantineJSON(raw, &request); err != nil {
		return quarantineRequest{}, errors.New("invalid quarantine request")
	}
	if err := validateQuarantinePath(request.Path, policy); err != nil {
		return quarantineRequest{}, errors.New("quarantine path is outside the permitted boundary")
	}
	return request, nil
}

// validateQuarantinePath applies the structural rules and the published path
// policy. The structural rules are immutable; the policy can only add
// restrictions, because the built-in denylist is appended at evaluation time and
// is never removed by configuration.
func validateQuarantinePath(path string, policy quarantinePolicy) error {
	clean := filepath.Clean(path)
	if path == "" || len(path) > 2048 || !filepath.IsAbs(path) ||
		clean != path || strings.ContainsRune(path, '\x00') ||
		policy.pathForbidden(clean) || policy.pathOutsideAllowedRoots(clean) {
		return errors.New("quarantine path is invalid")
	}
	return nil
}

// quarantinePathForbidden keeps the compiled-in rule set available for callers
// that have no published policy.
func quarantinePathForbidden(path string) bool {
	return quarantinePolicy{}.pathForbidden(path)
}

// validateQuarantinePathBuiltin applies only the immutable rules. The malware
// scan paths use it: they must never inherit an operator relaxation, and the
// built-in boundary is what protects the host and the control plane itself.
func validateQuarantinePathBuiltin(path string) error {
	return validateQuarantinePath(path, quarantinePolicy{})
}

func decodeQuarantinePlan(raw json.RawMessage, policy quarantinePolicy) (quarantinePlan, error) {
	var plan quarantinePlan
	if err := decodeQuarantineJSON(raw, &plan); err != nil ||
		plan.Schema != quarantineSchema || !validQuarantineObjectID(plan.ObjectID) {
		return quarantinePlan{}, errors.New("quarantine transaction plan is malformed")
	}
	if err := validateQuarantinePath(plan.Path, policy); err != nil {
		return quarantinePlan{}, errors.New("quarantine transaction path is invalid")
	}
	if err := validateQuarantineIdentity(plan.Identity); err != nil {
		return quarantinePlan{}, err
	}
	return plan, nil
}

func decodeQuarantineAfter(raw json.RawMessage) (quarantineAfter, error) {
	var after quarantineAfter
	if err := decodeQuarantineJSON(raw, &after); err != nil ||
		after.Schema != quarantineSchema || !validQuarantineObjectID(after.ObjectID) {
		return quarantineAfter{}, errors.New("quarantine transaction result is malformed")
	}
	if err := validateQuarantineIdentity(after.Identity); err != nil {
		return quarantineAfter{}, err
	}
	return after, nil
}

func decodeQuarantineJSON(raw json.RawMessage, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("quarantine document contains trailing data")
	}
	return nil
}

func (e *TransactionEngine) QuarantineStatus() QuarantineStatus {
	records := e.recordsByType(quarantineTransactionType)
	items := make([]QuarantineItem, 0, len(records))
	healthy := true
	for index := len(records) - 1; index >= 0; index-- {
		record := records[index]
		if record.Status == "reversed" || record.Status == "failed" {
			continue
		}
		plan, err := decodeQuarantinePlan(record.Plan, quarantinePolicy{})
		if err != nil {
			healthy = false
			continue
		}
		if record.Status == "recovery_required" {
			healthy = false
		}
		items = append(items, QuarantineItem{
			TransactionID: record.ID, ObjectID: plan.ObjectID, Path: plan.Path,
			Status: record.Status, Size: plan.Identity.Size, SHA256: plan.Identity.SHA256,
			Reason: record.Reason, CreatedAt: record.CreatedAt, AppliedAt: record.AppliedAt,
			Identity: plan.Identity,
		})
	}
	return QuarantineStatus{Healthy: healthy, Count: len(items), Items: items}
}
