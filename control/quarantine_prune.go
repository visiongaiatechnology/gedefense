// STATUS: DIAMANT VGT SUPREME
package main

// V6.3.0 AP-7: evidence-first QUARANTINE_PRUNE orchestration.
//
// The operator action removes a verified false-positive object from the
// encrypted vault. It is deliberately narrow:
//   - the request must carry the full captured identity (never a bare object id)
//     and a `confirm` field equal to the object id;
//   - a first evidence record with the object id, hash and identity is committed
//     BEFORE the privileged core is contacted. If that commit fails, the prune is
//     refused and the vault is never touched;
//   - only after a successful core prune is a second confirmation evidence
//     record/event written, so the audit chain always shows intent -> outcome.
//
// The Go side never resolves a host path: the core owns vault access and only
// deletes the derived `<object_dir>/<object_id>.qv` file.

import (
	"errors"
	"fmt"
	"time"
)

// quarantinePruneCore is the narrow privileged capability the pruner needs. It
// is satisfied by *CoreClient; tests use a fake implementation.
type quarantinePruneCore interface {
	QuarantinePrune(objectID string, identity QuarantineIdentity) (string, error)
}

// quarantinePruneEvidence is the mandatory evidence sink. It is satisfied by
// *State; tests can fake a failing sink to prove the evidence-first refusal.
type quarantinePruneEvidence interface {
	RecordEvidence(record EvidenceRecord) error
}

// Sentinel errors let the HTTP layer map the refusal precisely without parsing
// free-form text.
var (
	errQuarantinePruneCore        = errors.New("privileged quarantine core unavailable")
	errQuarantinePruneEvidence    = errors.New("mandatory evidence commit failed")
	errQuarantinePruneRejected    = errors.New("quarantine prune rejected")
	errQuarantinePruneConfirmOnly = errors.New("quarantine pruned but confirmation evidence failed")
)

// QuarantinePruneResult is the bounded API result of a successful prune.
type QuarantinePruneResult struct {
	ObjectID string    `json:"object_id"`
	State    string    `json:"state"`
	PrunedAt time.Time `json:"pruned_at"`
	SHA256   string    `json:"sha256"`
	Size     uint64    `json:"size"`
}

// quarantinePruner performs the evidence-first prune flow.
type quarantinePruner struct {
	core      quarantinePruneCore
	evidence  quarantinePruneEvidence
	events    func(Event)
	now       func() time.Time
	requestID string
}

// newQuarantinePruner wires the flow to the real state and the privileged core.
func newQuarantinePruner(core quarantinePruneCore, evidence quarantinePruneEvidence, events func(Event)) *quarantinePruner {
	return &quarantinePruner{
		core: core, evidence: evidence, events: events,
		now: func() time.Time { return time.Now().UTC() },
	}
}

// pruneEvidenceMessage renders the bounded identity summary used by the two
// evidence records. No host path and no secret is included.
func pruneEvidenceMessage(identity QuarantineIdentity) string {
	return fmt.Sprintf(
		"vault object identity sha256=%s size=%d device=%d inode=%d uid=%d gid=%d mode=%#o",
		identity.SHA256, identity.Size, identity.Device, identity.Inode, identity.UID, identity.GID, identity.Mode,
	)
}

// Prune enforces evidence-first ordering and validates every input before the
// privileged core is asked to act.
func (p *quarantinePruner) Prune(objectID string, identity *QuarantineIdentity, confirm string) (QuarantinePruneResult, error) {
	result := QuarantinePruneResult{}
	if p == nil || p.core == nil {
		return result, fmt.Errorf("%w: trusted quarantine core is not wired", errQuarantinePruneCore)
	}
	if !validQuarantineObjectID(objectID) {
		return result, errors.New("quarantine object ID is invalid")
	}
	// Never prune without an identity.
	if identity == nil {
		return result, errors.New("quarantine prune requires the full captured identity")
	}
	if err := validateQuarantineIdentity(*identity); err != nil {
		return result, errors.New("quarantine identity is invalid")
	}
	if confirm != objectID {
		return result, errors.New("quarantine prune confirmation does not match the object ID")
	}
	if p.evidence == nil {
		return result, fmt.Errorf("%w; quarantine prune refused", errQuarantinePruneEvidence)
	}
	now := p.now()
	// EVIDENCE-FIRST: the intent record must be durable before the vault object
	// may be removed.
	if err := p.evidence.RecordEvidence(EvidenceRecord{
		Time: now, Severity: "high", Kind: "quarantine.prune.intent", Source: "operator",
		Message:   "Quarantine vault prune intent committed for a verified false-positive object",
		Target:    objectID,
		RequestID: p.requestID,
	}); err != nil {
		return result, fmt.Errorf("%w; quarantine prune refused: %v", errQuarantinePruneEvidence, err)
	}
	state, err := p.core.QuarantinePrune(objectID, *identity)
	if err != nil {
		// Best-effort failure record: a failed evidence write here must not hide
		// the core refusal, which is the primary result.
		_ = p.evidence.RecordEvidence(EvidenceRecord{
			Time: p.now(), Severity: "high", Kind: "quarantine.prune.failed", Source: "operator",
			Message: "Quarantine vault prune was refused by the privileged core; the vault object was preserved",
			Target:  objectID, RequestID: p.requestID,
		})
		return result, fmt.Errorf("%w: %v", errQuarantinePruneRejected, err)
	}
	if state != "pruned" {
		return result, fmt.Errorf("%w: unknown core prune state", errQuarantinePruneRejected)
	}
	result = QuarantinePruneResult{
		ObjectID: objectID, State: "pruned", PrunedAt: p.now(),
		SHA256: identity.SHA256, Size: identity.Size,
	}
	// Confirmation evidence is mandatory for the audit chain. The object is
	// already gone at this point; if the confirmation cannot be committed the
	// caller is told that the audit trail is incomplete instead of being lied to.
	if err := p.evidence.RecordEvidence(EvidenceRecord{
		Time: result.PrunedAt, Severity: "high", Kind: "quarantine.prune.confirmed", Source: "operator",
		Message: "Quarantine vault object pruned after identity re-verification: " + pruneEvidenceMessage(*identity),
		Target:  objectID, RequestID: p.requestID,
	}); err != nil {
		if p.events != nil {
			p.events(Event{
				Severity: "warning", Kind: "quarantine.prune_evidence_incomplete", Source: "operator",
				Message: "Quarantine vault object was pruned but the confirmation evidence could not be committed",
				Target:  objectID,
			})
		}
		return result, fmt.Errorf("%w: %v", errQuarantinePruneConfirmOnly, err)
	}
	if p.events != nil {
		p.events(Event{
			Severity: "info", Kind: "quarantine.pruned", Source: "operator",
			Message: "Verified false-positive object pruned from the encrypted quarantine vault",
			Target:  objectID,
		})
	}
	return result, nil
}
