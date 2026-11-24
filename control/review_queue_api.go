package main

import (
	"errors"
	"path/filepath"
	"strings"
	"time"
)

// reviewQueueBinding derives the queue store configuration from the engine.
func (e *XDREngine) reviewQueueBinding() reviewQueueBinding {
	binding := reviewQueueBinding{TTL: reviewQueueDefaultTTL, MaxEntries: reviewQueueDefaultMaxEntries, MaxBytes: reviewQueueDefaultMaxBytes, DiskReserve: reviewQueueDiskReserveBytes}
	if e == nil {
		return binding
	}
	storageDir := filepath.Dir(strings.TrimSpace(e.cfg.XDR.IncidentLog))
	if storageDir == "." || storageDir == "" {
		storageDir = "/var/lib/vgt/gedefense"
	}
	binding.StorageDir = storageDir
	storageKeyPath := firstNonEmptyPath(e.cfg.XDR.StorageKeyFile, e.cfg.Runtime.StorageKeyFile, e.cfg.Policy.StorageKeyFile)
	if storageKeyPath != "" {
		if cipher, err := NewStorageCipher(storageKeyPath, e.cfg.Node.Name); err == nil && cipher != nil {
			binding.Cipher = cipher
		}
	}
	return binding
}

func (e *XDREngine) reviewQueueCauseSet() bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	_, ok := e.degradeCauses["review_queue"]
	return ok
}

func (e *XDREngine) noteReviewQueueDegraded(reason string) {
	if e == nil {
		return
	}
	firstTransition := !e.reviewQueueCauseSet()
	e.markDegradedCause("review_queue", reason)
	if firstTransition && e.state != nil {
		e.state.AddEvent(Event{
			Severity: "warning", Kind: "xdr.review_queue_degraded", Source: "review-queue",
			Message: "Persistent review queue degraded: " + boundedPermitText(reason, 320),
		})
	}
}

func (e *XDREngine) clearReviewQueueDegraded() {
	if e == nil || !e.reviewQueueCauseSet() {
		return
	}
	e.clearDegradedCause("review_queue")
	if e.state != nil {
		e.state.AddEvent(Event{
			Severity: "info", Kind: "xdr.review_queue_recovered", Source: "review-queue",
			Message: "Persistent review queue store verified",
		})
	}
}

// reviewQueueEnsureBound binds the queue lazily, throttling failed retries so a
// corrupt store cannot cause a disk read per incident.
func (e *XDREngine) reviewQueueEnsureBound() bool {
	if e == nil || e.reviewQueue == nil {
		return false
	}
	if e.reviewQueue.ready() {
		return true
	}
	e.reviewQueue.mu.Lock()
	retryAt := e.reviewQueue.lastBindAttempt.Add(permitMaintenanceInterval)
	if !e.reviewQueue.lastBindAttempt.IsZero() && time.Now().UTC().Before(retryAt) {
		e.reviewQueue.mu.Unlock()
		return e.reviewQueue.ready()
	}
	e.reviewQueue.mu.Unlock()
	if err := e.reviewQueue.bindReviewQueue(e.reviewQueueBinding()); err != nil {
		e.noteReviewQueueDegraded(err.Error())
		return false
	}
	e.clearReviewQueueDegraded()
	return true
}

// enqueueReviewFinding is the additive appendIncident integration: incidents
// that reach the incident stream (AUTHORIZED-suppressed findings never do) are
// offered to the persistent review queue. Storage failures degrade the queue,
// they never fail the XDR path.
func (e *XDREngine) enqueueReviewFinding(incident XDRIncident) {
	if e == nil || e.reviewQueue == nil {
		return
	}
	if !e.reviewQueueEnsureBound() {
		return
	}
	if _, err := e.reviewQueue.EnqueueIncident(incident); err != nil {
		e.noteReviewQueueDegraded(err.Error())
	}
}

// maintainReviewQueue expires TTLs, flushes dirty state and returns the next
// maintenance deadline. It is driven from pollPermits on the bounded cadence.
func (e *XDREngine) maintainReviewQueue(now time.Time) time.Time {
	if e == nil || e.reviewQueue == nil {
		return now.Add(reviewQueueFlushInterval)
	}
	if !e.reviewQueueEnsureBound() {
		return now.Add(reviewQueueFlushInterval)
	}
	if _, flushed, err := e.reviewQueue.maintain(now); err != nil {
		e.noteReviewQueueDegraded(err.Error())
	} else if flushed {
		e.clearReviewQueueDegraded()
	}
	return e.reviewQueue.nextFlushDue(now)
}

// reviewQueueDue returns the next maintenance time for the review queue.
func (e *XDREngine) reviewQueueDue(now time.Time) time.Time {
	if e == nil || e.reviewQueue == nil {
		return now.Add(reviewQueueFlushInterval)
	}
	return e.reviewQueue.nextFlushDue(now)
}

// ReviewQueueReport returns the bounded queue projection for the API.
func (e *XDREngine) ReviewQueueReport(limit int) (ReviewQueueReport, []ReviewEntry, bool) {
	if e == nil || e.reviewQueue == nil {
		return ReviewQueueReport{MaxEntries: reviewQueueDefaultMaxEntries, MaxBytes: reviewQueueDefaultMaxBytes}, nil, false
	}
	if !e.reviewQueueEnsureBound() {
		return e.reviewQueue.Report(), nil, false
	}
	return e.reviewQueue.Report(), e.reviewQueue.Entries(limit), true
}

// AcknowledgeReviewEntry / DeleteReviewEntry are the operator API helpers.
func (e *XDREngine) AcknowledgeReviewEntry(id string) (bool, error) {
	if e == nil || e.reviewQueue == nil {
		return false, errors.New("review queue unavailable")
	}
	if !e.reviewQueueEnsureBound() {
		return false, errors.New("review queue unavailable")
	}
	return e.reviewQueue.Acknowledge(id)
}

func (e *XDREngine) DeleteReviewEntry(id string) (bool, error) {
	if e == nil || e.reviewQueue == nil {
		return false, errors.New("review queue unavailable")
	}
	if !e.reviewQueueEnsureBound() {
		return false, errors.New("review queue unavailable")
	}
	return e.reviewQueue.Delete(id)
}
