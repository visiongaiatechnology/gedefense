// STATUS: DIAMANT VGT SUPREME
// SPDX-FileCopyrightText: 2026 VisionGaia Technology
// SPDX-License-Identifier: AGPL-3.0-only

package main

// Real host integrations for Titan: the existing quarantine transaction
// applier, the XDR incident time context and the FIM baseline. None of these
// adapters invents evidence; each one only forwards what the platform already
// owns.

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

// titanStateContext exposes only the time of recent XDR incidents. It is used as
// a temporal risk input, never as actor attribution.
type titanStateContext struct {
	state *State
}

func newTitanStateContext(state *State) titanContextProvider {
	if state == nil {
		return nil
	}
	return &titanStateContext{state: state}
}

func (c *titanStateContext) RecentIncidents(ctx context.Context, since time.Time) (int, error) {
	if c == nil || c.state == nil {
		return 0, nil
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	incidents := c.state.Snapshot().Incidents
	count := 0
	for _, incident := range incidents {
		if incident.Time.After(since) {
			count++
		}
	}
	return count, nil
}

// titanTransactionContainment drives the existing QuarantineTransactionApplier
// through the transaction engine: Preview inspects and pins the object identity,
// Apply moves it through the privileged core, and Verify runs inside Apply.
// Titan never deletes anything.
type titanTransactionContainment struct {
	engine *TransactionEngine
}

func newTitanTransactionContainment(engine *TransactionEngine) titanContainment {
	if engine == nil {
		return nil
	}
	return &titanTransactionContainment{engine: engine}
}

func (c *titanTransactionContainment) RequestContain(ctx context.Context, path, reason string) (titanContainmentResult, error) {
	if c == nil || c.engine == nil {
		return titanContainmentResult{}, errors.New("privileged quarantine core is unavailable")
	}
	if err := ctx.Err(); err != nil {
		return titanContainmentResult{}, err
	}
	payload, err := json.Marshal(quarantineRequest{Path: path})
	if err != nil {
		return titanContainmentResult{}, err
	}
	transactionReason := strings.TrimSpace(reason)
	if len(transactionReason) > 240 {
		transactionReason = transactionReason[:240]
	}
	if len(transactionReason) < 3 {
		transactionReason = "Titan containment of an unapproved ingress change"
	}
	transaction, err := c.engine.Preview(
		quarantineTransactionType,
		"Titan containment of an unapproved ingress file",
		transactionReason,
		payload,
	)
	if err != nil {
		return titanContainmentResult{}, err
	}
	applied, err := c.engine.Apply(transaction.ID, "APPLY "+transaction.ID)
	if err != nil {
		return titanContainmentResult{TransactionID: transaction.ID}, err
	}
	result := titanContainmentResult{TransactionID: applied.ID}
	planRaw := applied.Plan
	if len(planRaw) == 0 {
		planRaw = transaction.Plan
	}
	if len(planRaw) > 0 {
		var plan quarantinePlan
		if decodeErr := json.Unmarshal(planRaw, &plan); decodeErr == nil {
			result.ObjectID = plan.ObjectID
			result.SHA256 = plan.Identity.SHA256
		}
	}
	return result, nil
}

func (c *titanTransactionContainment) Items() []titanQuarantineItem {
	if c == nil || c.engine == nil {
		return nil
	}
	status := c.engine.QuarantineStatus()
	items := make([]titanQuarantineItem, 0, len(status.Items))
	for _, item := range status.Items {
		items = append(items, titanQuarantineItem{
			ID:           item.TransactionID,
			Path:         item.Path,
			SampleSHA256: item.SHA256,
			CreatedUTC:   item.CreatedAt,
			State:        strings.ToUpper(item.Status),
		})
	}
	return items
}
