// STATUS: DIAMANT VGT SUPREME
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
)

const (
	cellTransactionType   = "isolation.gaia-cell"
	cellTransactionSchema = "vgt-gedefense-cell-transaction-v1"
)

type cellIsolationRequest struct {
	UUID       string `json:"uuid"`
	Generation uint64 `json:"generation"`
	CgroupID   uint64 `json:"cgroup_id"`
	Action     string `json:"action"`
}

type cellIsolationPlan struct {
	Schema string   `json:"schema"`
	Action string   `json:"action"`
	Cell   GaiaCell `json:"cell"`
}

type cellIsolationAfter struct {
	Schema       string `json:"schema"`
	UUID         string `json:"uuid"`
	Generation   uint64 `json:"generation"`
	CgroupID     uint64 `json:"cgroup_id"`
	State        string `json:"state"`
	NetworkState string `json:"network_state"`
}

type CellTransactionApplier struct {
	cells *GaiaCellsAdapter
}

func NewCellTransactionApplier(cells *GaiaCellsAdapter) *CellTransactionApplier {
	return &CellTransactionApplier{cells: cells}
}

func (a *CellTransactionApplier) Type() string {
	return cellTransactionType
}

func (a *CellTransactionApplier) ExclusiveTransactionType() bool {
	return false
}

func (a *CellTransactionApplier) Preview(
	payload json.RawMessage,
) (json.RawMessage, json.RawMessage, error) {
	if a.cells == nil {
		return nil, nil, errors.New("Gaia Cells adapter is unavailable")
	}
	request, err := decodeCellIsolationRequest(payload)
	if err != nil {
		return nil, nil, err
	}
	cell, err := a.findCell(request.UUID, request.Generation, request.CgroupID)
	if err != nil {
		return nil, nil, err
	}
	switch request.Action {
	case "freeze":
		if cell.State != "running" {
			return nil, nil, errors.New("Gaia Cell must be running before freeze")
		}
	case "revoke-network":
		if cell.NetworkState != "normal" {
			return nil, nil, errors.New("Gaia Cell network is not in normal state")
		}
	default:
		return nil, nil, errors.New("Gaia Cell isolation action is unsupported")
	}
	plan := cellIsolationPlan{
		Schema: cellTransactionSchema, Action: request.Action, Cell: cell,
	}
	encoded, err := json.Marshal(plan)
	if err != nil {
		return nil, nil, err
	}
	return encoded, append(json.RawMessage(nil), encoded...), nil
}

func (a *CellTransactionApplier) Apply(
	planRaw json.RawMessage,
	beforeRaw json.RawMessage,
) (json.RawMessage, error) {
	plan, err := decodeCellIsolationPlan(planRaw)
	if err != nil {
		return nil, err
	}
	before, err := decodeCellIsolationPlan(beforeRaw)
	if err != nil || before != plan {
		return nil, errors.New("Gaia Cell pre-state does not match the authorized plan")
	}
	current, err := a.findCell(
		plan.Cell.UUID, plan.Cell.Generation, plan.Cell.CgroupID,
	)
	if err != nil || current != plan.Cell {
		return nil, errors.New("Gaia Cell identity changed after preview")
	}
	command, state, network := "", plan.Cell.State, plan.Cell.NetworkState
	switch plan.Action {
	case "freeze":
		command, state = "FREEZE", "frozen"
	case "revoke-network":
		command, network = "REVOKE_NETWORK", "revoked"
	default:
		return nil, errors.New("Gaia Cell action is unsupported")
	}
	if err := a.cells.Action(
		command, plan.Cell.UUID, plan.Cell.Generation, plan.Cell.CgroupID,
	); err != nil {
		return nil, err
	}
	return json.Marshal(cellIsolationAfter{
		Schema: cellTransactionSchema, UUID: plan.Cell.UUID,
		Generation: plan.Cell.Generation, CgroupID: plan.Cell.CgroupID,
		State: state, NetworkState: network,
	})
}

func (a *CellTransactionApplier) Verify(
	planRaw json.RawMessage,
	afterRaw json.RawMessage,
) error {
	plan, err := decodeCellIsolationPlan(planRaw)
	if err != nil {
		return err
	}
	after, err := decodeCellIsolationAfter(afterRaw)
	if err != nil || after.UUID != plan.Cell.UUID ||
		after.Generation != plan.Cell.Generation || after.CgroupID != plan.Cell.CgroupID {
		return errors.New("Gaia Cell post-state identity mismatch")
	}
	current, err := a.findCell(after.UUID, after.Generation, after.CgroupID)
	if err != nil {
		return err
	}
	if current.State != after.State || current.NetworkState != after.NetworkState {
		return errors.New("Gaia Cell runtime post-state verification failed")
	}
	return nil
}

func (a *CellTransactionApplier) Reverse(
	beforeRaw json.RawMessage,
	afterRaw json.RawMessage,
) error {
	before, err := decodeCellIsolationPlan(beforeRaw)
	if err != nil {
		return err
	}
	if len(bytes.TrimSpace(afterRaw)) > 0 {
		after, err := decodeCellIsolationAfter(afterRaw)
		if err != nil || after.UUID != before.Cell.UUID ||
			after.Generation != before.Cell.Generation || after.CgroupID != before.Cell.CgroupID {
			return errors.New("Gaia Cell reverse-state identity mismatch")
		}
	}
	command := ""
	switch before.Action {
	case "freeze":
		command = "UNFREEZE"
	case "revoke-network":
		command = "RESTORE_NETWORK"
	default:
		return errors.New("Gaia Cell reverse action is unsupported")
	}
	if err := a.cells.Action(
		command, before.Cell.UUID, before.Cell.Generation, before.Cell.CgroupID,
	); err != nil {
		return err
	}
	current, err := a.findCell(
		before.Cell.UUID, before.Cell.Generation, before.Cell.CgroupID,
	)
	if err != nil {
		return err
	}
	if current.State != before.Cell.State ||
		current.NetworkState != before.Cell.NetworkState {
		return errors.New("Gaia Cell reverse verification failed")
	}
	return nil
}

func (a *CellTransactionApplier) findCell(
	uuid string,
	generation uint64,
	cgroupID uint64,
) (GaiaCell, error) {
	cells, err := a.cells.List()
	if err != nil {
		return GaiaCell{}, err
	}
	for _, cell := range cells {
		if cell.UUID == uuid && cell.Generation == generation &&
			cell.CgroupID == cgroupID {
			return cell, nil
		}
	}
	return GaiaCell{}, errors.New("Gaia Cell immutable identity was not found")
}

func decodeCellIsolationRequest(raw json.RawMessage) (cellIsolationRequest, error) {
	var request cellIsolationRequest
	if err := decodeCellJSON(raw, &request); err != nil ||
		!validCellUUID(request.UUID) || request.Generation == 0 ||
		request.CgroupID == 0 {
		return cellIsolationRequest{}, errors.New("Gaia Cell isolation request is malformed")
	}
	if request.Action != "freeze" && request.Action != "revoke-network" {
		return cellIsolationRequest{}, errors.New("Gaia Cell isolation action is unsupported")
	}
	return request, nil
}

func decodeCellIsolationPlan(raw json.RawMessage) (cellIsolationPlan, error) {
	var plan cellIsolationPlan
	if err := decodeCellJSON(raw, &plan); err != nil ||
		plan.Schema != cellTransactionSchema ||
		(plan.Action != "freeze" && plan.Action != "revoke-network") {
		return cellIsolationPlan{}, errors.New("Gaia Cell transaction plan is malformed")
	}
	if err := validateGaiaCell(plan.Cell); err != nil {
		return cellIsolationPlan{}, err
	}
	return plan, nil
}

func decodeCellIsolationAfter(raw json.RawMessage) (cellIsolationAfter, error) {
	var after cellIsolationAfter
	if err := decodeCellJSON(raw, &after); err != nil ||
		after.Schema != cellTransactionSchema || !validCellUUID(after.UUID) ||
		after.Generation == 0 || after.CgroupID == 0 {
		return cellIsolationAfter{}, errors.New("Gaia Cell transaction result is malformed")
	}
	if after.State != "running" && after.State != "frozen" {
		return cellIsolationAfter{}, errors.New("Gaia Cell result state is invalid")
	}
	if after.NetworkState != "normal" && after.NetworkState != "revoked" &&
		after.NetworkState != "none" {
		return cellIsolationAfter{}, errors.New("Gaia Cell result network state is invalid")
	}
	return after, nil
}

func decodeCellJSON(raw json.RawMessage, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errors.New("Gaia Cell document contains trailing data")
	}
	return nil
}
