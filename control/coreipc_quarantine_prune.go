// STATUS: DIAMANT VGT SUPREME
package main

// V6.3.0 AP-7: authenticated QUARANTINE_PRUNE IPC command.
//
// Wire contract (append-only VGT3 command surface):
//   QUARANTINE_PRUNE <object_id> <protocol_identity_token> -> "pruned"
//
// The identity token is the existing v1:... encoding validated by
// QuarantineIdentity.protocolToken; the core re-parses and re-validates it and
// only deletes the derived vault object, never a host path. A mismatch, a
// missing object or an already restored/pruned object is a core error and is
// propagated unchanged so the operator sees the real reason.

import "errors"

// QuarantinePrune asks the privileged core to remove a verified false-positive
// object from the encrypted vault.
func (c *CoreClient) QuarantinePrune(objectID string, identity QuarantineIdentity) (string, error) {
	if c == nil {
		return "", errors.New("privileged core client is unavailable")
	}
	if !validQuarantineObjectID(objectID) {
		return "", errors.New("quarantine object ID is invalid")
	}
	identityToken, err := identity.protocolToken()
	if err != nil {
		return "", err
	}
	state, err := c.command("QUARANTINE_PRUNE", objectID, identityToken)
	if err != nil {
		return "", err
	}
	if state != "pruned" {
		return "", errors.New("core returned an invalid quarantine prune state")
	}
	return state, nil
}

// Compile-time proof that the core client implements the pruner capability.
var _ quarantinePruneCore = (*CoreClient)(nil)
