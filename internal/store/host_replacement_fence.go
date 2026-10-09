package store

import (
	"context"
	"database/sql"
	"errors"
	"github.com/vegastack/vegastack-labs/internal/generated"
)

// A freeze survives failed runs and alias reassignment. Returning old identities
// do not regain issuance authority by acquiring a new lease or target name.
func requireHostUnfrozen(row discoveryRow, hostID string) error {
	var frozen string
	err := row(`SELECT replacement_id FROM host_replacement_events WHERE event_type='frozen' AND (old_host_id=? OR old_host_id IN (SELECT host_id FROM managed_hosts WHERE target_id=?)) LIMIT 1`, hostID, hostID).Scan(&frozen)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	return actionError(generated.ErrorCodePrerequisiteBlocked)
}
func validateReplacementReservation(ctx context.Context, tx *sql.Tx, p generated.Plan) error {
	row := func(q string, a ...any) *sql.Row { return tx.QueryRowContext(ctx, q, a...) }
	// Every actual native/probe execution target is checked, including auxiliary
	// source probes; a replacement core target is not an old-host action.
	for _, op := range p.Operations {
		if op.OperationType == "host.action.execute" || op.OperationType == "host.access.probe.local" || op.OperationType == "credential.stage" || op.OperationType == "credential.activate" || op.OperationType == "credential.rotate" || op.OperationType == "credential.recover" {
			if err := requireHostUnfrozen(row, op.TargetID); err != nil {
				return err
			}
		}
	}
	if p.HostAction != nil {
		return requireHostUnfrozen(row, p.HostAction.HostID)
	}
	return nil
}
