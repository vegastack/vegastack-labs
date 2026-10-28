package store

import (
	"context"
	"encoding/json"
	"github.com/vegastack/vegastack-labs/internal/generated"
)

// ControllerSetupLease reads only the active normal-central lease belonging to
// the exact acknowledged finite controller operation; external executor rights
// are neither used nor granted by this path.
func (r *RunRepository) ControllerSetupLease(ctx context.Context, runID, leaseID string) (out generated.ExecutorLease, err error) {
	var raw []byte
	err = r.store.Read(ctx, func(tx ReadTx) error {
		if e := tx.queryRow(ctx, `SELECT l.canonical_bytes FROM target_execution_leases l JOIN plan_runs r ON r.run_id=l.run_id JOIN plan_run_steps s ON s.run_id=r.run_id AND s.step_id=l.step_id JOIN acknowledgement_requests a ON a.acknowledgement_id=r.acknowledgement_id WHERE l.lease_id=? AND l.run_id=? AND l.lease_kind='central' AND l.status='active' AND r.status='running' AND r.cancellation_requested=0 AND r.executor_mode='central' AND l.recovery_epoch=(SELECT recovery_epoch FROM system_meta WHERE id=1) AND s.active_lease_id=l.lease_id AND s.status='running' AND s.effect_state IN ('intent-recorded','receipt-recorded') AND s.operation_type='controller.setup.bootstrap' AND s.adapter_id='core.controller-setup' AND a.status='approved' AND a.consumed_at IS NOT NULL AND a.plan_id=r.plan_id AND a.plan_digest=r.plan_digest AND a.recovery_epoch=r.recovery_epoch`, leaseID, runID).Scan(&raw); e != nil {
			return newStoreError(generated.ErrorCodeAuthorizationDenied, "controller-setup-lease", false, nil)
		}
		if json.Unmarshal(raw, &out) != nil || out.LeaseID != leaseID || out.RunID != runID || out.AdapterID != "core.controller-setup" || out.Status != "active" || generated.ValidateLeaseTiming(out) != nil {
			return newStoreError(generated.ErrorCodeIntegrityFailure, "controller-setup-lease", false, nil)
		}
		return nil
	})
	return
}
