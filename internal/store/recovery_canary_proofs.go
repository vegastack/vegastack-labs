package store

import (
	"context"
	"errors"
	"time"

	"github.com/vegastack/vegastack-labs/internal/generated"
)

// VerifyRecoveryOldEpochMutationDenied exercises the real write-admission
// boundary with the former epoch and succeeds only for its exact rejection.
func (store *Store) VerifyRecoveryOldEpochMutationDenied(ctx context.Context, stateRevision, formerEpoch int64) error {
	called := false
	_, err := store.WriteIntent(ctx, &RevisionToken{StateRevision: stateRevision, RecoveryEpoch: formerEpoch}, func(IntentTx) error {
		called = true
		return errors.New("old epoch mutation callback reached")
	})
	if called || Code(err) != generated.ErrorCodeRecoveryEpochMismatch {
		return newStoreError(generated.ErrorCodeRecoveryRequired, "recovery-canary-old-epoch", false, err)
	}
	return nil
}

// RecoveryCanaryNoopEvent independently resolves the exact durable audit event
// for the subordinate no-op so a later checkpoint must cover that event.
func (store *Store) RecoveryCanaryNoopEvent(ctx context.Context, planID, runID string) (int64, time.Time, error) {
	var eventID int64
	var occurred string
	err := store.Read(ctx, func(tx ReadTx) error {
		return tx.queryRow(ctx, `SELECT e.event_id,e.occurred_at FROM recovery_canary_runs r JOIN audit_events e ON e.correlation_id=r.run_id AND e.event_type='recovery.canary-noop-verified' AND e.target_kind='recovery' AND e.target_id=r.instance_id AND e.recovery_epoch=r.recovery_epoch AND e.state_revision=r.state_revision WHERE r.plan_id=? AND r.run_id=?`, planID, runID).Scan(&eventID, &occurred)
	})
	at, parseErr := time.Parse(time.RFC3339, occurred)
	if err != nil || parseErr != nil {
		return 0, time.Time{}, newStoreError(generated.ErrorCodeIntegrityFailure, "recovery-canary-noop-event", false, err)
	}
	return eventID, at, nil
}
