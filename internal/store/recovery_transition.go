package store

import (
	"context"
	"time"

	"github.com/vegastack/vegastack-labs/internal/audit"
	"github.com/vegastack/vegastack-labs/internal/generated"
)

// PrepareRecoveredAuthority performs the one permitted identity/epoch change
// inside an isolated candidate. The candidate remains recovery-required and
// therefore cannot serve ordinary mutation after promotion.
func (store *Store) PrepareRecoveredAuthority(ctx context.Context, binding generated.RestoreBinding, priorCheckpoint audit.Fingerprint) error {
	if store == nil || !validRestoreBinding(binding) || !audit.ValidFingerprint(priorCheckpoint) || binding.NextRecoveryEpoch != binding.PriorRecoveryEpoch+1 {
		return newStoreError(generated.ErrorCodeInputInvalid, "recovery-authority", false, nil)
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.readyForTransaction(ctx); err != nil {
		return err
	}
	tx, err := store.conn.BeginTx(ctx, nil)
	if err != nil {
		return store.transactionError(ctx, err)
	}
	defer tx.Rollback()
	var currentInstance, mode string
	var revision, epoch int64
	if err := tx.QueryRowContext(ctx, `SELECT instance_id,state_revision,recovery_epoch,authority_mode FROM system_meta WHERE id=1`).Scan(&currentInstance, &revision, &epoch, &mode); err != nil {
		return store.transactionError(ctx, err)
	}
	if currentInstance != binding.PriorInstanceID || epoch != binding.PriorRecoveryEpoch || mode != "ready" {
		return newStoreError(generated.ErrorCodeStateConflict, "recovery-authority", false, nil)
	}
	stamp := store.config.Clock().UTC().Truncate(time.Second).Format(time.RFC3339)
	if _, err := tx.ExecContext(ctx, `INSERT INTO audit_instances(instance_id,created_at) VALUES(?,?)`, binding.NewInstanceID, stamp); err != nil {
		return store.transactionError(ctx, err)
	}
	genesis := audit.GenesisLink(binding.NewInstanceID, binding.NextRecoveryEpoch, priorCheckpoint, audit.Fingerprint(binding.AuditDecisionDigest))
	if !audit.ValidFingerprint(genesis.LinkDigest) {
		return newStoreError(generated.ErrorCodeIntegrityFailure, "recovery-authority", false, nil)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO audit_epoch_genesis(recovery_epoch,instance_id,prior_checkpoint_digest,recovery_decision_digest,genesis_digest) VALUES(?,?,?,?,?)`, binding.NextRecoveryEpoch, binding.NewInstanceID, genesis.PriorCheckpoint, genesis.RecoveryDecision, genesis.LinkDigest); err != nil {
		return store.transactionError(ctx, err)
	}
	result, err := tx.ExecContext(ctx, `UPDATE system_meta SET instance_id=?,recovery_epoch=?,state_revision=state_revision+1,authority_mode='recovery-required' WHERE id=1 AND instance_id=? AND recovery_epoch=? AND state_revision=? AND authority_mode='ready'`, binding.NewInstanceID, binding.NextRecoveryEpoch, binding.PriorInstanceID, binding.PriorRecoveryEpoch, revision)
	if err != nil {
		return store.transactionError(ctx, err)
	}
	changed, _ := result.RowsAffected()
	if changed != 1 {
		return newStoreError(generated.ErrorCodeStateConflict, "recovery-authority", false, nil)
	}
	if err := tx.Commit(); err != nil {
		return store.transactionError(ctx, err)
	}
	store.health.Revision = RevisionToken{StateRevision: revision + 1, RecoveryEpoch: binding.NextRecoveryEpoch}
	store.health.RecoveryPending = true
	store.health.MutationEnabled = false
	return nil
}

// EnableRecoveredAuthority is an exact one-way compare-and-swap after the
// complete canary digest is durably recorded in the transition journal.
func (store *Store) EnableRecoveredAuthority(ctx context.Context, instanceID string, epoch, revision int64, canaryDigest string) error {
	if store == nil || instanceID == "" || epoch < 1 || revision < 0 || !restoreDigest(canaryDigest) {
		return newStoreError(generated.ErrorCodeInputInvalid, "recovery-enable", false, nil)
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	tx, err := store.conn.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `UPDATE system_meta SET authority_mode='ready',state_revision=state_revision+1 WHERE id=1 AND instance_id=? AND recovery_epoch=? AND state_revision=? AND authority_mode='recovery-required'`, instanceID, epoch, revision)
	if err != nil {
		return store.transactionError(ctx, err)
	}
	changed, _ := result.RowsAffected()
	if changed != 1 {
		return newStoreError(generated.ErrorCodeRecoveryRequired, "recovery-enable", false, nil)
	}
	// A canary digest is retained append-only as the final verified transition.
	if _, err := tx.ExecContext(ctx, `INSERT INTO restore_transitions(plan_id,from_status,to_status,plan_digest,evidence_digest,state_revision,recovery_epoch,created_at) SELECT plan_id,'verification-required','verified',plan_digest,?,?,?,? FROM restore_sessions WHERE new_instance_id=? AND next_recovery_epoch=? ORDER BY created_at DESC LIMIT 1`, canaryDigest, revision+1, epoch, store.config.Clock().UTC().Truncate(time.Second).Format(time.RFC3339), instanceID, epoch); err != nil {
		return store.transactionError(ctx, err)
	}
	if err := tx.Commit(); err != nil {
		return store.transactionError(ctx, err)
	}
	store.health.Revision = RevisionToken{StateRevision: revision + 1, RecoveryEpoch: epoch}
	store.health.RecoveryPending = false
	store.health.MutationEnabled = true
	return nil
}
