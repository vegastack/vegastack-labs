package store

import (
	"bytes"
	"context"
	"encoding/json"
	"time"

	"github.com/vegastack/vegastack-labs/internal/audit"
	"github.com/vegastack/vegastack-labs/internal/generated"
)

// VerifyRecoveredAuthority proves that the post-mutation candidate still
// carries the exact planned transition. File-byte hashes cannot serve this
// purpose because preparing authority necessarily mutates the SQLite file.
func (store *Store) VerifyRecoveredAuthority(ctx context.Context, binding generated.RestoreBinding) error {
	if store == nil || !validRestoreBinding(binding) {
		return newStoreError(generated.ErrorCodeInputInvalid, "recovery-authority-binding", false, nil)
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.readyForRead(ctx); err != nil {
		return err
	}
	var instance, mode string
	var epoch int64
	if err := store.conn.QueryRowContext(ctx, `SELECT instance_id,recovery_epoch,authority_mode FROM system_meta WHERE id=1`).Scan(&instance, &epoch, &mode); err != nil {
		return store.transactionError(ctx, err)
	}
	if instance != binding.NewInstanceID || epoch != binding.NextRecoveryEpoch || mode != "recovery-required" {
		return newStoreError(generated.ErrorCodeIntegrityFailure, "recovery-authority-binding", false, nil)
	}
	var planDigest, candidateDigest, fenceDigest, decisionDigest, journalInstance, evidenceDigest string
	var journalEpoch int64
	var bindingBytes []byte
	err := store.conn.QueryRowContext(ctx, `SELECT plan_digest,candidate_digest,fence_set_digest,audit_decision_digest,instance_id,recovery_epoch,evidence_digest,binding_bytes FROM recovery_authority_journal WHERE plan_id=? AND transition='promoted'`, binding.PlanID).Scan(&planDigest, &candidateDigest, &fenceDigest, &decisionDigest, &journalInstance, &journalEpoch, &evidenceDigest, &bindingBytes)
	if err != nil {
		return store.transactionError(ctx, err)
	}
	wantBinding, err := json.Marshal(binding)
	if err != nil || !bytes.Equal(bindingBytes, wantBinding) || planDigest != binding.PlanDigest || candidateDigest != binding.CandidateDigest || fenceDigest != binding.FenceSetDigest || decisionDigest != binding.AuditDecisionDigest || journalInstance != binding.NewInstanceID || journalEpoch != binding.NextRecoveryEpoch || evidenceDigest != binding.CandidateDigest {
		return newStoreError(generated.ErrorCodeIntegrityFailure, "recovery-authority-binding", false, nil)
	}
	var genesisInstance, recoveryDecision string
	if err := store.conn.QueryRowContext(ctx, `SELECT instance_id,recovery_decision_digest FROM audit_epoch_genesis WHERE recovery_epoch=?`, binding.NextRecoveryEpoch).Scan(&genesisInstance, &recoveryDecision); err != nil {
		return store.transactionError(ctx, err)
	}
	if genesisInstance != binding.NewInstanceID || recoveryDecision != binding.AuditDecisionDigest {
		return newStoreError(generated.ErrorCodeIntegrityFailure, "recovery-authority-binding", false, nil)
	}
	return nil
}

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
	bindingBytes, err := json.Marshal(binding)
	if err != nil {
		return newStoreError(generated.ErrorCodeIntegrityFailure, "recovery-authority", false, err)
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO recovery_authority_journal(plan_id,transition,plan_digest,candidate_digest,fence_set_digest,audit_decision_digest,instance_id,recovery_epoch,evidence_digest,binding_bytes,created_at) VALUES(?,'promoted',?,?,?,?,?,?,?,?,?)`, binding.PlanID, binding.PlanDigest, binding.CandidateDigest, binding.FenceSetDigest, binding.AuditDecisionDigest, binding.NewInstanceID, binding.NextRecoveryEpoch, binding.CandidateDigest, bindingBytes, stamp); err != nil {
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
	// The canary is appended beside the promoted binding. This deliberately
	// does not depend on plan rows that may be newer than the restored point.
	result, err = tx.ExecContext(ctx, `INSERT INTO recovery_authority_journal(plan_id,transition,plan_digest,candidate_digest,fence_set_digest,audit_decision_digest,instance_id,recovery_epoch,evidence_digest,binding_bytes,created_at) SELECT plan_id,'verified',plan_digest,candidate_digest,fence_set_digest,audit_decision_digest,instance_id,recovery_epoch,?,binding_bytes,? FROM recovery_authority_journal WHERE transition='promoted' AND instance_id=? AND recovery_epoch=?`, canaryDigest, store.config.Clock().UTC().Truncate(time.Second).Format(time.RFC3339), instanceID, epoch)
	if err != nil {
		return store.transactionError(ctx, err)
	}
	changed, _ = result.RowsAffected()
	if changed != 1 {
		return newStoreError(generated.ErrorCodeRecoveryRequired, "recovery-enable", false, nil)
	}
	if err := tx.Commit(); err != nil {
		return store.transactionError(ctx, err)
	}
	store.health.Revision = RevisionToken{StateRevision: revision + 1, RecoveryEpoch: epoch}
	store.health.RecoveryPending = false
	store.health.MutationEnabled = true
	return nil
}
