package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/vegastack/vegastack-labs/internal/generated"
)

type OffsiteRetirementRule struct{ RuleID, Prefix string }
type OffsiteRetirementObject struct {
	Key, Digest string
	Bytes       int64
}
type OffsiteRetirementIntent struct {
	IntentID, PlanID, PlanDigest, GenerationID, PointID, BucketID                     string
	RuleSetDigest, SurvivorRuleDigest, ManifestDigest, CatalogDigest, InventoryDigest string
	OneOwnerProofID, LockAdminConsumerID, RetentionConsumerID                         string
	Rules                                                                             []OffsiteRetirementRule
	Objects                                                                           []OffsiteRetirementObject
	SurvivorPointIDs                                                                  []string
	SourceRevision, StateRevision, RecoveryEpoch, MaxWorkObjects, MaxMutationBytes    int64
}
type OffsiteRetirementClaim struct {
	IntentID, LeaseID, RunID, StepID, ExecutorLeaseID string
	MaximumExpiresAt                                  time.Time
}
type OffsiteRetirementLease struct {
	LeaseID, IntentID, RunID, StepID, GenerationID, BucketID string
	LockAdminConsumerID, RetentionConsumerID                 string
	RecoveryEpoch, MaxWorkObjects, MaxMutationBytes          int64
	MaximumExpiresAt                                         time.Time
}
type OffsiteRetirementAttempt struct {
	AttemptID, LeaseID, Kind, Target, RequestDigest, Status, ResponseDigest string
	Sequence                                                                int64
}
type OffsiteRetirementReceipt struct {
	ReceiptID, IntentID, LeaseID, Status, EffectDigest, SurvivorProofDigest string
	ReclaimedBytes                                                          int64
	CanonicalJSON                                                           []byte
}
type OffsiteRetirementRepository struct{ store *Store }

func NewOffsiteRetirementRepository(authority *Store) *OffsiteRetirementRepository {
	return &OffsiteRetirementRepository{authority}
}

func (r *OffsiteRetirementRepository) StageOffsiteRetirement(ctx context.Context, intent OffsiteRetirementIntent) (string, error) {
	if r == nil || r.store == nil || intent.IntentID == "" || intent.PlanID == "" || !validBackupDigest(intent.PlanDigest) || intent.GenerationID == "" || intent.PointID == "" || intent.BucketID == "" ||
		!validBackupDigest(intent.RuleSetDigest) || !validBackupDigest(intent.SurvivorRuleDigest) || !validBackupDigest(intent.ManifestDigest) || !validBackupDigest(intent.CatalogDigest) || !validBackupDigest(intent.InventoryDigest) ||
		intent.OneOwnerProofID == "" || intent.LockAdminConsumerID == "" || intent.RetentionConsumerID == "" || intent.LockAdminConsumerID == intent.RetentionConsumerID || len(intent.Rules) != 5 || len(intent.Objects) == 0 || len(intent.SurvivorPointIDs) == 0 || intent.MaxWorkObjects != int64(len(intent.Objects)) || intent.MaxMutationBytes < 0 {
		return "", newStoreError(generated.ErrorCodeInputInvalid, "offsite-retirement-intent", false, nil)
	}
	body, err := json.Marshal(intent)
	if err != nil {
		return "", err
	}
	now := r.store.config.Clock().UTC().Format(time.RFC3339)
	err = r.inTx(ctx, func(ctx context.Context, tx *sql.Tx) error {
		var revision, epoch int64
		if e := tx.QueryRowContext(ctx, `SELECT state_revision,recovery_epoch FROM system_meta WHERE id=1`).Scan(&revision, &epoch); e != nil {
			return e
		}
		if revision != intent.StateRevision || epoch != intent.RecoveryEpoch {
			return newStoreError(generated.ErrorCodePlanStale, "offsite-retirement-intent", false, nil)
		}
		var exact int
		if e := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM backup_offsite_generations WHERE generation_id=? AND source_point_id=? AND source_revision=? AND state_revision<=? AND recovery_epoch=?`, intent.GenerationID, intent.PointID, intent.SourceRevision, intent.StateRevision, intent.RecoveryEpoch).Scan(&exact); e != nil || exact != 1 {
			return newStoreError(generated.ErrorCodePlanStale, "offsite-retirement-generation", false, e)
		}
		if _, e := tx.ExecContext(ctx, `INSERT INTO backup_offsite_retirement_intents(intent_id,plan_id,plan_digest,generation_id,point_id,bucket_id,rule_set_digest,survivor_rule_digest,manifest_digest,catalog_digest,inventory_digest,one_owner_proof_id,lock_admin_consumer_id,retention_consumer_id,canonical_json,source_revision,state_revision,recovery_epoch,max_work_objects,max_mutation_bytes,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, intent.IntentID, intent.PlanID, intent.PlanDigest, intent.GenerationID, intent.PointID, intent.BucketID, intent.RuleSetDigest, intent.SurvivorRuleDigest, intent.ManifestDigest, intent.CatalogDigest, intent.InventoryDigest, intent.OneOwnerProofID, intent.LockAdminConsumerID, intent.RetentionConsumerID, string(body), intent.SourceRevision, intent.StateRevision, intent.RecoveryEpoch, intent.MaxWorkObjects, intent.MaxMutationBytes, now); e != nil {
			return e
		}
		for i, v := range intent.Rules {
			if _, e := tx.ExecContext(ctx, `INSERT INTO backup_offsite_retirement_rules(intent_id,sequence,rule_id,protected_prefix) VALUES(?,?,?,?)`, intent.IntentID, i+1, v.RuleID, v.Prefix); e != nil {
				return e
			}
		}
		for i, v := range intent.Objects {
			if _, e := tx.ExecContext(ctx, `INSERT INTO backup_offsite_retirement_objects(intent_id,sequence,object_key,object_digest,object_bytes) VALUES(?,?,?,?,?)`, intent.IntentID, i+1, v.Key, v.Digest, v.Bytes); e != nil {
				return e
			}
		}
		for _, v := range intent.SurvivorPointIDs {
			if _, e := tx.ExecContext(ctx, `INSERT INTO backup_offsite_retirement_survivors(intent_id,point_id) VALUES(?,?)`, intent.IntentID, v); e != nil {
				return e
			}
		}
		return nil
	})
	return intent.IntentID, err
}

func (r *OffsiteRetirementRepository) ClaimOffsiteRetirement(ctx context.Context, claim OffsiteRetirementClaim) (OffsiteRetirementLease, error) {
	var result OffsiteRetirementLease
	if r == nil || r.store == nil || claim.IntentID == "" || claim.LeaseID == "" || claim.RunID == "" || claim.StepID == "" || claim.ExecutorLeaseID == "" || claim.MaximumExpiresAt.IsZero() {
		return result, newStoreError(generated.ErrorCodeInputInvalid, "offsite-retirement-claim", false, nil)
	}
	now := r.store.config.Clock().UTC()
	if !now.Before(claim.MaximumExpiresAt) {
		return result, newStoreError(generated.ErrorCodePlanStale, "offsite-retirement-claim", false, nil)
	}
	err := r.inTx(ctx, func(ctx context.Context, tx *sql.Tx) error {
		var planID, planDigest, generation, bucket, lockAdmin, retention string
		var revision, epoch, maxWork, maxBytes int64
		if e := tx.QueryRowContext(ctx, `SELECT plan_id,plan_digest,generation_id,bucket_id,lock_admin_consumer_id,retention_consumer_id,state_revision,recovery_epoch,max_work_objects,max_mutation_bytes FROM backup_offsite_retirement_intents WHERE intent_id=?`, claim.IntentID).Scan(&planID, &planDigest, &generation, &bucket, &lockAdmin, &retention, &revision, &epoch, &maxWork, &maxBytes); e != nil {
			return e
		}
		var ack, human, leaseExpiry, planExpiry, ackExpiry string
		e := tx.QueryRowContext(ctx, `SELECT a.acknowledgement_id,a.human_id,e.maximum_expires_at,p.expires_at,a.expires_at FROM plan_runs r JOIN immutable_plans p ON p.plan_id=r.plan_id AND p.plan_digest=r.plan_digest JOIN plan_run_steps s ON s.run_id=r.run_id AND s.step_id=? AND s.operation_type='backup.retire.offsite' AND s.adapter_id='r2.retention' AND s.target_id=? AND s.status='running' AND s.effect_state='intent-recorded' AND s.active_lease_id=? JOIN target_execution_leases e ON e.lease_id=? AND e.run_id=r.run_id AND e.step_id=s.step_id AND e.target_id=? AND e.recovery_epoch=? AND e.status='active' JOIN acknowledgement_requests a ON a.acknowledgement_id=r.acknowledgement_id AND a.plan_id=r.plan_id AND a.plan_digest=r.plan_digest AND a.authority_id='infra-admin' AND a.state_revision=? AND a.recovery_epoch=? AND a.status='approved' AND a.consumed_at IS NOT NULL JOIN acknowledgement_proofs ap ON ap.acknowledgement_id=a.acknowledgement_id AND ap.status='approved' WHERE r.run_id=? AND r.plan_id=? AND r.plan_digest=? AND r.executor_mode='central' AND r.status='running'`, claim.StepID, generation, claim.ExecutorLeaseID, claim.ExecutorLeaseID, generation, epoch, revision, epoch, claim.RunID, planID, planDigest).Scan(&ack, &human, &leaseExpiry, &planExpiry, &ackExpiry)
		if e != nil {
			return newStoreError(generated.ErrorCodeAuthorizationDenied, "offsite-retirement-human-run", false, e)
		}
		for _, raw := range []string{leaseExpiry, planExpiry, ackExpiry} {
			deadline, e := time.Parse(time.RFC3339, raw)
			if e != nil || claim.MaximumExpiresAt.After(deadline) {
				return newStoreError(generated.ErrorCodePlanStale, "offsite-retirement-deadline", false, e)
			}
		}
		var currentRevision, currentEpoch int64
		if e := tx.QueryRowContext(ctx, `SELECT state_revision,recovery_epoch FROM system_meta WHERE id=1`).Scan(&currentRevision, &currentEpoch); e != nil {
			return e
		}
		if currentRevision != revision || currentEpoch != epoch {
			return newStoreError(generated.ErrorCodePlanStale, "offsite-retirement-claim", false, nil)
		}
		if _, e := tx.ExecContext(ctx, `INSERT INTO backup_offsite_retirement_leases(lease_id,intent_id,run_id,step_id,executor_lease_id,acknowledgement_id,human_id,recovery_epoch,maximum_expires_at,acquired_at) VALUES(?,?,?,?,?,?,?,?,?,?)`, claim.LeaseID, claim.IntentID, claim.RunID, claim.StepID, claim.ExecutorLeaseID, ack, human, epoch, claim.MaximumExpiresAt.Format(time.RFC3339), now.Format(time.RFC3339)); e != nil {
			return e
		}
		result = OffsiteRetirementLease{claim.LeaseID, claim.IntentID, claim.RunID, claim.StepID, generation, bucket, lockAdmin, retention, epoch, maxWork, maxBytes, claim.MaximumExpiresAt}
		return nil
	})
	return result, err
}

func (r *OffsiteRetirementRepository) AppendAttempt(ctx context.Context, a OffsiteRetirementAttempt) error {
	if r == nil || r.store == nil || a.AttemptID == "" || a.LeaseID == "" || a.Sequence < 1 || (a.Kind != "rule-put" && a.Kind != "object-delete") || a.Target == "" || !validBackupDigest(a.RequestDigest) || (a.Status != "attempted" && a.Status != "observed" && a.Status != "denied" && a.Status != "uncertain") {
		return newStoreError(generated.ErrorCodeInputInvalid, "offsite-retirement-attempt", false, nil)
	}
	_, err := r.store.conn.ExecContext(ctx, `INSERT INTO backup_offsite_retirement_attempts(attempt_id,lease_id,sequence,kind,target,request_digest,status,response_digest,recorded_at) VALUES(?,?,?,?,?,?,?,?,?)`, a.AttemptID, a.LeaseID, a.Sequence, a.Kind, a.Target, a.RequestDigest, a.Status, nilIfEmpty(a.ResponseDigest), r.store.config.Clock().UTC().Format(time.RFC3339))
	return err
}
func (r *OffsiteRetirementRepository) AppendReceipt(ctx context.Context, v OffsiteRetirementReceipt) error {
	if r == nil || r.store == nil || v.ReceiptID == "" || v.IntentID == "" || v.LeaseID == "" || (v.Status != "uncertain" && v.Status != "failed" && v.Status != "verified") || !validBackupDigest(v.EffectDigest) || v.ReclaimedBytes < 0 || len(v.CanonicalJSON) < 2 || (v.Status == "verified" && !validBackupDigest(v.SurvivorProofDigest)) {
		return newStoreError(generated.ErrorCodeInputInvalid, "offsite-retirement-receipt", false, nil)
	}
	_, err := r.store.conn.ExecContext(ctx, `INSERT INTO backup_offsite_retirement_receipts(receipt_id,intent_id,lease_id,status,effect_digest,survivor_proof_digest,reclaimed_bytes,canonical_json,recorded_at) VALUES(?,?,?,?,?,?,?,?,?)`, v.ReceiptID, v.IntentID, v.LeaseID, v.Status, v.EffectDigest, nilIfEmpty(v.SurvivorProofDigest), v.ReclaimedBytes, string(v.CanonicalJSON), r.store.config.Clock().UTC().Format(time.RFC3339))
	return err
}
func nilIfEmpty(v string) any {
	if v == "" {
		return nil
	}
	return v
}

func (r *OffsiteRetirementRepository) inTx(ctx context.Context, fn func(context.Context, *sql.Tx) error) error {
	tx, err := r.store.conn.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	if err = fn(ctx, tx); err != nil {
		_ = tx.Rollback()
		return err
	}
	return tx.Commit()
}

var _ = errors.Is
