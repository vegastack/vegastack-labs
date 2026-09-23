package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"path"
	"slices"
	"strings"
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
	PreRuleCount, SurvivorRuleCount                                                   int
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
		intent.OneOwnerProofID == "" || intent.LockAdminConsumerID == "" || intent.RetentionConsumerID == "" || intent.LockAdminConsumerID == intent.RetentionConsumerID || len(intent.Rules) != 5 || len(intent.Objects) == 0 || len(intent.SurvivorPointIDs) == 0 || intent.MaxWorkObjects != int64(len(intent.Objects)) || intent.MaxMutationBytes < 0 || intent.PreRuleCount < 5 || intent.SurvivorRuleCount != intent.PreRuleCount-5 {
		return "", newStoreError(generated.ErrorCodeInputInvalid, "offsite-retirement-intent", false, nil)
	}
	ruleIDs, prefixes := map[string]bool{}, map[string]bool{}
	for _, rule := range intent.Rules {
		if !validRetirementID(rule.RuleID) || !safeOffsiteRetirementPath(rule.Prefix, 512) || ruleIDs[rule.RuleID] || prefixes[rule.Prefix] {
			return "", newStoreError(generated.ErrorCodeInputInvalid, "offsite-retirement-rules", false, nil)
		}
		ruleIDs[rule.RuleID], prefixes[rule.Prefix] = true, true
	}
	objectKeys, survivors := map[string]bool{}, map[string]bool{}
	var objectBytes int64
	for _, object := range intent.Objects {
		if !safeOffsiteRetirementPath(object.Key, 1024) || !validBackupDigest(object.Digest) || object.Bytes < 0 || objectKeys[object.Key] || object.Bytes > intent.MaxMutationBytes-objectBytes {
			return "", newStoreError(generated.ErrorCodeInputInvalid, "offsite-retirement-objects", false, nil)
		}
		objectKeys[object.Key] = true
		objectBytes += object.Bytes
	}
	if objectBytes != intent.MaxMutationBytes {
		return "", newStoreError(generated.ErrorCodeInputInvalid, "offsite-retirement-object-bound", false, nil)
	}
	for _, pointID := range intent.SurvivorPointIDs {
		if !validRetirementID(pointID) || survivors[pointID] || pointID == intent.PointID {
			return "", newStoreError(generated.ErrorCodeInputInvalid, "offsite-retirement-survivors", false, nil)
		}
		survivors[pointID] = true
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
		if e := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM backup_offsite_generations g WHERE g.generation_id=? AND g.source_point_id=? AND g.source_revision=? AND g.state_revision<=? AND g.recovery_epoch=? AND json_extract(g.pending_json,'$.SourceManifestDigest')=? AND json_extract(g.pending_json,'$.OffsiteInventoryDigest')=? AND EXISTS(SELECT 1 FROM immutable_plans p WHERE p.plan_id=? AND p.plan_digest=? AND p.state_revision=? AND p.recovery_epoch=? AND p.expires_at>?)`, intent.GenerationID, intent.PointID, intent.SourceRevision, intent.StateRevision, intent.RecoveryEpoch, intent.ManifestDigest, intent.InventoryDigest, intent.PlanID, intent.PlanDigest, intent.StateRevision, intent.RecoveryEpoch, now).Scan(&exact); e != nil || exact != 1 {
			return newStoreError(generated.ErrorCodePlanStale, "offsite-retirement-generation", false, e)
		}
		var planBytes []byte
		if e := tx.QueryRowContext(ctx, `SELECT canonical_bytes FROM immutable_plans WHERE plan_id=? AND plan_digest=?`, intent.PlanID, intent.PlanDigest).Scan(&planBytes); e != nil {
			return newStoreError(generated.ErrorCodePlanStale, "offsite-retirement-plan", false, e)
		}
		var plan generated.Plan
		if json.Unmarshal(planBytes, &plan) != nil || generated.ValidateContractJSON(generated.SchemaIDPlan, planBytes, generated.ContractExact) != nil || !planBindsOffsiteRetirement(plan, intent) {
			return newStoreError(generated.ErrorCodeIntegrityFailure, "offsite-retirement-plan", false, nil)
		}
		if e := exactRetirementCatalogRows(ctx, tx, intent); e != nil {
			return e
		}
		if _, e := tx.ExecContext(ctx, `INSERT INTO backup_offsite_retirement_intents(intent_id,plan_id,plan_digest,generation_id,point_id,bucket_id,rule_set_digest,survivor_rule_digest,manifest_digest,catalog_digest,inventory_digest,one_owner_proof_id,lock_admin_consumer_id,retention_consumer_id,canonical_json,source_revision,state_revision,recovery_epoch,max_work_objects,max_mutation_bytes,pre_rule_count,survivor_rule_count,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, intent.IntentID, intent.PlanID, intent.PlanDigest, intent.GenerationID, intent.PointID, intent.BucketID, intent.RuleSetDigest, intent.SurvivorRuleDigest, intent.ManifestDigest, intent.CatalogDigest, intent.InventoryDigest, intent.OneOwnerProofID, intent.LockAdminConsumerID, intent.RetentionConsumerID, string(body), intent.SourceRevision, intent.StateRevision, intent.RecoveryEpoch, intent.MaxWorkObjects, intent.MaxMutationBytes, intent.PreRuleCount, intent.SurvivorRuleCount, now); e != nil {
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
	// Resolve the intent's exact proof through the canonical current live G-008
	// path before entering the write transaction. Append-only evidence plus the
	// in-transaction revision/epoch check fences any concurrent replacement.
	var proofID, proofBucket string
	if err := r.store.conn.QueryRowContext(ctx, `SELECT one_owner_proof_id,bucket_id FROM backup_offsite_retirement_intents WHERE intent_id=?`, claim.IntentID).Scan(&proofID, &proofBucket); err != nil {
		return result, err
	}
	qualifiedEvidence, err := NewGateRepository(r.store).ResolveCurrentExclusiveAdminEvidence(ctx, proofID, proofBucket, now)
	if err != nil {
		return result, newStoreError(generated.ErrorCodePrerequisiteBlocked, "offsite-retirement-one-owner", false, err)
	}
	err = r.inTx(ctx, func(ctx context.Context, tx *sql.Tx) error {
		var planID, planDigest, generation, bucket, oneOwnerProof, lockAdmin, retention string
		var revision, epoch, maxWork, maxBytes int64
		if e := tx.QueryRowContext(ctx, `SELECT plan_id,plan_digest,generation_id,bucket_id,one_owner_proof_id,lock_admin_consumer_id,retention_consumer_id,state_revision,recovery_epoch,max_work_objects,max_mutation_bytes FROM backup_offsite_retirement_intents WHERE intent_id=?`, claim.IntentID).Scan(&planID, &planDigest, &generation, &bucket, &oneOwnerProof, &lockAdmin, &retention, &revision, &epoch, &maxWork, &maxBytes); e != nil {
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
		if qualifiedEvidence.EvidenceID != oneOwnerProof || qualifiedEvidence.SubjectID != bucket || qualifiedEvidence.RecoveryEpoch != epoch || qualifiedEvidence.StateRevision > currentRevision {
			return newStoreError(generated.ErrorCodePrerequisiteBlocked, "offsite-retirement-one-owner", false, nil)
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
	return r.inTx(ctx, func(ctx context.Context, tx *sql.Tx) error {
		var matches, observed, uncertain int
		var maxWork, maxBytes int64
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM backup_offsite_retirement_leases WHERE lease_id=? AND intent_id=?`, v.LeaseID, v.IntentID).Scan(&matches); err != nil || matches != 1 {
			return newStoreError(generated.ErrorCodeAuthorizationDenied, "offsite-retirement-receipt-lease", false, err)
		}
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM backup_offsite_retirement_attempts WHERE lease_id=? AND status='observed'`, v.LeaseID).Scan(&observed); err != nil {
			return err
		}
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM backup_offsite_retirement_attempts WHERE lease_id=? AND status='uncertain'`, v.LeaseID).Scan(&uncertain); err != nil {
			return err
		}
		if err := tx.QueryRowContext(ctx, `SELECT max_work_objects,max_mutation_bytes FROM backup_offsite_retirement_intents WHERE intent_id=?`, v.IntentID).Scan(&maxWork, &maxBytes); err != nil {
			return err
		}
		if v.Status == "verified" && (uncertain != 0 || int64(observed) != maxWork+1 || v.ReclaimedBytes != maxBytes || v.EffectDigest != v.SurvivorProofDigest) {
			return newStoreError(generated.ErrorCodePrerequisiteBlocked, "offsite-retirement-receipt-proof", false, nil)
		}
		_, err := tx.ExecContext(ctx, `INSERT INTO backup_offsite_retirement_receipts(receipt_id,intent_id,lease_id,status,effect_digest,survivor_proof_digest,reclaimed_bytes,canonical_json,recorded_at) VALUES(?,?,?,?,?,?,?,?,?)`, v.ReceiptID, v.IntentID, v.LeaseID, v.Status, v.EffectDigest, nilIfEmpty(v.SurvivorProofDigest), v.ReclaimedBytes, string(v.CanonicalJSON), r.store.config.Clock().UTC().Format(time.RFC3339))
		return err
	})
}

func exactRetirementCatalogRows(ctx context.Context, tx *sql.Tx, intent OffsiteRetirementIntent) error {
	rows, err := tx.QueryContext(ctx, `SELECT rule_id,protected_prefix FROM backup_offsite_retention_rules WHERE generation_id=? ORDER BY sequence`, intent.GenerationID)
	if err != nil {
		return err
	}
	defer rows.Close()
	var rules []OffsiteRetirementRule
	for rows.Next() {
		var v OffsiteRetirementRule
		if err := rows.Scan(&v.RuleID, &v.Prefix); err != nil {
			return err
		}
		rules = append(rules, v)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	objectsRows, err := tx.QueryContext(ctx, `SELECT object_key,object_digest,object_bytes FROM backup_offsite_objects WHERE generation_id=? ORDER BY sequence`, intent.GenerationID)
	if err != nil {
		return err
	}
	defer objectsRows.Close()
	var objects []OffsiteRetirementObject
	for objectsRows.Next() {
		var v OffsiteRetirementObject
		if err := objectsRows.Scan(&v.Key, &v.Digest, &v.Bytes); err != nil {
			return err
		}
		objects = append(objects, v)
	}
	if err := objectsRows.Err(); err != nil {
		return err
	}
	if !slices.Equal(rules, intent.Rules) || !slices.Equal(objects, intent.Objects) {
		return newStoreError(generated.ErrorCodeIntegrityFailure, "offsite-retirement-catalog", false, nil)
	}
	lastGoodSeen := false
	for _, pointID := range intent.SurvivorPointIDs {
		var count int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM backup_offsite_generations WHERE source_point_id=? AND recovery_epoch=? AND generation_id<>?`, pointID, intent.RecoveryEpoch, intent.GenerationID).Scan(&count); err != nil || count != 1 {
			return newStoreError(generated.ErrorCodeIntegrityFailure, "offsite-retirement-survivors", false, err)
		}
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM backup_offsite_last_good_history h JOIN backup_offsite_generations g ON g.generation_id=h.generation_id WHERE g.source_point_id=? AND h.recovery_epoch=? AND h.sequence=(SELECT MAX(sequence) FROM backup_offsite_last_good_history WHERE recovery_epoch=?)`, pointID, intent.RecoveryEpoch, intent.RecoveryEpoch).Scan(&count); err != nil {
			return err
		}
		if count == 1 {
			lastGoodSeen = true
		}
	}
	if !lastGoodSeen {
		return newStoreError(generated.ErrorCodePrerequisiteBlocked, "offsite-retirement-last-good", false, nil)
	}
	return nil
}

func planBindsOffsiteRetirement(plan generated.Plan, intent OffsiteRetirementIntent) bool {
	if plan.PlanID != intent.PlanID || plan.PlanDigest != intent.PlanDigest || plan.Binding.StateRevision != intent.StateRevision || plan.Binding.RecoveryEpoch != intent.RecoveryEpoch || plan.Risk != "destructive" || plan.AuthorizationBranch != "human" || plan.ExecutorMode != "central" {
		return false
	}
	matched := 0
	for _, operation := range plan.Operations {
		if operation.OperationType == "backup.retire.offsite" && operation.AdapterID == "r2.retention" && operation.TargetID == intent.GenerationID && !operation.Idempotent {
			matched++
		}
	}
	return matched == 1
}
func nilIfEmpty(v string) any {
	if v == "" {
		return nil
	}
	return v
}

func safeOffsiteRetirementPath(value string, maximum int) bool {
	trimmed := strings.TrimSuffix(value, "/")
	return trimmed != "" && len(value) <= maximum && !strings.HasPrefix(value, "/") && !strings.Contains(value, "\\") && path.Clean(trimmed) == trimmed && !strings.Contains(trimmed, "../")
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
