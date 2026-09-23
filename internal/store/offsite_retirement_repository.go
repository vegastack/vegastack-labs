package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"path"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/generated"
)

type OffsiteRetirementRule struct{ RuleID, Prefix string }
type OffsiteRetirementObject struct {
	Key, Digest string
	Bytes       int64
}
type OffsiteRetirementSurvivorKey struct{ PointID, GenerationID, ReferenceID string }
type OffsiteRetirementIntent struct {
	IntentID, PlanID, PlanDigest, GenerationID, PointID, BucketID                     string
	RuleSetDigest, SurvivorRuleDigest, ManifestDigest, CatalogDigest, InventoryDigest string
	OneOwnerProofID, LockAdminReferenceID, RetentionReferenceID                       string
	G008BundleDigest, QualificationDigest, PutCutoffDigest, MultipartCutoffDigest     string
	ExclusiveAdminDigest, IntentDigest, CredentialBindingDigest                       string
	Rules                                                                             []OffsiteRetirementRule
	Objects                                                                           []OffsiteRetirementObject
	SurvivorPointIDs                                                                  []string
	SurvivorKeyReferences                                                             []OffsiteRetirementSurvivorKey
	SourceRevision, StateRevision, RecoveryEpoch, MaxWorkObjects, MaxMutationBytes    int64
	PreRuleCount, SurvivorRuleCount                                                   int
}
type OffsiteRetirementClaim struct {
	IntentID, LeaseID, RunID, StepID, ExecutorLeaseID string
	MaximumExpiresAt                                  time.Time
}
type OffsiteRetirementLease struct {
	LeaseID, IntentID, RunID, StepID, GenerationID, BucketID string
	LockAdminReferenceID, RetentionReferenceID               string
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
type OffsiteRetirementSurvivorSettlement struct {
	PointID, GenerationID, RuleDigest, InventoryDigest, FullReadDigest, RestoreDigest string
	RecoveryEpoch                                                                     int64
	ObservedAt                                                                        time.Time
}
type OffsiteRetirementVerifiedSettlement struct {
	ReceiptID, IntentID, LeaseID string
	ReclaimedBytes               int64
	Survivors                    []OffsiteRetirementSurvivorSettlement
}
type offsiteJournalRow struct {
	Sequence                      int64
	Kind, Target, Request, Status string
	Response                      sql.NullString
}
type OffsiteRetirementCatalogGeneration struct {
	CanonicalJSON       []byte
	GenerationID        string
	PointID             string
	CreatedAt           time.Time
	Qualified, LastGood bool
}
type OffsiteRetirementRepository struct{ store *Store }

func NewOffsiteRetirementRepository(authority *Store) *OffsiteRetirementRepository {
	return &OffsiteRetirementRepository{authority}
}

func (r *OffsiteRetirementRepository) GetOffsiteRetirementIntentByDigest(ctx context.Context, digest string) (OffsiteRetirementIntent, error) {
	var intent OffsiteRetirementIntent
	var canonical string
	if r == nil || r.store == nil || !validBackupDigest(digest) {
		return intent, newStoreError(generated.ErrorCodeInputInvalid, "offsite-retirement-intent", false, nil)
	}
	if err := r.store.conn.QueryRowContext(ctx, `SELECT canonical_json FROM backup_offsite_retirement_intents WHERE intent_digest=?`, digest).Scan(&canonical); err != nil {
		return intent, err
	}
	if json.Unmarshal([]byte(canonical), &intent) != nil || intent.IntentDigest != digest {
		return OffsiteRetirementIntent{}, newStoreError(generated.ErrorCodeIntegrityFailure, "offsite-retirement-intent", false, nil)
	}
	want, credentials, err := OffsiteRetirementIntentDigests(intent)
	if err != nil || want != digest || credentials != intent.CredentialBindingDigest {
		return OffsiteRetirementIntent{}, newStoreError(generated.ErrorCodeIntegrityFailure, "offsite-retirement-intent", false, err)
	}
	return intent, nil
}

func (r *OffsiteRetirementRepository) CurrentSurvivorSettlements(ctx context.Context, intent OffsiteRetirementIntent) ([]OffsiteRetirementSurvivorSettlement, error) {
	if r == nil || r.store == nil || len(intent.SurvivorPointIDs) == 0 {
		return nil, newStoreError(generated.ErrorCodeInputInvalid, "offsite-retirement-survivors", false, nil)
	}
	result := make([]OffsiteRetirementSurvivorSettlement, 0, len(intent.SurvivorPointIDs))
	for _, pointID := range intent.SurvivorPointIDs {
		var value OffsiteRetirementSurvivorSettlement
		var pendingJSON, observed string
		err := r.store.conn.QueryRowContext(ctx, `SELECT g.source_point_id,g.generation_id,g.pending_json,p.proof_digest,v.proof_digest,g.recovery_epoch,p.observed_at
			FROM backup_offsite_generations g
			JOIN backup_offsite_proofs p ON p.generation_id=g.generation_id AND p.status='offsite-verified' AND p.proof_class='qualified-provider' AND p.recovery_epoch=g.recovery_epoch
			JOIN backup_local_verifications v ON v.point_id=g.source_point_id AND v.status='local-verified' AND v.proof_class='live' AND v.recovery_epoch=g.recovery_epoch
			WHERE g.source_point_id=? AND g.recovery_epoch=?
			ORDER BY p.created_at DESC,p.proof_id DESC,v.created_at DESC,v.verification_id DESC LIMIT 1`, pointID, intent.RecoveryEpoch).
			Scan(&value.PointID, &value.GenerationID, &pendingJSON, &value.FullReadDigest, &value.RestoreDigest, &value.RecoveryEpoch, &observed)
		if err != nil {
			return nil, err
		}
		var pending struct{ RuleDigest, OffsiteInventoryDigest string }
		at, timeErr := time.Parse(time.RFC3339Nano, observed)
		if timeErr != nil {
			at, timeErr = time.Parse(time.RFC3339, observed)
		}
		if json.Unmarshal([]byte(pendingJSON), &pending) != nil || timeErr != nil {
			return nil, newStoreError(generated.ErrorCodeIntegrityFailure, "offsite-retirement-survivors", false, timeErr)
		}
		value.RuleDigest, value.InventoryDigest, value.ObservedAt = pending.RuleDigest, pending.OffsiteInventoryDigest, at
		result = append(result, value)
	}
	return result, nil
}

func (r *OffsiteRetirementRepository) ExpectedOffsiteSurvivor(ctx context.Context, pointID string) (OffsiteRetirementSurvivorSettlement, error) {
	var result OffsiteRetirementSurvivorSettlement
	var pendingJSON string
	if r == nil || r.store == nil || pointID == "" {
		return result, newStoreError(generated.ErrorCodeInputInvalid, "offsite-retirement-survivor", false, nil)
	}
	err := r.store.conn.QueryRowContext(ctx, `SELECT g.source_point_id,g.generation_id,g.pending_json,p.proof_digest,v.proof_digest,g.recovery_epoch
		FROM backup_offsite_generations g
		JOIN backup_offsite_proofs p ON p.generation_id=g.generation_id AND p.status='offsite-verified' AND p.proof_class='qualified-provider' AND p.recovery_epoch=g.recovery_epoch
		JOIN backup_local_verifications v ON v.point_id=g.source_point_id AND v.status='local-verified' AND v.proof_class='live' AND v.recovery_epoch=g.recovery_epoch
		WHERE g.source_point_id=? AND g.recovery_epoch=(SELECT recovery_epoch FROM system_meta WHERE id=1)
		ORDER BY p.created_at DESC,p.proof_id DESC,v.created_at DESC,v.verification_id DESC LIMIT 1`, pointID).
		Scan(&result.PointID, &result.GenerationID, &pendingJSON, &result.FullReadDigest, &result.RestoreDigest, &result.RecoveryEpoch)
	if err != nil {
		return result, err
	}
	var pending struct{ RuleDigest, OffsiteInventoryDigest string }
	if json.Unmarshal([]byte(pendingJSON), &pending) != nil {
		return OffsiteRetirementSurvivorSettlement{}, newStoreError(generated.ErrorCodeIntegrityFailure, "offsite-retirement-survivor", false, nil)
	}
	result.RuleDigest, result.InventoryDigest = pending.RuleDigest, pending.OffsiteInventoryDigest
	return result, nil
}

func (r *OffsiteRetirementRepository) CurrentOffsiteLastGood(ctx context.Context, epoch int64) (string, error) {
	var pointID string
	if r == nil || r.store == nil || epoch < 0 {
		return "", newStoreError(generated.ErrorCodeInputInvalid, "offsite-retirement-last-good", false, nil)
	}
	err := r.store.conn.QueryRowContext(ctx, `SELECT g.source_point_id FROM backup_offsite_last_good_history h JOIN backup_offsite_generations g ON g.generation_id=h.generation_id WHERE h.recovery_epoch=? ORDER BY h.sequence DESC LIMIT 1`, epoch).Scan(&pointID)
	return pointID, err
}

func (r *OffsiteRetirementRepository) IsQualifiedSurvivorKey(ctx context.Context, referenceID string, epoch int64) (bool, error) {
	if r == nil || r.store == nil || referenceID == "" || epoch < 0 {
		return false, newStoreError(generated.ErrorCodeInputInvalid, "offsite-survivor-key", false, nil)
	}
	var count int
	err := r.store.conn.QueryRowContext(ctx, `SELECT COUNT(*) FROM backup_offsite_run_specs s JOIN backup_offsite_generations g ON g.generation_id=s.generation_id JOIN backup_offsite_proofs p ON p.generation_id=g.generation_id AND p.status='offsite-verified' AND p.proof_class='qualified-provider' AND p.recovery_epoch=g.recovery_epoch WHERE s.repository_key_reference_id=? AND g.recovery_epoch=?`, referenceID, epoch).Scan(&count)
	return count > 0, err
}

func (r *OffsiteRetirementRepository) VerifySurvivorReadLease(ctx context.Context, intentID, leaseID, runID, stepID, pointID, generationID string, epoch int64, at time.Time) error {
	if r == nil || r.store == nil || intentID == "" || leaseID == "" || pointID == "" || generationID == "" || at.IsZero() {
		return newStoreError(generated.ErrorCodeInputInvalid, "offsite-survivor-read-lease", false, nil)
	}
	var maximum string
	err := r.store.conn.QueryRowContext(ctx, `SELECT l.maximum_expires_at FROM backup_offsite_retirement_leases l JOIN backup_offsite_retirement_survivors s ON s.intent_id=l.intent_id JOIN backup_offsite_generations g ON g.source_point_id=s.point_id AND g.recovery_epoch=l.recovery_epoch WHERE l.intent_id=? AND l.lease_id=? AND l.run_id=? AND l.step_id=? AND s.point_id=? AND g.generation_id=? AND l.recovery_epoch=?`, intentID, leaseID, runID, stepID, pointID, generationID, epoch).Scan(&maximum)
	if err != nil {
		return newStoreError(generated.ErrorCodeAuthorizationDenied, "offsite-survivor-read-lease", false, err)
	}
	deadline, err := time.Parse(time.RFC3339, maximum)
	if err != nil || !at.Before(deadline) {
		return newStoreError(generated.ErrorCodePlanStale, "offsite-survivor-read-lease", false, err)
	}
	return nil
}

func (r *OffsiteRetirementRepository) VerifiedReceiptExists(ctx context.Context, generationID, digest string) (bool, error) {
	if r == nil || r.store == nil || generationID == "" || !validBackupDigest(digest) {
		return false, newStoreError(generated.ErrorCodeInputInvalid, "offsite-retirement-receipt", false, nil)
	}
	var count int
	err := r.store.conn.QueryRowContext(ctx, `SELECT COUNT(*) FROM backup_offsite_retirement_receipts r JOIN backup_offsite_retirement_intents i ON i.intent_id=r.intent_id WHERE i.generation_id=? AND r.status='verified' AND r.effect_digest=?`, generationID, digest).Scan(&count)
	return count == 1, err
}

func (r *OffsiteRetirementRepository) CurrentCatalogGenerations(ctx context.Context, epoch int64) ([]OffsiteRetirementCatalogGeneration, error) {
	if r == nil || r.store == nil || epoch < 0 {
		return nil, newStoreError(generated.ErrorCodeInputInvalid, "offsite-retirement-catalog", false, nil)
	}
	rows, err := r.store.conn.QueryContext(ctx, `SELECT g.generation_id,g.source_point_id,g.pending_json,g.created_at,
		EXISTS(SELECT 1 FROM backup_offsite_proofs p WHERE p.generation_id=g.generation_id AND p.status='offsite-verified' AND p.proof_class='qualified-provider' AND p.recovery_epoch=g.recovery_epoch),
		EXISTS(SELECT 1 FROM backup_offsite_last_good_history h WHERE h.generation_id=g.generation_id AND h.recovery_epoch=g.recovery_epoch AND h.sequence=(SELECT MAX(sequence) FROM backup_offsite_last_good_history WHERE recovery_epoch=g.recovery_epoch))
		FROM backup_offsite_generations g WHERE g.recovery_epoch=? ORDER BY g.created_at,g.generation_id`, epoch)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []OffsiteRetirementCatalogGeneration
	for rows.Next() {
		var value OffsiteRetirementCatalogGeneration
		var canonical, created string
		if err := rows.Scan(&value.GenerationID, &value.PointID, &canonical, &created, &value.Qualified, &value.LastGood); err != nil {
			return nil, err
		}
		value.CreatedAt, err = time.Parse(time.RFC3339, created)
		if err != nil {
			value.CreatedAt, err = time.Parse(time.RFC3339Nano, created)
		}
		if err != nil {
			return nil, newStoreError(generated.ErrorCodeIntegrityFailure, "offsite-retirement-catalog", false, err)
		}
		value.CanonicalJSON = []byte(canonical)
		result = append(result, value)
	}
	return result, rows.Err()
}

func (r *OffsiteRetirementRepository) StageOffsiteRetirement(ctx context.Context, intent OffsiteRetirementIntent) (string, error) {
	if r == nil || r.store == nil || intent.IntentID == "" || intent.PlanID == "" || !validBackupDigest(intent.PlanDigest) || intent.GenerationID == "" || intent.PointID == "" || intent.BucketID == "" ||
		!validBackupDigest(intent.RuleSetDigest) || !validBackupDigest(intent.SurvivorRuleDigest) || !validBackupDigest(intent.ManifestDigest) || !validBackupDigest(intent.CatalogDigest) || !validBackupDigest(intent.InventoryDigest) ||
		intent.OneOwnerProofID == "" || intent.LockAdminReferenceID == "" || intent.RetentionReferenceID == "" || intent.LockAdminReferenceID == intent.RetentionReferenceID || !validBackupDigest(intent.G008BundleDigest) || !validBackupDigest(intent.QualificationDigest) || !validBackupDigest(intent.PutCutoffDigest) || !validBackupDigest(intent.MultipartCutoffDigest) || !validBackupDigest(intent.ExclusiveAdminDigest) || !validBackupDigest(intent.IntentDigest) || !validBackupDigest(intent.CredentialBindingDigest) || len(intent.Rules) != 5 || len(intent.Objects) == 0 || len(intent.SurvivorPointIDs) == 0 || len(intent.SurvivorKeyReferences) != len(intent.SurvivorPointIDs) || intent.MaxWorkObjects != int64(len(intent.Objects)) || intent.MaxMutationBytes < 0 || intent.PreRuleCount < 5 || intent.SurvivorRuleCount != intent.PreRuleCount-5 {
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
	keyPoints, keyReferences := map[string]bool{}, map[string]bool{}
	for _, key := range intent.SurvivorKeyReferences {
		if !survivors[key.PointID] || key.GenerationID == "" || key.ReferenceID == "" || keyPoints[key.PointID] || keyReferences[key.ReferenceID] || key.ReferenceID == intent.LockAdminReferenceID || key.ReferenceID == intent.RetentionReferenceID {
			return "", newStoreError(generated.ErrorCodeInputInvalid, "offsite-retirement-survivor-keys", false, nil)
		}
		keyPoints[key.PointID], keyReferences[key.ReferenceID] = true, true
	}
	wantIntent, wantCredential, err := OffsiteRetirementIntentDigests(intent)
	if err != nil || intent.IntentDigest != wantIntent || intent.CredentialBindingDigest != wantCredential {
		return "", newStoreError(generated.ErrorCodeIntegrityFailure, "offsite-retirement-intent-digest", false, err)
	}
	body, err := json.Marshal(intent)
	if err != nil {
		return "", err
	}
	committed, err := NewPlanRepository(r.store).GetPlan(ctx, intent.PlanID)
	if err != nil || committed.Plan.PlanDigest != intent.PlanDigest {
		return "", newStoreError(generated.ErrorCodePlanStale, "offsite-retirement-plan", false, err)
	}
	var operationID string
	for _, operation := range committed.Plan.Operations {
		if operation.OperationType == "backup.retire.offsite" && operation.AdapterID == "r2.retention" && operation.TargetID == intent.GenerationID && operation.ArtifactDigest == intent.IntentDigest {
			operationID = operation.OperationID
		}
	}
	bindings, err := NewCredentialRepository(r.store).GetStepBindings(ctx, committed.Plan, operationID)
	if err != nil || len(bindings) != 2+len(intent.SurvivorKeyReferences) || credentialref.OperationManifestDigest(bindings, operationID) != intent.CredentialBindingDigest || !exactOffsiteCredentialBindings(bindings, intent) {
		return "", newStoreError(generated.ErrorCodeIntegrityFailure, "offsite-retirement-credential-bindings", false, err)
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
		if _, e := tx.ExecContext(ctx, `INSERT INTO backup_offsite_retirement_intents(intent_id,plan_id,plan_digest,generation_id,point_id,bucket_id,rule_set_digest,survivor_rule_digest,manifest_digest,catalog_digest,inventory_digest,one_owner_proof_id,lock_admin_consumer_id,retention_consumer_id,canonical_json,g008_bundle_digest,qualification_digest,put_cutoff_digest,multipart_cutoff_digest,exclusive_admin_digest,intent_digest,credential_binding_digest,source_revision,state_revision,recovery_epoch,max_work_objects,max_mutation_bytes,pre_rule_count,survivor_rule_count,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, intent.IntentID, intent.PlanID, intent.PlanDigest, intent.GenerationID, intent.PointID, intent.BucketID, intent.RuleSetDigest, intent.SurvivorRuleDigest, intent.ManifestDigest, intent.CatalogDigest, intent.InventoryDigest, intent.OneOwnerProofID, intent.LockAdminReferenceID, intent.RetentionReferenceID, string(body), intent.G008BundleDigest, intent.QualificationDigest, intent.PutCutoffDigest, intent.MultipartCutoffDigest, intent.ExclusiveAdminDigest, intent.IntentDigest, intent.CredentialBindingDigest, intent.SourceRevision, intent.StateRevision, intent.RecoveryEpoch, intent.MaxWorkObjects, intent.MaxMutationBytes, intent.PreRuleCount, intent.SurvivorRuleCount, now); e != nil {
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
	var proofID, proofBucket, bundleDigest, qualificationDigest, putDigest, multipartDigest, exclusiveDigest string
	if err := r.store.conn.QueryRowContext(ctx, `SELECT one_owner_proof_id,bucket_id,g008_bundle_digest,qualification_digest,put_cutoff_digest,multipart_cutoff_digest,exclusive_admin_digest FROM backup_offsite_retirement_intents WHERE intent_id=?`, claim.IntentID).Scan(&proofID, &proofBucket, &bundleDigest, &qualificationDigest, &putDigest, &multipartDigest, &exclusiveDigest); err != nil {
		return result, err
	}
	qualifiedEvidence, err := NewGateRepository(r.store).ResolveCurrentLiveGateEvidenceWithExclusiveAdmin(ctx, "G-008", bundleDigest, qualificationDigest, putDigest, multipartDigest, exclusiveDigest, now)
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
	if r == nil || r.store == nil || v.ReceiptID == "" || v.IntentID == "" || v.LeaseID == "" || (v.Status != "uncertain" && v.Status != "failed") || !validBackupDigest(v.EffectDigest) || v.ReclaimedBytes < 0 || len(v.CanonicalJSON) < 2 || v.SurvivorProofDigest != "" {
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
		_ = observed
		_ = uncertain
		_ = maxWork
		_ = maxBytes
		_, err := tx.ExecContext(ctx, `INSERT INTO backup_offsite_retirement_receipts(receipt_id,intent_id,lease_id,status,effect_digest,survivor_proof_digest,reclaimed_bytes,canonical_json,recorded_at) VALUES(?,?,?,?,?,?,?,?,?)`, v.ReceiptID, v.IntentID, v.LeaseID, v.Status, v.EffectDigest, nilIfEmpty(v.SurvivorProofDigest), v.ReclaimedBytes, string(v.CanonicalJSON), r.store.config.Clock().UTC().Format(time.RFC3339))
		return err
	})
}

func (r *OffsiteRetirementRepository) SettleVerifiedReceipt(ctx context.Context, v OffsiteRetirementVerifiedSettlement) (OffsiteRetirementReceipt, error) {
	var result OffsiteRetirementReceipt
	if r == nil || r.store == nil || v.ReceiptID == "" || v.IntentID == "" || v.LeaseID == "" || v.ReclaimedBytes < 0 || len(v.Survivors) == 0 {
		return result, newStoreError(generated.ErrorCodeInputInvalid, "offsite-retirement-settlement", false, nil)
	}
	err := r.inTx(ctx, func(ctx context.Context, tx *sql.Tx) error {
		var canonical string
		var maxWork, maxBytes, epoch int64
		var bucket, survivorRuleDigest string
		if err := tx.QueryRowContext(ctx, `SELECT i.canonical_json,i.max_work_objects,i.max_mutation_bytes,i.recovery_epoch,i.bucket_id,i.survivor_rule_digest FROM backup_offsite_retirement_intents i JOIN backup_offsite_retirement_leases l ON l.intent_id=i.intent_id AND l.lease_id=? WHERE i.intent_id=?`, v.LeaseID, v.IntentID).Scan(&canonical, &maxWork, &maxBytes, &epoch, &bucket, &survivorRuleDigest); err != nil {
			return newStoreError(generated.ErrorCodeAuthorizationDenied, "offsite-retirement-settlement-lease", false, err)
		}
		var intent OffsiteRetirementIntent
		if json.Unmarshal([]byte(canonical), &intent) != nil {
			return newStoreError(generated.ErrorCodeIntegrityFailure, "offsite-retirement-settlement-intent", false, nil)
		}
		if v.ReclaimedBytes != maxBytes || int64(len(intent.Objects)) != maxWork {
			return newStoreError(generated.ErrorCodeIntegrityFailure, "offsite-retirement-settlement-bounds", false, nil)
		}
		rows, err := tx.QueryContext(ctx, `SELECT sequence,kind,target,request_digest,status,response_digest FROM backup_offsite_retirement_attempts WHERE lease_id=? ORDER BY sequence`, v.LeaseID)
		if err != nil {
			return err
		}
		defer rows.Close()
		var journal []offsiteJournalRow
		for rows.Next() {
			var a offsiteJournalRow
			if err := rows.Scan(&a.Sequence, &a.Kind, &a.Target, &a.Request, &a.Status, &a.Response); err != nil {
				return err
			}
			if a.Status == "uncertain" || a.Status == "denied" {
				return newStoreError(generated.ErrorCodePrerequisiteBlocked, "offsite-retirement-settlement-uncertain", false, nil)
			}
			journal = append(journal, a)
		}
		if err := rows.Err(); err != nil {
			return err
		}
		if !exactOffsiteEffectJournal(intent, bucket, survivorRuleDigest, journal) {
			return newStoreError(generated.ErrorCodeIntegrityFailure, "offsite-retirement-settlement-journal", false, nil)
		}
		var lastEffectText string
		if err := tx.QueryRowContext(ctx, `SELECT MAX(recorded_at) FROM backup_offsite_retirement_attempts WHERE lease_id=?`, v.LeaseID).Scan(&lastEffectText); err != nil {
			return err
		}
		lastEffectAt, err := time.Parse(time.RFC3339Nano, lastEffectText)
		if err != nil {
			lastEffectAt, err = time.Parse(time.RFC3339, lastEffectText)
		}
		if err != nil {
			return newStoreError(generated.ErrorCodeIntegrityFailure, "offsite-retirement-settlement-time", false, err)
		}
		survivors := append([]OffsiteRetirementSurvivorSettlement(nil), v.Survivors...)
		slices.SortFunc(survivors, func(a, b OffsiteRetirementSurvivorSettlement) int {
			if a.PointID < b.PointID {
				return -1
			}
			if a.PointID > b.PointID {
				return 1
			}
			return 0
		})
		if !exactOffsiteSurvivorSettlement(ctx, tx, intent, survivors, epoch) {
			return newStoreError(generated.ErrorCodeIntegrityFailure, "offsite-retirement-settlement-survivors", false, nil)
		}
		for _, survivor := range survivors {
			if survivor.ObservedAt.Before(lastEffectAt) {
				return newStoreError(generated.ErrorCodePrerequisiteBlocked, "offsite-retirement-settlement-stale-proof", false, nil)
			}
		}
		body, err := json.Marshal(struct {
			IntentDigest   string
			Journal        []offsiteJournalRow
			Survivors      []OffsiteRetirementSurvivorSettlement
			ReclaimedBytes int64
		}{intent.IntentDigest, journal, survivors, v.ReclaimedBytes})
		if err != nil {
			return err
		}
		sum := sha256.Sum256(append([]byte("offsite-retirement-settlement-v1\x00"), body...))
		digest := "sha256:" + hex.EncodeToString(sum[:])
		now := r.store.config.Clock().UTC().Format(time.RFC3339)
		if _, err := tx.ExecContext(ctx, `INSERT INTO backup_offsite_retirement_receipts(receipt_id,intent_id,lease_id,status,effect_digest,survivor_proof_digest,reclaimed_bytes,canonical_json,recorded_at) VALUES(?,?,?,'verified',?,?,?,?,?)`, v.ReceiptID, v.IntentID, v.LeaseID, digest, digest, v.ReclaimedBytes, string(body), now); err != nil {
			return err
		}
		for _, p := range survivors {
			if _, err := tx.ExecContext(ctx, `INSERT INTO backup_offsite_retirement_survivor_proofs(receipt_id,point_id,generation_id,rule_digest,inventory_digest,full_read_digest,restore_digest,recovery_epoch,observed_at) VALUES(?,?,?,?,?,?,?,?,?)`, v.ReceiptID, p.PointID, p.GenerationID, p.RuleDigest, p.InventoryDigest, p.FullReadDigest, p.RestoreDigest, p.RecoveryEpoch, p.ObservedAt.UTC().Format(time.RFC3339Nano)); err != nil {
				return err
			}
		}
		result = OffsiteRetirementReceipt{ReceiptID: v.ReceiptID, IntentID: v.IntentID, LeaseID: v.LeaseID, Status: "verified", EffectDigest: digest, SurvivorProofDigest: digest, ReclaimedBytes: v.ReclaimedBytes, CanonicalJSON: body}
		return nil
	})
	return result, err
}

func exactOffsiteEffectJournal(intent OffsiteRetirementIntent, bucket, survivorRuleDigest string, journal []offsiteJournalRow) bool {
	want := make([]offsiteJournalRow, 0, 2+2*len(intent.Objects))
	ruleRequest := survivorRuleDigest
	want = append(want,
		offsiteJournalRow{Sequence: 1, Kind: "rule-put", Target: bucket, Request: ruleRequest, Status: "attempted"},
		offsiteJournalRow{Sequence: 2, Kind: "rule-put", Target: bucket, Request: ruleRequest, Status: "observed", Response: sql.NullString{String: survivorRuleDigest, Valid: true}},
	)
	objects := append([]OffsiteRetirementObject(nil), intent.Objects...)
	slices.SortFunc(objects, func(a, b OffsiteRetirementObject) int { return strings.Compare(a.Key, b.Key) })
	for index, object := range objects {
		request := offsiteDigestParts("delete", object.Key, object.Digest, strconv.FormatInt(object.Bytes, 10))
		sequence := int64(3 + 2*index)
		want = append(want,
			offsiteJournalRow{Sequence: sequence, Kind: "object-delete", Target: object.Key, Request: request, Status: "attempted"},
			offsiteJournalRow{Sequence: sequence + 1, Kind: "object-delete", Target: object.Key, Request: request, Status: "observed", Response: sql.NullString{String: object.Digest, Valid: true}},
		)
	}
	return slices.Equal(journal, want)
}

func exactOffsiteSurvivorSettlement(ctx context.Context, tx *sql.Tx, intent OffsiteRetirementIntent, survivors []OffsiteRetirementSurvivorSettlement, epoch int64) bool {
	expected := append([]string(nil), intent.SurvivorPointIDs...)
	slices.Sort(expected)
	if len(survivors) != len(expected) {
		return false
	}
	var currentLastGood string
	if err := tx.QueryRowContext(ctx, `SELECT g.source_point_id FROM backup_offsite_last_good_history h JOIN backup_offsite_generations g ON g.generation_id=h.generation_id WHERE h.recovery_epoch=? ORDER BY h.sequence DESC LIMIT 1`, epoch).Scan(&currentLastGood); err != nil {
		return false
	}
	lastGoodSeen := false
	for index, proof := range survivors {
		if proof.PointID != expected[index] || proof.GenerationID == intent.GenerationID || proof.RecoveryEpoch != epoch || proof.ObservedAt.IsZero() ||
			!validBackupDigest(proof.RuleDigest) || !validBackupDigest(proof.InventoryDigest) || !validBackupDigest(proof.FullReadDigest) || !validBackupDigest(proof.RestoreDigest) {
			return false
		}
		var pendingJSON string
		if err := tx.QueryRowContext(ctx, `SELECT g.pending_json,p.proof_digest,v.proof_digest
			FROM backup_offsite_generations g
			JOIN backup_offsite_proofs p ON p.generation_id=g.generation_id AND p.status='offsite-verified' AND p.proof_class='qualified-provider' AND p.recovery_epoch=g.recovery_epoch
			JOIN backup_local_verifications v ON v.point_id=g.source_point_id AND v.status='local-verified' AND v.proof_class='live' AND v.recovery_epoch=g.recovery_epoch
			WHERE g.generation_id=? AND g.source_point_id=? AND g.recovery_epoch=?
			ORDER BY p.created_at DESC,p.proof_id DESC,v.created_at DESC,v.verification_id DESC LIMIT 1`, proof.GenerationID, proof.PointID, epoch).Scan(&pendingJSON, new(string), new(string)); err != nil {
			return false
		}
		var pending struct{ RuleDigest, OffsiteInventoryDigest string }
		if json.Unmarshal([]byte(pendingJSON), &pending) != nil || pending.RuleDigest != proof.RuleDigest || pending.OffsiteInventoryDigest != proof.InventoryDigest {
			return false
		}
		if proof.PointID == currentLastGood {
			lastGoodSeen = true
		}
	}
	return lastGoodSeen
}

func offsiteDigestParts(values ...string) string {
	hash := sha256.New()
	for _, value := range values {
		_, _ = hash.Write([]byte(value))
		_, _ = hash.Write([]byte{0})
	}
	return "sha256:" + hex.EncodeToString(hash.Sum(nil))
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
	slices.SortFunc(rules, func(a, b OffsiteRetirementRule) int { return strings.Compare(a.RuleID, b.RuleID) })
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
	slices.SortFunc(objects, func(a, b OffsiteRetirementObject) int { return strings.Compare(a.Key, b.Key) })
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
		if operation.OperationType == "backup.retire.offsite" && operation.AdapterID == "r2.retention" && operation.TargetID == intent.GenerationID && operation.ArtifactDigest == intent.IntentDigest && operation.InputDigest == intent.CredentialBindingDigest && !operation.Idempotent {
			matched++
		}
	}
	retirement, credential := 0, 0
	for _, extension := range plan.Extensions {
		switch extension.Name {
		case "x-backup-offsite-retirement":
			if extension.ValueDigest == intent.IntentDigest {
				retirement++
			}
		case "x-credential-bindings":
			if extension.ValueDigest == intent.CredentialBindingDigest {
				credential++
			}
		}
	}
	return matched == 1 && retirement == 1 && credential == 1 && len(plan.Extensions) == 2
}

func OffsiteRetirementIntentDigests(intent OffsiteRetirementIntent) (string, string, error) {
	rules := append([]OffsiteRetirementRule(nil), intent.Rules...)
	slices.SortFunc(rules, func(a, b OffsiteRetirementRule) int {
		if a.RuleID < b.RuleID {
			return -1
		}
		if a.RuleID > b.RuleID {
			return 1
		}
		return 0
	})
	objects := append([]OffsiteRetirementObject(nil), intent.Objects...)
	slices.SortFunc(objects, func(a, b OffsiteRetirementObject) int {
		if a.Key < b.Key {
			return -1
		}
		if a.Key > b.Key {
			return 1
		}
		return 0
	})
	survivors := append([]string(nil), intent.SurvivorPointIDs...)
	slices.Sort(survivors)
	survivorKeys := append([]OffsiteRetirementSurvivorKey(nil), intent.SurvivorKeyReferences...)
	slices.SortFunc(survivorKeys, func(a, b OffsiteRetirementSurvivorKey) int { return strings.Compare(a.PointID, b.PointID) })
	payload := struct {
		GenerationID, PointID, BucketID, RuleSetDigest, SurvivorRuleDigest, ManifestDigest, CatalogDigest, InventoryDigest, OneOwnerProofID, LockAdminReferenceID, RetentionReferenceID, G008BundleDigest, QualificationDigest, PutCutoffDigest, MultipartCutoffDigest, ExclusiveAdminDigest string
		Rules                                                                                                                                                                                                                                                                                []OffsiteRetirementRule
		Objects                                                                                                                                                                                                                                                                              []OffsiteRetirementObject
		Survivors                                                                                                                                                                                                                                                                            []string
		SurvivorKeys                                                                                                                                                                                                                                                                         []OffsiteRetirementSurvivorKey
		SourceRevision, StateRevision, RecoveryEpoch, MaxWorkObjects, MaxMutationBytes                                                                                                                                                                                                       int64
		PreRuleCount, SurvivorRuleCount                                                                                                                                                                                                                                                      int
	}{intent.GenerationID, intent.PointID, intent.BucketID, intent.RuleSetDigest, intent.SurvivorRuleDigest, intent.ManifestDigest, intent.CatalogDigest, intent.InventoryDigest, intent.OneOwnerProofID, intent.LockAdminReferenceID, intent.RetentionReferenceID, intent.G008BundleDigest, intent.QualificationDigest, intent.PutCutoffDigest, intent.MultipartCutoffDigest, intent.ExclusiveAdminDigest, rules, objects, survivors, survivorKeys, intent.SourceRevision, intent.StateRevision, intent.RecoveryEpoch, intent.MaxWorkObjects, intent.MaxMutationBytes, intent.PreRuleCount, intent.SurvivorRuleCount}
	body, err := json.Marshal(payload)
	if err != nil {
		return "", "", err
	}
	sum := sha256.Sum256(append([]byte("offsite-retirement-intent-v1\x00"), body...))
	return "sha256:" + hex.EncodeToString(sum[:]), intent.CredentialBindingDigest, nil
}

func exactOffsiteCredentialBindings(bindings []credentialref.StepBinding, intent OffsiteRetirementIntent) bool {
	seenLock, seenRetention := false, false
	keys := map[string]OffsiteRetirementSurvivorKey{}
	for _, key := range intent.SurvivorKeyReferences {
		keys[key.ReferenceID] = key
	}
	for _, binding := range bindings {
		if binding.AdapterID != "r2.retention" || binding.TargetID != intent.GenerationID || binding.ConsumerID != "r2.retention" || binding.ResolverID != "native-systemd" || binding.StateRevision != intent.StateRevision || binding.RecoveryEpoch != intent.RecoveryEpoch {
			return false
		}
		switch binding.PurposeID {
		case "lock-admin":
			if seenLock || binding.ReferenceID != intent.LockAdminReferenceID {
				return false
			}
			seenLock = true
		case "retention":
			if seenRetention || binding.ReferenceID != intent.RetentionReferenceID {
				return false
			}
			seenRetention = true
		case "repository-key":
			if _, ok := keys[binding.ReferenceID]; !ok {
				return false
			}
			delete(keys, binding.ReferenceID)
		default:
			return false
		}
	}
	return seenLock && seenRetention && len(keys) == 0
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
