package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/vegastack/vegastack-labs/internal/audit"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/stateexport"
)

type recoveryCanaryMutationContextKey struct{}

type recoveryCanaryMutationToken struct {
	store                             *Store
	planID, planDigest, runID, stepID string
	stateRevision, recoveryEpoch      int64
}

// RecoveryCanaryMutationRequest names the exact, already acknowledged
// subordinate canary operation. It is deliberately smaller than a general
// write capability.
type RecoveryCanaryMutationRequest struct {
	PlanID, PlanDigest, RunID, StepID, LeaseID string
	InstanceID                                 string
	StateRevision, RecoveryEpoch               int64
}

// WithRecoveryCanaryMutation admits only the exact sealed canary while normal
// mutation is disabled. The private context token is usable only during this
// synchronous callback and only while the in-memory authority remains at the
// same recovery-required revision and epoch.
func (store *Store) WithRecoveryCanaryMutation(ctx context.Context, request RecoveryCanaryMutationRequest, mutate func(context.Context) error) error {
	if store == nil || ctx == nil || ctx.Err() != nil || mutate == nil || request.PlanID == "" || request.PlanDigest == "" || request.RunID == "" || request.StepID == "" || request.LeaseID == "" || request.InstanceID == "" || request.StateRevision < 0 || request.RecoveryEpoch < 1 {
		return newStoreError(generated.ErrorCodeInputInvalid, "recovery-canary-mutation", false, nil)
	}
	bundle, _, err := store.RecoveredAuthorityBundle(ctx, request.PlanID)
	if err != nil || bundle.Status != "verification-required" || bundle.Plan.PlanDigest != request.PlanDigest || bundle.Binding.NewInstanceID != request.InstanceID || bundle.Binding.NextRecoveryEpoch != request.RecoveryEpoch || bundle.Binding.CanaryRunID != request.RunID || bundle.Binding.CanaryStepID != request.StepID || bundle.Binding.CanaryLeaseID != request.LeaseID {
		return newStoreError(generated.ErrorCodePlanStale, "recovery-canary-mutation", false, err)
	}
	state, err := store.CurrentAuthority(ctx)
	if err != nil || state.InstanceID != request.InstanceID || state.RecoveryEpoch != request.RecoveryEpoch || state.Mode != "recovery-required" || store.health.Revision.StateRevision != request.StateRevision {
		return newStoreError(generated.ErrorCodeRecoveryRequired, "recovery-canary-mutation", false, err)
	}
	token := recoveryCanaryMutationToken{store: store, planID: request.PlanID, planDigest: request.PlanDigest, runID: request.RunID, stepID: request.StepID, stateRevision: request.StateRevision, recoveryEpoch: request.RecoveryEpoch}
	return mutate(context.WithValue(ctx, recoveryCanaryMutationContextKey{}, token))
}

func requireRecoveryCanaryToken(ctx context.Context, store *Store, planID, runID, stepID string, revision, epoch int64) error {
	token, ok := ctx.Value(recoveryCanaryMutationContextKey{}).(recoveryCanaryMutationToken)
	if !ok || token.store != store || token.planID != planID || token.runID != runID || token.stepID != stepID || token.stateRevision != revision || token.recoveryEpoch != epoch {
		return newStoreError(generated.ErrorCodeAuthorizationDenied, "recovery-canary-mutation", false, nil)
	}
	return nil
}

// RecoveryCanaryCheckpointRecord is the independently produced, signed and
// exported checkpoint plus the encrypted payload retained by its outbox.
type RecoveryCanaryCheckpointRecord struct {
	Checkpoint       generated.AuditCheckpoint `json:"checkpoint"`
	ExactPath        string                    `json:"exactPath"`
	EncryptedPayload []byte                    `json:"encryptedPayload"`
	PayloadDigest    string                    `json:"payloadDigest"`
	// CapabilityObservedAt is authenticated by the outer capability response.
	// It is intentionally excluded from the nested checkpoint wire payload.
	CapabilityObservedAt time.Time `json:"-"`
}

// RecordRecoveryCanaryCheckpoint is a narrow server-owned import of an
// independently authenticated checkpoint. It proves the checkpoint covers the
// exact durable noop event before inserting ordinary checkpoint/outbox rows.
func (store *Store) RecordRecoveryCanaryCheckpoint(ctx context.Context, request RecoveryCanaryMutationRequest, startedAt time.Time, record RecoveryCanaryCheckpointRecord) error {
	if err := requireRecoveryCanaryToken(ctx, store, request.PlanID, request.RunID, request.StepID, request.StateRevision, request.RecoveryEpoch); err != nil {
		return err
	}
	eventID, eventAt, err := store.RecoveryCanaryNoopEvent(ctx, request.PlanID, request.RunID)
	if err != nil || eventAt.Before(startedAt) {
		return newStoreError(generated.ErrorCodePrerequisiteBlocked, "recovery-canary-checkpoint", false, err)
	}
	chain, err := store.ChainRange(ctx, audit.EventID(eventID), audit.EventID(eventID))
	cp := record.Checkpoint
	verifiedAt := time.Time{}
	if cp.VerifiedAt != nil {
		verifiedAt, _ = time.Parse(time.RFC3339, *cp.VerifiedAt)
	}
	now := store.config.Clock().UTC()
	raw, marshalErr := json.Marshal(cp)
	payloadSum := sha256.Sum256(record.EncryptedPayload)
	if err != nil || marshalErr != nil || generated.ValidateContractJSON(generated.SchemaIDAuditCheckpoint, raw, generated.ContractExact) != nil ||
		cp.CheckpointID == "" || cp.InstanceID != request.InstanceID || cp.RecoveryEpoch != request.RecoveryEpoch || cp.FirstEventID != eventID || cp.LastEventID != eventID || cp.FirstSegmentSequence != chain.Links[0].SegmentSequence || cp.LastSegmentSequence != chain.Links[0].SegmentSequence || cp.ChainDigest != string(chain.RangeDigest) || cp.Status != "anchored" || cp.VerificationStatus != "verified" || cp.SourceKind != "independent" || cp.ProofClass != "live" || cp.SignatureDigest == nil || cp.PublicKeyID == nil || cp.ExportReceiptDigest == nil || cp.IndependentReadDigest == nil || cp.IndependentCopyDigest == nil || verifiedAt.Before(eventAt) || verifiedAt.Before(startedAt) || record.CapabilityObservedAt.Before(verifiedAt) || record.CapabilityObservedAt.Before(startedAt) || record.CapabilityObservedAt.After(now) || now.Sub(record.CapabilityObservedAt) > 60*time.Second || record.ExactPath == "" || len(record.EncryptedPayload) == 0 || record.PayloadDigest != "sha256:"+hex.EncodeToString(payloadSum[:]) {
		return newStoreError(generated.ErrorCodeIntegrityFailure, "recovery-canary-checkpoint", false, errors.Join(err, marshalErr))
	}
	return store.executeRecoveryCanaryAuditMutation(ctx, request, "recovery-canary-checkpoint", cp.CheckpointID, string(chain.RangeDigest), func(tx *sql.Tx, now string) error {
		if _, err := tx.ExecContext(ctx, `INSERT INTO audit_checkpoints(checkpoint_id,schema_version,instance_id,recovery_epoch,first_event_id,last_event_id,first_segment_sequence,last_segment_sequence,chain_digest,signer_reference_id,signer_material_version,signature_digest,public_key_id,export_namespace,export_receipt_digest,independent_read_digest,status,reason_code,pre_anchor,canonical_bytes,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, cp.CheckpointID, cp.SchemaVersion, cp.InstanceID, cp.RecoveryEpoch, cp.FirstEventID, cp.LastEventID, cp.FirstSegmentSequence, cp.LastSegmentSequence, cp.ChainDigest, cp.SignerReferenceID, cp.SignerMaterialVersion, cp.SignatureDigest, cp.PublicKeyID, record.ExactPath, cp.ExportReceiptDigest, cp.IndependentReadDigest, cp.Status, cp.ReasonCode, cp.PreAnchor, raw, now, now); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, `INSERT INTO audit_checkpoint_outbox(checkpoint_id,exact_path,encrypted_payload,payload_digest,status,attempt_count,last_error_code,next_attempt_at,updated_at) VALUES(?,?,?,?, 'confirmed',1,NULL,NULL,?)`, cp.CheckpointID, record.ExactPath, record.EncryptedPayload, record.PayloadDigest, now)
		return err
	})
}

func (store *Store) executeRecoveryCanaryAuditMutation(ctx context.Context, request RecoveryCanaryMutationRequest, scope, correlationID, digest string, business func(*sql.Tx, string) error) error {
	keySum := sha256.Sum256([]byte(request.PlanID + "\x00" + request.RunID + "\x00" + scope))
	requestSum := sha256.Sum256([]byte(request.PlanDigest + "\x00" + correlationID + "\x00" + digest))
	after := audit.Fingerprint(digest)
	human := "recovery-operator"
	event := audit.EventDraft{Type: "recovery.canary-checkpoint", CorrelationID: correlationID, Attribution: audit.Attribution{AuthenticatedPrincipalID: human, AuthenticatedPrincipalMethod: "recovery-canary", ResponsibleHumanPrincipalID: &human}, Target: audit.Target{Kind: "recovery", ID: request.InstanceID}, After: &after}
	_, err := store.executeAuditIntent(ctx, intentRequest{Idempotency: audit.IntentKey{Scope: scope, KeyDigest: audit.Fingerprint("sha256:" + hex.EncodeToString(keySum[:])), RequestDigest: audit.Fingerprint("sha256:" + hex.EncodeToString(requestSum[:]))}, Event: event, Context: audit.ContextIDs{PlanID: request.PlanID, RunID: request.RunID}}, false, func(_ context.Context, tx *sql.Tx) error {
		return business(tx, store.config.Clock().UTC().Truncate(time.Second).Format(time.RFC3339))
	})
	return err
}

// PrepareRecoveryCanaryBackupPolicy carries the exact source point's immutable
// policy into the new epoch. No caller chooses a policy: the restored point and
// acknowledged restore bundle determine it.
func (repository *BackupRepository) PrepareRecoveryCanaryBackupPolicy(ctx context.Context, request RecoveryCanaryMutationRequest, sourcePointID, sourceManifestDigest string) (generated.BackupPolicy, string, error) {
	var policy generated.BackupPolicy
	if repository == nil || repository.store == nil || sourcePointID == "" || !validBackupDigest(sourceManifestDigest) || requireRecoveryCanaryToken(ctx, repository.store, request.PlanID, request.RunID, request.StepID, request.StateRevision, request.RecoveryEpoch) != nil {
		return policy, "", backupStoreError(generated.ErrorCodeAuthorizationDenied, "recovery-canary-backup-policy")
	}
	var priorJSON, priorDigest, manifestDigest, manifestJSON string
	err := repository.store.Read(ctx, func(tx ReadTx) error {
		return tx.queryRow(ctx, `SELECT d.canonical_json,d.policy_digest,p.manifest_digest,p.manifest_json FROM recovery_points p JOIN backup_policy_drafts d ON d.policy_digest=p.policy_digest AND d.recovery_epoch=p.recovery_epoch WHERE p.point_id=?`, sourcePointID).Scan(&priorJSON, &priorDigest, &manifestDigest, &manifestJSON)
	})
	manifestSum := sha256.Sum256([]byte(manifestJSON))
	var manifest pendingCreationManifest
	if err != nil || manifestDigest != sourceManifestDigest || manifestDigest != "sha256:"+hex.EncodeToString(manifestSum[:]) || json.Unmarshal([]byte(manifestJSON), &manifest) != nil || manifest.PointID != sourcePointID || manifest.PolicyDigest != priorDigest || json.Unmarshal([]byte(priorJSON), &policy) != nil || policy.RepositoryClass == "none" {
		return generated.BackupPolicy{}, "", backupStoreError(generated.ErrorCodeIntegrityFailure, "recovery-canary-backup-policy")
	}
	policy.RecoveryEpoch = request.RecoveryEpoch
	canonical, sum, err := stateexport.CanonicalJSON(policy)
	if err != nil || validateBackupPolicy(policy, request.RecoveryEpoch) != nil {
		return generated.BackupPolicy{}, "", backupStoreError(generated.ErrorCodeIntegrityFailure, "recovery-canary-backup-policy")
	}
	digest := "sha256:" + hex.EncodeToString(sum[:])
	idempotencySum := sha256.Sum256([]byte(request.PlanDigest + "\x00recovery-canary-backup-policy"))
	draftID := "backup-recovery-" + stringsTrimDigest(digest)[:32]
	err = repository.inTx(ctx, func(ctx context.Context, tx *sql.Tx) error {
		var existing string
		scanErr := tx.QueryRowContext(ctx, `SELECT policy_digest FROM backup_policy_drafts WHERE policy_id=? AND revision=? AND recovery_epoch=?`, policy.PolicyID, policy.Revision, request.RecoveryEpoch).Scan(&existing)
		if scanErr == nil {
			if existing != digest {
				return backupStoreError(generated.ErrorCodeStateConflict, "recovery-canary-backup-policy")
			}
			return nil
		}
		if !errors.Is(scanErr, sql.ErrNoRows) {
			return scanErr
		}
		_, insertErr := tx.ExecContext(ctx, `INSERT INTO backup_policy_drafts(draft_id,policy_id,owner_id,repository_class,revision,recovery_epoch,canonical_json,policy_digest,idempotency_key_digest,state_revision,created_by,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`, draftID, policy.PolicyID, policy.OwnerID, policy.RepositoryClass, policy.Revision, request.RecoveryEpoch, string(canonical), digest, "sha256:"+hex.EncodeToString(idempotencySum[:]), request.StateRevision, "recovery-operator", repository.store.config.Clock().UTC().Truncate(time.Second).Format(time.RFC3339))
		return insertErr
	})
	if err != nil {
		return generated.BackupPolicy{}, "", err
	}
	_ = priorDigest
	return policy, digest, nil
}

func stringsTrimDigest(value string) string {
	if len(value) == 71 {
		return value[7:]
	}
	return value
}
