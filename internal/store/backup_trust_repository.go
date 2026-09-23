package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/url"
	"time"

	"github.com/vegastack/vegastack-labs/internal/audit"
	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/stateexport"
)

// BackupTrustSourceDraft is public trust metadata only. Artifact, bundle and
// root bytes remain behind the separately registered ArtifactReader.
type BackupTrustSourceDraft struct {
	SourceID, DependencyID, DependencyKind, ArtifactID                    string
	ArtifactDigest, BundleDigest, TrustedRootReferenceID, TrustRootDigest string
	SignerIdentity, SignerIssuer, Digest                                  string
	Revision, RecoveryEpoch, StateRevision                                int64
	CreatedBy, CreatedAt                                                  string
}

type backupTrustCanonical struct {
	SourceID, DependencyID, DependencyKind, ArtifactID                    string
	ArtifactDigest, BundleDigest, TrustedRootReferenceID, TrustRootDigest string
	SignerIdentity, SignerIssuer                                          string
	Revision, RecoveryEpoch                                               int64
}

// BackupTrustSourceApplyRequest records the exact already-authorized execution
// that makes one inert draft current or revokes it. The run engine remains the
// authority that verifies acknowledgement and lease ownership.
type BackupTrustSourceApplyRequest struct {
	BindingID, SourceID, Status                string
	PlanID, PlanDigest, RunID, StepID, LeaseID string
	DeclarationID                              string
	SourceRevision, DeclarationRevision        int64
	Expected                                   RevisionToken
	Attribution                                audit.Attribution
}

func (repository *BackupRepository) CreateBackupTrustSourceDraft(ctx context.Context, input generated.BackupTrustSourceDraftRequest, attribution audit.Attribution) (BackupTrustSourceDraft, error) {
	var zero BackupTrustSourceDraft
	if repository == nil || repository.store == nil || attribution.AuthenticatedPrincipalID == "" || attribution.AuthenticatedPrincipalMethod == "" ||
		input.Schema != generated.SchemaIDBackupTrustSourceDraftRequest || input.SchemaVersion != "1.0.0" || input.ExpectedStateRevision < 0 || input.RecoveryEpoch < 0 {
		return zero, backupStoreError(generated.ErrorCodeInputInvalid, "backup-trust-source-draft")
	}
	raw, err := json.Marshal(input)
	if err != nil || generated.ValidateContractJSON(generated.SchemaIDBackupTrustSourceDraftRequest, raw, generated.ContractExact) != nil ||
		!validBackupTrustKind(input.DependencyKind) || input.Revision <= 0 {
		return zero, backupStoreError(generated.ErrorCodeInputInvalid, "backup-trust-source-draft")
	}
	for _, id := range []string{input.SourceID, input.DependencyID, input.ArtifactID, input.TrustedRootReferenceID, input.IdempotencyKey} {
		if _, err := credentialref.ParseID(id); err != nil {
			return zero, backupStoreError(generated.ErrorCodeInputInvalid, "backup-trust-source-draft")
		}
	}
	for _, digest := range []string{input.ArtifactDigest, input.BundleDigest, input.TrustRootDigest} {
		if !validBackupDigest(digest) {
			return zero, backupStoreError(generated.ErrorCodeInputInvalid, "backup-trust-source-draft")
		}
	}
	if !validTrustURL(input.SignerIdentity) || !validTrustURL(input.SignerIssuer) {
		return zero, backupStoreError(generated.ErrorCodeInputInvalid, "backup-trust-source-identity")
	}
	canonical, sum, err := stateexport.CanonicalJSON(backupTrustCanonical{
		SourceID: input.SourceID, DependencyID: input.DependencyID, DependencyKind: input.DependencyKind,
		ArtifactID: input.ArtifactID, ArtifactDigest: input.ArtifactDigest, BundleDigest: input.BundleDigest,
		TrustedRootReferenceID: input.TrustedRootReferenceID, TrustRootDigest: input.TrustRootDigest,
		SignerIdentity: input.SignerIdentity, SignerIssuer: input.SignerIssuer,
		Revision: input.Revision, RecoveryEpoch: input.RecoveryEpoch,
	})
	if err != nil {
		return zero, backupStoreError(generated.ErrorCodeInputInvalid, "backup-trust-source-canonical")
	}
	_ = canonical
	digest := "sha256:" + hex.EncodeToString(sum[:])
	key := sha256.Sum256([]byte(input.IdempotencyKey))
	keyDigest := "sha256:" + hex.EncodeToString(key[:])
	if existing, err := repository.getBackupTrustDraftByKey(ctx, keyDigest, input.RecoveryEpoch); err == nil {
		if existing.Digest != digest {
			return zero, backupStoreError(generated.ErrorCodeStateConflict, "backup-trust-source-idempotency")
		}
		return existing, nil
	} else if Code(err) != generated.ErrorCodeResourceNotFound {
		return zero, err
	}

	expected := RevisionToken{StateRevision: input.ExpectedStateRevision, RecoveryEpoch: input.RecoveryEpoch}
	created := repository.store.config.Clock().UTC().Truncate(time.Second)
	after := audit.Fingerprint(digest)
	event := audit.EventDraft{Type: "backup.trust-source-draft-created", CorrelationID: input.SourceID, Attribution: attribution,
		Target: audit.Target{Kind: "backup-trust-source", ID: input.SourceID}, After: &after}
	intentKey := audit.IntentKey{Scope: "backup-trust-source-draft", KeyDigest: audit.Fingerprint(keyDigest), RequestDigest: audit.Fingerprint(digest)}
	intent, err := repository.store.writeIntent(ctx, intentRequest{Expected: &expected, Idempotency: intentKey, Event: event}, func(ctx context.Context, tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO backup_trust_source_drafts(source_id,dependency_id,dependency_kind,artifact_id,artifact_digest,bundle_digest,trusted_root_reference_id,trust_root_digest,signer_identity,signer_issuer,revision,recovery_epoch,source_digest,idempotency_key_digest,state_revision,created_by,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
			input.SourceID, input.DependencyID, input.DependencyKind, input.ArtifactID, input.ArtifactDigest, input.BundleDigest,
			input.TrustedRootReferenceID, input.TrustRootDigest, input.SignerIdentity, input.SignerIssuer, input.Revision,
			input.RecoveryEpoch, digest, keyDigest, expected.StateRevision+1, attribution.AuthenticatedPrincipalID, created.Format(time.RFC3339))
		return err
	})
	if err != nil {
		if existing, lookupErr := repository.getBackupTrustDraftByKey(ctx, keyDigest, input.RecoveryEpoch); lookupErr == nil && existing.Digest == digest {
			return existing, nil
		}
		return zero, err
	}
	return repository.getBackupTrustDraft(ctx, input.SourceID, input.Revision, intent.Commit.RecoveryEpoch)
}

func (repository *BackupRepository) ApplyBackupTrustSource(ctx context.Context, request BackupTrustSourceApplyRequest) (BackupTrustSourceDraft, error) {
	var zero BackupTrustSourceDraft
	if repository == nil || repository.store == nil || request.BindingID == "" || request.SourceID == "" || request.SourceRevision <= 0 ||
		(request.Status != "current" && request.Status != "revoked") || request.Expected.StateRevision < 0 || request.Expected.RecoveryEpoch < 0 ||
		request.DeclarationRevision <= 0 || request.Attribution.AuthenticatedPrincipalID == "" || request.Attribution.AuthenticatedPrincipalMethod == "" ||
		!validBackupDigest(request.PlanDigest) {
		return zero, backupStoreError(generated.ErrorCodeInputInvalid, "backup-trust-source-binding")
	}
	for _, id := range []string{request.BindingID, request.SourceID, request.PlanID, request.RunID, request.StepID, request.LeaseID, request.DeclarationID} {
		if _, err := credentialref.ParseID(id); err != nil {
			return zero, backupStoreError(generated.ErrorCodeInputInvalid, "backup-trust-source-binding")
		}
	}
	draft, err := repository.getBackupTrustDraft(ctx, request.SourceID, request.SourceRevision, request.Expected.RecoveryEpoch)
	if err != nil {
		return zero, err
	}
	now := repository.store.config.Clock().UTC().Truncate(time.Second)
	after := audit.Fingerprint(draft.Digest + ":" + request.Status)
	event := audit.EventDraft{Type: audit.EventType("backup.trust-source-" + request.Status), CorrelationID: request.BindingID, Attribution: request.Attribution,
		Target: audit.Target{Kind: "backup-trust-source", ID: request.SourceID}, After: &after}
	keySum := sha256.Sum256([]byte(request.BindingID + ":" + request.PlanDigest))
	requestSum := sha256.Sum256([]byte(draft.Digest + ":" + request.Status + ":" + request.PlanID + ":" + request.RunID + ":" + request.StepID + ":" + request.LeaseID))
	intentKey := audit.IntentKey{Scope: "backup-trust-source-binding", KeyDigest: audit.Fingerprint("sha256:" + hex.EncodeToString(keySum[:])), RequestDigest: audit.Fingerprint("sha256:" + hex.EncodeToString(requestSum[:]))}
	_, err = repository.store.writeIntent(ctx, intentRequest{Expected: &request.Expected, Idempotency: intentKey, Event: event}, func(ctx context.Context, tx *sql.Tx) error {
		if err := backupTrustExactStep(ctx, tx, request, draft, now.Format(time.RFC3339)); err != nil {
			return err
		}
		var prior int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(1) FROM backup_trust_source_bindings WHERE binding_id=?`, request.BindingID).Scan(&prior); err != nil {
			return err
		}
		if prior != 0 {
			return backupStoreError(generated.ErrorCodeStateConflict, "backup-trust-source-binding")
		}
		_, err := tx.ExecContext(ctx, `INSERT INTO backup_trust_source_bindings(binding_id,source_id,dependency_id,source_revision,status,plan_id,plan_digest,run_id,step_id,lease_id,declaration_id,declaration_revision,state_revision,recovery_epoch,applied_by,applied_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
			request.BindingID, request.SourceID, draft.DependencyID, request.SourceRevision, request.Status, request.PlanID, request.PlanDigest,
			request.RunID, request.StepID, request.LeaseID, request.DeclarationID, request.DeclarationRevision,
			request.Expected.StateRevision+1, request.Expected.RecoveryEpoch, request.Attribution.AuthenticatedPrincipalID, now.Format(time.RFC3339))
		return err
	})
	if err != nil {
		return zero, err
	}
	if request.Status == "revoked" {
		draft.StateRevision = request.Expected.StateRevision + 1
		return draft, nil
	}
	return repository.GetCurrentBackupTrustSource(ctx, request.SourceID, request.SourceRevision, request.Expected.StateRevision+1, request.Expected.RecoveryEpoch)
}

func backupTrustExactStep(ctx context.Context, tx *sql.Tx, request BackupTrustSourceApplyRequest, draft BackupTrustSourceDraft, now string) error {
	operationType := "backup.trust-source.current"
	if request.Status == "revoked" {
		operationType = "backup.trust-source.revoke"
	}
	var count int
	err := tx.QueryRowContext(ctx, `SELECT COUNT(1) FROM immutable_plans p JOIN plan_runs r ON r.plan_id=p.plan_id JOIN plan_run_steps s ON s.run_id=r.run_id JOIN target_execution_leases l ON l.run_id=r.run_id AND l.step_id=s.step_id WHERE p.plan_id=? AND p.plan_digest=? AND p.declaration_id=? AND p.declaration_revision=? AND p.state_revision=? AND p.recovery_epoch=? AND p.expires_at>? AND r.run_id=? AND r.plan_digest=? AND r.state_revision=? AND r.recovery_epoch=? AND r.executor_mode='central' AND r.status='running' AND s.step_id=? AND s.operation_type=? AND s.adapter_id='core.backup-trust' AND s.target_id=? AND s.input_digest=? AND s.artifact_digest=? AND s.effect_state='intent-recorded' AND s.active_lease_id=? AND l.lease_id=? AND l.status='active' AND l.lease_kind='central' AND l.expires_at>? AND l.recovery_epoch=?`, request.PlanID, request.PlanDigest, request.DeclarationID, request.DeclarationRevision, request.Expected.StateRevision, request.Expected.RecoveryEpoch, now, request.RunID, request.PlanDigest, request.Expected.StateRevision, request.Expected.RecoveryEpoch, request.StepID, operationType, draft.SourceID, draft.Digest, draft.Digest, request.LeaseID, request.LeaseID, now, request.Expected.RecoveryEpoch).Scan(&count)
	if err != nil {
		return err
	}
	if count != 1 {
		return backupStoreError(generated.ErrorCodePrerequisiteBlocked, "backup-trust-source-exact-step")
	}
	return nil
}

func (repository *BackupRepository) GetCurrentBackupTrustSource(ctx context.Context, sourceID string, sourceRevision, stateRevision, epoch int64) (BackupTrustSourceDraft, error) {
	draft, err := repository.getBackupTrustDraft(ctx, sourceID, sourceRevision, epoch)
	if err != nil {
		return BackupTrustSourceDraft{}, err
	}
	current, err := repository.currentBackupTrustSource(ctx, draft.DependencyID, stateRevision, epoch)
	if err != nil || current.SourceID != sourceID || current.Revision != sourceRevision {
		return BackupTrustSourceDraft{}, backupStoreError(generated.ErrorCodePrerequisiteBlocked, "backup-trust-source-current")
	}
	return current, nil
}

func (repository *BackupRepository) GetCurrentBackupTrustSourceForDependency(ctx context.Context, dependencyID, kind string, stateRevision, epoch int64) (BackupTrustSourceDraft, error) {
	if !validBackupTrustKind(kind) {
		return BackupTrustSourceDraft{}, backupStoreError(generated.ErrorCodeInputInvalid, "backup-trust-source-current")
	}
	current, err := repository.currentBackupTrustSource(ctx, dependencyID, stateRevision, epoch)
	if err != nil || current.DependencyKind != kind {
		return BackupTrustSourceDraft{}, backupStoreError(generated.ErrorCodePrerequisiteBlocked, "backup-trust-source-current")
	}
	return current, nil
}

func (repository *BackupRepository) currentBackupTrustSource(ctx context.Context, dependencyID string, stateRevision, epoch int64) (BackupTrustSourceDraft, error) {
	if repository == nil || repository.store == nil || dependencyID == "" || stateRevision < 0 || epoch < 0 {
		return BackupTrustSourceDraft{}, backupStoreError(generated.ErrorCodeInputInvalid, "backup-trust-source-current")
	}
	var sourceID, status string
	var sourceRevision, currentRevision, currentEpoch int64
	err := repository.store.Read(ctx, func(tx ReadTx) error {
		if err := tx.queryRow(ctx, `SELECT state_revision,recovery_epoch FROM system_meta WHERE id=1`).Scan(&currentRevision, &currentEpoch); err != nil {
			return err
		}
		return tx.queryRow(ctx, `SELECT source_id,source_revision,status FROM backup_trust_source_bindings WHERE dependency_id=? AND recovery_epoch=? AND state_revision<=? ORDER BY state_revision DESC LIMIT 1`, dependencyID, epoch, stateRevision).Scan(&sourceID, &sourceRevision, &status)
	})
	if errors.Is(err, sql.ErrNoRows) || err == nil && (status != "current" || currentRevision != stateRevision || currentEpoch != epoch) {
		return BackupTrustSourceDraft{}, backupStoreError(generated.ErrorCodePrerequisiteBlocked, "backup-trust-source-current")
	}
	if err != nil {
		return BackupTrustSourceDraft{}, err
	}
	return repository.getBackupTrustDraft(ctx, sourceID, sourceRevision, epoch)
}

func (repository *BackupRepository) getBackupTrustDraftByKey(ctx context.Context, keyDigest string, epoch int64) (BackupTrustSourceDraft, error) {
	return repository.scanBackupTrustDraft(ctx, `WHERE idempotency_key_digest=? AND recovery_epoch=?`, keyDigest, epoch)
}

func (repository *BackupRepository) getBackupTrustDraft(ctx context.Context, sourceID string, revision, epoch int64) (BackupTrustSourceDraft, error) {
	return repository.scanBackupTrustDraft(ctx, `WHERE source_id=? AND revision=? AND recovery_epoch=?`, sourceID, revision, epoch)
}

func (repository *BackupRepository) scanBackupTrustDraft(ctx context.Context, clause string, args ...any) (BackupTrustSourceDraft, error) {
	var value BackupTrustSourceDraft
	err := repository.store.Read(ctx, func(tx ReadTx) error {
		return tx.queryRow(ctx, `SELECT source_id,dependency_id,dependency_kind,artifact_id,artifact_digest,bundle_digest,trusted_root_reference_id,trust_root_digest,signer_identity,signer_issuer,revision,recovery_epoch,source_digest,state_revision,created_by,created_at FROM backup_trust_source_drafts `+clause, args...).Scan(
			&value.SourceID, &value.DependencyID, &value.DependencyKind, &value.ArtifactID, &value.ArtifactDigest, &value.BundleDigest,
			&value.TrustedRootReferenceID, &value.TrustRootDigest, &value.SignerIdentity, &value.SignerIssuer,
			&value.Revision, &value.RecoveryEpoch, &value.Digest, &value.StateRevision, &value.CreatedBy, &value.CreatedAt)
	})
	if errors.Is(err, sql.ErrNoRows) {
		return BackupTrustSourceDraft{}, backupStoreError(generated.ErrorCodeResourceNotFound, "backup-trust-source")
	}
	if err != nil {
		return BackupTrustSourceDraft{}, err
	}
	return value, nil
}

func validBackupTrustKind(kind string) bool {
	return kind == "config" || kind == "image" || kind == "signature"
}

func validTrustURL(value string) bool {
	parsed, err := url.ParseRequestURI(value)
	return err == nil && parsed.Scheme == "https" && parsed.Host != "" && parsed.User == nil && len(value) <= 512
}
