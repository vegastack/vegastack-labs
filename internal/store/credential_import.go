package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/vegastack/vegastack-labs/internal/audit"
	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/generated"
)

type CredentialImportDraftRequest struct {
	Input                                          generated.CredentialImportRequest
	DraftID, CiphertextName, CiphertextFingerprint string
	Expected                                       RevisionToken
	Attribution                                    audit.Attribution
	KeyDigest, RequestDigest                       string
}

type CredentialImportLookup struct {
	KeyDigest     string
	RecoveryEpoch int64
}

type CredentialImportDraft struct {
	DraftID, ReferenceID, ConsumerID, PurposeID, TargetID, ResolverID string
	MaterialVersion, KeyDigest, RequestDigest, TargetDigest           string
	CiphertextName, CiphertextFingerprint                             string
	StateRevision, RecoveryEpoch                                      int64
	CreatedBy, CreatedAt                                              string
}

func (repository *CredentialRepository) PutImportDraft(ctx context.Context, request CredentialImportDraftRequest) (generated.CredentialImportSubmission, error) {
	var zero generated.CredentialImportSubmission
	if err := validateCredentialImportDraftRequest(repository, request); err != nil {
		return zero, err
	}
	lookup := CredentialImportLookup{KeyDigest: request.KeyDigest, RecoveryEpoch: request.Expected.RecoveryEpoch}
	if existing, err := repository.LookupImportDraft(ctx, lookup); err == nil {
		if !credentialImportDraftMatches(existing, request) {
			return zero, credentialStoreError(generated.ErrorCodeStateConflict, "credential-import-idempotency")
		}
		return existing.submission(), nil
	} else if Code(err) != generated.ErrorCodeResourceNotFound {
		return zero, err
	}

	createdAt := repository.store.config.Clock().UTC().Truncate(time.Second).Format(time.RFC3339)
	after := audit.Fingerprint(request.CiphertextFingerprint)
	event := audit.EventDraft{Type: "credential.import-draft-created", CorrelationID: request.DraftID, Attribution: request.Attribution, Target: audit.Target{Kind: "credential-import-draft", ID: request.DraftID}, After: &after}
	key := audit.IntentKey{Scope: "credential-import-draft", KeyDigest: audit.Fingerprint(request.KeyDigest), RequestDigest: audit.Fingerprint(request.RequestDigest)}
	intent, err := repository.store.writeIntent(ctx, intentRequest{Expected: &request.Expected, Idempotency: key, Event: event}, func(ctx context.Context, tx *sql.Tx) error {
		var existingKey string
		bindingErr := tx.QueryRowContext(ctx, `SELECT idempotency_key_digest FROM credential_import_drafts WHERE reference_id=? AND consumer_id=? AND material_version=? AND recovery_epoch=?`, request.Input.ReferenceID, request.Input.ConsumerID, request.Input.MaterialVersion, request.Expected.RecoveryEpoch).Scan(&existingKey)
		if bindingErr == nil {
			return credentialStoreError(generated.ErrorCodeStateConflict, "credential-import-binding")
		}
		if !errors.Is(bindingErr, sql.ErrNoRows) {
			return bindingErr
		}
		_, insertErr := tx.ExecContext(ctx, `INSERT INTO credential_import_drafts(draft_id,reference_id,consumer_id,purpose_id,target_id,resolver_id,material_version,idempotency_key_digest,request_digest,target_digest,ciphertext_name,ciphertext_fingerprint,state_revision,recovery_epoch,created_by,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
			request.DraftID, request.Input.ReferenceID, request.Input.ConsumerID, request.Input.PurposeID, request.Input.TargetID, request.Input.ResolverID, request.Input.MaterialVersion,
			request.KeyDigest, request.RequestDigest, request.Input.TargetDigest, request.CiphertextName, request.CiphertextFingerprint, request.Expected.StateRevision+1, request.Expected.RecoveryEpoch, request.Attribution.AuthenticatedPrincipalID, createdAt)
		return insertErr
	})
	if err != nil {
		if existing, lookupErr := repository.LookupImportDraft(ctx, lookup); lookupErr == nil && credentialImportDraftMatches(existing, request) {
			return existing.submission(), nil
		}
		return zero, err
	}
	if !intent.Created {
		existing, lookupErr := repository.LookupImportDraft(ctx, lookup)
		if lookupErr != nil || !credentialImportDraftMatches(existing, request) {
			return zero, credentialStoreError(generated.ErrorCodeIntegrityFailure, "credential-import-replay")
		}
		return existing.submission(), nil
	}
	return generated.CredentialImportSubmission{Schema: generated.SchemaIDCredentialImportSubmission, SchemaVersion: "1.1.0", DraftID: request.DraftID, ReferenceID: request.Input.ReferenceID, CiphertextFingerprint: request.CiphertextFingerprint, Status: "draft", StateRevision: intent.Commit.StateRevision, RecoveryEpoch: intent.Commit.RecoveryEpoch}, nil
}

func validateCredentialImportDraftRequest(repository *CredentialRepository, request CredentialImportDraftRequest) error {
	if repository == nil || repository.store == nil || request.Input.ExpectedStateRevision != request.Expected.StateRevision || request.Input.RecoveryEpoch != request.Expected.RecoveryEpoch || request.Expected.StateRevision < 0 || request.Expected.RecoveryEpoch < 0 || request.Attribution.AuthenticatedPrincipalMethod != "local-os-peer" || request.Attribution.AuthenticatedPrincipalID == "" {
		return credentialStoreError(generated.ErrorCodeInputInvalid, "credential-import-draft")
	}
	for _, id := range []string{request.DraftID, request.CiphertextName, request.Input.IdempotencyKey, request.Input.ReferenceID, request.Input.ConsumerID, request.Input.PurposeID, request.Input.TargetID, request.Input.ResolverID, request.Input.MaterialVersion} {
		if _, err := credentialref.ParseID(id); err != nil {
			return credentialStoreError(generated.ErrorCodeInputInvalid, "credential-import-id")
		}
	}
	if request.Input.ResolverID != "native-systemd" || request.Input.TargetDigest != credentialref.ImportTargetDigest(request.Input) || !validImportFingerprint(request.KeyDigest) || !validImportFingerprint(request.RequestDigest) || !validImportFingerprint(request.CiphertextFingerprint) {
		return credentialStoreError(generated.ErrorCodeInputInvalid, "credential-import-binding")
	}
	metadata, err := json.Marshal(request.Input)
	if err != nil || generated.ValidateContractJSON(generated.SchemaIDCredentialImportRequest, metadata, generated.ContractExact) != nil {
		return credentialStoreError(generated.ErrorCodeInputInvalid, "credential-import-contract")
	}
	key := audit.IntentKey{Scope: "credential-import-draft", KeyDigest: audit.Fingerprint(request.KeyDigest), RequestDigest: audit.Fingerprint(request.RequestDigest)}
	after := audit.Fingerprint(request.CiphertextFingerprint)
	event := audit.EventDraft{Type: "credential.import-draft-created", CorrelationID: request.DraftID, Attribution: request.Attribution, Target: audit.Target{Kind: "credential-import-draft", ID: request.DraftID}, After: &after}
	if audit.ValidateIntentKey(key) != nil || audit.ValidateEventDraft(event) != nil {
		return credentialStoreError(generated.ErrorCodeInputInvalid, "credential-import-audit")
	}
	return nil
}

func (repository *CredentialRepository) LookupImportDraft(ctx context.Context, lookup CredentialImportLookup) (CredentialImportDraft, error) {
	var value CredentialImportDraft
	if repository == nil || repository.store == nil || lookup.RecoveryEpoch < 0 || !validImportFingerprint(lookup.KeyDigest) {
		return value, credentialStoreError(generated.ErrorCodeInputInvalid, "credential-import-lookup")
	}
	err := repository.store.Read(ctx, func(tx ReadTx) error {
		return tx.queryRow(ctx, `SELECT draft_id,reference_id,consumer_id,purpose_id,target_id,resolver_id,material_version,idempotency_key_digest,request_digest,target_digest,ciphertext_name,ciphertext_fingerprint,state_revision,recovery_epoch,created_by,created_at FROM credential_import_drafts WHERE idempotency_key_digest=? AND recovery_epoch=?`, lookup.KeyDigest, lookup.RecoveryEpoch).Scan(
			&value.DraftID, &value.ReferenceID, &value.ConsumerID, &value.PurposeID, &value.TargetID, &value.ResolverID, &value.MaterialVersion, &value.KeyDigest, &value.RequestDigest, &value.TargetDigest, &value.CiphertextName, &value.CiphertextFingerprint, &value.StateRevision, &value.RecoveryEpoch, &value.CreatedBy, &value.CreatedAt)
	})
	if errors.Is(err, sql.ErrNoRows) {
		return CredentialImportDraft{}, credentialStoreError(generated.ErrorCodeResourceNotFound, "credential-import-draft")
	}
	if err != nil {
		return CredentialImportDraft{}, err
	}
	if value.KeyDigest != lookup.KeyDigest || value.RecoveryEpoch != lookup.RecoveryEpoch || value.StateRevision <= 0 || !validImportFingerprint(value.RequestDigest) || !validImportFingerprint(value.TargetDigest) || !validImportFingerprint(value.CiphertextFingerprint) {
		return CredentialImportDraft{}, credentialStoreError(generated.ErrorCodeIntegrityFailure, "credential-import-draft")
	}
	return value, nil
}

func (draft CredentialImportDraft) submission() generated.CredentialImportSubmission {
	return generated.CredentialImportSubmission{Schema: generated.SchemaIDCredentialImportSubmission, SchemaVersion: "1.1.0", DraftID: draft.DraftID, ReferenceID: draft.ReferenceID, CiphertextFingerprint: draft.CiphertextFingerprint, Status: "draft", StateRevision: draft.StateRevision, RecoveryEpoch: draft.RecoveryEpoch}
}

func credentialImportDraftMatches(draft CredentialImportDraft, request CredentialImportDraftRequest) bool {
	return draft.DraftID == request.DraftID && draft.ReferenceID == request.Input.ReferenceID && draft.ConsumerID == request.Input.ConsumerID && draft.PurposeID == request.Input.PurposeID && draft.TargetID == request.Input.TargetID && draft.ResolverID == request.Input.ResolverID && draft.MaterialVersion == request.Input.MaterialVersion && draft.KeyDigest == request.KeyDigest && draft.RequestDigest == request.RequestDigest && draft.TargetDigest == request.Input.TargetDigest && draft.CiphertextName == request.CiphertextName && draft.CiphertextFingerprint == request.CiphertextFingerprint && draft.RecoveryEpoch == request.Expected.RecoveryEpoch
}

func validImportFingerprint(value string) bool {
	if len(value) != 71 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	for _, character := range strings.TrimPrefix(value, "sha256:") {
		if !strings.ContainsRune("0123456789abcdef", character) {
			return false
		}
	}
	return true
}
