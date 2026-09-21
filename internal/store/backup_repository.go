package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/vegastack/vegastack-labs/internal/audit"
	"github.com/vegastack/vegastack-labs/internal/backupidentity"
	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/stateexport"
)

// BackupRepository owns the inert backup-policy-draft catalog and, for later
// tasks, the append-only pending recovery-point receipts. It never stores a
// plaintext secret, key material, or repository password.
type BackupRepository struct{ store *Store }

func NewBackupRepository(authority *Store) *BackupRepository {
	return &BackupRepository{store: authority}
}

// BackupPolicyDraft is the stored inert canonical policy draft. CanonicalJSON is
// the exact bytes the digest binds; no field carries secret material.
type BackupPolicyDraft struct {
	DraftID          string
	PolicyID         string
	Revision         int64
	RecoveryEpoch    int64
	RepositoryClass  string
	CanonicalJSON    []byte
	Digest           string
	State            string
	CreatedByHumanID string
	CreatedAt        string
	StateRevision    int64
}

func backupStoreError(code, target string) error { return newStoreError(code, target, false, nil) }

// CreateBackupPolicyDraft validates, canonicalizes and durably stores one inert
// backup-policy draft, returning its opaque draft ID and canonical SHA-256
// digest. It activates nothing: no job, point, lease or run is created.
func (repository *BackupRepository) CreateBackupPolicyDraft(ctx context.Context, input generated.BackupPolicyDraftRequest, attribution audit.Attribution) (generated.BackupPolicyDraftSubmission, error) {
	var zero generated.BackupPolicyDraftSubmission
	canonical, policyDigest, err := validateBackupPolicyDraftRequest(input, attribution)
	if err != nil {
		return zero, err
	}
	expected := RevisionToken{StateRevision: input.ExpectedStateRevision, RecoveryEpoch: input.RecoveryEpoch}
	keySum := sha256.Sum256([]byte(input.IdempotencyKey))
	keyDigest := "sha256:" + hex.EncodeToString(keySum[:])
	requestSum := sha256.Sum256(canonical)
	requestDigest := "sha256:" + hex.EncodeToString(requestSum[:])
	draftID := "backup-draft-" + strings.TrimPrefix(policyDigest, "sha256:")[:32]

	lookup := backupDraftLookup{keyDigest: keyDigest, recoveryEpoch: expected.RecoveryEpoch}
	if existing, lookupErr := repository.lookupDraftByKey(ctx, lookup); lookupErr == nil {
		if existing.Digest != policyDigest || existing.DraftID != draftID || existing.PolicyID != input.Policy.PolicyID {
			return zero, backupStoreError(generated.ErrorCodeStateConflict, "backup-policy-draft-idempotency")
		}
		return existing.submission(), nil
	} else if Code(lookupErr) != generated.ErrorCodeResourceNotFound {
		return zero, lookupErr
	}

	createdAt := repository.store.config.Clock().UTC().Truncate(time.Second).Format(time.RFC3339)
	after := audit.Fingerprint(policyDigest)
	event := audit.EventDraft{Type: "backup.policy-draft-created", CorrelationID: draftID, Attribution: attribution, Target: audit.Target{Kind: "backup-policy-draft", ID: draftID}, After: &after}
	key := audit.IntentKey{Scope: "backup-policy-draft", KeyDigest: audit.Fingerprint(keyDigest), RequestDigest: audit.Fingerprint(requestDigest)}
	if audit.ValidateIntentKey(key) != nil || audit.ValidateEventDraft(event) != nil {
		return zero, backupStoreError(generated.ErrorCodeInputInvalid, "backup-policy-draft-audit")
	}

	intent, err := repository.store.writeIntent(ctx, intentRequest{Expected: &expected, Idempotency: key, Event: event}, func(ctx context.Context, tx *sql.Tx) error {
		var existingDigest string
		bindingErr := tx.QueryRowContext(ctx, `SELECT policy_digest FROM backup_policy_drafts WHERE policy_id=? AND revision=? AND recovery_epoch=?`, input.Policy.PolicyID, input.Policy.Revision, expected.RecoveryEpoch).Scan(&existingDigest)
		if bindingErr == nil {
			return backupStoreError(generated.ErrorCodeStateConflict, "backup-policy-draft-binding")
		}
		if !errors.Is(bindingErr, sql.ErrNoRows) {
			return bindingErr
		}
		_, insertErr := tx.ExecContext(ctx, `INSERT INTO backup_policy_drafts(draft_id,policy_id,owner_id,repository_class,revision,recovery_epoch,canonical_json,policy_digest,idempotency_key_digest,state_revision,created_by,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`,
			draftID, input.Policy.PolicyID, input.Policy.OwnerID, input.Policy.RepositoryClass, input.Policy.Revision, expected.RecoveryEpoch, string(canonical), policyDigest, keyDigest, expected.StateRevision+1, attribution.AuthenticatedPrincipalID, createdAt)
		return insertErr
	})
	if err != nil {
		if existing, lookupErr := repository.lookupDraftByKey(ctx, lookup); lookupErr == nil && existing.Digest == policyDigest {
			return existing.submission(), nil
		}
		return zero, err
	}
	if !intent.Created {
		existing, lookupErr := repository.lookupDraftByKey(ctx, lookup)
		if lookupErr != nil || existing.Digest != policyDigest {
			return zero, backupStoreError(generated.ErrorCodeIntegrityFailure, "backup-policy-draft-replay")
		}
		return existing.submission(), nil
	}
	return generated.BackupPolicyDraftSubmission{Schema: generated.SchemaIDBackupPolicyDraftSubmission, SchemaVersion: "1.1.0", DraftID: draftID, PolicyID: input.Policy.PolicyID, PolicyDigest: policyDigest, Status: "draft", StateRevision: intent.Commit.StateRevision, RecoveryEpoch: intent.Commit.RecoveryEpoch}, nil
}

// GetBackupPolicyDraft reads one stored draft by its opaque draft ID.
func (repository *BackupRepository) GetBackupPolicyDraft(ctx context.Context, draftID string) (BackupPolicyDraft, error) {
	if repository == nil || repository.store == nil || draftID == "" {
		return BackupPolicyDraft{}, backupStoreError(generated.ErrorCodeInputInvalid, "backup-policy-draft-lookup")
	}
	return repository.scanDraft(ctx, `WHERE draft_id=?`, draftID)
}

// GetBackupPolicyDraftByDigest reads one stored draft by its canonical policy
// digest at an exact recovery epoch. Planning uses this to resolve an
// x-backup-policy declaration binding to the exact stored canonical bytes.
func (repository *BackupRepository) GetBackupPolicyDraftByDigest(ctx context.Context, digest string, recoveryEpoch int64) (BackupPolicyDraft, error) {
	if repository == nil || repository.store == nil || !validBackupDigest(digest) || recoveryEpoch < 0 {
		return BackupPolicyDraft{}, backupStoreError(generated.ErrorCodeInputInvalid, "backup-policy-draft-lookup")
	}
	return repository.scanDraft(ctx, `WHERE policy_digest=? AND recovery_epoch=?`, digest, recoveryEpoch)
}

type backupDraftLookup struct {
	keyDigest     string
	recoveryEpoch int64
}

func (repository *BackupRepository) lookupDraftByKey(ctx context.Context, lookup backupDraftLookup) (BackupPolicyDraft, error) {
	if !validBackupDigest(lookup.keyDigest) || lookup.recoveryEpoch < 0 {
		return BackupPolicyDraft{}, backupStoreError(generated.ErrorCodeInputInvalid, "backup-policy-draft-lookup")
	}
	return repository.scanDraft(ctx, `WHERE idempotency_key_digest=? AND recovery_epoch=?`, lookup.keyDigest, lookup.recoveryEpoch)
}

func (repository *BackupRepository) scanDraft(ctx context.Context, clause string, arguments ...any) (BackupPolicyDraft, error) {
	var value BackupPolicyDraft
	var canonical, ownerID string
	err := repository.store.Read(ctx, func(tx ReadTx) error {
		return tx.queryRow(ctx, `SELECT draft_id,policy_id,owner_id,repository_class,revision,recovery_epoch,canonical_json,policy_digest,state_revision,created_by,created_at FROM backup_policy_drafts `+clause, arguments...).Scan(
			&value.DraftID, &value.PolicyID, &ownerID, &value.RepositoryClass, &value.Revision, &value.RecoveryEpoch, &canonical, &value.Digest, &value.StateRevision, &value.CreatedByHumanID, &value.CreatedAt)
	})
	_ = ownerID
	if errors.Is(err, sql.ErrNoRows) {
		return BackupPolicyDraft{}, backupStoreError(generated.ErrorCodeResourceNotFound, "backup-policy-draft")
	}
	if err != nil {
		return BackupPolicyDraft{}, err
	}
	value.CanonicalJSON = []byte(canonical)
	value.State = "draft"
	if !validBackupDigest(value.Digest) || value.Revision <= 0 || value.StateRevision <= 0 {
		return BackupPolicyDraft{}, backupStoreError(generated.ErrorCodeIntegrityFailure, "backup-policy-draft")
	}
	// The stored canonical bytes must reproduce the bound digest exactly.
	sum := sha256.Sum256(value.CanonicalJSON)
	if "sha256:"+hex.EncodeToString(sum[:]) != value.Digest {
		return BackupPolicyDraft{}, backupStoreError(generated.ErrorCodeIntegrityFailure, "backup-policy-draft-digest")
	}
	return value, nil
}

func (draft BackupPolicyDraft) submission() generated.BackupPolicyDraftSubmission {
	return generated.BackupPolicyDraftSubmission{Schema: generated.SchemaIDBackupPolicyDraftSubmission, SchemaVersion: "1.1.0", DraftID: draft.DraftID, PolicyID: draft.PolicyID, PolicyDigest: draft.Digest, Status: "draft", StateRevision: draft.StateRevision, RecoveryEpoch: draft.RecoveryEpoch}
}

// validateBackupPolicyDraftRequest enforces the contract, request-level and
// cross-field policy rules, returning the canonical policy bytes and digest.
func validateBackupPolicyDraftRequest(input generated.BackupPolicyDraftRequest, attribution audit.Attribution) ([]byte, string, error) {
	if input.Schema != generated.SchemaIDBackupPolicyDraftRequest || input.SchemaVersion != "1.1.0" ||
		input.ExpectedStateRevision < 0 || input.RecoveryEpoch < 0 ||
		attribution.AuthenticatedPrincipalID == "" || attribution.AuthenticatedPrincipalMethod == "" {
		return nil, "", backupStoreError(generated.ErrorCodeInputInvalid, "backup-policy-draft-request")
	}
	if _, err := credentialref.ParseID(input.IdempotencyKey); err != nil {
		return nil, "", backupStoreError(generated.ErrorCodeInputInvalid, "backup-policy-draft-request")
	}
	marshaled, err := json.Marshal(input)
	if err != nil || generated.ValidateContractJSON(generated.SchemaIDBackupPolicyDraftRequest, marshaled, generated.ContractExact) != nil {
		return nil, "", backupStoreError(generated.ErrorCodeInputInvalid, "backup-policy-draft-contract")
	}
	if err := validateBackupPolicy(input.Policy, input.RecoveryEpoch); err != nil {
		return nil, "", err
	}
	canonical, sum, err := stateexport.CanonicalJSON(input.Policy)
	if err != nil {
		return nil, "", backupStoreError(generated.ErrorCodeInputInvalid, "backup-policy-draft-canonical")
	}
	policyDigest := "sha256:" + hex.EncodeToString(sum[:])
	if input.TargetDigest != policyDigest {
		return nil, "", backupStoreError(generated.ErrorCodeInputInvalid, "backup-policy-draft-target")
	}
	return canonical, policyDigest, nil
}

// validateBackupPolicy enforces the cross-field policy invariants the field-level
// schema cannot express. `none` means unsupported mutable-data recovery: no
// repository, no keys, no retention. `standard`/`critical` require a repository,
// both key references and positive retention.
func validateBackupPolicy(policy generated.BackupPolicy, recoveryEpoch int64) error {
	if policy.Schema != generated.SchemaIDBackupPolicy || policy.SchemaVersion != "1.1.0" || policy.Revision <= 0 || policy.RecoveryEpoch != recoveryEpoch {
		return backupStoreError(generated.ErrorCodeInputInvalid, "backup-policy")
	}
	for _, id := range []string{policy.PolicyID, policy.OwnerID, policy.SourceID, policy.ConsistencyHookID, policy.RestoreTargetID} {
		if _, err := credentialref.ParseID(id); err != nil {
			return backupStoreError(generated.ErrorCodeInputInvalid, "backup-policy-id")
		}
	}
	if len(policy.SourceSelectors) == 0 || len(policy.SourceSelectors) > 64 {
		return backupStoreError(generated.ErrorCodeInputInvalid, "backup-policy-selectors")
	}
	selectors := map[string]struct{}{}
	for _, selector := range policy.SourceSelectors {
		if _, err := credentialref.ParseID(selector); err != nil {
			return backupStoreError(generated.ErrorCodeInputInvalid, "backup-policy-selectors")
		}
		if _, seen := selectors[selector]; seen {
			return backupStoreError(generated.ErrorCodeInputInvalid, "backup-policy-selectors")
		}
		selectors[selector] = struct{}{}
	}
	dependencies := map[string]struct{}{}
	for _, dependency := range policy.Dependencies {
		if _, err := credentialref.ParseID(dependency.DependencyID); err != nil || !validBackupDigest(dependency.Digest) {
			return backupStoreError(generated.ErrorCodeInputInvalid, "backup-policy-dependency")
		}
		if _, seen := dependencies[dependency.DependencyID]; seen {
			return backupStoreError(generated.ErrorCodeInputInvalid, "backup-policy-dependency")
		}
		dependencies[dependency.DependencyID] = struct{}{}
	}
	if policy.ExpectedBytes < 0 || policy.ExpectedGrowthBytes < 0 || policy.MinimumFreeBytes < 0 {
		return backupStoreError(generated.ErrorCodeInputInvalid, "backup-policy-forecast")
	}
	switch policy.RepositoryClass {
	case "none":
		if policy.RepositoryID != nil || policy.EncryptionKeyReferenceID != nil || policy.RecoveryKeyReferenceID != nil || policy.RetentionDays != 0 {
			return backupStoreError(generated.ErrorCodeInputInvalid, "backup-policy-none")
		}
	case "standard", "critical":
		if policy.RepositoryID == nil || policy.EncryptionKeyReferenceID == nil || policy.RecoveryKeyReferenceID == nil || policy.RetentionDays <= 0 {
			return backupStoreError(generated.ErrorCodeInputInvalid, "backup-policy-class")
		}
		if !backupidentity.Registered(policy.SourceID, policy.SourceSelectors, policy.RepositoryClass, policy.RepositoryID) {
			return backupStoreError(generated.ErrorCodeInputInvalid, "backup-policy-identity")
		}
		for _, id := range []string{*policy.RepositoryID, *policy.EncryptionKeyReferenceID, *policy.RecoveryKeyReferenceID} {
			if _, err := credentialref.ParseID(id); err != nil {
				return backupStoreError(generated.ErrorCodeInputInvalid, "backup-policy-reference")
			}
		}
	default:
		return backupStoreError(generated.ErrorCodeInputInvalid, "backup-policy-class")
	}
	return nil
}

func validBackupDigest(value string) bool {
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
