package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"
	"time"

	"github.com/vegastack/vegastack-labs/internal/audit"
	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/generated"
)

// draftLifecycleDigest reads the sealed x-credential-lifecycle extension digest.
func draftLifecycleDigest(extensions []generated.ContractExtension) string {
	for _, extension := range extensions {
		if extension.Name == "x-credential-lifecycle" {
			return extension.ValueDigest
		}
	}
	return ""
}

// CredentialLifecycleDraftRequest stages one inert lifecycle binding whose exact
// digest was already sealed into a committed-inert declaration draft's
// x-credential-lifecycle extension. It changes no credential status.
type CredentialLifecycleDraftRequest struct {
	DeclarationID       string
	DeclarationRevision int64
	Binding             credentialref.LifecycleBinding
	Expected            RevisionToken
	Attribution         audit.Attribution
	KeyDigest           string
	RequestDigest       string
}

// CredentialLifecycleDraft is the inert result of persisting one lifecycle
// binding. It carries only metadata.
type CredentialLifecycleDraft struct {
	OperationID   string
	ReferenceID   string
	Action        credentialref.LifecycleAction
	BindingDigest string
	StateRevision int64
	RecoveryEpoch int64
}

// PutLifecycleDraft persists one inert lifecycle binding for a declaration draft
// whose single core.credential operation seals the binding digest. It never
// changes credential status and never reads credential material.
func (repository *CredentialRepository) PutLifecycleDraft(ctx context.Context, request CredentialLifecycleDraftRequest) (CredentialLifecycleDraft, error) {
	var zero CredentialLifecycleDraft
	if repository == nil || repository.store == nil || request.DeclarationRevision <= 0 || credentialHuman(request.Attribution) == "" {
		return zero, credentialStoreError(generated.ErrorCodeInputInvalid, "credential-lifecycle")
	}
	if _, err := credentialref.ParseID(request.DeclarationID); err != nil {
		return zero, credentialStoreError(generated.ErrorCodeInputInvalid, "credential-declaration")
	}
	binding := request.Binding
	if !credentialref.ValidLifecycleBinding(binding) || binding.RecoveryEpoch != request.Expected.RecoveryEpoch {
		return zero, credentialStoreError(generated.ErrorCodeInputInvalid, "credential-lifecycle-binding")
	}
	digest := credentialref.LifecycleManifestDigestOf(binding)
	if digest == "" {
		return zero, credentialStoreError(generated.ErrorCodeInputInvalid, "credential-lifecycle-binding")
	}
	draft, err := NewDeclarationRepository(repository.store).GetRevision(ctx, request.DeclarationID, request.DeclarationRevision)
	if err != nil {
		return zero, err
	}
	if draft.Status != "draft" || draft.StateRevision != request.Expected.StateRevision || draft.RecoveryEpoch != request.Expected.RecoveryEpoch || draftLifecycleDigest(draft.Extensions) != digest {
		return zero, credentialStoreError(generated.ErrorCodePrerequisiteBlocked, "credential-lifecycle-unbound")
	}
	var operation *generated.DeclarationOperation
	for index := range draft.Operations {
		if draft.Operations[index].OperationID == binding.OperationID {
			operation = &draft.Operations[index]
			break
		}
	}
	// The lifecycle binding is sealed in the x-credential-lifecycle extension
	// (checked above). The single core.credential operation binds input and
	// artifact digests to the exact ciphertext fingerprint, matching the exact
	// run step the append later requires.
	if operation == nil || operation.AdapterID != "core.credential" || operation.TargetID != binding.TargetID || operation.InputDigest != binding.CiphertextFingerprint || operation.ArtifactDigest != binding.CiphertextFingerprint || len(draft.Operations) != 1 {
		return zero, credentialStoreError(generated.ErrorCodeInputInvalid, "credential-lifecycle-operation")
	}
	body, encodeErr := json.Marshal(binding)
	if encodeErr != nil || len(body) > 4096 {
		return zero, credentialStoreError(generated.ErrorCodeInputInvalid, "credential-lifecycle-binding")
	}
	key := audit.IntentKey{Scope: "credential-lifecycle-stage", KeyDigest: audit.Fingerprint(request.KeyDigest), RequestDigest: audit.Fingerprint(request.RequestDigest)}
	after := audit.Fingerprint(digest)
	event := audit.EventDraft{Type: "credential.lifecycle-staged", CorrelationID: request.DeclarationID, Attribution: request.Attribution, Target: audit.Target{Kind: "credential-lifecycle", ID: request.DeclarationID}, After: &after}
	if audit.ValidateIntentKey(key) != nil || audit.ValidateEventDraft(event) != nil {
		return zero, credentialStoreError(generated.ErrorCodeInputInvalid, "credential-lifecycle-audit")
	}
	created := repository.store.config.Clock().UTC().Truncate(time.Second).Format(time.RFC3339)
	id := credentialBindingID(request.DeclarationID, request.DeclarationRevision, digest)
	_, err = repository.store.writeIntent(ctx, intentRequest{Expected: &request.Expected, Idempotency: key, Event: event}, func(ctx context.Context, tx *sql.Tx) error {
		_, executeErr := tx.ExecContext(ctx, `INSERT INTO credential_lifecycle_bindings(binding_id,declaration_id,declaration_revision,operation_id,action,reference_id,binding_digest,binding_bytes,recovery_epoch,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)`, id, request.DeclarationID, request.DeclarationRevision, binding.OperationID, string(binding.Action), binding.ReferenceID, digest, body, binding.RecoveryEpoch, created)
		return executeErr
	})
	if err != nil {
		return zero, err
	}
	return CredentialLifecycleDraft{OperationID: binding.OperationID, ReferenceID: binding.ReferenceID, Action: binding.Action, BindingDigest: digest, StateRevision: request.Expected.StateRevision, RecoveryEpoch: binding.RecoveryEpoch}, nil
}

// GetLifecycleBinding reads the single lifecycle binding sealed into one exact
// committed plan's core.credential operation. It mirrors GetStepBindings: the
// stored plan, committed declaration and persisted binding bytes must all agree.
func (repository *CredentialRepository) GetLifecycleBinding(ctx context.Context, plan generated.Plan, operationID string) (credentialref.LifecycleBinding, error) {
	var zero credentialref.LifecycleBinding
	if repository == nil || repository.store == nil || plan.PlanID == "" || plan.PlanDigest == "" || plan.DeclarationID == "" || plan.Binding.DeclarationRevision <= 0 || operationID == "" {
		return zero, credentialStoreError(generated.ErrorCodeInputInvalid, "credential-lifecycle-step")
	}
	extensionDigest := draftLifecycleDigest(plan.Extensions)
	if extensionDigest == "" || plan.ExecutorMode != "central" {
		return zero, credentialStoreError(generated.ErrorCodePrerequisiteBlocked, "credential-lifecycle-uncommitted")
	}
	stored, err := NewPlanRepository(repository.store).GetPlan(ctx, plan.PlanID)
	if err != nil {
		return zero, credentialStoreError(generated.ErrorCodePrerequisiteBlocked, "credential-lifecycle-plan-uncommitted")
	}
	canonical, err := json.Marshal(plan)
	if err != nil || string(canonical) != string(stored.Canonical) {
		return zero, credentialStoreError(generated.ErrorCodeIntegrityFailure, "credential-lifecycle-plan-mismatch")
	}
	committed, err := NewDeclarationRepository(repository.store).GetRevision(ctx, plan.DeclarationID, plan.Binding.DeclarationRevision)
	if err != nil || committed.Status != "committed" || draftLifecycleDigest(committed.Extensions) != extensionDigest || committed.StateRevision != plan.Binding.StateRevision || committed.RecoveryEpoch != plan.Binding.RecoveryEpoch {
		return zero, credentialStoreError(generated.ErrorCodePrerequisiteBlocked, "credential-lifecycle-declaration-uncommitted")
	}
	var (
		digest string
		raw    []byte
		epoch  int64
	)
	err = repository.store.Read(ctx, func(tx ReadTx) error {
		return tx.queryRow(ctx, `SELECT binding_digest,binding_bytes,recovery_epoch FROM credential_lifecycle_bindings WHERE declaration_id=? AND declaration_revision=? AND operation_id=? ORDER BY binding_id LIMIT 1`, plan.DeclarationID, plan.Binding.DeclarationRevision-1, operationID).Scan(&digest, &raw, &epoch)
	})
	if errors.Is(err, sql.ErrNoRows) {
		return zero, credentialStoreError(generated.ErrorCodePrerequisiteBlocked, "credential-lifecycle-uncommitted")
	}
	if err != nil {
		return zero, err
	}
	var binding credentialref.LifecycleBinding
	// PutLifecycleDraft seals the single-member manifest, not its domain-separated
	// member digest. Validate the persisted bytes under that same manifest domain.
	if len(raw) > 4096 || json.Unmarshal(raw, &binding) != nil || credentialref.LifecycleManifestDigestOf(binding) != digest || binding.RecoveryEpoch != epoch {
		return zero, credentialStoreError(generated.ErrorCodeIntegrityFailure, "credential-lifecycle-binding")
	}
	if credentialref.LifecycleManifestDigestOf(binding) != extensionDigest || binding.OperationID != operationID {
		return zero, credentialStoreError(generated.ErrorCodePrerequisiteBlocked, "credential-lifecycle-uncommitted")
	}
	if binding.StateRevision != plan.Binding.StateRevision || binding.RecoveryEpoch != plan.Binding.RecoveryEpoch {
		return zero, credentialStoreError(generated.ErrorCodePlanStale, "credential-lifecycle-binding")
	}
	var operation *generated.PlanOperation
	for index := range plan.Operations {
		if plan.Operations[index].OperationID == operationID {
			operation = &plan.Operations[index]
			break
		}
	}
	if operation == nil || operation.AdapterID != "core.credential" || operation.TargetID != binding.TargetID || operation.InputDigest != binding.CiphertextFingerprint || operation.ArtifactDigest != binding.CiphertextFingerprint {
		return zero, credentialStoreError(generated.ErrorCodeIntegrityFailure, "credential-lifecycle-binding")
	}
	return binding, nil
}

// GetCredentialVersion returns the latest version row for one reference and
// material version. It exposes metadata and status only.
func (repository *CredentialRepository) GetCredentialVersion(ctx context.Context, referenceID, materialVersion string) (generated.CredentialReference, error) {
	if repository == nil || repository.store == nil {
		return generated.CredentialReference{}, credentialStoreError(generated.ErrorCodeInputInvalid, "credential-reference")
	}
	if _, err := credentialref.ParseID(referenceID); err != nil {
		return generated.CredentialReference{}, credentialStoreError(generated.ErrorCodeInputInvalid, "credential-reference")
	}
	if _, err := credentialref.ParseID(materialVersion); err != nil {
		return generated.CredentialReference{}, credentialStoreError(generated.ErrorCodeInputInvalid, "credential-material")
	}
	var result generated.CredentialReference
	var verified []byte
	err := repository.store.Read(ctx, func(tx ReadTx) error {
		return tx.queryRow(ctx, `SELECT reference_id,consumer_id,purpose_id,target_id,resolver_id,material_version,fingerprint,status,state_revision,recovery_epoch,activated_at,verified_consumers_bytes FROM credential_reference_versions WHERE reference_id=? AND material_version=? ORDER BY state_revision DESC,version_id DESC LIMIT 1`, referenceID, materialVersion).Scan(&result.ReferenceID, &result.ConsumerID, &result.PurposeID, &result.TargetID, &result.ResolverID, &result.MaterialVersion, &result.Fingerprint, &result.Status, &result.StateRevision, &result.RecoveryEpoch, &result.ActivatedAt, &verified)
	})
	if errors.Is(err, sql.ErrNoRows) {
		return generated.CredentialReference{}, credentialStoreError(generated.ErrorCodeResourceNotFound, "credential-version")
	}
	if err != nil {
		return generated.CredentialReference{}, err
	}
	result.Schema, result.SchemaVersion = generated.SchemaIDCredentialReference, "1.1.0"
	if json.Unmarshal(verified, &result.VerifiedConsumerIDs) != nil {
		return generated.CredentialReference{}, credentialStoreError(generated.ErrorCodeIntegrityFailure, "credential-version")
	}
	return result, nil
}

// ListCredentialVersions returns every version row for one reference in one
// recovery epoch, oldest first. Metadata and status only.
func (repository *CredentialRepository) ListCredentialVersions(ctx context.Context, referenceID string, recoveryEpoch int64) ([]generated.CredentialReference, error) {
	if repository == nil || repository.store == nil || recoveryEpoch < 0 {
		return nil, credentialStoreError(generated.ErrorCodeInputInvalid, "credential-reference")
	}
	if _, err := credentialref.ParseID(referenceID); err != nil {
		return nil, credentialStoreError(generated.ErrorCodeInputInvalid, "credential-reference")
	}
	var versions []generated.CredentialReference
	err := repository.store.Read(ctx, func(tx ReadTx) error {
		rows, queryErr := tx.query(ctx, `SELECT reference_id,consumer_id,purpose_id,target_id,resolver_id,material_version,fingerprint,status,state_revision,recovery_epoch,activated_at,verified_consumers_bytes FROM credential_reference_versions WHERE reference_id=? AND recovery_epoch=? ORDER BY state_revision ASC,version_id ASC`, referenceID, recoveryEpoch)
		if queryErr != nil {
			return queryErr
		}
		defer rows.Close()
		for rows.Next() {
			var value generated.CredentialReference
			var verified []byte
			if scanErr := rows.Scan(&value.ReferenceID, &value.ConsumerID, &value.PurposeID, &value.TargetID, &value.ResolverID, &value.MaterialVersion, &value.Fingerprint, &value.Status, &value.StateRevision, &value.RecoveryEpoch, &value.ActivatedAt, &verified); scanErr != nil {
				return scanErr
			}
			value.Schema, value.SchemaVersion = generated.SchemaIDCredentialReference, "1.1.0"
			if json.Unmarshal(verified, &value.VerifiedConsumerIDs) != nil {
				return credentialStoreError(generated.ErrorCodeIntegrityFailure, "credential-version")
			}
			versions = append(versions, value)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return versions, nil
}

// LookupImportDraftByReference returns the single inert import draft for one
// reference, material version and recovery epoch. It fails closed when no draft
// or more than one draft matches, so an ambiguous owning consumer never silently
// selects an identity. It exposes metadata only.
func (repository *CredentialRepository) LookupImportDraftByReference(ctx context.Context, referenceID, materialVersion string, recoveryEpoch int64) (CredentialImportDraft, error) {
	if repository == nil || repository.store == nil || recoveryEpoch < 0 {
		return CredentialImportDraft{}, credentialStoreError(generated.ErrorCodeInputInvalid, "credential-import-draft")
	}
	if _, err := credentialref.ParseID(referenceID); err != nil {
		return CredentialImportDraft{}, credentialStoreError(generated.ErrorCodeInputInvalid, "credential-import-draft")
	}
	if _, err := credentialref.ParseID(materialVersion); err != nil {
		return CredentialImportDraft{}, credentialStoreError(generated.ErrorCodeInputInvalid, "credential-import-draft")
	}
	var drafts []CredentialImportDraft
	err := repository.store.Read(ctx, func(tx ReadTx) error {
		rows, queryErr := tx.query(ctx, `SELECT draft_id,reference_id,consumer_id,purpose_id,target_id,resolver_id,material_version,ciphertext_fingerprint,state_revision,recovery_epoch FROM credential_import_drafts WHERE reference_id=? AND material_version=? AND recovery_epoch=? ORDER BY draft_id`, referenceID, materialVersion, recoveryEpoch)
		if queryErr != nil {
			return queryErr
		}
		defer rows.Close()
		for rows.Next() {
			var draft CredentialImportDraft
			if scanErr := rows.Scan(&draft.DraftID, &draft.ReferenceID, &draft.ConsumerID, &draft.PurposeID, &draft.TargetID, &draft.ResolverID, &draft.MaterialVersion, &draft.CiphertextFingerprint, &draft.StateRevision, &draft.RecoveryEpoch); scanErr != nil {
				return scanErr
			}
			drafts = append(drafts, draft)
		}
		return rows.Err()
	})
	if err != nil {
		return CredentialImportDraft{}, err
	}
	if len(drafts) != 1 {
		return CredentialImportDraft{}, credentialStoreError(generated.ErrorCodePrerequisiteBlocked, "credential-import-draft")
	}
	return drafts[0], nil
}

// CredentialLifecycleApplyRequest carries the complete, server-derived exact
// step: the verified lifecycle binding, the fully-formed target version row
// (Stage), and the consumer/recovery evidence to append in the same
// transaction. It is wired only into the run engine's core.credential effect.
type CredentialLifecycleApplyRequest struct {
	Binding       credentialref.LifecycleBinding
	Stage         CredentialStageRequest
	Verifications []credentialref.ConsumerVerification
	Recovery      *credentialref.RecoveryVerification
}

// ApplyCredentialLifecycle appends exactly one credential version plus its
// consumer/recovery evidence, only after the exact human central plan, running
// step and active lease are proven inside one transaction. It performs the
// action-specific status transition checks; it never reads credential material.
func (repository *CredentialRepository) ApplyCredentialLifecycle(ctx context.Context, request CredentialLifecycleApplyRequest) (generated.CredentialReference, error) {
	binding := request.Binding
	if !credentialref.ValidLifecycleBinding(binding) {
		return generated.CredentialReference{}, credentialStoreError(generated.ErrorCodeInputInvalid, "credential-lifecycle-binding")
	}
	target := request.Stage.Reference
	if target.ReferenceID != binding.ReferenceID || target.TargetID != binding.TargetID || target.ResolverID != binding.ResolverID || target.MaterialVersion != binding.MaterialVersion || target.Fingerprint != binding.CiphertextFingerprint || target.RecoveryEpoch != binding.RecoveryEpoch || request.Stage.Expected.RecoveryEpoch != binding.RecoveryEpoch {
		return generated.CredentialReference{}, credentialStoreError(generated.ErrorCodeInputInvalid, "credential-lifecycle-mismatch")
	}

	current, currentErr := repository.GetReference(ctx, binding.ReferenceID)
	if currentErr != nil && Code(currentErr) != generated.ErrorCodeResourceNotFound {
		return generated.CredentialReference{}, currentErr
	}
	hasCurrent := currentErr == nil

	var extra func(ctx context.Context, tx *sql.Tx, versionID, created string) error

	switch binding.Action {
	case credentialref.ActionStage:
		if target.Status != "staged" || target.ActivatedAt != nil || len(target.VerifiedConsumerIDs) != 0 {
			return generated.CredentialReference{}, credentialStoreError(generated.ErrorCodeInputInvalid, "credential-lifecycle-stage")
		}
		if hasCurrent && current.RecoveryEpoch == binding.RecoveryEpoch && (current.Status == "staged" || current.MaterialVersion == binding.MaterialVersion) {
			return generated.CredentialReference{}, credentialStoreError(generated.ErrorCodeStateConflict, "credential-lifecycle-version")
		}
	case credentialref.ActionActivate:
		if target.Status != "active" || target.ActivatedAt == nil {
			return generated.CredentialReference{}, credentialStoreError(generated.ErrorCodeInputInvalid, "credential-lifecycle-activate")
		}
		if !hasCurrent || current.RecoveryEpoch != binding.RecoveryEpoch || current.MaterialVersion != binding.MaterialVersion || current.Fingerprint != binding.CiphertextFingerprint || (current.Status != "staged" && current.Status != "unavailable") {
			return generated.CredentialReference{}, credentialStoreError(generated.ErrorCodePrerequisiteBlocked, "credential-lifecycle-activate")
		}
		if err := requireConsumerVerifications(binding, request.Verifications, target.VerifiedConsumerIDs); err != nil {
			return generated.CredentialReference{}, err
		}
		extra = repository.consumerVerificationExtra(binding, request.Verifications)
	case credentialref.ActionRotate:
		if target.Status != "active" || target.ActivatedAt == nil || binding.PriorMaterialVersion == nil || *binding.PriorMaterialVersion == binding.MaterialVersion {
			return generated.CredentialReference{}, credentialStoreError(generated.ErrorCodeInputInvalid, "credential-lifecycle-rotate")
		}
		if !hasCurrent || current.RecoveryEpoch != binding.RecoveryEpoch || current.Status != "active" || current.MaterialVersion != *binding.PriorMaterialVersion {
			return generated.CredentialReference{}, credentialStoreError(generated.ErrorCodePrerequisiteBlocked, "credential-lifecycle-rotate")
		}
		if err := requireConsumerVerifications(binding, request.Verifications, target.VerifiedConsumerIDs); err != nil {
			return generated.CredentialReference{}, err
		}
		extra = repository.consumerVerificationExtra(binding, request.Verifications)
	case credentialref.ActionRevoke:
		if target.Status != "revoked" {
			return generated.CredentialReference{}, credentialStoreError(generated.ErrorCodeInputInvalid, "credential-lifecycle-revoke")
		}
		if !hasCurrent || current.RecoveryEpoch != binding.RecoveryEpoch || current.MaterialVersion != binding.MaterialVersion || (current.Status != "active" && current.Status != "unavailable") {
			return generated.CredentialReference{}, credentialStoreError(generated.ErrorCodePrerequisiteBlocked, "credential-lifecycle-revoke")
		}
	case credentialref.ActionRecover:
		if target.Status != "staged" || target.ActivatedAt != nil || len(target.VerifiedConsumerIDs) != 0 {
			return generated.CredentialReference{}, credentialStoreError(generated.ErrorCodeInputInvalid, "credential-lifecycle-recover")
		}
		if request.Recovery == nil || !recoveryEvidenceMatchesBinding(binding, *request.Recovery) {
			return generated.CredentialReference{}, credentialStoreError(generated.ErrorCodePrerequisiteBlocked, "credential-lifecycle-recovery")
		}
		// A recovered version is staged under the new epoch; any prior version
		// belongs to a superseded epoch and cannot be current here.
		if hasCurrent && current.RecoveryEpoch >= binding.RecoveryEpoch {
			return generated.CredentialReference{}, credentialStoreError(generated.ErrorCodeRecoveryEpochMismatch, "credential-lifecycle-recover")
		}
		extra = repository.recoveryRecordExtra(binding, *request.Recovery)
	default:
		return generated.CredentialReference{}, credentialStoreError(generated.ErrorCodeInputInvalid, "credential-lifecycle-action")
	}

	return repository.applyCredentialVersion(ctx, request.Stage, string(binding.Action), repository.lifecycleAppendExtra(request.Stage, extra))
}

// lifecycleAppendExtra wraps every lifecycle append with the consumed
// human-acknowledgement proof (Finding F3). The #123 exact-step primitive joins
// plan/run/step/lease but never the acknowledgement row, so the lifecycle layer
// proves it here, inside the same append transaction, before running any
// action-specific evidence hook. No lifecycle status can be appended without it,
// including by a direct in-process caller that seeds an otherwise exact step.
func (repository *CredentialRepository) lifecycleAppendExtra(stage CredentialStageRequest, actionExtra func(ctx context.Context, tx *sql.Tx, versionID, created string) error) func(ctx context.Context, tx *sql.Tx, versionID, created string) error {
	return func(ctx context.Context, tx *sql.Tx, versionID, created string) error {
		if err := requireConsumedHumanAcknowledgement(ctx, tx, stage); err != nil {
			return err
		}
		if actionExtra != nil {
			return actionExtra(ctx, tx, versionID, created)
		}
		return nil
	}
}

// requireConsumedHumanAcknowledgement proves, inside the append transaction, that
// this exact run consumed an approved human acknowledgement bound to the same
// plan, plan digest, responsible human, state revision and recovery epoch. It is
// the lifecycle-layer complement to the #123 exact-step join (which never proves
// the acknowledgement); a NULL run acknowledgement, an unapproved or unconsumed
// request, or a mismatched human/plan/revision/epoch yields no row and blocks the
// append. It never reads or persists credential material.
func requireConsumedHumanAcknowledgement(ctx context.Context, tx *sql.Tx, request CredentialStageRequest) error {
	var count int
	err := tx.QueryRowContext(ctx, `SELECT COUNT(1) FROM plan_runs r JOIN acknowledgement_requests a ON a.acknowledgement_id=r.acknowledgement_id WHERE r.run_id=? AND r.plan_id=? AND r.plan_digest=? AND r.acknowledgement_id IS NOT NULL AND a.plan_id=? AND a.plan_digest=? AND a.human_id=? AND a.state_revision=? AND a.recovery_epoch=? AND a.status='approved' AND a.consumed_at IS NOT NULL`,
		request.RunID, request.PlanID, request.PlanDigest, request.PlanID, request.PlanDigest, request.HumanID, request.Expected.StateRevision, request.Expected.RecoveryEpoch).Scan(&count)
	if err != nil {
		return err
	}
	if count != 1 {
		return credentialStoreError(generated.ErrorCodePrerequisiteBlocked, "credential-lifecycle-acknowledgement")
	}
	return nil
}

// requireConsumerVerifications enforces one positive result per declared
// consumer and one denied result per required-denied consumer, with no unknown
// or duplicate consumer, and confirms the recorded verified set matches exactly.
func requireConsumerVerifications(binding credentialref.LifecycleBinding, verifications []credentialref.ConsumerVerification, verifiedConsumerIDs []string) error {
	positive := map[string]bool{}
	for _, id := range binding.ConsumerIDs {
		positive[id] = false
	}
	denied := map[string]bool{}
	for _, id := range binding.RequiredDeniedConsumerIDs {
		denied[id] = false
	}
	for _, verification := range verifications {
		switch verification.Result {
		case "verified":
			seen, known := positive[verification.ConsumerID]
			if !known || seen {
				return credentialStoreError(generated.ErrorCodePrerequisiteBlocked, "credential-consumer-verification")
			}
			if !verification.RestartObserved || verification.MaterialVersion != binding.MaterialVersion || verification.CiphertextFingerprint != binding.CiphertextFingerprint {
				return credentialStoreError(generated.ErrorCodePrerequisiteBlocked, "credential-consumer-verification")
			}
			positive[verification.ConsumerID] = true
		case "denied":
			seen, known := denied[verification.ConsumerID]
			if !known || seen {
				return credentialStoreError(generated.ErrorCodePrerequisiteBlocked, "credential-consumer-denial")
			}
			denied[verification.ConsumerID] = true
		default:
			return credentialStoreError(generated.ErrorCodePrerequisiteBlocked, "credential-consumer-verification")
		}
		if !credentialValidDigest(verification.EvidenceDigest) {
			return credentialStoreError(generated.ErrorCodePrerequisiteBlocked, "credential-consumer-verification")
		}
	}
	for _, complete := range positive {
		if !complete {
			return credentialStoreError(generated.ErrorCodePrerequisiteBlocked, "credential-consumer-verification")
		}
	}
	for _, complete := range denied {
		if !complete {
			return credentialStoreError(generated.ErrorCodePrerequisiteBlocked, "credential-consumer-denial")
		}
	}
	expected := append([]string(nil), binding.ConsumerIDs...)
	got := append([]string(nil), verifiedConsumerIDs...)
	sort.Strings(expected)
	sort.Strings(got)
	if len(expected) != len(got) {
		return credentialStoreError(generated.ErrorCodePrerequisiteBlocked, "credential-consumer-set")
	}
	for index := range expected {
		if expected[index] != got[index] {
			return credentialStoreError(generated.ErrorCodePrerequisiteBlocked, "credential-consumer-set")
		}
	}
	return nil
}

func recoveryEvidenceMatchesBinding(binding credentialref.LifecycleBinding, evidence credentialref.RecoveryVerification) bool {
	if binding.DraftID == nil || binding.CustodyProofDigest == nil || binding.FormerControllerFenceDigest == nil || binding.PriorRecoveryEpoch == nil {
		return false
	}
	return evidence.DraftID == *binding.DraftID &&
		evidence.CustodyProofDigest == *binding.CustodyProofDigest &&
		evidence.FormerControllerFenceDigest == *binding.FormerControllerFenceDigest &&
		evidence.PriorRecoveryEpoch == *binding.PriorRecoveryEpoch &&
		evidence.RecoveryEpoch == binding.RecoveryEpoch &&
		evidence.RecoveryEpoch > evidence.PriorRecoveryEpoch &&
		credentialValidDigest(evidence.EvidenceDigest) &&
		credentialValidDigest(evidence.CustodyProofDigest) &&
		credentialValidDigest(evidence.FormerControllerFenceDigest)
}

func (repository *CredentialRepository) consumerVerificationExtra(binding credentialref.LifecycleBinding, verifications []credentialref.ConsumerVerification) func(ctx context.Context, tx *sql.Tx, versionID, created string) error {
	return func(ctx context.Context, tx *sql.Tx, versionID, created string) error {
		for _, verification := range verifications {
			restart := 0
			if verification.RestartObserved {
				restart = 1
			}
			id := lifecycleEvidenceID(versionID, verification.ConsumerID, verification.Result)
			if _, err := tx.ExecContext(ctx, `INSERT INTO credential_consumer_verifications(verification_id,reference_id,version_id,consumer_id,profile_id,role_id,material_version,ciphertext_fingerprint,evidence_digest,restart_observed,result,reason_code,recovery_epoch,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, id, binding.ReferenceID, versionID, verification.ConsumerID, verification.ProfileID, verification.RoleID, verification.MaterialVersion, verification.CiphertextFingerprint, verification.EvidenceDigest, restart, verification.Result, verification.ReasonCode, binding.RecoveryEpoch, created); err != nil {
				return err
			}
		}
		return nil
	}
}

func (repository *CredentialRepository) recoveryRecordExtra(binding credentialref.LifecycleBinding, evidence credentialref.RecoveryVerification) func(ctx context.Context, tx *sql.Tx, versionID, created string) error {
	return func(ctx context.Context, tx *sql.Tx, versionID, created string) error {
		id := lifecycleEvidenceID(versionID, evidence.DraftID, "recovery")
		_, err := tx.ExecContext(ctx, `INSERT INTO credential_recovery_records(record_id,reference_id,version_id,draft_id,custody_proof_digest,former_controller_fence_digest,prior_recovery_epoch,recovery_epoch,evidence_digest,created_at) VALUES(?,?,?,?,?,?,?,?,?,?)`, id, binding.ReferenceID, versionID, evidence.DraftID, evidence.CustodyProofDigest, evidence.FormerControllerFenceDigest, evidence.PriorRecoveryEpoch, evidence.RecoveryEpoch, evidence.EvidenceDigest, created)
		return err
	}
}

func lifecycleEvidenceID(versionID, discriminator, kind string) string {
	sum := sha256.Sum256([]byte(versionID + "\x00" + discriminator + "\x00" + kind))
	return "evidence-" + hex.EncodeToString(sum[:16])
}

func credentialValidDigest(value string) bool {
	return len(value) == 71 && value[:7] == "sha256:"
}
