package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/vegastack/vegastack-labs/internal/audit"
	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/generated"
)

type CredentialRepository struct{ store *Store }

func NewCredentialRepository(authority *Store) *CredentialRepository {
	return &CredentialRepository{store: authority}
}

type CredentialBindingStageRequest struct {
	DeclarationID       string
	DeclarationRevision int64
	Bindings            []credentialref.StepBinding
	Expected            RevisionToken
	Attribution         audit.Attribution
	KeyDigest           string
	RequestDigest       string
}

// CredentialStageRequest is an applied, human-authorized core effect request.
// It carries only ciphertext metadata; plaintext is never a store input.
type CredentialStageRequest struct {
	Reference           generated.CredentialReference
	DeclarationID       string
	DeclarationRevision int64
	PlanID, PlanDigest  string
	RunID, StepID       string
	LeaseID, HumanID    string
	Expected            RevisionToken
	Attribution         audit.Attribution
	KeyDigest           string
	RequestDigest       string
}

func credentialStoreError(code, target string) error {
	return newStoreError(code, target, false, nil)
}

func credentialHuman(attribution audit.Attribution) string {
	if attribution.ResponsibleHumanPrincipalID != nil {
		return *attribution.ResponsibleHumanPrincipalID
	}
	return attribution.AuthenticatedPrincipalID
}

func (repository *CredentialRepository) StageStepBindings(ctx context.Context, request CredentialBindingStageRequest) (string, error) {
	if repository == nil || repository.store == nil || request.DeclarationRevision <= 0 || len(request.Bindings) == 0 || len(request.Bindings) > 64 || credentialHuman(request.Attribution) == "" {
		return "", credentialStoreError(generated.ErrorCodeInputInvalid, "credential-bindings")
	}
	if _, err := credentialref.ParseID(request.DeclarationID); err != nil {
		return "", credentialStoreError(generated.ErrorCodeInputInvalid, "credential-declaration")
	}
	seen := map[string]bool{}
	for _, binding := range request.Bindings {
		key := binding.OperationID + "\x00" + binding.ReferenceID
		if !credentialref.ValidBinding(binding) || binding.RecoveryEpoch != request.Expected.RecoveryEpoch || seen[key] {
			return "", credentialStoreError(generated.ErrorCodeInputInvalid, "credential-binding")
		}
		seen[key] = true
	}
	digest := credentialref.ManifestDigest(request.Bindings)
	draft, err := NewDeclarationRepository(repository.store).GetRevision(ctx, request.DeclarationID, request.DeclarationRevision)
	if err != nil {
		return "", err
	}
	if draft.Status != "draft" || draft.StateRevision != request.Expected.StateRevision || draft.RecoveryEpoch != request.Expected.RecoveryEpoch || draftCredentialDigest(draft.Extensions) != digest {
		return "", credentialStoreError(generated.ErrorCodePrerequisiteBlocked, "credential-draft-unbound")
	}
	operations := map[string]generated.DeclarationOperation{}
	for _, operation := range draft.Operations {
		operations[operation.OperationID] = operation
	}
	for _, binding := range request.Bindings {
		operation, found := operations[binding.OperationID]
		if !found || binding.StateRevision != request.Expected.StateRevision+2 || binding.AdapterID != operation.AdapterID || binding.TargetID != operation.TargetID || operation.InputDigest != credentialref.OperationManifestDigest(request.Bindings, binding.OperationID) {
			return "", credentialStoreError(generated.ErrorCodeInputInvalid, "credential-binding-input")
		}
	}
	key := audit.IntentKey{Scope: "credential-bindings-stage", KeyDigest: audit.Fingerprint(request.KeyDigest), RequestDigest: audit.Fingerprint(request.RequestDigest)}
	after := audit.Fingerprint(digest)
	event := audit.EventDraft{Type: "credential.bindings-staged", CorrelationID: request.DeclarationID, Attribution: request.Attribution, Target: audit.Target{Kind: "credential-bindings", ID: request.DeclarationID}, After: &after}
	if digest == "" || audit.ValidateIntentKey(key) != nil || audit.ValidateEventDraft(event) != nil {
		return "", credentialStoreError(generated.ErrorCodeInputInvalid, "credential-bindings")
	}
	created := repository.store.config.Clock().UTC().Truncate(time.Second).Format(time.RFC3339)
	_, err = repository.store.writeIntent(ctx, intentRequest{Expected: &request.Expected, Idempotency: key, Event: event}, func(ctx context.Context, tx *sql.Tx) error {
		for _, binding := range request.Bindings {
			body, encodeErr := json.Marshal(binding)
			if encodeErr != nil || len(body) > 4096 {
				return credentialStoreError(generated.ErrorCodeInputInvalid, "credential-binding")
			}
			id := credentialBindingID(request.DeclarationID, request.DeclarationRevision, binding.Digest())
			if _, executeErr := tx.ExecContext(ctx, `INSERT INTO credential_step_bindings(binding_id,declaration_id,declaration_revision,operation_id,binding_digest,binding_bytes,recovery_epoch,created_at) VALUES(?,?,?,?,?,?,?,?)`, id, request.DeclarationID, request.DeclarationRevision, binding.OperationID, binding.Digest(), body, binding.RecoveryEpoch, created); executeErr != nil {
				return executeErr
			}
		}
		return nil
	})
	if err != nil {
		return "", err
	}
	return digest, nil
}

func credentialBindingID(declarationID string, revision int64, digest string) string {
	sum := sha256.Sum256([]byte(declarationID + "\x00" + fmt.Sprint(revision) + "\x00" + digest))
	return "binding-" + hex.EncodeToString(sum[:12])
}

func credentialExtensionDigest(plan generated.Plan) string {
	return draftCredentialDigest(plan.Extensions)
}

func draftCredentialDigest(extensions []generated.ContractExtension) string {
	for _, extension := range extensions {
		if extension.Name == "x-credential-bindings" {
			return extension.ValueDigest
		}
	}
	return ""
}

func (repository *CredentialRepository) GetStepBindings(ctx context.Context, plan generated.Plan, operationID string) ([]credentialref.StepBinding, error) {
	if repository == nil || repository.store == nil || plan.PlanID == "" || plan.PlanDigest == "" || plan.DeclarationID == "" || plan.Binding.DeclarationRevision <= 0 || operationID == "" {
		return nil, credentialStoreError(generated.ErrorCodeInputInvalid, "credential-step")
	}
	extensionDigest := credentialExtensionDigest(plan)
	if extensionDigest == "" || plan.ExecutorMode != "central" {
		return nil, credentialStoreError(generated.ErrorCodePrerequisiteBlocked, "credential-binding-uncommitted")
	}
	stored, err := NewPlanRepository(repository.store).GetPlan(ctx, plan.PlanID)
	if err != nil {
		return nil, credentialStoreError(generated.ErrorCodePrerequisiteBlocked, "credential-plan-uncommitted")
	}
	canonical, err := json.Marshal(plan)
	if err != nil || string(canonical) != string(stored.Canonical) {
		return nil, credentialStoreError(generated.ErrorCodeIntegrityFailure, "credential-plan-mismatch")
	}
	committed, err := NewDeclarationRepository(repository.store).GetRevision(ctx, plan.DeclarationID, plan.Binding.DeclarationRevision)
	if err != nil || committed.Status != "committed" || draftCredentialDigest(committed.Extensions) != extensionDigest || committed.StateRevision != plan.Binding.StateRevision || committed.RecoveryEpoch != plan.Binding.RecoveryEpoch {
		return nil, credentialStoreError(generated.ErrorCodePrerequisiteBlocked, "credential-declaration-uncommitted")
	}
	var all []credentialref.StepBinding
	err = repository.store.Read(ctx, func(tx ReadTx) error {
		rows, queryErr := tx.query(ctx, `SELECT binding_digest,binding_bytes,recovery_epoch FROM credential_step_bindings WHERE declaration_id=? AND declaration_revision=? ORDER BY operation_id,binding_id`, plan.DeclarationID, plan.Binding.DeclarationRevision-1)
		if queryErr != nil {
			return queryErr
		}
		defer rows.Close()
		for rows.Next() {
			var digest string
			var raw []byte
			var epoch int64
			if scanErr := rows.Scan(&digest, &raw, &epoch); scanErr != nil {
				return scanErr
			}
			var binding credentialref.StepBinding
			if len(raw) > 4096 || json.Unmarshal(raw, &binding) != nil || binding.Digest() != digest || binding.RecoveryEpoch != epoch {
				return credentialStoreError(generated.ErrorCodeIntegrityFailure, "credential-binding")
			}
			all = append(all, binding)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	if len(all) == 0 || credentialref.ManifestDigest(all) != extensionDigest {
		return nil, credentialStoreError(generated.ErrorCodePrerequisiteBlocked, "credential-binding-uncommitted")
	}
	var operation *generated.PlanOperation
	for index := range plan.Operations {
		if plan.Operations[index].OperationID == operationID {
			operation = &plan.Operations[index]
			break
		}
	}
	if operation == nil {
		return nil, credentialStoreError(generated.ErrorCodeInputInvalid, "credential-operation")
	}
	result := make([]credentialref.StepBinding, 0, len(all))
	seen := map[string]bool{}
	for _, binding := range all {
		if binding.StateRevision != plan.Binding.StateRevision || binding.RecoveryEpoch != plan.Binding.RecoveryEpoch {
			return nil, credentialStoreError(generated.ErrorCodePlanStale, "credential-binding")
		}
		if binding.OperationID != operationID {
			continue
		}
		if binding.AdapterID != operation.AdapterID || binding.TargetID != operation.TargetID || seen[binding.ReferenceID] || operation.InputDigest != credentialref.OperationManifestDigest(all, binding.OperationID) {
			return nil, credentialStoreError(generated.ErrorCodeIntegrityFailure, "credential-binding")
		}
		seen[binding.ReferenceID] = true
		result = append(result, binding)
	}
	if len(result) == 0 {
		// The complete committed manifest and exact stored plan were checked
		// above. This operation simply has no credential binding; mixed plans
		// must not turn an ordinary step into a secret step.
		return []credentialref.StepBinding{}, nil
	}
	return result, nil
}

func (repository *CredentialRepository) GetReference(ctx context.Context, referenceID string) (generated.CredentialReference, error) {
	if repository == nil || repository.store == nil {
		return generated.CredentialReference{}, credentialStoreError(generated.ErrorCodeInputInvalid, "credential-reference")
	}
	if _, err := credentialref.ParseID(referenceID); err != nil {
		return generated.CredentialReference{}, credentialStoreError(generated.ErrorCodeInputInvalid, "credential-reference")
	}
	var result generated.CredentialReference
	var verified []byte
	err := repository.store.Read(ctx, func(tx ReadTx) error {
		return tx.queryRow(ctx, `SELECT reference_id,consumer_id,purpose_id,target_id,resolver_id,material_version,fingerprint,status,state_revision,recovery_epoch,activated_at,verified_consumers_bytes FROM credential_reference_versions WHERE reference_id=? ORDER BY state_revision DESC,version_id DESC LIMIT 1`, referenceID).Scan(&result.ReferenceID, &result.ConsumerID, &result.PurposeID, &result.TargetID, &result.ResolverID, &result.MaterialVersion, &result.Fingerprint, &result.Status, &result.StateRevision, &result.RecoveryEpoch, &result.ActivatedAt, &verified)
	})
	if errors.Is(err, sql.ErrNoRows) {
		return generated.CredentialReference{}, credentialStoreError(generated.ErrorCodeResourceNotFound, "credential-reference")
	}
	if err != nil {
		return generated.CredentialReference{}, err
	}
	active, activeErr := repository.GetActiveVersion(ctx, referenceID, result.RecoveryEpoch)
	if activeErr == nil {
		return active, nil
	}
	if Code(activeErr) != generated.ErrorCodeResourceNotFound {
		return generated.CredentialReference{}, activeErr
	}
	result.Schema, result.SchemaVersion = generated.SchemaIDCredentialReference, "1.1.0"
	if json.Unmarshal(verified, &result.VerifiedConsumerIDs) != nil || !strings.HasPrefix(result.Fingerprint, "sha256:") {
		return generated.CredentialReference{}, credentialStoreError(generated.ErrorCodeIntegrityFailure, "credential-reference")
	}
	raw, encodeErr := json.Marshal(result)
	if encodeErr != nil || generated.ValidateContractJSON(generated.SchemaIDCredentialReference, raw, generated.ContractExact) != nil {
		return generated.CredentialReference{}, credentialStoreError(generated.ErrorCodeIntegrityFailure, "credential-reference")
	}
	return result, nil
}

// applyCredentialVersion appends exactly one credential reference version inside
// one intent transaction, only after the exact human central plan, running step
// and active lease are proven. The optional extra hook appends additional
// lifecycle evidence (consumer verifications, recovery records) in the same
// transaction; it must never read or persist credential material.
func (repository *CredentialRepository) applyCredentialVersion(ctx context.Context, request CredentialStageRequest, operationType string, extra func(ctx context.Context, tx *sql.Tx, versionID, created string) error) (generated.CredentialReference, error) {
	if repository == nil || repository.store == nil {
		return generated.CredentialReference{}, credentialStoreError(generated.ErrorCodeInputInvalid, "credential-repository")
	}
	value := request.Reference
	if request.Expected.StateRevision < 0 || value.StateRevision != request.Expected.StateRevision+1 || value.RecoveryEpoch != request.Expected.RecoveryEpoch || credentialHuman(request.Attribution) == "" || credentialHuman(request.Attribution) != request.HumanID {
		return generated.CredentialReference{}, credentialStoreError(generated.ErrorCodeInputInvalid, "credential-effect")
	}
	for _, id := range []string{value.ReferenceID, value.ConsumerID, value.PurposeID, value.TargetID, value.ResolverID, value.MaterialVersion, request.DeclarationID, request.PlanID, request.RunID, request.StepID, request.LeaseID, request.HumanID} {
		if _, err := credentialref.ParseID(id); err != nil {
			return generated.CredentialReference{}, credentialStoreError(generated.ErrorCodeInputInvalid, "credential-identifier")
		}
	}
	verified, err := json.Marshal(value.VerifiedConsumerIDs)
	if err != nil || len(verified) > 4096 || !strings.HasPrefix(value.Fingerprint, "sha256:") {
		return generated.CredentialReference{}, credentialStoreError(generated.ErrorCodeInputInvalid, "credential-metadata")
	}
	raw, err := json.Marshal(value)
	if err != nil || generated.ValidateContractJSON(generated.SchemaIDCredentialReference, raw, generated.ContractExact) != nil {
		return generated.CredentialReference{}, credentialStoreError(generated.ErrorCodeInputInvalid, "credential-metadata")
	}
	storedPlan, err := NewPlanRepository(repository.store).GetPlan(ctx, request.PlanID)
	if err != nil {
		return generated.CredentialReference{}, credentialStoreError(generated.ErrorCodePrerequisiteBlocked, "credential-plan")
	}
	plan := storedPlan.Plan
	if plan.PlanDigest != request.PlanDigest || plan.DeclarationID != request.DeclarationID || plan.Binding.DeclarationRevision != request.DeclarationRevision || plan.Binding.StateRevision != request.Expected.StateRevision || plan.Binding.RecoveryEpoch != request.Expected.RecoveryEpoch || plan.AuthorizationBranch != "human" || plan.ExecutorMode != "central" || plan.Status != "planned" {
		return generated.CredentialReference{}, credentialStoreError(generated.ErrorCodePrerequisiteBlocked, "credential-human-plan")
	}
	key := audit.IntentKey{Scope: "credential-version-apply", KeyDigest: audit.Fingerprint(request.KeyDigest), RequestDigest: audit.Fingerprint(request.RequestDigest)}
	after := audit.Fingerprint(value.Fingerprint)
	event := audit.EventDraft{Type: "credential.version-applied", CorrelationID: value.ReferenceID, Attribution: request.Attribution, Target: audit.Target{Kind: "credential-reference", ID: value.ReferenceID}, After: &after}
	if audit.ValidateIntentKey(key) != nil || audit.ValidateEventDraft(event) != nil {
		return generated.CredentialReference{}, credentialStoreError(generated.ErrorCodeInputInvalid, "credential-audit")
	}
	created := repository.store.config.Clock().UTC().Truncate(time.Second).Format(time.RFC3339)
	versionID := credentialBindingID(value.ReferenceID, value.StateRevision, value.Fingerprint+"\x00"+operationType)
	_, err = repository.store.writeIntent(ctx, intentRequest{Expected: &request.Expected, Idempotency: key, Event: event}, func(ctx context.Context, tx *sql.Tx) error {
		if err := credentialExactStep(ctx, tx, request, operationType, created); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO credential_reference_versions(version_id,reference_id,consumer_id,purpose_id,target_id,resolver_id,material_version,fingerprint,status,state_revision,recovery_epoch,activated_at,verified_consumers_bytes,declaration_id,declaration_revision,plan_id,plan_digest,run_id,step_id,lease_id,human_id,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, versionID, value.ReferenceID, value.ConsumerID, value.PurposeID, value.TargetID, value.ResolverID, value.MaterialVersion, value.Fingerprint, value.Status, value.StateRevision, value.RecoveryEpoch, value.ActivatedAt, verified, request.DeclarationID, request.DeclarationRevision, request.PlanID, request.PlanDigest, request.RunID, request.StepID, request.LeaseID, request.HumanID, created); err != nil {
			return err
		}
		if extra != nil {
			return extra(ctx, tx, versionID, created)
		}
		return nil
	})
	if Code(err) == generated.ErrorCodeStateConflict {
		return generated.CredentialReference{}, credentialStoreError(generated.ErrorCodePlanStale, "credential-plan")
	}
	if err != nil {
		return generated.CredentialReference{}, err
	}
	return value, nil
}

func credentialExactStep(ctx context.Context, tx *sql.Tx, request CredentialStageRequest, operationType, now string) error {
	var count int
	err := tx.QueryRowContext(ctx, `SELECT COUNT(1) FROM immutable_plans p JOIN plan_runs r ON r.plan_id=p.plan_id JOIN plan_run_steps s ON s.run_id=r.run_id JOIN target_execution_leases l ON l.run_id=r.run_id AND l.step_id=s.step_id WHERE p.plan_id=? AND p.plan_digest=? AND p.declaration_id=? AND p.declaration_revision=? AND p.state_revision=? AND p.recovery_epoch=? AND p.expires_at>? AND r.run_id=? AND r.plan_digest=? AND r.state_revision=? AND r.recovery_epoch=? AND r.executor_mode='central' AND r.status='running' AND s.step_id=? AND s.operation_type=? AND s.adapter_id='core.credential' AND s.target_id=? AND s.input_digest=? AND s.artifact_digest=? AND s.effect_state='intent-recorded' AND s.active_lease_id=? AND l.lease_id=? AND l.status='active' AND l.lease_kind='central' AND l.expires_at>? AND l.recovery_epoch=?`, request.PlanID, request.PlanDigest, request.DeclarationID, request.DeclarationRevision, request.Expected.StateRevision, request.Expected.RecoveryEpoch, now, request.RunID, request.PlanDigest, request.Expected.StateRevision, request.Expected.RecoveryEpoch, request.StepID, operationType, request.Reference.TargetID, request.Reference.Fingerprint, request.Reference.Fingerprint, request.LeaseID, request.LeaseID, now, request.Expected.RecoveryEpoch).Scan(&count)
	if err != nil {
		return err
	}
	if count != 1 {
		return credentialStoreError(generated.ErrorCodePrerequisiteBlocked, "credential-exact-step")
	}
	return nil
}
