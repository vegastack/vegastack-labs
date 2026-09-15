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
)

type GateRepository struct{ store *Store }

func NewGateRepository(authority *Store) *GateRepository { return &GateRepository{store: authority} }

func gateDigest(raw []byte) string {
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func gateHuman(attribution audit.Attribution) string {
	if attribution.ResponsibleHumanPrincipalID != nil {
		return *attribution.ResponsibleHumanPrincipalID
	}
	if attribution.Agent != nil {
		return ""
	}
	return attribution.AuthenticatedPrincipalID
}

func (repository *GateRepository) PutGateDraft(ctx context.Context, request GateDraftRequest) (GateDraft, error) {
	if repository == nil || repository.store == nil || gateHuman(request.Attribution) == "" {
		return GateDraft{}, newStoreError(generated.ErrorCodeInputInvalid, "gate-draft", false, nil)
	}
	bundleBytes, err := json.Marshal(request.Bundle)
	if err != nil || len(bundleBytes) > 65536 || generated.ValidateContractJSON(generated.SchemaIDGateEvidenceBundle, bundleBytes, generated.ContractExact) != nil {
		return GateDraft{}, newStoreError(generated.ErrorCodeInputInvalid, "gate-bundle", false, err)
	}
	if len(request.Bundle.Attachments) > 16 {
		return GateDraft{}, newStoreError(generated.ErrorCodeInputInvalid, "gate-attachments", false, nil)
	}
	for _, attachment := range request.Bundle.Attachments {
		if attachment.SizeBytes > 8<<20 {
			return GateDraft{}, newStoreError(generated.ErrorCodeInputInvalid, "gate-attachment-size", false, nil)
		}
	}
	check := generated.GateEvidenceRequest{
		Schema: generated.SchemaIDGateEvidenceRequest, SchemaVersion: "1.1.0", ExpectedStateRevision: request.Expected.StateRevision,
		RecoveryEpoch: request.Expected.RecoveryEpoch, TargetDigest: request.ArtifactDigest, IdempotencyKey: "key-" + request.EvidenceID,
		EvidenceID: request.EvidenceID, GateID: request.GateID, SubjectID: request.SubjectID,
		DefinitionVersion: request.DefinitionVersion, EvaluatorVersion: request.EvaluatorVersion,
		ArtifactDigest: request.ArtifactDigest, ObservedAt: request.Bundle.ObservedAt, Bundle: request.Bundle,
	}
	checkBytes, err := json.Marshal(check)
	if err != nil || generated.ValidateContractJSON(generated.SchemaIDGateEvidenceRequest, checkBytes, generated.ContractExact) != nil {
		return GateDraft{}, newStoreError(generated.ErrorCodeInputInvalid, "gate-draft", false, err)
	}
	bundleDigest := gateDigest(bundleBytes)
	draftID := "draft-" + request.EvidenceID
	key := audit.IntentKey{Scope: "gate-evidence-draft", KeyDigest: audit.Fingerprint(request.KeyDigest), RequestDigest: audit.Fingerprint(request.RequestDigest)}
	after := audit.Fingerprint(bundleDigest)
	event := audit.EventDraft{Type: "gate.evidence-draft-created", CorrelationID: request.EvidenceID, Attribution: request.Attribution, Target: audit.Target{Kind: "gate-evidence", ID: request.EvidenceID}, After: &after}
	if audit.ValidateIntentKey(key) != nil || audit.ValidateEventDraft(event) != nil {
		return GateDraft{}, newStoreError(generated.ErrorCodeInputInvalid, "gate-draft", false, nil)
	}
	if existing, lookupErr := repository.GetGateDraft(ctx, request.EvidenceID); lookupErr == nil {
		if existing.BundleDigest == bundleDigest && existing.GateID == request.GateID && existing.SubjectID == request.SubjectID && existing.DefinitionVersion == request.DefinitionVersion && existing.EvaluatorVersion == request.EvaluatorVersion && existing.ArtifactDigest == request.ArtifactDigest && existing.RecoveryEpoch == request.Expected.RecoveryEpoch {
			return existing, nil
		}
		return GateDraft{}, newStoreError(generated.ErrorCodeStateConflict, "gate-draft", false, nil)
	} else if Code(lookupErr) != generated.ErrorCodeResourceNotFound {
		return GateDraft{}, lookupErr
	}
	createdAt := repository.store.config.Clock().UTC().Truncate(time.Second).Format(time.RFC3339)
	_, err = repository.store.writeIntent(ctx, intentRequest{Expected: &request.Expected, Idempotency: key, Event: event}, func(ctx context.Context, tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO gate_evidence_drafts(draft_id,evidence_id,gate_id,subject_id,definition_version,evaluator_version,artifact_digest,bundle_digest,bundle_bytes,observed_at,state_revision,recovery_epoch,human_id,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, draftID, request.EvidenceID, request.GateID, request.SubjectID, request.DefinitionVersion, request.EvaluatorVersion, request.ArtifactDigest, bundleDigest, bundleBytes, request.Bundle.ObservedAt, request.Expected.StateRevision+1, request.Expected.RecoveryEpoch, gateHuman(request.Attribution), createdAt)
		return err
	})
	if err != nil {
		return GateDraft{}, err
	}
	return repository.GetGateDraft(ctx, request.EvidenceID)
}

func (repository *GateRepository) GetGateDraft(ctx context.Context, evidenceID string) (GateDraft, error) {
	if repository == nil || repository.store == nil {
		return GateDraft{}, newStoreError(generated.ErrorCodeInputInvalid, "gate-draft", false, nil)
	}
	var result GateDraft
	var raw []byte
	err := repository.store.Read(ctx, func(tx ReadTx) error {
		return tx.queryRow(ctx, `SELECT draft_id,evidence_id,gate_id,subject_id,definition_version,evaluator_version,artifact_digest,bundle_digest,bundle_bytes,state_revision,recovery_epoch,human_id,created_at FROM gate_evidence_drafts WHERE evidence_id=? OR draft_id=?`, evidenceID, evidenceID).Scan(&result.DraftID, &result.EvidenceID, &result.GateID, &result.SubjectID, &result.DefinitionVersion, &result.EvaluatorVersion, &result.ArtifactDigest, &result.BundleDigest, &raw, &result.StateRevision, &result.RecoveryEpoch, &result.HumanID, &result.CreatedAt)
	})
	if errors.Is(err, sql.ErrNoRows) {
		return GateDraft{}, newStoreError(generated.ErrorCodeResourceNotFound, "gate-draft", false, nil)
	}
	if err != nil {
		return GateDraft{}, err
	}
	if gateDigest(raw) != result.BundleDigest || json.Unmarshal(raw, &result.Bundle) != nil || generated.ValidateContractJSON(generated.SchemaIDGateEvidenceBundle, raw, generated.ContractExact) != nil {
		return GateDraft{}, newStoreError(generated.ErrorCodeIntegrityFailure, "gate-draft", false, nil)
	}
	return result, nil
}

func (repository *GateRepository) ListAppliedGateEvidence(ctx context.Context, gateID, subjectID string) ([]generated.GateEvidence, error) {
	if repository == nil || repository.store == nil {
		return nil, newStoreError(generated.ErrorCodeInputInvalid, "gate-evidence", false, nil)
	}
	result := []generated.GateEvidence{}
	err := repository.store.Read(ctx, func(tx ReadTx) error {
		rows, err := tx.query(ctx, `SELECT canonical_bytes FROM gate_applied_evidence WHERE gate_id=? AND subject_id=? ORDER BY state_revision,evidence_id`, gateID, subjectID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var raw []byte
			if err := rows.Scan(&raw); err != nil {
				return err
			}
			var evidence generated.GateEvidence
			if json.Unmarshal(raw, &evidence) != nil || generated.ValidateContractJSON(generated.SchemaIDGateEvidence, raw, generated.ContractExact) != nil || evidence.GateID != gateID || evidence.SubjectID != subjectID {
				return newStoreError(generated.ErrorCodeIntegrityFailure, "gate-evidence", false, nil)
			}
			result = append(result, evidence)
		}
		return rows.Err()
	})
	return result, err
}

func (repository *GateRepository) ApplyGateEvidence(ctx context.Context, request GateApplyRequest) (generated.GateEvidence, error) {
	if repository == nil || repository.store == nil {
		return generated.GateEvidence{}, newStoreError(generated.ErrorCodeInputInvalid, "gate-evidence", false, nil)
	}
	if existing, found, err := repository.existingGateApply(ctx, request); err != nil || found {
		return existing, err
	}
	current, err := NewPlanRepository(repository.store).CurrentRevision(ctx)
	if err != nil {
		return generated.GateEvidence{}, err
	}
	if current != request.Expected {
		return generated.GateEvidence{}, newStoreError(generated.ErrorCodePlanStale, "gate-plan", false, nil)
	}
	draft, err := repository.GetGateDraft(ctx, request.DraftID)
	if err != nil {
		return generated.GateEvidence{}, err
	}
	if draft.EvidenceID != request.EvidenceID || draft.GateID != request.GateID || draft.SubjectID != request.SubjectID || draft.RecoveryEpoch != request.Expected.RecoveryEpoch || request.ReleaseBuildID == "" || request.ToolVersion == "" || request.ExpiresAt == "" || gateHuman(request.Attribution) == "" {
		return generated.GateEvidence{}, newStoreError(generated.ErrorCodeInputInvalid, "gate-evidence", false, nil)
	}
	scope, err := repository.GetAppliedProfileScope(ctx)
	if err != nil {
		return generated.GateEvidence{}, newStoreError(generated.ErrorCodePrerequisiteBlocked, "applied-profile", false, err)
	}
	if scope.RecoveryEpoch != request.Expected.RecoveryEpoch || scope.StateRevision > request.Expected.StateRevision {
		return generated.GateEvidence{}, newStoreError(generated.ErrorCodePlanStale, "applied-profile", false, nil)
	}
	status := request.Status
	if status == "" {
		status = "applied"
	}
	sourceKind, proofClass := request.SourceKind, request.ProofClass
	if sourceKind == "" {
		sourceKind = "fixture"
	}
	if proofClass == "" {
		proofClass = "fixture"
	}
	appliedAt := repository.store.config.Clock().UTC().Truncate(time.Second).Format(time.RFC3339)
	evidence := generated.GateEvidence{
		Schema: generated.SchemaIDGateEvidence, SchemaVersion: "1.1.0", EvidenceID: request.EvidenceID,
		GateID: request.GateID, SubjectID: request.SubjectID, DefinitionVersion: draft.DefinitionVersion,
		EvaluatorVersion: draft.EvaluatorVersion, ReleaseBuildID: request.ReleaseBuildID, ToolVersion: request.ToolVersion,
		ProfileID: scope.ProfileID, ProfileVersion: scope.ProfileVersion, PolicyID: scope.PolicyID, PolicyVersion: scope.PolicyVersion,
		DeclarationID: request.DeclarationID, DeclarationRevision: request.DeclarationRevision, StateRevision: request.Expected.StateRevision + 1,
		SourceKind: sourceKind, ProofClass: proofClass, CollectorID: draft.Bundle.CollectorID, HumanID: gateHuman(request.Attribution),
		ArtifactDigest: draft.ArtifactDigest, BundleDigest: draft.BundleDigest, ObservedAt: draft.Bundle.ObservedAt,
		AppliedAt: appliedAt, ExpiresAt: request.ExpiresAt, RecoveryEpoch: request.Expected.RecoveryEpoch,
		SupersedesEvidenceID: request.SupersedesEvidenceID, RevokesEvidenceID: request.RevokesEvidenceID, Status: status,
	}
	raw, err := json.Marshal(evidence)
	if err != nil || generated.ValidateContractJSON(generated.SchemaIDGateEvidence, raw, generated.ContractExact) != nil {
		return generated.GateEvidence{}, newStoreError(generated.ErrorCodeInputInvalid, "gate-evidence", false, err)
	}
	key := audit.IntentKey{Scope: "gate-evidence-apply", KeyDigest: audit.Fingerprint(request.KeyDigest), RequestDigest: audit.Fingerprint(request.RequestDigest)}
	after := audit.Fingerprint(draft.BundleDigest)
	event := audit.EventDraft{Type: "gate.evidence-applied", CorrelationID: request.EvidenceID, Attribution: request.Attribution, Target: audit.Target{Kind: "gate-evidence", ID: request.EvidenceID}, After: &after}
	if audit.ValidateIntentKey(key) != nil || audit.ValidateEventDraft(event) != nil {
		return generated.GateEvidence{}, newStoreError(generated.ErrorCodeInputInvalid, "gate-evidence", false, nil)
	}
	intent, err := repository.store.writeIntent(ctx, intentRequest{Expected: &request.Expected, Idempotency: key, Event: event}, func(ctx context.Context, tx *sql.Tx) error {
		operation := "gate.evidence.apply"
		if status == "revoked" {
			operation = "gate.evidence.revoke"
		}
		if request.SupersedesEvidenceID != nil {
			operation = "gate.evidence.supersede"
		}
		if err := gateExactStep(ctx, tx, request.PlanID, request.PlanDigest, request.RunID, request.StepID, request.LeaseID, request.DeclarationID, request.DeclarationRevision, request.SubjectID, draft.BundleDigest, request.Expected, operation, appliedAt); err != nil {
			return err
		}
		if err := gateRelation(ctx, tx, request.SupersedesEvidenceID, request.GateID, request.SubjectID); err != nil {
			return err
		}
		if err := gateRelation(ctx, tx, request.RevokesEvidenceID, request.GateID, request.SubjectID); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, `INSERT INTO gate_applied_evidence(evidence_id,draft_id,gate_id,subject_id,status,source_kind,proof_class,bundle_digest,canonical_bytes,state_revision,recovery_epoch,declaration_id,declaration_revision,plan_id,plan_digest,run_id,step_id,lease_id,supersedes_evidence_id,revokes_evidence_id,applied_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, evidence.EvidenceID, draft.DraftID, evidence.GateID, evidence.SubjectID, evidence.Status, evidence.SourceKind, evidence.ProofClass, evidence.BundleDigest, raw, evidence.StateRevision, evidence.RecoveryEpoch, evidence.DeclarationID, evidence.DeclarationRevision, request.PlanID, request.PlanDigest, request.RunID, request.StepID, request.LeaseID, request.SupersedesEvidenceID, request.RevokesEvidenceID, appliedAt)
		return err
	})
	if Code(err) == generated.ErrorCodeStateConflict {
		return generated.GateEvidence{}, newStoreError(generated.ErrorCodePlanStale, "gate-plan", false, err)
	}
	if err != nil {
		return generated.GateEvidence{}, err
	}
	if !intent.Created {
		if existing, found, lookupErr := repository.existingGateApply(ctx, request); lookupErr != nil || found {
			return existing, lookupErr
		}
		return generated.GateEvidence{}, newStoreError(generated.ErrorCodeIntegrityFailure, "gate-intent-result", false, nil)
	}
	return evidence, nil
}

func (repository *GateRepository) existingGateApply(ctx context.Context, request GateApplyRequest) (generated.GateEvidence, bool, error) {
	var requestDigest, storedDraftID, storedGateID, storedSubjectID, storedPlanID, storedPlanDigest, storedRunID, storedStepID, storedLeaseID string
	var raw []byte
	err := repository.store.Read(ctx, func(tx ReadTx) error {
		return tx.queryRow(ctx, `SELECT i.request_digest,e.draft_id,e.gate_id,e.subject_id,e.plan_id,e.plan_digest,e.run_id,e.step_id,e.lease_id,e.canonical_bytes FROM intent_keys i JOIN audit_events a ON a.event_id=i.event_id JOIN gate_applied_evidence e ON e.evidence_id=a.correlation_id WHERE i.scope='gate-evidence-apply' AND i.key_digest=?`, request.KeyDigest).Scan(&requestDigest, &storedDraftID, &storedGateID, &storedSubjectID, &storedPlanID, &storedPlanDigest, &storedRunID, &storedStepID, &storedLeaseID, &raw)
	})
	if errors.Is(err, sql.ErrNoRows) {
		return generated.GateEvidence{}, false, nil
	}
	if err != nil {
		return generated.GateEvidence{}, false, err
	}
	var evidence generated.GateEvidence
	if json.Unmarshal(raw, &evidence) != nil || generated.ValidateContractJSON(generated.SchemaIDGateEvidence, raw, generated.ContractExact) != nil {
		return generated.GateEvidence{}, true, newStoreError(generated.ErrorCodeIntegrityFailure, "gate-evidence", false, nil)
	}
	status := request.Status
	if status == "" {
		status = "applied"
	}
	sourceKind, proofClass := request.SourceKind, request.ProofClass
	if sourceKind == "" {
		sourceKind = "fixture"
	}
	if proofClass == "" {
		proofClass = "fixture"
	}
	if requestDigest != request.RequestDigest || evidence.EvidenceID != request.EvidenceID || storedDraftID != request.DraftID || storedGateID != request.GateID || storedSubjectID != request.SubjectID || storedPlanID != request.PlanID || storedPlanDigest != request.PlanDigest || storedRunID != request.RunID || storedStepID != request.StepID || storedLeaseID != request.LeaseID || evidence.DeclarationID != request.DeclarationID || evidence.DeclarationRevision != request.DeclarationRevision || evidence.StateRevision != request.Expected.StateRevision+1 || evidence.RecoveryEpoch != request.Expected.RecoveryEpoch || evidence.Status != status || evidence.SourceKind != sourceKind || evidence.ProofClass != proofClass || evidence.ReleaseBuildID != request.ReleaseBuildID || evidence.ToolVersion != request.ToolVersion || evidence.ExpiresAt != request.ExpiresAt || evidence.HumanID != gateHuman(request.Attribution) || !sameGateRelation(evidence.SupersedesEvidenceID, request.SupersedesEvidenceID) || !sameGateRelation(evidence.RevokesEvidenceID, request.RevokesEvidenceID) {
		return generated.GateEvidence{}, true, newStoreError(generated.ErrorCodeStateConflict, "gate-intent-key", false, nil)
	}
	return evidence, true, nil
}

func sameGateRelation(left, right *string) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return *left == *right
}

func gateRelation(ctx context.Context, tx *sql.Tx, evidenceID *string, gateID, subjectID string) error {
	if evidenceID == nil {
		return nil
	}
	var count int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(1) FROM gate_applied_evidence WHERE evidence_id=? AND gate_id=? AND subject_id=? AND status='applied'`, *evidenceID, gateID, subjectID).Scan(&count); err != nil {
		return err
	}
	if count != 1 {
		return newStoreError(generated.ErrorCodePrerequisiteBlocked, "gate-relation", false, nil)
	}
	return nil
}

func gateExactStep(ctx context.Context, tx *sql.Tx, planID, planDigest, runID, stepID, leaseID, declarationID string, declarationRevision int64, targetID, artifactDigest string, expected RevisionToken, operationType, now string) error {
	var count int
	err := tx.QueryRowContext(ctx, `SELECT COUNT(1) FROM immutable_plans p JOIN plan_runs r ON r.plan_id=p.plan_id JOIN plan_run_steps s ON s.run_id=r.run_id JOIN target_execution_leases l ON l.run_id=r.run_id AND l.step_id=s.step_id WHERE p.plan_id=? AND p.plan_digest=? AND p.declaration_id=? AND p.declaration_revision=? AND p.state_revision=? AND p.recovery_epoch=? AND p.expires_at>? AND r.run_id=? AND r.plan_digest=? AND r.state_revision=? AND r.recovery_epoch=? AND r.executor_mode='central' AND r.status='running' AND s.step_id=? AND s.operation_type=? AND s.adapter_id='core.gate' AND s.target_id=? AND s.input_digest=? AND s.artifact_digest=? AND s.effect_state='intent-recorded' AND s.active_lease_id=? AND l.lease_id=? AND l.status='active' AND l.lease_kind='central' AND l.expires_at>? AND l.recovery_epoch=?`, planID, planDigest, declarationID, declarationRevision, expected.StateRevision, expected.RecoveryEpoch, now, runID, planDigest, expected.StateRevision, expected.RecoveryEpoch, stepID, operationType, targetID, artifactDigest, artifactDigest, leaseID, leaseID, now, expected.RecoveryEpoch).Scan(&count)
	if err != nil {
		return err
	}
	if count != 1 {
		return newStoreError(generated.ErrorCodePrerequisiteBlocked, "gate-exact-step", false, nil)
	}
	return nil
}

func (repository *GateRepository) GetAppliedProfileScope(ctx context.Context) (GateAppliedProfile, error) {
	if repository == nil || repository.store == nil {
		return GateAppliedProfile{}, newStoreError(generated.ErrorCodeInputInvalid, "applied-profile", false, nil)
	}
	var scope GateAppliedProfile
	var raw []byte
	err := repository.store.Read(ctx, func(tx ReadTx) error {
		return tx.queryRow(ctx, `SELECT profile_id,profile_version,policy_id,policy_version,capabilities_bytes,state_revision,recovery_epoch FROM gate_applied_profiles WHERE recovery_epoch=(SELECT recovery_epoch FROM system_meta WHERE id=1) AND state_revision<=(SELECT state_revision FROM system_meta WHERE id=1) ORDER BY state_revision DESC,binding_id DESC LIMIT 1`).Scan(&scope.ProfileID, &scope.ProfileVersion, &scope.PolicyID, &scope.PolicyVersion, &raw, &scope.StateRevision, &scope.RecoveryEpoch)
	})
	if errors.Is(err, sql.ErrNoRows) {
		return GateAppliedProfile{}, newStoreError(generated.ErrorCodeResourceNotFound, "applied-profile", false, nil)
	}
	if err != nil {
		return GateAppliedProfile{}, err
	}
	if json.Unmarshal(raw, &scope.Capabilities) != nil {
		return GateAppliedProfile{}, newStoreError(generated.ErrorCodeIntegrityFailure, "applied-profile", false, nil)
	}
	return scope, nil
}

func (repository *GateRepository) ApplyProfileBinding(ctx context.Context, request ProfileApplyRequest) (GateAppliedProfile, error) {
	if repository == nil || repository.store == nil || gateHuman(request.Attribution) == "" || request.BindingID == "" || request.Scope.ProfileID == "" || request.Scope.ProfileVersion == "" || request.Scope.PolicyID == "" || request.Scope.PolicyVersion == "" {
		return GateAppliedProfile{}, newStoreError(generated.ErrorCodeInputInvalid, "profile-binding", false, nil)
	}
	if existing, found, err := repository.existingProfileApply(ctx, request); err != nil || found {
		return existing, err
	}
	current, err := NewPlanRepository(repository.store).CurrentRevision(ctx)
	if err != nil {
		return GateAppliedProfile{}, err
	}
	if current != request.Expected {
		return GateAppliedProfile{}, newStoreError(generated.ErrorCodePlanStale, "profile-plan", false, nil)
	}
	raw, err := json.Marshal(request.Scope.Capabilities)
	if err != nil || len(raw) > 4096 {
		return GateAppliedProfile{}, newStoreError(generated.ErrorCodeInputInvalid, "profile-capabilities", false, err)
	}
	scope := request.Scope
	scope.StateRevision, scope.RecoveryEpoch = request.Expected.StateRevision+1, request.Expected.RecoveryEpoch
	key := audit.IntentKey{Scope: "gate-profile-bind", KeyDigest: audit.Fingerprint(request.KeyDigest), RequestDigest: audit.Fingerprint(request.RequestDigest)}
	after := audit.Fingerprint(gateDigest(raw))
	event := audit.EventDraft{Type: "gate.profile-bound", CorrelationID: request.BindingID, Attribution: request.Attribution, Target: audit.Target{Kind: "profile", ID: scope.ProfileID}, After: &after}
	if audit.ValidateIntentKey(key) != nil || audit.ValidateEventDraft(event) != nil {
		return GateAppliedProfile{}, newStoreError(generated.ErrorCodeInputInvalid, "profile-binding", false, nil)
	}
	appliedAt := repository.store.config.Clock().UTC().Truncate(time.Second).Format(time.RFC3339)
	intent, err := repository.store.writeIntent(ctx, intentRequest{Expected: &request.Expected, Idempotency: key, Event: event}, func(ctx context.Context, tx *sql.Tx) error {
		if err := gateExactStep(ctx, tx, request.PlanID, request.PlanDigest, request.RunID, request.StepID, request.LeaseID, request.DeclarationID, request.DeclarationRevision, scope.ProfileID, gateDigest(raw), request.Expected, "gate.profile.bind", appliedAt); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, `INSERT INTO gate_applied_profiles(binding_id,profile_id,profile_version,policy_id,policy_version,capabilities_bytes,state_revision,recovery_epoch,declaration_id,declaration_revision,plan_id,plan_digest,run_id,step_id,lease_id,human_id,applied_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, request.BindingID, scope.ProfileID, scope.ProfileVersion, scope.PolicyID, scope.PolicyVersion, raw, scope.StateRevision, scope.RecoveryEpoch, request.DeclarationID, request.DeclarationRevision, request.PlanID, request.PlanDigest, request.RunID, request.StepID, request.LeaseID, gateHuman(request.Attribution), appliedAt)
		return err
	})
	if Code(err) == generated.ErrorCodeStateConflict {
		return GateAppliedProfile{}, newStoreError(generated.ErrorCodePlanStale, "profile-plan", false, err)
	}
	if err != nil {
		return GateAppliedProfile{}, err
	}
	if !intent.Created {
		if existing, found, lookupErr := repository.existingProfileApply(ctx, request); lookupErr != nil || found {
			return existing, lookupErr
		}
		return GateAppliedProfile{}, newStoreError(generated.ErrorCodeIntegrityFailure, "profile-intent-result", false, nil)
	}
	return scope, nil
}

func (repository *GateRepository) existingProfileApply(ctx context.Context, request ProfileApplyRequest) (GateAppliedProfile, bool, error) {
	var requestDigest, bindingID, planID, planDigest, runID, stepID, leaseID, declarationID, humanID string
	var declarationRevision int64
	var raw []byte
	var scope GateAppliedProfile
	err := repository.store.Read(ctx, func(tx ReadTx) error {
		return tx.queryRow(ctx, `SELECT i.request_digest,p.binding_id,p.profile_id,p.profile_version,p.policy_id,p.policy_version,p.capabilities_bytes,p.state_revision,p.recovery_epoch,p.declaration_id,p.declaration_revision,p.plan_id,p.plan_digest,p.run_id,p.step_id,p.lease_id,p.human_id FROM intent_keys i JOIN audit_events a ON a.event_id=i.event_id JOIN gate_applied_profiles p ON p.binding_id=a.correlation_id WHERE i.scope='gate-profile-bind' AND i.key_digest=?`, request.KeyDigest).Scan(&requestDigest, &bindingID, &scope.ProfileID, &scope.ProfileVersion, &scope.PolicyID, &scope.PolicyVersion, &raw, &scope.StateRevision, &scope.RecoveryEpoch, &declarationID, &declarationRevision, &planID, &planDigest, &runID, &stepID, &leaseID, &humanID)
	})
	if errors.Is(err, sql.ErrNoRows) {
		return GateAppliedProfile{}, false, nil
	}
	if err != nil {
		return GateAppliedProfile{}, false, err
	}
	if json.Unmarshal(raw, &scope.Capabilities) != nil {
		return GateAppliedProfile{}, true, newStoreError(generated.ErrorCodeIntegrityFailure, "applied-profile", false, nil)
	}
	requestedCaps, marshalErr := json.Marshal(request.Scope.Capabilities)
	if marshalErr != nil || requestDigest != request.RequestDigest || bindingID != request.BindingID || scope.ProfileID != request.Scope.ProfileID || scope.ProfileVersion != request.Scope.ProfileVersion || scope.PolicyID != request.Scope.PolicyID || scope.PolicyVersion != request.Scope.PolicyVersion || string(raw) != string(requestedCaps) || scope.RecoveryEpoch != request.Expected.RecoveryEpoch || scope.StateRevision != request.Expected.StateRevision+1 || planID != request.PlanID || planDigest != request.PlanDigest || runID != request.RunID || stepID != request.StepID || leaseID != request.LeaseID || declarationID != request.DeclarationID || declarationRevision != request.DeclarationRevision || humanID != gateHuman(request.Attribution) {
		return GateAppliedProfile{}, true, newStoreError(generated.ErrorCodeStateConflict, "profile-intent-key", false, nil)
	}
	return scope, true, nil
}
