package plan

import (
	"context"
	"encoding/json"
	"sort"
	"strings"
	"time"

	"github.com/vegastack/vegastack-labs/internal/change"
	"github.com/vegastack/vegastack-labs/internal/generated"
)

// BuildRestorePlan turns the exact inert restore declaration into an immutable
// human-authorized central plan. It never executes the cutover operation.
func BuildRestorePlan(ctx context.Context, declaration generated.DeclarationRevision, request generated.RestoreRequest, source generated.RestoreSourceBinding, fences []generated.RestoreFenceItem, decision generated.RestoreAuditDecision) (generated.Plan, generated.RestoreBinding, error) {
	if ctx == nil || ctx.Err() != nil || declaration.DeclarationType != "recovery.restore" || declaration.Status != "draft" || len(declaration.Operations) != 2 || len(declaration.Extensions) != 1 || declaration.Extensions[0].Name != "x-restore-binding" {
		return generated.Plan{}, generated.RestoreBinding{}, planError(generated.ErrorCodeInputInvalid)
	}
	bindingDigest, err := change.RestoreBindingDigest(request, source, fences, decision)
	if err != nil || bindingDigest != declaration.Extensions[0].ValueDigest {
		return generated.Plan{}, generated.RestoreBinding{}, planError(generated.ErrorCodeStateConflict)
	}
	operation := declaration.Operations[0]
	canary := declaration.Operations[1]
	if operation.OperationType != "recovery.restore.cutover" || operation.AdapterID != "core.recovery" || operation.Idempotent || operation.InputDigest != declaration.Extensions[0].ValueDigest || canary.Sequence != 2 || canary.OperationID != request.CanaryStepID || canary.OperationType != "recovery.canary.noop" || canary.AdapterID != "core.recovery" || canary.TargetID != request.NewInstanceID || canary.InputDigest != request.CanaryBindingDigest || canary.ArtifactDigest != request.CanaryBindingDigest || !canary.Idempotent {
		return generated.Plan{}, generated.RestoreBinding{}, planError(generated.ErrorCodeInputInvalid)
	}
	created, err := time.Parse(time.RFC3339, declaration.CreatedAt)
	if err != nil {
		return generated.Plan{}, generated.RestoreBinding{}, planError(generated.ErrorCodeInputInvalid)
	}
	targets := append([]string(nil), request.TargetIDs...)
	sort.Strings(targets)
	plan := generated.Plan{Schema: generated.SchemaIDPlan, SchemaVersion: "1.0.0", DeclarationID: declaration.DeclarationID,
		Binding:    generated.PlanBinding{RecoveryEpoch: declaration.RecoveryEpoch, PriorStateRevision: declaration.StateRevision, StateRevision: declaration.StateRevision + 1, DeclarationRevision: declaration.Revision + 1, ObservationFingerprint: source.VerificationDigest, TargetDigest: request.TargetDigest, ReasonDigest: request.AuditDecisionDigest, PolicyVersion: "1.0.0", ToolVersion: "1.0.0", ContractVersion: "1.0.0"},
		Operations: []generated.PlanOperation{{Sequence: 1, OperationID: operation.OperationID, OperationType: operation.OperationType, AdapterID: operation.AdapterID, ExecutorID: "executor-central", TargetID: operation.TargetID, InputDigest: operation.InputDigest, ArtifactDigest: operation.ArtifactDigest, Idempotent: false}, {Sequence: 2, OperationID: canary.OperationID, OperationType: canary.OperationType, AdapterID: canary.AdapterID, ExecutorID: "executor-central", TargetID: canary.TargetID, InputDigest: canary.InputDigest, ArtifactDigest: canary.ArtifactDigest, Idempotent: true}}, Status: "planned", Risk: "control-plane", AuthorizationBranch: "human", ExecutorMode: "central", CreatedAt: created.UTC().Format(time.RFC3339), ExpiresAt: created.Add(time.Duration(generated.PlanValiditySeconds) * time.Second).UTC().Format(time.RFC3339), Extensions: declaration.Extensions}
	readable := readablePlan(plan)
	plan.ReadableDigest = sha([]byte(readable))
	plan.PlanDigest, err = planDigest(plan)
	if err != nil {
		return generated.Plan{}, generated.RestoreBinding{}, planError(generated.ErrorCodeInputInvalid)
	}
	plan.PlanID = "plan-" + strings.TrimPrefix(plan.PlanDigest, "sha256:")[:32]
	raw, err := json.Marshal(plan)
	if err != nil || generated.ValidateContractJSON(generated.SchemaIDPlan, raw, generated.ContractExact) != nil {
		return generated.Plan{}, generated.RestoreBinding{}, planError(generated.ErrorCodeInputInvalid)
	}
	binding := generated.RestoreBinding{Schema: generated.SchemaIDRestoreBinding, SchemaVersion: "1.1.0", Source: source, PointID: request.PointID, DependencyIDs: append([]string(nil), request.DependencyIDs...), TargetIDs: targets, TargetDigest: request.TargetDigest, PlanID: plan.PlanID, PlanDigest: plan.PlanDigest, HumanAcknowledgementID: "pending-human-acknowledgement", FenceSetDigest: request.FenceSetDigest, AuditDecisionDigest: request.AuditDecisionDigest, CandidateDigest: request.CandidateDigest,
		FormerHostID: request.FormerHostID, ReplacementHostID: request.ReplacementHostID, RecoveryDraftID: request.RecoveryDraftID, CiphertextFingerprint: request.CiphertextFingerprint, SourceAdmissionDigest: request.SourceAdmissionDigest, FenceQualificationDigest: request.FenceQualificationDigest,
		RecoveryRunID: request.RecoveryRunID, RecoveryStepID: request.RecoveryStepID, RecoveryLeaseID: request.RecoveryLeaseID, RecoveryChallengeID: request.RecoveryChallengeID, RecoveryReceiptID: request.RecoveryReceiptID,
		CanaryRunID: request.CanaryRunID, CanaryStepID: request.CanaryStepID, CanaryLeaseID: request.CanaryLeaseID, CanaryChallengeID: request.CanaryChallengeID, CanaryReceiptID: request.CanaryReceiptID, CanaryBindingDigest: request.CanaryBindingDigest,
		PriorInstanceID: request.PriorInstanceID, NewInstanceID: request.NewInstanceID, PriorRecoveryEpoch: request.PriorRecoveryEpoch, NextRecoveryEpoch: request.NextRecoveryEpoch, Status: "planned"}
	bindingRaw, err := json.Marshal(binding)
	if err != nil || generated.ValidateContractJSON(generated.SchemaIDRestoreBinding, bindingRaw, generated.ContractExact) != nil {
		return generated.Plan{}, generated.RestoreBinding{}, planError(generated.ErrorCodeInputInvalid)
	}
	return plan, binding, nil
}

func RestorePlanArtifacts(value generated.Plan) ([]byte, string, error) {
	readable := readablePlan(value)
	canonical, err := json.Marshal(value)
	if err != nil || value.ReadableDigest != sha([]byte(readable)) {
		return nil, "", planError(generated.ErrorCodeIntegrityFailure)
	}
	return canonical, readable, nil
}
