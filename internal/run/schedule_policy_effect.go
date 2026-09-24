package run

import (
	"context"

	"github.com/vegastack/vegastack-labs/internal/adapter"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/store"
)

type SchedulePolicyEffect struct {
	repository *store.ScheduleRepository
	approvals  GateApprovalSource
}

func NewSchedulePolicyEffect(repository *store.ScheduleRepository, approvals GateApprovalSource) (*SchedulePolicyEffect, error) {
	if repository == nil || approvals == nil {
		return nil, runError(generated.ErrorCodeInputInvalid, "schedule-policy-effect")
	}
	return &SchedulePolicyEffect{repository: repository, approvals: approvals}, nil
}

func (effect *SchedulePolicyEffect) Execute(ctx context.Context, binding ExactStepBinding) (adapter.Effect, error) {
	if binding.Plan.AuthorizationBranch != "human" || binding.Plan.ExecutorMode != "central" || binding.Run.AcknowledgementID == nil || binding.Step.AdapterID != "core.schedule" || binding.Step.OperationType != "schedule.policy.activate" || binding.Step.EffectState != "intent-recorded" {
		return adapter.Effect{}, runError(generated.ErrorCodeAuthorizationDenied, "schedule-policy-activation")
	}
	draft, err := effect.repository.GetDraft(ctx, binding.Step.TargetID)
	if err != nil {
		return adapter.Effect{}, err
	}
	if draft.Digest != binding.Step.InputDigest || binding.Step.ArtifactDigest != draft.Digest || !hasSchedulePolicyExtension(binding.Plan, draft.Digest) {
		return adapter.Effect{}, runError(generated.ErrorCodePlanStale, "schedule-policy-activation")
	}
	approval, err := effect.approvals.Get(ctx, binding.Plan.PlanID)
	if err != nil || !approval.Consumed || approval.Acknowledgement.Status != "approved" || approval.Acknowledgement.AcknowledgementID != *binding.Run.AcknowledgementID || approval.Acknowledgement.PlanDigest != binding.Plan.PlanDigest || approval.Acknowledgement.HumanID == "" {
		return adapter.Effect{}, runError(generated.ErrorCodeApprovalRequired, "schedule-policy-human")
	}
	attribution := binding.Attribution
	humanID := approval.Acknowledgement.HumanID
	attribution.ResponsibleHumanPrincipalID = &humanID
	policy, err := effect.repository.Activate(ctx, store.ScheduleActivationRequest{DraftID: draft.DraftID, AuthorizationBranch: binding.Plan.AuthorizationBranch, ExecutingOperation: binding.Step.OperationType, PlanID: binding.Plan.PlanID, PlanDigest: binding.Plan.PlanDigest, AcknowledgementID: *binding.Run.AcknowledgementID, ApprovedByHumanID: humanID, Expected: store.RevisionToken{StateRevision: binding.Plan.Binding.StateRevision, RecoveryEpoch: binding.Plan.Binding.RecoveryEpoch}, Attribution: attribution})
	if err != nil {
		return adapter.Effect{}, err
	}
	return adapter.Effect{Status: "succeeded", ResultDigest: draft.Digest, Changed: true, EffectObserved: policy.Enabled}, nil
}

func hasSchedulePolicyExtension(plan generated.Plan, digest string) bool {
	for _, extension := range plan.Extensions {
		if extension.Name == "x-scheduled-policy" && extension.ValueDigest == digest {
			return true
		}
	}
	return false
}

func (effect *SchedulePolicyEffect) Verify(ctx context.Context, binding ExactStepBinding, result adapter.Effect) (adapter.Verification, error) {
	if adapter.ValidateEffect(result) != nil || result.Status != "succeeded" || result.ResultDigest != binding.Step.InputDigest {
		return adapter.Verification{}, runError(generated.ErrorCodeIntegrityFailure, "schedule-policy-effect")
	}
	policy, err := effect.repository.GetActivePolicy(ctx, binding.Step.TargetID)
	if err != nil {
		draft, draftErr := effect.repository.GetDraft(ctx, binding.Step.TargetID)
		if draftErr != nil {
			return adapter.Verification{}, err
		}
		policy, err = effect.repository.GetActivePolicy(ctx, draft.Policy.PolicyID)
	}
	return adapter.Verification{Verified: err == nil && policy.Enabled, Digest: result.ResultDigest}, err
}
