package run

import (
	"context"

	"github.com/vegastack/vegastack-labs/internal/adapter"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/store"
)

type SchedulePolicyEffect struct{ repository *store.ScheduleRepository }

func NewSchedulePolicyEffect(repository *store.ScheduleRepository) (*SchedulePolicyEffect, error) {
	if repository == nil {
		return nil, runError(generated.ErrorCodeInputInvalid, "schedule-policy-effect")
	}
	return &SchedulePolicyEffect{repository: repository}, nil
}

func (effect *SchedulePolicyEffect) Execute(ctx context.Context, binding ExactStepBinding) (adapter.Effect, error) {
	if binding.Plan.AuthorizationBranch != "human" || binding.Plan.ExecutorMode != "central" || binding.Step.AdapterID != "core.schedule" || binding.Step.OperationType != "schedule.policy.activate" || binding.Step.EffectState != "intent-recorded" {
		return adapter.Effect{}, runError(generated.ErrorCodeAuthorizationDenied, "schedule-policy-activation")
	}
	draft, err := effect.repository.GetDraft(ctx, binding.Step.TargetID)
	if err != nil {
		return adapter.Effect{}, err
	}
	if draft.Digest != binding.Step.InputDigest || binding.Step.ArtifactDigest != draft.Digest || draft.Policy.ApprovalPlanID != binding.Plan.PlanID || draft.Policy.ApprovalPlanDigest != binding.Plan.PlanDigest {
		return adapter.Effect{}, runError(generated.ErrorCodePlanStale, "schedule-policy-activation")
	}
	policy, err := effect.repository.Activate(ctx, store.ScheduleActivationRequest{DraftID: draft.DraftID, AuthorizationBranch: binding.Plan.AuthorizationBranch, ExecutingOperation: binding.Step.OperationType, PlanID: binding.Plan.PlanID, PlanDigest: binding.Plan.PlanDigest, Expected: store.RevisionToken{StateRevision: binding.Plan.Binding.StateRevision, RecoveryEpoch: binding.Plan.Binding.RecoveryEpoch}, Attribution: binding.Attribution})
	if err != nil {
		return adapter.Effect{}, err
	}
	return adapter.Effect{Status: "succeeded", ResultDigest: draft.Digest, Changed: true, EffectObserved: policy.Enabled}, nil
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
