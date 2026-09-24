package run

import (
	"context"

	"github.com/vegastack/vegastack-labs/internal/adapter"
	"github.com/vegastack/vegastack-labs/internal/generated"
)

// ScheduledObserver performs the two read-only scheduled actions against typed
// authoritative repositories. It returns a digest of the exact observation.
type ScheduledObserver interface {
	ObserveScheduled(context.Context, ExactStepBinding) (string, error)
}

type ScheduleObservationEffect struct{ observer ScheduledObserver }

func NewScheduleObservationEffect(observer ScheduledObserver) (*ScheduleObservationEffect, error) {
	if observer == nil {
		return nil, runError(generated.ErrorCodeInputInvalid, "schedule-observer")
	}
	return &ScheduleObservationEffect{observer: observer}, nil
}

func (effect *ScheduleObservationEffect) Execute(ctx context.Context, binding ExactStepBinding) (adapter.Effect, error) {
	if effect == nil || effect.observer == nil || binding.Plan.AuthorizationBranch != "preauthorized" || binding.Plan.ExecutorMode != "central" || binding.Run.AcknowledgementID != nil || binding.Step.AdapterID != "core.schedule-observe" || (binding.Step.OperationType != "schedule.gate.check" && binding.Step.OperationType != "schedule.observation.refresh") || binding.Step.EffectState != "intent-recorded" || binding.Lease.Status != "active" || binding.Lease.PlanID != binding.Plan.PlanID || binding.Lease.PlanDigest != binding.Plan.PlanDigest || binding.Lease.RunID != binding.Run.RunID || binding.Lease.StepID != binding.Step.StepID || binding.Lease.RecoveryEpoch != binding.Run.RecoveryEpoch {
		return adapter.Effect{}, runError(generated.ErrorCodeAuthorizationDenied, "schedule-observation-binding")
	}
	digest, err := effect.observer.ObserveScheduled(ctx, binding)
	if err != nil {
		return adapter.Effect{}, err
	}
	return adapter.Effect{Status: "succeeded", ResultDigest: digest, Changed: false, EffectObserved: true}, nil
}

func (effect *ScheduleObservationEffect) Verify(ctx context.Context, binding ExactStepBinding, result adapter.Effect) (adapter.Verification, error) {
	if adapter.ValidateEffect(result) != nil || result.Status != "succeeded" || result.ResultDigest == "" || result.Changed {
		return adapter.Verification{}, runError(generated.ErrorCodeIntegrityFailure, "schedule-observation")
	}
	digest, err := effect.observer.ObserveScheduled(ctx, binding)
	return adapter.Verification{Verified: err == nil && digest == result.ResultDigest, Digest: result.ResultDigest}, err
}
