package run

import (
	"context"
	"github.com/vegastack/vegastack-labs/internal/adapter"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostinglifecycle"
	"github.com/vegastack/vegastack-labs/internal/identity"
	"github.com/vegastack/vegastack-labs/internal/store"
)

type HostingLifecycleEffect struct {
	Repository *store.HostingLifecycleRepository
	Approvals  GateApprovalSource
	Apply      func(context.Context, generated.HostingLifecycleRequest, identity.Principal) (hostinglifecycle.Outcome, error)
}

func (e *HostingLifecycleEffect) Execute(ctx context.Context, b ExactStepBinding) (adapter.Effect, error) {
	if e == nil || e.Repository == nil || e.Approvals == nil || e.Apply == nil || generated.ValidateExecutorLeaseBinding(b.Plan, b.Run, b.Lease) != nil || b.Plan.AuthorizationBranch != "human" || b.Plan.ExecutorMode != "central" || b.Plan.HostingLifecycle == nil || b.Run.AcknowledgementID == nil || b.Step.AdapterID != hostinglifecycle.AdapterID || b.Step.OperationType != hostinglifecycle.Operation || b.Step.EffectState != "intent-recorded" || b.Lease.Status != "active" || b.Lease.RunID != b.Run.RunID || b.Lease.StepID != b.Step.StepID || b.Lease.PlanID != b.Plan.PlanID || b.Lease.PlanDigest != b.Plan.PlanDigest || b.Lease.RecoveryEpoch != b.Plan.Binding.RecoveryEpoch {
		return adapter.Effect{}, runError(generated.ErrorCodeAuthorizationDenied, "hosting-lifecycle-binding")
	}
	in := b.Plan.HostingLifecycle
	if hostinglifecycle.ValidateRequest(*in) != nil || b.Step.TargetID != in.TargetID || b.Step.InputDigest != hostinglifecycle.Digest(in) || b.Step.ArtifactDigest != hostinglifecycle.Digest(in) || len(b.Plan.Operations) != 1 {
		return adapter.Effect{}, runError(generated.ErrorCodePlanStale, "hosting-lifecycle-input")
	}
	approved, err := e.Approvals.Get(ctx, b.Plan.PlanID)
	if err != nil || !approved.Consumed || approved.Acknowledgement.Status != "approved" || approved.Acknowledgement.AcknowledgementID != *b.Run.AcknowledgementID || approved.Acknowledgement.PlanDigest != b.Plan.PlanDigest || approved.Acknowledgement.RecoveryEpoch != b.Plan.Binding.RecoveryEpoch || approved.Acknowledgement.HumanID == "" {
		return adapter.Effect{}, runError(generated.ErrorCodeApprovalRequired, "hosting-lifecycle-human")
	}
	attribution := b.Attribution
	attribution.ResponsibleHumanPrincipalID = &approved.Acknowledgement.HumanID
	apply := store.HostingLifecycleApply{PlanID: b.Plan.PlanID, PlanDigest: b.Plan.PlanDigest, RunID: b.Run.RunID, StepID: b.Step.StepID, LeaseID: b.Lease.LeaseID, Attribution: attribution}
	actor, err := e.Repository.ExecutionActor(ctx, apply)
	if err != nil {
		return adapter.Effect{}, err
	}
	if err = e.Repository.Begin(ctx, apply); err != nil {
		return adapter.Effect{}, err
	}
	outcome, callbackErr := e.Apply(ctx, *in, actor)
	if callbackErr != nil {
		outcome.Status = "partial"
	}
	digest, err := e.Repository.Complete(context.WithoutCancel(ctx), apply, outcome)
	if err != nil {
		return adapter.Effect{Status: "partial", Changed: true, EffectObserved: true}, err
	}
	if callbackErr != nil || outcome.Status != "succeeded" {
		return adapter.Effect{Status: "partial", ResultDigest: digest, Changed: true, EffectObserved: true}, nil
	}
	// Persisted verification also catches authority revoked while the callback ran.
	if e.Repository.Verify(ctx, b.Plan.PlanID, b.Run.RunID, digest) != nil {
		return adapter.Effect{Status: "partial", ResultDigest: digest, Changed: true, EffectObserved: true}, nil
	}
	return adapter.Effect{Status: "succeeded", ResultDigest: digest, Changed: true, EffectObserved: true}, nil
}
func (e *HostingLifecycleEffect) Verify(ctx context.Context, b ExactStepBinding, result adapter.Effect) (adapter.Verification, error) {
	if e == nil || e.Repository == nil || b.Plan.HostingLifecycle == nil || b.Step.AdapterID != hostinglifecycle.AdapterID || result.Status != "succeeded" || !result.Changed || !result.EffectObserved {
		return adapter.Verification{}, runError(generated.ErrorCodeIntegrityFailure, "hosting-lifecycle-verification")
	}
	if err := e.Repository.Verify(ctx, b.Plan.PlanID, b.Run.RunID, result.ResultDigest); err != nil {
		return adapter.Verification{}, err
	}
	return adapter.Verification{Verified: true, Digest: result.ResultDigest}, nil
}
