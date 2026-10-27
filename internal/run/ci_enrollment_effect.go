package run

import (
	"context"
	"github.com/vegastack/vegastack-labs/internal/adapter"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"github.com/vegastack/vegastack-labs/internal/store"
)

type CIEnrollmentEffect struct {
	Repository *store.CIEnrollmentRepository
	Approvals  GateApprovalSource
}

func (e *CIEnrollmentEffect) Execute(ctx context.Context, b ExactStepBinding) (adapter.Effect, error) {
	if e == nil || e.Repository == nil || e.Approvals == nil || generated.ValidateExecutorLeaseBinding(b.Plan, b.Run, b.Lease) != nil || b.Plan.AuthorizationBranch != "human" || b.Plan.ExecutorMode != "central" || b.Plan.CIEnrollment == nil || b.Run.AcknowledgementID == nil || b.Step.AdapterID != "core.ci-enrollment" || b.Step.OperationType != "ci.enrollment.register" || b.Step.EffectState != "intent-recorded" || b.Lease.Status != "active" || b.Lease.RunID != b.Run.RunID || b.Lease.StepID != b.Step.StepID || b.Lease.PlanID != b.Plan.PlanID || b.Lease.PlanDigest != b.Plan.PlanDigest || b.Lease.RecoveryEpoch != b.Plan.Binding.RecoveryEpoch {
		return adapter.Effect{}, runError(generated.ErrorCodeAuthorizationDenied, "ci-enrollment-binding")
	}
	in := b.Plan.CIEnrollment
	if b.Step.TargetID != in.Definition.EnrollmentID || b.Step.InputDigest != hostaction.Digest(in) || b.Step.ArtifactDigest != hostaction.Digest(in) || len(b.Plan.Operations) != 1 {
		return adapter.Effect{}, runError(generated.ErrorCodePlanStale, "ci-enrollment-input")
	}
	approved, err := e.Approvals.Get(ctx, b.Plan.PlanID)
	if err != nil || !approved.Consumed || approved.Acknowledgement.Status != "approved" || approved.Acknowledgement.AcknowledgementID != *b.Run.AcknowledgementID || approved.Acknowledgement.PlanDigest != b.Plan.PlanDigest || approved.Acknowledgement.RecoveryEpoch != b.Plan.Binding.RecoveryEpoch || approved.Acknowledgement.HumanID == "" {
		return adapter.Effect{}, runError(generated.ErrorCodeApprovalRequired, "ci-enrollment-human")
	}
	attribution := b.Attribution
	attribution.ResponsibleHumanPrincipalID = &approved.Acknowledgement.HumanID
	apply := store.CIEnrollmentApply{PlanID: b.Plan.PlanID, PlanDigest: b.Plan.PlanDigest, RunID: b.Run.RunID, StepID: b.Step.StepID, LeaseID: b.Lease.LeaseID, Attribution: attribution}
	digest, err := e.Repository.Apply(ctx, apply)
	if err != nil {
		return adapter.Effect{}, err
	}
	return adapter.Effect{Status: "succeeded", ResultDigest: digest, Changed: true, EffectObserved: true}, nil
}
func (e *CIEnrollmentEffect) Verify(ctx context.Context, b ExactStepBinding, result adapter.Effect) (adapter.Verification, error) {
	if e == nil || e.Repository == nil || b.Plan.CIEnrollment == nil || b.Step.AdapterID != "core.ci-enrollment" || result.Status != "succeeded" || !result.Changed || !result.EffectObserved || result.ResultDigest != hostaction.Digest(b.Plan.CIEnrollment) {
		return adapter.Verification{}, runError(generated.ErrorCodeIntegrityFailure, "ci-enrollment-verification")
	}
	if err := e.Repository.Verify(ctx, b.Plan.PlanID, b.Run.RunID, result.ResultDigest); err != nil {
		return adapter.Verification{}, err
	}
	return adapter.Verification{Verified: true, Digest: result.ResultDigest}, nil
}
