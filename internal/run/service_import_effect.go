package run

import (
	"context"
	"github.com/vegastack/vegastack-labs/internal/adapter"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/identity"
	"github.com/vegastack/vegastack-labs/internal/servicecatalog"
	"github.com/vegastack/vegastack-labs/internal/store"
)

type ServiceImportEffect struct {
	Repository   *store.ServiceRepository
	Approvals    GateApprovalSource
	VerifyImport func(context.Context, generated.ServiceImportRequest, identity.Principal) error
}

func (e *ServiceImportEffect) Execute(ctx context.Context, b ExactStepBinding) (adapter.Effect, error) {
	if e == nil || e.Repository == nil || e.Approvals == nil || e.VerifyImport == nil || generated.ValidateExecutorLeaseBinding(b.Plan, b.Run, b.Lease) != nil || b.Plan.AuthorizationBranch != "human" || b.Plan.ExecutorMode != "central" || b.Plan.ServiceImport == nil || b.Run.AcknowledgementID == nil || b.Step.AdapterID != servicecatalog.AdapterID || b.Step.OperationType != servicecatalog.Operation || b.Step.EffectState != "intent-recorded" || b.Lease.Status != "active" || b.Lease.RunID != b.Run.RunID || b.Lease.StepID != b.Step.StepID || b.Lease.PlanID != b.Plan.PlanID || b.Lease.PlanDigest != b.Plan.PlanDigest || b.Lease.RecoveryEpoch != b.Plan.Binding.RecoveryEpoch {
		return adapter.Effect{}, runError(generated.ErrorCodeAuthorizationDenied, "service-import-binding")
	}
	in := b.Plan.ServiceImport
	if servicecatalog.ValidateImportRequest(*in) != nil || b.Step.TargetID != in.Definition.ServiceID || b.Step.InputDigest != servicecatalog.Digest(in) || b.Step.ArtifactDigest != servicecatalog.Digest(in) || len(b.Plan.Operations) != 1 {
		return adapter.Effect{}, runError(generated.ErrorCodePlanStale, "service-import-input")
	}
	approved, err := e.Approvals.Get(ctx, b.Plan.PlanID)
	if err != nil || !approved.Consumed || approved.Acknowledgement.Status != "approved" || approved.Acknowledgement.AcknowledgementID != *b.Run.AcknowledgementID || approved.Acknowledgement.PlanDigest != b.Plan.PlanDigest || approved.Acknowledgement.RecoveryEpoch != b.Plan.Binding.RecoveryEpoch || approved.Acknowledgement.HumanID == "" {
		return adapter.Effect{}, runError(generated.ErrorCodeApprovalRequired, "service-import-human")
	}
	attribution := b.Attribution
	attribution.ResponsibleHumanPrincipalID = &approved.Acknowledgement.HumanID
	apply := store.ServiceImportApply{PlanID: b.Plan.PlanID, PlanDigest: b.Plan.PlanDigest, RunID: b.Run.RunID, StepID: b.Step.StepID, LeaseID: b.Lease.LeaseID, Attribution: attribution}
	actor, err := e.Repository.ExecutionActor(ctx, apply)
	if err != nil {
		return adapter.Effect{}, err
	}
	if err := e.VerifyImport(ctx, *in, actor); err != nil {
		return adapter.Effect{}, err
	}
	digest, err := e.Repository.Apply(ctx, apply)
	if err != nil {
		return adapter.Effect{}, err
	}
	return adapter.Effect{Status: "succeeded", ResultDigest: digest, Changed: true, EffectObserved: true}, nil
}
func (e *ServiceImportEffect) Verify(ctx context.Context, b ExactStepBinding, result adapter.Effect) (adapter.Verification, error) {
	if e == nil || e.Repository == nil || b.Plan.ServiceImport == nil || b.Step.AdapterID != servicecatalog.AdapterID || result.Status != "succeeded" || !result.Changed || !result.EffectObserved || result.ResultDigest != servicecatalog.Digest(b.Plan.ServiceImport) {
		return adapter.Verification{}, runError(generated.ErrorCodeIntegrityFailure, "service-import-verification")
	}
	if err := e.Repository.Verify(ctx, b.Plan.PlanID, b.Run.RunID, result.ResultDigest); err != nil {
		return adapter.Verification{}, err
	}
	return adapter.Verification{Verified: true, Digest: result.ResultDigest}, nil
}
