package run

import (
	"context"
	"github.com/vegastack/vegastack-labs/internal/adapter"
	"github.com/vegastack/vegastack-labs/internal/backup"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/identity"
	"github.com/vegastack/vegastack-labs/internal/servicerecovery"
	"github.com/vegastack/vegastack-labs/internal/store"
	"time"
)

type ServiceRecoveryEffect struct {
	Repository *store.ServiceRecoveryRepository
	Approvals  GateApprovalSource
	Recover    func(context.Context, generated.ServiceRecoveryRequest, identity.Principal, backup.WriterLease) (servicerecovery.Outcome, error)
}

func (e *ServiceRecoveryEffect) Execute(ctx context.Context, b ExactStepBinding) (adapter.Effect, error) {
	if e == nil || e.Repository == nil || e.Approvals == nil || e.Recover == nil || generated.ValidateExecutorLeaseBinding(b.Plan, b.Run, b.Lease) != nil || b.Plan.AuthorizationBranch != "human" || b.Plan.ExecutorMode != "central" || b.Plan.ServiceRecovery == nil || b.Run.AcknowledgementID == nil || b.Step.AdapterID != servicerecovery.AdapterID || b.Step.OperationType != servicerecovery.Operation || b.Step.EffectState != "intent-recorded" || b.Lease.Status != "active" || b.Lease.RunID != b.Run.RunID || b.Lease.StepID != b.Step.StepID || b.Lease.PlanID != b.Plan.PlanID || b.Lease.PlanDigest != b.Plan.PlanDigest || b.Lease.RecoveryEpoch != b.Plan.Binding.RecoveryEpoch {
		return adapter.Effect{}, runError(generated.ErrorCodeAuthorizationDenied, "service-recovery-binding")
	}
	in := b.Plan.ServiceRecovery
	if servicerecovery.ValidateRequest(*in) != nil || b.Step.TargetID != in.Definition.ServiceID || b.Step.InputDigest != servicerecovery.Digest(in) || b.Step.ArtifactDigest != servicerecovery.Digest(in) || len(b.Plan.Operations) != 1 {
		return adapter.Effect{}, runError(generated.ErrorCodePlanStale, "service-recovery-input")
	}
	approved, err := e.Approvals.Get(ctx, b.Plan.PlanID)
	if err != nil || !approved.Consumed || approved.Acknowledgement.Status != "approved" || approved.Acknowledgement.AcknowledgementID != *b.Run.AcknowledgementID || approved.Acknowledgement.PlanDigest != b.Plan.PlanDigest || approved.Acknowledgement.RecoveryEpoch != b.Plan.Binding.RecoveryEpoch || approved.Acknowledgement.HumanID == "" {
		return adapter.Effect{}, runError(generated.ErrorCodeApprovalRequired, "service-recovery-human")
	}
	attribution := b.Attribution
	attribution.ResponsibleHumanPrincipalID = &approved.Acknowledgement.HumanID
	apply := store.ServiceRecoveryApply{PlanID: b.Plan.PlanID, PlanDigest: b.Plan.PlanDigest, RunID: b.Run.RunID, StepID: b.Step.StepID, LeaseID: b.Lease.LeaseID, Attribution: attribution}
	actor, err := e.Repository.ExecutionActor(ctx, apply)
	if err != nil {
		return adapter.Effect{}, err
	}
	if err = e.Repository.Begin(ctx, apply); err != nil {
		return adapter.Effect{}, err
	}
	deadline, parseErr := time.Parse(time.RFC3339, b.Lease.MaximumExpiresAt)
	if parseErr != nil {
		return adapter.Effect{}, parseErr
	}
	lease := backup.WriterLease{PolicyID: in.Binding.PolicyID, PointID: in.BackupPointID, PlanID: b.Plan.PlanID, PlanDigest: b.Plan.PlanDigest, RunID: b.Run.RunID, StepID: b.Step.StepID, LeaseID: b.Lease.LeaseID, RepositoryClass: "critical", TargetID: in.Definition.ServiceID, SourceRevision: in.ExpectedStateRevision, RecoveryEpoch: in.RecoveryEpoch, MaximumExpiresAt: deadline}
	outcome, callbackErr := e.Recover(ctx, *in, actor, lease)
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
func (e *ServiceRecoveryEffect) Verify(ctx context.Context, b ExactStepBinding, result adapter.Effect) (adapter.Verification, error) {
	if e == nil || e.Repository == nil || b.Plan.ServiceRecovery == nil || b.Step.AdapterID != servicerecovery.AdapterID || result.Status != "succeeded" || !result.Changed || !result.EffectObserved {
		return adapter.Verification{}, runError(generated.ErrorCodeIntegrityFailure, "service-recovery-verification")
	}
	if err := e.Repository.Verify(ctx, b.Plan.PlanID, b.Run.RunID, result.ResultDigest); err != nil {
		return adapter.Verification{}, err
	}
	return adapter.Verification{Verified: true, Digest: result.ResultDigest}, nil
}
