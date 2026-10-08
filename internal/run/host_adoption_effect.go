package run

import (
	"context"
	"github.com/vegastack/vegastack-labs/internal/adapter"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostadoption"
	"github.com/vegastack/vegastack-labs/internal/store"
)

type HostAdoptionRepository interface {
	GetDraft(context.Context, string) (store.HostAdoptionDraft, error)
	Apply(context.Context, store.HostAdoptionApply) (generated.ManagedHost, error)
	Verify(context.Context, string, string, string) error
}

// HostAdoptionEffect is a database-only core effect. Like gate/profile
// effects, it consumes the exact engine binding, never a caller's plan claim.
type HostAdoptionEffect struct {
	Repository HostAdoptionRepository
	Approvals  GateApprovalSource
}

func (e *HostAdoptionEffect) Execute(ctx context.Context, b ExactStepBinding) (adapter.Effect, error) {
	if e == nil || e.Repository == nil || e.Approvals == nil || b.Plan.AuthorizationBranch != "human" || b.Plan.ExecutorMode != "central" || b.Run.AcknowledgementID == nil || b.Step.AdapterID != "core.host-adoption" || b.Step.EffectState != "intent-recorded" || b.Lease.Status != "active" || b.Lease.RunID != b.Run.RunID || b.Lease.StepID != b.Step.StepID || b.Lease.PlanID != b.Plan.PlanID || b.Lease.PlanDigest != b.Plan.PlanDigest {
		return adapter.Effect{}, runError(generated.ErrorCodeAuthorizationDenied, "host-adoption-binding")
	}

	draft, err := e.Repository.GetDraft(ctx, b.Step.TargetID)
	if err != nil {
		return adapter.Effect{}, err
	}
	if b.Step.OperationType != "host.adopt" || b.Step.InputDigest != draft.Digest || b.Step.ArtifactDigest != draft.Digest || len(b.Plan.Operations) != 1 || b.Plan.HostAdoption == nil || hostadoption.Digest(*b.Plan.HostAdoption) != draft.Digest {
		return adapter.Effect{}, runError(generated.ErrorCodePlanStale, "host-adoption-draft")
	}
	approved, err := e.Approvals.Get(ctx, b.Plan.PlanID)
	if err != nil || !approved.Consumed || approved.Acknowledgement.Status != "approved" || approved.Acknowledgement.AcknowledgementID != *b.Run.AcknowledgementID || approved.Acknowledgement.PlanDigest != b.Plan.PlanDigest || approved.Acknowledgement.HumanID == "" {
		return adapter.Effect{}, runError(generated.ErrorCodeApprovalRequired, "host-adoption-human")
	}
	attribution := b.Attribution
	attribution.ResponsibleHumanPrincipalID = &approved.Acknowledgement.HumanID
	_, err = e.Repository.Apply(ctx, store.HostAdoptionApply{DraftID: draft.ID, PlanID: b.Plan.PlanID, PlanDigest: b.Plan.PlanDigest, RunID: b.Run.RunID, StepID: b.Step.StepID, LeaseID: b.Lease.LeaseID, Attribution: attribution})
	if err != nil {
		return adapter.Effect{}, err
	}
	return adapter.Effect{Status: "succeeded", ResultDigest: draft.Digest, Changed: true, EffectObserved: true}, nil
}
func (e *HostAdoptionEffect) Verify(ctx context.Context, b ExactStepBinding, result adapter.Effect) (adapter.Verification, error) {
	if e == nil || e.Repository == nil || b.Step.AdapterID != "core.host-adoption" || result.Status != "succeeded" || result.ResultDigest != b.Step.InputDigest || result.ResultDigest != b.Step.ArtifactDigest {
		return adapter.Verification{}, runError(generated.ErrorCodeIntegrityFailure, "host-adoption-verification")
	}
	if err := e.Repository.Verify(ctx, b.Step.TargetID, b.Plan.PlanID, result.ResultDigest); err != nil {
		return adapter.Verification{}, err
	}
	return adapter.Verification{Verified: true, Digest: result.ResultDigest}, nil
}
