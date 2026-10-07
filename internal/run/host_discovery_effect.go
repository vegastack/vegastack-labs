package run

import (
	"context"
	"github.com/vegastack/vegastack-labs/internal/adapter"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/store"
)

type DiscoveryTargetRepository interface {
	GetDraft(context.Context, string) (store.DiscoveryDraft, error)
	ApplyTarget(context.Context, store.DiscoveryActivation) (string, error)
	VerifyTarget(context.Context, string, string, string) error
}

// HostDiscoveryTargetEffect is a database-only core effect. Like gate/profile
// effects, it consumes the exact engine binding, never a caller's plan claim.
type HostDiscoveryTargetEffect struct {
	Repository       DiscoveryTargetRepository
	Approvals        GateApprovalSource
	RecoveryPrecheck GateVerifier
}

func (e *HostDiscoveryTargetEffect) Execute(ctx context.Context, b ExactStepBinding) (adapter.Effect, error) {
	if e == nil || e.Repository == nil || e.Approvals == nil || e.RecoveryPrecheck == nil || b.Plan.AuthorizationBranch != "human" || b.Plan.ExecutorMode != "central" || b.Run.AcknowledgementID == nil || b.Step.AdapterID != "core.host-discovery-target" || b.Step.EffectState != "intent-recorded" || b.Lease.Status != "active" || b.Lease.RunID != b.Run.RunID || b.Lease.StepID != b.Step.StepID || b.Lease.PlanID != b.Plan.PlanID || b.Lease.PlanDigest != b.Plan.PlanDigest {
		return adapter.Effect{}, runError(generated.ErrorCodeAuthorizationDenied, "discovery-target-binding")
	}
	// The existing fail-closed gate verifier must establish the recovery
	// prerequisite. A plan/acknowledgement alone cannot qualify recovery.
	if len(b.Plan.Operations) != 1 {
		return adapter.Effect{}, runError(generated.ErrorCodeAuthorizationDenied, "discovery-target-plan")
	}
	if err := e.RecoveryPrecheck.VerifySecretStep(ctx, b.Plan, b.Plan.Operations[0]); err != nil {
		return adapter.Effect{}, err
	}
	draft, err := e.Repository.GetDraft(ctx, b.Step.TargetID)
	if err != nil {
		return adapter.Effect{}, err
	}
	if b.Step.OperationType != "host.discovery-target."+draft.Request.Action || b.Step.InputDigest != draft.Digest || b.Step.ArtifactDigest != draft.Digest || len(b.Plan.Operations) != 1 {
		return adapter.Effect{}, runError(generated.ErrorCodePlanStale, "discovery-target-draft")
	}
	approved, err := e.Approvals.Get(ctx, b.Plan.PlanID)
	if err != nil || !approved.Consumed || approved.Acknowledgement.Status != "approved" || approved.Acknowledgement.AcknowledgementID != *b.Run.AcknowledgementID || approved.Acknowledgement.PlanDigest != b.Plan.PlanDigest || approved.Acknowledgement.HumanID == "" {
		return adapter.Effect{}, runError(generated.ErrorCodeApprovalRequired, "discovery-target-human")
	}
	attribution := b.Attribution
	attribution.ResponsibleHumanPrincipalID = &approved.Acknowledgement.HumanID
	digest, err := e.Repository.ApplyTarget(ctx, store.DiscoveryActivation{DraftID: draft.ID, PlanID: b.Plan.PlanID, PlanDigest: b.Plan.PlanDigest, RunID: b.Run.RunID, StepID: b.Step.StepID, LeaseID: b.Lease.LeaseID, Attribution: attribution})
	if err != nil {
		return adapter.Effect{}, err
	}
	return adapter.Effect{Status: "succeeded", ResultDigest: digest, Changed: true, EffectObserved: true}, nil
}
func (e *HostDiscoveryTargetEffect) Verify(ctx context.Context, b ExactStepBinding, result adapter.Effect) (adapter.Verification, error) {
	if e == nil || e.Repository == nil || b.Step.AdapterID != "core.host-discovery-target" || result.Status != "succeeded" || result.ResultDigest != b.Step.InputDigest || result.ResultDigest != b.Step.ArtifactDigest {
		return adapter.Verification{}, runError(generated.ErrorCodeIntegrityFailure, "discovery-target-verification")
	}
	if err := e.Repository.VerifyTarget(ctx, b.Step.TargetID, b.Plan.PlanID, result.ResultDigest); err != nil {
		return adapter.Verification{}, err
	}
	return adapter.Verification{Verified: true, Digest: result.ResultDigest}, nil
}
