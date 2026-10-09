package run

import (
	"context"
	"github.com/vegastack/vegastack-labs/internal/adapter"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"github.com/vegastack/vegastack-labs/internal/hostreplacement"
	"github.com/vegastack/vegastack-labs/internal/store"
)

// HostReplacementOperations composes the finite ownership transaction with
// current admission and installed qualified recovery observers. It cannot run
// an arbitrary host command or substitute the responsible human for the actor.
type HostReplacementOperations interface {
	ApplyReplacement(context.Context, generated.Plan, store.HostReplacementExecution) (string, error)
	VerifyReplacement(context.Context, generated.Plan, store.HostReplacementExecution, string) error
}
type HostReplacementEffect struct {
	Operations HostReplacementOperations
	Approvals  GateApprovalSource
}

func replacementEffectShape(b ExactStepBinding) bool {
	if b.Step.AdapterID != hostreplacement.AdapterID || len(b.Plan.Operations) != 1 || b.Step.InputDigest != b.Step.ArtifactDigest {
		return false
	}
	switch b.Step.OperationType {
	case hostreplacement.AliasClaimOperation:
		return b.Plan.HostReplacement == nil && b.Plan.HostAliasClaim != nil && hostreplacement.ValidateAliasClaim(*b.Plan.HostAliasClaim) == nil && hostaction.Digest(*b.Plan.HostAliasClaim) == b.Step.InputDigest && b.Step.TargetID == b.Plan.DeclarationID
	case hostreplacement.FreezeOperation, hostreplacement.CommitOperation:
		return b.Plan.HostAliasClaim == nil && b.Plan.HostReplacement != nil && hostreplacement.ValidateInput(*b.Plan.HostReplacement) == nil && hostaction.Digest(*b.Plan.HostReplacement) == b.Step.InputDigest && b.Step.OperationType == "host.replacement."+b.Plan.HostReplacement.Operation
	default:
		return false
	}
}
func replacementExecution(b ExactStepBinding) store.HostReplacementExecution {
	e := store.HostReplacementExecution{DraftID: b.Step.TargetID, PlanID: b.Plan.PlanID, PlanDigest: b.Plan.PlanDigest, RunID: b.Run.RunID, StepID: b.Step.StepID, LeaseID: b.Lease.LeaseID, Attribution: b.Attribution}
	if b.Plan.HostReplacement != nil {
		e.ReplacementID = b.Plan.HostReplacement.ReplacementID
	}
	return e
}
func (e *HostReplacementEffect) Execute(ctx context.Context, b ExactStepBinding) (adapter.Effect, error) {
	if e == nil || e.Operations == nil || e.Approvals == nil || !replacementEffectShape(b) || b.Plan.AuthorizationBranch != "human" || b.Plan.ExecutorMode != "central" || b.Run.AcknowledgementID == nil || b.Step.EffectState != "intent-recorded" || b.Lease.Status != "active" || b.Lease.RunID != b.Run.RunID || b.Lease.StepID != b.Step.StepID || b.Lease.PlanID != b.Plan.PlanID || b.Lease.PlanDigest != b.Plan.PlanDigest {
		return adapter.Effect{}, runError(generated.ErrorCodeAuthorizationDenied, "host-replacement-binding")
	}
	approved, err := e.Approvals.Get(ctx, b.Plan.PlanID)
	if err != nil || !approved.Consumed || approved.Acknowledgement.Status != "approved" || approved.Acknowledgement.AcknowledgementID != *b.Run.AcknowledgementID || approved.Acknowledgement.PlanDigest != b.Plan.PlanDigest || approved.Acknowledgement.HumanID == "" {
		return adapter.Effect{}, runError(generated.ErrorCodeApprovalRequired, "host-replacement-human")
	}
	x := replacementExecution(b)
	x.Attribution.ResponsibleHumanPrincipalID = &approved.Acknowledgement.HumanID
	digest, err := e.Operations.ApplyReplacement(ctx, b.Plan, x)
	if err != nil {
		return adapter.Effect{}, err
	}
	if digest == "" {
		return adapter.Effect{}, runError(generated.ErrorCodeIntegrityFailure, "host-replacement-result")
	}
	return adapter.Effect{Status: "succeeded", ResultDigest: digest, Changed: true, EffectObserved: true}, nil
}
func (e *HostReplacementEffect) Verify(ctx context.Context, b ExactStepBinding, result adapter.Effect) (adapter.Verification, error) {
	if e == nil || e.Operations == nil || !replacementEffectShape(b) || result.Status != "succeeded" || result.ResultDigest == "" {
		return adapter.Verification{}, runError(generated.ErrorCodeIntegrityFailure, "host-replacement-verification")
	}
	if err := e.Operations.VerifyReplacement(ctx, b.Plan, replacementExecution(b), result.ResultDigest); err != nil {
		return adapter.Verification{}, err
	}
	return adapter.Verification{Verified: true, Digest: result.ResultDigest}, nil
}
