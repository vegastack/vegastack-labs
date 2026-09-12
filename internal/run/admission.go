package run

import (
	"context"
	"time"

	"github.com/vegastack/vegastack-labs/internal/authorization"
	"github.com/vegastack/vegastack-labs/internal/generated"
)

type AcknowledgementSource interface {
	GetAcknowledgement(context.Context, string) (generated.Acknowledgement, error)
}

// AdmissionGate validates only provider-neutral immutable proof bindings. A
// missing proof source denies restart/resume of human-authorized work.
type AdmissionGate struct {
	acknowledgements AcknowledgementSource
	clock            func() time.Time
}

func NewAdmissionGate(source AcknowledgementSource, clock func() time.Time) *AdmissionGate {
	if clock == nil {
		clock = time.Now
	}
	return &AdmissionGate{acknowledgements: source, clock: clock}
}

func (gate *AdmissionGate) Verify(_ context.Context, plan generated.Plan, decision generated.AuthorizationDecision, acknowledgement *generated.Acknowledgement) error {
	if gate == nil || !exactContract(generated.SchemaIDPlan, plan) || !exactContract(generated.SchemaIDAuthorizationDecision, decision) || !decision.Allowed || decision.Action != string(authorization.ActionExecute) || decision.PlanDigest != plan.PlanDigest || decision.RecoveryEpoch != plan.Binding.RecoveryEpoch || decision.Branch == nil || *decision.Branch != plan.AuthorizationBranch {
		return runError(generated.ErrorCodeAuthorizationDenied, "run-admission")
	}
	if plan.AuthorizationBranch == string(authorization.BranchPreauthorized) {
		if acknowledgement != nil {
			return runError(generated.ErrorCodeAuthorizationDenied, "run-admission")
		}
		return nil
	}
	if acknowledgement == nil || !exactContract(generated.SchemaIDAcknowledgement, *acknowledgement) || acknowledgement.Status != "approved" || acknowledgement.PlanID != plan.PlanID || acknowledgement.PlanDigest != plan.PlanDigest || acknowledgement.TargetDigest != plan.Binding.TargetDigest || acknowledgement.ReasonDigest != plan.Binding.ReasonDigest || acknowledgement.StateRevision != plan.Binding.StateRevision || acknowledgement.RecoveryEpoch != plan.Binding.RecoveryEpoch || !gate.clock().UTC().Before(parseTime(acknowledgement.ExpiresAt)) {
		return runError(generated.ErrorCodeApprovalRequired, "acknowledgement")
	}
	return nil
}

func (gate *AdmissionGate) VerifyRun(ctx context.Context, plan generated.Plan, current generated.Run) error {
	if current.PlanID != plan.PlanID || current.PlanDigest != plan.PlanDigest || current.RecoveryEpoch != plan.Binding.RecoveryEpoch || current.PolicyVersion != plan.Binding.PolicyVersion {
		return runError(generated.ErrorCodePlanStale, "run-admission")
	}
	if plan.AuthorizationBranch == string(authorization.BranchPreauthorized) {
		if current.AcknowledgementID != nil {
			return runError(generated.ErrorCodeAuthorizationDenied, "run-admission")
		}
		return nil
	}
	if current.AcknowledgementID == nil || gate.acknowledgements == nil {
		return runError(generated.ErrorCodeApprovalRequired, "acknowledgement")
	}
	acknowledgement, err := gate.acknowledgements.GetAcknowledgement(ctx, *current.AcknowledgementID)
	if err != nil {
		return err
	}
	branch := plan.AuthorizationBranch
	decision := generated.AuthorizationDecision{Schema: generated.SchemaIDAuthorizationDecision, SchemaVersion: "1.0.0", DecisionID: current.AuthorizationDecisionID, PrincipalID: acknowledgement.HumanID, Action: string(authorization.ActionExecute), TargetID: plan.Operations[0].TargetID, Allowed: true, Branch: &branch, ReasonCode: authorization.ReasonAllowed, GrantRevision: 1, RecoveryEpoch: current.RecoveryEpoch, PlanDigest: current.PlanDigest, DecidedAt: current.CreatedAt, Extensions: []generated.ContractExtension{}}
	return gate.Verify(ctx, plan, decision, &acknowledgement)
}
