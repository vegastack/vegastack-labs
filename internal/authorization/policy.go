package authorization

import (
	"context"
	"errors"

	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/identity"
)

const (
	ReasonAllowed                = "allowed"
	ReasonAuthenticationRequired = "authentication-required"
	ReasonPolicyUnavailable      = "policy-unavailable"
	ReasonPolicyInactive         = "policy-inactive"
	ReasonGrantRevisionStale     = "grant-revision-stale"
	ReasonStateRevisionStale     = "state-revision-stale"
	ReasonRecoveryEpochMismatch  = "recovery-epoch-mismatch"
	ReasonGrantMissing           = "grant-missing"
	ReasonRoleInsufficient       = "role-insufficient"
	ReasonAgentCannotAcknowledge = "agent-cannot-acknowledge"
	ReasonAuthorizationBranch    = "authorization-branch"
	ReasonRiskUnknown            = "risk-unknown"
	ReasonPreauthorizationDenied = "preauthorization-denied"
	ReasonTargetMismatch         = "target-mismatch"
)

type Request struct {
	Action                Action
	Target                Target
	Plan                  *generated.Plan
	Branches              []Branch
	ExpectedGrantRevision int64
	ExpectedStateRevision int64
	ExpectedRecoveryEpoch int64
}

type Decision struct {
	PrincipalID   string
	Action        Action
	Target        Target
	Allowed       bool
	Branch        *Branch
	ReasonCode    string
	GrantRevision int64
	StateRevision int64
	RecoveryEpoch int64
	PlanDigest    string
	Risk          RiskClass
	Scope         EffectiveScope
}

type Evaluator struct{ repository EffectivePolicyRepository }

func NewEvaluator(repository EffectivePolicyRepository) *Evaluator {
	return &Evaluator{repository: repository}
}

func (evaluator *Evaluator) Authorize(ctx context.Context, principal identity.Principal, request Request) (Decision, error) {
	decision := Decision{PrincipalID: principal.ID, Action: request.Action, Target: request.Target, ReasonCode: ReasonAuthenticationRequired}
	if request.Plan != nil {
		decision.PlanDigest = request.Plan.PlanDigest
	}
	if evaluator == nil || evaluator.repository == nil || !identity.ValidPrincipal(principal) || !ValidAction(request.Action) || !ValidAuthorizationTarget(request.Target) {
		return decision, nil
	}
	snapshot, err := evaluator.repository.Snapshot(ctx, principal.ID, request.Target)
	if err != nil {
		decision.ReasonCode = ReasonPolicyUnavailable
		return decision, err
	}
	decision.GrantRevision, decision.StateRevision, decision.RecoveryEpoch = snapshot.GrantRevision, snapshot.StateRevision, snapshot.RecoveryEpoch
	if snapshot.PrincipalID != principal.ID || snapshot.PrincipalKind != identity.EffectivePrincipalKind(principal) || snapshot.Status != EffectiveActive || snapshot.GrantRevision <= 0 {
		decision.ReasonCode = ReasonPolicyInactive
		return decision, nil
	}
	if request.ExpectedGrantRevision > 0 && request.ExpectedGrantRevision != snapshot.GrantRevision {
		decision.ReasonCode = ReasonGrantRevisionStale
		return decision, nil
	}
	if request.ExpectedRecoveryEpoch != 0 && request.ExpectedRecoveryEpoch != snapshot.RecoveryEpoch {
		decision.ReasonCode = ReasonRecoveryEpochMismatch
		return decision, nil
	}
	if request.ExpectedStateRevision > 0 && request.ExpectedStateRevision != snapshot.StateRevision {
		decision.ReasonCode = ReasonStateRevisionStale
		return decision, nil
	}

	branch, reason := requestedBranch(request, principal)
	if reason != "" {
		decision.ReasonCode = reason
		return decision, nil
	}
	decision.Branch = branch

	risk := RiskRoutine
	if request.Action == ActionAcknowledge || request.Action == ActionExecute {
		if request.Plan == nil {
			decision.Branch = nil
			decision.ReasonCode = ReasonRiskUnknown
			return decision, nil
		}
		classified, classifyErr := ClassifyPlan(*request.Plan)
		if classifyErr != nil {
			decision.Branch = nil
			decision.ReasonCode = ReasonRiskUnknown
			return decision, nil
		}
		risk = classified
		decision.Risk = risk
		if request.Plan.Binding.RecoveryEpoch != snapshot.RecoveryEpoch {
			decision.Branch = nil
			decision.ReasonCode = ReasonRecoveryEpochMismatch
			return decision, nil
		}
		if request.Plan.Binding.StateRevision != snapshot.StateRevision {
			decision.Branch = nil
			decision.ReasonCode = ReasonStateRevisionStale
			return decision, nil
		}
	}

	if request.Action == ActionAcknowledge && identity.EffectivePrincipalKind(principal) != identity.PrincipalHuman {
		decision.Branch = nil
		decision.ReasonCode = ReasonAgentCannotAcknowledge
		return decision, nil
	}
	if branch != nil && *branch == BranchPreauthorized && !validPreauthorized(principal, request, risk) {
		decision.Branch = nil
		decision.ReasonCode = ReasonPreauthorizationDenied
		return decision, nil
	}
	if request.Plan != nil && !planContainsTarget(*request.Plan, request.Target.ResourceID) {
		decision.Branch = nil
		decision.ReasonCode = ReasonTargetMismatch
		return decision, nil
	}

	grant, found, targetMismatch := matchingGrant(snapshot.Grants, request, branch)
	if !found {
		decision.Branch = nil
		if targetMismatch {
			decision.ReasonCode = ReasonTargetMismatch
		} else {
			decision.ReasonCode = ReasonGrantMissing
		}
		return decision, nil
	}
	if !roleAllows(grant.Role, request.Action, risk) {
		decision.Branch = nil
		decision.ReasonCode = ReasonRoleInsufficient
		return decision, nil
	}
	decision.Allowed = true
	decision.ReasonCode = ReasonAllowed
	decision.Scope, _ = BindEffectiveScope(snapshot, grant, request.Target)
	return decision, nil
}

func requestedBranch(request Request, principal identity.Principal) (*Branch, string) {
	if request.Action == ActionRead || request.Action == ActionAuthor {
		if len(request.Branches) != 0 {
			return nil, ReasonAuthorizationBranch
		}
		return nil, ""
	}
	if len(request.Branches) != 1 || !ValidBranch(request.Branches[0]) {
		return nil, ReasonAuthorizationBranch
	}
	branch := request.Branches[0]
	if request.Plan == nil || request.Plan.AuthorizationBranch != string(branch) {
		return nil, ReasonAuthorizationBranch
	}
	if branch == BranchHuman && identity.EffectivePrincipalKind(principal) == identity.PrincipalPolicy {
		return nil, ReasonAuthorizationBranch
	}
	return &branch, ""
}

func matchingGrant(grants []EffectiveGrant, request Request, branch *Branch) (EffectiveGrant, bool, bool) {
	targetMismatch := false
	for _, grant := range grants {
		if !ValidRole(grant.Role) || grant.Action != request.Action || grant.Capability != request.Target.Capability || grant.ResourceKind != request.Target.ResourceKind {
			continue
		}
		if grant.ResourceID != "" && grant.ResourceID != request.Target.ResourceID {
			targetMismatch = true
			continue
		}
		if branch != nil && grant.Branch != *branch {
			continue
		}
		if branch == nil && grant.Branch != "" {
			continue
		}
		return grant, true, false
	}
	return EffectiveGrant{}, false, targetMismatch
}

func validPreauthorized(principal identity.Principal, request Request, risk RiskClass) bool {
	if identity.EffectivePrincipalKind(principal) != identity.PrincipalPolicy || risk != RiskRoutine || request.Plan == nil {
		return false
	}
	for _, operation := range request.Plan.Operations {
		if !preauthorizedOperation(operation.OperationType) {
			return false
		}
	}
	return planContainsTarget(*request.Plan, request.Target.ResourceID)
}

func planContainsTarget(plan generated.Plan, targetID string) bool {
	for _, operation := range plan.Operations {
		if operation.TargetID == targetID {
			return true
		}
	}
	return false
}

func roleAllows(role Role, action Action, risk RiskClass) bool {
	if !ValidRole(role) || !ValidAction(action) || !ValidRiskClass(risk) {
		return false
	}
	switch role {
	case RoleReader:
		return action == ActionRead
	case RoleAuthor:
		return action == ActionRead || action == ActionAuthor
	case RoleMaintainer:
		return (action == ActionRead || action == ActionAuthor) || ((action == ActionAcknowledge || action == ActionExecute) && (risk == RiskRoutine || risk == RiskProductionLike))
	case RoleInfrastructureAdmin:
		return risk != RiskControlPlane
	case RoleControlPlaneAdmin:
		return true
	case RolePreauthorizedExecutor:
		return action == ActionExecute && risk == RiskRoutine
	default:
		return false
	}
}

func IsRiskClassificationError(err error) bool { return errors.Is(err, errUnknownRisk) }
