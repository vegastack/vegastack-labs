package authorization

import (
	"context"
	"regexp"
	"time"

	"github.com/vegastack/vegastack-labs/internal/audit"
)

var digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

type DecisionRecord struct {
	DecisionID    string
	Decision      Decision
	DecidedAt     time.Time
	CorrelationID string
	Attribution   audit.Attribution
	Idempotency   audit.IntentKey
	Destinations  []audit.OutboxRequirement
}

type EffectivePolicyRepository interface {
	Snapshot(context.Context, string, Target) (EffectivePolicySnapshot, error)
}

type DecisionRecorder interface {
	RecordDecision(context.Context, DecisionRecord) error
}

func ValidDecisionRecord(record DecisionRecord) bool {
	decision := record.Decision
	if !tokenPattern.MatchString(record.DecisionID) || record.DecidedAt.IsZero() || record.DecidedAt.Location() != time.UTC || !tokenPattern.MatchString(record.CorrelationID) ||
		!tokenPattern.MatchString(decision.PrincipalID) || !ValidAction(decision.Action) || !ValidAuthorizationTarget(decision.Target) || !validReasonCode(decision.ReasonCode) ||
		decision.GrantRevision < 0 || decision.StateRevision < 0 || decision.RecoveryEpoch < 0 || (decision.PlanDigest != "" && !digestPattern.MatchString(decision.PlanDigest)) ||
		(decision.Scope.ScopeDigest != "" && !digestPattern.MatchString(decision.Scope.ScopeDigest)) || audit.ValidateIntentKey(record.Idempotency) != nil || audit.ValidateOutboxRequirements(record.Destinations) != nil {
		return false
	}
	if record.Attribution.AuthenticatedPrincipalID != decision.PrincipalID {
		return false
	}
	if decision.Allowed {
		if decision.ReasonCode != ReasonAllowed || decision.Scope.ScopeDigest == "" || decision.Scope.PrincipalID != decision.PrincipalID || decision.Scope.Action != decision.Action ||
			decision.Scope.Capability != decision.Target.Capability || decision.Scope.ResourceKind != decision.Target.ResourceKind || decision.Scope.ResourceID != decision.Target.ResourceID ||
			decision.Scope.GrantRevision != decision.GrantRevision || decision.Scope.StateRevision != decision.StateRevision || decision.Scope.RecoveryEpoch != decision.RecoveryEpoch {
			return false
		}
		if decision.Action == ActionAcknowledge || decision.Action == ActionExecute {
			return decision.Branch != nil && ValidBranch(*decision.Branch)
		}
		return decision.Branch == nil
	}
	return decision.ReasonCode != ReasonAllowed && decision.Branch == nil
}

func validReasonCode(code string) bool {
	switch code {
	case ReasonAllowed, ReasonAuthenticationRequired, ReasonPolicyUnavailable, ReasonPolicyInactive, ReasonGrantRevisionStale, ReasonStateRevisionStale, ReasonRecoveryEpochMismatch, ReasonGrantMissing, ReasonRoleInsufficient, ReasonAgentCannotAcknowledge, ReasonAuthorizationBranch, ReasonRiskUnknown, ReasonPreauthorizationDenied, ReasonTargetMismatch:
		return true
	default:
		return false
	}
}
