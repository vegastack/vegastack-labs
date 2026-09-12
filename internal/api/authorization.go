package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"time"

	"github.com/vegastack/vegastack-labs/internal/audit"
	"github.com/vegastack/vegastack-labs/internal/authorization"
	"github.com/vegastack/vegastack-labs/internal/failure"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/identity"
)

type EffectiveAuthorizer interface {
	Authorize(context.Context, identity.Principal, authorization.Request) (authorization.Decision, error)
}

type EffectiveAuthorizationConfig struct {
	Authorizer EffectiveAuthorizer
	Recorder   authorization.DecisionRecorder
	Clock      func() time.Time
}

func (app *Application) authorizeAction(request *http.Request, action authorization.Action, target authorization.Target) (authorization.EffectiveScope, error) {
	return app.authorize(request, authorization.Request{Action: action, Target: target})
}

// authorizePlanAction is the shared acknowledgement/execution preflight for
// the later transition endpoints. It intentionally accepts the immutable plan
// unchanged and leaves all provider-neutral risk classification to the policy
// evaluator.
func (app *Application) authorizePlanAction(request *http.Request, action authorization.Action, target authorization.Target, plan generated.Plan, branches []authorization.Branch, expected authorization.RevisionBinding) (authorization.EffectiveScope, error) {
	return app.authorize(request, authorization.Request{Action: action, Target: target, Plan: &plan, Branches: branches, Expected: &expected})
}

func (app *Application) authorize(request *http.Request, policyRequest authorization.Request) (authorization.EffectiveScope, error) {
	if app == nil || request == nil || app.effective.Authorizer == nil || app.effective.Recorder == nil || app.effective.Clock == nil {
		return authorization.EffectiveScope{}, apiFailure(generated.ErrorCodeIntegrityFailure, "effective-authorization")
	}
	principal, ok := identity.PrincipalFromContext(request.Context())
	if !ok {
		return authorization.EffectiveScope{}, apiFailure(generated.ErrorCodeAuthenticationRequired, "principal")
	}
	decision, evaluationErr := app.effective.Authorizer.Authorize(request.Context(), principal, policyRequest)
	if evaluationErr != nil || decision.PrincipalID != principal.ID || decision.Action != policyRequest.Action || decision.Target != policyRequest.Target {
		decision = unavailableAuthorizationDecision(principal, policyRequest, decision)
	}
	if err := app.recordAuthorizationDecision(request.Context(), principal, decision); err != nil {
		if apiErrorCode(err) != "" {
			return authorization.EffectiveScope{}, err
		}
		return authorization.EffectiveScope{}, apiFailure(generated.ErrorCodeIntegrityFailure, "authorization-audit")
	}
	if evaluationErr != nil {
		return authorization.EffectiveScope{}, apiFailure(generated.ErrorCodeDependencyUnavailable, "effective-authorization")
	}
	if !decision.Allowed {
		return authorization.EffectiveScope{}, authorizationDecisionFailure(decision.ReasonCode)
	}
	return decision.Scope, nil
}

func unavailableAuthorizationDecision(principal identity.Principal, request authorization.Request, previous authorization.Decision) authorization.Decision {
	decision := authorization.Decision{
		PrincipalID: principal.ID, Action: request.Action, Target: request.Target, ReasonCode: authorization.ReasonPolicyUnavailable,
		GrantRevision: previous.GrantRevision, StateRevision: previous.StateRevision, RecoveryEpoch: previous.RecoveryEpoch,
	}
	if request.Plan != nil {
		decision.PlanDigest = request.Plan.PlanDigest
	}
	return decision
}

func (app *Application) recordAuthorizationDecision(ctx context.Context, principal identity.Principal, decision authorization.Decision) error {
	requestID, err := app.config.Results.RequestID()
	if err != nil {
		return err
	}
	var responsible *identity.Principal
	var agent *audit.AgentMetadata
	switch identity.EffectivePrincipalKind(principal) {
	case identity.PrincipalHuman:
		responsible = &principal
	case identity.PrincipalAgent:
		agent = &audit.AgentMetadata{Name: principal.ID, SessionID: requestID}
	}
	attribution, err := audit.NewAttribution(principal, responsible, agent)
	if err != nil {
		return apiFailure(generated.ErrorCodeIntegrityFailure, "authorization-attribution")
	}
	requestDigest, err := authorizationDecisionDigest(decision)
	if err != nil {
		return apiFailure(generated.ErrorCodeIntegrityFailure, "authorization-audit")
	}
	keyDigest := sha256.Sum256([]byte("authorization-decision-key-v1\x00" + requestID))
	record := authorization.DecisionRecord{
		DecisionID: requestID, Decision: decision, DecidedAt: app.effective.Clock().UTC().Truncate(time.Second), CorrelationID: requestID,
		Attribution: attribution,
		Idempotency: audit.IntentKey{Scope: "authorization-decision", KeyDigest: audit.Fingerprint("sha256:" + hex.EncodeToString(keyDigest[:])), RequestDigest: audit.Fingerprint(requestDigest)},
	}
	if !authorization.ValidDecisionRecord(record) {
		return apiFailure(generated.ErrorCodeIntegrityFailure, "authorization-decision")
	}
	return app.effective.Recorder.RecordDecision(ctx, record)
}

func authorizationDecisionDigest(decision authorization.Decision) (string, error) {
	raw, err := json.Marshal(decision)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(append([]byte("authorization-decision-request-v1\x00"), raw...))
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func authorizationDecisionFailure(reason string) error {
	code := generated.ErrorCodeAuthorizationDenied
	switch reason {
	case authorization.ReasonGrantRevisionStale, authorization.ReasonStateRevisionStale:
		code = generated.ErrorCodePlanStale
	case authorization.ReasonRecoveryEpochMismatch:
		code = generated.ErrorCodeRecoveryEpochMismatch
	case authorization.ReasonAuthorizationBranch, authorization.ReasonPreauthorizationDenied:
		code = generated.ErrorCodeApprovalRequired
	case authorization.ReasonAuthenticationRequired:
		code = generated.ErrorCodeAuthenticationRequired
	}
	return failure.New(code, "effective-authorization", false)
}
