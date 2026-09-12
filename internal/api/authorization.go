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

type PlanAuthorization struct {
	Scope    authorization.EffectiveScope
	Decision generated.AuthorizationDecision
}

func (app *Application) authorizeAction(request *http.Request, action authorization.Action, target authorization.Target) (authorization.EffectiveScope, error) {
	outcome, err := app.authorize(request, authorization.Request{Action: action, Target: target})
	return outcome.Scope, err
}

// authorizePlanAction is the shared acknowledgement/execution preflight for
// the later transition endpoints. It intentionally accepts the immutable plan
// unchanged and leaves all provider-neutral risk classification to the policy
// evaluator.
func (app *Application) authorizePlanAction(request *http.Request, action authorization.Action, target authorization.Target, plan generated.Plan, branches []authorization.Branch, expected authorization.RevisionBinding) (PlanAuthorization, error) {
	outcome, err := app.authorize(request, authorization.Request{Action: action, Target: target, Plan: &plan, Branches: branches, Expected: &expected})
	if err != nil {
		return PlanAuthorization{}, err
	}
	projected, err := projectAuthorizationDecision(outcome.Record)
	if err != nil {
		return PlanAuthorization{}, err
	}
	return PlanAuthorization{Scope: outcome.Scope, Decision: projected}, nil
}

type authorizationOutcome struct {
	Scope  authorization.EffectiveScope
	Record authorization.DecisionRecord
}

func (app *Application) authorize(request *http.Request, policyRequest authorization.Request) (authorizationOutcome, error) {
	if app == nil || request == nil || app.effective.Authorizer == nil || app.effective.Recorder == nil || app.effective.Clock == nil {
		return authorizationOutcome{}, apiFailure(generated.ErrorCodeIntegrityFailure, "effective-authorization")
	}
	principal, ok := identity.PrincipalFromContext(request.Context())
	if !ok {
		return authorizationOutcome{}, apiFailure(generated.ErrorCodeAuthenticationRequired, "principal")
	}
	decision, evaluationErr := app.effective.Authorizer.Authorize(request.Context(), principal, policyRequest)
	if evaluationErr != nil || decision.PrincipalID != principal.ID || decision.Action != policyRequest.Action || decision.Target != policyRequest.Target {
		decision = unavailableAuthorizationDecision(principal, policyRequest, decision)
	}
	record, err := app.recordAuthorizationDecision(request.Context(), principal, decision)
	if err != nil {
		if apiErrorCode(err) != "" {
			return authorizationOutcome{}, err
		}
		return authorizationOutcome{}, apiFailure(generated.ErrorCodeIntegrityFailure, "authorization-audit")
	}
	if evaluationErr != nil {
		return authorizationOutcome{Record: record}, apiFailure(generated.ErrorCodeDependencyUnavailable, "effective-authorization")
	}
	if !decision.Allowed {
		return authorizationOutcome{Record: record}, authorizationDecisionFailure(decision.ReasonCode)
	}
	return authorizationOutcome{Scope: decision.Scope, Record: record}, nil
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

func (app *Application) recordAuthorizationDecision(ctx context.Context, principal identity.Principal, decision authorization.Decision) (authorization.DecisionRecord, error) {
	requestID, err := app.config.Results.RequestID()
	if err != nil {
		return authorization.DecisionRecord{}, err
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
		return authorization.DecisionRecord{}, apiFailure(generated.ErrorCodeIntegrityFailure, "authorization-attribution")
	}
	requestDigest, err := authorizationDecisionDigest(decision)
	if err != nil {
		return authorization.DecisionRecord{}, apiFailure(generated.ErrorCodeIntegrityFailure, "authorization-audit")
	}
	keyDigest := sha256.Sum256([]byte("authorization-decision-key-v1\x00" + requestID))
	record := authorization.DecisionRecord{
		DecisionID: requestID, Decision: decision, DecidedAt: app.effective.Clock().UTC().Truncate(time.Second), CorrelationID: requestID,
		Attribution: attribution,
		Idempotency: audit.IntentKey{Scope: "authorization-decision", KeyDigest: audit.Fingerprint("sha256:" + hex.EncodeToString(keyDigest[:])), RequestDigest: audit.Fingerprint(requestDigest)},
	}
	if !authorization.ValidDecisionRecord(record) {
		return authorization.DecisionRecord{}, apiFailure(generated.ErrorCodeIntegrityFailure, "authorization-decision")
	}
	if err := app.effective.Recorder.RecordDecision(ctx, record); err != nil {
		return authorization.DecisionRecord{}, err
	}
	return record, nil
}

func projectAuthorizationDecision(record authorization.DecisionRecord) (generated.AuthorizationDecision, error) {
	decision := record.Decision
	var branch *string
	if decision.Branch != nil {
		value := string(*decision.Branch)
		branch = &value
	}
	projected := generated.AuthorizationDecision{
		Schema: generated.SchemaIDAuthorizationDecision, SchemaVersion: "1.0.0", DecisionID: record.DecisionID,
		PrincipalID: decision.PrincipalID, Action: string(decision.Action), TargetID: decision.Target.ResourceID,
		Allowed: decision.Allowed, Branch: branch, ReasonCode: decision.ReasonCode, GrantRevision: decision.GrantRevision,
		RecoveryEpoch: decision.RecoveryEpoch, PlanDigest: decision.PlanDigest, DecidedAt: record.DecidedAt.Format(time.RFC3339),
		Extensions: []generated.ContractExtension{},
	}
	raw, err := json.Marshal(projected)
	if err != nil || generated.ValidateContractJSON(generated.SchemaIDAuthorizationDecision, raw, generated.ContractExact) != nil {
		return generated.AuthorizationDecision{}, apiFailure(generated.ErrorCodeIntegrityFailure, "authorization-decision")
	}
	return projected, nil
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
