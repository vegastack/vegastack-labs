package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/vegastack/vegastack-labs/internal/authorization"
	"github.com/vegastack/vegastack-labs/internal/failure"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/identity"
	"github.com/vegastack/vegastack-labs/internal/result"
)

type apiPolicyRepository struct {
	snapshot authorization.EffectivePolicySnapshot
	err      error
}

func (repository apiPolicyRepository) Snapshot(_ context.Context, principalID string, _ authorization.Target) (authorization.EffectivePolicySnapshot, error) {
	repository.snapshot.PrincipalID = principalID
	return repository.snapshot, repository.err
}

type authorizationRecorderStub struct {
	records []authorization.DecisionRecord
}

func (recorder *authorizationRecorderStub) RecordDecision(_ context.Context, record authorization.DecisionRecord) error {
	recorder.records = append(recorder.records, record)
	return nil
}

func TestPlanPreflightRejectsMixedBranchesAndRecordsSanitizedDecision(t *testing.T) {
	principal := identity.Principal{ID: "human-maintainer", Method: identity.LocalOSPeerMethod, Kind: identity.PrincipalHuman}
	target := authorization.Target{Capability: "application.deploy", ResourceKind: "application", ResourceID: "app-test"}
	plan := apiAuthorizationPlan(authorization.BranchHuman)
	recorder := &authorizationRecorderStub{}
	app := newAuthorizationTestApplication(t, authorization.NewEvaluator(apiPolicyRepository{snapshot: authorization.EffectivePolicySnapshot{
		PrincipalKind: identity.PrincipalHuman, Status: authorization.EffectiveActive, GrantRevision: 7, StateRevision: 12, RecoveryEpoch: 3,
		Grants: []authorization.EffectiveGrant{{Role: authorization.RoleMaintainer, AllowedAction: authorization.ActionExecute, Capability: target.Capability, ResourceKind: target.ResourceKind, ResourceID: target.ResourceID, Branch: authorization.BranchHuman}},
	}}), recorder)
	request := httptest.NewRequest("POST", "/api/v1/runs", nil)
	request = request.WithContext(identity.WithVerifiedPrincipal(request.Context(), principal))
	_, err := app.authorizePlanAction(request, authorization.ActionExecute, target, plan, []authorization.Branch{authorization.BranchHuman, authorization.BranchPreauthorized}, authorization.RevisionBinding{GrantRevision: 7, StateRevision: 12, RecoveryEpoch: 3})
	stable, ok := failure.As(err)
	if !ok || stable.Code != generated.ErrorCodeApprovalRequired || len(recorder.records) != 1 {
		t.Fatalf("mixed branch = %v records=%d", err, len(recorder.records))
	}
	record := recorder.records[0]
	if record.Decision.ReasonCode != authorization.ReasonAuthorizationBranch || !authorization.ValidDecisionRecord(record) || record.Decision.PlanDigest != plan.PlanDigest {
		t.Fatalf("decision record = %#v", record)
	}
}

func TestAllowedPlanPreflightReturnsPersistedGeneratedDecision(t *testing.T) {
	principal := identity.Principal{ID: "human-maintainer", Method: identity.LocalOSPeerMethod, Kind: identity.PrincipalHuman}
	target := authorization.Target{Capability: "application.deploy", ResourceKind: "application", ResourceID: "app-test"}
	plan := apiAuthorizationPlan(authorization.BranchHuman)
	recorder := &authorizationRecorderStub{}
	app := newAuthorizationTestApplication(t, authorization.NewEvaluator(apiPolicyRepository{snapshot: authorization.EffectivePolicySnapshot{
		PrincipalKind: identity.PrincipalHuman, Status: authorization.EffectiveActive, GrantRevision: 7, StateRevision: 12, RecoveryEpoch: 3,
		Grants: []authorization.EffectiveGrant{{Role: authorization.RoleMaintainer, AllowedAction: authorization.ActionExecute, Capability: target.Capability, ResourceKind: target.ResourceKind, ResourceID: target.ResourceID, Branch: authorization.BranchHuman}},
	}}), recorder)
	request := httptest.NewRequest("POST", "/api/v1/plans/plan-test/execute", nil)
	request = request.WithContext(identity.WithVerifiedPrincipal(request.Context(), principal))
	preflight, err := app.authorizePlanAction(request, authorization.ActionExecute, target, plan, []authorization.Branch{authorization.BranchHuman}, authorization.RevisionBinding{GrantRevision: 7, StateRevision: 12, RecoveryEpoch: 3})
	if err != nil || len(recorder.records) != 1 || preflight.Decision.DecisionID != recorder.records[0].DecisionID || preflight.Decision.Schema != generated.SchemaIDAuthorizationDecision || preflight.Scope.ScopeDigest == "" {
		t.Fatalf("preflight=%#v records=%#v err=%v", preflight, recorder.records, err)
	}
	raw, err := json.Marshal(preflight.Decision)
	if err != nil || generated.ValidateContractJSON(generated.SchemaIDAuthorizationDecision, raw, generated.ContractExact) != nil {
		t.Fatalf("generated decision invalid: %s, %v", raw, err)
	}
}

func TestPlanPreflightRejectsAgentAcknowledgement(t *testing.T) {
	principal := identity.Principal{ID: "agent-codex", Method: identity.LocalOSPeerMethod, Kind: identity.PrincipalAgent}
	target := authorization.Target{Capability: "application.deploy", ResourceKind: "application", ResourceID: "app-test"}
	plan := apiAuthorizationPlan(authorization.BranchHuman)
	recorder := &authorizationRecorderStub{}
	app := newAuthorizationTestApplication(t, authorization.NewEvaluator(apiPolicyRepository{snapshot: authorization.EffectivePolicySnapshot{
		PrincipalKind: identity.PrincipalAgent, Status: authorization.EffectiveActive, GrantRevision: 4, StateRevision: 12, RecoveryEpoch: 3,
		Grants: []authorization.EffectiveGrant{{Role: authorization.RoleMaintainer, AllowedAction: authorization.ActionAcknowledge, Capability: target.Capability, ResourceKind: target.ResourceKind, ResourceID: target.ResourceID, Branch: authorization.BranchHuman}},
	}}), recorder)
	request := httptest.NewRequest("POST", "/api/v1/acknowledgements", nil)
	request = request.WithContext(identity.WithVerifiedPrincipal(request.Context(), principal))
	_, err := app.authorizePlanAction(request, authorization.ActionAcknowledge, target, plan, []authorization.Branch{authorization.BranchHuman}, authorization.RevisionBinding{GrantRevision: 4, StateRevision: 12, RecoveryEpoch: 3})
	stable, ok := failure.As(err)
	if !ok || stable.Code != generated.ErrorCodeAuthorizationDenied || len(recorder.records) != 1 || recorder.records[0].Decision.ReasonCode != authorization.ReasonAgentCannotAcknowledge {
		t.Fatalf("agent acknowledgement = %v records=%#v", err, recorder.records)
	}
}

func TestEvaluatorFailureIsAuditedAndFailsClosed(t *testing.T) {
	repositoryFailure := errors.New("private database detail")
	recorder := &authorizationRecorderStub{}
	app := newAuthorizationTestApplication(t, authorization.NewEvaluator(apiPolicyRepository{err: repositoryFailure}), recorder)
	request := httptest.NewRequest("POST", "/api/v1/plans", nil)
	request = request.WithContext(identity.WithVerifiedPrincipal(request.Context(), identity.Principal{ID: "human-author", Method: identity.LocalOSPeerMethod, Kind: identity.PrincipalHuman}))
	_, err := app.authorizeAction(request, authorization.ActionAuthor, authorization.Target{Capability: "plan.author", ResourceKind: "declaration", ResourceID: "declaration-test"})
	stable, ok := failure.As(err)
	if !ok || stable.Code != generated.ErrorCodeDependencyUnavailable || len(recorder.records) != 1 || recorder.records[0].Decision.ReasonCode != authorization.ReasonPolicyUnavailable || err.Error() == repositoryFailure.Error() {
		t.Fatalf("evaluator failure = %v records=%#v", err, recorder.records)
	}
}

func newAuthorizationTestApplication(t *testing.T, authorizer EffectiveAuthorizer, recorder authorization.DecisionRecorder) *Application {
	t.Helper()
	factory := result.NewFactory(result.BuildInfo{ToolVersion: "test", ReleaseBuildID: "test"}, func() (string, error) { return "request-auth-test", nil })
	app, err := NewApplication(Config{Authority: testAuthority{}, Authorizer: allowOperationAuthorizer(), Reads: testReads{}, Results: factory, Cursors: testCursor{}})
	if err != nil {
		t.Fatal(err)
	}
	app.effective = EffectiveAuthorizationConfig{Authorizer: authorizer, Recorder: recorder, Clock: func() time.Time { return time.Date(2026, 9, 13, 0, 0, 0, 0, time.UTC) }}
	return app
}

func apiAuthorizationPlan(branch authorization.Branch) generated.Plan {
	return generated.Plan{
		PlanID: "plan-test", PlanDigest: testAPIDigest("a"), Risk: string(authorization.RiskRoutine), AuthorizationBranch: string(branch),
		Binding:    generated.PlanBinding{StateRevision: 12, RecoveryEpoch: 3},
		Operations: []generated.PlanOperation{{Sequence: 1, OperationID: "operation-test", OperationType: "application.deploy.low-risk", TargetID: "app-test"}},
	}
}
