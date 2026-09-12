package api

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/vegastack/vegastack-labs/internal/authorization"
	"github.com/vegastack/vegastack-labs/internal/change"
	"github.com/vegastack/vegastack-labs/internal/failure"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/identity"
	planengine "github.com/vegastack/vegastack-labs/internal/plan"
	"github.com/vegastack/vegastack-labs/internal/result"
	"github.com/vegastack/vegastack-labs/internal/store"
)

func TestPlanCreateDeniesBeforeMalformedBodyIsRead(t *testing.T) {
	body := &countingBody{data: bytes.NewReader([]byte("{broken"))}
	app := newPlanTestApplication(t, authorizerFunc(func(context.Context, identity.Principal, authorization.ReadTarget) (authorization.ReadScope, error) {
		return authorization.ReadScope{}, failure.New(generated.ErrorCodeAuthorizationDenied, "plan", false)
	}), &fakeDeclarationService{}, &fakePlanService{})
	request := httptest.NewRequest(http.MethodPost, "/api/v1/plans", nil)
	request.Body = body
	request.Header.Set("Content-Type", "application/json")
	request = request.WithContext(identity.WithVerifiedPrincipal(request.Context(), identity.Principal{ID: "principal.test", Method: identity.LocalOSPeerMethod}))
	response := httptest.NewRecorder()
	app.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden || body.reads != 0 {
		t.Fatalf("response/reads = %d/%d %s", response.Code, body.reads, response.Body.String())
	}
}

func TestDeclarationAndPlanRoutesReturnCanonicalDomainResultsWithoutExternalCalls(t *testing.T) {
	declarations := &fakeDeclarationService{result: change.Result{Document: generated.DeclarationRevision{Schema: generated.SchemaIDDeclarationRevision, SchemaVersion: "1.0.0", DeclarationID: "declaration-test", DeclarationType: "node.configuration", Revision: 1, StateRevision: 1, RecoveryEpoch: 0, ContentDigest: testAPIDigest("a"), Status: "draft", Operations: []generated.DeclarationOperation{{Sequence: 1, OperationID: "operation-test", OperationType: "health.check", AdapterID: "adapter-test", TargetID: "node-test", InputDigest: testAPIDigest("b"), ArtifactDigest: testAPIDigest("c"), Idempotent: true}}, CreatedAt: "2026-09-12T19:00:00Z", CreatedBy: "principal.test", AgentSessionID: "request-plan-test", Extensions: []generated.ContractExtension{}}, Changed: true, Created: true}}
	plans := &fakePlanService{result: store.PlanCommitResult{Plan: generated.Plan{Schema: generated.SchemaIDPlan, SchemaVersion: "1.0.0", PlanID: "plan-test", PlanDigest: testAPIDigest("d"), DeclarationID: "declaration-test", Binding: generated.PlanBinding{RecoveryEpoch: 0, PriorStateRevision: 1, StateRevision: 2, DeclarationRevision: 1, ObservationFingerprint: testAPIDigest("e"), TargetDigest: testAPIDigest("f"), ReasonDigest: testAPIDigest("a"), PolicyVersion: "1.0.0", ToolVersion: "1.0.0", ContractVersion: "1.0.0"}, Operations: []generated.PlanOperation{{Sequence: 1, OperationID: "operation-test", OperationType: "health.check", AdapterID: "adapter-test", ExecutorID: "executor-central", TargetID: "node-test", InputDigest: testAPIDigest("b"), ArtifactDigest: testAPIDigest("c"), Idempotent: true}}, Status: "planned", Risk: "routine", AuthorizationBranch: "human", ExecutorMode: "central", CreatedAt: "2026-09-12T19:00:00Z", ExpiresAt: "2026-09-12T19:30:00Z", ReadableDigest: testAPIDigest("f"), Extensions: []generated.ContractExtension{}}, Commit: store.Commit{Changed: true, StateRevision: 2, RecoveryEpoch: 0}, Created: true}}
	app := newPlanTestApplication(t, allowOperationAuthorizer(), declarations, plans)
	revised := serveOperationJSON(t, app, "/api/v1/declarations", map[string]any{"schema": generated.SchemaIDDeclarationRevisionRequest, "schemaVersion": "1.0.0", "declarationId": "declaration-test", "declarationType": "node.configuration", "expectedRevision": 1, "expectedStateRevision": 0, "recoveryEpoch": 0, "operations": declarations.result.Document.Operations, "reasonDigest": testAPIDigest("a"), "extensions": []any{}})
	planned := serveOperationJSON(t, app, "/api/v1/plans", map[string]any{"schema": generated.SchemaIDPlanCreateRequest, "schemaVersion": "1.0.0", "declarationId": "declaration-test", "declarationRevision": 1, "expectedStateRevision": 1, "recoveryEpoch": 0, "observationFingerprint": testAPIDigest("e"), "idempotencyKey": "request-plan-test", "extensions": []any{}})
	if revised.Code != http.StatusOK || planned.Code != http.StatusOK || declarations.calls != 1 || plans.calls != 1 || !strings.Contains(planned.Body.String(), `"planId":"plan-test"`) {
		t.Fatalf("results = %d/%d calls=%d/%d %s", revised.Code, planned.Code, declarations.calls, plans.calls, planned.Body.String())
	}
}

type fakeDeclarationService struct {
	result change.Result
	calls  int
}

func (service *fakeDeclarationService) Revise(context.Context, change.AuthorScope, generated.DeclarationRevisionRequest) (change.Result, error) {
	service.calls++
	return service.result, nil
}
func (service *fakeDeclarationService) Get(context.Context, string, int64) (generated.DeclarationRevision, error) {
	return service.result.Document, nil
}

type fakePlanService struct {
	result store.PlanCommitResult
	calls  int
}

func (service *fakePlanService) Create(context.Context, planengine.AuthorScope, generated.PlanCreateRequest) (store.PlanCommitResult, error) {
	service.calls++
	return service.result, nil
}
func (service *fakePlanService) Get(context.Context, string) (store.PlanCommitResult, error) {
	return service.result, nil
}

func newPlanTestApplication(t *testing.T, authorizer authorization.ReadAuthorizer, declarations DeclarationService, plans PlanService) *Application {
	t.Helper()
	factory := result.NewFactory(result.BuildInfo{ToolVersion: "test", ReleaseBuildID: "test"}, func() (string, error) { return "request-plan-test", nil })
	app, err := NewApplication(Config{Authority: testAuthority{}, Authorizer: authorizer, Reads: testReads{}, Results: factory, Cursors: testCursor{}})
	if err != nil {
		t.Fatal(err)
	}
	if err := RegisterDeclarationPlanOperations(app, DeclarationPlanConfig{Declarations: declarations, Plans: plans, Results: factory}); err != nil {
		t.Fatal(err)
	}
	return app
}

func testAPIDigest(fill string) string { return "sha256:" + strings.Repeat(fill, 64) }
