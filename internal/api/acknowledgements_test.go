package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/vegastack/vegastack-labs/internal/acknowledgement"
	"github.com/vegastack/vegastack-labs/internal/authorization"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/identity"
	"github.com/vegastack/vegastack-labs/internal/result"
	"github.com/vegastack/vegastack-labs/internal/store"
)

func TestAcknowledgementRouteDeniesBeforeReadingBody(t *testing.T) {
	body := &countingBody{data: bytes.NewReader([]byte("{broken"))}
	effective := &effectiveAuthorizationStub{decision: authorization.Decision{ReasonCode: authorization.ReasonGrantMissing}}
	app := newAcknowledgementTestApplication(t, effective, &fakeAcknowledgementService{}, fixedAcknowledgementScope{}, fakeAcknowledgementPublisher{})
	request := httptest.NewRequest(http.MethodPost, "/api/v1/plans/plan-test/acknowledgements", nil)
	request.Body = body
	request.Header.Set("Content-Type", "application/json")
	request = request.WithContext(identity.WithVerifiedPrincipal(request.Context(), identity.Principal{ID: "agent.test", Method: identity.LocalOSPeerMethod, Kind: identity.PrincipalAgent}))
	response := httptest.NewRecorder()
	app.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden || body.reads != 0 {
		t.Fatalf("response/reads = %d/%d %s", response.Code, body.reads, response.Body.String())
	}
}

func TestAcknowledgementRoutePublishesOnlyExactServerResolvedBinding(t *testing.T) {
	input := acknowledgementAPIRequest()
	service := &fakeAcknowledgementService{card: acknowledgement.RequestCard{Request: input, AcknowledgementID: "ack-test", Nonce: "nonce-one-time"}, outcome: acknowledgementOutcome(input, "pending")}
	publisher := &recordingAcknowledgementPublisher{}
	app := newAcknowledgementTestApplication(t, &effectiveAuthorizationStub{}, service, fixedAcknowledgementScope{}, publisher)
	response := serveAcknowledgementJSON(t, app, input)
	if response.Code != http.StatusOK || service.requests != 1 || publisher.calls != 1 || !strings.Contains(response.Body.String(), `"status":"pending"`) {
		t.Fatalf("response=%d requests=%d publishes=%d %s", response.Code, service.requests, publisher.calls, response.Body.String())
	}

	tampered := input
	tampered.PlanDigest = testAPIDigest("b")
	response = serveAcknowledgementJSON(t, app, tampered)
	if response.Code != http.StatusForbidden || service.requests != 1 || publisher.calls != 1 {
		t.Fatalf("tampered response=%d requests=%d publishes=%d %s", response.Code, service.requests, publisher.calls, response.Body.String())
	}
}

func newAcknowledgementTestApplication(t *testing.T, effective *effectiveAuthorizationStub, service AcknowledgementService, scopes AcknowledgementScopeResolver, publisher AcknowledgementPublisher) *Application {
	t.Helper()
	factory := result.NewFactory(result.BuildInfo{ToolVersion: "test", ReleaseBuildID: "test"}, func() (string, error) { return "request-ack-test", nil })
	app, err := NewApplication(Config{Authority: testAuthority{}, Authorizer: allowOperationAuthorizer(), Reads: testReads{}, Results: factory, Cursors: testCursor{}})
	if err != nil {
		t.Fatal(err)
	}
	plans := &fakePlanService{result: planAPIResult()}
	if err := RegisterDeclarationPlanOperations(app, DeclarationPlanConfig{Declarations: &fakeDeclarationService{}, Plans: plans, Results: factory, Authorization: EffectiveAuthorizationConfig{Authorizer: effective, Recorder: effective, Clock: func() time.Time { return time.Date(2026, 9, 13, 1, 5, 0, 0, time.UTC) }}}); err != nil {
		t.Fatal(err)
	}
	if err := RegisterAcknowledgementOperations(app, AcknowledgementOperationConfig{Plans: plans, Acknowledgements: service, Scopes: scopes, Publisher: publisher, Results: factory}); err != nil {
		t.Fatal(err)
	}
	return app
}

func serveAcknowledgementJSON(t *testing.T, app *Application, input generated.AcknowledgementRequest) *httptest.ResponseRecorder {
	t.Helper()
	var body bytes.Buffer
	if err := json.NewEncoder(&body).Encode(input); err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/api/v1/plans/plan-test/acknowledgements", &body)
	request.Header.Set("Content-Type", "application/json")
	request = request.WithContext(identity.WithVerifiedPrincipal(request.Context(), identity.Principal{ID: "agent.test", Method: identity.LocalOSPeerMethod, Kind: identity.PrincipalAgent}))
	response := httptest.NewRecorder()
	app.ServeHTTP(response, request)
	return response
}

func acknowledgementAPIRequest() generated.AcknowledgementRequest {
	return generated.AcknowledgementRequest{Schema: generated.SchemaIDAcknowledgementRequest, SchemaVersion: "1.0.0", PlanID: "plan-test", PlanDigest: testAPIDigest("d"), TargetDigest: testAPIDigest("f"), ReasonDigest: testAPIDigest("a"), HumanID: "person-operator", AuthorityID: "authority-slack", NonceDigest: "sha256:70f33a1a23daa3f2788dd35d63f683dc916d6d95686d4452f2f6a99982333f51", StateRevision: 2, RecoveryEpoch: 0, ExpiresAt: "2026-09-13T01:30:00Z", Extensions: []generated.ContractExtension{}}
}

func acknowledgementOutcome(input generated.AcknowledgementRequest, status string) generated.Acknowledgement {
	return generated.Acknowledgement{Schema: generated.SchemaIDAcknowledgement, SchemaVersion: "1.0.0", PlanID: input.PlanID, PlanDigest: input.PlanDigest, TargetDigest: input.TargetDigest, ReasonDigest: input.ReasonDigest, HumanID: input.HumanID, AuthorityID: input.AuthorityID, NonceDigest: input.NonceDigest, StateRevision: input.StateRevision, RecoveryEpoch: input.RecoveryEpoch, ExpiresAt: input.ExpiresAt, AcknowledgementID: "ack-test", ProofDigest: testAPIDigest("e"), Status: status, ReceivedAt: "2026-09-13T01:05:00Z", Extensions: []generated.ContractExtension{}}
}

func planAPIResult() store.PlanCommitResult {
	return store.PlanCommitResult{Plan: generated.Plan{Schema: generated.SchemaIDPlan, SchemaVersion: "1.0.0", PlanID: "plan-test", PlanDigest: testAPIDigest("d"), DeclarationID: "declaration-test", Binding: generated.PlanBinding{RecoveryEpoch: 0, PriorStateRevision: 1, StateRevision: 2, DeclarationRevision: 1, ObservationFingerprint: testAPIDigest("e"), TargetDigest: testAPIDigest("f"), ReasonDigest: testAPIDigest("a"), PolicyVersion: "1.0.0", ToolVersion: "1.0.0", ContractVersion: "1.0.0"}, Operations: []generated.PlanOperation{{Sequence: 1, OperationID: "operation-test", OperationType: "health.check", AdapterID: "adapter-test", ExecutorID: "executor-central", TargetID: "node-test", InputDigest: testAPIDigest("b"), ArtifactDigest: testAPIDigest("c"), Idempotent: true}}, Status: "planned", Risk: "routine", AuthorizationBranch: "human", ExecutorMode: "central", CreatedAt: "2026-09-13T01:00:00Z", ExpiresAt: "2026-09-13T01:30:00Z", ReadableDigest: testAPIDigest("f"), Extensions: []generated.ContractExtension{}}, Commit: store.Commit{Changed: true, StateRevision: 2, RecoveryEpoch: 0}, Created: true}
}

type fakeAcknowledgementService struct {
	card     acknowledgement.RequestCard
	outcome  generated.Acknowledgement
	requests int
}

func (service *fakeAcknowledgementService) Request(context.Context, acknowledgement.Scope, string) (acknowledgement.RequestCard, error) {
	service.requests++
	return service.card, nil
}
func (service *fakeAcknowledgementService) Status(context.Context, string) (generated.Acknowledgement, error) {
	return service.outcome, nil
}

type fixedAcknowledgementScope struct{}

func (fixedAcknowledgementScope) Resolve(context.Context, generated.AcknowledgementRequest) (acknowledgement.Scope, error) {
	return acknowledgement.Scope{Human: identity.Principal{ID: "person-operator", Method: identity.SlackSocketModeMethod, Kind: identity.PrincipalHuman}, AuthorityID: "authority-slack", Nonce: "nonce-one-time"}, nil
}

type fakeAcknowledgementPublisher struct{}

func (fakeAcknowledgementPublisher) Publish(context.Context, acknowledgement.RequestCard) error {
	return nil
}

type recordingAcknowledgementPublisher struct{ calls int }

func (publisher *recordingAcknowledgementPublisher) Publish(context.Context, acknowledgement.RequestCard) error {
	publisher.calls++
	return nil
}
