package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/vegastack/vegastack-labs/internal/audit"
	"github.com/vegastack/vegastack-labs/internal/authorization"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/identity"
	runengine "github.com/vegastack/vegastack-labs/internal/run"
	"github.com/vegastack/vegastack-labs/internal/store"
)

func TestRunExecuteAuthorizesBeforeParsingAndPreservesDuplicateSubmit(t *testing.T) {
	plan := apiRunPlan()
	runs := &runAPIStub{plan: plan, run: apiRunResult(plan)}
	app := newRunTestApplication(t, runs)
	malformed := httptest.NewRequest(http.MethodPost, "/api/v1/plans/"+plan.PlanID+"/execute", bytes.NewBufferString(`{"secret":"must-not-parse"}`))
	malformed.Header.Set("Content-Type", "application/json")
	malformed = malformed.WithContext(identity.WithVerifiedPrincipal(malformed.Context(), identity.Principal{ID: "human-run-test", Method: identity.LocalOSPeerMethod, Kind: identity.PrincipalHuman}))
	recorder := httptest.NewRecorder()
	app.ServeHTTP(recorder, malformed)
	if recorder.Code != http.StatusBadRequest || runs.submitCalls != 0 {
		t.Fatalf("malformed response=%d submits=%d body=%s", recorder.Code, runs.submitCalls, recorder.Body.String())
	}

	request := generated.PlanReferenceRequest{Schema: generated.SchemaIDPlanReferenceRequest, SchemaVersion: "1.0.0", PlanID: plan.PlanID, PlanDigest: plan.PlanDigest, RecoveryEpoch: plan.Binding.RecoveryEpoch, IdempotencyKey: "run-submit-test", Extensions: []generated.ContractExtension{}}
	body, _ := json.Marshal(request)
	for index := 0; index < 2; index++ {
		httpRequest := httptest.NewRequest(http.MethodPost, "/api/v1/plans/"+plan.PlanID+"/execute", bytes.NewReader(body))
		httpRequest.Header.Set("Content-Type", "application/json")
		httpRequest = httpRequest.WithContext(identity.WithVerifiedPrincipal(httpRequest.Context(), identity.Principal{ID: "human-run-test", Method: identity.LocalOSPeerMethod, Kind: identity.PrincipalHuman}))
		response := httptest.NewRecorder()
		app.ServeHTTP(response, httpRequest)
		if response.Code != http.StatusOK || !bytes.Contains(response.Body.Bytes(), []byte(runs.run.RunID)) {
			t.Fatalf("submit %d response=%d body=%s", index, response.Code, response.Body.String())
		}
	}
	if runs.submitCalls != 1 || runs.existingCalls != 2 || runs.last.Reference.IdempotencyKey != request.IdempotencyKey {
		t.Fatalf("submit/existing calls=%d/%d last=%#v", runs.submitCalls, runs.existingCalls, runs.last)
	}
}

func TestRunExecuteDenialDoesNotReadRequestBody(t *testing.T) {
	plan := apiRunPlan()
	runs := &runAPIStub{plan: plan, run: apiRunResult(plan)}
	effective := &effectiveAuthorizationStub{decision: authorization.Decision{ReasonCode: authorization.ReasonGrantMissing}}
	app := newRunTestApplicationWithAuthorization(t, runs, effective)
	body := &countingBody{data: bytes.NewReader([]byte(`{"secret":"must-not-read"}`))}
	request := httptest.NewRequest(http.MethodPost, "/api/v1/plans/"+plan.PlanID+"/execute", nil)
	request.Body = body
	request.ContentLength = int64(body.data.Len())
	request.Header.Set("Content-Type", "application/json")
	request = request.WithContext(identity.WithVerifiedPrincipal(request.Context(), identity.Principal{ID: "human-run-test", Method: identity.LocalOSPeerMethod, Kind: identity.PrincipalHuman}))
	response := httptest.NewRecorder()
	app.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden || body.reads != 0 || runs.submitCalls != 0 {
		t.Fatalf("denial response/reads/submits = %d/%d/%d %s", response.Code, body.reads, runs.submitCalls, response.Body.String())
	}
}

func TestConcurrentExactSubmitConsumesHumanProofOnce(t *testing.T) {
	plan := apiRunPlan()
	runs := &runAPIStub{plan: plan, run: apiRunResult(plan)}
	app := newRunTestApplication(t, runs)
	input := generated.PlanReferenceRequest{Schema: generated.SchemaIDPlanReferenceRequest, SchemaVersion: "1.0.0", PlanID: plan.PlanID, PlanDigest: plan.PlanDigest, RecoveryEpoch: plan.Binding.RecoveryEpoch, IdempotencyKey: "concurrent-submit-test", Extensions: []generated.ContractExtension{}}
	body, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}

	start := make(chan struct{})
	statuses := make(chan int, 2)
	var requests sync.WaitGroup
	requests.Add(2)
	for range 2 {
		go func() {
			defer requests.Done()
			<-start
			request := httptest.NewRequest(http.MethodPost, "/api/v1/plans/"+plan.PlanID+"/execute", bytes.NewReader(body))
			request.Header.Set("Content-Type", "application/json")
			request = request.WithContext(identity.WithVerifiedPrincipal(request.Context(), identity.Principal{ID: "human-run-test", Method: identity.LocalOSPeerMethod, Kind: identity.PrincipalHuman}))
			response := httptest.NewRecorder()
			app.ServeHTTP(response, request)
			statuses <- response.Code
		}()
	}
	close(start)
	requests.Wait()
	close(statuses)
	for status := range statuses {
		if status != http.StatusOK {
			t.Fatalf("concurrent submit response=%d", status)
		}
	}
	runs.mu.Lock()
	defer runs.mu.Unlock()
	if runs.submitCalls != 1 || runs.acknowledgementCalls != 1 {
		t.Fatalf("submit/proof calls=%d/%d", runs.submitCalls, runs.acknowledgementCalls)
	}
}

func TestRunGetCancelResumeRemainLocalAndRecoveryBound(t *testing.T) {
	plan := apiRunPlan()
	runs := &runAPIStub{plan: plan, run: apiRunResult(plan)}
	app := newRunTestApplication(t, runs)
	for _, path := range []string{"/api/v1/runs/" + runs.run.RunID + "/cancel", "/api/v1/runs/" + runs.run.RunID + "/resume"} {
		wrong := generated.RunReferenceRequest{Schema: generated.SchemaIDRunReferenceRequest, SchemaVersion: "1.0.0", RunID: runs.run.RunID, IdempotencyKey: "operation-test", RecoveryEpoch: 99, Extensions: []generated.ContractExtension{}}
		body, _ := json.Marshal(wrong)
		request := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
		request = request.WithContext(identity.WithVerifiedPrincipal(request.Context(), identity.Principal{ID: "human-run-test", Method: identity.LocalOSPeerMethod, Kind: identity.PrincipalHuman}))
		response := httptest.NewRecorder()
		app.ServeHTTP(response, request)
		if response.Code != http.StatusConflict {
			t.Fatalf("%s status=%d body=%s", path, response.Code, response.Body.String())
		}
	}
	if RemoteReadRequestAllowed(http.MethodPost, "/api/v1/runs/"+runs.run.RunID+"/cancel") || RemoteReadRequestAllowed(http.MethodPost, "/api/v1/runs/"+runs.run.RunID+"/resume") {
		t.Fatal("run mutation became remotely callable")
	}
}

type runAPIStub struct {
	mu                   sync.Mutex
	plan                 generated.Plan
	run                  generated.Run
	submitCalls          int
	existingCalls        int
	acknowledgementCalls int
	existing             bool
	last                 runengine.SubmitRequest
}

func (stub *runAPIStub) Submit(_ context.Context, request runengine.SubmitRequest) (generated.Run, error) {
	stub.mu.Lock()
	defer stub.mu.Unlock()
	stub.submitCalls++
	stub.last = request
	return stub.run, nil
}
func (stub *runAPIStub) Existing(context.Context, generated.PlanReferenceRequest) (generated.Run, bool, error) {
	stub.mu.Lock()
	defer stub.mu.Unlock()
	stub.existingCalls++
	if stub.existing {
		return stub.run, true, nil
	}
	if stub.submitCalls > 0 {
		return stub.run, true, nil
	}
	return generated.Run{}, false, nil
}
func (stub *runAPIStub) Get(context.Context, string) (generated.Run, error)    { return stub.run, nil }
func (stub *runAPIStub) Cancel(context.Context, string) (generated.Run, error) { return stub.run, nil }
func (stub *runAPIStub) Resume(context.Context, string) (generated.Run, error) { return stub.run, nil }
func (stub *runAPIStub) CancelAs(context.Context, string, audit.Attribution) (generated.Run, error) {
	return stub.run, nil
}
func (stub *runAPIStub) ResumeAs(context.Context, string, audit.Attribution) (generated.Run, error) {
	return stub.run, nil
}
func (*runAPIStub) Startup(context.Context) error { return nil }
func (stub *runAPIStub) GetPlan(context.Context, string) (store.PlanCommitResult, error) {
	stub.mu.Lock()
	defer stub.mu.Unlock()
	return store.PlanCommitResult{Plan: stub.plan}, nil
}
func (stub *runAPIStub) VerifyForExecution(context.Context, string) (generated.Acknowledgement, error) {
	stub.mu.Lock()
	defer stub.mu.Unlock()
	stub.acknowledgementCalls++
	return apiRunAcknowledgement(stub.plan), nil
}
func (stub *runAPIStub) Status(context.Context, string) (generated.Acknowledgement, error) {
	stub.mu.Lock()
	defer stub.mu.Unlock()
	return apiRunAcknowledgement(stub.plan), nil
}

func newRunTestApplication(t *testing.T, runs *runAPIStub) *Application {
	t.Helper()
	effective := &effectiveAuthorizationStub{}
	return newRunTestApplicationWithAuthorization(t, runs, effective)
}

func newRunTestApplicationWithAuthorization(t *testing.T, runs *runAPIStub, effective *effectiveAuthorizationStub) *Application {
	t.Helper()
	app := newAuthorizationTestApplication(t, effective, effective)
	if err := RegisterRunOperations(app, RunOperationConfig{Runs: runs, Plans: runs, Acknowledgements: runs, Results: app.config.Results, Authorization: app.effective}); err != nil {
		t.Fatal(err)
	}
	return app
}

func apiRunPlan() generated.Plan {
	now := time.Date(2026, 9, 13, 0, 0, 0, 0, time.UTC)
	plan := apiAuthorizationPlan(authorization.BranchHuman)
	plan.CreatedAt, plan.ExpiresAt = now.Format(time.RFC3339), now.Add(30*time.Minute).Format(time.RFC3339)
	plan.Status, plan.ExecutorMode = "planned", "central"
	plan.Binding.PolicyVersion, plan.Binding.ToolVersion, plan.Binding.ContractVersion = "1.0.0", "1.0.0", "1.0.0"
	plan.Operations[0].AdapterID, plan.Operations[0].ExecutorID, plan.Operations[0].InputDigest, plan.Operations[0].ArtifactDigest = "adapter-test", "executor-central", testAPIDigest("b"), testAPIDigest("c")
	plan.ReadableDigest, plan.Extensions = testAPIDigest("d"), []generated.ContractExtension{}
	return plan
}

func apiRunResult(plan generated.Plan) generated.Run {
	ack := "ack-test"
	return generated.Run{Schema: generated.SchemaIDRun, SchemaVersion: "1.0.0", RunID: "run-test", PlanID: plan.PlanID, PlanDigest: plan.PlanDigest, AuthorizationDecisionID: "decision-test", AcknowledgementID: &ack, PolicyVersion: plan.Binding.PolicyVersion, ExecutorMode: "central", ExecutorID: "executor-central", ExecutorBindingDigest: testAPIDigest("e"), Status: "succeeded", Steps: []generated.RunStep{}, CancellationRequested: false, RollbackStatus: "not-requested", VerificationStatus: "verified", VerificationDigest: ptrAPITestDigest("f"), Changed: true, StateRevision: plan.Binding.StateRevision, RecoveryEpoch: plan.Binding.RecoveryEpoch, CreatedAt: plan.CreatedAt, UpdatedAt: plan.CreatedAt, Extensions: []generated.ContractExtension{}}
}

func ptrAPITestDigest(fill string) *string { value := testAPIDigest(fill); return &value }

func apiRunAcknowledgement(plan generated.Plan) generated.Acknowledgement {
	return generated.Acknowledgement{Schema: generated.SchemaIDAcknowledgement, SchemaVersion: "1.0.0", PlanID: plan.PlanID, PlanDigest: plan.PlanDigest, TargetDigest: plan.Binding.TargetDigest, ReasonDigest: plan.Binding.ReasonDigest, HumanID: "human-run-test", AuthorityID: "authority-test", NonceDigest: testAPIDigest("1"), StateRevision: plan.Binding.StateRevision, RecoveryEpoch: plan.Binding.RecoveryEpoch, ExpiresAt: plan.ExpiresAt, AcknowledgementID: "ack-test", ProofDigest: testAPIDigest("2"), Status: "approved", ReceivedAt: plan.CreatedAt, Extensions: []generated.ContractExtension{}}
}
