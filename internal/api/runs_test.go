package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/vegastack/vegastack-labs/internal/audit"
	"github.com/vegastack/vegastack-labs/internal/authorization"
	"github.com/vegastack/vegastack-labs/internal/failure"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/identity"
	"github.com/vegastack/vegastack-labs/internal/result"
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
		if response.Code != http.StatusOK || !bytes.Contains(response.Body.Bytes(), []byte(runs.run.RunID)) || !bytes.Contains(response.Body.Bytes(), []byte(`"requestId":"run-submit-test"`)) {
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

func TestConcurrentExactSubmitReadsHumanProofStatusOnce(t *testing.T) {
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
	if runs.submitCalls != 1 || runs.acknowledgementStatusCalls != 1 {
		t.Fatalf("submit/status calls=%d/%d", runs.submitCalls, runs.acknowledgementStatusCalls)
	}
}

func TestRunExecuteFailureAndExactReplayReturnSameDurableResult(t *testing.T) {
	for _, test := range []struct {
		status string
		cause  string
		code   string
		http   int
	}{
		{status: generated.RunStatusFailed, cause: generated.ErrorCodeExecutionFailed, code: generated.ErrorCodeExecutionFailed, http: http.StatusBadGateway},
		{status: generated.RunStatusPartial, cause: generated.ErrorCodeExecutionPartial, code: generated.ErrorCodeRecoveryRequired, http: http.StatusConflict},
		{status: generated.RunStatusInterrupted, cause: generated.ErrorCodeInterrupted, code: generated.ErrorCodeInterrupted, http: http.StatusRequestTimeout},
	} {
		t.Run(test.status, func(t *testing.T) {
			plan := apiRunPlan()
			durable := apiRunResult(plan)
			durable.Status = test.status
			durable.VerificationStatus = "incomplete"
			durable.VerificationDigest = nil
			durable.StateRevision = 41
			durable.RecoveryEpoch = 7
			runs := &runAPIStub{plan: plan, run: durable, submitErr: runengineError{code: test.cause}}
			app := newRunTestApplication(t, runs)
			input := generated.PlanReferenceRequest{Schema: generated.SchemaIDPlanReferenceRequest, SchemaVersion: "1.0.0", PlanID: plan.PlanID, PlanDigest: plan.PlanDigest, RecoveryEpoch: plan.Binding.RecoveryEpoch, IdempotencyKey: test.status + "-submit-test", Extensions: []generated.ContractExtension{}}
			body, _ := json.Marshal(input)

			var first generated.RunResult
			for attempt := range 2 {
				request := httptest.NewRequest(http.MethodPost, "/api/v1/plans/"+plan.PlanID+"/execute", bytes.NewReader(body))
				request.Header.Set("Content-Type", "application/json")
				request = request.WithContext(identity.WithVerifiedPrincipal(request.Context(), identity.Principal{ID: "human-run-test", Method: identity.LocalOSPeerMethod, Kind: identity.PrincipalHuman}))
				response := httptest.NewRecorder()
				app.ServeHTTP(response, request)
				if response.Code != test.http {
					t.Fatalf("attempt %d response=%d body=%s", attempt, response.Code, response.Body.String())
				}
				var envelope generated.RunResult
				if err := json.Unmarshal(response.Body.Bytes(), &envelope); err != nil {
					t.Fatal(err)
				}
				var data generated.Run
				if err := json.Unmarshal(envelope.Data, &data); err != nil {
					t.Fatal(err)
				}
				if envelope.Status != test.status || len(envelope.Errors) != 1 || envelope.Errors[0].Code != test.code || envelope.RunID == nil || *envelope.RunID != durable.RunID || envelope.PlanID == nil || *envelope.PlanID != durable.PlanID || !envelope.Changed || envelope.StateRevision != durable.StateRevision || envelope.RecoveryEpoch != durable.RecoveryEpoch || data.RunID != durable.RunID || data.Status != durable.Status {
					t.Fatalf("attempt %d envelope=%#v data=%#v", attempt, envelope, data)
				}
				if attempt == 0 {
					first = envelope
				} else if envelope.Status != first.Status || envelope.Errors[0] != first.Errors[0] || envelope.RequestID != first.RequestID {
					t.Fatalf("replay changed semantic result: first=%#v replay=%#v", first, envelope)
				}
			}
		})
	}
}

func TestRunExecuteSucceededAfterCommitErrorAndReplayStaySuccessful(t *testing.T) {
	plan := apiRunPlan()
	durable := apiRunResult(plan)
	runs := &runAPIStub{plan: plan, run: durable, submitErr: runengineError{code: generated.ErrorCodeIntegrityFailure}}
	app := newRunTestApplication(t, runs)
	input := generated.PlanReferenceRequest{Schema: generated.SchemaIDPlanReferenceRequest, SchemaVersion: "1.0.0", PlanID: plan.PlanID, PlanDigest: plan.PlanDigest, RecoveryEpoch: plan.Binding.RecoveryEpoch, IdempotencyKey: "succeeded-after-commit-error", Extensions: []generated.ContractExtension{}}
	body, _ := json.Marshal(input)

	for attempt := range 2 {
		request := httptest.NewRequest(http.MethodPost, "/api/v1/plans/"+plan.PlanID+"/execute", bytes.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
		request = request.WithContext(identity.WithVerifiedPrincipal(request.Context(), identity.Principal{ID: "human-run-test", Method: identity.LocalOSPeerMethod, Kind: identity.PrincipalHuman}))
		response := httptest.NewRecorder()
		app.ServeHTTP(response, request)
		if response.Code != http.StatusOK {
			t.Fatalf("attempt %d response=%d body=%s", attempt, response.Code, response.Body.String())
		}
		var envelope generated.RunResult
		if err := json.Unmarshal(response.Body.Bytes(), &envelope); err != nil {
			t.Fatal(err)
		}
		if envelope.Status != generated.RunStatusSucceeded || len(envelope.Errors) != 0 || envelope.RunID == nil || *envelope.RunID != durable.RunID {
			t.Fatalf("attempt %d envelope=%#v", attempt, envelope)
		}
	}
	if runs.submitCalls != 1 {
		t.Fatalf("submit calls = %d", runs.submitCalls)
	}
}

func TestRunGetAuthorizesExactRunIDBeforeReading(t *testing.T) {
	plan := apiRunPlan()
	runs := &runAPIStub{plan: plan, run: apiRunResult(plan)}
	var targets []authorization.ReadTarget
	authorizer := authorizerFunc(func(_ context.Context, principal identity.Principal, target authorization.ReadTarget) (authorization.ReadScope, error) {
		targets = append(targets, target)
		if target.ResourceID != runs.run.RunID {
			return authorization.ReadScope{}, failure.New(generated.ErrorCodeAuthorizationDenied, "read-scope", false)
		}
		return authorization.ReadScope{PrincipalID: principal.ID, Capability: target.Capability, ResourceKind: target.ResourceKind, GrantRevision: 1, ScopeDigest: testAPIDigest("9")}, nil
	})
	app := newRunTestApplicationWithReadAuthorization(t, runs, &effectiveAuthorizationStub{}, authorizer)

	request := httptest.NewRequest(http.MethodGet, "/api/v1/runs/"+runs.run.RunID, nil)
	request = request.WithContext(identity.WithVerifiedPrincipal(request.Context(), identity.Principal{ID: "human-run-test", Method: identity.LocalOSPeerMethod, Kind: identity.PrincipalHuman}))
	response := httptest.NewRecorder()
	app.ServeHTTP(response, request)
	if response.Code != http.StatusOK || len(runs.getIDs) != 1 || runs.getIDs[0] != runs.run.RunID {
		t.Fatalf("allowed response=%d gets=%v body=%s", response.Code, runs.getIDs, response.Body.String())
	}

	request = httptest.NewRequest(http.MethodGet, "/api/v1/runs/run-other", nil)
	request = request.WithContext(identity.WithVerifiedPrincipal(request.Context(), identity.Principal{ID: "human-run-test", Method: identity.LocalOSPeerMethod, Kind: identity.PrincipalHuman}))
	response = httptest.NewRecorder()
	app.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden || len(runs.getIDs) != 1 || len(targets) != 2 || targets[0].ResourceID != runs.run.RunID || targets[1].ResourceID != "run-other" {
		t.Fatalf("denied response=%d targets=%v gets=%v body=%s", response.Code, targets, runs.getIDs, response.Body.String())
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

func TestRunMutationsPassTheExactOperationAndCanonicalIdempotencyRequest(t *testing.T) {
	for _, operation := range []string{"cancel", "resume"} {
		t.Run(operation, func(t *testing.T) {
			plan := apiRunPlan()
			runs := &runAPIStub{plan: plan, run: apiRunResult(plan)}
			app := newRunTestApplication(t, runs)
			input := generated.RunReferenceRequest{Schema: generated.SchemaIDRunReferenceRequest, SchemaVersion: "1.0.0", RunID: runs.run.RunID, IdempotencyKey: operation + "-key", RecoveryEpoch: runs.run.RecoveryEpoch, Extensions: []generated.ContractExtension{{Name: "x-request-binding", ValueDigest: testAPIDigest("8")}}}
			body, _ := json.Marshal(input)

			for range 2 {
				request := httptest.NewRequest(http.MethodPost, "/api/v1/runs/"+runs.run.RunID+"/"+operation, bytes.NewReader(body))
				request.Header.Set("Content-Type", "application/json")
				request = request.WithContext(identity.WithVerifiedPrincipal(request.Context(), identity.Principal{ID: "human-run-test", Method: identity.LocalOSPeerMethod, Kind: identity.PrincipalHuman}))
				response := httptest.NewRecorder()
				app.ServeHTTP(response, request)
				if response.Code != http.StatusOK {
					t.Fatalf("response=%d body=%s", response.Code, response.Body.String())
				}
				var envelope generated.RunResult
				if err := json.Unmarshal(response.Body.Bytes(), &envelope); err != nil {
					t.Fatal(err)
				}
				if envelope.RequestID != input.IdempotencyKey || envelope.RunID == nil || *envelope.RunID != runs.run.RunID || envelope.PlanID == nil || *envelope.PlanID != runs.run.PlanID {
					t.Fatalf("envelope=%#v", envelope)
				}
			}

			if len(runs.mutationCalls) != 2 || len(runs.mutationOperations) != 2 {
				t.Fatalf("mutations=%v operations=%v", runs.mutationCalls, runs.mutationOperations)
			}
			for index := range runs.mutationCalls {
				if runs.mutationOperations[index] != operation || !reflect.DeepEqual(runs.mutationCalls[index], input) {
					t.Fatalf("mutation %d operation=%q request=%#v", index, runs.mutationOperations[index], runs.mutationCalls[index])
				}
			}
		})
	}
}

func TestRunMutationChangedIdempotencyReuseFailsClosed(t *testing.T) {
	plan := apiRunPlan()
	runs := &runAPIStub{plan: plan, run: apiRunResult(plan), mutationErr: failure.New(generated.ErrorCodeStateConflict, "run-mutation-key", false)}
	app := newRunTestApplication(t, runs)
	input := generated.RunReferenceRequest{Schema: generated.SchemaIDRunReferenceRequest, SchemaVersion: "1.0.0", RunID: runs.run.RunID, IdempotencyKey: "changed-reuse-key", RecoveryEpoch: runs.run.RecoveryEpoch, Extensions: []generated.ContractExtension{{Name: "x-request-binding", ValueDigest: testAPIDigest("7")}}}
	body, _ := json.Marshal(input)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/runs/"+runs.run.RunID+"/cancel", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request = request.WithContext(identity.WithVerifiedPrincipal(request.Context(), identity.Principal{ID: "human-run-test", Method: identity.LocalOSPeerMethod, Kind: identity.PrincipalHuman}))
	response := httptest.NewRecorder()
	app.ServeHTTP(response, request)
	if response.Code != http.StatusConflict || !bytes.Contains(response.Body.Bytes(), []byte(`"code":"STATE_CONFLICT"`)) || !bytes.Contains(response.Body.Bytes(), []byte(`"requestId":"changed-reuse-key"`)) {
		t.Fatalf("response=%d body=%s", response.Code, response.Body.String())
	}
}

type runAPIStub struct {
	mu                         sync.Mutex
	plan                       generated.Plan
	run                        generated.Run
	submitCalls                int
	existingCalls              int
	acknowledgementStatusCalls int
	existing                   bool
	last                       runengine.SubmitRequest
	submitErr                  error
	getIDs                     []string
	mutationCalls              []generated.RunReferenceRequest
	mutationOperations         []string
	mutationErr                error
}

func (stub *runAPIStub) Submit(_ context.Context, request runengine.SubmitRequest) (generated.Run, error) {
	stub.mu.Lock()
	defer stub.mu.Unlock()
	stub.submitCalls++
	stub.last = request
	return stub.run, stub.submitErr
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
func (stub *runAPIStub) Get(_ context.Context, id string) (generated.Run, error) {
	stub.mu.Lock()
	defer stub.mu.Unlock()
	stub.getIDs = append(stub.getIDs, id)
	return stub.run, nil
}
func (stub *runAPIStub) MutateAs(_ context.Context, operation string, reference generated.RunReferenceRequest, _ audit.Attribution) (generated.Run, error) {
	stub.mu.Lock()
	defer stub.mu.Unlock()
	stub.mutationOperations = append(stub.mutationOperations, operation)
	stub.mutationCalls = append(stub.mutationCalls, reference)
	return stub.run, stub.mutationErr
}
func (*runAPIStub) Startup(context.Context) error { return nil }
func (stub *runAPIStub) GetPlan(context.Context, string) (store.PlanCommitResult, error) {
	stub.mu.Lock()
	defer stub.mu.Unlock()
	return store.PlanCommitResult{Plan: stub.plan}, nil
}
func (stub *runAPIStub) Status(context.Context, string) (generated.Acknowledgement, error) {
	stub.mu.Lock()
	defer stub.mu.Unlock()
	stub.acknowledgementStatusCalls++
	return apiRunAcknowledgement(stub.plan), nil
}

func newRunTestApplication(t *testing.T, runs *runAPIStub) *Application {
	t.Helper()
	effective := &effectiveAuthorizationStub{}
	return newRunTestApplicationWithAuthorization(t, runs, effective)
}

func newRunTestApplicationWithAuthorization(t *testing.T, runs *runAPIStub, effective *effectiveAuthorizationStub) *Application {
	return newRunTestApplicationWithReadAuthorization(t, runs, effective, allowOperationAuthorizer())
}

func newRunTestApplicationWithReadAuthorization(t *testing.T, runs *runAPIStub, effective *effectiveAuthorizationStub, reads authorization.ReadAuthorizer) *Application {
	t.Helper()
	factory := result.NewFactory(result.BuildInfo{ToolVersion: "test", ReleaseBuildID: "test"}, func() (string, error) { return "request-run-test", nil })
	app, err := NewApplication(Config{Authority: testAuthority{}, Authorizer: reads, Reads: testReads{}, Results: factory, Cursors: testCursor{}})
	if err != nil {
		t.Fatal(err)
	}
	app.effective = EffectiveAuthorizationConfig{Authorizer: effective, Recorder: effective, Clock: func() time.Time { return time.Date(2026, 9, 13, 0, 0, 0, 0, time.UTC) }}
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

type runengineError struct{ code string }

func (err runengineError) Error() string { return err.code }
func (err runengineError) Code() string  { return err.code }

func apiRunAcknowledgement(plan generated.Plan) generated.Acknowledgement {
	return generated.Acknowledgement{Schema: generated.SchemaIDAcknowledgement, SchemaVersion: "1.0.0", PlanID: plan.PlanID, PlanDigest: plan.PlanDigest, TargetDigest: plan.Binding.TargetDigest, ReasonDigest: plan.Binding.ReasonDigest, HumanID: "human-run-test", AuthorityID: "authority-test", NonceDigest: testAPIDigest("1"), StateRevision: plan.Binding.StateRevision, RecoveryEpoch: plan.Binding.RecoveryEpoch, ExpiresAt: plan.ExpiresAt, AcknowledgementID: "ack-test", ProofDigest: testAPIDigest("2"), Status: "approved", ReceivedAt: plan.CreatedAt, Extensions: []generated.ContractExtension{}}
}
