package localapi

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/runprotocol"
	"github.com/vegastack/vegastack-labs/internal/serverconfig"
)

func TestPlanReadsServerPreparationBeforeExactCreate(t *testing.T) {
	plan := clientPhase4Plan()
	preparation := generated.PlanPreparation{Schema: generated.SchemaIDPlanPreparation, SchemaVersion: "1.0.0", DeclarationID: plan.DeclarationID, DeclarationRevision: 1, ExpectedStateRevision: 6, RecoveryEpoch: 2, ObservationFingerprint: plan.Binding.ObservationFingerprint}
	var requests []capturedRequest
	profile := servePhase4(t, func(writer http.ResponseWriter, request *http.Request) {
		body, _ := io.ReadAll(request.Body)
		requests = append(requests, capturedRequest{method: request.Method, path: request.URL.Path, body: body})
		if len(requests) == 1 {
			writePhase4Envelope(t, writer, "api.v1.declarations.plan-preparation.get", false, 2, 6, preparation)
			return
		}
		writePhase4Envelope(t, writer, "api.v1.plans.create", true, 2, 7, clientPlanPresentation(plan))
	})
	response, err := NewClient(clientTestFactory()).Plan(context.Background(), profile, plan.DeclarationID, 1)
	if err != nil || response.Data.PlanDigest != plan.PlanDigest || len(requests) != 2 || requests[0].method != http.MethodGet || requests[0].path != "/api/v1/declarations/declaration-1/revisions/1/plan-preparation" || requests[1].method != http.MethodPost || requests[1].path != "/api/v1/declarations/declaration-1/plans" {
		t.Fatalf("Plan() response=%#v requests=%#v err=%v", response, requests, err)
	}
	var input generated.PlanCreateRequest
	if json.Unmarshal(requests[1].body, &input) != nil || input.ExpectedStateRevision != 6 || input.RecoveryEpoch != 2 || input.ObservationFingerprint != preparation.ObservationFingerprint || input.IdempotencyKey != "request-local" {
		t.Fatalf("plan create input = %s", requests[1].body)
	}
}

func TestApplyDisconnectInspectsDerivedRunExactlyOnce(t *testing.T) {
	plan := clientPhase4Plan()
	runID := runprotocol.ID(plan.PlanID, "request-local")
	run := clientPhase4Run(plan, runID)
	var mu sync.Mutex
	var requests []capturedRequest
	profile := servePhase4(t, func(writer http.ResponseWriter, request *http.Request) {
		body, _ := io.ReadAll(request.Body)
		mu.Lock()
		requests = append(requests, capturedRequest{method: request.Method, path: request.URL.Path, body: body})
		mu.Unlock()
		switch {
		case request.Method == http.MethodGet && request.URL.Path == "/api/v1/plans/plan-1":
			writePhase4Envelope(t, writer, "api.v1.plans.get", false, 2, 7, clientPlanPresentation(plan))
		case request.Method == http.MethodPost && request.URL.Path == "/api/v1/plans/plan-1/execute":
			connection, _, err := writer.(http.Hijacker).Hijack()
			if err != nil {
				t.Error(err)
				return
			}
			_ = connection.Close()
		case request.Method == http.MethodGet && request.URL.Path == "/api/v1/runs/"+runID:
			writePhase4Envelope(t, writer, "api.v1.runs.get", false, 2, 7, clientRunPresentation(run))
		default:
			t.Errorf("unexpected request %s %s", request.Method, request.URL.Path)
		}
	})
	response, err := NewClient(clientTestFactory()).Apply(context.Background(), profile, plan.PlanID)
	mu.Lock()
	defer mu.Unlock()
	if err != nil || response.Data.Run.RunID != runID || len(requests) != 3 {
		t.Fatalf("Apply() response=%#v requests=%#v err=%v", response, requests, err)
	}
	var submitted generated.PlanReferenceRequest
	if json.Unmarshal(requests[1].body, &submitted) != nil || submitted.PlanID != plan.PlanID || submitted.PlanDigest != plan.PlanDigest || submitted.RecoveryEpoch != 2 || submitted.IdempotencyKey != "request-local" {
		t.Fatalf("submit input = %s", requests[1].body)
	}
}

func TestApplyDisconnectAbsentOrMalformedRunRemainsUncertainWithoutResubmit(t *testing.T) {
	plan := clientPhase4Plan()
	runID := runprotocol.ID(plan.PlanID, "request-local")
	for _, mode := range []string{"absent", "malformed"} {
		t.Run(mode, func(t *testing.T) {
			var mu sync.Mutex
			var requests []capturedRequest
			profile := servePhase4(t, func(writer http.ResponseWriter, request *http.Request) {
				body, _ := io.ReadAll(request.Body)
				mu.Lock()
				requests = append(requests, capturedRequest{method: request.Method, path: request.URL.Path, body: body})
				mu.Unlock()
				switch {
				case request.Method == http.MethodGet && request.URL.Path == "/api/v1/plans/plan-1":
					writePhase4Envelope(t, writer, "api.v1.plans.get", false, 2, 7, clientPlanPresentation(plan))
				case request.Method == http.MethodPost && request.URL.Path == "/api/v1/plans/plan-1/execute":
					connection, _, err := writer.(http.Hijacker).Hijack()
					if err != nil {
						t.Error(err)
						return
					}
					_ = connection.Close()
				case request.Method == http.MethodGet && request.URL.Path == "/api/v1/runs/"+runID && mode == "absent":
					envelope, err := clientTestFactory().FailureWithRequestID("api.v1.runs.get", "request-absent", generated.RunStatusFailed, generated.ErrorCodeResourceNotFound, "run", false, 0, 0, struct{}{})
					if err != nil {
						t.Fatal(err)
					}
					writer.Header().Set("Content-Type", "application/json")
					writer.WriteHeader(http.StatusNotFound)
					_ = json.NewEncoder(writer).Encode(envelope)
				case request.Method == http.MethodGet && request.URL.Path == "/api/v1/runs/"+runID:
					writer.Header().Set("Content-Type", "application/json")
					_, _ = writer.Write([]byte("{malformed\n"))
				default:
					t.Errorf("unexpected request %s %s", request.Method, request.URL.Path)
				}
			})
			_, err := NewClient(clientTestFactory()).Apply(context.Background(), profile, plan.PlanID)
			uncertain, ok := AsUncertainRun(err)
			mu.Lock()
			defer mu.Unlock()
			posts := 0
			for _, request := range requests {
				if request.method == http.MethodPost {
					posts++
				}
			}
			if !ok || uncertain.RunID != runID || len(requests) != 3 || posts != 1 || requests[2].method != http.MethodGet || requests[2].path != "/api/v1/runs/"+runID {
				t.Fatalf("uncertain=%#v ok=%t requests=%#v err=%v", uncertain, ok, requests, err)
			}
		})
	}
}

func TestDurablePartialResponseRetainsExactRunAndExit(t *testing.T) {
	plan := clientPhase4Plan()
	run := clientPhase4Run(plan, "run-partial")
	run.Status, run.Changed, run.RollbackStatus, run.VerificationStatus = generated.RunStatusPartial, true, "required", "incomplete"
	envelope, err := clientTestFactory().FailureWithRequestID("api.v1.plans.execute", "request-remote", generated.RunStatusPartial, generated.ErrorCodeRecoveryRequired, "run", false, run.RecoveryEpoch, run.StateRevision, clientRunPresentation(run))
	if err != nil {
		t.Fatal(err)
	}
	envelope.RunID, envelope.PlanID, envelope.Changed = &run.RunID, &run.PlanID, true
	raw, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	raw = append(raw, '\n')
	response, err := validateTypedResponse(raw, http.StatusConflict, requestSpec{http.MethodPost, "/api/v1/plans/plan-1/execute", "api.v1.plans.execute", maxOperationResponseBodyBytes, operationTimeout, true}, validRunPresentation)
	if err != nil || response.ExitCode != generated.ErrorExitCodes[generated.ErrorCodeRecoveryRequired] || response.Data.Run.RunID != run.RunID || string(response.Raw) != string(raw) {
		t.Fatalf("partial response=%#v err=%v", response, err)
	}
	envelope.RunID = new(string)
	bad, _ := json.Marshal(envelope)
	if _, err := validateTypedResponse(append(bad, '\n'), http.StatusConflict, requestSpec{http.MethodPost, "/api/v1/plans/plan-1/execute", "api.v1.plans.execute", maxOperationResponseBodyBytes, operationTimeout, true}, validRunPresentation); err == nil {
		t.Fatal("accepted a durable run whose envelope run ID disagreed")
	}
	malformed := clientRunPresentation(run)
	malformed.CompletedWork = append(malformed.CompletedWork, clientBrowserRunStep(run.Steps[0]))
	envelope.RunID = &run.RunID
	envelope.Data, _ = json.Marshal(malformed)
	bad, _ = json.Marshal(envelope)
	if _, err := validateTypedResponse(append(bad, '\n'), http.StatusConflict, requestSpec{http.MethodPost, "/api/v1/plans/plan-1/execute", "api.v1.plans.execute", maxOperationResponseBodyBytes, operationTimeout, true}, validRunPresentation); err == nil {
		t.Fatal("accepted a run presentation with duplicated work")
	}
}

func servePhase4(t *testing.T, handler http.HandlerFunc) serverconfig.Profile {
	t.Helper()
	directory, err := os.MkdirTemp("/tmp", "vsk-phase4-client-")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "control.sock")
	listener, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: handler}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { _ = server.Close(); _ = listener.Close(); _ = os.RemoveAll(directory) })
	return serverconfig.Profile{SocketPath: path}
}

func writePhase4Envelope(t *testing.T, writer http.ResponseWriter, command string, changed bool, epoch, revision int64, data any) {
	t.Helper()
	writer.Header().Set("Content-Type", "application/json")
	_, _ = writer.Write(operationEnvelope(t, command, changed, epoch, revision, data))
}

func clientPhase4Plan() generated.Plan {
	digest := func(character string) string { return "sha256:" + strings.Repeat(character, 64) }
	return generated.Plan{Schema: generated.SchemaIDPlan, SchemaVersion: "1.0.0", PlanID: "plan-1", PlanDigest: digest("a"), DeclarationID: "declaration-1", Binding: generated.PlanBinding{RecoveryEpoch: 2, PriorStateRevision: 6, StateRevision: 7, DeclarationRevision: 2, ObservationFingerprint: digest("b"), TargetDigest: digest("c"), ReasonDigest: digest("d"), PolicyVersion: "1.0.0", ToolVersion: "0.0.0-dev", ContractVersion: "1.0.0"}, Operations: []generated.PlanOperation{{Sequence: 1, OperationID: "operation-1", OperationType: "application.deploy.low-risk", AdapterID: "adapter.synthetic", ExecutorID: "executor-central", TargetID: "target-1", InputDigest: digest("e"), ArtifactDigest: digest("f"), Idempotent: true}}, Status: "planned", Risk: "routine", AuthorizationBranch: "preauthorized", ExecutorMode: "central", CreatedAt: "2026-09-13T06:00:00Z", ExpiresAt: "2026-09-13T06:30:00Z", ReadableDigest: digest("1"), Extensions: []generated.ContractExtension{}}
}

func clientPhase4Run(plan generated.Plan, runID string) generated.Run {
	return generated.Run{Schema: generated.SchemaIDRun, SchemaVersion: "1.0.0", RunID: runID, PlanID: plan.PlanID, PlanDigest: plan.PlanDigest, AuthorizationDecisionID: "decision-1", PolicyVersion: "1.0.0", ExecutorMode: "central", ExecutorID: "executor-central", ExecutorBindingDigest: "sha256:" + strings.Repeat("2", 64), Status: "running", Steps: []generated.RunStep{{Sequence: 1, OperationID: "operation-1", OperationType: "application.deploy.low-risk", AdapterID: "adapter.synthetic", ExecutorID: "executor-central", TargetID: "target-1", InputDigest: plan.Operations[0].InputDigest, ArtifactDigest: plan.Operations[0].ArtifactDigest, Idempotent: true, StepID: "step-1", Status: "running", EffectState: "intent-recorded"}}, RollbackStatus: "not-requested", VerificationStatus: "pending", StateRevision: 7, RecoveryEpoch: 2, CreatedAt: "2026-09-13T06:01:00Z", UpdatedAt: "2026-09-13T06:01:01Z", Extensions: []generated.ContractExtension{}}
}

func clientRunPresentation(run generated.Run) generated.RunPresentation {
	next := "inspect or cancel through the server"
	if run.Status == generated.RunStatusPartial {
		next = "recovery required; inspect the durable run"
	}
	steps := make([]generated.BrowserRunStep, 0, len(run.Steps))
	for _, step := range run.Steps {
		steps = append(steps, clientBrowserRunStep(step))
	}
	return generated.RunPresentation{Run: clientBrowserRun(run), CompletedWork: []generated.BrowserRunStep{}, IncompleteWork: steps, NextSafeAction: next}
}

func clientBrowserRun(run generated.Run) generated.BrowserRun {
	steps := make([]generated.BrowserRunStep, 0, len(run.Steps))
	for _, step := range run.Steps {
		steps = append(steps, clientBrowserRunStep(step))
	}
	return generated.BrowserRun{Schema: generated.SchemaIDBrowserRun, SchemaVersion: "1.0.0", RunID: run.RunID, PlanID: run.PlanID, PlanDigest: run.PlanDigest, Status: run.Status, Steps: steps, CancellationRequested: run.CancellationRequested, RollbackStatus: run.RollbackStatus, VerificationStatus: run.VerificationStatus, VerificationDigest: run.VerificationDigest, Changed: run.Changed, StateRevision: run.StateRevision, RecoveryEpoch: run.RecoveryEpoch, CreatedAt: run.CreatedAt, UpdatedAt: run.UpdatedAt, Extensions: run.Extensions}
}

func clientBrowserRunStep(step generated.RunStep) generated.BrowserRunStep {
	progress := map[string]string{"not-started": "not-started", "intent-recorded": "started", "receipt-recorded": "unverified", "verified": "verified", "effect-unknown": "unknown"}[step.EffectState]
	return generated.BrowserRunStep{Sequence: step.Sequence, OperationID: step.OperationID, OperationType: step.OperationType, TargetID: step.TargetID, StepID: step.StepID, Status: step.Status, ProgressState: progress}
}

func clientPlanPresentation(plan generated.Plan) generated.PlanPresentation {
	raw, _ := json.Marshal(plan)
	return generated.PlanPresentation{Plan: plan, ReadablePlan: "exact readable test plan", CanonicalPlan: string(raw)}
}
