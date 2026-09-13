//go:build linux

package api_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vegastack/vegastack-labs/internal/adapter"
	"github.com/vegastack/vegastack-labs/internal/api"
	"github.com/vegastack/vegastack-labs/internal/audit"
	"github.com/vegastack/vegastack-labs/internal/authorization"
	"github.com/vegastack/vegastack-labs/internal/change"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/identity"
	planengine "github.com/vegastack/vegastack-labs/internal/plan"
	"github.com/vegastack/vegastack-labs/internal/result"
	runengine "github.com/vegastack/vegastack-labs/internal/run"
	"github.com/vegastack/vegastack-labs/internal/store"
)

func TestExecutorAPIConcreteLifecycleSQLiteIntegration(t *testing.T) {
	t.Run("server-selected ordering and independent completion", func(t *testing.T) {
		fixture := newExecutorSQLiteFixture(t)

		wrong := fixture.claimRequest("adapter-wrong", "wrong-adapter")
		wrongResponse := fixture.post(wrong, "/api/v1/executor-leases/claim", fixture.principal)
		assertResultError(t, wrongResponse, http.StatusForbidden, generated.ErrorCodeAuthorizationDenied)
		if strings.Contains(wrongResponse.body, fixture.plan.Operations[0].OperationID) || strings.Contains(wrongResponse.body, fixture.plan.Operations[0].ArtifactDigest) {
			t.Fatalf("wrong binding disclosed work: %s", wrongResponse.body)
		}

		wrongPrincipal := identity.Principal{ID: "executor-wrong", Method: identity.CloudflareAccessMethod, Kind: identity.PrincipalPolicy}
		wrongIdentity := fixture.claimRequest(fixture.adapterID, "wrong-principal")
		wrongIdentity.PrincipalID = wrongPrincipal.ID
		wrongResponse = fixture.post(wrongIdentity, "/api/v1/executor-leases/claim", wrongPrincipal)
		assertResultError(t, wrongResponse, http.StatusForbidden, generated.ErrorCodeAuthorizationDenied)
		if strings.Contains(wrongResponse.body, fixture.plan.Operations[0].OperationID) || strings.Contains(wrongResponse.body, fixture.plan.Operations[0].ArtifactDigest) {
			t.Fatalf("wrong principal disclosed work: %s", wrongResponse.body)
		}

		first := decodeResultData[generated.ExecutorLease](t, fixture.post(fixture.claimRequest(fixture.adapterID, "claim-first"), "/api/v1/executor-leases/claim", fixture.principal), http.StatusOK)
		if first.OperationID != fixture.plan.Operations[0].OperationID || first.TargetID != fixture.plan.Operations[0].TargetID {
			t.Fatalf("first claim = %#v, want operation sequence 1", first)
		}

		fixture.clock.Set(parseIntegrationTime(t, first.RenewAfter))
		renewed := decodeResultData[generated.ExecutorLease](t, fixture.post(generated.ExecutorRenewRequest{
			Schema: generated.SchemaIDExecutorRenewRequest, SchemaVersion: "1.0.0", LeaseID: first.LeaseID,
			BindingDigest: first.BindingDigest, NonceDigest: first.NonceDigest, RecoveryEpoch: first.RecoveryEpoch,
			Extensions: fixture.executorEvidence(),
		}, "/api/v1/executor-leases/"+first.LeaseID+"/renew", fixture.principal), http.StatusOK)
		if renewed.NonceDigest == first.NonceDigest || renewed.MaximumExpiresAt != first.MaximumExpiresAt || renewed.LeaseExpiresAt != first.LeaseExpiresAt {
			t.Fatalf("renewal widened authority or failed to rotate nonce: before=%#v after=%#v", first, renewed)
		}

		fixture.clock.Advance(time.Second)
		firstReceipt := fixture.receipt(renewed, "receipt-operation-1")
		decodeResultData[generated.ExecutionReceipt](t, fixture.post(firstReceipt, "/api/v1/execution-receipts", fixture.principal), http.StatusOK)

		second := decodeResultData[generated.ExecutorLease](t, fixture.post(fixture.claimRequest(fixture.adapterID, "claim-second"), "/api/v1/executor-leases/claim", fixture.principal), http.StatusOK)
		if second.OperationID != fixture.plan.Operations[1].OperationID || second.TargetID != fixture.plan.Operations[1].TargetID || second.StepID == first.StepID {
			t.Fatalf("second claim = %#v, want operation sequence 2", second)
		}

		fixture.clock.Advance(time.Second)
		secondReceipt := fixture.receipt(second, "receipt-operation-2")
		decodeResultData[generated.ExecutionReceipt](t, fixture.post(secondReceipt, "/api/v1/execution-receipts", fixture.principal), http.StatusOK)

		completed, err := fixture.runs.GetRun(context.Background(), fixture.running.RunID)
		if err != nil {
			t.Fatal(err)
		}
		if completed.Status != "succeeded" || completed.VerificationStatus != "verified" || !completed.Changed || len(completed.Steps) != 2 || completed.Steps[0].EffectState != "verified" || completed.Steps[1].EffectState != "verified" {
			t.Fatalf("completed external run = %#v", completed)
		}
		if got := fixture.verifier.counts(); got != (integrationAdapterCounts{receiptVerifications: 2}) {
			t.Fatalf("adapter calls = %#v", got)
		}
	})

	t.Run("renewal loss reconciles to recovery required", func(t *testing.T) {
		fixture := newExecutorSQLiteFixture(t)
		lease := decodeResultData[generated.ExecutorLease](t, fixture.post(fixture.claimRequest(fixture.adapterID, "claim-loss"), "/api/v1/executor-leases/claim", fixture.principal), http.StatusOK)

		fixture.clock.Set(parseIntegrationTime(t, lease.RenewAfter))
		renewed := decodeResultData[generated.ExecutorLease](t, fixture.post(generated.ExecutorRenewRequest{
			Schema: generated.SchemaIDExecutorRenewRequest, SchemaVersion: "1.0.0", LeaseID: lease.LeaseID,
			BindingDigest: lease.BindingDigest, NonceDigest: lease.NonceDigest, RecoveryEpoch: lease.RecoveryEpoch,
			Extensions: fixture.executorEvidence(),
		}, "/api/v1/executor-leases/"+lease.LeaseID+"/renew", fixture.principal), http.StatusOK)

		fixture.clock.Set(parseIntegrationTime(t, renewed.LeaseExpiresAt).Add(time.Second))
		lost := fixture.post(generated.ExecutorRenewRequest{
			Schema: generated.SchemaIDExecutorRenewRequest, SchemaVersion: "1.0.0", LeaseID: renewed.LeaseID,
			BindingDigest: renewed.BindingDigest, NonceDigest: renewed.NonceDigest, RecoveryEpoch: renewed.RecoveryEpoch,
			Extensions: fixture.executorEvidence(),
		}, "/api/v1/executor-leases/"+renewed.LeaseID+"/renew", fixture.principal)
		if lost.status < 400 {
			t.Fatalf("expired renewal unexpectedly succeeded: %s", lost.body)
		}

		current, err := fixture.runs.GetRun(context.Background(), fixture.running.RunID)
		if err != nil {
			t.Fatal(err)
		}
		if current.Status != "partial" || current.VerificationStatus != "incomplete" || current.RollbackStatus != "required" || current.Steps[0].EffectState != "effect-unknown" {
			t.Fatalf("lost lease did not fail closed: %#v", current)
		}
		noReassignment := fixture.post(fixture.claimRequest(fixture.adapterID, "claim-after-loss"), "/api/v1/executor-leases/claim", fixture.principal)
		assertResultError(t, noReassignment, http.StatusNotFound, generated.ErrorCodeResourceNotFound)
		if got := fixture.verifier.counts(); got != (integrationAdapterCounts{}) {
			t.Fatalf("lease loss invoked adapter: %#v", got)
		}
	})

	t.Run("restart after durable receipt before finish requires recovery", func(t *testing.T) {
		fixture := newExecutorSQLiteFixture(t)
		fixture.installLifecycle(&failFinishRepository{RunRepository: fixture.runs, fail: true})
		lease := decodeResultData[generated.ExecutorLease](t, fixture.post(fixture.claimRequest(fixture.adapterID, "claim-crash"), "/api/v1/executor-leases/claim", fixture.principal), http.StatusOK)

		fixture.clock.Advance(time.Second)
		crashed := fixture.post(fixture.receipt(lease, "receipt-before-finish-crash"), "/api/v1/execution-receipts", fixture.principal)
		assertResultError(t, crashed, http.StatusServiceUnavailable, generated.ErrorCodeDependencyUnavailable)
		beforeRestart, err := fixture.runs.GetRun(context.Background(), fixture.running.RunID)
		if err != nil {
			t.Fatal(err)
		}
		if beforeRestart.Status != "running" || beforeRestart.Steps[0].Status != "running" || beforeRestart.Steps[0].EffectState != "receipt-recorded" {
			t.Fatalf("injected boundary was not durable receipt-before-finish: %#v", beforeRestart)
		}

		fixture.reopen(t)
		if err := fixture.engine.Startup(context.Background()); err != nil {
			t.Fatal(err)
		}
		recovered, err := fixture.runs.GetRun(context.Background(), fixture.running.RunID)
		if err != nil {
			t.Fatal(err)
		}
		if recovered.Status != "partial" || recovered.VerificationStatus != "incomplete" || recovered.RollbackStatus != "required" || recovered.Steps[0].EffectState != "effect-unknown" {
			t.Fatalf("restart accepted an incompletely settled receipt: %#v", recovered)
		}
		noReassignment := fixture.post(fixture.claimRequest(fixture.adapterID, "claim-after-restart"), "/api/v1/executor-leases/claim", fixture.principal)
		assertResultError(t, noReassignment, http.StatusNotFound, generated.ErrorCodeResourceNotFound)
		if got := fixture.verifier.counts(); got != (integrationAdapterCounts{receiptVerifications: 1}) {
			t.Fatalf("restart repeated or skipped independent verification: %#v", got)
		}
	})
}

type executorSQLiteFixture struct {
	testingT  *testing.T
	config    store.Config
	authority *store.Store
	clock     *integrationClock
	adapterID string
	principal identity.Principal
	verifier  *independentReceiptAdapter
	registry  *adapter.Registry
	plans     *planengine.Service
	runs      *store.RunRepository
	engine    *runengine.Engine
	external  *runengine.ExternalExecutor
	app       *api.Application
	plan      generated.Plan
	running   generated.Run
}

func newExecutorSQLiteFixture(t *testing.T) *executorSQLiteFixture {
	t.Helper()
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	clock := &integrationClock{now: time.Date(2026, 9, 13, 7, 0, 0, 0, time.UTC)}
	config := store.Config{
		DatabasePath: filepath.Join(directory, "control.db"), Mode: store.InitializeNew,
		ExpectedUID: uint32(os.Geteuid()), ToolVersion: "executor-api-integration", BuildVersion: "executor-api-integration", Clock: clock.Now,
	}
	authority, err := store.Open(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	fixture := &executorSQLiteFixture{
		testingT: t, config: config, authority: authority, clock: clock, adapterID: "adapter-executor-integration",
		principal: identity.Principal{ID: "executor-integration", Method: identity.CloudflareAccessMethod, Kind: identity.PrincipalPolicy},
		verifier:  &independentReceiptAdapter{},
	}
	t.Cleanup(func() { _ = fixture.authority.Close() })
	fixture.compose(t)
	fixture.plan = fixture.seedPlan(t)
	fixture.running = fixture.submitPlan(t)
	fixture.installLifecycle(fixture.runs)
	return fixture
}

func (fixture *executorSQLiteFixture) compose(t *testing.T) {
	t.Helper()
	planRepository := store.NewPlanRepository(fixture.authority)
	observations, err := planengine.NewStateObservationReader(planRepository)
	if err != nil {
		t.Fatal(err)
	}
	executorID := fixture.principal.ID
	fixture.plans, err = planengine.NewService(planengine.Config{
		Repository: planRepository, Observations: observations, Clock: fixture.clock.Now,
		PolicyVersion: "1.0.0", ToolVersion: "1.0.0", ContractVersion: "1.0.0", Risk: "routine",
		AuthorizationBranch: string(authorization.BranchPreauthorized), ExecutorMode: "external", ExecutorID: &executorID, OperationExecutorID: executorID,
	})
	if err != nil {
		t.Fatal(err)
	}
	fixture.registry = adapter.NewRegistry()
	if err := fixture.registry.Register(fixture.adapterID, fixture.verifier); err != nil {
		t.Fatal(err)
	}
	fixture.runs = store.NewRunRepository(fixture.authority)
	fixture.engine, err = runengine.NewEngine(runengine.Config{
		Repository: fixture.runs, Plans: fixture.plans, Admission: runengine.NewAdmissionGate(nil, fixture.clock.Now),
		Adapters: fixture.registry, Clock: fixture.clock.Now,
	})
	if err != nil {
		t.Fatal(err)
	}
}

func (fixture *executorSQLiteFixture) installLifecycle(runs runengine.Repository) {
	t := fixture.testingT
	var err error
	fixture.external, err = runengine.NewExternalExecutor(runengine.ExternalExecutorConfig{
		Runs: runs, Leases: store.NewExecutorLeaseRepository(fixture.authority), Plans: fixture.plans,
		Admission: runengine.NewAdmissionGate(nil, fixture.clock.Now), Adapters: fixture.registry, Clock: fixture.clock.Now,
	})
	if err != nil {
		t.Fatal(err)
	}
	factory := result.NewFactory(result.BuildInfo{ToolVersion: "executor-api-integration", ReleaseBuildID: "executor-api-integration"}, func() (string, error) {
		return "request-executor-api-integration", nil
	})
	fixture.app, err = api.NewApplication(api.Config{
		Authority: fixture.authority, Authorizer: store.NewReadAuthorizer(fixture.authority),
		Reads: store.NewReadRepository(fixture.authority), Results: factory,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := api.RegisterExecutorOperations(fixture.app, api.ExecutorOperationConfig{Lifecycle: fixture.external, Results: factory}); err != nil {
		t.Fatal(err)
	}
}

func (fixture *executorSQLiteFixture) seedPlan(t *testing.T) generated.Plan {
	t.Helper()
	declarations, err := change.NewService(store.NewDeclarationRepository(fixture.authority), fixture.clock.Now)
	if err != nil {
		t.Fatal(err)
	}
	operations := []generated.DeclarationOperation{
		{Sequence: 1, OperationID: "operation-executor-first", OperationType: "configuration.update", AdapterID: fixture.adapterID, TargetID: "target-executor-first", InputDigest: integrationDigest("input-first"), ArtifactDigest: integrationDigest("artifact-first"), Idempotent: true},
		{Sequence: 2, OperationID: "operation-executor-second", OperationType: "configuration.update", AdapterID: fixture.adapterID, TargetID: "target-executor-second", InputDigest: integrationDigest("input-second"), ArtifactDigest: integrationDigest("artifact-second"), Idempotent: true},
	}
	author := change.AuthorScope{PrincipalID: "principal-executor-author", PrincipalMethod: identity.LocalOSPeerMethod, AgentSessionID: "session-executor-integration"}
	revised, err := declarations.Revise(context.Background(), author, generated.DeclarationRevisionRequest{
		Schema: generated.SchemaIDDeclarationRevisionRequest, SchemaVersion: "1.0.0",
		DeclarationID: "declaration-executor-integration", DeclarationType: "node.configuration",
		ExpectedRevision: 1, ExpectedStateRevision: 0, RecoveryEpoch: 0, Operations: operations,
		ReasonDigest: integrationDigest("reason"), Extensions: []generated.ContractExtension{{Name: "x-executor-project", ValueDigest: integrationDigest("project")}},
	})
	if err != nil {
		t.Fatal(err)
	}
	planRepository := store.NewPlanRepository(fixture.authority)
	observations, err := planengine.NewStateObservationReader(planRepository)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := observations.CurrentFingerprint(context.Background(), revised.Document.DeclarationID, revised.Document.Operations)
	if err != nil {
		t.Fatal(err)
	}
	created, err := fixture.plans.Create(context.Background(), planengine.AuthorScope{
		PrincipalID: author.PrincipalID, PrincipalMethod: author.PrincipalMethod, AgentSessionID: author.AgentSessionID,
	}, generated.PlanCreateRequest{
		Schema: generated.SchemaIDPlanCreateRequest, SchemaVersion: "1.0.0", DeclarationID: revised.Document.DeclarationID,
		DeclarationRevision: revised.Document.Revision, ExpectedStateRevision: revised.Document.StateRevision,
		RecoveryEpoch: revised.Document.RecoveryEpoch, ObservationFingerprint: fingerprint,
		IdempotencyKey: "plan-executor-integration",
		Extensions:     []generated.ContractExtension{{Name: "x-executor-project", ValueDigest: integrationDigest("project")}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return created.Plan
}

func (fixture *executorSQLiteFixture) submitPlan(t *testing.T) generated.Run {
	t.Helper()
	branch := string(authorization.BranchPreauthorized)
	decision := generated.AuthorizationDecision{
		Schema: generated.SchemaIDAuthorizationDecision, SchemaVersion: "1.0.0", DecisionID: "decision-executor-integration",
		PrincipalID: "policy-executor-integration", Action: string(authorization.ActionExecute), TargetID: fixture.plan.Operations[0].TargetID,
		Allowed: true, Branch: &branch, ReasonCode: authorization.ReasonAllowed, GrantRevision: 1,
		RecoveryEpoch: fixture.plan.Binding.RecoveryEpoch, PlanDigest: fixture.plan.PlanDigest,
		DecidedAt: fixture.clock.Now().Format(time.RFC3339), Extensions: []generated.ContractExtension{},
	}
	attribution, err := audit.NewAttribution(identity.Principal{ID: decision.PrincipalID, Method: identity.LocalOSPeerMethod, Kind: identity.PrincipalPolicy}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	running, err := fixture.engine.Submit(context.Background(), runengine.SubmitRequest{
		Reference: generated.PlanReferenceRequest{
			Schema: generated.SchemaIDPlanReferenceRequest, SchemaVersion: "1.0.0", PlanID: fixture.plan.PlanID,
			PlanDigest: fixture.plan.PlanDigest, RecoveryEpoch: fixture.plan.Binding.RecoveryEpoch,
			IdempotencyKey: "submit-executor-integration", Extensions: []generated.ContractExtension{},
		},
		Authorization: decision, Attribution: attribution,
	})
	if err != nil {
		t.Fatal(err)
	}
	if running.Status != "running" || len(running.Steps) != 2 {
		t.Fatalf("external submission = %#v", running)
	}
	return running
}

func (fixture *executorSQLiteFixture) reopen(t *testing.T) {
	t.Helper()
	if err := fixture.authority.Close(); err != nil {
		t.Fatal(err)
	}
	fixture.config.Mode = store.OpenExisting
	authority, err := store.Open(context.Background(), fixture.config)
	if err != nil {
		t.Fatal(err)
	}
	fixture.authority = authority
	fixture.compose(t)
	fixture.installLifecycle(fixture.runs)
}

func (fixture *executorSQLiteFixture) claimRequest(adapterID, nonce string) generated.ExecutorClaimRequest {
	return generated.ExecutorClaimRequest{
		Schema: generated.SchemaIDExecutorClaimRequest, SchemaVersion: "1.0.0",
		ExecutorID: fixture.principal.ID, PrincipalID: fixture.principal.ID, AdapterID: adapterID,
		RecoveryEpoch: fixture.plan.Binding.RecoveryEpoch, NonceDigest: integrationDigest(nonce),
		Extensions: fixture.executorEvidence(),
	}
}

func (fixture *executorSQLiteFixture) receipt(lease generated.ExecutorLease, receiptID string) generated.ExecutionReceiptRequest {
	receipt := generated.ExecutionReceipt{
		Schema: generated.SchemaIDExecutionReceipt, SchemaVersion: "1.0.0", LeaseID: lease.LeaseID,
		PlanID: lease.PlanID, PlanDigest: lease.PlanDigest, RunID: lease.RunID, StepID: lease.StepID,
		OperationID: lease.OperationID, ExecutorID: lease.ExecutorID, AdapterID: lease.AdapterID, TargetID: lease.TargetID,
		ArtifactDigest: lease.ArtifactDigest, BindingDigest: lease.BindingDigest, NonceDigest: lease.NonceDigest,
		RecoveryEpoch: lease.RecoveryEpoch, ReceiptID: receiptID, Status: "succeeded",
		ResultDigest: expectedIntegrationResult(lease.OperationID), RecordedAt: fixture.clock.Now().Format(time.RFC3339), Extensions: []generated.ContractExtension{},
	}
	return generated.ExecutionReceiptRequest{
		Schema: generated.SchemaIDExecutionReceiptRequest, SchemaVersion: "1.0.0", Receipt: receipt,
		ExpectedBindingDigest: lease.BindingDigest, Extensions: fixture.executorEvidence(),
	}
}

func (fixture *executorSQLiteFixture) executorEvidence() []generated.ContractExtension {
	return []generated.ContractExtension{{Name: "x-executor-project", ValueDigest: integrationDigest("project")}}
}

type integrationHTTPResponse struct {
	status int
	body   string
	result generated.RunResult
}

func (fixture *executorSQLiteFixture) post(value any, path string, principal identity.Principal) integrationHTTPResponse {
	fixture.testingT.Helper()
	body, err := json.Marshal(value)
	if err != nil {
		fixture.testingT.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request = request.WithContext(identity.WithVerifiedPrincipal(request.Context(), principal))
	response := httptest.NewRecorder()
	fixture.app.ServeHTTP(response, request)
	var decoded generated.RunResult
	if err := json.Unmarshal(response.Body.Bytes(), &decoded); err != nil {
		fixture.testingT.Fatalf("decode response %d %q: %v", response.Code, response.Body.String(), err)
	}
	return integrationHTTPResponse{status: response.Code, body: response.Body.String(), result: decoded}
}

func decodeResultData[T any](t *testing.T, response integrationHTTPResponse, wantStatus int) T {
	t.Helper()
	if response.status != wantStatus || response.result.Status != generated.RunStatusSucceeded || len(response.result.Errors) != 0 {
		t.Fatalf("response = %d %s", response.status, response.body)
	}
	var value T
	if err := json.Unmarshal(response.result.Data, &value); err != nil {
		t.Fatalf("decode result data: %v", err)
	}
	return value
}

func assertResultError(t *testing.T, response integrationHTTPResponse, wantStatus int, wantCode string) {
	t.Helper()
	if response.status != wantStatus || len(response.result.Errors) != 1 || response.result.Errors[0].Code != wantCode {
		t.Fatalf("response = %d %s, want %d/%s", response.status, response.body, wantStatus, wantCode)
	}
}

type integrationClock struct {
	mu  sync.Mutex
	now time.Time
}

func (clock *integrationClock) Now() time.Time {
	clock.mu.Lock()
	defer clock.mu.Unlock()
	return clock.now
}

func (clock *integrationClock) Set(value time.Time) {
	clock.mu.Lock()
	clock.now = value.UTC().Truncate(time.Second)
	clock.mu.Unlock()
}

func (clock *integrationClock) Advance(duration time.Duration) {
	clock.mu.Lock()
	clock.now = clock.now.Add(duration).UTC().Truncate(time.Second)
	clock.mu.Unlock()
}

type integrationAdapterCounts struct {
	executions           int
	receiptVerifications int
}

type independentReceiptAdapter struct {
	mu    sync.Mutex
	stats integrationAdapterCounts
}

func (implementation *independentReceiptAdapter) Execute(context.Context, adapter.Operation) (adapter.Effect, error) {
	implementation.mu.Lock()
	implementation.stats.executions++
	implementation.mu.Unlock()
	return adapter.Effect{}, errors.New("external operation reached central execution")
}

func (*independentReceiptAdapter) Verify(context.Context, adapter.Operation, adapter.Effect) (adapter.Verification, error) {
	return adapter.Verification{}, errors.New("external receipt reached central verification")
}

func (implementation *independentReceiptAdapter) VerifyReceipt(_ context.Context, operation adapter.Operation, observation adapter.ReceiptObservation) (adapter.ReceiptVerification, error) {
	implementation.mu.Lock()
	implementation.stats.receiptVerifications++
	implementation.mu.Unlock()
	if observation.Status != "succeeded" || observation.ResultDigest != expectedIntegrationResult(operation.OperationID) {
		return adapter.ReceiptVerification{Verified: false, Digest: integrationDigest("verification-denied", operation.OperationID)}, nil
	}
	return adapter.ReceiptVerification{Verified: true, Digest: integrationDigest("verification", operation.OperationID), Changed: true}, nil
}

func (implementation *independentReceiptAdapter) counts() integrationAdapterCounts {
	implementation.mu.Lock()
	defer implementation.mu.Unlock()
	return implementation.stats
}

type failFinishRepository struct {
	*store.RunRepository
	fail bool
}

func (repository *failFinishRepository) FinishStep(ctx context.Context, request store.StepFinishRequest) (generated.Run, error) {
	if repository.fail {
		return generated.Run{}, errors.New("injected process crash after durable external receipt")
	}
	return repository.RunRepository.FinishStep(ctx, request)
}

func integrationDigest(values ...string) string {
	sum := sha256.Sum256([]byte(strings.Join(values, "\x00")))
	return "sha256:" + hex.EncodeToString(sum[:])
}

func expectedIntegrationResult(operationID string) string {
	return integrationDigest("observed-target-state", operationID)
}

func parseIntegrationTime(t *testing.T, value string) time.Time {
	t.Helper()
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}

var _ adapter.Adapter = (*independentReceiptAdapter)(nil)
var _ adapter.ReceiptVerifier = (*independentReceiptAdapter)(nil)
var _ runengine.Repository = (*failFinishRepository)(nil)
