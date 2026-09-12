package run

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/vegastack/vegastack-labs/internal/adapter"
	"github.com/vegastack/vegastack-labs/internal/generated"
)

func TestRestartAtEveryDurableBoundaryNeverRepeatsAmbiguousEffect(t *testing.T) {
	for _, boundary := range []Boundary{BoundaryRunCreated, BoundaryRunStarted, BoundaryLeaseAcquired, BoundaryIntentRecorded, BoundaryEffectReturned, BoundaryReceiptRecorded, BoundaryVerified} {
		t.Run(string(boundary), func(t *testing.T) {
			fixture := newEngineFixture(t)
			fixture.engine.testAfterBoundary = func(got Boundary) error {
				if got == boundary {
					return errors.New("injected crash")
				}
				return nil
			}
			_, _ = fixture.engine.Submit(context.Background(), fixture.request)
			restarted := fixture.restart(t)
			if err := restarted.Reconcile(context.Background()); err != nil {
				t.Fatal(err)
			}
			run, err := restarted.Get(context.Background(), fixture.runID)
			if err != nil {
				t.Fatal(err)
			}
			if fixture.adapter.calls > 1 {
				t.Fatalf("ambiguous effect repeated %d times at %s", fixture.adapter.calls, boundary)
			}
			if boundary >= BoundaryIntentRecorded && boundary <= BoundaryReceiptRecorded && run.Status != "partial" {
				t.Fatalf("ambiguous boundary %s reported %q", boundary, run.Status)
			}
		})
	}
}

func TestQueuedRunAfterCreateCrashContinuesOnExactRetry(t *testing.T) {
	fixture := newEngineFixture(t)
	fixture.engine.testAfterBoundary = func(boundary Boundary) error {
		if boundary == BoundaryRunCreated {
			return errors.New("injected crash")
		}
		return nil
	}
	first, err := fixture.engine.Submit(context.Background(), fixture.request)
	if err == nil || first.Status != "queued" || fixture.adapter.calls != 0 {
		t.Fatalf("first = %#v calls=%d err=%v", first, fixture.adapter.calls, err)
	}
	fixture.engine.testAfterBoundary = nil
	continued, err := fixture.engine.Submit(context.Background(), fixture.request)
	if err != nil || continued.Status != "succeeded" || fixture.adapter.calls != 1 {
		t.Fatalf("continued = %#v calls=%d err=%v", continued, fixture.adapter.calls, err)
	}
}

func TestCancellationConflictFailureVerifyAndSafeResume(t *testing.T) {
	fixture := newEngineFixture(t)
	run, err := fixture.engine.Submit(context.Background(), fixture.request)
	if err != nil || run.Status != "succeeded" || !run.Changed || fixture.adapter.calls != 1 {
		t.Fatalf("success = %#v, calls=%d, err=%v", run, fixture.adapter.calls, err)
	}
	replay, err := fixture.engine.Submit(context.Background(), fixture.request)
	if err != nil || replay.RunID != run.RunID || fixture.adapter.calls != 1 {
		t.Fatalf("replay = %#v, calls=%d, err=%v", replay, fixture.adapter.calls, err)
	}
	refreshed := fixture.request
	refreshed.Authorization.DecisionID = "decision-refreshed-test"
	refreshedReplay, err := fixture.engine.Submit(context.Background(), refreshed)
	if err != nil || refreshedReplay.AuthorizationDecisionID != run.AuthorizationDecisionID || fixture.adapter.calls != 1 {
		t.Fatalf("refreshed authorization replay = %#v, calls=%d, err=%v", refreshedReplay, fixture.adapter.calls, err)
	}

	cancelFixture := newEngineFixture(t)
	cancelFixture.engine.testAfterBoundary = func(boundary Boundary) error {
		if boundary == BoundaryRunCreated {
			_, cancelErr := cancelFixture.engine.Cancel(context.Background(), cancelFixture.runID)
			return cancelErr
		}
		return nil
	}
	cancelled, err := cancelFixture.engine.Submit(context.Background(), cancelFixture.request)
	if err != nil || cancelled.Status != "cancelled" || cancelFixture.adapter.calls != 0 {
		t.Fatalf("cancelled = %#v, calls=%d, err=%v", cancelled, cancelFixture.adapter.calls, err)
	}

	verifyFixture := newEngineFixture(t)
	verifyFixture.adapter.verify = false
	partial, err := verifyFixture.engine.Submit(context.Background(), verifyFixture.request)
	if Code(err) != generated.ErrorCodeRecoveryRequired || partial.Status != "partial" {
		t.Fatalf("verify partial = %#v, code=%q", partial, Code(err))
	}

	resumeFixture := newEngineFixture(t)
	resumeFixture.engine.testAfterBoundary = func(boundary Boundary) error {
		if boundary == BoundaryRunStarted {
			return errors.New("safe interruption")
		}
		return nil
	}
	_, _ = resumeFixture.engine.Submit(context.Background(), resumeFixture.request)
	resumeFixture.engine.testAfterBoundary = nil
	if err := resumeFixture.engine.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := resumeFixture.engine.Startup(context.Background()); err != nil {
		t.Fatalf("second startup reconciliation was not idempotent: %v", err)
	}
	resumed, err := resumeFixture.engine.Resume(context.Background(), resumeFixture.runID)
	if err != nil || resumed.Status != "succeeded" {
		t.Fatalf("resume = %#v, %v", resumed, err)
	}

	unsafe := newEngineFixture(t)
	unsafe.store.plan.Operations[0].Idempotent = false
	unsafe.engine.testAfterBoundary = func(boundary Boundary) error {
		if boundary == BoundaryRunStarted {
			return errors.New("unsafe interruption")
		}
		return nil
	}
	_, _ = unsafe.engine.Submit(context.Background(), unsafe.request)
	unsafe.engine.testAfterBoundary = nil
	if err := unsafe.engine.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := unsafe.engine.Resume(context.Background(), unsafe.runID); Code(err) != generated.ErrorCodeRecoveryRequired {
		t.Fatalf("unsafe resume code = %q", Code(err))
	}
}

func TestClientDisconnectDoesNotCancelDurableServerOwnedRun(t *testing.T) {
	fixture := newEngineFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	fixture.engine.testAfterBoundary = func(boundary Boundary) error {
		if boundary == BoundaryRunStarted {
			cancel()
		}
		return nil
	}
	completed, err := fixture.engine.Submit(ctx, fixture.request)
	if err != nil || completed.Status != "succeeded" || fixture.adapter.calls != 1 {
		t.Fatalf("disconnect result = %#v, calls=%d err=%v", completed, fixture.adapter.calls, err)
	}
	stored, err := fixture.engine.Get(context.Background(), fixture.runID)
	if err != nil || stored.Status != "succeeded" {
		t.Fatalf("stored disconnect run = %#v, %v", stored, err)
	}
}

func TestServerShutdownInterruptsAtSafeBoundaryAndReleasesLease(t *testing.T) {
	fixture := newEngineFixture(t)
	executionContext, stop := context.WithCancel(context.Background())
	fixture.engine.executionContext = executionContext
	fixture.adapter.beforeExecute = stop
	interrupted, err := fixture.engine.Submit(context.Background(), fixture.request)
	if Code(err) != generated.ErrorCodeInterrupted || interrupted.Status != "interrupted" {
		t.Fatalf("shutdown result = %#v code=%q err=%v", interrupted, Code(err), err)
	}
	fixture.store.mu.Lock()
	defer fixture.store.mu.Unlock()
	if len(fixture.store.targets) != 0 || fixture.store.leases["lease-deterministic"].Status != "released" {
		t.Fatalf("shutdown left active target/lease = %#v/%#v", fixture.store.targets, fixture.store.leases)
	}
}

func TestTimeoutBeforeEffectInterruptsAndReleasesLease(t *testing.T) {
	fixture := newEngineFixture(t)
	fixture.adapter.executeErr = context.DeadlineExceeded
	interrupted, err := fixture.engine.Submit(context.Background(), fixture.request)
	if Code(err) != generated.ErrorCodeInterrupted || interrupted.Status != "interrupted" {
		t.Fatalf("timeout result = %#v code=%q err=%v", interrupted, Code(err), err)
	}
	fixture.store.mu.Lock()
	defer fixture.store.mu.Unlock()
	if len(fixture.store.targets) != 0 || fixture.store.leases["lease-deterministic"].Status != "released" {
		t.Fatalf("timeout left active target/lease = %#v/%#v", fixture.store.targets, fixture.store.leases)
	}
}

func TestTargetLeaseConflictInterruptsBeforeEffect(t *testing.T) {
	fixture := newEngineFixture(t)
	fixture.store.targets["target-test"] = "lease-other"
	fixture.store.leases["lease-other"] = generated.ExecutorLease{LeaseID: "lease-other", RunID: "run-other", TargetID: "target-test", Status: "active"}
	interrupted, err := fixture.engine.Submit(context.Background(), fixture.request)
	if Code(err) != generated.ErrorCodeStateConflict || interrupted.Status != "interrupted" || fixture.adapter.calls != 0 {
		t.Fatalf("conflict result = %#v code=%q calls=%d err=%v", interrupted, Code(err), fixture.adapter.calls, err)
	}
	fixture.store.mu.Lock()
	defer fixture.store.mu.Unlock()
	if fixture.store.targets["target-test"] != "lease-other" {
		t.Fatalf("conflicting owner was changed: %#v", fixture.store.targets)
	}
}

func TestRunTransitionTableIsClosed(t *testing.T) {
	statuses := []string{"queued", "running", "succeeded", "failed", "partial", "interrupted", "cancelled"}
	allowed := map[string]bool{
		"queued\x00running":        true,
		"queued\x00cancelled":      true,
		"running\x00succeeded":     true,
		"running\x00failed":        true,
		"running\x00partial":       true,
		"running\x00interrupted":   true,
		"interrupted\x00running":   true,
		"interrupted\x00cancelled": true,
	}
	for _, from := range statuses {
		for _, to := range statuses {
			err := generated.ValidateRunTransition(from, to)
			if (err == nil) != allowed[from+"\x00"+to] {
				t.Fatalf("transition %s -> %s err=%v", from, to, err)
			}
		}
	}
}

func TestExpiredPlanAndMissingAdapterFailBeforeEffect(t *testing.T) {
	expired := newEngineFixture(t)
	expired.store.plan.ExpiresAt = expired.engine.clock().UTC().Format(time.RFC3339)
	if _, err := expired.engine.Submit(context.Background(), expired.request); Code(err) != generated.ErrorCodePlanStale || expired.adapter.calls != 0 {
		t.Fatalf("expired plan code/calls = %q/%d", Code(err), expired.adapter.calls)
	}

	missing := newEngineFixture(t)
	engine, err := NewEngine(Config{Repository: missing.store, Plans: missing.store, Admission: allowAdmission{}, Adapters: adapter.NewRegistry(), Clock: missing.engine.clock, IDs: deterministicIDs{}})
	if err != nil {
		t.Fatal(err)
	}
	failed, err := engine.Submit(context.Background(), missing.request)
	if adapter.Code(err) != generated.ErrorCodePrerequisiteBlocked || failed.Status != "failed" || missing.adapter.calls != 0 {
		t.Fatalf("missing adapter run/code/calls = %#v/%q/%d", failed, adapter.Code(err), missing.adapter.calls)
	}
}

func TestVerifiedNoopDoesNotClaimInfrastructureChanged(t *testing.T) {
	fixture := newEngineFixture(t)
	fixture.adapter.changed = false
	completed, err := fixture.engine.Submit(context.Background(), fixture.request)
	if err != nil || completed.Status != "succeeded" || completed.Changed {
		t.Fatalf("verified noop = %#v, %v", completed, err)
	}
}

type engineFixture struct {
	engine  *Engine
	store   *memoryRepository
	adapter *fakeAdapter
	request SubmitRequest
	runID   string
}

func newEngineFixture(t *testing.T) *engineFixture {
	t.Helper()
	now := time.Date(2026, 9, 13, 0, 0, 0, 0, time.UTC)
	plan := testPlan(now)
	repository := newMemoryRepository(plan)
	registry := adapter.NewRegistry()
	fixtureAdapter := &fakeAdapter{verify: true}
	fixtureAdapter.changed = true
	if err := registry.Register("adapter-test", fixtureAdapter); err != nil {
		t.Fatal(err)
	}
	engine, err := NewEngine(Config{Repository: repository, Plans: repository, Admission: allowAdmission{}, Adapters: registry, Clock: func() time.Time { return now }, IDs: deterministicIDs{}})
	if err != nil {
		t.Fatal(err)
	}
	branch := "preauthorized"
	request := SubmitRequest{Reference: generated.PlanReferenceRequest{Schema: generated.SchemaIDPlanReferenceRequest, SchemaVersion: "1.0.0", PlanID: plan.PlanID, PlanDigest: plan.PlanDigest, RecoveryEpoch: 0, IdempotencyKey: "submit-test", Extensions: []generated.ContractExtension{}}, Authorization: generated.AuthorizationDecision{Schema: generated.SchemaIDAuthorizationDecision, SchemaVersion: "1.0.0", DecisionID: "decision-test", PrincipalID: "policy-test", Action: "execute", TargetID: "target-test", Allowed: true, Branch: &branch, ReasonCode: "allowed", GrantRevision: 1, RecoveryEpoch: 0, PlanDigest: plan.PlanDigest, DecidedAt: now.Format(time.RFC3339), Extensions: []generated.ContractExtension{}}}
	return &engineFixture{engine: engine, store: repository, adapter: fixtureAdapter, request: request, runID: runID(plan.PlanID, request.Reference.IdempotencyKey)}
}

func (fixture *engineFixture) restart(t *testing.T) *Engine {
	t.Helper()
	engine, err := NewEngine(Config{Repository: fixture.store, Plans: fixture.store, Admission: allowAdmission{}, Adapters: fixture.engine.adapters, Clock: fixture.engine.clock, IDs: deterministicIDs{}})
	if err != nil {
		t.Fatal(err)
	}
	return engine
}

type fakeAdapter struct {
	calls         int
	verify        bool
	changed       bool
	beforeExecute func()
	executeErr    error
}

func (adapterFixture *fakeAdapter) Execute(ctx context.Context, _ adapter.Operation) (adapter.Effect, error) {
	if adapterFixture.beforeExecute != nil {
		adapterFixture.beforeExecute()
	}
	if adapterFixture.executeErr != nil {
		return adapter.Effect{Status: "failed", ResultDigest: digest("failed-result"), EffectObserved: false}, adapterFixture.executeErr
	}
	if err := ctx.Err(); err != nil {
		return adapter.Effect{Status: "failed", ResultDigest: digest("cancelled-result"), EffectObserved: false}, err
	}
	adapterFixture.calls++
	return adapter.Effect{Status: "succeeded", ResultDigest: digest("result"), Changed: adapterFixture.changed, EffectObserved: true}, nil
}
func (adapterFixture *fakeAdapter) Verify(context.Context, adapter.Operation, adapter.Effect) (adapter.Verification, error) {
	return adapter.Verification{Verified: adapterFixture.verify, Digest: digest("verification")}, nil
}
