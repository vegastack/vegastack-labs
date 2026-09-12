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
	resumed, err := resumeFixture.engine.Resume(context.Background(), resumeFixture.runID)
	if err != nil || resumed.Status != "succeeded" {
		t.Fatalf("resume = %#v, %v", resumed, err)
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
	calls  int
	verify bool
}

func (adapterFixture *fakeAdapter) Execute(context.Context, adapter.Operation) (adapter.Effect, error) {
	adapterFixture.calls++
	return adapter.Effect{Status: "succeeded", ResultDigest: digest("result"), Changed: true, EffectObserved: true}, nil
}
func (adapterFixture *fakeAdapter) Verify(context.Context, adapter.Operation, adapter.Effect) (adapter.Verification, error) {
	return adapter.Verification{Verified: adapterFixture.verify, Digest: digest("verification")}, nil
}
