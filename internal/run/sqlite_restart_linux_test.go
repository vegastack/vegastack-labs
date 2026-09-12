//go:build linux

package run

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/vegastack/vegastack-labs/internal/acknowledgement"
	"github.com/vegastack/vegastack-labs/internal/adapter"
	"github.com/vegastack/vegastack-labs/internal/authorization"
	"github.com/vegastack/vegastack-labs/internal/change"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/identity"
	planengine "github.com/vegastack/vegastack-labs/internal/plan"
	"github.com/vegastack/vegastack-labs/internal/store"
)

func TestSQLiteRestartAtEveryDurableRunBoundaryDoesNotRepeatAmbiguousEffect(t *testing.T) {
	boundaries := []Boundary{
		BoundaryRunCreated,
		BoundaryAdmissionActivated,
		BoundaryRunStarted,
		BoundaryLeaseAcquired,
		BoundaryIntentRecorded,
		BoundaryEffectReturned,
		BoundaryReceiptRecorded,
		BoundaryVerified,
		BoundaryRunCompleted,
	}
	for _, boundary := range boundaries {
		t.Run(string(boundary), func(t *testing.T) {
			fixture := newSQLiteRestartFixture(t, string(authorization.BranchPreauthorized))
			fixture.engine.testAfterBoundary = func(got Boundary) error {
				if got == boundary {
					return errors.New("injected process crash")
				}
				return nil
			}
			if _, err := fixture.engine.Submit(context.Background(), fixture.request); err == nil {
				t.Fatalf("submission crossed injected %s crash boundary", boundary)
			}

			restarted := fixture.restart(t)
			if err := restarted.Startup(context.Background()); err != nil {
				t.Fatal(err)
			}
			current, err := restarted.Get(context.Background(), fixture.runID())
			if err != nil {
				t.Fatal(err)
			}
			switch boundary {
			case BoundaryRunCreated, BoundaryAdmissionActivated:
				current, err = restarted.Submit(context.Background(), fixture.request)
			case BoundaryRunStarted, BoundaryLeaseAcquired:
				if current.Status != "interrupted" {
					t.Fatalf("safe pre-effect boundary reconciled as %q", current.Status)
				}
				current, err = restarted.Resume(context.Background(), current.RunID)
			case BoundaryIntentRecorded, BoundaryEffectReturned, BoundaryReceiptRecorded:
				if current.Status != "partial" {
					t.Fatalf("ambiguous boundary reconciled as %q", current.Status)
				}
				callsBeforeResume := fixture.adapter.callCount()
				if _, resumeErr := restarted.Resume(context.Background(), current.RunID); Code(resumeErr) != generated.ErrorCodeRecoveryRequired {
					t.Fatalf("ambiguous run resume code = %q, err=%v", Code(resumeErr), resumeErr)
				}
				if fixture.adapter.callCount() != callsBeforeResume {
					t.Fatal("denied ambiguous resume repeated the adapter effect")
				}
			case BoundaryVerified, BoundaryRunCompleted:
				if current.Status != "succeeded" {
					t.Fatalf("durably verified boundary reconciled as %q", current.Status)
				}
			}
			if err != nil {
				t.Fatalf("recovery at %s: %v", boundary, err)
			}

			callsBeforeReplay := fixture.adapter.callCount()
			replayed, replayErr := restarted.Submit(context.Background(), fixture.request)
			if replayErr != nil || replayed.RunID != current.RunID || fixture.adapter.callCount() != callsBeforeReplay {
				t.Fatalf("exact replay at %s = %#v, calls %d -> %d, err=%v", boundary, replayed, callsBeforeReplay, fixture.adapter.callCount(), replayErr)
			}
			wantCalls := 1
			if boundary == BoundaryIntentRecorded {
				// The durable intent is conservatively ambiguous even when the
				// injected crash happened before this fake adapter was invoked.
				wantCalls = 0
			}
			if fixture.adapter.callCount() != wantCalls {
				t.Fatalf("adapter effects at %s = %d, want %d", boundary, fixture.adapter.callCount(), wantCalls)
			}
		})
	}
}

func TestSQLiteRestartRecoversBothSidesOfHumanAcknowledgementActivation(t *testing.T) {
	for _, test := range []struct {
		name           string
		boundary       Boundary
		consumedBefore bool
	}{
		{name: "created-before-proof-consumption", boundary: BoundaryRunCreated, consumedBefore: false},
		{name: "proof-consumed-before-start", boundary: BoundaryAdmissionActivated, consumedBefore: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newSQLiteRestartFixture(t, string(authorization.BranchHuman))
			fixture.engine.testAfterBoundary = func(got Boundary) error {
				if got == test.boundary {
					return errors.New("injected process crash")
				}
				return nil
			}
			queued, err := fixture.engine.Submit(context.Background(), fixture.request)
			if err == nil || queued.Status != "queued" || fixture.adapter.callCount() != 0 {
				t.Fatalf("pre-restart submission = %#v, calls=%d, err=%v", queued, fixture.adapter.callCount(), err)
			}
			stored, err := store.NewAcknowledgementRepository(fixture.authority).Get(context.Background(), fixture.plan.PlanID)
			if err != nil || stored.Consumed != test.consumedBefore {
				t.Fatalf("proof consumed before restart = %v, want %v, err=%v", stored.Consumed, test.consumedBefore, err)
			}

			restarted := fixture.restart(t)
			completed, err := restarted.Submit(context.Background(), fixture.request)
			if err != nil || completed.Status != "succeeded" || fixture.adapter.callCount() != 1 {
				t.Fatalf("recovered submission = %#v, calls=%d, err=%v", completed, fixture.adapter.callCount(), err)
			}
			stored, err = store.NewAcknowledgementRepository(fixture.authority).Get(context.Background(), fixture.plan.PlanID)
			if err != nil || !stored.Consumed {
				t.Fatalf("recovered proof was not consumed exactly once: %#v, %v", stored, err)
			}

			replayed, err := restarted.Submit(context.Background(), fixture.request)
			if err != nil || replayed.RunID != completed.RunID || fixture.adapter.callCount() != 1 {
				t.Fatalf("exact recovered replay = %#v, calls=%d, err=%v", replayed, fixture.adapter.callCount(), err)
			}
			second := fixture.request
			second.Reference.IdempotencyKey = "second-run-same-proof"
			if _, err := restarted.Submit(context.Background(), second); err == nil {
				t.Fatal("the consumed proof admitted a second durable run")
			}
			if fixture.adapter.callCount() != 1 {
				t.Fatalf("second proof claim repeated the adapter effect: %d", fixture.adapter.callCount())
			}
			if _, err := restarted.Get(context.Background(), runID(fixture.plan.PlanID, second.Reference.IdempotencyKey)); Code(err) != generated.ErrorCodeResourceNotFound {
				t.Fatalf("second proof claim left a run: %v", err)
			}
		})
	}
}

type sqliteRestartFixture struct {
	testingT     *testing.T
	config       store.Config
	authority    *store.Store
	clock        func() time.Time
	branch       string
	plan         generated.Plan
	request      SubmitRequest
	adapter      *sqliteCountingAdapter
	ids          *deterministicIDs
	engine       *Engine
	acknowledger *acknowledgement.Service
}

func newSQLiteRestartFixture(t *testing.T, branch string) *sqliteRestartFixture {
	t.Helper()
	now := time.Date(2026, 9, 13, 6, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	config := store.Config{
		DatabasePath: filepath.Join(directory, "control.db"),
		Mode:         store.InitializeNew,
		ExpectedUID:  uint32(os.Geteuid()),
		ToolVersion:  "sqlite-restart-test",
		BuildVersion: "sqlite-restart-test",
		Clock:        clock,
	}
	authority, err := store.Open(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	fixture := &sqliteRestartFixture{testingT: t, config: config, authority: authority, clock: clock, branch: branch, adapter: &sqliteCountingAdapter{}, ids: &deterministicIDs{}}
	t.Cleanup(func() { _ = fixture.authority.Close() })
	fixture.plan = fixture.seedPlan()
	fixture.recompose()
	fixture.request = fixture.submitRequest()
	return fixture
}

func (fixture *sqliteRestartFixture) seedPlan() generated.Plan {
	t := fixture.testingT
	declarations, err := change.NewService(store.NewDeclarationRepository(fixture.authority), fixture.clock)
	if err != nil {
		t.Fatal(err)
	}
	operation := generated.DeclarationOperation{
		Sequence:       1,
		OperationID:    "operation-sqlite-restart",
		OperationType:  "configuration.update",
		AdapterID:      "adapter-sqlite-restart",
		TargetID:       "target-sqlite-restart",
		InputDigest:    digest("sqlite-input"),
		ArtifactDigest: digest("sqlite-artifact"),
		Idempotent:     true,
	}
	author := change.AuthorScope{PrincipalID: "principal-sqlite-restart", PrincipalMethod: identity.LocalOSPeerMethod, AgentSessionID: "session-sqlite-restart"}
	revised, err := declarations.Revise(context.Background(), author, generated.DeclarationRevisionRequest{
		Schema:                generated.SchemaIDDeclarationRevisionRequest,
		SchemaVersion:         "1.0.0",
		DeclarationID:         "declaration-sqlite-restart",
		DeclarationType:       "node.configuration",
		ExpectedRevision:      1,
		ExpectedStateRevision: 0,
		RecoveryEpoch:         0,
		Operations:            []generated.DeclarationOperation{operation},
		ReasonDigest:          digest("sqlite-reason"),
		Extensions: []generated.ContractExtension{{
			Name:        "x-sqlite-restart",
			ValueDigest: digest("sqlite-extension"),
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	repository := store.NewPlanRepository(fixture.authority)
	observations, err := planengine.NewStateObservationReader(repository)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := observations.CurrentFingerprint(context.Background(), revised.Document.DeclarationID, revised.Document.Operations)
	if err != nil {
		t.Fatal(err)
	}
	plans := fixture.newPlanService(repository, observations)
	created, err := plans.Create(context.Background(), planengine.AuthorScope{PrincipalID: author.PrincipalID, PrincipalMethod: author.PrincipalMethod, AgentSessionID: author.AgentSessionID}, generated.PlanCreateRequest{
		Schema:                 generated.SchemaIDPlanCreateRequest,
		SchemaVersion:          "1.0.0",
		DeclarationID:          revised.Document.DeclarationID,
		DeclarationRevision:    revised.Document.Revision,
		ExpectedStateRevision:  revised.Document.StateRevision,
		RecoveryEpoch:          revised.Document.RecoveryEpoch,
		ObservationFingerprint: fingerprint,
		IdempotencyKey:         "plan-sqlite-restart",
		Extensions:             []generated.ContractExtension{},
	})
	if err != nil {
		t.Fatal(err)
	}
	return created.Plan
}

func (fixture *sqliteRestartFixture) newPlanService(repository *store.PlanRepository, observations planengine.ObservationReader) *planengine.Service {
	fixture.testingT.Helper()
	plans, err := planengine.NewService(planengine.Config{
		Repository:          repository,
		Observations:        observations,
		Clock:               fixture.clock,
		PolicyVersion:       "1.0.0",
		ToolVersion:         "1.0.0",
		ContractVersion:     "1.0.0",
		Risk:                "routine",
		AuthorizationBranch: fixture.branch,
		ExecutorMode:        "central",
		OperationExecutorID: "executor-central",
	})
	if err != nil {
		fixture.testingT.Fatal(err)
	}
	return plans
}

func (fixture *sqliteRestartFixture) recompose() {
	t := fixture.testingT
	planRepository := store.NewPlanRepository(fixture.authority)
	observations, err := planengine.NewStateObservationReader(planRepository)
	if err != nil {
		t.Fatal(err)
	}
	plans := fixture.newPlanService(planRepository, observations)
	var acknowledger *acknowledgement.Service
	if fixture.branch == string(authorization.BranchHuman) {
		acknowledger, err = acknowledgement.NewService(acknowledgement.Config{
			Repository: store.NewAcknowledgementRepository(fixture.authority),
			Plans:      sqliteAcknowledgementPlanReader{plans: plans},
			Authorizer: sqliteAcknowledgementAuthorizer{},
			Clock:      fixture.clock,
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	registry := adapter.NewRegistry()
	if err := registry.Register("adapter-sqlite-restart", fixture.adapter); err != nil {
		t.Fatal(err)
	}
	engine, err := NewEngine(Config{
		Repository:   store.NewRunRepository(fixture.authority),
		Plans:        plans,
		Admission:    NewAdmissionGate(acknowledger, fixture.clock),
		Adapters:     registry,
		Clock:        fixture.clock,
		IDs:          fixture.ids,
		LeaseContext: sqliteTestLeaseContext,
	})
	if err != nil {
		t.Fatal(err)
	}
	fixture.acknowledger = acknowledger
	fixture.engine = engine
}

func (fixture *sqliteRestartFixture) submitRequest() SubmitRequest {
	t := fixture.testingT
	branch := fixture.branch
	principalID := "policy-sqlite-restart"
	var proof *generated.Acknowledgement
	if branch == string(authorization.BranchHuman) {
		principalID = "human-sqlite-restart"
		human := identity.Principal{ID: principalID, Method: identity.SlackSocketModeMethod, Kind: identity.PrincipalHuman}
		card, err := fixture.acknowledger.Request(context.Background(), acknowledgement.Scope{Human: human, AuthorityID: "authority-sqlite-restart", Nonce: "nonce-sqlite-restart"}, fixture.plan.PlanID)
		if err != nil {
			t.Fatal(err)
		}
		approved, err := fixture.acknowledger.Decide(context.Background(), acknowledgement.Candidate{
			Human:         human,
			AuthorityID:   card.Request.AuthorityID,
			Action:        acknowledgement.ActionApprove,
			PlanID:        fixture.plan.PlanID,
			PlanDigest:    fixture.plan.PlanDigest,
			TargetDigest:  fixture.plan.Binding.TargetDigest,
			ReasonDigest:  fixture.plan.Binding.ReasonDigest,
			Nonce:         card.Nonce,
			StateRevision: fixture.plan.Binding.StateRevision,
			RecoveryEpoch: fixture.plan.Binding.RecoveryEpoch,
			ExpiresAt:     parseTime(fixture.plan.ExpiresAt),
			DecidedAt:     fixture.clock(),
		})
		if err != nil {
			t.Fatal(err)
		}
		proof = &approved
	}
	decision := generated.AuthorizationDecision{
		Schema:        generated.SchemaIDAuthorizationDecision,
		SchemaVersion: "1.0.0",
		DecisionID:    "decision-sqlite-restart",
		PrincipalID:   principalID,
		Action:        string(authorization.ActionExecute),
		TargetID:      fixture.plan.Operations[0].TargetID,
		Allowed:       true,
		Branch:        &branch,
		ReasonCode:    authorization.ReasonAllowed,
		GrantRevision: 1,
		RecoveryEpoch: fixture.plan.Binding.RecoveryEpoch,
		PlanDigest:    fixture.plan.PlanDigest,
		DecidedAt:     fixture.clock().Format(time.RFC3339),
		Extensions:    []generated.ContractExtension{},
	}
	return SubmitRequest{
		Reference: generated.PlanReferenceRequest{
			Schema:         generated.SchemaIDPlanReferenceRequest,
			SchemaVersion:  "1.0.0",
			PlanID:         fixture.plan.PlanID,
			PlanDigest:     fixture.plan.PlanDigest,
			RecoveryEpoch:  fixture.plan.Binding.RecoveryEpoch,
			IdempotencyKey: "submit-sqlite-restart",
			Extensions:     []generated.ContractExtension{},
		},
		Authorization:   decision,
		Acknowledgement: proof,
		Attribution:     systemAttribution(),
	}
}

func (fixture *sqliteRestartFixture) restart(t *testing.T) *Engine {
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
	fixture.recompose()
	return fixture.engine
}

func (fixture *sqliteRestartFixture) runID() string {
	return runID(fixture.plan.PlanID, fixture.request.Reference.IdempotencyKey)
}

type sqliteAcknowledgementPlanReader struct{ plans *planengine.Service }

func (reader sqliteAcknowledgementPlanReader) Get(ctx context.Context, planID string) (generated.Plan, error) {
	stored, err := reader.plans.Get(ctx, planID)
	return stored.Plan, err
}

func (reader sqliteAcknowledgementPlanReader) ValidateCurrent(ctx context.Context, candidate generated.Plan) error {
	return reader.plans.ValidateCurrent(ctx, candidate)
}

type sqliteAcknowledgementAuthorizer struct{}

func (sqliteAcknowledgementAuthorizer) Authorize(_ context.Context, principal identity.Principal, request authorization.Request) (authorization.Decision, error) {
	branch := authorization.BranchHuman
	return authorization.Decision{
		PrincipalID:   principal.ID,
		Action:        request.Action,
		Target:        request.Target,
		Allowed:       true,
		Branch:        &branch,
		ReasonCode:    authorization.ReasonAllowed,
		GrantRevision: 1,
		StateRevision: request.Plan.Binding.StateRevision,
		RecoveryEpoch: request.Plan.Binding.RecoveryEpoch,
		PlanDigest:    request.Plan.PlanDigest,
	}, nil
}

type sqliteCountingAdapter struct {
	mu    sync.Mutex
	calls int
}

func (implementation *sqliteCountingAdapter) Execute(ctx context.Context, _ adapter.Operation) (adapter.Effect, error) {
	if err := ctx.Err(); err != nil {
		return adapter.Effect{Status: "failed", ResultDigest: digest("sqlite-cancelled"), EffectObserved: false}, err
	}
	implementation.mu.Lock()
	implementation.calls++
	implementation.mu.Unlock()
	return adapter.Effect{Status: "succeeded", ResultDigest: digest("sqlite-result"), Changed: true, EffectObserved: true}, nil
}

func (*sqliteCountingAdapter) Verify(context.Context, adapter.Operation, adapter.Effect) (adapter.Verification, error) {
	return adapter.Verification{Verified: true, Digest: digest("sqlite-verification")}, nil
}

func (implementation *sqliteCountingAdapter) callCount() int {
	implementation.mu.Lock()
	defer implementation.mu.Unlock()
	return implementation.calls
}

func sqliteTestLeaseContext(ctx context.Context, _ time.Time) (context.Context, context.CancelFunc) {
	return context.WithCancel(ctx)
}

var _ acknowledgement.Authorizer = sqliteAcknowledgementAuthorizer{}
var _ acknowledgement.PlanReader = sqliteAcknowledgementPlanReader{}
var _ adapter.Adapter = (*sqliteCountingAdapter)(nil)
