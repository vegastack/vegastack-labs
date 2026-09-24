//go:build linux

package run

import (
	"context"
	"database/sql"
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
	"github.com/vegastack/vegastack-labs/internal/credentialref"
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
	testingT          *testing.T
	config            store.Config
	authority         *store.Store
	clock             func() time.Time
	branch            string
	plan              generated.Plan
	request           SubmitRequest
	adapter           *sqliteCountingAdapter
	effects           *sqliteCountingAdapter
	ids               *deterministicIDs
	engine            *Engine
	acknowledger      *acknowledgement.Service
	operation         phase5OperationBinding
	credentialBinding *credentialref.StepBinding
}

type phase5OperationBinding struct {
	name, declarationType, operationType, adapterID, branch string
	idempotent, sameDigest                                  bool
	extensions                                              []string
}

func newSQLiteRestartFixture(t *testing.T, branch string) *sqliteRestartFixture {
	return newSQLiteRestartFixtureForOperation(t, branch, phase5OperationBinding{name: "generic-run", declarationType: "node.configuration", operationType: "configuration.update", adapterID: "adapter-sqlite-restart", branch: branch, idempotent: true})
}

func newSQLiteRestartFixtureForOperation(t *testing.T, branch string, operation phase5OperationBinding) *sqliteRestartFixture {
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
	counter := &sqliteCountingAdapter{}
	fixture := &sqliteRestartFixture{testingT: t, config: config, authority: authority, clock: clock, branch: branch, adapter: counter, effects: counter, ids: &deterministicIDs{}, operation: operation}
	t.Cleanup(func() { _ = fixture.authority.Close() })
	fixture.plan = fixture.seedPlan()
	fixture.recompose()
	fixture.request = fixture.submitRequest()
	return fixture
}

func (fixture *sqliteRestartFixture) seedPlan() generated.Plan {
	t := fixture.testingT
	if fixture.operation.name == "" || fixture.operation.operationType == "" || fixture.operation.adapterID == "" || fixture.operation.declarationType == "" {
		t.Fatal("durable operation binding is incomplete")
	}
	if fixture.operation.name == "offsite-copy" {
		d := digest("phase5-offsite-source")
		at := fixture.clock().Format(time.RFC3339)
		database, err := sql.Open("sqlite3", fixture.config.DatabasePath)
		if err != nil {
			t.Fatal(err)
		}
		defer database.Close()
		if _, err := database.ExecContext(context.Background(), `INSERT INTO backup_jobs(job_id,policy_id,policy_digest,repository_id,repository_class,source_kind,proof_class,status,recovery_epoch,created_at,updated_at) VALUES(?,?,?,?,?,'local','fixture','pending',0,?,?)`, "job-phase5", "policy-phase5", d, "repository-phase5", "critical", at, at); err != nil {
			t.Fatal(err)
		}
		if _, err := database.ExecContext(context.Background(), `INSERT INTO recovery_points(point_id,job_id,policy_id,policy_digest,repository_id,repository_class,source_kind,proof_class,snapshot_id,snapshot_count,object_count,object_bytes,content_digest,manifest_digest,manifest_json,inventory_digest,source_revision,recovery_epoch,verification_status,created_at) VALUES(?,?,?,?,?,?,'local','fixture',?,1,1,1,?,?,'{}',?,1,0,'pending',?)`, "point-phase5", "job-phase5", "policy-phase5", d, "repository-phase5", "critical", "snapshot-phase5", d, d, d, at); err != nil {
			t.Fatal(err)
		}
	}
	declarations, err := change.NewService(store.NewDeclarationRepository(fixture.authority), fixture.clock)
	if err != nil {
		t.Fatal(err)
	}
	inputDigest, artifactDigest := digest("sqlite-input-"+fixture.operation.name), digest("sqlite-artifact-"+fixture.operation.name)
	if fixture.operation.sameDigest {
		artifactDigest = inputDigest
	}
	for _, name := range fixture.operation.extensions {
		if name == "x-credential-bindings" {
			binding := credentialref.StepBinding{OperationID: "operation-sqlite-restart-" + fixture.operation.name, AdapterID: fixture.operation.adapterID, TargetID: "target-sqlite-restart", ReferenceID: "reference-" + fixture.operation.name, ConsumerID: fixture.operation.adapterID, PurposeID: "phase5-durable-matrix", MaterialVersion: "version-1", ResolverID: "native-phase5", StateRevision: 2, RecoveryEpoch: 0}
			fixture.credentialBinding = &binding
			inputDigest = credentialref.OperationManifestDigest([]credentialref.StepBinding{binding}, binding.OperationID)
		}
	}
	extensions := make([]generated.ContractExtension, 0, len(fixture.operation.extensions))
	for _, name := range fixture.operation.extensions {
		value := artifactDigest
		if name == "x-credential-bindings" {
			value = credentialref.ManifestDigest([]credentialref.StepBinding{*fixture.credentialBinding})
		}
		extensions = append(extensions, generated.ContractExtension{Name: name, ValueDigest: value})
	}
	operation := generated.DeclarationOperation{
		Sequence:       1,
		OperationID:    "operation-sqlite-restart-" + fixture.operation.name,
		OperationType:  fixture.operation.operationType,
		AdapterID:      fixture.operation.adapterID,
		TargetID:       "target-sqlite-restart",
		InputDigest:    inputDigest,
		ArtifactDigest: artifactDigest,
		Idempotent:     fixture.operation.idempotent,
	}
	if fixture.operation.name == "offsite-copy" {
		operation.TargetID = "generation-phase5"
		operation.OffsiteRunSpec = &generated.OffsiteRunSpec{GenerationID: operation.TargetID, SourcePointID: "point-phase5", SourceRevision: 1, SnapshotPath: "/var/lib/vsk-labs/offsite/phase5", RepositoryURL: "s3:https://account.r2.cloudflarestorage.com/bucket/phase5", ParentReferenceID: "parent-phase5", RepositoryKeyReferenceID: "password-phase5", ObserverReferenceID: "observer-phase5", RuleDigest: artifactDigest, G008EvidenceDigest: artifactDigest, MaximumBytes: 4096, MaximumPUTs: 100, MaximumLISTs: 20, MaximumRetainedGenerations: 100, RuleLimit: 1000, RetentionSeconds: 86400, SessionTTLSeconds: 60}
		fixture.credentialBinding.TargetID = operation.TargetID
		inputDigest = credentialref.OperationManifestDigest([]credentialref.StepBinding{*fixture.credentialBinding}, fixture.credentialBinding.OperationID)
		operation.InputDigest = inputDigest
		for index := range extensions {
			if extensions[index].Name == "x-credential-bindings" {
				extensions[index].ValueDigest = credentialref.ManifestDigest([]credentialref.StepBinding{*fixture.credentialBinding})
			}
		}
	}
	author := change.AuthorScope{PrincipalID: "principal-sqlite-restart", PrincipalMethod: identity.LocalOSPeerMethod, AgentSessionID: "session-sqlite-restart"}
	revised, err := declarations.Revise(context.Background(), author, generated.DeclarationRevisionRequest{
		Schema:                generated.SchemaIDDeclarationRevisionRequest,
		SchemaVersion:         "1.0.0",
		DeclarationID:         "declaration-sqlite-restart-" + fixture.operation.name,
		DeclarationType:       fixture.operation.declarationType,
		ExpectedRevision:      1,
		ExpectedStateRevision: 0,
		RecoveryEpoch:         0,
		Operations:            []generated.DeclarationOperation{operation},
		ReasonDigest:          digest("sqlite-reason"),
		Extensions:            extensions,
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
		IdempotencyKey:         "plan-sqlite-restart-" + fixture.operation.name,
		Extensions:             extensions,
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
	if fixture.operation.adapterID != "core.credential" && fixture.operation.adapterID != "core.audit" && fixture.operation.adapterID != "core.recovery" && fixture.operation.adapterID != "core.schedule-observe" {
		if err := registry.Register(fixture.operation.adapterID, phase5ProviderBoundary(fixture.operation, fixture.effects)); err != nil {
			t.Fatal(err)
		}
	} else if err := registry.Register("adapter-sqlite-restart", fixture.adapter); err != nil {
		t.Fatal(err)
	}
	core := phase5CoreBoundary(fixture.operation, fixture.effects)
	var secretGate GateVerifier
	var credentialStep *CredentialStep
	if fixture.credentialBinding != nil {
		activeAt := fixture.clock().Format(time.RFC3339)
		binding := *fixture.credentialBinding
		secretGate = &syntheticGateVerifier{}
		credentialStep = &CredentialStep{
			Bindings:  &fakeCredentialBindings{binding: binding, reference: generated.CredentialReference{ReferenceID: binding.ReferenceID, ConsumerID: binding.ConsumerID, PurposeID: binding.PurposeID, TargetID: binding.TargetID, ResolverID: binding.ResolverID, MaterialVersion: binding.MaterialVersion, Status: "active", StateRevision: 2, RecoveryEpoch: 0, ActivatedAt: &activeAt, VerifiedConsumerIDs: []string{binding.ConsumerID}}},
			Resolvers: &fakeCredentialRegistry{resolver: &countingCredentialResolver{}},
			Profiles:  fakeCredentialProfiles{scope: store.GateAppliedProfile{ProfileID: "profile-phase5", StateRevision: 2, RecoveryEpoch: 0, Capabilities: []string{"credential.native.read"}}},
			Plans:     plans,
			Clock:     fixture.clock,
		}
	}
	engine, err := NewEngine(Config{
		Repository:     store.NewRunRepository(fixture.authority),
		Plans:          plans,
		Admission:      NewAdmissionGate(acknowledger, fixture.clock),
		Adapters:       registry,
		Core:           core,
		CredentialCore: core,
		SecretGate:     secretGate,
		CredentialStep: credentialStep,
		Clock:          fixture.clock,
		IDs:            fixture.ids,
		LeaseContext:   sqliteTestLeaseContext,
	})
	if err != nil {
		t.Fatal(err)
	}
	fixture.acknowledger = acknowledger
	fixture.engine = engine
}

func (fixture *sqliteRestartFixture) effectCount() int { return fixture.effects.callCount() }

type phase5ExactAdapter struct {
	expectedAdapter, expectedOperation string
	counter                            *sqliteCountingAdapter
}

type phase5LocalBackupBoundary struct{ *phase5ExactAdapter }
type phase5LocalRetentionBoundary struct{ *phase5ExactAdapter }
type phase5OffsiteCopyBoundary struct{ *phase5ExactAdapter }
type phase5OffsiteRetirementBoundary struct{ *phase5ExactAdapter }

func phase5ProviderBoundary(operation phase5OperationBinding, counter *sqliteCountingAdapter) adapter.Adapter {
	base := &phase5ExactAdapter{expectedAdapter: operation.adapterID, expectedOperation: operation.operationType, counter: counter}
	switch operation.adapterID {
	case "local.backup":
		return &phase5LocalBackupBoundary{base}
	case "local.retention":
		return &phase5LocalRetentionBoundary{base}
	case "labs.r2-offsite":
		return &phase5OffsiteCopyBoundary{base}
	case "r2.retention":
		return &phase5OffsiteRetirementBoundary{base}
	default:
		return base
	}
}

func (implementation *phase5ExactAdapter) Execute(ctx context.Context, operation adapter.Operation) (adapter.Effect, error) {
	if operation.AdapterID != implementation.expectedAdapter || operation.OperationType != implementation.expectedOperation {
		return adapter.Effect{}, errors.New("unexpected phase5 adapter route")
	}
	return implementation.counter.Execute(ctx, operation)
}
func (implementation *phase5ExactAdapter) Verify(ctx context.Context, operation adapter.Operation, effect adapter.Effect) (adapter.Verification, error) {
	if operation.AdapterID != implementation.expectedAdapter || operation.OperationType != implementation.expectedOperation {
		return adapter.Verification{}, errors.New("unexpected phase5 adapter verification route")
	}
	return implementation.counter.Verify(ctx, operation, effect)
}
func (implementation *phase5ExactAdapter) ExecuteWithCredentials(ctx context.Context, operation adapter.Operation, _ []*credentialref.Value) (adapter.Effect, error) {
	return implementation.Execute(ctx, operation)
}

type phase5ExactCore struct {
	expectedAdapter, expectedOperation string
	counter                            *sqliteCountingAdapter
}

type phase5CredentialBoundary struct{ *phase5ExactCore }
type phase5AuditBoundary struct{ *phase5ExactCore }
type phase5RecoveryBoundary struct{ *phase5ExactCore }
type phase5ScheduleBoundary struct{ *phase5ExactCore }

func phase5CoreBoundary(operation phase5OperationBinding, counter *sqliteCountingAdapter) CoreEffect {
	base := &phase5ExactCore{expectedAdapter: operation.adapterID, expectedOperation: operation.operationType, counter: counter}
	switch operation.adapterID {
	case "core.credential":
		return &phase5CredentialBoundary{base}
	case "core.audit":
		return &phase5AuditBoundary{base}
	case "core.recovery":
		return &phase5RecoveryBoundary{base}
	case "core.schedule-observe":
		return &phase5ScheduleBoundary{base}
	default:
		return base
	}
}

func (implementation *phase5ExactCore) Execute(ctx context.Context, binding ExactStepBinding) (adapter.Effect, error) {
	operation := binding.Plan.Operations[0]
	if operation.AdapterID != implementation.expectedAdapter || operation.OperationType != implementation.expectedOperation {
		return adapter.Effect{}, errors.New("unexpected phase5 core route")
	}
	return implementation.counter.Execute(ctx, adapter.Operation{AdapterID: operation.AdapterID, OperationType: operation.OperationType})
}
func (implementation *phase5ExactCore) Verify(ctx context.Context, binding ExactStepBinding, effect adapter.Effect) (adapter.Verification, error) {
	operation := binding.Plan.Operations[0]
	if operation.AdapterID != implementation.expectedAdapter || operation.OperationType != implementation.expectedOperation {
		return adapter.Verification{}, errors.New("unexpected phase5 core verification route")
	}
	return implementation.counter.Verify(ctx, adapter.Operation{AdapterID: operation.AdapterID, OperationType: operation.OperationType}, effect)
}

func (fixture *sqliteRestartFixture) submitRequest() SubmitRequest {
	t := fixture.testingT
	branch := fixture.branch
	principalID := "policy-sqlite-restart"
	var proof *generated.Acknowledgement
	if branch == string(authorization.BranchHuman) {
		principalID = "human-sqlite-restart"
		human := identity.Principal{ID: principalID, Method: identity.SlackSocketModeMethod, Kind: identity.PrincipalHuman}
		card, err := fixture.acknowledger.Request(context.Background(), acknowledgement.Scope{Human: human, AuthorityID: "authority-sqlite-restart", Nonce: "nonce-sqlite-restart-" + fixture.plan.PlanID}, fixture.plan.PlanID)
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
