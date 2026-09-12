package plan

import (
	"bytes"
	"context"
	"os"
	"testing"
	"time"

	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/store"
)

func TestCreatePlanIsDeterministicAcrossStoredInputOrder(t *testing.T) {
	declaration := validDeclaration()
	first := createWithDeclaration(t, declaration)
	golden, err := os.ReadFile("testdata/plan.golden.json")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first.Canonical, bytes.TrimSpace(golden)) {
		t.Fatal("canonical plan differs from golden bytes")
	}
	declaration.Operations[0], declaration.Operations[1] = declaration.Operations[1], declaration.Operations[0]
	second := createWithDeclaration(t, declaration)
	if first.Plan.PlanDigest != second.Plan.PlanDigest || first.Readable != second.Readable || string(first.Canonical) != string(second.Canonical) {
		t.Fatal("plan drift")
	}
}

func TestValidateCurrentRejectsExpiryFactsRevisionAndRecoveryDrift(t *testing.T) {
	repository := &fakePlanRepository{declaration: validDeclaration(), current: store.RevisionToken{StateRevision: 9, RecoveryEpoch: 2}}
	observations := &fakeObservations{fingerprint: testDigestString("b")}
	clock := time.Date(2026, 9, 12, 19, 0, 0, 0, time.UTC)
	service := newTestService(t, repository, observations, func() time.Time { return clock })
	result, err := service.Create(context.Background(), AuthorScope{PrincipalID: "principal-test", PrincipalMethod: "local-os-peer"}, validRequest())
	if err != nil {
		t.Fatal(err)
	}
	repository.current.StateRevision = result.Plan.Binding.StateRevision
	if err := service.ValidateCurrent(context.Background(), result.Plan); err != nil {
		t.Fatal(err)
	}
	clock = clock.Add(31 * time.Minute)
	if err := service.ValidateCurrent(context.Background(), result.Plan); err == nil {
		t.Fatal("expired plan accepted")
	}
}

func TestCreateCommitsASeparateDesiredDeclarationWithThePlan(t *testing.T) {
	repository := &fakePlanRepository{declaration: validDeclaration(), current: store.RevisionToken{StateRevision: 9, RecoveryEpoch: 2}}
	service := newTestService(t, repository, &fakeObservations{fingerprint: testDigestString("b")}, func() time.Time {
		return time.Date(2026, 9, 12, 19, 0, 0, 0, time.UTC)
	})
	result, err := service.Create(context.Background(), AuthorScope{PrincipalID: "principal-test", PrincipalMethod: "local-os-peer", AgentSessionID: "session-plan"}, validRequest())
	if err != nil {
		t.Fatal(err)
	}
	desired := repository.committed.DesiredDeclaration
	if desired.Status != "committed" || desired.Revision != 2 || desired.StateRevision != 10 || desired.AgentSessionID != "session-plan" {
		t.Fatalf("desired declaration = %#v", desired)
	}
	if repository.committed.SourceDeclarationRevision != 1 || result.Plan.Binding.DeclarationRevision != desired.Revision || desired.ContentDigest != repository.declaration.ContentDigest {
		t.Fatal("plan did not bind the atomically committed desired declaration")
	}
}

func TestCreateNormalizesPlanExtensionsForDigestAndReplay(t *testing.T) {
	repository := &fakePlanRepository{declaration: validDeclaration(), current: store.RevisionToken{StateRevision: 9, RecoveryEpoch: 2}}
	service := newTestService(t, repository, &fakeObservations{fingerprint: testDigestString("b")}, func() time.Time {
		return time.Date(2026, 9, 12, 19, 0, 0, 0, time.UTC)
	})
	request := validRequest()
	request.Extensions = []generated.ContractExtension{{Name: "x-z", ValueDigest: testDigestString("c")}, {Name: "x-a", ValueDigest: testDigestString("d")}}
	first, err := service.Create(context.Background(), AuthorScope{PrincipalID: "principal-test", PrincipalMethod: "local-os-peer", AgentSessionID: "session-plan"}, request)
	if err != nil {
		t.Fatal(err)
	}
	firstRequestDigest := repository.committed.RequestDigest
	request.Extensions[0], request.Extensions[1] = request.Extensions[1], request.Extensions[0]
	second, err := service.Create(context.Background(), AuthorScope{PrincipalID: "principal-test", PrincipalMethod: "local-os-peer", AgentSessionID: "session-plan"}, request)
	if err != nil {
		t.Fatal(err)
	}
	if first.Plan.PlanDigest != second.Plan.PlanDigest || firstRequestDigest != repository.committed.RequestDigest || second.Plan.Extensions[0].Name != "x-a" {
		t.Fatal("compatible plan extension reorder changed canonical output or replay digest")
	}
}

func TestStateObservationFingerprintDoesNotBecomeStaleWhenPlanCommitAdvancesState(t *testing.T) {
	repository := &fakePlanRepository{current: store.RevisionToken{StateRevision: 9, RecoveryEpoch: 2}}
	reader, err := NewStateObservationReader(repository)
	if err != nil {
		t.Fatal(err)
	}
	declaration := validDeclaration()
	before, err := reader.CurrentFingerprint(context.Background(), declaration.DeclarationID, declaration.Operations)
	if err != nil {
		t.Fatal(err)
	}
	repository.current.StateRevision++
	after, err := reader.CurrentFingerprint(context.Background(), declaration.DeclarationID, declaration.Operations)
	if err != nil {
		t.Fatal(err)
	}
	if before != after {
		t.Fatal("the plan's own state commit made its observation fingerprint stale")
	}
}

func createWithDeclaration(t *testing.T, declaration generated.DeclarationRevision) store.PlanCommitResult {
	t.Helper()
	repository := &fakePlanRepository{declaration: declaration, current: store.RevisionToken{StateRevision: 9, RecoveryEpoch: 2}}
	service := newTestService(t, repository, &fakeObservations{fingerprint: testDigestString("b")}, func() time.Time { return time.Date(2026, 9, 12, 19, 0, 0, 0, time.UTC) })
	result, err := service.Create(context.Background(), AuthorScope{PrincipalID: "principal-test", PrincipalMethod: "local-os-peer"}, validRequest())
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func newTestService(t *testing.T, repository Repository, observations ObservationReader, clock func() time.Time) *Service {
	t.Helper()
	service, err := NewService(Config{Repository: repository, Observations: observations, Clock: clock, PolicyVersion: "1.0.0", ToolVersion: "1.0.0", ContractVersion: "1.0.0", Risk: "routine", AuthorizationBranch: "human", ExecutorMode: "central", OperationExecutorID: "executor-central"})
	if err != nil {
		t.Fatal(err)
	}
	return service
}

type fakePlanRepository struct {
	declaration generated.DeclarationRevision
	current     store.RevisionToken
	committed   store.PlanCommitRequest
}

func (repository *fakePlanRepository) GetDeclaration(context.Context, string, int64) (generated.DeclarationRevision, error) {
	return repository.declaration, nil
}
func (repository *fakePlanRepository) GetDeclarationReason(context.Context, string, int64) (string, error) {
	return testDigestString("a"), nil
}
func (repository *fakePlanRepository) CurrentRevision(context.Context) (store.RevisionToken, error) {
	return repository.current, nil
}
func (repository *fakePlanRepository) ExistingPlan(context.Context, string, string) (store.PlanCommitResult, bool, error) {
	return store.PlanCommitResult{}, false, nil
}
func (repository *fakePlanRepository) GetPlan(context.Context, string) (store.PlanCommitResult, error) {
	return store.PlanCommitResult{Plan: repository.committed.Plan, Canonical: repository.committed.CanonicalBytes, Readable: repository.committed.Readable}, nil
}
func (repository *fakePlanRepository) CommitDeclarationAndPlan(_ context.Context, request store.PlanCommitRequest) (store.PlanCommitResult, error) {
	repository.committed = request
	return store.PlanCommitResult{Plan: request.Plan, Canonical: request.CanonicalBytes, Readable: request.Readable, Commit: store.Commit{Changed: true, StateRevision: request.Plan.Binding.StateRevision, RecoveryEpoch: request.Plan.Binding.RecoveryEpoch}, Created: true}, nil
}

type fakeObservations struct{ fingerprint string }

func (reader *fakeObservations) CurrentFingerprint(context.Context, string, []generated.DeclarationOperation) (string, error) {
	return reader.fingerprint, nil
}

func validRequest() generated.PlanCreateRequest {
	return generated.PlanCreateRequest{Schema: generated.SchemaIDPlanCreateRequest, SchemaVersion: "1.0.0", DeclarationID: "declaration-test-1", DeclarationRevision: 1, ExpectedStateRevision: 9, RecoveryEpoch: 2, ObservationFingerprint: testDigestString("b"), IdempotencyKey: "plan-request-1", Extensions: []generated.ContractExtension{}}
}

func validDeclaration() generated.DeclarationRevision {
	return generated.DeclarationRevision{Schema: generated.SchemaIDDeclarationRevision, SchemaVersion: "1.0.0", DeclarationID: "declaration-test-1", DeclarationType: "node.configuration", Revision: 1, StateRevision: 9, RecoveryEpoch: 2, ContentDigest: testDigestString("a"), Status: "draft", Operations: []generated.DeclarationOperation{{Sequence: 2, OperationID: "operation-b", OperationType: "configuration.update", AdapterID: "adapter-test", TargetID: "node-b", InputDigest: testDigestString("b"), ArtifactDigest: testDigestString("c"), Idempotent: true}, {Sequence: 1, OperationID: "operation-a", OperationType: "configuration.update", AdapterID: "adapter-test", TargetID: "node-a", InputDigest: testDigestString("a"), ArtifactDigest: testDigestString("b"), Idempotent: true}}, CreatedAt: "2026-09-12T18:59:00Z", CreatedBy: "principal-test", AgentSessionID: "session-test", Extensions: []generated.ContractExtension{}}
}

func testDigestString(fill string) string {
	value := ""
	for len(value) < 64 {
		value += fill
	}
	return "sha256:" + value[:64]
}
