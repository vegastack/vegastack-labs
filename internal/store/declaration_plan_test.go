//go:build linux

package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/vegastack/vegastack-labs/internal/audit"
	"github.com/vegastack/vegastack-labs/internal/generated"
)

const testDigest = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func TestDeclarationAndPlanCommitRollsBackTogether(t *testing.T) {
	config := testConfig(t)
	config.Clock = func() time.Time { return time.Date(2026, 9, 12, 18, 30, 0, 0, time.UTC) }
	s, err := Open(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })

	declarations := NewDeclarationRepository(s)
	created, err := declarations.CreateRevision(context.Background(), validDeclarationStoreRequest())
	if err != nil {
		t.Fatal(err)
	}
	plans := NewPlanRepository(s)
	plans.testFailBeforePlanInsert = func() error { return errors.New("stop") }
	_, err = plans.CommitDeclarationAndPlan(context.Background(), validPlanStoreRequest(created.Document))
	if err == nil {
		t.Fatal("expected failure")
	}
	if _, err := plans.GetPlan(context.Background(), "plan-test-1"); Code(err) != generated.ErrorCodeResourceNotFound {
		t.Fatalf("plan lookup error = %v", err)
	}
	health, err := s.Health(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if health.Revision.StateRevision != created.Commit.StateRevision {
		t.Fatalf("state revision advanced after rollback: %d", health.Revision.StateRevision)
	}
}

func TestDeclarationAndPlanRejectStaleAndConflictingReplay(t *testing.T) {
	config := testConfig(t)
	config.Clock = func() time.Time { return time.Date(2026, 9, 12, 18, 30, 0, 0, time.UTC) }
	s, err := Open(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })

	declarations := NewDeclarationRepository(s)
	request := validDeclarationStoreRequest()
	first, err := declarations.CreateRevision(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	replayed, err := declarations.CreateRevision(context.Background(), request)
	if err != nil || replayed.Created || replayed.Document.ContentDigest != first.Document.ContentDigest {
		t.Fatalf("declaration replay = %#v, %v", replayed, err)
	}
	request.RequestDigest = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	if _, err := declarations.CreateRevision(context.Background(), request); Code(err) != generated.ErrorCodeStateConflict {
		t.Fatalf("conflicting declaration replay error = %v", err)
	}

	plans := NewPlanRepository(s)
	planRequest := validPlanStoreRequest(first.Document)
	committed, err := plans.CommitDeclarationAndPlan(context.Background(), planRequest)
	if err != nil {
		t.Fatal(err)
	}
	replayedPlan, err := plans.CommitDeclarationAndPlan(context.Background(), planRequest)
	if err != nil || replayedPlan.Created || replayedPlan.Plan.PlanID != committed.Plan.PlanID {
		t.Fatalf("plan replay = %#v, %v", replayedPlan, err)
	}
	planRequest.RequestDigest = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	if _, err := plans.CommitDeclarationAndPlan(context.Background(), planRequest); Code(err) != generated.ErrorCodeStateConflict {
		t.Fatalf("conflicting plan replay error = %v", err)
	}
}

func validDeclarationStoreRequest() DeclarationRevisionRequest {
	return DeclarationRevisionRequest{
		Document:     generated.DeclarationRevision{Schema: generated.SchemaIDDeclarationRevision, SchemaVersion: "1.0.0", DeclarationID: "declaration-test-1", DeclarationType: "node.configuration", Revision: 1, StateRevision: 1, RecoveryEpoch: 0, ContentDigest: testDigest, Status: "draft", Operations: []generated.DeclarationOperation{{Sequence: 1, OperationID: "operation-test-1", OperationType: "configuration.update", AdapterID: "adapter-test-1", TargetID: "target-test-1", InputDigest: testDigest, ArtifactDigest: testDigest, Idempotent: true}}, CreatedAt: "2026-09-12T18:30:00Z", CreatedBy: "principal-test-1", AgentSessionID: "session-test-1", Extensions: []generated.ContractExtension{}},
		ReasonDigest: testDigest, Expected: RevisionToken{StateRevision: 0, RecoveryEpoch: 0}, KeyDigest: testDigest, RequestDigest: testDigest, Attribution: audit.Attribution{AuthenticatedPrincipalID: "principal-test-1", AuthenticatedPrincipalMethod: "local-os-peer"},
	}
}

func validPlanStoreRequest(declaration generated.DeclarationRevision) PlanCommitRequest {
	readable := "readable\n"
	readableSum := sha256.Sum256([]byte(readable))
	value := generated.Plan{Schema: generated.SchemaIDPlan, SchemaVersion: "1.0.0", DeclarationID: declaration.DeclarationID, Binding: generated.PlanBinding{RecoveryEpoch: 0, PriorStateRevision: 1, StateRevision: 2, DeclarationRevision: declaration.Revision, ObservationFingerprint: testDigest, TargetDigest: testDigest, ReasonDigest: testDigest, PolicyVersion: "1.0.0", ToolVersion: "1.0.0", ContractVersion: "1.0.0"}, Operations: []generated.PlanOperation{{Sequence: 1, OperationID: "operation-test-1", OperationType: "configuration.update", AdapterID: "adapter-test-1", ExecutorID: "executor-central", TargetID: "target-test-1", InputDigest: testDigest, ArtifactDigest: testDigest, Idempotent: true}}, Status: "planned", Risk: "routine", AuthorizationBranch: "human", ExecutorMode: "central", CreatedAt: "2026-09-12T18:30:00Z", ExpiresAt: "2026-09-12T19:00:00Z", ReadableDigest: "sha256:" + hex.EncodeToString(readableSum[:]), Extensions: []generated.ContractExtension{}}
	preimage, _ := json.Marshal(value)
	planSum := sha256.Sum256(preimage)
	value.PlanDigest = "sha256:" + hex.EncodeToString(planSum[:])
	value.PlanID = "plan-" + hex.EncodeToString(planSum[:16])
	canonical, _ := json.Marshal(value)
	return PlanCommitRequest{Plan: value, CanonicalBytes: canonical, Readable: readable, Expected: RevisionToken{StateRevision: 1, RecoveryEpoch: 0}, KeyDigest: testDigest, RequestDigest: testDigest, Attribution: audit.Attribution{AuthenticatedPrincipalID: "principal-test-1", AuthenticatedPrincipalMethod: "local-os-peer"}}
}
