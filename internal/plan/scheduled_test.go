package plan

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/schedule"
	"github.com/vegastack/vegastack-labs/internal/store"
)

type operationalPlanMemory struct {
	request store.OperationalPlanCommitRequest
}

func (memory *operationalPlanMemory) CommitOperationalPlan(_ context.Context, request store.OperationalPlanCommitRequest) (store.PlanCommitResult, error) {
	memory.request = request
	return store.PlanCommitResult{Plan: request.Plan, Canonical: request.CanonicalBytes, Readable: request.Readable, Created: true}, nil
}

func scheduledPlanPolicy() generated.ScheduledJobPolicy {
	digest := "sha256:" + strings.Repeat("a", 64)
	return generated.ScheduledJobPolicy{Schema: generated.SchemaIDScheduledJobPolicy, SchemaVersion: "1.1.0", PolicyID: "policy-a", Revision: 1, DeclarationID: "declaration-a", DeclarationRevision: 2, ApprovalPlanID: "approval-plan-a", ApprovalPlanDigest: digest, ApprovedByHumanID: "human-a", ActionKind: "backup-create", OperationType: "backup.local.create", AdapterID: "core.backup", ExactSourceIDs: []string{"source-a"}, ExactSubjectIDs: []string{"subject-a"}, ExactTargetIDs: []string{"target-a"}, MaximumWork: 1, CredentialReferenceIDs: []string{"credential-a"}, GrantRevision: 3, StateRevision: 8, RecoveryEpoch: 2, PolicyVersion: "1.0.0", RetentionRuleDigest: digest, AnchorAt: "2026-09-16T00:00:00Z", IntervalSeconds: 3600, WindowSeconds: 1800, CatchUp: "latest", Concurrency: "forbid", MaxAttempts: 2, InitialBackoffSeconds: 5, MaximumBackoffSeconds: 30, ExpiresAt: "2026-10-16T00:00:00Z", Enabled: true}
}

func TestScheduledPlanIsFreshPreauthorizedAndDoesNotAdvanceDesiredState(t *testing.T) {
	policy := scheduledPlanPolicy()
	canonical, digest, err := schedule.CanonicalPolicy(policy)
	_ = canonical
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 9, 16, 1, 0, 0, 0, time.UTC)
	memory := &operationalPlanMemory{}
	service, err := NewScheduledService(memory, func() time.Time { return now }, "1.0.0", "1.0.0", "central-schedule")
	if err != nil {
		t.Fatal(err)
	}
	result, err := service.CreateScheduled(context.Background(), ScheduledRequest{Policy: policy, PolicyDigest: digest, JobID: "scheduled-job-a", OccurrenceDigest: "sha256:" + strings.Repeat("b", 64), ObservationFingerprint: "sha256:" + strings.Repeat("c", 64), Attempt: 1, ScheduledAt: now, WindowClosesAt: now.Add(30 * time.Minute), Expected: store.RevisionToken{StateRevision: 8, RecoveryEpoch: 2}})
	if err != nil {
		t.Fatal(err)
	}
	if result.Plan.AuthorizationBranch != "preauthorized" || result.Plan.ExecutorMode != "central" || result.Plan.Binding.StateRevision != 8 || result.Plan.Binding.PriorStateRevision != 8 || result.Plan.Operations[0].OperationType != "backup.local.create" || len(result.Plan.Extensions) != 2 {
		t.Fatalf("plan=%#v", result.Plan)
	}
	if memory.request.Expected.StateRevision != 8 || memory.request.Plan.PlanDigest == "" {
		t.Fatalf("commit=%#v", memory.request)
	}
}

func TestScheduledPlanCannotOutliveOccurrenceWindow(t *testing.T) {
	policy := scheduledPlanPolicy()
	_, digest, _ := schedule.CanonicalPolicy(policy)
	now := time.Date(2026, 9, 16, 1, 0, 0, 0, time.UTC)
	service, _ := NewScheduledService(&operationalPlanMemory{}, func() time.Time { return now }, "1.0.0", "1.0.0", "central-schedule")
	_, err := service.CreateScheduled(context.Background(), ScheduledRequest{Policy: policy, PolicyDigest: digest, JobID: "scheduled-job-a", OccurrenceDigest: "sha256:" + strings.Repeat("b", 64), ObservationFingerprint: "sha256:" + strings.Repeat("c", 64), Attempt: 1, ScheduledAt: now, WindowClosesAt: now.Add(29 * time.Minute), Expected: store.RevisionToken{StateRevision: 8, RecoveryEpoch: 2}})
	if err == nil {
		t.Fatal("plan outlived occurrence window")
	}
}
