//go:build linux

package store

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/vegastack/vegastack-labs/internal/audit"
	"github.com/vegastack/vegastack-labs/internal/generated"
)

func scheduledPolicyFixture() generated.ScheduledJobPolicy {
	digest := "sha256:" + strings.Repeat("a", 64)
	return generated.ScheduledJobPolicy{Schema: generated.SchemaIDScheduledJobPolicy, SchemaVersion: "1.1.0", PolicyID: "policy-a", Revision: 1,
		DeclarationID: "declaration-a", DeclarationRevision: 1, ApprovalPlanID: "plan-a", ApprovalPlanDigest: digest, ApprovedByHumanID: "human-a",
		ActionKind: "backup-create", OperationType: "backup.local.create", AdapterID: "local.backup", ExactSourceIDs: []string{"source-a"}, ExactSubjectIDs: []string{"subject-a"}, ExactTargetIDs: []string{"target-a"}, MaximumWork: 1, CredentialReferenceIDs: []string{"credential-a"},
		GrantRevision: 1, StateRevision: 0, RecoveryEpoch: 0, PolicyVersion: "1.0.0", RetentionRuleDigest: digest, AnchorAt: "2026-09-16T00:00:00Z", IntervalSeconds: 3600, WindowSeconds: 1800, CatchUp: "latest", Concurrency: "forbid", MaxAttempts: 3, InitialBackoffSeconds: 10, MaximumBackoffSeconds: 60, ExpiresAt: "2026-10-16T00:00:00Z", Enabled: true}
}

func TestPolicyActivationRequiresExactHumanPlanAndOccurrenceSlotIsUnique(t *testing.T) {
	ctx := context.Background()
	authority := openTestStore(t)
	repository := NewScheduleRepository(authority)
	attribution := audit.Attribution{AuthenticatedPrincipalID: "human-a", AuthenticatedPrincipalMethod: "local-os-peer"}
	policy := scheduledPolicyFixture()
	draft, err := repository.StageDraft(ctx, policy, attribution)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repository.Activate(ctx, ScheduleActivationRequest{DraftID: draft.DraftID, AuthorizationBranch: "preauthorized", ExecutingOperation: "schedule.policy.activate", PlanID: policy.ApprovalPlanID, PlanDigest: policy.ApprovalPlanDigest, AcknowledgementID: "ack-a", Expected: RevisionToken{}, Attribution: attribution}); Code(err) != generated.ErrorCodeAuthorizationDenied {
		t.Fatalf("preauthorized activation err=%v", err)
	}
	active, err := repository.Activate(ctx, ScheduleActivationRequest{DraftID: draft.DraftID, AuthorizationBranch: "human", ExecutingOperation: "schedule.policy.activate", PlanID: policy.ApprovalPlanID, PlanDigest: policy.ApprovalPlanDigest, AcknowledgementID: "ack-a", Expected: RevisionToken{}, Attribution: attribution})
	if err != nil || active.PolicyID != policy.PolicyID {
		t.Fatalf("activation=%#v err=%v", active, err)
	}
	due := time.Date(2026, 9, 16, 1, 0, 0, 0, time.UTC)
	first, err := repository.ClaimOccurrence(ctx, OccurrenceClaim{Policy: policy, ScheduledAt: due, OccurrenceToken: "token-a", TargetDigest: policy.RetentionRuleDigest, IdempotencyKey: "key-a", Expected: RevisionToken{}})
	if err != nil {
		t.Fatal(err)
	}
	second, err := repository.ClaimOccurrence(ctx, OccurrenceClaim{Policy: policy, ScheduledAt: due, OccurrenceToken: "token-b", TargetDigest: policy.RetentionRuleDigest, IdempotencyKey: "key-b", Expected: RevisionToken{}})
	if err != nil || second.JobID != first.JobID {
		t.Fatalf("duplicate=%#v err=%v", second, err)
	}
	if _, err := authority.conn.ExecContext(ctx, `UPDATE scheduled_occurrences SET target_digest='changed' WHERE job_id=?`, first.JobID); err == nil {
		t.Fatal("occurrence mutation accepted")
	}
}

func TestOccurrenceTransitionsAttemptsAndLeaseFailClosed(t *testing.T) {
	ctx := context.Background()
	authority := openTestStore(t)
	repository := NewScheduleRepository(authority)
	policy := scheduledPolicyFixture()
	attribution := audit.Attribution{AuthenticatedPrincipalID: "human-a", AuthenticatedPrincipalMethod: "local-os-peer"}
	draft, _ := repository.StageDraft(ctx, policy, attribution)
	_, _ = repository.Activate(ctx, ScheduleActivationRequest{DraftID: draft.DraftID, AuthorizationBranch: "human", ExecutingOperation: "schedule.policy.activate", PlanID: policy.ApprovalPlanID, PlanDigest: policy.ApprovalPlanDigest, AcknowledgementID: "ack-a", Expected: RevisionToken{}, Attribution: attribution})
	job, err := repository.ClaimOccurrence(ctx, OccurrenceClaim{Policy: policy, ScheduledAt: time.Date(2026, 9, 16, 1, 0, 0, 0, time.UTC), OccurrenceToken: "token-a", TargetDigest: policy.RetentionRuleDigest, IdempotencyKey: "key-a", Expected: RevisionToken{}})
	if err != nil {
		t.Fatal(err)
	}
	if err := repository.AppendAttempt(ctx, ScheduledAttempt{JobID: job.JobID, Attempt: 1, Status: "queued"}); err != nil {
		t.Fatal(err)
	}
	if err := repository.AcquireOccurrenceLease(ctx, job.JobID, "lease-a", "runner-a", time.Now().Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := repository.AcquireOccurrenceLease(ctx, job.JobID, "lease-b", "runner-b", time.Now().Add(time.Minute)); Code(err) != generated.ErrorCodeStateConflict {
		t.Fatalf("overlap err=%v", err)
	}
	running, err := repository.TransitionOccurrence(ctx, job.JobID, "queued", "running", "attempt-started", nil, nil)
	if err != nil || running.Status != "running" {
		t.Fatalf("running=%#v err=%v", running, err)
	}
	uncertain, err := repository.TransitionOccurrence(ctx, job.JobID, "running", "uncertain", "effect-unknown", nil, nil)
	if err != nil || uncertain.Status != "uncertain" {
		t.Fatalf("uncertain=%#v err=%v", uncertain, err)
	}
	if _, err := repository.TransitionOccurrence(ctx, job.JobID, "uncertain", "running", "retry", nil, nil); err == nil {
		t.Fatal("uncertain effect retried")
	}
}
