package schedule

import (
	"context"
	"testing"
	"time"

	"github.com/vegastack/vegastack-labs/internal/audit"
	"github.com/vegastack/vegastack-labs/internal/generated"
)

type runnerRepository struct {
	policy   generated.ScheduledJobPolicy
	revision Revision
	window   time.Time
	job      generated.ScheduledJob
	attempts int
	leased   bool
}

func (r *runnerRepository) GetActivePolicy(context.Context, string) (generated.ScheduledJobPolicy, error) {
	return r.policy, nil
}
func (r *runnerRepository) GetActivePolicyApprover(context.Context, string, int64) (string, error) {
	return "human-a", nil
}
func (r *runnerRepository) CurrentScheduleRevision(context.Context) (Revision, error) {
	return r.revision, nil
}
func (r *runnerRepository) AppendScheduledAttempt(_ context.Context, _ string, _ int64, _ string, _ string, _ string, _ bool, _ time.Time) error {
	r.attempts++
	return nil
}
func (r *runnerRepository) TransitionScheduledOccurrence(_ context.Context, _ string, _ string, to, reason string, planID, runID *string) (generated.ScheduledJob, error) {
	r.job.Status, r.job.ReasonCode, r.job.PlanID, r.job.RunID = to, reason, planID, runID
	return r.job, nil
}
func (r *runnerRepository) AcquireOccurrenceLease(context.Context, string, string, string, time.Time) error {
	r.leased = true
	return nil
}
func (r *runnerRepository) ReleaseOccurrenceLease(context.Context, string, string) error {
	r.leased = false
	return nil
}
func (r *runnerRepository) ListRecoverableOccurrences(context.Context) ([]generated.ScheduledJob, error) {
	return []generated.ScheduledJob{r.job}, nil
}
func (r *runnerRepository) LatestScheduledAttempt(context.Context, string) (AttemptRecord, bool, error) {
	return AttemptRecord{}, false, nil
}
func (r *runnerRepository) ReleaseExpiredOccurrenceLeases(context.Context, time.Time) error {
	return nil
}
func (r *runnerRepository) ScheduledOccurrenceWindowClosesAt(context.Context, string) (time.Time, error) {
	return r.window, nil
}
func (r *runnerRepository) ScheduledOccurrenceDigest(context.Context, string) (string, error) {
	return digestForTest("occurrence"), nil
}

type runnerPlans struct{ plan generated.Plan }

func (p runnerPlans) CreateScheduledPlan(context.Context, PlanRequest) (generated.Plan, error) {
	return p.plan, nil
}

type runnerAuthorization struct{}

func (runnerAuthorization) AuthorizeScheduled(_ context.Context, principal string, plan generated.Plan) (generated.AuthorizationDecision, error) {
	branch := "preauthorized"
	return generated.AuthorizationDecision{Allowed: true, Branch: &branch, GrantRevision: 3, RecoveryEpoch: plan.Binding.RecoveryEpoch, PlanDigest: plan.PlanDigest}, nil
}

type runnerRuns struct{ run generated.Run }

func (r runnerRuns) SubmitScheduled(context.Context, generated.Plan, generated.AuthorizationDecision, string, audit.Attribution) (generated.Run, error) {
	return r.run, nil
}
func (r runnerRuns) GetScheduledRun(context.Context, string) (generated.Run, error) {
	return r.run, nil
}

type runnerObservation struct{}

func (runnerObservation) CurrentObservationFingerprint(context.Context, generated.ScheduledJobPolicy) (string, error) {
	return digestForTest("observation"), nil
}

type runnerPrerequisites struct{}

func (runnerPrerequisites) Current(_ context.Context, requirements []PrerequisiteRequirement) ([]PrerequisiteStatus, error) {
	out := make([]PrerequisiteStatus, len(requirements))
	now := time.Date(2026, 9, 24, 0, 0, 0, 0, time.UTC)
	for i, v := range requirements {
		out[i] = PrerequisiteStatus{Requirement: v, State: "current", ObservedAt: now, RecoveryEpoch: v.RecoveryEpoch}
	}
	return out, nil
}

func TestRunnerExecutesOneExactOccurrenceAndSettlesVerified(t *testing.T) {
	now := time.Date(2026, 9, 24, 0, 0, 0, 0, time.UTC)
	policy := validPolicy()
	policy.StateRevision = 4
	policy.GrantRevision = 3
	policy.ActionKind = "gate-check"
	policy.OperationType = "schedule.gate.check"
	policy.AdapterID = "core.schedule-observe"
	policy.CredentialReferenceIDs = []string{}
	policy.AnchorAt = now.Format(time.RFC3339)
	policy.ExpiresAt = now.Add(time.Hour).Format(time.RFC3339)
	job := generated.ScheduledJob{Schema: generated.SchemaIDScheduledJob, SchemaVersion: "1.1.0", JobID: "job-a", PolicyID: policy.PolicyID, PolicyRevision: policy.Revision, ScheduledAt: now.Format(time.RFC3339), Attempt: 1, Status: "queued", ReasonCode: "due", RecoveryEpoch: policy.RecoveryEpoch}
	operation := generated.PlanOperation{Sequence: 1, OperationID: "operation-a", OperationType: policy.OperationType, AdapterID: policy.AdapterID, ExecutorID: "executor-central", TargetID: policy.ExactTargetIDs[0], InputDigest: policy.RetentionRuleDigest, ArtifactDigest: policy.RetentionRuleDigest, Idempotent: true}
	plan := generated.Plan{PlanID: "plan-a", PlanDigest: digestForTest("plan"), AuthorizationBranch: "preauthorized", ExecutorMode: "central", Binding: generated.PlanBinding{StateRevision: 4, RecoveryEpoch: policy.RecoveryEpoch}, Operations: []generated.PlanOperation{operation}}
	completed := generated.Run{RunID: "run-a", Status: "succeeded", Steps: []generated.RunStep{{EffectState: "verified"}}}
	repository := &runnerRepository{policy: policy, revision: Revision{4, policy.RecoveryEpoch}, window: now.Add(30 * time.Minute), job: job}
	runner, err := NewRunner(repository, runnerPlans{plan}, runnerAuthorization{}, runnerRuns{completed}, runnerObservation{}, runnerPrerequisites{}, func() time.Time { return now }, "runner-a")
	if err != nil {
		t.Fatal(err)
	}
	settled, err := runner.Run(context.Background(), job, audit.Attribution{AuthenticatedPrincipalID: "runner-a", AuthenticatedPrincipalMethod: "local-os-peer"})
	if err != nil || settled.Status != "succeeded" || repository.attempts != 1 || repository.leased {
		t.Fatalf("settled=%#v attempts=%d leased=%v err=%v", settled, repository.attempts, repository.leased, err)
	}
}

func digestForTest(value string) string {
	const h = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	return "sha256:" + h
}
