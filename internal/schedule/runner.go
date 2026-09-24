package schedule

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/vegastack/vegastack-labs/internal/audit"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/runprotocol"
	"github.com/vegastack/vegastack-labs/internal/stateexport"
)

type PlanRequest struct {
	Policy                                                        generated.ScheduledJobPolicy
	PolicyDigest, JobID, OccurrenceDigest, ObservationFingerprint string
	Attempt                                                       int64
	ScheduledAt, WindowClosesAt                                   time.Time
	Expected                                                      Revision
}
type PlanCreator interface {
	CreateScheduledPlan(context.Context, PlanRequest) (generated.Plan, error)
}
type ScheduledAuthorizer interface {
	AuthorizeScheduled(context.Context, string, generated.Plan) (generated.AuthorizationDecision, error)
}
type RunSubmitter interface {
	SubmitScheduled(context.Context, generated.Plan, generated.AuthorizationDecision, string, audit.Attribution) (generated.Run, error)
}
type ObservationReader interface {
	CurrentObservationFingerprint(context.Context, generated.ScheduledJobPolicy) (string, error)
}
type PrerequisiteReader interface {
	Current(context.Context, []PrerequisiteRequirement) ([]PrerequisiteStatus, error)
}
type AttemptRecord struct {
	Attempt    int64
	RecordedAt time.Time
}
type RuntimeRepository interface {
	GetActivePolicy(context.Context, string) (generated.ScheduledJobPolicy, error)
	CurrentScheduleRevision(context.Context) (Revision, error)
	AppendScheduledAttempt(context.Context, string, int64, string, string, string, bool, time.Time) error
	TransitionScheduledOccurrence(context.Context, string, string, string, string, *string, *string) (generated.ScheduledJob, error)
	AcquireOccurrenceLease(context.Context, string, string, string, time.Time) error
	ReleaseOccurrenceLease(context.Context, string, string) error
	ListRecoverableOccurrences(context.Context) ([]generated.ScheduledJob, error)
	LatestScheduledAttempt(context.Context, string) (AttemptRecord, bool, error)
	ReleaseExpiredOccurrenceLeases(context.Context, time.Time) error
}

type Runner struct {
	repository    RuntimeRepository
	plans         PlanCreator
	authorizer    ScheduledAuthorizer
	runs          RunSubmitter
	observations  ObservationReader
	prerequisites PrerequisiteReader
	clock         func() time.Time
	principalID   string
}

func NewRunner(repository RuntimeRepository, plans PlanCreator, authorizer ScheduledAuthorizer, runs RunSubmitter, observations ObservationReader, prerequisites PrerequisiteReader, clock func() time.Time, principalID string) (*Runner, error) {
	if repository == nil || plans == nil || authorizer == nil || runs == nil || observations == nil || prerequisites == nil || principalID == "" {
		return nil, fmt.Errorf("invalid scheduled runner")
	}
	if clock == nil {
		clock = time.Now
	}
	return &Runner{repository: repository, plans: plans, authorizer: authorizer, runs: runs, observations: observations, prerequisites: prerequisites, clock: clock, principalID: principalID}, nil
}

func (runner *Runner) Run(ctx context.Context, job generated.ScheduledJob, attribution audit.Attribution) (generated.ScheduledJob, error) {
	if runner == nil || (job.Status != "queued" && job.Status != "retry-wait") || job.Attempt <= 0 {
		return generated.ScheduledJob{}, fmt.Errorf("invalid scheduled job")
	}
	policy, err := runner.repository.GetActivePolicy(ctx, job.PolicyID)
	if err != nil {
		return job, err
	}
	if generated.ValidateScheduledJobBinding(policy, job) != nil {
		return runner.block(ctx, job, "policy-binding-stale")
	}
	if attribution.AuthenticatedPrincipalID == "" || attribution.AuthenticatedPrincipalMethod == "" {
		return runner.block(ctx, job, "runner-principal-missing")
	}
	attribution.ResponsibleHumanPrincipalID = &policy.ApprovedByHumanID
	now := runner.clock().UTC().Truncate(time.Second)
	fromStatus, attempt := job.Status, job.Attempt
	if job.Status == "retry-wait" {
		previous, found, latestErr := runner.repository.LatestScheduledAttempt(ctx, job.JobID)
		if latestErr != nil {
			return job, latestErr
		}
		if !found || now.Before(previous.RecordedAt.Add(Backoff(policy, previous.Attempt))) {
			return job, nil
		}
		attempt = previous.Attempt + 1
		job.Attempt = attempt
	}
	scheduledAt, err := time.Parse(time.RFC3339, job.ScheduledAt)
	if err != nil {
		return runner.block(ctx, job, "scheduled-at-invalid")
	}
	windowCloses := scheduledAt.Add(time.Duration(policy.WindowSeconds) * time.Second)
	if policy.CatchUp == "latest" && !now.Before(windowCloses) {
		windowCloses = now.Add(time.Duration(policy.WindowSeconds) * time.Second)
	}
	if !now.Before(windowCloses) {
		return runner.block(ctx, job, "window-closed")
	}
	revision, err := runner.repository.CurrentScheduleRevision(ctx)
	if err != nil {
		return job, err
	}
	if revision != (Revision{StateRevision: policy.StateRevision, RecoveryEpoch: policy.RecoveryEpoch}) {
		return runner.block(ctx, job, "revision-or-epoch-stale")
	}
	leaseID := fmt.Sprintf("%s-lease-%d", job.JobID, job.Attempt)
	if err := runner.repository.AcquireOccurrenceLease(ctx, job.JobID, leaseID, "schedule:"+policy.PolicyID, windowCloses); err != nil {
		return runner.block(ctx, job, "overlap")
	}
	defer func() { _ = runner.repository.ReleaseOccurrenceLease(context.WithoutCancel(ctx), job.JobID, leaseID) }()
	requirements := Requirements(policy)
	statuses, err := runner.prerequisites.Current(ctx, requirements)
	if err != nil {
		return runner.block(ctx, job, "prerequisite-unavailable")
	}
	if RequireCurrent(statuses, now) != nil {
		return runner.block(ctx, job, "prerequisite-blocked")
	}
	observation, err := runner.observations.CurrentObservationFingerprint(ctx, policy)
	if err != nil || observation == "" {
		return runner.block(ctx, job, "observation-unavailable")
	}
	_, policyDigest, err := CanonicalPolicy(policy)
	if err != nil {
		return runner.block(ctx, job, "policy-invalid")
	}
	jobBytes, _, err := stateexport.CanonicalJSON(job)
	if err != nil {
		return runner.block(ctx, job, "occurrence-invalid")
	}
	occurrenceDigest := scheduleBytesDigest(jobBytes)
	plan, err := runner.plans.CreateScheduledPlan(ctx, PlanRequest{Policy: policy, PolicyDigest: policyDigest, JobID: job.JobID, OccurrenceDigest: occurrenceDigest, ObservationFingerprint: observation, Attempt: attempt, ScheduledAt: scheduledAt, WindowClosesAt: windowCloses, Expected: revision})
	if err != nil {
		return runner.block(ctx, job, "plan-create-failed")
	}
	decision, err := runner.authorizer.AuthorizeScheduled(ctx, attribution.AuthenticatedPrincipalID, plan)
	if err != nil || !decision.Allowed || decision.Branch == nil || *decision.Branch != "preauthorized" || decision.GrantRevision != policy.GrantRevision || decision.RecoveryEpoch != policy.RecoveryEpoch {
		return runner.block(ctx, job, "authorization-denied")
	}
	submitKey := fmt.Sprintf("%s-attempt-%d", job.JobID, attempt)
	runID := runprotocol.ID(plan.PlanID, submitKey)
	if err := runner.repository.AppendScheduledAttempt(ctx, job.JobID, attempt, "running", plan.PlanID, runID, false, now); err != nil {
		return job, err
	}
	running, err := runner.repository.TransitionScheduledOccurrence(ctx, job.JobID, fromStatus, "running", "attempt-started", &plan.PlanID, &runID)
	if err != nil {
		return job, err
	}
	runResult, submitErr := runner.runs.SubmitScheduled(context.WithoutCancel(ctx), plan, decision, submitKey, attribution)
	if submitErr != nil || runResult.Status == "uncertain" || hasUncertainEffect(runResult) {
		return runner.repository.TransitionScheduledOccurrence(context.WithoutCancel(ctx), job.JobID, "running", "uncertain", "effect-unknown", &plan.PlanID, &runID)
	}
	if runResult.Status == "succeeded" {
		return runner.repository.TransitionScheduledOccurrence(context.WithoutCancel(ctx), job.JobID, "running", "succeeded", "verified", &plan.PlanID, &runID)
	}
	if runResult.Status == "failed" && allNotStarted(runResult) {
		if job.Attempt < policy.MaxAttempts && now.Add(Backoff(policy, job.Attempt)).Before(windowCloses) {
			return runner.repository.TransitionScheduledOccurrence(context.WithoutCancel(ctx), job.JobID, "running", "retry-wait", "failed-before-effect", &plan.PlanID, &runID)
		}
		return runner.repository.TransitionScheduledOccurrence(context.WithoutCancel(ctx), job.JobID, "running", "failed", "retry-exhausted", &plan.PlanID, &runID)
	}
	_ = running
	return runner.repository.TransitionScheduledOccurrence(context.WithoutCancel(ctx), job.JobID, "running", "uncertain", "non-terminal-run", &plan.PlanID, &runID)
}

func (runner *Runner) Startup(ctx context.Context) error {
	now := runner.clock().UTC().Truncate(time.Second)
	if err := runner.repository.ReleaseExpiredOccurrenceLeases(ctx, now); err != nil {
		return err
	}
	jobs, err := runner.repository.ListRecoverableOccurrences(ctx)
	if err != nil {
		return err
	}
	for _, job := range jobs {
		if job.Status == "running" {
			if _, err = runner.repository.TransitionScheduledOccurrence(ctx, job.JobID, "running", "uncertain", "restart-after-start", job.PlanID, job.RunID); err != nil {
				return err
			}
			continue
		}
		if _, err = runner.Run(ctx, job, audit.Attribution{AuthenticatedPrincipalID: runner.principalID, AuthenticatedPrincipalMethod: "local-os-peer"}); err != nil {
			return err
		}
	}
	return nil
}

func (runner *Runner) block(ctx context.Context, job generated.ScheduledJob, reason string) (generated.ScheduledJob, error) {
	if job.Status == "retry-wait" {
		return runner.repository.TransitionScheduledOccurrence(ctx, job.JobID, "retry-wait", "failed", reason, job.PlanID, job.RunID)
	}
	return runner.repository.TransitionScheduledOccurrence(ctx, job.JobID, "queued", "blocked", reason, nil, nil)
}
func scheduleBytesDigest(value []byte) string {
	_, sum, _ := stateexport.CanonicalJSON(struct {
		Bytes json.RawMessage `json:"bytes"`
	}{value})
	return "sha256:" + hex.EncodeToString(sum[:])
}
func hasUncertainEffect(run generated.Run) bool {
	for _, step := range run.Steps {
		if step.EffectState == "intent-recorded" || step.EffectState == "effect-unknown" || step.EffectState == "receipt-recorded" {
			return true
		}
	}
	return false
}
func allNotStarted(run generated.Run) bool {
	if len(run.Steps) == 0 {
		return false
	}
	for _, step := range run.Steps {
		if step.EffectState != "not-started" {
			return false
		}
	}
	return true
}

func Requirements(policy generated.ScheduledJobPolicy) []PrerequisiteRequirement {
	maximum := policy.IntervalSeconds * 2
	requirements := []PrerequisiteRequirement{{Kind: "recovery-authority", SubjectID: policy.ExactSubjectIDs[0], PolicyID: policy.PolicyID, PolicyRevision: policy.Revision, RecoveryEpoch: policy.RecoveryEpoch, MaximumAgeSeconds: maximum}}
	switch policy.ActionKind {
	case "gate-check":
		requirements = append(requirements, PrerequisiteRequirement{Kind: "applicable-gate-current", SubjectID: policy.ExactSubjectIDs[0], PolicyID: policy.PolicyID, PolicyRevision: policy.Revision, RecoveryEpoch: policy.RecoveryEpoch, MaximumAgeSeconds: maximum})
	case "observation-refresh":
		requirements = append(requirements, PrerequisiteRequirement{Kind: "observation-authority-current", SubjectID: policy.ExactSubjectIDs[0], PolicyID: policy.PolicyID, PolicyRevision: policy.Revision, RecoveryEpoch: policy.RecoveryEpoch, MaximumAgeSeconds: maximum})
	case "backup-create", "backup-integrity-verify":
		requirements = append(requirements, PrerequisiteRequirement{Kind: "local-backup-qualification", SubjectID: policy.ExactSubjectIDs[0], PolicyID: policy.PolicyID, PolicyRevision: policy.Revision, RecoveryEpoch: policy.RecoveryEpoch, MaximumAgeSeconds: maximum}, PrerequisiteRequirement{Kind: "retirement-certainty", SubjectID: policy.ExactSubjectIDs[0], PolicyID: policy.PolicyID, PolicyRevision: policy.Revision, RecoveryEpoch: policy.RecoveryEpoch, MaximumAgeSeconds: maximum})
	case "audit-checkpoint-export":
		requirements = append(requirements, PrerequisiteRequirement{Kind: "audit-chain-current", SubjectID: policy.ExactSubjectIDs[0], PolicyID: policy.PolicyID, PolicyRevision: policy.Revision, RecoveryEpoch: policy.RecoveryEpoch, MaximumAgeSeconds: maximum})
	}
	return requirements
}
