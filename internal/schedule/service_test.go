package schedule

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/vegastack/vegastack-labs/internal/generated"
)

type memoryRepository struct {
	policy   generated.ScheduledJobPolicy
	revision Revision
	jobs     map[string]generated.ScheduledJob
	windows  map[string]time.Time
}

func (m *memoryRepository) GetActivePolicy(context.Context, string) (generated.ScheduledJobPolicy, error) {
	return m.policy, nil
}
func (m *memoryRepository) GetActivePolicyApprover(context.Context, string, int64) (string, error) {
	return "human-a", nil
}
func (m *memoryRepository) CurrentScheduleRevision(context.Context) (Revision, error) {
	return m.revision, nil
}
func (m *memoryRepository) ClaimScheduledOccurrence(_ context.Context, p generated.ScheduledJobPolicy, s Slot, _, _, _ string, _ Revision) (generated.ScheduledJob, error) {
	key := fmt.Sprintf("%s/%d/%s", p.PolicyID, p.Revision, s.ScheduledAt.Format(time.RFC3339))
	if job, ok := m.jobs[key]; ok {
		return job, nil
	}
	job := generated.ScheduledJob{Schema: generated.SchemaIDScheduledJob, SchemaVersion: "1.1.0", JobID: "job-" + s.ScheduledAt.Format("150405"), PolicyID: p.PolicyID, PolicyRevision: p.Revision, ScheduledAt: s.ScheduledAt.Format(time.RFC3339), Attempt: 1, Status: "queued", ReasonCode: "due", RecoveryEpoch: p.RecoveryEpoch}
	m.jobs[key] = job
	if m.windows == nil {
		m.windows = map[string]time.Time{}
	}
	m.windows[key] = s.WindowClosesAt
	return job, nil
}
func (m *memoryRepository) TransitionScheduledOccurrence(_ context.Context, id, from, to, reason string, _, _ *string) (generated.ScheduledJob, error) {
	for key, job := range m.jobs {
		if job.JobID == id {
			if job.Status != from {
				return job, fmt.Errorf("conflict")
			}
			job.Status = to
			job.ReasonCode = reason
			m.jobs[key] = job
			return job, nil
		}
	}
	return generated.ScheduledJob{}, fmt.Errorf("missing")
}
func (m *memoryRepository) GetOccurrence(_ context.Context, id string) (generated.ScheduledJob, error) {
	for _, job := range m.jobs {
		if job.JobID == id {
			return job, nil
		}
	}
	return generated.ScheduledJob{}, fmt.Errorf("missing")
}

func TestDispatchUsesServerClockAndOneDurableSlot(t *testing.T) {
	policy := validPolicy()
	now := time.Date(2026, 9, 16, 1, 10, 0, 0, time.UTC)
	repository := &memoryRepository{policy: policy, revision: Revision{StateRevision: policy.StateRevision, RecoveryEpoch: policy.RecoveryEpoch}, jobs: map[string]generated.ScheduledJob{}}
	service, err := NewService(repository, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	target, err := ExactTargetDigest(policy)
	if err != nil {
		t.Fatal(err)
	}
	request := DispatchRequest{PolicyID: policy.PolicyID, PolicyRevision: policy.Revision, OccurrenceToken: "token-a", ObservedAt: now, ExpectedStateRevision: policy.StateRevision, RecoveryEpoch: policy.RecoveryEpoch, TargetDigest: target, IdempotencyKey: "key-a"}
	first, err := service.Dispatch(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	request.OccurrenceToken = "token-b"
	request.IdempotencyKey = "key-b"
	second, err := service.Dispatch(context.Background(), request)
	if err != nil || first.JobID != second.JobID {
		t.Fatalf("jobs=%#v %#v err=%v", first, second, err)
	}
	request.ObservedAt = now.Add(-time.Minute)
	if _, err := service.Dispatch(context.Background(), request); err == nil {
		t.Fatal("caller-controlled clock accepted")
	}
}

func TestDispatchBlocksRevisionEpochAndTargetWidening(t *testing.T) {
	policy := validPolicy()
	now := time.Date(2026, 9, 16, 1, 10, 0, 0, time.UTC)
	repository := &memoryRepository{policy: policy, revision: Revision{StateRevision: policy.StateRevision, RecoveryEpoch: policy.RecoveryEpoch}, jobs: map[string]generated.ScheduledJob{}}
	service, _ := NewService(repository, func() time.Time { return now })
	target, _ := ExactTargetDigest(policy)
	base := DispatchRequest{PolicyID: policy.PolicyID, PolicyRevision: policy.Revision, OccurrenceToken: "token-a", ObservedAt: now, ExpectedStateRevision: policy.StateRevision, RecoveryEpoch: policy.RecoveryEpoch, TargetDigest: target, IdempotencyKey: "key-a"}
	changed := base
	changed.TargetDigest = "sha256:" + fmt.Sprintf("%064d", 1)
	if _, err := service.Dispatch(context.Background(), changed); err == nil {
		t.Fatal("widened target accepted")
	}
	changed = base
	changed.RecoveryEpoch++
	if _, err := service.Dispatch(context.Background(), changed); err == nil {
		t.Fatal("wrong recovery epoch accepted")
	}
}

func TestCancelOnlyStopsOccurrenceBeforeEffect(t *testing.T) {
	policy := validPolicy()
	repository := &memoryRepository{policy: policy, revision: Revision{StateRevision: policy.StateRevision, RecoveryEpoch: policy.RecoveryEpoch}, jobs: map[string]generated.ScheduledJob{"slot": {JobID: "job-a", Status: "queued"}}}
	service, _ := NewService(repository, time.Now)
	job, err := service.Cancel(context.Background(), "job-a")
	if err != nil || job.Status != "cancelled" {
		t.Fatalf("cancel=%#v err=%v", job, err)
	}
	repository.jobs["slot"] = generated.ScheduledJob{JobID: "job-a", Status: "running"}
	if _, err := service.Cancel(context.Background(), "job-a"); err == nil {
		t.Fatal("running effect cancelled through occurrence path")
	}
}

func TestCatchUpWindowIsFixedWhenOccurrenceIsClaimed(t *testing.T) {
	policy := validPolicy()
	now := time.Date(2026, 9, 16, 1, 45, 0, 0, time.UTC)
	repository := &memoryRepository{policy: policy, revision: Revision{policy.StateRevision, policy.RecoveryEpoch}, jobs: map[string]generated.ScheduledJob{}, windows: map[string]time.Time{}}
	service, _ := NewService(repository, func() time.Time { return now })
	target, _ := ExactTargetDigest(policy)
	request := DispatchRequest{PolicyID: policy.PolicyID, PolicyRevision: policy.Revision, OccurrenceToken: "token-a", ObservedAt: now, ExpectedStateRevision: policy.StateRevision, RecoveryEpoch: policy.RecoveryEpoch, TargetDigest: target, IdempotencyKey: "key-a"}
	first, err := service.Dispatch(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	key := fmt.Sprintf("%s/%d/%s", policy.PolicyID, policy.Revision, time.Date(2026, 9, 16, 1, 0, 0, 0, time.UTC).Format(time.RFC3339))
	want := now.Add(time.Duration(policy.WindowSeconds) * time.Second)
	if !repository.windows[key].Equal(want) {
		t.Fatalf("window=%s want=%s", repository.windows[key], want)
	}
	now = now.Add(5 * time.Minute)
	request.ObservedAt = now
	request.OccurrenceToken = "token-b"
	request.IdempotencyKey = "key-b"
	second, err := service.Dispatch(context.Background(), request)
	if err != nil || second.JobID != first.JobID || !repository.windows[key].Equal(want) {
		t.Fatalf("duplicate reopened catch-up window: first=%#v second=%#v window=%s err=%v", first, second, repository.windows[key], err)
	}
}
