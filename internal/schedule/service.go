package schedule

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/vegastack/vegastack-labs/internal/failure"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/stateexport"
)

type Revision struct{ StateRevision, RecoveryEpoch int64 }

type Repository interface {
	GetActivePolicy(context.Context, string) (generated.ScheduledJobPolicy, error)
	CurrentScheduleRevision(context.Context) (Revision, error)
	ClaimScheduledOccurrence(context.Context, generated.ScheduledJobPolicy, Slot, string, string, string, Revision) (generated.ScheduledJob, error)
	TransitionScheduledOccurrence(context.Context, string, string, string, string, *string, *string) (generated.ScheduledJob, error)
}

type occurrenceReader interface {
	GetOccurrence(context.Context, string) (generated.ScheduledJob, error)
}

type DispatchRequest struct {
	PolicyID, OccurrenceToken, TargetDigest, IdempotencyKey string
	PolicyRevision, ExpectedStateRevision, RecoveryEpoch    int64
	ObservedAt                                              time.Time
}

type Service struct {
	repository Repository
	clock      func() time.Time
}

func NewService(repository Repository, clock func() time.Time) (*Service, error) {
	if repository == nil {
		return nil, failure.New(generated.ErrorCodeInputInvalid, "schedule-service", false)
	}
	if clock == nil {
		clock = time.Now
	}
	return &Service{repository: repository, clock: clock}, nil
}

func ExactTargetDigest(policy generated.ScheduledJobPolicy) (string, error) {
	value := struct{ SourceIDs, SubjectIDs, TargetIDs []string }{policy.ExactSourceIDs, policy.ExactSubjectIDs, policy.ExactTargetIDs}
	_, sum, err := stateexport.CanonicalJSON(value)
	if err != nil {
		return "", err
	}
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func (service *Service) Dispatch(ctx context.Context, request DispatchRequest) (generated.ScheduledJob, error) {
	if service == nil || request.PolicyID == "" || request.PolicyRevision <= 0 || request.OccurrenceToken == "" || request.TargetDigest == "" || request.IdempotencyKey == "" || request.ObservedAt.IsZero() {
		return generated.ScheduledJob{}, failure.New(generated.ErrorCodeInputInvalid, "scheduled-dispatch", false)
	}
	now := service.clock().UTC().Truncate(time.Second)
	if request.ObservedAt.UTC().Truncate(time.Second) != now {
		return generated.ScheduledJob{}, failure.New(generated.ErrorCodeStateConflict, "scheduled-clock", false)
	}
	policy, err := service.repository.GetActivePolicy(ctx, request.PolicyID)
	if err != nil {
		return generated.ScheduledJob{}, err
	}
	if policy.Revision != request.PolicyRevision || !policy.Enabled {
		return generated.ScheduledJob{}, failure.New(generated.ErrorCodePlanStale, "scheduled-policy", false)
	}
	current, err := service.repository.CurrentScheduleRevision(ctx)
	if err != nil {
		return generated.ScheduledJob{}, err
	}
	if current != (Revision{StateRevision: request.ExpectedStateRevision, RecoveryEpoch: request.RecoveryEpoch}) || policy.StateRevision != current.StateRevision || policy.RecoveryEpoch != current.RecoveryEpoch {
		return generated.ScheduledJob{}, failure.New(generated.ErrorCodeRecoveryEpochMismatch, "scheduled-policy", false)
	}
	targetDigest, err := ExactTargetDigest(policy)
	if err != nil || targetDigest != request.TargetDigest {
		return generated.ScheduledJob{}, failure.New(generated.ErrorCodeAuthorizationDenied, "scheduled-target", false)
	}
	expires, err := time.Parse(time.RFC3339, policy.ExpiresAt)
	if err != nil || !now.Before(expires) {
		return generated.ScheduledJob{}, failure.New(generated.ErrorCodePlanStale, "scheduled-policy", false)
	}
	slot, dueErr := Due(policy, now)
	if dueErr != nil && !errors.Is(dueErr, ErrWindowMissed) {
		return generated.ScheduledJob{}, failure.New(generated.ErrorCodeStateConflict, "scheduled-slot", false)
	}
	job, err := service.repository.ClaimScheduledOccurrence(ctx, policy, slot, request.OccurrenceToken, targetDigest, request.IdempotencyKey, current)
	if err != nil {
		return generated.ScheduledJob{}, err
	}
	if errors.Is(dueErr, ErrWindowMissed) && job.Status == "queued" {
		return service.repository.TransitionScheduledOccurrence(ctx, job.JobID, "queued", "skipped", "window-missed", nil, nil)
	}
	return job, nil
}

// Cancel stops only work that has not begun. Running work must use the run
// cancellation path so an effect that may have started cannot be mislabeled.
func (service *Service) Cancel(ctx context.Context, jobID string) (generated.ScheduledJob, error) {
	if service == nil || jobID == "" {
		return generated.ScheduledJob{}, failure.New(generated.ErrorCodeInputInvalid, "scheduled-cancel", false)
	}
	reader, ok := service.repository.(occurrenceReader)
	if !ok {
		return generated.ScheduledJob{}, failure.New(generated.ErrorCodeInputInvalid, "scheduled-cancel", false)
	}
	job, err := reader.GetOccurrence(ctx, jobID)
	if err != nil {
		return job, err
	}
	if job.Status != "queued" && job.Status != "retry-wait" {
		return job, failure.New(generated.ErrorCodeStateConflict, "scheduled-cancel", false)
	}
	return service.repository.TransitionScheduledOccurrence(ctx, jobID, job.Status, "cancelled", "operator-cancelled", job.PlanID, job.RunID)
}

func DecodeRequest(raw []byte) (DispatchRequest, error) {
	var input generated.ScheduledJobRequest
	if json.Unmarshal(raw, &input) != nil || generated.ValidateContractJSON(generated.SchemaIDScheduledJobRequest, raw, generated.ContractExact) != nil {
		return DispatchRequest{}, failure.New(generated.ErrorCodeInputInvalid, "scheduled-request", false)
	}
	observed, err := time.Parse(time.RFC3339, input.ObservedAt)
	if err != nil {
		return DispatchRequest{}, failure.New(generated.ErrorCodeInputInvalid, "scheduled-request", false)
	}
	return DispatchRequest{PolicyID: input.PolicyID, PolicyRevision: input.PolicyRevision, OccurrenceToken: input.OccurrenceToken, ObservedAt: observed, ExpectedStateRevision: input.ExpectedStateRevision, RecoveryEpoch: input.RecoveryEpoch, TargetDigest: input.TargetDigest, IdempotencyKey: input.IdempotencyKey}, nil
}
