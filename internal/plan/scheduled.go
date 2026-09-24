package plan

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/vegastack/vegastack-labs/internal/authorization"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/schedule"
	"github.com/vegastack/vegastack-labs/internal/store"
)

type ScheduledRequest struct {
	Policy                                                        generated.ScheduledJobPolicy
	PolicyDigest, JobID, OccurrenceDigest, ObservationFingerprint string
	Attempt                                                       int64
	ScheduledAt, WindowClosesAt                                   time.Time
	Expected                                                      store.RevisionToken
}

type OperationalPlanRepository interface {
	CommitOperationalPlan(context.Context, store.OperationalPlanCommitRequest) (store.PlanCommitResult, error)
}
type ScheduledService struct {
	repository                               OperationalPlanRepository
	clock                                    func() time.Time
	toolVersion, contractVersion, executorID string
}

func NewScheduledService(repository OperationalPlanRepository, clock func() time.Time, toolVersion, contractVersion, executorID string) (*ScheduledService, error) {
	if repository == nil || toolVersion == "" || contractVersion == "" || executorID == "" {
		return nil, planError(generated.ErrorCodeInputInvalid)
	}
	if clock == nil {
		clock = time.Now
	}
	return &ScheduledService{repository: repository, clock: clock, toolVersion: toolVersion, contractVersion: contractVersion, executorID: executorID}, nil
}

func (service *ScheduledService) CreateScheduled(ctx context.Context, request ScheduledRequest) (store.PlanCommitResult, error) {
	if service == nil || request.JobID == "" || request.Attempt <= 0 || request.PolicyDigest == "" || request.OccurrenceDigest == "" || request.ObservationFingerprint == "" || request.Expected.StateRevision <= 0 {
		return store.PlanCommitResult{}, planError(generated.ErrorCodeInputInvalid)
	}
	if _, digest, err := schedule.CanonicalPolicy(request.Policy); err != nil || digest != request.PolicyDigest {
		return store.PlanCommitResult{}, planError(generated.ErrorCodeAuthorizationDenied)
	}
	created := service.clock().UTC().Truncate(time.Second)
	expires := created.Add(time.Duration(generated.PlanValiditySeconds) * time.Second)
	if request.WindowClosesAt.UTC().Before(expires) || created.Before(request.ScheduledAt.UTC()) {
		return store.PlanCommitResult{}, planError(generated.ErrorCodePlanStale)
	}
	action, err := schedule.BuildAction(request.Policy)
	if err != nil {
		return store.PlanCommitResult{}, planError(generated.ErrorCodeAuthorizationDenied)
	}
	operations := make([]generated.PlanOperation, len(action.TargetIDs))
	for index, target := range action.TargetIDs {
		operations[index] = generated.PlanOperation{Sequence: int64(index + 1), OperationID: fmt.Sprintf("%s-operation-%d", request.JobID, index+1), OperationType: action.OperationType, AdapterID: action.AdapterID, ExecutorID: service.executorID, TargetID: target, InputDigest: request.PolicyDigest, ArtifactDigest: request.Policy.RetentionRuleDigest, Idempotent: true}
	}
	targets, err := targetDigest(operations)
	if err != nil {
		return store.PlanCommitResult{}, planError(generated.ErrorCodeInputInvalid)
	}
	plan := generated.Plan{Schema: generated.SchemaIDPlan, SchemaVersion: "1.0.0", DeclarationID: request.Policy.DeclarationID, Binding: generated.PlanBinding{RecoveryEpoch: request.Expected.RecoveryEpoch, PriorStateRevision: request.Expected.StateRevision, StateRevision: request.Expected.StateRevision, DeclarationRevision: request.Policy.DeclarationRevision, ObservationFingerprint: request.ObservationFingerprint, TargetDigest: targets, ReasonDigest: request.PolicyDigest, PolicyVersion: request.Policy.PolicyVersion, ToolVersion: service.toolVersion, ContractVersion: service.contractVersion}, Operations: operations, Status: "planned", Risk: string(authorization.RiskRoutine), AuthorizationBranch: "preauthorized", ExecutorMode: "central", CreatedAt: created.Format(time.RFC3339), ExpiresAt: expires.Format(time.RFC3339), Extensions: []generated.ContractExtension{{Name: "x-scheduled-occurrence", ValueDigest: request.OccurrenceDigest}, {Name: "x-scheduled-policy", ValueDigest: request.PolicyDigest}}}
	readable := readablePlan(plan)
	plan.ReadableDigest = sha([]byte(readable))
	plan.PlanDigest, err = planDigest(plan)
	if err != nil {
		return store.PlanCommitResult{}, planError(generated.ErrorCodeInputInvalid)
	}
	plan.PlanID = "plan-" + strings.TrimPrefix(plan.PlanDigest, "sha256:")[:32]
	canonical, err := canonicalPlan(plan)
	if err != nil || generated.ValidateContractJSON(generated.SchemaIDPlan, canonical, generated.ContractExact) != nil || generated.ValidatePlanTiming(plan) != nil {
		return store.PlanCommitResult{}, planError(generated.ErrorCodeInputInvalid)
	}
	requestBytes, _ := json.Marshal(struct {
		JobID, OccurrenceDigest string
		Attempt                 int64
	}{request.JobID, request.OccurrenceDigest, request.Attempt})
	return service.repository.CommitOperationalPlan(ctx, store.OperationalPlanCommitRequest{Plan: plan, CanonicalBytes: canonical, Readable: readable, KeyDigest: sha([]byte(fmt.Sprintf("%s/%d", request.JobID, request.Attempt))), RequestDigest: sha(requestBytes), Expected: request.Expected})
}

func (service *ScheduledService) CreateScheduledPlan(ctx context.Context, request schedule.PlanRequest) (generated.Plan, error) {
	result, err := service.CreateScheduled(ctx, ScheduledRequest{Policy: request.Policy, PolicyDigest: request.PolicyDigest, JobID: request.JobID, OccurrenceDigest: request.OccurrenceDigest, ObservationFingerprint: request.ObservationFingerprint, Attempt: request.Attempt, ScheduledAt: request.ScheduledAt, WindowClosesAt: request.WindowClosesAt, Expected: store.RevisionToken{StateRevision: request.Expected.StateRevision, RecoveryEpoch: request.Expected.RecoveryEpoch}})
	return result.Plan, err
}
