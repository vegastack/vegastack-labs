package run

import (
	"context"
	"strconv"
	"sync"
	"time"

	"github.com/vegastack/vegastack-labs/internal/adapter"
	"github.com/vegastack/vegastack-labs/internal/audit"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/store"
)

type memoryRepository struct {
	mu                    sync.Mutex
	plan                  generated.Plan
	runs                  map[string]generated.Run
	submits               map[string]string
	leases                map[string]generated.ExecutorLease
	targets               map[string]string
	receipts              map[string]generated.ExecutionReceipt
	releaseRunLeasesError error
}

func newMemoryRepository(plan generated.Plan) *memoryRepository {
	return &memoryRepository{plan: plan, runs: map[string]generated.Run{}, submits: map[string]string{}, leases: map[string]generated.ExecutorLease{}, targets: map[string]string{}, receipts: map[string]generated.ExecutionReceipt{}}
}

func (repository *memoryRepository) Get(_ context.Context, id string) (store.PlanCommitResult, error) {
	if id != repository.plan.PlanID {
		return store.PlanCommitResult{}, runError(generated.ErrorCodeResourceNotFound, "plan")
	}
	return store.PlanCommitResult{Plan: repository.plan}, nil
}
func (*memoryRepository) ValidateCurrent(context.Context, generated.Plan) error { return nil }

func (repository *memoryRepository) Create(_ context.Context, request store.RunCreateRequest) (store.RunCreateResult, error) {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	key := string(request.SubmitKeyDigest)
	if id, exists := repository.submits[key]; exists {
		existing := repository.runs[id]
		if id != request.Run.RunID {
			return store.RunCreateResult{}, runError(generated.ErrorCodeStateConflict, "run-submit")
		}
		return store.RunCreateResult{Run: existing, Created: false}, nil
	}
	repository.runs[request.Run.RunID] = cloneRun(request.Run)
	repository.submits[key] = request.Run.RunID
	return store.RunCreateResult{Run: cloneRun(request.Run), Created: true}, nil
}

func (repository *memoryRepository) GetRun(_ context.Context, id string) (generated.Run, error) {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	run, ok := repository.runs[id]
	if !ok {
		return generated.Run{}, runError(generated.ErrorCodeResourceNotFound, "run")
	}
	return cloneRun(run), nil
}

func (repository *memoryRepository) TransitionRun(_ context.Context, request store.RunTransitionRequest) (generated.Run, error) {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	run, ok := repository.runs[request.RunID]
	if !ok {
		return generated.Run{}, runError(generated.ErrorCodeResourceNotFound, "run")
	}
	if run.Status != request.From || generated.ValidateRunTransition(request.From, request.To) != nil {
		return run, runError(generated.ErrorCodeStateConflict, "run-transition")
	}
	if request.From == "interrupted" && request.To == "running" {
		for index := range run.Steps {
			if run.Steps[index].Status == "interrupted" {
				if !run.Steps[index].Idempotent || run.Steps[index].EffectState != "not-started" {
					return run, runError(generated.ErrorCodeRecoveryRequired, "run-resume")
				}
				run.Steps[index].Status = "queued"
			}
		}
	}
	if request.To == "cancelled" || request.To == "interrupted" || request.To == "failed" || request.To == "partial" {
		status := "interrupted"
		if request.To == "cancelled" {
			status = "cancelled"
		}
		for index := range run.Steps {
			if run.Steps[index].Status == "queued" {
				run.Steps[index].Status = status
			}
		}
	}
	run.Status, run.UpdatedAt = request.To, request.At.Format(time.RFC3339)
	if request.VerificationStatus != "" {
		run.VerificationStatus, run.VerificationDigest = request.VerificationStatus, request.VerificationDigest
	}
	if request.RollbackStatus != "" {
		run.RollbackStatus = request.RollbackStatus
	}
	if request.Changed != nil {
		run.Changed = *request.Changed
	}
	repository.runs[run.RunID] = run
	return cloneRun(run), nil
}

func (repository *memoryRepository) RequestCancellation(_ context.Context, id string, at time.Time, _ audit.Attribution) (generated.Run, error) {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	run := repository.runs[id]
	run.CancellationRequested = true
	run.UpdatedAt = at.Format(time.RFC3339)
	repository.runs[id] = run
	return cloneRun(run), nil
}

func (repository *memoryRepository) AcquireTargetLease(_ context.Context, lease generated.ExecutorLease, _ audit.Attribution) error {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	if _, exists := repository.leases[lease.LeaseID]; exists {
		return runError(generated.ErrorCodeStateConflict, "target-lease")
	}
	if _, exists := repository.targets[lease.TargetID]; exists {
		return runError(generated.ErrorCodeStateConflict, "target-lease")
	}
	repository.leases[lease.LeaseID], repository.targets[lease.TargetID] = lease, lease.LeaseID
	return nil
}
func (repository *memoryRepository) ReleaseTargetLease(_ context.Context, id string, _ time.Time) error {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	lease, ok := repository.leases[id]
	if !ok {
		return runError(generated.ErrorCodeStateConflict, "target-lease")
	}
	delete(repository.targets, lease.TargetID)
	lease.Status = "released"
	repository.leases[id] = lease
	return nil
}
func (repository *memoryRepository) ReleaseRunLeases(_ context.Context, id string, _ time.Time) error {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	if repository.releaseRunLeasesError != nil {
		return repository.releaseRunLeasesError
	}
	for leaseID, lease := range repository.leases {
		if lease.RunID == id && lease.Status == "active" {
			delete(repository.targets, lease.TargetID)
			lease.Status = "released"
			repository.leases[leaseID] = lease
		}
	}
	return nil
}

func (repository *memoryRepository) BeginStep(_ context.Context, request store.StepBeginRequest) (generated.Run, error) {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	run := repository.runs[request.RunID]
	step := findRunStep(run, request.StepID)
	if step == nil || step.Status != "queued" {
		return run, runError(generated.ErrorCodeStateConflict, "run-step")
	}
	step.Status, step.EffectState = "running", "intent-recorded"
	repository.runs[run.RunID] = run
	return cloneRun(run), nil
}
func (repository *memoryRepository) RecordReceipt(_ context.Context, request store.ReceiptRecordRequest) (generated.Run, error) {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	run := repository.runs[request.RunID]
	step := findRunStep(run, request.StepID)
	if step == nil || step.EffectState != "intent-recorded" {
		return run, runError(generated.ErrorCodeStateConflict, "run-receipt")
	}
	repository.receipts[request.Receipt.ReceiptID] = request.Receipt
	step.EffectState = "receipt-recorded"
	repository.runs[run.RunID] = run
	return cloneRun(run), nil
}
func (repository *memoryRepository) FinishStep(_ context.Context, request store.StepFinishRequest) (generated.Run, error) {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	run := repository.runs[request.RunID]
	step := findRunStep(run, request.StepID)
	if step == nil || step.EffectState != "receipt-recorded" {
		return run, runError(generated.ErrorCodeStateConflict, "run-step")
	}
	step.Status, step.EffectState = request.Status, request.EffectState
	run.Changed = run.Changed || request.Changed
	repository.runs[run.RunID] = run
	return cloneRun(run), nil
}
func (repository *memoryRepository) MarkStepUnknown(_ context.Context, id, stepID string, _ time.Time, _ audit.Attribution) (generated.Run, error) {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	run := repository.runs[id]
	step := findRunStep(run, stepID)
	if step == nil || step.Status != "running" {
		return run, runError(generated.ErrorCodeStateConflict, "run-step")
	}
	step.Status, step.EffectState, run.Changed = "partial", "effect-unknown", true
	repository.runs[id] = run
	return cloneRun(run), nil
}
func (repository *memoryRepository) FailStepBeforeEffect(_ context.Context, id, stepID string, _ time.Time, _ audit.Attribution) (generated.Run, error) {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	run := repository.runs[id]
	step := findRunStep(run, stepID)
	if step == nil || step.Status != "running" {
		return run, runError(generated.ErrorCodeStateConflict, "run-step")
	}
	step.Status, step.EffectState = "failed", "not-started"
	repository.runs[id] = run
	return cloneRun(run), nil
}
func (repository *memoryRepository) InterruptStepBeforeEffect(_ context.Context, id, stepID string, _ time.Time, _ audit.Attribution) (generated.Run, error) {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	run := repository.runs[id]
	step := findRunStep(run, stepID)
	if step == nil || step.Status != "running" {
		return run, runError(generated.ErrorCodeStateConflict, "run-step")
	}
	step.Status, step.EffectState = "interrupted", "not-started"
	repository.runs[id] = run
	return cloneRun(run), nil
}
func (repository *memoryRepository) ActiveRuns(context.Context) ([]generated.Run, error) {
	repository.mu.Lock()
	defer repository.mu.Unlock()
	result := []generated.Run{}
	for _, run := range repository.runs {
		if run.Status == "queued" || run.Status == "running" || run.Status == "interrupted" {
			result = append(result, cloneRun(run))
		}
	}
	return result, nil
}
func (*memoryRepository) PruneRunHistory(context.Context, time.Time) (store.RunPruneResult, error) {
	return store.RunPruneResult{}, nil
}

type allowAdmission struct{}

func (allowAdmission) Verify(context.Context, generated.Plan, generated.AuthorizationDecision, *generated.Acknowledgement) error {
	return nil
}
func (allowAdmission) VerifyRun(context.Context, generated.Plan, generated.Run) error { return nil }

type deterministicIDs struct {
	mu      sync.Mutex
	attempt int
}

func (source *deterministicIDs) Lease(step generated.RunStep) (string, string, error) {
	source.mu.Lock()
	defer source.mu.Unlock()
	source.attempt++
	attempt := strconv.Itoa(source.attempt)
	return "lease-deterministic-" + attempt, digest("nonce", step.StepID, attempt), nil
}

func testPlan(now time.Time) generated.Plan {
	return generated.Plan{Schema: generated.SchemaIDPlan, SchemaVersion: "1.0.0", PlanID: "plan-test", PlanDigest: digest("plan"), DeclarationID: "declaration-test", Binding: generated.PlanBinding{RecoveryEpoch: 0, PriorStateRevision: 0, StateRevision: 1, DeclarationRevision: 1, ObservationFingerprint: digest("observation"), TargetDigest: digest("target"), ReasonDigest: digest("reason"), PolicyVersion: "1.0.0", ToolVersion: "1.0.0", ContractVersion: "1.0.0"}, Operations: []generated.PlanOperation{{Sequence: 1, OperationID: "operation-test", OperationType: "application.deploy.low-risk", AdapterID: "adapter-test", ExecutorID: "executor-central", TargetID: "target-test", InputDigest: digest("input"), ArtifactDigest: digest("artifact"), Idempotent: true}}, Status: "planned", Risk: "routine", AuthorizationBranch: "preauthorized", ExecutorMode: "central", ExecutorID: nil, CreatedAt: now.Format(time.RFC3339), ExpiresAt: now.Add(30 * time.Minute).Format(time.RFC3339), ReadableDigest: digest("readable"), Extensions: []generated.ContractExtension{}}
}

func cloneRun(run generated.Run) generated.Run {
	run.Steps = append([]generated.RunStep(nil), run.Steps...)
	return run
}

var _ adapter.Adapter = (*fakeAdapter)(nil)
