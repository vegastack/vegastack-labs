package run

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/vegastack/vegastack-labs/internal/adapter"
	"github.com/vegastack/vegastack-labs/internal/audit"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/identity"
	"github.com/vegastack/vegastack-labs/internal/store"
)

type Repository interface {
	Create(context.Context, store.RunCreateRequest) (store.RunCreateResult, error)
	GetRun(context.Context, string) (generated.Run, error)
	TransitionRun(context.Context, store.RunTransitionRequest) (generated.Run, error)
	RequestCancellation(context.Context, string, time.Time, audit.Attribution) (generated.Run, error)
	AcquireTargetLease(context.Context, generated.ExecutorLease, audit.Attribution) error
	ReleaseTargetLease(context.Context, string, time.Time) error
	ReleaseRunLeases(context.Context, string, time.Time) error
	BeginStep(context.Context, store.StepBeginRequest) (generated.Run, error)
	RecordReceipt(context.Context, store.ReceiptRecordRequest) (generated.Run, error)
	FinishStep(context.Context, store.StepFinishRequest) (generated.Run, error)
	MarkStepUnknown(context.Context, string, string, time.Time, audit.Attribution) (generated.Run, error)
	FailStepBeforeEffect(context.Context, string, string, time.Time, audit.Attribution) (generated.Run, error)
	InterruptStepBeforeEffect(context.Context, string, string, time.Time, audit.Attribution) (generated.Run, error)
	ActiveRuns(context.Context) ([]generated.Run, error)
	PruneRunHistory(context.Context, time.Time) (store.RunPruneResult, error)
}

type PlanSource interface {
	Get(context.Context, string) (store.PlanCommitResult, error)
	ValidateCurrent(context.Context, generated.Plan) error
}

type AdmissionVerifier interface {
	Verify(context.Context, generated.Plan, generated.AuthorizationDecision, *generated.Acknowledgement) error
	VerifyRun(context.Context, generated.Plan, generated.Run) error
}

type AdapterRegistry interface {
	Resolve(string) (adapter.Adapter, error)
}

type IDSource interface {
	LeaseID(generated.RunStep) string
	NonceDigest(generated.RunStep) string
	ReceiptID(generated.RunStep) string
}

type Config struct {
	Repository Repository
	Plans      PlanSource
	Admission  AdmissionVerifier
	Adapters   AdapterRegistry
	Clock      func() time.Time
	IDs        IDSource
}

type SubmitRequest struct {
	Reference       generated.PlanReferenceRequest
	Authorization   generated.AuthorizationDecision
	Acknowledgement *generated.Acknowledgement
	Attribution     audit.Attribution
}

type Engine struct {
	repository        Repository
	plans             PlanSource
	admission         AdmissionVerifier
	adapters          AdapterRegistry
	clock             func() time.Time
	ids               IDSource
	testAfterBoundary func(Boundary) error
}

func NewEngine(config Config) (*Engine, error) {
	if config.Repository == nil || config.Plans == nil || config.Admission == nil || config.Adapters == nil {
		return nil, runError(generated.ErrorCodeInputInvalid, "run-engine")
	}
	if config.Clock == nil {
		config.Clock = time.Now
	}
	if config.IDs == nil {
		config.IDs = deterministicIDSource{}
	}
	return &Engine{repository: config.Repository, plans: config.Plans, admission: config.Admission, adapters: config.Adapters, clock: config.Clock, ids: config.IDs}, nil
}

func (engine *Engine) Submit(ctx context.Context, request SubmitRequest) (generated.Run, error) {
	if engine == nil || !exactContract(generated.SchemaIDPlanReferenceRequest, request.Reference) || !exactContract(generated.SchemaIDAuthorizationDecision, request.Authorization) {
		return generated.Run{}, runError(generated.ErrorCodeInputInvalid, "run-submit")
	}
	stored, err := engine.plans.Get(ctx, request.Reference.PlanID)
	if err != nil {
		return generated.Run{}, err
	}
	plan := stored.Plan
	if plan.PlanID != request.Reference.PlanID || plan.PlanDigest != request.Reference.PlanDigest || plan.Binding.RecoveryEpoch != request.Reference.RecoveryEpoch || plan.Status != "planned" {
		return generated.Run{}, runError(generated.ErrorCodePlanStale, "plan")
	}
	if err := engine.verifyAdmission(ctx, plan, request.Authorization, request.Acknowledgement); err != nil {
		return generated.Run{}, err
	}
	now := engine.clock().UTC().Truncate(time.Second)
	if !now.Before(parseTime(plan.ExpiresAt)) {
		return generated.Run{}, runError(generated.ErrorCodePlanStale, "plan")
	}
	id := runID(plan.PlanID, request.Reference.IdempotencyKey)
	executorID, err := planExecutorID(plan)
	if err != nil {
		return generated.Run{}, err
	}
	steps := make([]generated.RunStep, len(plan.Operations))
	for index, operation := range plan.Operations {
		steps[index] = generated.RunStep{Sequence: operation.Sequence, OperationID: operation.OperationID, OperationType: operation.OperationType, AdapterID: operation.AdapterID, ExecutorID: operation.ExecutorID, TargetID: operation.TargetID, InputDigest: operation.InputDigest, ArtifactDigest: operation.ArtifactDigest, Idempotent: operation.Idempotent, StepID: stepID(id, operation.Sequence), Status: "queued", EffectState: "not-started"}
	}
	var acknowledgementID *string
	if request.Acknowledgement != nil {
		value := request.Acknowledgement.AcknowledgementID
		acknowledgementID = &value
	}
	run := generated.Run{Schema: generated.SchemaIDRun, SchemaVersion: "1.0.0", RunID: id, PlanID: plan.PlanID, PlanDigest: plan.PlanDigest, AuthorizationDecisionID: request.Authorization.DecisionID, AcknowledgementID: acknowledgementID, PolicyVersion: plan.Binding.PolicyVersion, ExecutorMode: plan.ExecutorMode, ExecutorID: executorID, ExecutorBindingDigest: digest("executor-binding", plan.PlanID, plan.PlanDigest, executorID, request.Authorization.DecisionID), Status: "queued", Steps: steps, CancellationRequested: false, RollbackStatus: "not-requested", VerificationStatus: "pending", VerificationDigest: nil, Changed: false, StateRevision: plan.Binding.StateRevision, RecoveryEpoch: plan.Binding.RecoveryEpoch, CreatedAt: now.Format(time.RFC3339), UpdatedAt: now.Format(time.RFC3339), Extensions: []generated.ContractExtension{}}
	created, err := engine.repository.Create(ctx, store.RunCreateRequest{Run: run, SubmitKeyDigest: audit.Fingerprint(digest("run-submit-key", request.Reference.IdempotencyKey)), RequestDigest: audit.Fingerprint(digest("run-submit-request", string(mustJSON(request.Reference)), string(mustJSON(request.Authorization)), string(mustJSON(request.Acknowledgement)))), Attribution: request.Attribution})
	if err != nil {
		return generated.Run{}, err
	}
	if !created.Created {
		return created.Run, nil
	}
	if err := engine.after(BoundaryRunCreated); err != nil {
		return created.Run, err
	}
	if err := engine.verifyAdmission(ctx, plan, request.Authorization, request.Acknowledgement); err != nil {
		return created.Run, err
	}
	// Once the run is durably created, client disconnect is no longer execution
	// authority. The server-owned run continues and remains observable.
	return engine.start(context.WithoutCancel(ctx), plan, created.Run, request.Attribution)
}

func (engine *Engine) Resume(ctx context.Context, id string) (generated.Run, error) {
	return engine.ResumeAs(ctx, id, systemAttribution())
}

func (engine *Engine) ResumeAs(ctx context.Context, id string, attribution audit.Attribution) (generated.Run, error) {
	run, err := engine.repository.GetRun(ctx, id)
	if err != nil {
		return generated.Run{}, err
	}
	if run.Status != "interrupted" {
		return run, runError(generated.ErrorCodeStateConflict, "run-resume")
	}
	for _, step := range run.Steps {
		if step.Status == "interrupted" && (!step.Idempotent || step.EffectState != "not-started") {
			return run, runError(generated.ErrorCodeRecoveryRequired, "run-resume")
		}
	}
	stored, err := engine.plans.Get(ctx, run.PlanID)
	if err != nil {
		return run, err
	}
	if err := engine.plans.ValidateCurrent(ctx, stored.Plan); err != nil {
		return run, runError(generated.ErrorCodePlanStale, "plan")
	}
	if err := engine.admission.VerifyRun(ctx, stored.Plan, run); err != nil {
		return run, err
	}
	return engine.start(ctx, stored.Plan, run, attribution)
}

func (engine *Engine) Cancel(ctx context.Context, id string) (generated.Run, error) {
	return engine.CancelAs(ctx, id, systemAttribution())
}

func (engine *Engine) CancelAs(ctx context.Context, id string, attribution audit.Attribution) (generated.Run, error) {
	run, err := engine.repository.GetRun(ctx, id)
	if err != nil {
		return generated.Run{}, err
	}
	now := engine.clock().UTC().Truncate(time.Second)
	switch run.Status {
	case "queued":
		return engine.repository.TransitionRun(ctx, store.RunTransitionRequest{RunID: id, From: "queued", To: "cancelled", At: now, Attribution: attribution})
	case "running":
		return engine.repository.RequestCancellation(ctx, id, now, attribution)
	case "interrupted":
		return engine.repository.TransitionRun(ctx, store.RunTransitionRequest{RunID: id, From: "interrupted", To: "cancelled", At: now, Attribution: attribution})
	default:
		return run, runError(generated.ErrorCodeStateConflict, "run-cancel")
	}
}

func (engine *Engine) Get(ctx context.Context, id string) (generated.Run, error) {
	return engine.repository.GetRun(ctx, id)
}

func (engine *Engine) Startup(ctx context.Context) error {
	if _, err := engine.repository.PruneRunHistory(ctx, engine.clock().UTC().Truncate(time.Second)); err != nil {
		return err
	}
	return engine.Reconcile(ctx)
}

func (engine *Engine) Reconcile(ctx context.Context) error {
	runs, err := engine.repository.ActiveRuns(ctx)
	if err != nil {
		return err
	}
	for _, run := range runs {
		now := engine.clock().UTC().Truncate(time.Second)
		_ = engine.repository.ReleaseRunLeases(ctx, run.RunID, now)
		if run.Status == "queued" {
			continue
		}
		ambiguous := false
		allSucceeded := len(run.Steps) > 0
		for _, step := range run.Steps {
			if step.Status != "succeeded" || step.EffectState != "verified" {
				allSucceeded = false
			}
			if step.Status == "running" && (step.EffectState == "intent-recorded" || step.EffectState == "receipt-recorded") {
				_, markErr := engine.repository.MarkStepUnknown(ctx, run.RunID, step.StepID, now, systemAttribution())
				if markErr != nil {
					return markErr
				}
				ambiguous = true
			}
		}
		if ambiguous {
			changed := true
			_, err = engine.repository.TransitionRun(ctx, store.RunTransitionRequest{RunID: run.RunID, From: "running", To: "partial", At: now, VerificationStatus: "incomplete", RollbackStatus: "required", Changed: &changed, Attribution: systemAttribution()})
		} else if allSucceeded {
			verification := digest("run-verified", run.RunID)
			_, err = engine.repository.TransitionRun(ctx, store.RunTransitionRequest{RunID: run.RunID, From: "running", To: "succeeded", At: now, VerificationStatus: "verified", VerificationDigest: &verification, Attribution: systemAttribution()})
		} else {
			_, err = engine.repository.TransitionRun(ctx, store.RunTransitionRequest{RunID: run.RunID, From: "running", To: "interrupted", At: now, VerificationStatus: "incomplete", Attribution: systemAttribution()})
		}
		if err != nil {
			return err
		}
	}
	return nil
}

func (engine *Engine) start(ctx context.Context, plan generated.Plan, current generated.Run, attribution audit.Attribution) (generated.Run, error) {
	now := engine.clock().UTC().Truncate(time.Second)
	if current.Status == "queued" {
		current, _ = engine.repository.GetRun(ctx, current.RunID)
		if terminal(current.Status) {
			return current, nil
		}
		if current.CancellationRequested {
			return engine.repository.TransitionRun(ctx, store.RunTransitionRequest{RunID: current.RunID, From: "queued", To: "cancelled", At: now, Attribution: attribution})
		}
		var err error
		current, err = engine.repository.TransitionRun(ctx, store.RunTransitionRequest{RunID: current.RunID, From: "queued", To: "running", At: now, Attribution: attribution})
		if err != nil {
			return current, err
		}
	} else if current.Status == "interrupted" {
		var err error
		current, err = engine.repository.TransitionRun(ctx, store.RunTransitionRequest{RunID: current.RunID, From: "interrupted", To: "running", At: now, Attribution: attribution})
		if err != nil {
			return current, err
		}
	}
	if err := engine.after(BoundaryRunStarted); err != nil {
		return current, err
	}
	for _, step := range current.Steps {
		current, _ = engine.repository.GetRun(ctx, current.RunID)
		if current.CancellationRequested {
			return engine.repository.TransitionRun(ctx, store.RunTransitionRequest{RunID: current.RunID, From: "running", To: "interrupted", At: engine.clock().UTC().Truncate(time.Second), VerificationStatus: "incomplete", Attribution: attribution})
		}
		live := findRunStep(current, step.StepID)
		if live == nil || live.Status == "succeeded" {
			continue
		}
		if live.Status != "queued" {
			return current, runError(generated.ErrorCodeRecoveryRequired, "run-step")
		}
		operation, err := exactOperation(plan, *live)
		if err != nil {
			return current, err
		}
		implementation, err := engine.adapters.Resolve(operation.AdapterID)
		if err != nil {
			current, transitionErr := engine.repository.TransitionRun(ctx, store.RunTransitionRequest{RunID: current.RunID, From: "running", To: "failed", At: engine.clock().UTC().Truncate(time.Second), VerificationStatus: "failed", Attribution: attribution})
			if transitionErr != nil {
				return current, transitionErr
			}
			return current, err
		}
		claimed := engine.clock().UTC().Truncate(time.Second)
		lease := generated.ExecutorLease{Schema: generated.SchemaIDExecutorLease, SchemaVersion: "1.0.0", LeaseID: engine.ids.LeaseID(*live), PlanID: plan.PlanID, PlanDigest: plan.PlanDigest, RunID: current.RunID, StepID: live.StepID, OperationID: live.OperationID, ExecutorID: live.ExecutorID, AdapterID: live.AdapterID, TargetID: live.TargetID, ArtifactDigest: live.ArtifactDigest, BindingDigest: current.ExecutorBindingDigest, NonceDigest: engine.ids.NonceDigest(*live), RecoveryEpoch: current.RecoveryEpoch, ClaimedAt: claimed.Format(time.RFC3339), RenewAfter: claimed.Add(time.Duration(generated.ExecutorCheckInSeconds) * time.Second).Format(time.RFC3339), LeaseExpiresAt: claimed.Add(time.Duration(generated.ExecutorLeaseSeconds) * time.Second).Format(time.RFC3339), MaximumExpiresAt: claimed.Add(time.Duration(generated.ExecutorLeaseSeconds) * time.Second).Format(time.RFC3339), Status: "active", Extensions: []generated.ContractExtension{}}
		if err := engine.repository.AcquireTargetLease(ctx, lease, attribution); err != nil {
			return current, err
		}
		if err := engine.after(BoundaryLeaseAcquired); err != nil {
			return current, err
		}
		current, err = engine.repository.BeginStep(ctx, store.StepBeginRequest{RunID: current.RunID, StepID: live.StepID, LeaseID: lease.LeaseID, At: claimed, Attribution: attribution})
		if err != nil {
			return current, err
		}
		if err := engine.after(BoundaryIntentRecorded); err != nil {
			return current, err
		}
		effect, executeErr := implementation.Execute(ctx, operation)
		if boundaryErr := engine.after(BoundaryEffectReturned); boundaryErr != nil {
			return current, boundaryErr
		}
		if executeErr != nil || adapter.ValidateEffect(effect) != nil {
			if !effect.EffectObserved {
				if errors.Is(executeErr, context.Canceled) || errors.Is(executeErr, context.DeadlineExceeded) {
					return engine.interruptBeforeEffect(ctx, current, *live, attribution)
				}
				return engine.failBeforeEffect(ctx, current, *live, attribution, firstError(executeErr, adapter.ValidateEffect(effect)))
			}
			return engine.partial(ctx, current, *live, attribution, firstError(executeErr, adapter.ValidateEffect(effect)))
		}
		recorded := engine.clock().UTC().Truncate(time.Second)
		receipt := generated.ExecutionReceipt{Schema: generated.SchemaIDExecutionReceipt, SchemaVersion: "1.0.0", LeaseID: lease.LeaseID, PlanID: lease.PlanID, PlanDigest: lease.PlanDigest, RunID: lease.RunID, StepID: lease.StepID, OperationID: lease.OperationID, ExecutorID: lease.ExecutorID, AdapterID: lease.AdapterID, TargetID: lease.TargetID, ArtifactDigest: lease.ArtifactDigest, BindingDigest: lease.BindingDigest, NonceDigest: lease.NonceDigest, RecoveryEpoch: lease.RecoveryEpoch, ReceiptID: engine.ids.ReceiptID(*live), Status: effect.Status, ResultDigest: effect.ResultDigest, RecordedAt: recorded.Format(time.RFC3339), Extensions: []generated.ContractExtension{}}
		current, err = engine.repository.RecordReceipt(ctx, store.ReceiptRecordRequest{RunID: current.RunID, StepID: live.StepID, LeaseID: lease.LeaseID, Receipt: receipt, At: recorded, Attribution: attribution})
		if err != nil {
			return current, err
		}
		if err := engine.after(BoundaryReceiptRecorded); err != nil {
			return current, err
		}
		verification, verifyErr := implementation.Verify(ctx, operation, effect)
		if verifyErr != nil || adapter.ValidateVerification(verification) != nil || !verification.Verified {
			return engine.partial(ctx, current, *live, attribution, firstError(verifyErr, adapter.ValidateVerification(verification)))
		}
		current, err = engine.repository.FinishStep(ctx, store.StepFinishRequest{RunID: current.RunID, StepID: live.StepID, LeaseID: lease.LeaseID, Receipt: receipt, Status: effect.Status, EffectState: "verified", VerificationDigest: verification.Digest, Changed: effect.Changed, At: engine.clock().UTC().Truncate(time.Second), Attribution: attribution})
		if err != nil {
			return current, err
		}
		if err := engine.repository.ReleaseTargetLease(ctx, lease.LeaseID, engine.clock().UTC().Truncate(time.Second)); err != nil {
			return current, err
		}
		if err := engine.after(BoundaryVerified); err != nil {
			return current, err
		}
		if effect.Status == "failed" {
			current, err = engine.repository.TransitionRun(ctx, store.RunTransitionRequest{RunID: current.RunID, From: "running", To: "failed", At: engine.clock().UTC().Truncate(time.Second), VerificationStatus: "failed", Changed: &effect.Changed, Attribution: attribution})
			return current, firstError(err, runError(generated.ErrorCodeExecutionFailed, "run"))
		}
		if effect.Status == "partial" {
			changed := current.Changed || effect.Changed
			current, transitionErr := engine.repository.TransitionRun(ctx, store.RunTransitionRequest{RunID: current.RunID, From: "running", To: "partial", At: engine.clock().UTC().Truncate(time.Second), VerificationStatus: "incomplete", RollbackStatus: "required", Changed: &changed, Attribution: attribution})
			if transitionErr != nil {
				return current, transitionErr
			}
			return current, runError(generated.ErrorCodeExecutionPartial, "run")
		}
	}
	verification := digest("run-verification", current.RunID, current.PlanDigest)
	current, err := engine.repository.TransitionRun(ctx, store.RunTransitionRequest{RunID: current.RunID, From: "running", To: "succeeded", At: engine.clock().UTC().Truncate(time.Second), VerificationStatus: "verified", VerificationDigest: &verification, Attribution: attribution})
	if err != nil {
		return current, err
	}
	if err := engine.after(BoundaryRunCompleted); err != nil {
		return current, err
	}
	return current, nil
}

func (engine *Engine) interruptBeforeEffect(ctx context.Context, current generated.Run, step generated.RunStep, attribution audit.Attribution) (generated.Run, error) {
	current, err := engine.repository.InterruptStepBeforeEffect(ctx, current.RunID, step.StepID, engine.clock().UTC().Truncate(time.Second), attribution)
	if err != nil {
		return current, err
	}
	current, err = engine.repository.TransitionRun(ctx, store.RunTransitionRequest{RunID: current.RunID, From: "running", To: "interrupted", At: engine.clock().UTC().Truncate(time.Second), VerificationStatus: "incomplete", Attribution: attribution})
	if err != nil {
		return current, err
	}
	return current, runError(generated.ErrorCodeInterrupted, "run")
}

func (engine *Engine) verifyAdmission(ctx context.Context, plan generated.Plan, decision generated.AuthorizationDecision, acknowledgement *generated.Acknowledgement) error {
	if err := engine.plans.ValidateCurrent(ctx, plan); err != nil {
		return runError(generated.ErrorCodePlanStale, "plan")
	}
	if !decision.Allowed || decision.Action != "execute" || decision.PlanDigest != plan.PlanDigest || decision.RecoveryEpoch != plan.Binding.RecoveryEpoch || decision.Branch == nil || *decision.Branch != plan.AuthorizationBranch {
		return runError(generated.ErrorCodeAuthorizationDenied, "run-admission")
	}
	if plan.AuthorizationBranch == "human" && acknowledgement == nil {
		return runError(generated.ErrorCodeApprovalRequired, "acknowledgement")
	}
	if plan.AuthorizationBranch == "preauthorized" && acknowledgement != nil {
		return runError(generated.ErrorCodeAuthorizationDenied, "acknowledgement")
	}
	return engine.admission.Verify(ctx, plan, decision, acknowledgement)
}

func (engine *Engine) failBeforeEffect(ctx context.Context, current generated.Run, step generated.RunStep, attribution audit.Attribution, cause error) (generated.Run, error) {
	current, markErr := engine.repository.FailStepBeforeEffect(ctx, current.RunID, step.StepID, engine.clock().UTC().Truncate(time.Second), attribution)
	if markErr != nil {
		return current, markErr
	}
	current, transitionErr := engine.repository.TransitionRun(ctx, store.RunTransitionRequest{RunID: current.RunID, From: "running", To: "failed", At: engine.clock().UTC().Truncate(time.Second), VerificationStatus: "failed", Attribution: attribution})
	if transitionErr != nil {
		return current, transitionErr
	}
	if Code(cause) != "" {
		return current, cause
	}
	return current, runError(generated.ErrorCodeExecutionFailed, "adapter")
}

func (engine *Engine) partial(ctx context.Context, current generated.Run, step generated.RunStep, attribution audit.Attribution, cause error) (generated.Run, error) {
	current, markErr := engine.repository.MarkStepUnknown(ctx, current.RunID, step.StepID, engine.clock().UTC().Truncate(time.Second), attribution)
	if markErr != nil {
		return current, markErr
	}
	changed := true
	current, transitionErr := engine.repository.TransitionRun(ctx, store.RunTransitionRequest{RunID: current.RunID, From: "running", To: "partial", At: engine.clock().UTC().Truncate(time.Second), VerificationStatus: "incomplete", RollbackStatus: "required", Changed: &changed, Attribution: attribution})
	if transitionErr != nil {
		return current, transitionErr
	}
	return current, runError(generated.ErrorCodeRecoveryRequired, "run")
}

func (engine *Engine) after(boundary Boundary) error {
	if engine.testAfterBoundary == nil {
		return nil
	}
	return engine.testAfterBoundary(boundary)
}

func exactOperation(plan generated.Plan, step generated.RunStep) (adapter.Operation, error) {
	for _, operation := range plan.Operations {
		if operation.OperationID != step.OperationID {
			continue
		}
		if operation.Sequence != step.Sequence || operation.OperationType != step.OperationType || operation.AdapterID != step.AdapterID || operation.ExecutorID != step.ExecutorID || operation.TargetID != step.TargetID || operation.InputDigest != step.InputDigest || operation.ArtifactDigest != step.ArtifactDigest || operation.Idempotent != step.Idempotent {
			return adapter.Operation{}, runError(generated.ErrorCodeIntegrityFailure, "run-step-binding")
		}
		result := adapter.Operation{OperationID: operation.OperationID, OperationType: operation.OperationType, AdapterID: operation.AdapterID, ExecutorID: operation.ExecutorID, TargetID: operation.TargetID, InputDigest: operation.InputDigest, ArtifactDigest: operation.ArtifactDigest, Idempotent: operation.Idempotent, SecretReferences: []adapter.SecretReference{}}
		if err := adapter.ValidateOperation(result); err != nil {
			return adapter.Operation{}, err
		}
		return result, nil
	}
	return adapter.Operation{}, runError(generated.ErrorCodeIntegrityFailure, "run-step-binding")
}

func planExecutorID(plan generated.Plan) (string, error) {
	if len(plan.Operations) == 0 {
		return "", runError(generated.ErrorCodeInputInvalid, "plan-operations")
	}
	executor := plan.Operations[0].ExecutorID
	for _, operation := range plan.Operations {
		if operation.ExecutorID != executor {
			return "", runError(generated.ErrorCodeInputInvalid, "plan-executor")
		}
	}
	if plan.ExecutorMode == "external" && (plan.ExecutorID == nil || *plan.ExecutorID != executor) {
		return "", runError(generated.ErrorCodeInputInvalid, "plan-executor")
	}
	if plan.ExecutorMode == "central" && plan.ExecutorID != nil {
		return "", runError(generated.ErrorCodeInputInvalid, "plan-executor")
	}
	return executor, nil
}

func findRunStep(run generated.Run, id string) *generated.RunStep {
	for index := range run.Steps {
		if run.Steps[index].StepID == id {
			return &run.Steps[index]
		}
	}
	return nil
}
func parseTime(value string) time.Time { result, _ := time.Parse(time.RFC3339, value); return result }
func mustJSON(value any) []byte        { raw, _ := json.Marshal(value); return raw }
func firstError(values ...error) error {
	for _, value := range values {
		if value != nil {
			return value
		}
	}
	return errors.New("unspecified failure")
}
func systemAttribution() audit.Attribution {
	value, _ := audit.NewAttribution(identity.Principal{ID: "system-run-engine", Method: "local-system", Kind: identity.PrincipalPolicy}, nil, nil)
	return value
}

type deterministicIDSource struct{}

func (deterministicIDSource) LeaseID(step generated.RunStep) string {
	return "lease-" + strings.TrimPrefix(digest("lease", step.StepID), "sha256:")[:32]
}
func (deterministicIDSource) NonceDigest(step generated.RunStep) string {
	return digest("lease-nonce", step.StepID)
}
func (deterministicIDSource) ReceiptID(step generated.RunStep) string {
	return "receipt-" + strings.TrimPrefix(digest("receipt", step.StepID), "sha256:")[:32]
}
