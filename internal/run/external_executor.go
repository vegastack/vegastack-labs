package run

import (
	"context"
	"sort"
	"time"

	"github.com/vegastack/vegastack-labs/internal/adapter"
	"github.com/vegastack/vegastack-labs/internal/audit"
	"github.com/vegastack/vegastack-labs/internal/authorization"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/identity"
	"github.com/vegastack/vegastack-labs/internal/store"
)

type ExternalLeaseRepository interface {
	Claim(context.Context, store.ExecutorLeaseClaimRequest) (generated.ExecutorLease, error)
	Renew(context.Context, store.ExecutorLeaseRenewalRequest) (generated.ExecutorLease, error)
	Expire(context.Context, store.ExecutorLeaseExpiryRequest) ([]generated.ExecutorLease, error)
	RecordReceipt(context.Context, store.ExecutorReceiptPersistenceRequest) (generated.ExecutionReceipt, error)
	Get(context.Context, string) (generated.ExecutorLease, error)
	RecordAuthorizationDenial(context.Context, store.ExecutorAuthorizationDenialRequest) error
}

type ExternalExecutorConfig struct {
	Runs      Repository
	Leases    ExternalLeaseRepository
	Plans     PlanSource
	Admission AdmissionVerifier
	Adapters  AdapterRegistry
	Clock     func() time.Time
	IDs       IDSource
	// SweepInterval is test-configurable; production always uses the generated
	// 20-second executor check-in cadence.
	SweepInterval time.Duration
}

// ExternalExecutor is the in-process, provider-neutral claim protocol. It
// gives an authenticated executor only server-selected work and never calls an
// adapter Execute method. Receipts remain observations until ReceiptVerifier
// independently checks the exact target.
type ExternalExecutor struct {
	runs          Repository
	leases        ExternalLeaseRepository
	plans         PlanSource
	admission     AdmissionVerifier
	adapters      AdapterRegistry
	clock         func() time.Time
	ids           IDSource
	sweepInterval time.Duration
}

func NewExternalExecutor(config ExternalExecutorConfig) (*ExternalExecutor, error) {
	if config.Runs == nil || config.Leases == nil || config.Plans == nil || config.Admission == nil || config.Adapters == nil {
		return nil, runError(generated.ErrorCodeInputInvalid, "external-executor")
	}
	if config.Clock == nil {
		config.Clock = time.Now
	}
	if config.IDs == nil {
		config.IDs = secureIDSource{}
	}
	if config.SweepInterval <= 0 {
		config.SweepInterval = time.Duration(generated.ExecutorCheckInSeconds) * time.Second
	}
	return &ExternalExecutor{runs: config.Runs, leases: config.Leases, plans: config.Plans, admission: config.Admission, adapters: config.Adapters, clock: config.Clock, ids: config.IDs, sweepInterval: config.SweepInterval}, nil
}

// Run makes lease loss fail closed even if no worker sends another request.
// It is hosted by the existing vsk-labs server process, not a second daemon.
func (executor *ExternalExecutor) Run(ctx context.Context) error {
	if executor == nil {
		return runError(generated.ErrorCodeInputInvalid, "external-executor")
	}
	ticker := time.NewTicker(executor.sweepInterval)
	defer ticker.Stop()
	for {
		// A transient authority error must not permanently disable expiry. Claims
		// still call Reconcile synchronously and fail closed while this retries.
		_ = executor.Reconcile(ctx)
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}

func (executor *ExternalExecutor) Claim(ctx context.Context, principal identity.Principal, request generated.ExecutorClaimRequest) (generated.ExecutorLease, error) {
	if executor == nil || !exactContract(generated.SchemaIDExecutorClaimRequest, request) {
		return generated.ExecutorLease{}, runError(generated.ErrorCodeInputInvalid, "executor-claim")
	}
	if err := executor.Reconcile(ctx); err != nil {
		return generated.ExecutorLease{}, err
	}
	runs, err := executor.runs.ActiveRuns(ctx)
	if err != nil {
		return generated.ExecutorLease{}, err
	}
	sort.Slice(runs, func(i, j int) bool {
		if runs[i].CreatedAt == runs[j].CreatedAt {
			return runs[i].RunID < runs[j].RunID
		}
		return runs[i].CreatedAt < runs[j].CreatedAt
	})
	// One executor gets one exact work item at a time across all of its runs.
	// This also prevents a missed renewal from opening another step while the
	// first external effect remains ambiguous.
	for _, current := range runs {
		if current.Status != "running" || current.ExecutorMode != "external" || current.ExecutorID != request.ExecutorID {
			continue
		}
		for _, step := range current.Steps {
			if step.Status == "running" || step.EffectState == "intent-recorded" || step.EffectState == "receipt-recorded" || step.EffectState == "effect-unknown" {
				return generated.ExecutorLease{}, runError(generated.ErrorCodeStateConflict, "executor-work-active")
			}
		}
	}
	for _, current := range runs {
		if current.Status != "running" || current.ExecutorMode != "external" || current.ExecutorID != request.ExecutorID || current.CancellationRequested {
			continue
		}
		stored, getErr := executor.plans.Get(ctx, current.PlanID)
		if getErr != nil {
			return generated.ExecutorLease{}, getErr
		}
		plan := stored.Plan
		if err := executor.admission.VerifyRun(ctx, plan, current); err != nil {
			return generated.ExecutorLease{}, err
		}
		for _, step := range current.Steps {
			if step.Status == "succeeded" && step.EffectState == "verified" {
				continue
			}
			// The first unresolved step is the only server-selected candidate.
			// A caller adapter is an assertion, never a step-selection input.
			if step.Status != "queued" || step.EffectState != "not-started" {
				break
			}
			if step.AdapterID != request.AdapterID {
				return generated.ExecutorLease{}, executor.authorizationDenied(ctx, principal, "claim-adapter", current.RunID)
			}
			if _, ok := authorization.BindExternalExecutorIdentity(principal, request, plan, step); !ok {
				return generated.ExecutorLease{}, executor.authorizationDenied(ctx, principal, "claim-binding", current.RunID)
			}
			implementation, resolveErr := executor.adapters.Resolve(step.AdapterID)
			if resolveErr != nil {
				return generated.ExecutorLease{}, resolveErr
			}
			if _, ok := implementation.(adapter.ReceiptVerifier); !ok {
				return generated.ExecutorLease{}, runError(generated.ErrorCodeDependencyUnavailable, "executor-verification-adapter")
			}
			now := executor.now()
			leaseID, _, idErr := executor.ids.Lease(step)
			if idErr != nil {
				return generated.ExecutorLease{}, runError(generated.ErrorCodeIntegrityFailure, "executor-lease-identity")
			}
			lease := generated.ExecutorLease{
				Schema: generated.SchemaIDExecutorLease, SchemaVersion: "1.0.0", LeaseID: leaseID,
				PlanID: plan.PlanID, PlanDigest: plan.PlanDigest, RunID: current.RunID, StepID: step.StepID,
				OperationID: step.OperationID, ExecutorID: step.ExecutorID, AdapterID: step.AdapterID,
				TargetID: step.TargetID, ArtifactDigest: step.ArtifactDigest, BindingDigest: current.ExecutorBindingDigest,
				NonceDigest: request.NonceDigest, RecoveryEpoch: current.RecoveryEpoch,
				ClaimedAt: now.Format(time.RFC3339), RenewAfter: now.Add(time.Duration(generated.ExecutorCheckInSeconds) * time.Second).Format(time.RFC3339),
				LeaseExpiresAt:   now.Add(time.Duration(generated.ExecutorLeaseSeconds) * time.Second).Format(time.RFC3339),
				MaximumExpiresAt: now.Add(time.Duration(generated.ExecutorLeaseSeconds) * time.Second).Format(time.RFC3339),
				Status:           "active", Extensions: append([]generated.ContractExtension(nil), request.Extensions...),
			}
			attribution, attributionErr := externalAttribution(principal)
			if attributionErr != nil {
				return generated.ExecutorLease{}, attributionErr
			}
			return executor.leases.Claim(ctx, store.ExecutorLeaseClaimRequest{Request: request, Lease: lease, At: now, Attribution: attribution})
		}
	}
	return generated.ExecutorLease{}, runError(generated.ErrorCodeResourceNotFound, "executor-work")
}

func (executor *ExternalExecutor) Renew(ctx context.Context, principal identity.Principal, request generated.ExecutorRenewRequest) (generated.ExecutorLease, error) {
	if executor == nil || !exactContract(generated.SchemaIDExecutorRenewRequest, request) {
		return generated.ExecutorLease{}, runError(generated.ErrorCodeInputInvalid, "executor-renew")
	}
	if err := executor.Reconcile(ctx); err != nil {
		return generated.ExecutorLease{}, err
	}
	lease, current, plan, step, err := executor.boundLease(ctx, principal, request.LeaseID, request.Extensions)
	if err != nil {
		return generated.ExecutorLease{}, err
	}
	if request.RecoveryEpoch != lease.RecoveryEpoch {
		return generated.ExecutorLease{}, runError(generated.ErrorCodeRecoveryEpochMismatch, "executor-renew-binding")
	}
	if request.BindingDigest != lease.BindingDigest || request.NonceDigest != lease.NonceDigest || current.Status != "running" {
		return generated.ExecutorLease{}, executor.authorizationDenied(ctx, principal, "renew-binding", lease.LeaseID)
	}
	if err := executor.admission.VerifyRun(ctx, plan, current); err != nil {
		return generated.ExecutorLease{}, err
	}
	_, nextNonce, idErr := executor.ids.Lease(step)
	if idErr != nil {
		return generated.ExecutorLease{}, runError(generated.ErrorCodeIntegrityFailure, "executor-renew-identity")
	}
	attribution, err := externalAttribution(principal)
	if err != nil {
		return generated.ExecutorLease{}, err
	}
	return executor.leases.Renew(ctx, store.ExecutorLeaseRenewalRequest{Request: request, NextNonceDigest: nextNonce, At: executor.now(), Attribution: attribution})
}

func (executor *ExternalExecutor) SubmitReceipt(ctx context.Context, principal identity.Principal, request generated.ExecutionReceiptRequest) (generated.ExecutionReceipt, error) {
	if executor == nil || !exactContract(generated.SchemaIDExecutionReceiptRequest, request) {
		return generated.ExecutionReceipt{}, runError(generated.ErrorCodeInputInvalid, "executor-receipt")
	}
	lease, current, plan, step, err := executor.boundLease(ctx, principal, request.Receipt.LeaseID, request.Extensions)
	if err != nil {
		return generated.ExecutionReceipt{}, err
	}
	if err := executor.admission.VerifyRun(ctx, plan, current); err != nil {
		return generated.ExecutionReceipt{}, err
	}
	operation, err := exactOperation(plan, step)
	if err != nil {
		return generated.ExecutionReceipt{}, err
	}
	implementation, err := executor.adapters.Resolve(operation.AdapterID)
	if err != nil {
		return generated.ExecutionReceipt{}, err
	}
	verifier, ok := implementation.(adapter.ReceiptVerifier)
	if !ok {
		return generated.ExecutionReceipt{}, runError(generated.ErrorCodeDependencyUnavailable, "executor-verification-adapter")
	}
	attribution, err := externalAttribution(principal)
	if err != nil {
		return generated.ExecutionReceipt{}, err
	}
	now := executor.now()
	bindingExact := request.ExpectedBindingDigest == lease.BindingDigest && generated.ValidateExecutionReceiptBinding(lease, request.Receipt) == nil
	if !bindingExact {
		if err := executor.recordAuthorizationDenial(ctx, principal, "receipt-binding", lease.LeaseID); err != nil {
			return generated.ExecutionReceipt{}, err
		}
	}
	if bindingExact {
		if _, err := executor.leases.RecordReceipt(ctx, store.ExecutorReceiptPersistenceRequest{Request: request, At: now, Attribution: attribution}); err != nil {
			return generated.ExecutionReceipt{}, err
		}
	}
	observation := adapter.ReceiptObservation{Status: request.Receipt.Status, ResultDigest: request.Receipt.ResultDigest}
	if adapter.ValidateReceiptObservation(observation) != nil {
		return executor.recoveryRequired(ctx, current, step, lease, attribution)
	}
	if request.Receipt.Status == "running" {
		if !bindingExact || lease.Status != "active" || !now.Before(parseTime(lease.LeaseExpiresAt)) {
			return executor.recoveryRequired(ctx, current, step, lease, attribution)
		}
		return request.Receipt, nil
	}
	verification, verifyErr := verifier.VerifyReceipt(ctx, operation, observation)
	if !bindingExact || lease.Status != "active" || !now.Before(parseTime(lease.LeaseExpiresAt)) || verifyErr != nil || adapter.ValidateReceiptVerification(verification) != nil || !verification.Verified || request.Receipt.Status == "partial" {
		return executor.recoveryRequired(ctx, current, step, lease, attribution)
	}
	updated, err := executor.runs.FinishStep(context.WithoutCancel(ctx), store.StepFinishRequest{
		RunID: current.RunID, StepID: step.StepID, LeaseID: lease.LeaseID, Receipt: request.Receipt,
		Status: request.Receipt.Status, EffectState: "verified", VerificationDigest: verification.Digest,
		Changed: verification.Changed, At: now, Attribution: attribution,
	})
	if err != nil {
		return generated.ExecutionReceipt{}, err
	}
	if err := executor.runs.ReleaseTargetLease(context.WithoutCancel(ctx), lease.LeaseID, now); err != nil {
		return generated.ExecutionReceipt{}, err
	}
	if request.Receipt.Status == "failed" {
		changed := updated.Changed
		_, err = executor.runs.TransitionRun(context.WithoutCancel(ctx), store.RunTransitionRequest{RunID: updated.RunID, From: "running", To: "failed", At: now, VerificationStatus: "failed", Changed: &changed, Attribution: attribution})
		return request.Receipt, err
	}
	if updated.CancellationRequested && !allStepsVerified(updated) {
		_, err = executor.runs.TransitionRun(context.WithoutCancel(ctx), store.RunTransitionRequest{RunID: updated.RunID, From: "running", To: "interrupted", At: now, VerificationStatus: "incomplete", Attribution: attribution})
		return request.Receipt, err
	}
	if allStepsVerified(updated) {
		digest := digest("run-verification", updated.RunID, updated.PlanDigest)
		_, err = executor.runs.TransitionRun(context.WithoutCancel(ctx), store.RunTransitionRequest{RunID: updated.RunID, From: "running", To: "succeeded", At: now, VerificationStatus: "verified", VerificationDigest: &digest, Attribution: attribution})
		if err != nil {
			return generated.ExecutionReceipt{}, err
		}
	}
	return request.Receipt, nil
}

// Reconcile expires external leases and records every resulting ambiguous
// effect as partial/recovery-required. It is safe to call before every protocol
// operation and from the server's periodic integrity cycle.
func (executor *ExternalExecutor) Reconcile(ctx context.Context) error {
	if executor == nil {
		return runError(generated.ErrorCodeInputInvalid, "external-executor")
	}
	expired, err := executor.leases.Expire(ctx, store.ExecutorLeaseExpiryRequest{At: executor.now(), Attribution: systemAttribution()})
	if err != nil {
		return err
	}
	for _, lease := range expired {
		current, err := executor.runs.GetRun(ctx, lease.RunID)
		if err != nil {
			return err
		}
		step := findRunStep(current, lease.StepID)
		if current.Status != "running" || step == nil || (step.Status != "running" && !(step.Status == "partial" && step.EffectState == "effect-unknown")) {
			continue
		}
		if _, err := executor.recoveryRequired(ctx, current, *step, lease, systemAttribution()); Code(err) != generated.ErrorCodeRecoveryRequired {
			return err
		}
	}
	return nil
}

func (executor *ExternalExecutor) boundLease(ctx context.Context, principal identity.Principal, leaseID string, evidence []generated.ContractExtension) (generated.ExecutorLease, generated.Run, generated.Plan, generated.RunStep, error) {
	lease, err := executor.leases.Get(ctx, leaseID)
	if err != nil {
		return generated.ExecutorLease{}, generated.Run{}, generated.Plan{}, generated.RunStep{}, err
	}
	current, err := executor.runs.GetRun(ctx, lease.RunID)
	if err != nil {
		return generated.ExecutorLease{}, generated.Run{}, generated.Plan{}, generated.RunStep{}, err
	}
	stored, err := executor.plans.Get(ctx, current.PlanID)
	if err != nil {
		return generated.ExecutorLease{}, generated.Run{}, generated.Plan{}, generated.RunStep{}, err
	}
	step := findRunStep(current, lease.StepID)
	if step == nil || generated.ValidateExecutorLeaseBinding(stored.Plan, current, lease) != nil {
		return generated.ExecutorLease{}, generated.Run{}, generated.Plan{}, generated.RunStep{}, runError(generated.ErrorCodeIntegrityFailure, "executor-lease-binding")
	}
	claim := generated.ExecutorClaimRequest{ExecutorID: lease.ExecutorID, PrincipalID: principal.ID, AdapterID: lease.AdapterID, RecoveryEpoch: lease.RecoveryEpoch, Extensions: evidence}
	if _, ok := authorization.BindExternalExecutorIdentity(principal, claim, stored.Plan, *step); !ok {
		return generated.ExecutorLease{}, generated.Run{}, generated.Plan{}, generated.RunStep{}, executor.authorizationDenied(ctx, principal, "lease-identity", lease.LeaseID)
	}
	return lease, current, stored.Plan, *step, nil
}

func (executor *ExternalExecutor) recoveryRequired(ctx context.Context, current generated.Run, step generated.RunStep, lease generated.ExecutorLease, attribution audit.Attribution) (generated.ExecutionReceipt, error) {
	cleanup := context.WithoutCancel(ctx)
	updated := current
	if step.Status == "running" && (step.EffectState == "intent-recorded" || step.EffectState == "receipt-recorded") {
		var err error
		updated, err = executor.runs.MarkStepUnknown(cleanup, current.RunID, step.StepID, executor.now(), attribution)
		if err != nil {
			return generated.ExecutionReceipt{}, err
		}
	}
	updatedStep := findRunStep(updated, step.StepID)
	if updated.Status == "running" && updatedStep != nil && updatedStep.EffectState == "effect-unknown" {
		changed := true
		if _, err := executor.runs.TransitionRun(cleanup, store.RunTransitionRequest{RunID: updated.RunID, From: "running", To: "partial", At: executor.now(), VerificationStatus: "incomplete", RollbackStatus: "required", Changed: &changed, Attribution: attribution}); err != nil {
			return generated.ExecutionReceipt{}, err
		}
	}
	if lease.Status == "active" {
		if err := executor.runs.ReleaseTargetLease(cleanup, lease.LeaseID, executor.now()); err != nil {
			return generated.ExecutionReceipt{}, err
		}
	}
	return generated.ExecutionReceipt{}, runError(generated.ErrorCodeRecoveryRequired, "executor-reconciliation")
}

func (executor *ExternalExecutor) authorizationDenied(ctx context.Context, principal identity.Principal, reason, target string) error {
	if err := executor.recordAuthorizationDenial(ctx, principal, reason, target); err != nil {
		return err
	}
	return runError(generated.ErrorCodeAuthorizationDenied, "executor-authorization")
}

func (executor *ExternalExecutor) recordAuthorizationDenial(ctx context.Context, principal identity.Principal, reason, target string) error {
	attribution, err := externalAttribution(principal)
	if err != nil {
		return err
	}
	return executor.leases.RecordAuthorizationDenial(context.WithoutCancel(ctx), store.ExecutorAuthorizationDenialRequest{
		ReasonFingerprint: audit.Fingerprint(digest("executor-denial-reason", reason)),
		TargetFingerprint: audit.Fingerprint(digest("executor-denial-target", target)),
		At:                executor.now(), Attribution: attribution,
	})
}

func (executor *ExternalExecutor) now() time.Time {
	return executor.clock().UTC().Truncate(time.Second)
}

func externalAttribution(principal identity.Principal) (audit.Attribution, error) {
	value, err := audit.NewAttribution(principal, nil, nil)
	if err != nil {
		return audit.Attribution{}, runError(generated.ErrorCodeIntegrityFailure, "executor-attribution")
	}
	return value, nil
}

func allStepsVerified(run generated.Run) bool {
	if len(run.Steps) == 0 {
		return false
	}
	for _, step := range run.Steps {
		if step.Status != "succeeded" || step.EffectState != "verified" {
			return false
		}
	}
	return true
}
