package recovery

import (
	"context"

	"github.com/vegastack/vegastack-labs/internal/adapter"
	"github.com/vegastack/vegastack-labs/internal/audit"
	"github.com/vegastack/vegastack-labs/internal/change"
	"github.com/vegastack/vegastack-labs/internal/failure"
	"github.com/vegastack/vegastack-labs/internal/generated"
	runengine "github.com/vegastack/vegastack-labs/internal/run"
	"github.com/vegastack/vegastack-labs/internal/store"
)

type RecoveryCanaryRecorder interface {
	RecordRecoveryCanaryNoop(context.Context, store.RecoveryCanaryNoopRequest) error
}

// BoundCanaryNoop executes the subordinate no-op whose exact IDs were sealed
// into the acknowledged restore request. Normal run tables remain unavailable
// during recovery-required; the dedicated store journal is its bounded,
// append-only equivalent and uses the same CoreRouter/RecoveryEffect boundary.
type BoundCanaryNoop struct {
	Restores RecoveredBundleReader
	Core     runengine.CoreEffect
	Recorder RecoveryCanaryRecorder
}

func (runner BoundCanaryNoop) RunRecoveryCanaryNoop(ctx context.Context, request CanaryRequest) (string, error) {
	blocked := func() (string, error) {
		return "", failure.New(generated.ErrorCodeRecoveryRequired, "recovery-canary-noop", false)
	}
	if ctx == nil || ctx.Err() != nil || runner.Restores == nil || runner.Core == nil || runner.Recorder == nil || request.ResponsibleHumanID == "" || request.PrincipalMethod == "" {
		return blocked()
	}
	bundle, _, err := runner.Restores.RecoveredAuthorityBundle(ctx, request.PlanID)
	if err != nil || bundle.Status != "verification-required" || bundle.Binding.PlanDigest != request.PlanDigest || bundle.Binding.NewInstanceID != request.NewInstanceID || bundle.Binding.NextRecoveryEpoch != request.RecoveryEpoch || bundle.Binding.FenceSetDigest != request.FenceSetDigest || bundle.Binding.HumanAcknowledgementID == "" {
		return blocked()
	}
	digest, digestErr := change.RestoreCanaryBindingDigest(bundle.Request)
	if digestErr != nil || digest != bundle.Binding.CanaryBindingDigest || digest != bundle.Request.CanaryBindingDigest {
		return blocked()
	}
	plan := bundle.Plan
	if len(plan.Operations) != 2 {
		return blocked()
	}
	operation := plan.Operations[1]
	if operation.Sequence != 2 || operation.OperationID != bundle.Binding.CanaryStepID || operation.OperationType != "recovery.canary.noop" || operation.AdapterID != "core.recovery" || operation.TargetID != request.NewInstanceID || operation.InputDigest != digest || operation.ArtifactDigest != digest || !operation.Idempotent {
		return blocked()
	}
	acknowledgement := bundle.Binding.HumanAcknowledgementID
	run := generated.Run{RunID: bundle.Binding.CanaryRunID, PlanID: bundle.Plan.PlanID, PlanDigest: bundle.Plan.PlanDigest, AcknowledgementID: &acknowledgement, ExecutorMode: "central", StateRevision: request.ExpectedStateRevision, RecoveryEpoch: request.RecoveryEpoch}
	step := generated.RunStep{StepID: bundle.Binding.CanaryStepID, OperationID: operation.OperationID, OperationType: operation.OperationType, AdapterID: operation.AdapterID, ExecutorID: operation.ExecutorID, TargetID: operation.TargetID, InputDigest: digest, ArtifactDigest: digest, Idempotent: true, Status: "running", EffectState: "intent-recorded"}
	lease := generated.ExecutorLease{LeaseID: bundle.Binding.CanaryLeaseID, PlanID: bundle.Plan.PlanID, PlanDigest: bundle.Plan.PlanDigest, RunID: run.RunID, StepID: step.StepID, OperationID: operation.OperationID, ExecutorID: operation.ExecutorID, AdapterID: operation.AdapterID, TargetID: operation.TargetID, ArtifactDigest: digest, RecoveryEpoch: request.RecoveryEpoch, Status: "active"}
	human := request.ResponsibleHumanID
	binding := runengine.ExactStepBinding{Plan: plan, Run: run, Step: step, Lease: lease, Attribution: audit.Attribution{AuthenticatedPrincipalID: human, AuthenticatedPrincipalMethod: request.PrincipalMethod, ResponsibleHumanPrincipalID: &human}}
	effect, err := runner.Core.Execute(ctx, binding)
	if err != nil || adapter.ValidateEffect(effect) != nil || effect.Status != "succeeded" || effect.Changed || !effect.EffectObserved {
		return blocked()
	}
	verification, err := runner.Core.Verify(ctx, binding, effect)
	if err != nil || adapter.ValidateVerification(verification) != nil || !verification.Verified || verification.Digest != effect.ResultDigest {
		return blocked()
	}
	if err := runner.Recorder.RecordRecoveryCanaryNoop(ctx, store.RecoveryCanaryNoopRequest{PlanID: bundle.Plan.PlanID, PlanDigest: bundle.Plan.PlanDigest, RunID: run.RunID, StepID: step.StepID, LeaseID: lease.LeaseID, InstanceID: request.NewInstanceID, RecoveryEpoch: request.RecoveryEpoch, StateRevision: request.ExpectedStateRevision, ResultDigest: effect.ResultDigest, Attribution: binding.Attribution}); err != nil {
		return blocked()
	}
	return run.RunID, nil
}
