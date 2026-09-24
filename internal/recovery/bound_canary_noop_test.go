package recovery

import (
	"context"
	"strings"
	"testing"

	"github.com/vegastack/vegastack-labs/internal/adapter"
	"github.com/vegastack/vegastack-labs/internal/change"
	"github.com/vegastack/vegastack-labs/internal/generated"
	runengine "github.com/vegastack/vegastack-labs/internal/run"
	"github.com/vegastack/vegastack-labs/internal/store"
)

type recoveryCoreStub struct{ binding runengine.ExactStepBinding }

func (stub *recoveryCoreStub) Execute(_ context.Context, binding runengine.ExactStepBinding) (adapter.Effect, error) {
	stub.binding = binding
	return adapter.Effect{Status: "succeeded", ResultDigest: binding.Step.ArtifactDigest, EffectObserved: true}, nil
}
func (*recoveryCoreStub) Verify(_ context.Context, _ runengine.ExactStepBinding, effect adapter.Effect) (adapter.Verification, error) {
	return adapter.Verification{Verified: true, Digest: effect.ResultDigest}, nil
}

type recoveryRecorderStub struct {
	request store.RecoveryCanaryNoopRequest
}

func (stub *recoveryRecorderStub) RecordRecoveryCanaryNoop(_ context.Context, request store.RecoveryCanaryNoopRequest) error {
	stub.request = request
	return nil
}

func TestBoundCanaryNoopUsesUnchangedAcknowledgedPlanOperation(t *testing.T) {
	digest := "sha256:" + strings.Repeat("a", 64)
	request := generated.RestoreRequest{TargetDigest: digest, FenceSetDigest: digest, CandidateDigest: digest, NewInstanceID: "instance-new", NextRecoveryEpoch: 3, CanaryRunID: "canary-run-a", CanaryStepID: "canary-step-a", CanaryLeaseID: "canary-lease-a"}
	request.CanaryBindingDigest, _ = change.RestoreCanaryBindingDigest(request)
	operation := generated.PlanOperation{Sequence: 2, OperationID: request.CanaryStepID, OperationType: "recovery.canary.noop", AdapterID: "core.recovery", ExecutorID: "executor-central", TargetID: request.NewInstanceID, InputDigest: request.CanaryBindingDigest, ArtifactDigest: request.CanaryBindingDigest, Idempotent: true}
	plan := generated.Plan{PlanID: "plan-a", PlanDigest: digest, AuthorizationBranch: "human", ExecutorMode: "central", Binding: generated.PlanBinding{RecoveryEpoch: 2, StateRevision: 10}, Operations: []generated.PlanOperation{{Sequence: 1, OperationType: "recovery.restore.cutover"}, operation}}
	binding := generated.RestoreBinding{PlanID: plan.PlanID, PlanDigest: plan.PlanDigest, HumanAcknowledgementID: "ack-a", NewInstanceID: request.NewInstanceID, NextRecoveryEpoch: request.NextRecoveryEpoch, FenceSetDigest: digest, CanaryRunID: request.CanaryRunID, CanaryStepID: request.CanaryStepID, CanaryLeaseID: request.CanaryLeaseID, CanaryChallengeID: request.CanaryChallengeID, CanaryReceiptID: request.CanaryReceiptID, CanaryBindingDigest: request.CanaryBindingDigest}
	bundle := store.RecoveredAuthorityBundle{Plan: plan, Request: request, Binding: binding, Status: "verification-required"}
	core, recorder := &recoveryCoreStub{}, &recoveryRecorderStub{}
	runner := BoundCanaryNoop{Restores: bundleReaderStub{bundle: bundle}, Core: core, Recorder: recorder}
	canary := CanaryRequest{PlanID: plan.PlanID, PlanDigest: plan.PlanDigest, NewInstanceID: request.NewInstanceID, FenceSetDigest: digest, RecoveryEpoch: 3, ExpectedStateRevision: 19, ResponsibleHumanID: "human-a", PrincipalMethod: "local-os-peer"}
	got, err := runner.RunRecoveryCanaryNoop(context.Background(), canary)
	if err != nil || got != request.CanaryRunID {
		t.Fatalf("run = %q, err = %v", got, err)
	}
	if core.binding.Plan.PlanDigest != plan.PlanDigest || len(core.binding.Plan.Operations) != 2 || core.binding.Step.OperationID != request.CanaryStepID || recorder.request.RunID != request.CanaryRunID || recorder.request.ResultDigest != request.CanaryBindingDigest {
		t.Fatalf("core=%#v recorder=%#v", core.binding, recorder.request)
	}
}
