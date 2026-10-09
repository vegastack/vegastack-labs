//go:build linux

package server

import (
	"context"
	"path/filepath"

	"github.com/vegastack/vegastack-labs/internal/adapter/nativecredential"
	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/run"
)

type nativeLifecycleRunVerifier struct {
	native *nativecredential.NativeLifecycleVerifier
}

func (v nativeLifecycleRunVerifier) Verify(ctx context.Context, step run.ExactStepBinding, binding credentialref.LifecycleBinding) ([]credentialref.ConsumerVerification, error) {
	return v.native.VerifyNative(ctx, nativecredential.NativeVerificationStep{
		OperationID: step.Step.OperationID, OperationType: step.Step.OperationType, TargetID: step.Step.TargetID, ArtifactDigest: step.Step.ArtifactDigest,
		PlanID: step.Plan.PlanID, LeaseID: step.Lease.LeaseID, PlanDigest: step.Plan.PlanDigest, RunID: step.Run.RunID, StepID: step.Step.StepID,
	}, binding)
}

func composeNativeCredentialLifecycleVerifier(ctx context.Context, databasePath string, ownerUID uint32) run.CredentialLifecycleVerifier {
	root := filepath.Join(filepath.Dir(databasePath), "credential-drafts")
	verifier, err := nativecredential.NewInstalledNativeLifecycleVerifier(ctx, root, ownerUID)
	if err != nil {
		return run.UnavailableCredentialLifecycleVerifier{}
	}
	return nativeLifecycleRunVerifier{native: verifier}
}

func nativeRestartStep(step run.ExactStepBinding) nativecredential.NativeVerificationStep {
	return nativecredential.NativeVerificationStep{OperationID: step.Step.OperationID, OperationType: step.Step.OperationType, TargetID: step.Step.TargetID, ArtifactDigest: step.Step.ArtifactDigest, PlanID: step.Plan.PlanID, PlanDigest: step.Plan.PlanDigest, RunID: step.Run.RunID, StepID: step.Step.StepID, LeaseID: step.Lease.LeaseID}
}
func (v nativeLifecycleRunVerifier) PrepareNativeRestart(ctx context.Context, step run.ExactStepBinding, b credentialref.LifecycleBinding) (credentialref.NativeRestartPending, bool, error) {
	return v.native.PrepareNativeRestart(ctx, nativeRestartStep(step), b)
}
func (v nativeLifecycleRunVerifier) EnqueueNativeRestart(ctx context.Context, p credentialref.NativeRestartPending) error {
	return v.native.EnqueueNativeRestart(ctx, p)
}
func (v nativeLifecycleRunVerifier) VerifyNativeContinuation(ctx context.Context, step run.ExactStepBinding, b credentialref.LifecycleBinding, p credentialref.NativeRestartPending) ([]credentialref.ConsumerVerification, error) {
	return v.native.VerifyNativeContinuation(ctx, nativeRestartStep(step), b, p)
}
