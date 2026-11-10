//go:build linux

package server

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/vegastack/vegastack-labs/internal/adapter/nativecredential"
	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/run"
)

type nativeLifecycleRunVerifier struct {
	native           *nativecredential.NativeLifecycleVerifier
	loadedCredential controllerLoadedCredentialCheck
}

func (v nativeLifecycleRunVerifier) Verify(ctx context.Context, step run.ExactStepBinding, binding credentialref.LifecycleBinding) ([]credentialref.ConsumerVerification, error) {
	if v.loadedCredential != nil && binding.HostActionConsole == nil && len(binding.NativeConsumers) == 1 && binding.NativeConsumers[0].UnitName == "vsk-labs.service" && !ingressNativeLifecycle(binding) {
		if !v.loadedCredential(ctx, binding) {
			return nil, fmt.Errorf("controller credential scope unavailable")
		}
		// A declared unit is insufficient: its current main process must be this controller.
		u, err := v.native.Units.ObserveAppliedUnit(ctx, binding.NativeConsumers[0].UnitName)
		if err != nil || u.MainPID != uint32(os.Getpid()) {
			return nil, fmt.Errorf("controller credential consumer mismatch")
		}
		return v.native.VerifyNativeLoaded(ctx, nativeRestartStep(step), binding)
	}
	if ingressNativeLifecycle(binding) {
		return v.native.VerifyNativeLoaded(ctx, nativeRestartStep(step), binding)
	}
	return v.native.VerifyNative(ctx, nativecredential.NativeVerificationStep{
		OperationID: step.Step.OperationID, OperationType: step.Step.OperationType, TargetID: step.Step.TargetID, ArtifactDigest: step.Step.ArtifactDigest,
		PlanID: step.Plan.PlanID, LeaseID: step.Lease.LeaseID, PlanDigest: step.Plan.PlanDigest, RunID: step.Run.RunID, StepID: step.Step.StepID,
	}, binding)
}

func composeNativeCredentialLifecycleVerifier(ctx context.Context, databasePath string, ownerUID uint32, loaded ...controllerLoadedCredentialCheck) run.CredentialLifecycleVerifier {
	root := filepath.Join(filepath.Dir(databasePath), "credential-drafts")
	verifier, err := nativecredential.NewInstalledNativeLifecycleVerifier(ctx, root, ownerUID)
	if err != nil {
		fmt.Fprintln(os.Stderr, "native credential lifecycle verifier unavailable:", err)
		return run.UnavailableCredentialLifecycleVerifier{}
	}
	out := nativeLifecycleRunVerifier{native: verifier}
	if len(loaded) == 1 {
		out.loadedCredential = loaded[0]
	}
	return out
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
