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
		PlanDigest: step.Plan.PlanDigest, RunID: step.Run.RunID, StepID: step.Step.StepID,
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
