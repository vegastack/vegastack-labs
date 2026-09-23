package recovery

import (
	"context"

	"github.com/vegastack/vegastack-labs/internal/failure"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/store"
)

// Unavailable canary ports make absent site capabilities explicit in the
// production graph. They cannot be mistaken for successful fixture evidence.
type UnavailableCanaryNoop struct{}

func (UnavailableCanaryNoop) RunRecoveryCanaryNoop(context.Context, CanaryRequest) (string, error) {
	return "", unavailableCanaryPort("recovery-canary-noop")
}

type UnavailableCanaryAudit struct{}

func (UnavailableCanaryAudit) AppendAndVerifyRecoveryCheckpoint(context.Context, CanaryRequest, string) (string, error) {
	return "", unavailableCanaryPort("recovery-canary-audit")
}

type UnavailableCanaryBackup struct{}

func (UnavailableCanaryBackup) CreateAndVerifyRecoveryBackup(context.Context, CanaryRequest) (string, error) {
	return "", unavailableCanaryPort("recovery-canary-backup")
}

func unavailableCanaryPort(target string) error {
	return failure.New(generated.ErrorCodePrerequisiteBlocked, target, false)
}

type RecoveredBundleReader interface {
	RecoveredAuthorityBundle(context.Context, string) (store.RecoveredAuthorityBundle, string, error)
}

type ExactFenceRefresher interface {
	Verify(context.Context, generated.RestoreBinding, int64, []generated.RestoreFenceItem) (FenceResult, error)
}

// FreshFormerWriterCanary reloads the immutable recovered bundle and runs the
// #135 exact verifier again. That verifier reloads the protected package and
// invokes every qualified direct-denial adapter at the current time.
type FreshFormerWriterCanary struct {
	Restores RecoveredBundleReader
	Fences   ExactFenceRefresher
}

func (verifier FreshFormerWriterCanary) VerifyFormerWriterDenied(ctx context.Context, request CanaryRequest) error {
	if ctx == nil || ctx.Err() != nil || verifier.Restores == nil || verifier.Fences == nil {
		return unavailableCanaryPort("recovery-canary-former-writer")
	}
	bundle, _, err := verifier.Restores.RecoveredAuthorityBundle(ctx, request.PlanID)
	if err != nil || bundle.Status != "verification-required" || bundle.Binding.PlanDigest != request.PlanDigest ||
		bundle.Binding.NewInstanceID != request.NewInstanceID || bundle.Binding.NextRecoveryEpoch != request.RecoveryEpoch ||
		bundle.Binding.FenceSetDigest != request.FenceSetDigest {
		return unavailableCanaryPort("recovery-canary-former-writer")
	}
	result, err := verifier.Fences.Verify(ctx, bundle.Binding, request.ExpectedStateRevision, bundle.Request.Fences)
	if err != nil || result.FenceSetDigest != request.FenceSetDigest {
		return unavailableCanaryPort("recovery-canary-former-writer")
	}
	return nil
}
