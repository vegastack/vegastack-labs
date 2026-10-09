package run

import (
	"context"
	"github.com/vegastack/vegastack-labs/internal/audit"
	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/generated"
)

// NativeRestartVerifier is narrowly implemented by the installed native
// verifier. A queued self-restart never counts as verified delivery.
type NativeRestartVerifier interface {
	PrepareNativeRestart(context.Context, ExactStepBinding, credentialref.LifecycleBinding) (credentialref.NativeRestartPending, bool, error)
	EnqueueNativeRestart(context.Context, credentialref.NativeRestartPending) error
	VerifyNativeContinuation(context.Context, ExactStepBinding, credentialref.LifecycleBinding, credentialref.NativeRestartPending) ([]credentialref.ConsumerVerification, error)
}
type nativeRestartRepository interface {
	RecordNativeRestartPending(context.Context, credentialref.NativeRestartPending, audit.Attribution) error
	ReadNativeRestartPending(context.Context, string, string) (credentialref.NativeRestartPending, error)
}

func (e *CoreCredentialEffect) verifyLifecycle(ctx context.Context, step ExactStepBinding, b credentialref.LifecycleBinding) (results []credentialref.ConsumerVerification, outcome error) {
	defer func() {
		if recover() != nil {
			results = nil
			outcome = runError(generated.ErrorCodeRecoveryRequired, "credential-consumer-verify-uncertain")
		}
		if ctx.Err() != nil {
			results = nil
			outcome = runError(generated.ErrorCodeRecoveryRequired, "credential-consumer-verify-uncertain")
		}
		if outcome != nil {
			outcome = redactedVerifierError(outcome, "credential-consumer-verify")
		}
	}()
	v, ok := e.lifecycleVerifier.(NativeRestartVerifier)
	if b.NativeRestartContinuation != nil {
		r, stored := e.repository.(nativeRestartRepository)
		if !ok || !stored {
			return nil, runError(generated.ErrorCodePrerequisiteBlocked, "native-restart-continuation")
		}
		c := b.NativeRestartContinuation
		pending, err := r.ReadNativeRestartPending(ctx, c.PriorRunID, c.PriorStepID)
		if err != nil || !credentialref.PendingMatchesLifecycle(pending, b) {
			return nil, runError(generated.ErrorCodePrerequisiteBlocked, "native-restart-prior-attempt")
		}
		return v.VerifyNativeContinuation(ctx, step, b, pending)
	}
	if ok && b.HostActionConsole != nil && b.ResolverID == "native-systemd" && len(b.ConsumerIDs) == 1 && b.ConsumerIDs[0] == "host-action" {
		pending, self, err := v.PrepareNativeRestart(ctx, step, b)
		if err != nil {
			return nil, err
		}
		if self {
			r, stored := e.repository.(nativeRestartRepository)
			if !stored {
				return nil, runError(generated.ErrorCodePrerequisiteBlocked, "native-restart-persistence")
			}
			if err := r.RecordNativeRestartPending(ctx, pending, step.Attribution); err != nil {
				return nil, err
			}
			if err := v.EnqueueNativeRestart(ctx, pending); err != nil {
				return nil, err
			}
			return nil, runError(generated.ErrorCodePrerequisiteBlocked, "native-restart-awaits-new-plan")
		}
	}
	return guardedLifecycleVerify(ctx, e.lifecycleVerifier, step, b)
}
