package run

import (
	"context"

	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/generated"
)

// guardedLifecycleVerify never relays a verifier panic or error payload. The
// verifier owns and closes any borrowed credentialref.Value before returning;
// this boundary receives metadata only. An interrupted call may already have
// restarted a consumer, so its result is always uncertain.
func guardedLifecycleVerify(ctx context.Context, verifier CredentialLifecycleVerifier, binding ExactStepBinding, lifecycle credentialref.LifecycleBinding) (results []credentialref.ConsumerVerification, err error) {
	if _, unavailable := verifier.(UnavailableCredentialLifecycleVerifier); unavailable {
		// This built-in sentinel cannot have observed an external effect. Keep
		// its established stable denial target and pre-effect semantics.
		return verifier.Verify(ctx, binding, lifecycle)
	}
	defer func() {
		if recover() != nil {
			results = nil
			err = runError(generated.ErrorCodeRecoveryRequired, "credential-consumer-verify-uncertain")
		}
	}()
	results, err = verifier.Verify(ctx, binding, lifecycle)
	if ctx.Err() != nil {
		return nil, runError(generated.ErrorCodeRecoveryRequired, "credential-consumer-verify-uncertain")
	}
	if err != nil {
		return nil, redactedVerifierError(err, "credential-consumer-verify")
	}
	return results, nil
}

// guardedRecoveryVerify applies the same uncertain-effect and redaction
// boundary to clean-host custody/fence verification.
func guardedRecoveryVerify(ctx context.Context, verifier CredentialRecoveryVerifier, binding ExactStepBinding, lifecycle credentialref.LifecycleBinding) (result credentialref.RecoveryVerification, err error) {
	if _, unavailable := verifier.(UnavailableCredentialRecoveryVerifier); unavailable {
		return verifier.Verify(ctx, binding, lifecycle)
	}
	defer func() {
		if recover() != nil {
			result = credentialref.RecoveryVerification{}
			err = runError(generated.ErrorCodeRecoveryRequired, "credential-recovery-verify-uncertain")
		}
	}()
	result, err = verifier.Verify(ctx, binding, lifecycle)
	if ctx.Err() != nil {
		return credentialref.RecoveryVerification{}, runError(generated.ErrorCodeRecoveryRequired, "credential-recovery-verify-uncertain")
	}
	if err != nil {
		return credentialref.RecoveryVerification{}, redactedVerifierError(err, "credential-recovery-verify")
	}
	return result, nil
}

func redactedVerifierError(err error, target string) error {
	// Preserve only stable codes already declared by the platform. An
	// arbitrary error is uncertain, never a string to format or wrap.
	switch code := Code(err); code {
	case generated.ErrorCodeRateLimited,
		generated.ErrorCodeDependencyUnavailable,
		generated.ErrorCodeAuthorizationDenied,
		generated.ErrorCodePrerequisiteBlocked,
		generated.ErrorCodeIntegrityFailure,
		generated.ErrorCodeRecoveryEpochMismatch:
		return runError(code, target)
	default:
		return runError(generated.ErrorCodeRecoveryRequired, target+"-uncertain")
	}
}
