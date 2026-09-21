package run

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/generated"
)

type lifecycleVerifierFunc func(context.Context, ExactStepBinding, credentialref.LifecycleBinding) ([]credentialref.ConsumerVerification, error)

func (fn lifecycleVerifierFunc) Verify(ctx context.Context, binding ExactStepBinding, lifecycle credentialref.LifecycleBinding) ([]credentialref.ConsumerVerification, error) {
	return fn(ctx, binding, lifecycle)
}

type recoveryVerifierFunc func(context.Context, ExactStepBinding, credentialref.LifecycleBinding) (credentialref.RecoveryVerification, error)

func (fn recoveryVerifierFunc) Verify(ctx context.Context, binding ExactStepBinding, lifecycle credentialref.LifecycleBinding) (credentialref.RecoveryVerification, error) {
	return fn(ctx, binding, lifecycle)
}

func TestCredentialVerifierBoundaryDiscardsPanicAndRawError(t *testing.T) {
	canary := "secret=" + strings.Repeat("s", 32)
	for _, test := range []struct {
		name string
		call func() error
	}{
		{"lifecycle panic", func() error {
			_, err := guardedLifecycleVerify(context.Background(), lifecycleVerifierFunc(func(context.Context, ExactStepBinding, credentialref.LifecycleBinding) ([]credentialref.ConsumerVerification, error) {
				panic(canary)
			}), ExactStepBinding{}, credentialref.LifecycleBinding{})
			return err
		}},
		{"recovery panic", func() error {
			_, err := guardedRecoveryVerify(context.Background(), recoveryVerifierFunc(func(context.Context, ExactStepBinding, credentialref.LifecycleBinding) (credentialref.RecoveryVerification, error) {
				panic(canary)
			}), ExactStepBinding{}, credentialref.LifecycleBinding{})
			return err
		}},
		{"lifecycle raw error", func() error {
			_, err := guardedLifecycleVerify(context.Background(), lifecycleVerifierFunc(func(context.Context, ExactStepBinding, credentialref.LifecycleBinding) ([]credentialref.ConsumerVerification, error) {
				return nil, errors.New(canary)
			}), ExactStepBinding{}, credentialref.LifecycleBinding{})
			return err
		}},
		{"recovery raw error", func() error {
			_, err := guardedRecoveryVerify(context.Background(), recoveryVerifierFunc(func(context.Context, ExactStepBinding, credentialref.LifecycleBinding) (credentialref.RecoveryVerification, error) {
				return credentialref.RecoveryVerification{}, errors.New(canary)
			}), ExactStepBinding{}, credentialref.LifecycleBinding{})
			return err
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := test.call()
			if Code(err) != generated.ErrorCodeRecoveryRequired || strings.Contains(err.Error(), canary) {
				t.Fatalf("uncertain verifier exposed panic/error or lost recovery code: %v", err)
			}
		})
	}
}

func TestCredentialVerifierBoundaryTreatsCancellationAfterObservationAsUncertain(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	_, err := guardedLifecycleVerify(ctx, lifecycleVerifierFunc(func(context.Context, ExactStepBinding, credentialref.LifecycleBinding) ([]credentialref.ConsumerVerification, error) {
		cancel()
		return nil, nil
	}), ExactStepBinding{}, credentialref.LifecycleBinding{})
	if Code(err) != generated.ErrorCodeRecoveryRequired {
		t.Fatalf("cancel after lifecycle observation did not require recovery: %v", err)
	}
	ctx, cancel = context.WithCancel(context.Background())
	defer cancel()
	_, err = guardedRecoveryVerify(ctx, recoveryVerifierFunc(func(context.Context, ExactStepBinding, credentialref.LifecycleBinding) (credentialref.RecoveryVerification, error) {
		cancel()
		return credentialref.RecoveryVerification{}, nil
	}), ExactStepBinding{}, credentialref.LifecycleBinding{})
	if Code(err) != generated.ErrorCodeRecoveryRequired {
		t.Fatalf("cancel after recovery observation did not require recovery: %v", err)
	}
}

func TestCredentialVerifierBoundaryPreservesOnlyStableCode(t *testing.T) {
	_, err := guardedLifecycleVerify(context.Background(), lifecycleVerifierFunc(func(context.Context, ExactStepBinding, credentialref.LifecycleBinding) ([]credentialref.ConsumerVerification, error) {
		return nil, runError(generated.ErrorCodeRateLimited, "private-provider-path")
	}), ExactStepBinding{}, credentialref.LifecycleBinding{})
	if Code(err) != generated.ErrorCodeRateLimited || strings.Contains(err.Error(), "private-provider-path") {
		t.Fatalf("stable rate-limit code was lost or provider target leaked: %v", err)
	}
}
