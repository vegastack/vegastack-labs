package run

import (
	"context"
	"crypto/sha256"
	"encoding/hex"

	"github.com/vegastack/vegastack-labs/internal/adapter"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/store"
)

// RecoveryAuthorityReader is deliberately read-only. The canary no-op proves
// that the normal exact-step machinery reached the promoted authority while
// that authority is still recovery-required; it grants no mutation itself.
type RecoveryAuthorityReader interface {
	CurrentAuthority(context.Context) (store.AuthorityState, error)
	Health(context.Context) (store.Health, error)
}

type RecoveryEffect struct{ authority RecoveryAuthorityReader }

func NewRecoveryEffect(authority RecoveryAuthorityReader) (*RecoveryEffect, error) {
	if authority == nil {
		return nil, runError(generated.ErrorCodeInputInvalid, "recovery-effect")
	}
	return &RecoveryEffect{authority: authority}, nil
}

func (effect *RecoveryEffect) Execute(ctx context.Context, binding ExactStepBinding) (adapter.Effect, error) {
	if effect == nil || effect.authority == nil || !exactRecoveryCanaryBinding(binding) {
		return adapter.Effect{}, runError(generated.ErrorCodePrerequisiteBlocked, "recovery-canary-binding")
	}
	state, err := effect.authority.CurrentAuthority(ctx)
	if err != nil {
		return adapter.Effect{}, err
	}
	health, err := effect.authority.Health(ctx)
	if err != nil {
		return adapter.Effect{}, err
	}
	if state.InstanceID != binding.Step.TargetID || state.RecoveryEpoch != binding.Run.RecoveryEpoch || state.Mode != "recovery-required" ||
		health.Revision.StateRevision != binding.Run.StateRevision || health.Revision.RecoveryEpoch != binding.Run.RecoveryEpoch ||
		!health.RecoveryPending || health.MutationEnabled {
		return adapter.Effect{}, runError(generated.ErrorCodeRecoveryRequired, "recovery-canary-authority")
	}
	digest := recoveryCanaryDigest(binding)
	return adapter.Effect{Status: "succeeded", ResultDigest: digest, Changed: false, EffectObserved: true}, nil
}

func (effect *RecoveryEffect) Verify(ctx context.Context, binding ExactStepBinding, result adapter.Effect) (adapter.Verification, error) {
	if effect == nil || effect.authority == nil || !exactRecoveryCanaryBinding(binding) || adapter.ValidateEffect(result) != nil ||
		result.Status != "succeeded" || result.Changed || !result.EffectObserved || result.ResultDigest != recoveryCanaryDigest(binding) {
		return adapter.Verification{}, runError(generated.ErrorCodeIntegrityFailure, "recovery-canary-noop")
	}
	state, err := effect.authority.CurrentAuthority(ctx)
	if err != nil {
		return adapter.Verification{}, err
	}
	health, err := effect.authority.Health(ctx)
	if err != nil {
		return adapter.Verification{}, err
	}
	if state.InstanceID != binding.Step.TargetID || state.RecoveryEpoch != binding.Run.RecoveryEpoch || state.Mode != "recovery-required" ||
		health.Revision.StateRevision != binding.Run.StateRevision || health.Revision.RecoveryEpoch != binding.Run.RecoveryEpoch || !health.RecoveryPending || health.MutationEnabled {
		return adapter.Verification{}, runError(generated.ErrorCodeRecoveryRequired, "recovery-canary-authority")
	}
	return adapter.Verification{Verified: true, Digest: result.ResultDigest}, nil
}

func exactRecoveryCanaryBinding(binding ExactStepBinding) bool {
	return binding.Plan.AuthorizationBranch == "human" && binding.Plan.ExecutorMode == "central" && binding.Run.ExecutorMode == "central" && binding.Run.AcknowledgementID != nil &&
		binding.Step.AdapterID == "core.recovery" && binding.Step.OperationType == "recovery.canary.noop" && binding.Step.TargetID != "" &&
		binding.Step.InputDigest == binding.Step.ArtifactDigest && binding.Step.EffectState == "intent-recorded" && binding.Lease.Status == "active" &&
		binding.Lease.PlanID == binding.Plan.PlanID && binding.Lease.PlanDigest == binding.Plan.PlanDigest && binding.Lease.RunID == binding.Run.RunID &&
		binding.Lease.StepID == binding.Step.StepID && binding.Lease.ArtifactDigest == binding.Step.ArtifactDigest &&
		binding.Plan.Binding.StateRevision == binding.Run.StateRevision && binding.Plan.Binding.RecoveryEpoch == binding.Run.RecoveryEpoch &&
		binding.Lease.RecoveryEpoch == binding.Run.RecoveryEpoch
}

func recoveryCanaryDigest(binding ExactStepBinding) string {
	hash := sha256.New()
	for _, value := range []string{"vegastack-labs.dev/recovery-canary-noop/v1", binding.Plan.PlanID, binding.Plan.PlanDigest, binding.Run.RunID, binding.Step.StepID, binding.Lease.LeaseID, binding.Step.TargetID, binding.Step.ArtifactDigest} {
		_, _ = hash.Write([]byte(value))
		_, _ = hash.Write([]byte{0})
	}
	return "sha256:" + hex.EncodeToString(hash.Sum(nil))
}
