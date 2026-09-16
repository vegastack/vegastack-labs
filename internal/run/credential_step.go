package run

import (
	"context"
	"slices"
	"time"

	"github.com/vegastack/vegastack-labs/internal/adapter"
	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/store"
)

type CredentialBindingSource interface {
	GetStepBindings(context.Context, generated.Plan, string) ([]credentialref.StepBinding, error)
	GetReference(context.Context, string) (generated.CredentialReference, error)
}
type CredentialResolverRegistry interface {
	ResolveCredentialResolver(string, string, string) (adapter.CredentialResolver, error)
	ResolveCredentialCapability(string, string, string) (string, error)
}
type CredentialProfileSource interface {
	GetAppliedProfileScope(context.Context) (store.GateAppliedProfile, error)
}
type CredentialPlanValidator interface {
	ValidateCurrent(context.Context, generated.Plan) error
}

// CredentialStep is server-owned JIT delivery. It never accepts a caller
// authored reference, artifact, profile, gate proof, or plaintext value.
type CredentialStep struct {
	Bindings  CredentialBindingSource
	Resolvers CredentialResolverRegistry
	Profiles  CredentialProfileSource
	Plans     CredentialPlanValidator
	Clock     func() time.Time
}

func credentialPlanDigest(plan generated.Plan) string {
	for _, extension := range plan.Extensions {
		if extension.Name == "x-credential-bindings" {
			return extension.ValueDigest
		}
	}
	return ""
}

func closeCredentialValues(values []*credentialref.Value) {
	for _, value := range values {
		value.Close()
	}
}

// IsSecretOperation classifies an operation only from the authoritative
// committed manifest, not from adapter or caller assertions. Even a plain
// operation in a mixed plan must first pass whole-manifest/plan validation.
func (step *CredentialStep) IsSecretOperation(ctx context.Context, plan generated.Plan, operation generated.PlanOperation) (bool, error) {
	if step == nil || step.Bindings == nil || step.Plans == nil || credentialPlanDigest(plan) == "" || operation.OperationID == "" {
		return false, runError(generated.ErrorCodePrerequisiteBlocked, "credential-bound-manifest")
	}
	if err := step.Plans.ValidateCurrent(ctx, plan); err != nil {
		return false, runError(generated.ErrorCodePlanStale, "credential-plan")
	}
	bindings, err := step.Bindings.GetStepBindings(ctx, plan, operation.OperationID)
	if err != nil {
		return false, runError(generated.ErrorCodePrerequisiteBlocked, "credential-bound-manifest")
	}
	if len(bindings) == 0 {
		return false, nil
	}
	if len(bindings) > 16 || operation.InputDigest != credentialref.OperationManifestDigest(bindings, operation.OperationID) {
		return false, runError(generated.ErrorCodeIntegrityFailure, "credential-operation-input")
	}
	return true, nil
}

func (step *CredentialStep) Resolve(ctx context.Context, plan generated.Plan, operation generated.PlanOperation, lease generated.ExecutorLease) ([]*credentialref.Value, error) {
	if step == nil || step.Bindings == nil || step.Resolvers == nil || step.Profiles == nil || step.Plans == nil || ctx == nil {
		return nil, runError(generated.ErrorCodePrerequisiteBlocked, "credential-step")
	}
	clock := step.Clock
	if clock == nil {
		clock = time.Now
	}
	if plan.Status != "planned" || plan.ExecutorMode != "central" || plan.AuthorizationBranch != "human" || credentialPlanDigest(plan) == "" || lease.LeaseID == "" || lease.RunID == "" || lease.StepID == "" || lease.ExecutorID == "" || lease.PlanID != plan.PlanID || lease.PlanDigest != plan.PlanDigest || lease.OperationID != operation.OperationID || lease.AdapterID != operation.AdapterID || lease.TargetID != operation.TargetID || lease.ArtifactDigest != operation.ArtifactDigest || lease.RecoveryEpoch != plan.Binding.RecoveryEpoch || lease.Status != "active" || operation.AdapterID == "core.gate" || operation.AdapterID == "core.credential" {
		return nil, runError(generated.ErrorCodePrerequisiteBlocked, "credential-exact-plan-lease")
	}
	deadline, err := time.Parse(time.RFC3339, lease.MaximumExpiresAt)
	if err != nil || !clock().UTC().Before(deadline) || ctx.Err() != nil {
		return nil, runError(generated.ErrorCodePlanStale, "credential-lease")
	}
	if err := step.Plans.ValidateCurrent(ctx, plan); err != nil {
		return nil, runError(generated.ErrorCodePlanStale, "credential-plan")
	}
	profile, err := step.Profiles.GetAppliedProfileScope(ctx)
	if err != nil || profile.ProfileID == "" || profile.RecoveryEpoch != plan.Binding.RecoveryEpoch || profile.StateRevision > plan.Binding.StateRevision {
		return nil, runError(generated.ErrorCodePrerequisiteBlocked, "credential-applied-profile")
	}
	bindings, err := step.Bindings.GetStepBindings(ctx, plan, operation.OperationID)
	if err != nil {
		return nil, runError(generated.ErrorCodePrerequisiteBlocked, "credential-bound-manifest")
	}
	if len(bindings) == 0 || len(bindings) > 16 || operation.InputDigest != credentialref.OperationManifestDigest(bindings, operation.OperationID) {
		return nil, runError(generated.ErrorCodeIntegrityFailure, "credential-operation-input")
	}
	values := make([]*credentialref.Value, 0, len(bindings))
	for _, binding := range bindings {
		if ctx.Err() != nil || !clock().UTC().Before(deadline) {
			closeCredentialValues(values)
			return nil, runError(generated.ErrorCodeInterrupted, "credential-lease")
		}
		if binding.OperationID != operation.OperationID || binding.AdapterID != operation.AdapterID || binding.TargetID != operation.TargetID || binding.StateRevision != plan.Binding.StateRevision || binding.RecoveryEpoch != plan.Binding.RecoveryEpoch || binding.ConsumerID != operation.AdapterID {
			closeCredentialValues(values)
			return nil, runError(generated.ErrorCodeIntegrityFailure, "credential-binding")
		}
		if err := step.Plans.ValidateCurrent(ctx, plan); err != nil {
			closeCredentialValues(values)
			return nil, runError(generated.ErrorCodePlanStale, "credential-plan")
		}
		currentProfile, err := step.Profiles.GetAppliedProfileScope(ctx)
		if err != nil || currentProfile.ProfileID != profile.ProfileID || currentProfile.RecoveryEpoch != plan.Binding.RecoveryEpoch || currentProfile.StateRevision > plan.Binding.StateRevision {
			closeCredentialValues(values)
			return nil, runError(generated.ErrorCodePrerequisiteBlocked, "credential-applied-profile")
		}
		capabilityID, err := step.Resolvers.ResolveCredentialCapability(binding.ResolverID, binding.ConsumerID, profile.ProfileID)
		if err != nil || capabilityID == "" || !slices.Contains(currentProfile.Capabilities, capabilityID) {
			closeCredentialValues(values)
			return nil, runError(generated.ErrorCodePrerequisiteBlocked, "credential-applied-capability")
		}
		reference, err := step.Bindings.GetReference(ctx, binding.ReferenceID)
		if err != nil || reference.ReferenceID != binding.ReferenceID || reference.ConsumerID != binding.ConsumerID || reference.PurposeID != binding.PurposeID || reference.TargetID != binding.TargetID || reference.ResolverID != binding.ResolverID || reference.MaterialVersion != binding.MaterialVersion || reference.Status != "active" || reference.ActivatedAt == nil || reference.RecoveryEpoch != binding.RecoveryEpoch || reference.StateRevision > binding.StateRevision || !slices.Contains(reference.VerifiedConsumerIDs, binding.ConsumerID) {
			closeCredentialValues(values)
			return nil, runError(generated.ErrorCodePrerequisiteBlocked, "credential-active-consumer")
		}
		resolver, err := step.Resolvers.ResolveCredentialResolver(binding.ResolverID, binding.ConsumerID, profile.ProfileID)
		if err != nil || resolver == nil {
			closeCredentialValues(values)
			return nil, runError(generated.ErrorCodePrerequisiteBlocked, "credential-resolver")
		}
		value, err := resolver.Resolve(ctx, binding)
		if err != nil || value == nil || len(value.Bytes()) == 0 {
			value.Close()
			closeCredentialValues(values)
			return nil, runError(generated.ErrorCodeDependencyUnavailable, "credential-resolution")
		}
		values = append(values, value)
	}
	return values, nil
}
