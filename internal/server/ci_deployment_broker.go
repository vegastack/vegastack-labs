package server

import (
	"context"
	"github.com/vegastack/vegastack-labs/internal/adapter"
	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"github.com/vegastack/vegastack-labs/internal/store"
	"slices"
	"time"
)

// This broker is deliberately separate from the central CredentialStep. Its
// sole consumer is the admitted, held PID1 over the existing private CI stream.
type ciDeploymentBroker struct {
	jobs      *store.CIJobRepository
	registry  *adapter.Registry
	gates     *store.GateRepository
	authority *store.Store
}

func (b *ciDeploymentBroker) binding(ctx context.Context, parent adapter.ExactExecutionBinding, p generated.Plan, lease generated.ExecutorLease) (credentialref.StepBinding, store.GateAppliedProfile, error) {
	empty := credentialref.StepBinding{}
	scope := store.GateAppliedProfile{}
	if b == nil || b.jobs == nil || b.registry == nil || b.gates == nil || b.authority == nil || len(p.Operations) != 1 {
		return empty, scope, actionFailure()
	}
	currentLease, e := store.NewExecutorLeaseRepository(b.authority).Get(ctx, lease.LeaseID)
	if e != nil || currentLease.Status != "active" || currentLease.PlanID != p.PlanID || currentLease.PlanDigest != p.PlanDigest || currentLease.RunID != lease.RunID || currentLease.StepID != lease.StepID || currentLease.BindingDigest != lease.BindingDigest {
		return empty, scope, actionFailure()
	}
	for _, v := range []string{currentLease.LeaseExpiresAt, currentLease.MaximumExpiresAt} {
		at, e := time.Parse(time.RFC3339, v)
		if e != nil || !time.Now().UTC().Before(at) {
			return empty, scope, actionFailure()
		}
	}
	op := p.Operations[0]
	step := generated.RunStep{Sequence: op.Sequence, OperationID: op.OperationID, OperationType: op.OperationType, AdapterID: op.AdapterID, ExecutorID: op.ExecutorID, TargetID: op.TargetID, InputDigest: op.InputDigest, ArtifactDigest: op.ArtifactDigest, Idempotent: op.Idempotent, StepID: lease.StepID, Status: "running", EffectState: "intent-recorded"}
	proof, e := b.jobs.ManagedDeploymentAdmission(ctx, parent, p, step)
	if e != nil {
		return empty, scope, e
	}
	policy, e := b.jobs.ExternalDeploymentPolicy(proof.ExecutionBinding.BindingID)
	if e != nil || policy.Binding.BindingID == "" {
		return empty, scope, actionFailure()
	}
	binding := policy.Credential(p.Binding.StateRevision, p.Binding.RecoveryEpoch)
	if lease.PlanID != p.PlanID || lease.PlanDigest != p.PlanDigest || lease.RunID == "" || lease.LeaseID == "" || lease.OperationID != op.OperationID || lease.TargetID != binding.TargetID || lease.AdapterID != binding.AdapterID || lease.ArtifactDigest != policy.Artifact.Digest || lease.ExecutorID != policy.Binding.ExecutorID {
		return empty, scope, actionFailure()
	}
	scope, e = b.gates.GetAppliedProfileScope(ctx)
	if e != nil || scope.ProfileID == "" || scope.RecoveryEpoch != binding.RecoveryEpoch || scope.StateRevision > binding.StateRevision {
		return empty, scope, actionFailure()
	}
	capability, e := b.registry.ResolveCredentialCapability(binding.ResolverID, binding.ConsumerID, scope.ProfileID)
	if e != nil || capability == "" || !slices.Contains(scope.Capabilities, capability) {
		return empty, scope, actionFailure()
	}
	ref, e := store.NewCredentialRepository(b.authority).GetActiveVersion(ctx, binding.ReferenceID, binding.RecoveryEpoch)
	if e != nil || ref.ReferenceID != binding.ReferenceID || ref.ConsumerID != binding.ConsumerID || ref.PurposeID != binding.PurposeID || ref.TargetID != binding.TargetID || ref.ResolverID != binding.ResolverID || ref.MaterialVersion != binding.MaterialVersion || ref.Status != "active" || ref.ActivatedAt == nil || ref.StateRevision > binding.StateRevision || !slices.Contains(ref.VerifiedConsumerIDs, binding.ConsumerID) {
		return empty, scope, actionFailure()
	}
	return binding, scope, nil
}
func (b *ciDeploymentBroker) Check(ctx context.Context, parent adapter.ExactExecutionBinding, p generated.Plan, lease generated.ExecutorLease) error {
	_, _, e := b.binding(ctx, parent, p, lease)
	return e
}
func (b *ciDeploymentBroker) ResolveAndConsume(ctx context.Context, parent adapter.ExactExecutionBinding, p generated.Plan, lease generated.ExecutorLease) (value *credentialref.Value, err error) {
	defer func() {
		if recover() != nil {
			value.Close()
			value = nil
			err = actionFailure()
		}
	}()
	binding, scope, e := b.binding(ctx, parent, p, lease)
	if e != nil {
		return nil, e
	}
	priorRef, e := store.NewCredentialRepository(b.authority).GetActiveVersion(ctx, binding.ReferenceID, binding.RecoveryEpoch)
	if e != nil {
		return nil, e
	}
	resolver, e := b.registry.ResolveCredentialResolver(binding.ResolverID, binding.ConsumerID, scope.ProfileID)
	if e != nil || resolver == nil {
		return nil, actionFailure()
	}
	value, e = resolver.Resolve(ctx, binding)
	if e != nil || len(value.Bytes()) == 0 {
		value.Close()
		return nil, actionFailure()
	}
	afterRef, refErr := store.NewCredentialRepository(b.authority).GetActiveVersion(ctx, binding.ReferenceID, binding.RecoveryEpoch)
	current, currentScope, e := b.binding(ctx, parent, p, lease)
	if e != nil || refErr != nil || hostaction.Digest(priorRef) != hostaction.Digest(afterRef) || current != binding || storeProfileDigest(currentScope) != storeProfileDigest(scope) {
		value.Close()
		return nil, actionFailure()
	}
	if e = b.jobs.ConsumeDeploymentHandoff(ctx, parent, p, lease); e != nil {
		value.Close()
		return nil, e
	}
	if e = b.Check(ctx, parent, p, lease); e != nil {
		value.Close()
		return nil, e
	}
	return value, nil
}
func storeProfileDigest(p store.GateAppliedProfile) string {
	d, _ := store.ProfileScopeDigest(p)
	return d
}
