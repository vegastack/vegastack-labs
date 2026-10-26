package server

import (
	"context"
	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/servicerecovery"
	"slices"
)

// Recovery credentials use the existing applied-profile resolver and current
// reference version, including platform subjects with no Coolify app record.
func (c *serviceRecoveryComposition) credential(ctx context.Context, q generated.ServiceRecoveryRequest, serviceID, reference, consumer, purpose, capability string) (credentialref.StepBinding, serviceCredentialIdentity, error) {
	if e := c.repo.Authorize(ctx, q); e != nil {
		return credentialref.StepBinding{}, serviceCredentialIdentity{}, e
	}
	p := c.profiles[q.Binding.PolicyID]
	if serviceID != q.Definition.ServiceID && serviceID != p.TargetServiceID {
		return credentialref.StepBinding{}, serviceCredentialIdentity{}, servicerecovery.Blocked()
	}
	health, e := c.base.store.Health(ctx)
	if e != nil {
		return credentialref.StepBinding{}, serviceCredentialIdentity{}, e
	}
	scope, e := c.base.gates.GetAppliedProfileScope(ctx)
	if e != nil || scope.RecoveryEpoch != q.RecoveryEpoch || !slices.Contains(scope.Capabilities, capability) {
		return credentialref.StepBinding{}, serviceCredentialIdentity{}, servicerecovery.Blocked()
	}
	ref, e := c.base.creds.GetReference(ctx, reference)
	if e != nil || ref.Status != "active" || ref.ActivatedAt == nil || ref.ConsumerID != consumer || ref.PurposeID != purpose || ref.TargetID != serviceID || ref.RecoveryEpoch != q.RecoveryEpoch || ref.StateRevision > health.Revision.StateRevision || !slices.Contains(ref.VerifiedConsumerIDs, consumer) {
		return credentialref.StepBinding{}, serviceCredentialIdentity{}, servicerecovery.Blocked()
	}
	cap, e := c.base.registry.ResolveCredentialCapability(ref.ResolverID, consumer, scope.ProfileID)
	if e != nil || cap != capability {
		return credentialref.StepBinding{}, serviceCredentialIdentity{}, servicerecovery.Blocked()
	}
	binding := credentialref.StepBinding{OperationID: servicerecovery.OperationID, AdapterID: consumer, ConsumerID: consumer, PurposeID: purpose, TargetID: serviceID, ReferenceID: reference, ResolverID: ref.ResolverID, MaterialVersion: ref.MaterialVersion, StateRevision: health.Revision.StateRevision, RecoveryEpoch: q.RecoveryEpoch}
	if !credentialref.ValidBinding(binding) {
		return binding, serviceCredentialIdentity{}, servicerecovery.Blocked()
	}
	ident := serviceCredentialIdentity{ReferenceID: reference, ConsumerID: consumer, PurposeID: purpose, TargetID: serviceID, ResolverID: ref.ResolverID, MaterialVersion: ref.MaterialVersion, Fingerprint: ref.Fingerprint, ProfileDigest: serviceProfileDigest(scope), ReferenceStateRevision: ref.StateRevision, RecoveryEpoch: q.RecoveryEpoch}
	return binding, ident, nil
}
func (c *serviceRecoveryComposition) borrow(ctx context.Context, q generated.ServiceRecoveryRequest, serviceID, reference, consumer, purpose, capability string) (*credentialref.Value, serviceCredentialIdentity, error) {
	b, i, e := c.credential(ctx, q, serviceID, reference, consumer, purpose, capability)
	if e != nil {
		return nil, i, e
	}
	scope, e := c.base.gates.GetAppliedProfileScope(ctx)
	if e != nil {
		return nil, i, e
	}
	resolver, e := c.base.registry.ResolveCredentialResolver(b.ResolverID, consumer, scope.ProfileID)
	if e != nil {
		return nil, i, e
	}
	v, e := resolver.Resolve(ctx, b)
	if e != nil || v == nil {
		if v != nil {
			v.Close()
		}
		return nil, i, servicerecovery.Blocked()
	}
	_, after, e := c.credential(ctx, q, serviceID, reference, consumer, purpose, capability)
	if e != nil || after != i {
		v.Close()
		return nil, i, servicerecovery.Blocked()
	}
	return v, i, nil
}
func (c *serviceRecoveryComposition) recheck(ctx context.Context, q generated.ServiceRecoveryRequest, serviceID, reference, consumer, purpose, capability string, initial serviceCredentialIdentity) error {
	_, after, e := c.credential(ctx, q, serviceID, reference, consumer, purpose, capability)
	if e != nil {
		return e
	}
	if after != initial {
		return servicerecovery.Blocked()
	}
	return nil
}
