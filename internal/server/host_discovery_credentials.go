package server

import (
	"context"
	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostdiscovery"
	"slices"
)

type discoveryTargetVerifier interface {
	CheckCollection(context.Context, hostdiscovery.Target) error
}
type preloadedDiscoveryKeyReader interface {
	Borrow(context.Context, hostdiscovery.Target) (*credentialref.Value, error)
}
type hostDiscoveryCredentials struct {
	preloaded  preloadedDiscoveryKeyReader
	targets    discoveryTargetVerifier
	references recoveryCredentialReferences
	profiles   recoveryCredentialProfiles
	resolvers  recoveryCredentialResolvers
}

func (b hostDiscoveryCredentials) Check(ctx context.Context, target hostdiscovery.Target) error {
	_, err := b.resolve(ctx, target, false)
	return err
}
func (b hostDiscoveryCredentials) Borrow(ctx context.Context, target hostdiscovery.Target) (*credentialref.Value, error) {
	return b.resolve(ctx, target, true)
}
func (b hostDiscoveryCredentials) resolve(ctx context.Context, target hostdiscovery.Target, borrow bool) (*credentialref.Value, error) {
	blocked := func() (*credentialref.Value, error) {
		return nil, hostdiscovery.Error(generated.ErrorCodePrerequisiteBlocked)
	}
	if b.targets == nil || b.profiles == nil || b.targets.CheckCollection(ctx, target) != nil {
		return blocked()
	}
	t := target.Binding
	profile, err := b.profiles.GetAppliedProfileScope(ctx)
	if err != nil || profile.ProfileID != t.ProfileID || profile.RecoveryEpoch != t.RecoveryEpoch || profile.StateRevision > target.StateRevision {
		return blocked()
	}
	if t.CredentialMode != nil {
		if *t.CredentialMode != "preloaded-discovery" || b.preloaded == nil {
			return blocked()
		}
		value, err := b.preloaded.Borrow(ctx, target)
		if err != nil || value == nil || len(value.Bytes()) == 0 || b.targets.CheckCollection(ctx, target) != nil {
			if value != nil {
				value.Close()
			}
			return blocked()
		}
		if !borrow {
			value.Close()
			return nil, nil
		}
		return value, nil
	}
	if b.references == nil || b.resolvers == nil || t.CredentialPublicKeyDigest != nil {
		return blocked()
	}
	ref, err := b.references.GetActiveVersion(ctx, t.CredentialReferenceID, t.RecoveryEpoch)
	if err != nil || ref.ReferenceID != t.CredentialReferenceID || ref.ConsumerID != hostdiscovery.Consumer || ref.PurposeID != hostdiscovery.Purpose || ref.TargetID != t.TargetID || ref.MaterialVersion != t.MaterialVersion || ref.RecoveryEpoch != t.RecoveryEpoch || ref.StateRevision > target.StateRevision || ref.Status != "active" || ref.ActivatedAt == nil || !slices.Contains(ref.VerifiedConsumerIDs, hostdiscovery.Consumer) {
		return blocked()
	}
	capability, err := b.resolvers.ResolveCredentialCapability(ref.ResolverID, hostdiscovery.Consumer, profile.ProfileID)
	if err != nil || capability == "" || !slices.Contains(profile.Capabilities, capability) {
		return blocked()
	}
	resolver, err := b.resolvers.ResolveCredentialResolver(ref.ResolverID, hostdiscovery.Consumer, profile.ProfileID)
	if err != nil || resolver == nil {
		return blocked()
	}
	binding := credentialref.StepBinding{OperationID: "host.discovery.collect", AdapterID: hostdiscovery.Consumer, TargetID: t.TargetID, ReferenceID: ref.ReferenceID, ConsumerID: hostdiscovery.Consumer, PurposeID: hostdiscovery.Purpose, MaterialVersion: ref.MaterialVersion, ResolverID: ref.ResolverID, StateRevision: target.StateRevision, RecoveryEpoch: t.RecoveryEpoch}
	if !credentialref.ValidBinding(binding) {
		return blocked()
	}
	if !borrow {
		return nil, nil
	}
	value, err := resolver.Resolve(ctx, binding)
	if err != nil || value == nil || len(value.Bytes()) == 0 || b.targets.CheckCollection(ctx, target) != nil {
		if value != nil {
			value.Close()
		}
		return blocked()
	}
	return value, nil
}
