package server

import (
	"context"
	"encoding/json"
	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/ingressconnector"
	ingress "github.com/vegastack/vegastack-labs/internal/networkingress"
	"github.com/vegastack/vegastack-labs/internal/serverconfig"
	"github.com/vegastack/vegastack-labs/internal/store"
	"slices"
)

func matchControllerConnector(c ingressconnector.Input, s connectorSelection, marker string) error {
	raw, _ := json.Marshal(c)
	if _, e := ingressconnector.Decode(raw); e != nil || c.HostID != s.HostID || c.HostIdentityDigest != s.IdentityDigest || c.AccountID != s.AccountID || c.TunnelID != s.TunnelID || c.ControllerSetupPilotDigest != marker || (s.OriginCAPool != "" && s.OriginCAPool != ingressconnector.CAPath) || (c.OriginCADigest != "") != (s.OriginCAPool != "") {
		return actionFailure()
	}
	return nil
}
func verifyControllerConnectorStage(ctx context.Context, p generated.Plan, raw string, profile serverconfig.Profile, s *store.Store, path string) error {
	var in struct {
		Stage     string                  `json:"stage"`
		Connector *ingressconnector.Input `json:"connector"`
		Digest    string                  `json:"controllerSetupPilotDigest"`
	}
	if json.Unmarshal([]byte(raw), &in) != nil {
		return actionFailure()
	}
	if in.Stage != "connector-install" {
		return nil
	}
	policy := profile.IngressBootstrap
	if in.Connector == nil || policy == nil || policy.Change.Bootstrap == nil || s == nil || policy.RecoveryEpoch != p.Binding.RecoveryEpoch || profile.ControllerSetupPilot == nil || policy.ControllerHostID != profile.ControllerSetupPilot.HostID || policy.ControllerIdentityDigest != profile.ControllerSetupPilot.HostIdentityDigest || policy.ControllerInstanceID != profile.ControllerSetupPilot.ControllerInstanceID || policy.ControllerMachineIDDigest != profile.ControllerSetupPilot.ControllerMachineIDDigest {
		return actionFailure()
	}
	scope, e := store.NewGateRepository(s).GetAppliedProfileScope(ctx)
	if e != nil || scope.ProfileID != "vegastack-labs" || scope.RecoveryEpoch != p.Binding.RecoveryEpoch || !slices.Contains(scope.Capabilities, ingress.BootstrapCapability) || !slices.Contains(scope.Capabilities, "cloudflare.ingress") || !slices.Contains(scope.Capabilities, "credential.ingress.read") {
		return actionFailure()
	}
	tunnel, e := store.NewIngressRepository(s, []string{ingress.BootstrapScopeDigest(policy.Change)}).WithControllerPilot(ingressControllerPilot(profile)).BootstrapResource(ctx, policy.Change.ProfileID, "bootstrap-tunnel", p.Binding.RecoveryEpoch)
	if e != nil {
		return e
	}
	if e = matchControllerConnector(*in.Connector, connectorSelection{HostID: policy.ControllerHostID, IdentityDigest: policy.ControllerIdentityDigest, AccountID: policy.Change.AccountID, TunnelID: tunnel, OriginCAPool: policy.Change.Bootstrap.OriginCAPool, RecoveryEpoch: policy.RecoveryEpoch}, in.Digest); e != nil {
		return e
	}
	return observeControllerConnectorNative(ctx, profile, s, path, p, policy.Change)
}

type controllerConnectorReferences interface {
	GetActiveVersion(context.Context, string, int64) (generated.CredentialReference, error)
}

func checkControllerConnectorNative(ctx context.Context, p generated.Plan, c generated.IngressChange, refs controllerConnectorReferences, observe func(context.Context, credentialref.StepBinding) error) error {
	if len(p.Operations) != 1 || refs == nil || observe == nil || c.ObservationReferenceID == c.MutationReferenceID {
		return actionFailure()
	}
	for _, spec := range []struct{ id, purpose string }{{c.ObservationReferenceID, ingress.PurposeRead}, {c.MutationReferenceID, ingress.PurposeWrite}} {
		ref, e := refs.GetActiveVersion(ctx, spec.id, p.Binding.RecoveryEpoch)
		if e != nil || ref.ReferenceID != spec.id || ref.Status != "active" || ref.ResolverID != "native-systemd" || ref.ConsumerID != ingress.AdapterID || ref.TargetID != c.ProfileID || ref.PurposeID != spec.purpose || ref.RecoveryEpoch != p.Binding.RecoveryEpoch || ref.StateRevision > p.Binding.StateRevision || ref.ActivatedAt == nil || !slices.Contains(ref.VerifiedConsumerIDs, ingress.AdapterID) {
			return actionFailure()
		}
		b := credentialref.StepBinding{OperationID: p.Operations[0].OperationID, AdapterID: ingress.AdapterID, TargetID: ref.TargetID, ReferenceID: ref.ReferenceID, ConsumerID: ref.ConsumerID, PurposeID: ref.PurposeID, MaterialVersion: ref.MaterialVersion, ResolverID: ref.ResolverID, StateRevision: p.Binding.StateRevision, RecoveryEpoch: p.Binding.RecoveryEpoch}
		if !credentialref.ValidBinding(b) || observe(ctx, b) != nil {
			return actionFailure()
		}
	}
	return nil
}
