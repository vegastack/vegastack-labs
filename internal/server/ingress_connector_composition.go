package server

import (
	"context"
	"github.com/vegastack/vegastack-labs/internal/generated"
	ingress "github.com/vegastack/vegastack-labs/internal/networkingress"
	"github.com/vegastack/vegastack-labs/internal/serverconfig"
	"github.com/vegastack/vegastack-labs/internal/store"
	"slices"
	"time"
)

// Initial installation binds the successful bootstrap receipt; it must not
// depend on a connector ID which exists only after the first connection.
func ingressConnectorAuthorization(profile serverconfig.Profile, s *store.Store, gates *store.GateRepository, pilot connectorPilot) func(context.Context, generated.Plan) error {
	return func(ctx context.Context, p generated.Plan) error {
		policy := profile.IngressBootstrap
		if policy == nil || policy.Change.Bootstrap == nil || s == nil || gates == nil || policy.RecoveryEpoch != p.Binding.RecoveryEpoch {
			return actionFailure()
		}
		scope, e := gates.GetAppliedProfileScope(ctx)
		if e != nil || scope.ProfileID != "vegastack-labs" || scope.RecoveryEpoch != p.Binding.RecoveryEpoch || !slices.Contains(scope.Capabilities, ingress.BootstrapCapability) {
			return actionFailure()
		}
		authority, e := s.CurrentAuthority(ctx)
		if e != nil || authority.InstanceID != policy.ControllerInstanceID || authority.RecoveryEpoch != policy.RecoveryEpoch {
			return actionFailure()
		}
		machine, e := pilotMachineDigest()
		if e != nil || machine != policy.ControllerMachineIDDigest {
			return actionFailure()
		}
		tunnel, e := store.NewIngressRepository(s, []string{ingress.BootstrapScopeDigest(policy.Change)}).WithControllerPilot(ingressControllerPilot(profile)).BootstrapResource(ctx, policy.Change.ProfileID, "bootstrap-tunnel", p.Binding.RecoveryEpoch)
		if e != nil {
			return e
		}
		selected := connectorSelection{HostID: policy.ControllerHostID, AccountID: policy.Change.AccountID, IdentityDigest: policy.ControllerIdentityDigest, TunnelID: tunnel, OriginCAPool: policy.Change.Bootstrap.OriginCAPool, RecoveryEpoch: policy.RecoveryEpoch}
		baseline := hostRoleComposition{gates: gates, clock: time.Now}
		return verifyIngressConnector(ctx, p, selected, baseline.baseline, pilot)
	}
}
