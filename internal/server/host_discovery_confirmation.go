package server

import (
	"context"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostdiscovery"
	"github.com/vegastack/vegastack-labs/internal/run"
	"github.com/vegastack/vegastack-labs/internal/store"
)

// discoveryConsoleGate accepts the exact administrator attestation only for
// discovery-only targets. It does not qualify global credentials or recovery.
type discoveryConsoleGate struct {
	targets  *store.HostDiscoveryRepository
	fallback run.GateVerifier
}

func (g discoveryConsoleGate) VerifySecretStep(ctx context.Context, p generated.Plan, op generated.PlanOperation) error {
	deny := func() error { return hostdiscovery.Error(generated.ErrorCodePrerequisiteBlocked) }
	if g.targets == nil || len(p.Operations) != 1 || p.Operations[0] != op || p.AuthorizationBranch != "human" || p.ExecutorMode != "central" || p.Risk != "control-plane" || op.AdapterID != "core.host-discovery-target" {
		return deny()
	}
	d, err := g.targets.GetDraft(ctx, op.TargetID)
	if err != nil || d.ID != op.TargetID || d.Digest != op.InputDigest || d.Digest != op.ArtifactDigest || hostdiscovery.Digest(d.Request) != d.Digest || op.OperationType != "host.discovery-target."+d.Request.Action {
		return deny()
	}
	if d.Request.Target.CredentialMode == nil {
		if p.HostDiscoveryTarget != nil || g.fallback == nil {
			return deny()
		}
		return g.fallback.VerifySecretStep(ctx, p, op)
	}
	if hostdiscovery.ValidateConsoleConfirmation(d.Request) != nil || p.HostDiscoveryTarget == nil || hostdiscovery.Digest(*p.HostDiscoveryTarget) != d.Digest || p.Binding.RecoveryEpoch != d.Request.Target.RecoveryEpoch {
		return deny()
	}
	return nil
}
