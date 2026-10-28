package server

import (
	"context"
	"github.com/vegastack/vegastack-labs/internal/adapter"
	"github.com/vegastack/vegastack-labs/internal/generated"
	ingress "github.com/vegastack/vegastack-labs/internal/networkingress"
	"github.com/vegastack/vegastack-labs/internal/serverconfig"
	"github.com/vegastack/vegastack-labs/internal/store"
	"net"
	"os"
	"slices"
	"time"
)

// This finite initial-publication branch is distinct from ordinary G-012/G-016
// qualification. It never installs passed gate evidence or changes ordinary rules.
type ingressBootstrapComposition struct {
	profile serverconfig.Profile
	store   *store.Store
	source  *ingressAuthority
	machine func() (string, error)
	probe   func(context.Context, serverconfig.Profile, generated.IngressChange) (string, error)
}

func probeBootstrapOrigin(ctx context.Context, p serverconfig.Profile, c generated.IngressChange) (string, error) {
	if !p.RemoteRead.Enabled || !p.RemoteRead.ConfigurationValid || p.RemoteRead.PublicOrigin != "https://"+c.Hostname || "https://"+p.RemoteRead.BindAddress != c.OriginService {
		return "", ingress.Error(generated.ErrorCodePrerequisiteBlocked)
	}
	p.IngressControllerReadPilot = &generated.IngressControllerReadPilot{Change: c}
	return probePilotOrigin(ctx, p)
}
func (p *ingressBootstrapComposition) check(ctx context.Context, d ingress.Staged) error {
	deny := func() error { return ingress.Error(generated.ErrorCodePrerequisiteBlocked) }
	if p == nil || p.profile.IngressBootstrap == nil || p.store == nil || p.source == nil || p.machine == nil {
		return deny()
	}
	policy := *p.profile.IngressBootstrap
	if ingress.ValidateBootstrapChange(policy, d.Request.Change, d.Request.RecoveryEpoch) != nil {
		return ingress.Error(generated.ErrorCodeAuthorizationDenied)
	}
	scope, e := p.source.gates.GetAppliedProfileScope(ctx)
	if e != nil || scope.ProfileID != "vegastack-labs" || scope.RecoveryEpoch != d.Request.RecoveryEpoch || !slices.Contains(scope.Capabilities, ingress.BootstrapCapability) || !slices.Contains(scope.Capabilities, "credential.ingress.read") || p.profile.SocketPath == "" {
		return deny()
	}

	socket, e := os.Lstat(p.profile.SocketPath)
	if e != nil || socket.Mode()&os.ModeSocket == 0 {
		return deny()
	}
	local, e := net.DialTimeout("unix", p.profile.SocketPath, time.Second)
	if e != nil {
		return deny()
	}
	_ = local.Close()
	health, e := p.store.Health(ctx)
	if e != nil || health.Mode != store.DatabaseReady || health.RecoveryPending {
		return deny()
	}
	authority, e := p.store.CurrentAuthority(ctx)
	if e != nil || authority.InstanceID != policy.ControllerInstanceID || authority.RecoveryEpoch != policy.RecoveryEpoch {
		return deny()
	}
	machine, e := p.machine()
	if e != nil || machine != policy.ControllerMachineIDDigest {
		return deny()
	}
	// Native-systemd itself verifies current installed/loaded custody and denied
	// consumer evidence. Never accept the workstation/foreground fallback here.
	for _, id := range []string{d.Request.Change.ObservationReferenceID, d.Request.Change.MutationReferenceID} {
		ref, e := p.source.credentials.GetActiveVersion(ctx, id, d.Request.RecoveryEpoch)
		if e != nil || ref.ResolverID != "native-systemd" || ref.ConsumerID != ingress.AdapterID || ref.TargetID != d.Request.Change.ProfileID || ref.ActivatedAt == nil || !slices.Contains(ref.VerifiedConsumerIDs, ingress.AdapterID) {
			return deny()
		}
	}
	if d.Request.Change.Action == "bootstrap-cutover" {
		if p.probe == nil {
			return deny()
		}
		digest, e := p.probe(ctx, p.profile, d.Request.Change)
		if e != nil || digest != d.Request.Change.OriginIdentityDigest {
			return deny()
		}
	}
	return nil
}
func (c *ingressAuthority) ReserveBootstrap(ctx context.Context, d ingress.Staged, b adapter.ExactExecutionBinding, s ingress.Snapshot) error {
	if e := c.check(ctx, d); e != nil {
		return e
	}
	return c.repository.ReserveBootstrap(ctx, d, b, s)
}
