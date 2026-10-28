package server

import (
	"context"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/linuxrole"
	"github.com/vegastack/vegastack-labs/internal/localapi"
	"github.com/vegastack/vegastack-labs/internal/result"
	"github.com/vegastack/vegastack-labs/internal/serverconfig"
)

func (o *Operations) controllerSetupClient(ctx context.Context, path, raw string, receipt bool) (localapi.Client, serverconfig.Profile, error) {
	in, e := linuxrole.DecodeControllerInstallInput([]byte(raw))
	if e != nil {
		return nil, serverconfig.Profile{}, actionFailure()
	}
	owners := []uint32{uint32(in.AdministratorUID)}
	if in.Stage == "connector-install" {
		owners = []uint32{uint32(in.ServiceUID)}
	}
	if in.Stage == "service-handoff" && receipt {
		owners = append(owners, uint32(in.ServiceUID))
	}
	for _, owner := range owners {
		p, e := loadControllerSetupClientProfile(ctx, path, owner, uint32(in.AdministratorGID))
		if e != nil {
			continue
		}
		policy := p.ControllerSetupPilot
		if policy == nil || policy.AdministratorUID != in.AdministratorUID || policy.AdministratorGID != in.AdministratorGID || policy.ServiceUID != in.ServiceUID || policy.ServiceGID != in.ServiceGID || policy.ControllerInstanceID != in.ControllerInstanceID || p.SocketOwnerUID != owner || p.ConstrainedSSH != nil {
			continue
		}
		return localapi.NewClient(result.NewFactory(o.build, o.requestIDs)), p, nil
	}
	return nil, serverconfig.Profile{}, actionFailure()
}
func (o *Operations) ClaimControllerSetup(ctx context.Context, path string, q generated.ControllerSetupClaimRequest) (localapi.TypedResponse[generated.ControllerSetupClaim], error) {
	c, p, e := o.controllerSetupClient(ctx, path, q.InputJSON, false)
	if e != nil {
		return localapi.TypedResponse[generated.ControllerSetupClaim]{}, e
	}
	return c.ClaimControllerSetup(ctx, p, q)
}
func (o *Operations) SubmitControllerSetupReceipt(ctx context.Context, path string, q generated.ControllerSetupReceiptRequest) (localapi.TypedResponse[generated.Run], error) {
	c, p, e := o.controllerSetupClient(ctx, path, q.InputJSON, true)
	if e != nil {
		return localapi.TypedResponse[generated.Run]{}, e
	}
	return c.SubmitControllerSetupReceipt(ctx, p, q)
}

// Preparation precedes the protected pilot policy: the current initial-admin
// binding and existing own policy-author grant are checked by the server.
func (o *Operations) PrepareControllerSetupRecovery(ctx context.Context, path string, q generated.ControllerSetupRecoveryRequest) (localapi.TypedResponse[generated.ControllerSetupRecoveryData], error) {
	c, p, e := o.controlClient(ctx, path)
	if e != nil {
		return localapi.TypedResponse[generated.ControllerSetupRecoveryData]{}, e
	}
	return c.PrepareControllerSetupRecovery(ctx, p, q)
}
