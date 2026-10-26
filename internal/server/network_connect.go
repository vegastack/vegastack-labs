package server

import (
	"context"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/localapi"
	"github.com/vegastack/vegastack-labs/internal/networkconnect"
)

func (o *Operations) DraftNetworkEndpoint(ctx context.Context, path string, in generated.NetworkEndpointRequest) (localapi.TypedResponse[generated.DeclarationRevision], error) {
	c, p, e := o.controlClient(ctx, path)
	if e != nil {
		return localapi.TypedResponse[generated.DeclarationRevision]{}, e
	}
	return c.DraftNetworkEndpoint(ctx, p, in)
}
func (o *Operations) ConnectNetwork(ctx context.Context, path, host, route string) (generated.NetworkConnectResult, error) {
	c, p, e := o.controlClient(ctx, path)
	if e != nil {
		return generated.NetworkConnectResult{}, e
	}
	key, e := networkconnect.ReadPrivateKey(ctx, p.NetworkConnectPrivateKeyPath)
	if e != nil {
		return generated.NetworkConnectResult{}, e
	}
	defer clear(key)
	fetch := func(ctx context.Context) (generated.NetworkConnectDescriptor, error) {
		r, e := c.ConnectionDescriptor(ctx, p, host)
		if e != nil {
			return generated.NetworkConnectDescriptor{}, e
		}
		if r.ExitCode != 0 {
			return generated.NetworkConnectDescriptor{}, networkconnect.Denied()
		}
		return r.Data, nil
	}
	return networkconnect.Connect(ctx, route, key, fetch)
}
