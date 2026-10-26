package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/localapi"
	"github.com/vegastack/vegastack-labs/internal/networkconnect"
	"github.com/vegastack/vegastack-labs/internal/principal"
)

type NetworkControlOperations interface {
	DraftNetworkEndpoint(context.Context, string, generated.NetworkEndpointRequest) (localapi.TypedResponse[generated.DeclarationRevision], error)
	ConnectNetwork(context.Context, string, string, string) (generated.NetworkConnectResult, error)
}

func (app *App) runNetworkEndpoint(ctx context.Context, mode outputMode, p parsedArguments) int {
	c, ok := app.control.(NetworkControlOperations)
	if !ok || app.files == nil {
		return app.fail(mode, p.commandName(), generated.ErrorCodeIntegrityFailure, "network-control", generated.RunStatusFailed, false)
	}
	raw, err := app.files.Read(ctx, p.Value(generated.FlagFile), 16384)
	if err != nil {
		return app.failServer(mode, p.commandName(), err)
	}
	var in generated.NetworkEndpointRequest
	if len(raw) > 16384 || generated.ValidateContractJSON(generated.SchemaIDNetworkEndpointRequest, raw, generated.ContractExact) != nil || json.Unmarshal(raw, &in) != nil || networkconnect.ValidateRequest(in) != nil {
		return app.fail(mode, p.commandName(), generated.ErrorCodeInputInvalid, "network-endpoint", generated.RunStatusFailed, false)
	}
	r, err := c.DraftNetworkEndpoint(ctx, p.Value(generated.FlagConfig), in)
	if err != nil {
		return app.failServer(mode, p.commandName(), err)
	}
	if r.ExitCode != 0 {
		return app.remoteFailure(mode, r.Raw, r.Result, r.ExitCode)
	}
	if mode == outputJSON {
		return writeRemoteJSON(app.stdout, r.Raw, r.ExitCode)
	}
	_, err = fmt.Fprintf(app.stdout, "Endpoint %s for %s drafted\nDeclaration: %s revision %d\nAcknowledge and apply its exact plan to change controller declarations. No host or network is configured.\n", in.Action, in.Endpoint.HostID, r.Data.DeclarationID, r.Data.Revision)
	if err != nil {
		return exitCodeFor(generated.ErrorCodeIntegrityFailure)
	}
	return 0
}
func (app *App) runNetworkConnect(ctx context.Context, mode outputMode, p parsedArguments) int {
	c, ok := app.control.(NetworkControlOperations)
	if !ok {
		return app.fail(mode, p.commandName(), generated.ErrorCodeIntegrityFailure, "network-control", generated.RunStatusFailed, false)
	}
	host, path, port := p.Value(generated.FlagNode), p.Value(generated.FlagPath), p.Value(generated.FlagPort)
	if path == "" {
		path = "auto"
	}
	if port == "" {
		port = "22"
	}
	if !principal.ValidID(host) || port != "22" || (path != "auto" && path != "lan" && path != "mesh") {
		return app.fail(mode, p.commandName(), generated.ErrorCodeInputInvalid, "network-connect", generated.RunStatusFailed, false)
	}
	data, err := c.ConnectNetwork(ctx, p.Value(generated.FlagConfig), host, path)
	if err != nil {
		return app.failServer(mode, p.commandName(), err)
	}
	if mode == outputJSON {
		return app.succeedData(p.commandName(), data)
	}
	_, err = fmt.Fprintf(app.stdout, "Authenticated and closed connection to %s via %s\nEndpoint: %s\n", data.HostID, data.Path, data.EndpointDigest)
	if err != nil {
		return exitCodeFor(generated.ErrorCodeIntegrityFailure)
	}
	return 0
}
