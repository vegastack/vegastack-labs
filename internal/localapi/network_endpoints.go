package localapi

import (
	"context"
	"encoding/json"
	"github.com/vegastack/vegastack-labs/internal/failure"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/localtransport"
	"github.com/vegastack/vegastack-labs/internal/networkconnect"
	"github.com/vegastack/vegastack-labs/internal/principal"
	"github.com/vegastack/vegastack-labs/internal/serverconfig"
)

func (client *client) DraftNetworkEndpoint(ctx context.Context, profile serverconfig.Profile, input generated.NetworkEndpointRequest) (TypedResponse[generated.DeclarationRevision], error) {
	raw, err := json.Marshal(input)
	if err != nil || len(raw) > 32768 || !validGateData(input, generated.SchemaIDNetworkEndpointRequest) {
		return TypedResponse[generated.DeclarationRevision]{}, failure.New(generated.ErrorCodeInputInvalid, "grant-batch", false)
	}
	return requestTyped(client, ctx, profile, requestSpec{localtransport.MethodPost, "/api/v1/network/endpoint-drafts", "api.v1.network.endpoint-drafts.create", maxOperationResponseBodyBytes, operationTimeout, true}, input, func(d generated.DeclarationRevision, r generated.RunResult) bool {
		if len(d.Operations) != 1 {
			return false
		}
		op := d.Operations[0]
		digest := hostRequestDigest(input)
		return validGateData(d, generated.SchemaIDDeclarationRevision) && d.DeclarationID == "network-endpoint-"+hostRequestDigest(input.Endpoint.HostID)[7:39] && d.DeclarationType == "network.endpoint" && d.Status == "draft" && len(d.Extensions) == 0 && op.Sequence == 1 && op.OperationID == "network-endpoint" && op.OperationType == networkconnect.Operation && op.AdapterID == networkconnect.AdapterID && op.TargetID == input.Endpoint.HostID && op.InputDigest == digest && op.ArtifactDigest == digest && !op.Idempotent && op.OffsiteRunSpec == nil && d.NetworkEndpoint != nil && hostRequestDigest(d.NetworkEndpoint) == digest && d.Revision == input.ExpectedDeclarationRevision+1 && d.StateRevision == input.ExpectedStateRevision+1 && d.StateRevision == r.StateRevision && d.RecoveryEpoch == input.RecoveryEpoch

	})
}

func (client *client) ConnectionDescriptor(ctx context.Context, p serverconfig.Profile, host string) (TypedResponse[generated.NetworkConnectDescriptor], error) {
	if !principal.ValidID(host) {
		return TypedResponse[generated.NetworkConnectDescriptor]{}, failure.New(generated.ErrorCodeInputInvalid, "host", false)
	}
	return requestTyped(client, ctx, p, requestSpec{localtransport.MethodGet, "/api/v1/hosts/" + host + "/connection-descriptor", "api.v1.hosts.connection-descriptor.get", maxOperationResponseBodyBytes, operationTimeout, false}, nil, func(d generated.NetworkConnectDescriptor, r generated.RunResult) bool {
		return validGateData(d, generated.SchemaIDNetworkConnectDescriptor) && networkconnect.ValidateEndpoint(d.Endpoint) == nil && d.Endpoint.HostID == host && d.StateRevision == r.StateRevision && d.RecoveryEpoch == r.RecoveryEpoch
	})
}
