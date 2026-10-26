package localapi

import (
	"context"
	"github.com/vegastack/vegastack-labs/internal/failure"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/localtransport"
	"github.com/vegastack/vegastack-labs/internal/principal"
	"github.com/vegastack/vegastack-labs/internal/serverconfig"
	"github.com/vegastack/vegastack-labs/internal/servicecatalog"
)

func (c *client) GetServiceConfiguration(ctx context.Context, p serverconfig.Profile, id string) (TypedResponse[generated.ServiceConfigurationStatus], error) {
	if !principal.ValidID(id) {
		return TypedResponse[generated.ServiceConfigurationStatus]{}, failure.New(generated.ErrorCodeInputInvalid, "service-id", false)
	}
	return requestTyped(c, ctx, p, requestSpec{localtransport.MethodGet, "/api/v1/services/" + id + "/configuration", "api.v1.services.configuration.get", maxOperationResponseBodyBytes, operationTimeout, false}, nil, func(d generated.ServiceConfigurationStatus, r generated.RunResult) bool {
		return validGateData(d, generated.SchemaIDServiceConfigurationStatus) && d.ServiceID == id && d.StateRevision <= r.StateRevision && d.RecoveryEpoch == r.RecoveryEpoch && (d.Configuration == nil || servicecatalog.ValidateConfiguration(*d.Configuration) == nil)
	})
}
func serviceConfigurationRemoteArguments(spec requestSpec) []string {
	if spec.command == "api.v1.services.configuration.get" {
		if id, ok := pathID(spec.path, "/api/v1/services/", "/configuration"); ok {
			return []string{"service", "configuration", "show", "--service-id", id}
		}
	}
	return nil
}
