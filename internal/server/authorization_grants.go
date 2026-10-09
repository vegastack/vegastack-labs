package server

import (
	"context"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/localapi"
)

func (operations *Operations) DraftAuthorizationGrants(ctx context.Context, configPath string, input generated.AuthorizationGrantBatchRequest) (localapi.TypedResponse[generated.DeclarationRevision], error) {
	client, profile, err := operations.controlClient(ctx, configPath)
	if err != nil {
		return localapi.TypedResponse[generated.DeclarationRevision]{}, err
	}
	return client.DraftAuthorizationGrants(ctx, profile, input)
}
