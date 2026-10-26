package localapi

import (
	"context"
	"github.com/vegastack/vegastack-labs/internal/failure"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/localtransport"
	"github.com/vegastack/vegastack-labs/internal/serverconfig"
)

func (c *client) DraftMesh(ctx context.Context, p serverconfig.Profile, q generated.MeshDraftRequest) (TypedResponse[generated.MeshDraftSubmission], error) {
	if !validGateData(q, generated.SchemaIDMeshDraftRequest) {
		return TypedResponse[generated.MeshDraftSubmission]{}, failure.New(generated.ErrorCodeInputInvalid, "mesh-request", false)
	}
	return requestTyped(c, ctx, p, requestSpec{localtransport.MethodPost, "/api/v1/network/mesh/draft", "api.v1.network.mesh.draft", maxOperationResponseBodyBytes, operationTimeout, false}, q, func(d generated.MeshDraftSubmission, r generated.RunResult) bool {
		return validGateData(d, generated.SchemaIDMeshDraftSubmission) && d.RecoveryEpoch == q.RecoveryEpoch && d.StateRevision == r.StateRevision && d.RecoveryEpoch == r.RecoveryEpoch
	})
}
func (c *client) MeshStatus(ctx context.Context, p serverconfig.Profile, id string) (TypedResponse[generated.MeshStatusData], error) {
	if !validPathToken(id) {
		return TypedResponse[generated.MeshStatusData]{}, failure.New(generated.ErrorCodeInputInvalid, "mesh-profile", false)
	}
	return requestTyped(c, ctx, p, requestSpec{localtransport.MethodGet, "/api/v1/network/mesh/" + id, "api.v1.network.mesh.status", maxOperationResponseBodyBytes, operationTimeout, false}, nil, func(d generated.MeshStatusData, r generated.RunResult) bool {
		return validGateData(d, generated.SchemaIDMeshStatusData) && d.ProfileID == id && d.StateRevision == r.StateRevision && d.RecoveryEpoch == r.RecoveryEpoch
	})
}

func (c *client) ObserveMesh(ctx context.Context, p serverconfig.Profile, q generated.MeshDraftRequest) (TypedResponse[generated.MeshStatusData], error) {
	if !validGateData(q, generated.SchemaIDMeshDraftRequest) {
		return TypedResponse[generated.MeshStatusData]{}, failure.New(generated.ErrorCodeInputInvalid, "mesh-request", false)
	}
	return requestTyped(c, ctx, p, requestSpec{localtransport.MethodPost, "/api/v1/network/mesh/observe", "api.v1.network.mesh.observe", maxOperationResponseBodyBytes, operationTimeout, false}, q, func(d generated.MeshStatusData, r generated.RunResult) bool {
		return validGateData(d, generated.SchemaIDMeshStatusData) && d.ProfileID == q.Change.ProfileID && d.RecoveryEpoch == q.RecoveryEpoch && d.StateRevision == r.StateRevision && d.RecoveryEpoch == r.RecoveryEpoch
	})
}
