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

func (client *client) GetServiceDeployment(ctx context.Context, p serverconfig.Profile, id string) (TypedResponse[generated.ServiceDeploymentRecord], error) {
	if !principal.ValidID(id) {
		return TypedResponse[generated.ServiceDeploymentRecord]{}, failure.New(generated.ErrorCodeInputInvalid, "service-id", false)
	}
	return requestTyped(client, ctx, p, requestSpec{localtransport.MethodGet, "/api/v1/services/" + id + "/deployment", "api.v1.services.deployment.get", maxOperationResponseBodyBytes, operationTimeout, false}, nil, func(d generated.ServiceDeploymentRecord, r generated.RunResult) bool {
		return validGateData(d, generated.SchemaIDServiceDeploymentRecord) && servicecatalog.ValidateDeploymentRequest(d.Request) == nil && d.Request.Definition.ServiceID == id && d.Request.RecoveryEpoch == r.RecoveryEpoch && d.Request.ExpectedStateRevision <= r.StateRevision
	})
}
func (client *client) DraftServiceDeployment(ctx context.Context, p serverconfig.Profile, input generated.ServiceDeploymentDraftRequest) (TypedResponse[generated.DeclarationRevision], error) {
	if !validGateData(input, generated.SchemaIDServiceDeploymentDraftRequest) {
		return TypedResponse[generated.DeclarationRevision]{}, failure.New(generated.ErrorCodeInputInvalid, "service-deployment-request", false)
	}
	return requestTyped(client, ctx, p, requestSpec{localtransport.MethodPost, "/api/v1/services/deployment-drafts", "api.v1.services.deployment-drafts.create", maxOperationResponseBodyBytes, operationTimeout, true}, input, func(d generated.DeclarationRevision, r generated.RunResult) bool {
		if !validGateData(d, generated.SchemaIDDeclarationRevision) || d.ServiceDeployment == nil || len(d.Operations) != 1 || d.ServiceImport != nil || d.NetworkEndpoint != nil || d.AuthorizationGrantBatch != nil || d.HostAliasClaim != nil {
			return false
		}
		in := d.ServiceDeployment
		op := d.Operations[0]
		digest := servicecatalog.Digest(in)
		return servicecatalog.ValidateDeploymentRequest(*in) == nil && in.Definition.ServiceID == input.ServiceID && in.Artifact.ArtifactID == input.ArtifactID && in.Action == input.Action && in.ExpectedStateRevision == input.ExpectedStateRevision && in.RecoveryEpoch == input.RecoveryEpoch && in.IdempotencyKey == input.IdempotencyKey && in.ReasonDigest == input.ReasonDigest && d.DeclarationID == "service-deploy-"+digest[7:39] && d.DeclarationType == "service.deployment" && d.Status == "draft" && len(d.Extensions) == 0 && d.Revision == 1 && d.StateRevision == input.ExpectedStateRevision+1 && d.StateRevision == r.StateRevision && d.RecoveryEpoch == input.RecoveryEpoch && d.RecoveryEpoch == r.RecoveryEpoch && op.Sequence == 1 && op.OperationID == servicecatalog.DeploymentOperationID && op.OperationType == servicecatalog.DeploymentOperation && op.AdapterID == servicecatalog.DeploymentAdapterID && op.TargetID == input.ServiceID && op.InputDigest == digest && op.ArtifactDigest == digest && !op.Idempotent && op.OffsiteRunSpec == nil
	})
}
func serviceDeploymentRemoteArguments(spec requestSpec) []string {
	switch spec.command {
	case "api.v1.services.deployment-drafts.create":
		if spec.path == "/api/v1/services/deployment-drafts" {
			return []string{"service", "deployment", "draft"}
		}
	case "api.v1.services.deployment.get":
		if id, ok := pathID(spec.path, "/api/v1/services/", "/deployment"); ok {
			return []string{"service", "deployment", "show", "--service-id", id}
		}
	}
	return nil
}
