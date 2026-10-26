package localapi

import (
	"context"
	"github.com/vegastack/vegastack-labs/internal/failure"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostinglifecycle"
	"github.com/vegastack/vegastack-labs/internal/localtransport"
	"github.com/vegastack/vegastack-labs/internal/principal"
	"github.com/vegastack/vegastack-labs/internal/serverconfig"
)

func (client *client) GetHostingLifecycle(ctx context.Context, p serverconfig.Profile, id string) (TypedResponse[generated.HostingLifecycleRecord], error) {
	if !principal.ValidID(id) {
		return TypedResponse[generated.HostingLifecycleRecord]{}, failure.New(generated.ErrorCodeInputInvalid, "target-id", false)
	}
	return requestTyped(client, ctx, p, requestSpec{localtransport.MethodGet, "/api/v1/hosting/" + id + "/lifecycle", "api.v1.hosting.lifecycle.get", maxOperationResponseBodyBytes, operationTimeout, false}, nil, func(d generated.HostingLifecycleRecord, r generated.RunResult) bool {
		return validGateData(d, generated.SchemaIDHostingLifecycleRecord) && hostinglifecycle.ValidateRequest(d.Request) == nil && d.Request.TargetID == id && d.Request.RecoveryEpoch == r.RecoveryEpoch && d.Request.ExpectedStateRevision <= r.StateRevision
	})
}
func (client *client) DraftHostingLifecycle(ctx context.Context, p serverconfig.Profile, input generated.HostingLifecycleDraftRequest) (TypedResponse[generated.DeclarationRevision], error) {
	if !validGateData(input, generated.SchemaIDHostingLifecycleDraftRequest) {
		return TypedResponse[generated.DeclarationRevision]{}, failure.New(generated.ErrorCodeInputInvalid, "hosting-lifecycle-request", false)
	}
	return requestTyped(client, ctx, p, requestSpec{localtransport.MethodPost, "/api/v1/hosting/lifecycle-drafts", "api.v1.hosting.lifecycle-drafts.create", maxOperationResponseBodyBytes, operationTimeout, true}, input, func(d generated.DeclarationRevision, r generated.RunResult) bool {
		if !validGateData(d, generated.SchemaIDDeclarationRevision) || d.HostingLifecycle == nil || len(d.Operations) != 1 || d.ServiceImport != nil || d.NetworkEndpoint != nil || d.AuthorizationGrantBatch != nil || d.HostAliasClaim != nil {
			return false
		}
		in := d.HostingLifecycle
		op := d.Operations[0]
		digest := hostinglifecycle.Digest(in)
		return hostinglifecycle.ValidateRequest(*in) == nil && in.TargetID == input.TargetID && in.Action == input.Action && in.ExpectedStateRevision == input.ExpectedStateRevision && in.RecoveryEpoch == input.RecoveryEpoch && in.IdempotencyKey == input.IdempotencyKey && in.ReasonDigest == input.ReasonDigest && d.DeclarationID == "hosting-"+digest[7:39] && d.DeclarationType == "hosting.lifecycle" && d.Status == "draft" && len(d.Extensions) == 0 && d.Revision == 1 && d.StateRevision == input.ExpectedStateRevision+1 && d.StateRevision == r.StateRevision && d.RecoveryEpoch == input.RecoveryEpoch && d.RecoveryEpoch == r.RecoveryEpoch && op.Sequence == 1 && op.OperationID == hostinglifecycle.OperationID && op.OperationType == hostinglifecycle.Operation && op.AdapterID == hostinglifecycle.AdapterID && op.TargetID == input.TargetID && op.InputDigest == digest && op.ArtifactDigest == digest && !op.Idempotent && op.OffsiteRunSpec == nil
	})
}
func hostingLifecycleRemoteArguments(spec requestSpec) []string {
	switch spec.command {
	case "api.v1.hosting.lifecycle-drafts.create":
		if spec.path == "/api/v1/hosting/lifecycle-drafts" {
			return []string{"hosting", "lifecycle", "draft"}
		}
	case "api.v1.hosting.lifecycle.get":
		if id, ok := pathID(spec.path, "/api/v1/hosting/", "/lifecycle"); ok {
			return []string{"hosting", "lifecycle", "show", "--target-id", id}
		}
	}
	return nil
}
