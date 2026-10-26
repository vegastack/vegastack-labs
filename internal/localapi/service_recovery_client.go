package localapi

import (
	"context"
	"github.com/vegastack/vegastack-labs/internal/failure"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/localtransport"
	"github.com/vegastack/vegastack-labs/internal/principal"
	"github.com/vegastack/vegastack-labs/internal/serverconfig"
	"github.com/vegastack/vegastack-labs/internal/servicerecovery"
)

func (client *client) GetServiceRecovery(ctx context.Context, p serverconfig.Profile, id string) (TypedResponse[generated.ServiceRecoveryRecord], error) {
	if !principal.ValidID(id) {
		return TypedResponse[generated.ServiceRecoveryRecord]{}, failure.New(generated.ErrorCodeInputInvalid, "service-id", false)
	}
	return requestTyped(client, ctx, p, requestSpec{localtransport.MethodGet, "/api/v1/services/" + id + "/recovery", "api.v1.services.recovery.get", maxOperationResponseBodyBytes, operationTimeout, false}, nil, func(d generated.ServiceRecoveryRecord, r generated.RunResult) bool {
		return validGateData(d, generated.SchemaIDServiceRecoveryRecord) && servicerecovery.ValidateRequest(d.Request) == nil && d.Request.Definition.ServiceID == id && d.Request.RecoveryEpoch == r.RecoveryEpoch && d.Request.ExpectedStateRevision <= r.StateRevision
	})
}
func (client *client) DraftServiceRecovery(ctx context.Context, p serverconfig.Profile, input generated.ServiceRecoveryDraftRequest) (TypedResponse[generated.DeclarationRevision], error) {
	if !validGateData(input, generated.SchemaIDServiceRecoveryDraftRequest) {
		return TypedResponse[generated.DeclarationRevision]{}, failure.New(generated.ErrorCodeInputInvalid, "service-recovery-request", false)
	}
	return requestTyped(client, ctx, p, requestSpec{localtransport.MethodPost, "/api/v1/services/recovery-drafts", "api.v1.services.recovery-drafts.create", maxOperationResponseBodyBytes, operationTimeout, true}, input, func(d generated.DeclarationRevision, r generated.RunResult) bool {
		if !validGateData(d, generated.SchemaIDDeclarationRevision) || d.ServiceRecovery == nil || len(d.Operations) != 1 || d.ServiceImport != nil || d.NetworkEndpoint != nil || d.AuthorizationGrantBatch != nil || d.HostAliasClaim != nil {
			return false
		}
		in := d.ServiceRecovery
		op := d.Operations[0]
		digest := servicerecovery.Digest(in)
		return servicerecovery.ValidateRequest(*in) == nil && in.Definition.ServiceID == input.ServiceID && in.Binding.PolicyID == input.PolicyID && in.BackupPointID == input.BackupPointID && in.Action == input.Action && in.ExpectedStateRevision == input.ExpectedStateRevision && in.RecoveryEpoch == input.RecoveryEpoch && in.IdempotencyKey == input.IdempotencyKey && in.ReasonDigest == input.ReasonDigest && d.DeclarationID == "service-recovery-"+digest[7:39] && d.DeclarationType == "service.recovery" && d.Status == "draft" && len(d.Extensions) == 0 && d.Revision == 1 && d.StateRevision == input.ExpectedStateRevision+1 && d.StateRevision == r.StateRevision && d.RecoveryEpoch == input.RecoveryEpoch && d.RecoveryEpoch == r.RecoveryEpoch && op.Sequence == 1 && op.OperationID == servicerecovery.OperationID && op.OperationType == servicerecovery.Operation && op.AdapterID == servicerecovery.AdapterID && op.TargetID == input.ServiceID && op.InputDigest == digest && op.ArtifactDigest == digest && !op.Idempotent && op.OffsiteRunSpec == nil
	})
}
func serviceRecoveryRemoteArguments(spec requestSpec) []string {
	switch spec.command {
	case "api.v1.services.recovery-drafts.create":
		if spec.path == "/api/v1/services/recovery-drafts" {
			return []string{"service", "recovery", "draft"}
		}
	case "api.v1.services.recovery.get":
		if id, ok := pathID(spec.path, "/api/v1/services/", "/recovery"); ok {
			return []string{"service", "recovery", "show", "--service-id", id}
		}
	}
	return nil
}
