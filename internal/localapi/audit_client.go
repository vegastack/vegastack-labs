package localapi

import (
	"context"
	"encoding/json"

	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/localtransport"
	"github.com/vegastack/vegastack-labs/internal/serverconfig"
)

func (client *client) AuditCheckpoints(ctx context.Context, profile serverconfig.Profile) (TypedResponse[generated.BrowserAuditCheckpointListData], error) {
	return requestTyped(client, ctx, profile, requestSpec{localtransport.MethodGet, "/api/v1/audit-checkpoints", "api.v1.audit-checkpoints.list", maxResponseBodyBytes, statusTimeout, false}, nil, validAuditCheckpointList)
}

func (client *client) VerifyAudit(ctx context.Context, profile serverconfig.Profile) (TypedResponse[generated.BrowserAuditVerificationData], error) {
	return requestTyped(client, ctx, profile, requestSpec{localtransport.MethodGet, "/api/v1/audit-history/verification", "api.v1.audit-history.verification", maxResponseBodyBytes, statusTimeout, false}, nil, validAuditVerification)
}

func validAuditCheckpointList(value generated.BrowserAuditCheckpointListData, envelope generated.RunResult) bool {
	raw, err := json.Marshal(value)
	return err == nil && generated.ValidateContractJSON(generated.SchemaIDBrowserAuditCheckpointListData, raw, generated.ContractExact) == nil && value.StateRevision == envelope.StateRevision && value.RecoveryEpoch == envelope.RecoveryEpoch
}

func validAuditVerification(value generated.BrowserAuditVerificationData, envelope generated.RunResult) bool {
	raw, err := json.Marshal(value)
	return err == nil && generated.ValidateContractJSON(generated.SchemaIDBrowserAuditVerificationData, raw, generated.ContractExact) == nil && value.StateRevision == envelope.StateRevision && value.RecoveryEpoch == envelope.RecoveryEpoch
}
