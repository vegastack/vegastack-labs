package localapi

import (
	"context"
	"encoding/json"

	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/localtransport"
	"github.com/vegastack/vegastack-labs/internal/serverconfig"
)

func (client *client) AuditCheckpoints(ctx context.Context, profile serverconfig.Profile) (TypedResponse[generated.AuditCheckpointListData], error) {
	response, err := requestTyped(client, ctx, profile, requestSpec{localtransport.MethodGet, "/api/v1/audit-checkpoints", "api.v1.audit-checkpoints.list", maxResponseBodyBytes, statusTimeout, false}, nil, validAuditCheckpointList)
	if err != nil {
		return TypedResponse[generated.AuditCheckpointListData]{}, err
	}
	items := make([]generated.AuditCheckpoint, 0, len(response.Data.Items))
	for _, item := range response.Data.Items {
		items = append(items, generated.AuditCheckpoint{Schema: generated.SchemaIDAuditCheckpoint, SchemaVersion: "1.1.0", CheckpointID: item.CheckpointID, FirstEventID: item.FirstEventID, LastEventID: item.LastEventID, ChainDigest: item.ChainDigest, Status: item.Status, ReasonCode: item.ReasonCode, SourceKind: item.SourceKind, ProofClass: item.ProofClass, VerifiedAt: item.VerifiedAt, VerificationStatus: item.VerificationStatus, RecoveryEpoch: item.RecoveryEpoch})
	}
	legacy := generated.AuditCheckpointListData{Schema: generated.SchemaIDAuditCheckpointListData, SchemaVersion: "1.0.0", Checkpoints: items, RecoveryEpoch: response.Data.RecoveryEpoch}
	return TypedResponse[generated.AuditCheckpointListData]{Raw: response.Raw, Result: response.Result, Data: legacy, ExitCode: response.ExitCode}, nil
}

func (client *client) VerifyAudit(ctx context.Context, profile serverconfig.Profile) (TypedResponse[generated.AuditVerificationData], error) {
	response, err := requestTyped(client, ctx, profile, requestSpec{localtransport.MethodGet, "/api/v1/audit-history/verification", "api.v1.audit-history.verification", maxResponseBodyBytes, statusTimeout, false}, nil, validAuditVerification)
	if err != nil {
		return TypedResponse[generated.AuditVerificationData]{}, err
	}
	legacy := generated.AuditVerificationData{Schema: generated.SchemaIDAuditVerificationData, SchemaVersion: "1.1.0", Status: response.Data.Status, RecoveryEpoch: response.Data.RecoveryEpoch, IndependentMatch: response.Data.IndependentMatch, LastAnchoredSequence: response.Data.LastAnchoredSequence, ReasonCode: response.Data.ReasonCode, PreAnchor: response.Data.PreAnchor}
	return TypedResponse[generated.AuditVerificationData]{Raw: response.Raw, Result: response.Result, Data: legacy, ExitCode: response.ExitCode}, nil
}

func validAuditCheckpointList(value generated.BrowserAuditCheckpointListData, envelope generated.RunResult) bool {
	raw, err := json.Marshal(value)
	return err == nil && generated.ValidateContractJSON(generated.SchemaIDBrowserAuditCheckpointListData, raw, generated.ContractExact) == nil && value.StateRevision == envelope.StateRevision && value.RecoveryEpoch == envelope.RecoveryEpoch
}

func validAuditVerification(value generated.BrowserAuditVerificationData, envelope generated.RunResult) bool {
	raw, err := json.Marshal(value)
	return err == nil && generated.ValidateContractJSON(generated.SchemaIDBrowserAuditVerificationData, raw, generated.ContractExact) == nil && value.StateRevision == envelope.StateRevision && value.RecoveryEpoch == envelope.RecoveryEpoch
}
