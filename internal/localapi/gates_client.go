package localapi

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"

	"github.com/vegastack/vegastack-labs/internal/failure"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/localtransport"
	"github.com/vegastack/vegastack-labs/internal/serverconfig"
)

func gateToken(id string) bool {
	if validPathToken(id) {
		return true
	}
	if len(id) != 5 || id[:2] != "G-" {
		return false
	}
	for _, part := range id[2:] {
		if part < '0' || part > '9' {
			return false
		}
	}
	return true
}

func validGateData[T any](data T, schemaID string) bool {
	raw, err := json.Marshal(data)
	return err == nil && generated.ValidateContractJSON(schemaID, raw, generated.ContractExact) == nil
}

func (client *client) Gates(ctx context.Context, profile serverconfig.Profile) (TypedResponse[generated.GateListData], error) {
	return requestTyped(client, ctx, profile, requestSpec{localtransport.MethodGet, "/api/v1/gates", "api.v1.gates.list", maxOperationResponseBodyBytes, operationTimeout, false}, nil, func(data generated.GateListData, result generated.RunResult) bool {
		return validGateData(data, generated.SchemaIDGateListData) && data.RecoveryEpoch == result.RecoveryEpoch
	})
}

func (client *client) GetGate(ctx context.Context, profile serverconfig.Profile, gateID string) (TypedResponse[generated.GateView], error) {
	if !gateToken(gateID) {
		return TypedResponse[generated.GateView]{}, failure.New(generated.ErrorCodeInputInvalid, "gate-id", false)
	}
	return requestTyped(client, ctx, profile, requestSpec{localtransport.MethodGet, "/api/v1/gates/" + gateID, "api.v1.gates.get", maxOperationResponseBodyBytes, operationTimeout, false}, nil, func(data generated.GateView, _ generated.RunResult) bool {
		return validGateData(data, generated.SchemaIDGateView) && data.Definition.GateID == gateID && data.Evaluation.GateID == gateID
	})
}

func (client *client) CheckGate(ctx context.Context, profile serverconfig.Profile, gateID, subjectID string) (TypedResponse[generated.GateEvaluation], error) {
	var zero TypedResponse[generated.GateEvaluation]
	if !gateToken(gateID) || !validPathToken(subjectID) {
		return zero, failure.New(generated.ErrorCodeInputInvalid, "gate-subject", false)
	}
	view, err := client.GetGate(ctx, profile, gateID)
	if err != nil {
		return zero, err
	}
	if view.ExitCode != 0 {
		return remapResponse[generated.GateEvaluation](view), nil
	}
	key, err := client.results.RequestID()
	if err != nil {
		return zero, err
	}
	sum := sha256.Sum256([]byte(gateID + "\x00" + subjectID))
	input := generated.GateCheckRequest{Schema: generated.SchemaIDGateCheckRequest, SchemaVersion: "1.0.0", ExpectedStateRevision: view.Result.StateRevision, RecoveryEpoch: view.Result.RecoveryEpoch, TargetDigest: "sha256:" + hex.EncodeToString(sum[:]), IdempotencyKey: key, GateID: gateID, SubjectID: subjectID, DefinitionVersion: view.Data.Definition.DefinitionVersion}
	return requestTyped(client, ctx, profile, requestSpec{localtransport.MethodPost, "/api/v1/gates/" + gateID + "/check", "api.v1.gates.check", maxOperationResponseBodyBytes, operationTimeout, false}, input, func(data generated.GateEvaluation, result generated.RunResult) bool {
		return validGateData(data, generated.SchemaIDGateEvaluation) && data.GateID == gateID && data.SubjectID == subjectID && data.RecoveryEpoch == result.RecoveryEpoch
	})
}

func (client *client) SubmitGateEvidence(ctx context.Context, profile serverconfig.Profile, input generated.GateEvidenceRequest) (TypedResponse[generated.GateEvidenceSubmission], error) {
	var zero TypedResponse[generated.GateEvidenceSubmission]
	if !gateToken(input.GateID) || !validGateData(input, generated.SchemaIDGateEvidenceRequest) {
		return zero, failure.New(generated.ErrorCodeInputInvalid, "gate-evidence", false)
	}
	return requestTyped(client, ctx, profile, requestSpec{localtransport.MethodPost, "/api/v1/gates/" + input.GateID + "/evidence", "api.v1.gate-evidence.create", maxOperationResponseBodyBytes, operationTimeout, true}, input, func(data generated.GateEvidenceSubmission, result generated.RunResult) bool {
		return validGateData(data, generated.SchemaIDGateEvidenceSubmission) && data.EvidenceID == input.EvidenceID && data.StateRevision == result.StateRevision && data.RecoveryEpoch == result.RecoveryEpoch
	})
}

func (client *client) SubmitProfileDraft(ctx context.Context, profile serverconfig.Profile, input generated.GateProfileDraftRequest) (TypedResponse[generated.GateProfileDraftSubmission], error) {
	var zero TypedResponse[generated.GateProfileDraftSubmission]
	if !validGateData(input, generated.SchemaIDGateProfileDraftRequest) {
		return zero, failure.New(generated.ErrorCodeInputInvalid, "profile-draft", false)
	}
	return requestTyped(client, ctx, profile, requestSpec{localtransport.MethodPost, "/api/v1/gates/profile-drafts", "api.v1.gate-profile-drafts.create", maxOperationResponseBodyBytes, operationTimeout, true}, input, func(data generated.GateProfileDraftSubmission, result generated.RunResult) bool {
		return validGateData(data, generated.SchemaIDGateProfileDraftSubmission) && data.BindingID == input.BindingID && data.StateRevision == result.StateRevision && data.RecoveryEpoch == result.RecoveryEpoch
	})
}
