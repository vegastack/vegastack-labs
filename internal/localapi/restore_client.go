package localapi

import (
	"context"
	"encoding/json"

	"github.com/vegastack/vegastack-labs/internal/failure"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/localtransport"
	"github.com/vegastack/vegastack-labs/internal/serverconfig"
)

func (client *client) PlanRestore(ctx context.Context, profile serverconfig.Profile, input generated.RestoreRequest) (TypedResponse[generated.RestoreBinding], error) {
	return restoreMutation(client, ctx, profile, "/api/v1/restores/plans", "api.v1.restores.plan", generated.SchemaIDRestoreRequest, input, input.PointID, "")
}

func (client *client) RunRestore(ctx context.Context, profile serverconfig.Profile, input generated.RestoreRunRequest) (TypedResponse[generated.RestoreBinding], error) {
	if !validPathToken(input.PlanID) {
		return TypedResponse[generated.RestoreBinding]{}, failure.New(generated.ErrorCodeInputInvalid, "restore-plan", false)
	}
	return restoreMutation(client, ctx, profile, "/api/v1/restores/plans/"+input.PlanID+"/run", "api.v1.restores.run", generated.SchemaIDRestoreRunRequest, input, input.PointID, input.PlanID)
}

func restoreMutation(client *client, ctx context.Context, profile serverconfig.Profile, path, operation, schema string, input any, pointID, planID string) (TypedResponse[generated.RestoreBinding], error) {
	var zero TypedResponse[generated.RestoreBinding]
	raw, err := json.Marshal(input)
	if err != nil || generated.ValidateContractJSON(schema, raw, generated.ContractExact) != nil {
		return zero, failure.New(generated.ErrorCodeInputInvalid, "restore-request", false)
	}
	return requestTyped(client, ctx, profile, requestSpec{localtransport.MethodPost, path, operation, maxOperationResponseBodyBytes, operationTimeout, true}, input, func(data generated.RestoreBinding, result generated.RunResult) bool {
		encoded, err := json.Marshal(data)
		return err == nil && generated.ValidateContractJSON(generated.SchemaIDRestoreBinding, encoded, generated.ContractExact) == nil && data.PointID == pointID && (planID == "" || data.PlanID == planID) && data.PriorRecoveryEpoch == result.RecoveryEpoch
	})
}

func (client *client) VerifyRestore(ctx context.Context, profile serverconfig.Profile, input generated.RestoreVerifyRequest) (TypedResponse[generated.RestoreVerification], error) {
	var zero TypedResponse[generated.RestoreVerification]
	if !validPathToken(input.PlanID) {
		return zero, failure.New(generated.ErrorCodeInputInvalid, "restore-plan", false)
	}
	raw, err := json.Marshal(input)
	if err != nil || generated.ValidateContractJSON(generated.SchemaIDRestoreVerifyRequest, raw, generated.ContractExact) != nil {
		return zero, failure.New(generated.ErrorCodeInputInvalid, "restore-request", false)
	}
	return requestTyped(client, ctx, profile, requestSpec{localtransport.MethodPost, "/api/v1/restores/plans/" + input.PlanID + "/verify", "api.v1.restores.verify", maxOperationResponseBodyBytes, operationTimeout, true}, input, func(data generated.RestoreVerification, result generated.RunResult) bool {
		encoded, err := json.Marshal(data)
		return err == nil && generated.ValidateContractJSON(generated.SchemaIDRestoreVerification, encoded, generated.ContractExact) == nil && data.PlanID == input.PlanID && data.PointID == input.PointID && data.NextRecoveryEpoch == result.RecoveryEpoch
	})
}

func (client *client) GetRestore(ctx context.Context, profile serverconfig.Profile, planID string) (TypedResponse[generated.BrowserRestoreStatus], error) {
	if !validPathToken(planID) {
		return TypedResponse[generated.BrowserRestoreStatus]{}, failure.New(generated.ErrorCodeInputInvalid, "restore-plan", false)
	}
	return requestTyped(client, ctx, profile, requestSpec{localtransport.MethodGet, "/api/v1/restores/plans/" + planID, "api.v1.restores.get", maxOperationResponseBodyBytes, statusTimeout, false}, nil, func(data generated.BrowserRestoreStatus, result generated.RunResult) bool {
		raw, err := json.Marshal(data)
		return err == nil && generated.ValidateContractJSON(generated.SchemaIDBrowserRestoreStatus, raw, generated.ContractExact) == nil && data.PlanID == planID && data.RecoveryEpoch == result.RecoveryEpoch
	})
}
