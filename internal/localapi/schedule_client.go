package localapi

import (
	"context"
	"encoding/json"
	"time"

	"github.com/vegastack/vegastack-labs/internal/failure"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/localtransport"
	"github.com/vegastack/vegastack-labs/internal/schedule"
	"github.com/vegastack/vegastack-labs/internal/serverconfig"
)

func (client *client) SubmitScheduledPolicyDraft(ctx context.Context, profile serverconfig.Profile, policy generated.ScheduledJobPolicy) (TypedResponse[generated.ScheduledPolicyDraftSubmission], error) {
	var zero TypedResponse[generated.ScheduledPolicyDraftSubmission]
	raw, err := json.Marshal(policy)
	if err != nil || generated.ValidateContractJSON(generated.SchemaIDScheduledJobPolicy, raw, generated.ContractExact) != nil {
		return zero, failure.New(generated.ErrorCodeInputInvalid, "scheduled-policy-draft", false)
	}
	return requestTyped(client, ctx, profile, requestSpec{localtransport.MethodPost, "/api/v1/scheduled-job-policies/drafts", "api.v1.scheduled-job-policies.drafts.create", maxOperationResponseBodyBytes, operationTimeout, true}, policy, func(data generated.ScheduledPolicyDraftSubmission, result generated.RunResult) bool {
		return data.Schema == generated.SchemaIDScheduledPolicyDraftSubmission && data.PolicyID == policy.PolicyID && data.PolicyRevision == policy.Revision && data.PolicyDigest != "" && data.Status == "draft" && data.StateRevision == result.StateRevision && data.RecoveryEpoch == result.RecoveryEpoch
	})
}

func (client *client) GetScheduledPolicy(ctx context.Context, profile serverconfig.Profile, policyID string) (TypedResponse[generated.ScheduledJobPolicy], error) {
	var zero TypedResponse[generated.ScheduledJobPolicy]
	if !validPathToken(policyID) {
		return zero, failure.New(generated.ErrorCodeInputInvalid, "scheduled-policy", false)
	}
	return requestTyped(client, ctx, profile, requestSpec{localtransport.MethodGet, "/api/v1/scheduled-job-policies/" + policyID, "api.v1.scheduled-job-policies.get", maxOperationResponseBodyBytes, operationTimeout, false}, nil, func(data generated.ScheduledJobPolicy, result generated.RunResult) bool {
		return data.PolicyID == policyID && data.StateRevision == result.StateRevision && data.RecoveryEpoch == result.RecoveryEpoch
	})
}

func (client *client) DispatchSchedule(ctx context.Context, profile serverconfig.Profile, policyID string) (TypedResponse[generated.ScheduledJob], error) {
	var zero TypedResponse[generated.ScheduledJob]
	policyResponse, err := client.GetScheduledPolicy(ctx, profile, policyID)
	if err != nil {
		return zero, err
	}
	if policyResponse.ExitCode != 0 {
		return remapResponse[generated.ScheduledJob](policyResponse), nil
	}
	digest, err := schedule.ExactTargetDigest(policyResponse.Data)
	if err != nil {
		return zero, err
	}
	token, err := client.results.RequestID()
	if err != nil {
		return zero, err
	}
	key, err := client.results.RequestID()
	if err != nil {
		return zero, err
	}
	input := generated.ScheduledJobRequest{Schema: generated.SchemaIDScheduledJobRequest, SchemaVersion: "1.1.0", ExpectedStateRevision: policyResponse.Data.StateRevision, RecoveryEpoch: policyResponse.Data.RecoveryEpoch, TargetDigest: digest, IdempotencyKey: key, PolicyID: policyID, PolicyRevision: policyResponse.Data.Revision, OccurrenceToken: token, ObservedAt: time.Now().UTC().Truncate(time.Second).Format(time.RFC3339)}
	return requestTyped(client, ctx, profile, requestSpec{localtransport.MethodPost, "/api/v1/scheduled-jobs", "api.v1.scheduled-jobs.create", maxOperationResponseBodyBytes, operationTimeout, true}, input, func(data generated.ScheduledJob, result generated.RunResult) bool {
		return data.Schema == generated.SchemaIDScheduledJob && data.PolicyID == policyID && data.PolicyRevision == input.PolicyRevision && data.RecoveryEpoch == result.RecoveryEpoch
	})
}
