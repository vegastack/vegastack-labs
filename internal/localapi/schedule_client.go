package localapi

import (
	"context"
	"encoding/json"
	"time"

	"github.com/vegastack/vegastack-labs/internal/failure"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/localtransport"
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

func (client *client) GetScheduledPolicy(ctx context.Context, profile serverconfig.Profile, policyID string) (TypedResponse[generated.BrowserScheduledJobPolicy], error) {
	var zero TypedResponse[generated.BrowserScheduledJobPolicy]
	if !validPathToken(policyID) {
		return zero, failure.New(generated.ErrorCodeInputInvalid, "scheduled-policy", false)
	}
	return requestTyped(client, ctx, profile, requestSpec{localtransport.MethodGet, "/api/v1/scheduled-job-policies/" + policyID, "api.v1.scheduled-job-policies.get", maxOperationResponseBodyBytes, operationTimeout, false}, nil, func(data generated.BrowserScheduledJobPolicy, result generated.RunResult) bool {
		raw, err := json.Marshal(data)
		return err == nil && generated.ValidateContractJSON(generated.SchemaIDBrowserScheduledJobPolicy, raw, generated.ContractExact) == nil && data.PolicyID == policyID && data.StateRevision == result.StateRevision && data.RecoveryEpoch == result.RecoveryEpoch && data.TargetDigest != ""
	})
}

func (client *client) ListScheduledPolicies(ctx context.Context, profile serverconfig.Profile) (TypedResponse[generated.BrowserScheduledJobPolicyListData], error) {
	return requestTyped(client, ctx, profile, requestSpec{localtransport.MethodGet, "/api/v1/scheduled-job-policies", "api.v1.scheduled-job-policies.list", maxOperationResponseBodyBytes, operationTimeout, false}, nil, func(data generated.BrowserScheduledJobPolicyListData, result generated.RunResult) bool {
		return data.Schema == generated.SchemaIDBrowserScheduledJobPolicyListData && data.StateRevision == result.StateRevision && data.RecoveryEpoch == result.RecoveryEpoch && len(data.Items) <= 100
	})
}

func (client *client) InspectScheduledPolicy(ctx context.Context, profile serverconfig.Profile, policyID string) (TypedResponse[generated.BrowserScheduledJobPolicy], error) {
	var zero TypedResponse[generated.BrowserScheduledJobPolicy]
	if !validPathToken(policyID) {
		return zero, failure.New(generated.ErrorCodeInputInvalid, "scheduled-policy", false)
	}
	return requestTyped(client, ctx, profile, requestSpec{localtransport.MethodGet, "/api/v1/scheduled-job-policies/" + policyID, "api.v1.scheduled-job-policies.get", maxOperationResponseBodyBytes, operationTimeout, false}, nil, func(data generated.BrowserScheduledJobPolicy, result generated.RunResult) bool {
		return data.Schema == generated.SchemaIDBrowserScheduledJobPolicy && data.PolicyID == policyID && data.StateRevision == result.StateRevision && data.RecoveryEpoch == result.RecoveryEpoch
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
	token, err := client.results.RequestID()
	if err != nil {
		return zero, err
	}
	key, err := client.results.RequestID()
	if err != nil {
		return zero, err
	}
	input := generated.ScheduledJobRequest{Schema: generated.SchemaIDScheduledJobRequest, SchemaVersion: "1.1.0", ExpectedStateRevision: policyResponse.Data.StateRevision, RecoveryEpoch: policyResponse.Data.RecoveryEpoch, TargetDigest: policyResponse.Data.TargetDigest, IdempotencyKey: key, PolicyID: policyID, PolicyRevision: policyResponse.Data.Revision, OccurrenceToken: token, ObservedAt: time.Now().UTC().Truncate(time.Second).Format(time.RFC3339)}
	return requestTyped(client, ctx, profile, requestSpec{localtransport.MethodPost, "/api/v1/scheduled-job-policies/" + policyID + "/occurrences", "api.v1.scheduled-occurrences.create", maxOperationResponseBodyBytes, operationTimeout, true}, input, func(data generated.ScheduledJob, result generated.RunResult) bool {
		return data.Schema == generated.SchemaIDScheduledJob && data.PolicyID == policyID && data.PolicyRevision == input.PolicyRevision && data.RecoveryEpoch == result.RecoveryEpoch
	})
}

func (client *client) CancelSchedule(ctx context.Context, profile serverconfig.Profile, jobID string) (TypedResponse[generated.ScheduledJob], error) {
	var zero TypedResponse[generated.ScheduledJob]
	if !validPathToken(jobID) {
		return zero, failure.New(generated.ErrorCodeInputInvalid, "scheduled-job", false)
	}
	key, err := client.results.RequestID()
	if err != nil {
		return zero, err
	}
	input := generated.ScheduledJobCancelRequest{Schema: generated.SchemaIDScheduledJobCancelRequest, SchemaVersion: "1.1.0", IdempotencyKey: key}
	return requestTyped(client, ctx, profile, requestSpec{localtransport.MethodPost, "/api/v1/scheduled-jobs/" + jobID + "/cancel", "api.v1.scheduled-jobs.cancel", maxOperationResponseBodyBytes, operationTimeout, true}, input, func(data generated.ScheduledJob, result generated.RunResult) bool {
		return data.Schema == generated.SchemaIDScheduledJob && data.JobID == jobID && data.Status == "cancelled" && data.RecoveryEpoch == result.RecoveryEpoch
	})
}
