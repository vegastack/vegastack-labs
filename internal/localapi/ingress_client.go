package localapi

import (
	"context"
	"github.com/vegastack/vegastack-labs/internal/failure"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/localtransport"
	"github.com/vegastack/vegastack-labs/internal/serverconfig"
)

func (c *client) DraftIngress(ctx context.Context, p serverconfig.Profile, q generated.IngressDraftRequest) (TypedResponse[generated.IngressDraftSubmission], error) {
	if !validGateData(q, generated.SchemaIDIngressDraftRequest) {
		return TypedResponse[generated.IngressDraftSubmission]{}, failure.New(generated.ErrorCodeInputInvalid, "ingress-request", false)
	}
	return requestTyped(c, ctx, p, requestSpec{localtransport.MethodPost, "/api/v1/network/ingress/draft", "api.v1.network.ingress.draft", maxOperationResponseBodyBytes, operationTimeout, false}, q, func(d generated.IngressDraftSubmission, r generated.RunResult) bool {
		return validGateData(d, generated.SchemaIDIngressDraftSubmission) && d.RecoveryEpoch == q.RecoveryEpoch && d.StateRevision == r.StateRevision && d.RecoveryEpoch == r.RecoveryEpoch
	})
}
func (c *client) IngressStatus(ctx context.Context, p serverconfig.Profile, id string) (TypedResponse[generated.IngressStatusData], error) {
	if !validPathToken(id) {
		return TypedResponse[generated.IngressStatusData]{}, failure.New(generated.ErrorCodeInputInvalid, "ingress-profile", false)
	}
	return requestTyped(c, ctx, p, requestSpec{localtransport.MethodGet, "/api/v1/network/ingress/" + id, "api.v1.network.ingress.status", maxOperationResponseBodyBytes, operationTimeout, false}, nil, func(d generated.IngressStatusData, r generated.RunResult) bool {
		return validGateData(d, generated.SchemaIDIngressStatusData) && d.ProfileID == id && d.StateRevision == r.StateRevision && d.RecoveryEpoch == r.RecoveryEpoch
	})
}

func (c *client) ObserveIngress(ctx context.Context, p serverconfig.Profile, q generated.IngressDraftRequest) (TypedResponse[generated.IngressStatusData], error) {
	if !validGateData(q, generated.SchemaIDIngressDraftRequest) {
		return TypedResponse[generated.IngressStatusData]{}, failure.New(generated.ErrorCodeInputInvalid, "ingress-request", false)
	}
	return requestTyped(c, ctx, p, requestSpec{localtransport.MethodPost, "/api/v1/network/ingress/observe", "api.v1.network.ingress.observe", maxOperationResponseBodyBytes, operationTimeout, false}, q, func(d generated.IngressStatusData, r generated.RunResult) bool {
		return validGateData(d, generated.SchemaIDIngressStatusData) && d.ProfileID == q.Change.ProfileID && d.RecoveryEpoch == q.RecoveryEpoch && d.StateRevision == r.StateRevision && d.RecoveryEpoch == r.RecoveryEpoch
	})
}

func (c *client) SubmitIngressRolloutEvidence(ctx context.Context, p serverconfig.Profile, q generated.IngressRolloutEvidenceRequest) (TypedResponse[generated.IngressStatusData], error) {
	if !validGateData(q, generated.SchemaIDIngressRolloutEvidenceRequest) {
		return TypedResponse[generated.IngressStatusData]{}, failure.New(generated.ErrorCodeInputInvalid, "ingress-rollout", false)
	}
	return requestTyped(c, ctx, p, requestSpec{localtransport.MethodPost, "/api/v1/network/ingress/rollout-evidence", "api.v1.network.ingress.rollout-evidence", maxOperationResponseBodyBytes, operationTimeout, false}, q, func(d generated.IngressStatusData, r generated.RunResult) bool {
		return validGateData(d, generated.SchemaIDIngressStatusData) && d.ProfileID == q.ProfileID && d.StateRevision == r.StateRevision && d.RecoveryEpoch == r.RecoveryEpoch && d.RecoveryEpoch == q.RecoveryEpoch && d.Status == "partial" && d.RotationStage != "complete"
	})
}

func (c *client) DraftIngressPilotEvidence(ctx context.Context, p serverconfig.Profile, q generated.IngressPilotEvidenceRequest) (TypedResponse[generated.GateEvidenceSubmission], error) {
	if !validGateData(q, generated.SchemaIDIngressPilotEvidenceRequest) {
		return TypedResponse[generated.GateEvidenceSubmission]{}, failure.New(generated.ErrorCodeInputInvalid, "pilot-evidence", false)
	}
	return requestTyped(c, ctx, p, requestSpec{localtransport.MethodPost, "/api/v1/network/ingress/pilot-evidence", "api.v1.network.ingress.pilot-evidence", maxOperationResponseBodyBytes, operationTimeout, false}, q, func(d generated.GateEvidenceSubmission, r generated.RunResult) bool {
		return validGateData(d, generated.SchemaIDGateEvidenceSubmission) && d.EvidenceID == q.EvidenceID && d.StateRevision == r.StateRevision && d.RecoveryEpoch == q.Request.RecoveryEpoch
	})
}
