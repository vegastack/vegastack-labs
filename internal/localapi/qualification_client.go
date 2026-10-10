package localapi

import (
	"context"
	"github.com/vegastack/vegastack-labs/internal/failure"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"github.com/vegastack/vegastack-labs/internal/localtransport"
	"github.com/vegastack/vegastack-labs/internal/serverconfig"
)

func (c *client) InspectQualification(ctx context.Context, profile serverconfig.Profile, in generated.QualificationInspectRequest) (TypedResponse[generated.QualificationInspectData], error) {
	if !validGateData(in, generated.SchemaIDQualificationInspectRequest) {
		return TypedResponse[generated.QualificationInspectData]{}, failure.New(generated.ErrorCodeInputInvalid, "qualification-inspect", false)
	}
	return requestTyped(c, ctx, profile, requestSpec{localtransport.MethodPost, "/api/v1/qualification/inspect", "api.v1.qualification.inspect", maxOperationResponseBodyBytes, operationTimeout, false}, in, func(d generated.QualificationInspectData, r generated.RunResult) bool {
		return validGateData(d, generated.SchemaIDQualificationInspectData) && d.RequestDigest == hostaction.Digest(in) && d.Facts.TargetID == in.TargetID && d.Facts.TargetRevision == in.TargetRevision && d.Facts.TargetDigest == in.TargetDigest && d.Facts.PhysicalHostIdentityDigest == in.Scope.PhysicalHostIdentityDigest && d.StateRevision == r.StateRevision && d.StateRevision == in.ExpectedStateRevision && d.RecoveryEpoch == r.RecoveryEpoch && d.RecoveryEpoch == in.RecoveryEpoch
	})
}
func (c *client) CollectNativeQualification(ctx context.Context, profile serverconfig.Profile, in generated.NativeCollectRequest) (TypedResponse[generated.NativeCollectData], error) {
	if !validGateData(in, generated.SchemaIDNativeCollectRequest) {
		return TypedResponse[generated.NativeCollectData]{}, failure.New(generated.ErrorCodeInputInvalid, "qualification-collect", false)
	}
	return requestTyped(c, ctx, profile, requestSpec{localtransport.MethodPost, "/api/v1/qualification/collect", "api.v1.qualification.collect", maxOperationResponseBodyBytes, operationTimeout, true}, in, func(data generated.NativeCollectData, r generated.RunResult) bool {
		d := data.Submission
		if !validGateData(data, generated.SchemaIDNativeCollectData) || data.RequestDigest != hostaction.Digest(in) {
			return false
		}
		return validGateData(d, generated.SchemaIDGateEvidenceSubmission) && d.EvidenceID == in.EvidenceID && d.ChangeID == "gate-evidence-"+in.EvidenceID && d.Status == "draft" && d.StateRevision == r.StateRevision && d.StateRevision >= in.ExpectedStateRevision && d.RecoveryEpoch == r.RecoveryEpoch && d.RecoveryEpoch == in.RecoveryEpoch
	})
}
