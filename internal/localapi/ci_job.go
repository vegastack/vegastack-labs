package localapi

import (
	"context"
	"github.com/vegastack/vegastack-labs/internal/failure"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"github.com/vegastack/vegastack-labs/internal/localtransport"
	"github.com/vegastack/vegastack-labs/internal/serverconfig"
)

func (c *client) DraftCIJob(ctx context.Context, p serverconfig.Profile, in generated.CiJobDraftRequest) (TypedResponse[generated.DeclarationRevision], error) {
	if !validGateData(in, generated.SchemaIDCiJobDraftRequest) {
		return TypedResponse[generated.DeclarationRevision]{}, failure.New(generated.ErrorCodeInputInvalid, "ci-job-request", false)
	}
	return requestTyped(c, ctx, p, requestSpec{localtransport.MethodPost, "/api/v1/ci/jobs/drafts", "api.v1.ci.jobs.drafts.create", maxOperationResponseBodyBytes, operationTimeout, true}, in, func(d generated.DeclarationRevision, r generated.RunResult) bool {
		if !validGateData(d, generated.SchemaIDDeclarationRevision) || d.CIJob == nil || len(d.Operations) != 1 || len(d.Extensions) != 1 {
			return false
		}
		q := d.CIJob
		op := d.Operations[0]
		return validGateData(*q, generated.SchemaIDCiJobRequest) && q.Definition.EnrollmentID == in.EnrollmentID && q.ExecutionBindingID == in.ExecutionBindingID && q.RunID == in.RunID && q.Attempt == in.Attempt && q.ExpectedStateRevision == in.ExpectedStateRevision && q.RecoveryEpoch == in.RecoveryEpoch && q.IdempotencyKey == in.IdempotencyKey && q.ReasonDigest == in.ReasonDigest && d.DeclarationID == "ci-job-"+hostaction.Digest(q)[7:39] && d.DeclarationType == "ci.job.execute" && d.Status == "draft" && d.Revision == 1 && d.StateRevision == in.ExpectedStateRevision+1 && r.StateRevision == d.StateRevision+1 && r.RecoveryEpoch == in.RecoveryEpoch && d.RecoveryEpoch == in.RecoveryEpoch && d.Extensions[0].Name == "x-credential-bindings" && op.Sequence == 1 && op.OperationID == "ci-job" && op.OperationType == "ci.job.execute" && op.AdapterID == "host-action" && op.TargetID == q.HostID && op.ArtifactDigest == hostaction.Digest(q) && !op.Idempotent && op.OffsiteRunSpec == nil
	})
}
func ciJobRemoteArguments(s requestSpec) []string {
	if s.command == "api.v1.ci.jobs.drafts.create" && s.path == "/api/v1/ci/jobs/drafts" {
		return []string{"ci", "job", "draft"}
	}
	return nil
}
