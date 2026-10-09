package plan

import (
	"context"
	"github.com/vegastack/vegastack-labs/internal/debianaccess"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
)

func (service *Service) accessSequence(ctx context.Context, declaration generated.DeclarationRevision, ops []generated.PlanOperation) (*generated.HostAccessSequence, error) {
	if declaration.DeclarationType != "host.access" {
		return nil, nil
	}
	if service.config.HostActions == nil || service.config.AuthorizationBranch != "human" || service.config.ExecutorMode != "central" {
		return nil, planError(generated.ErrorCodeAuthorizationDenied)
	}
	requests := make([]generated.HostActionRequest, len(ops))
	for i, op := range ops {
		if len(op.ArtifactDigest) != 71 {
			return nil, planError(generated.ErrorCodeInputInvalid)
		}
		d, e := service.config.HostActions.GetDraft(ctx, "host-action-"+op.ArtifactDigest[7:39])
		if e != nil {
			return nil, e
		}
		if d.Digest != op.ArtifactDigest {
			return nil, planError(generated.ErrorCodeIntegrityFailure)
		}
		requests[i] = d.Request
	}
	seq, e := debianaccess.Sequence(ops, requests)
	if e != nil {
		return nil, planError(generated.ErrorCodeInputInvalid)
	}
	sealed := false
	for _, extension := range declaration.Extensions {
		if extension.Name == "x-host-access-sequence" {
			sealed = extension.ValueDigest == hostaction.Digest(seq)
		}
	}
	if !sealed {
		return nil, planError(generated.ErrorCodePlanStale)
	}
	return &seq, nil
}
