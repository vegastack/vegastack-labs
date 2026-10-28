package localapi

import (
	"context"
	"github.com/vegastack/vegastack-labs/internal/failure"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/localtransport"
	"github.com/vegastack/vegastack-labs/internal/serverconfig"
)

func (c *client) DraftCIPublication(ctx context.Context, p serverconfig.Profile, in generated.CiPublicationDraftRequest) (TypedResponse[generated.DeclarationRevision], error) {
	if !validGateData(in, generated.SchemaIDCiPublicationDraftRequest) {
		return TypedResponse[generated.DeclarationRevision]{}, failure.New(generated.ErrorCodeInputInvalid, "ci-publication-request", false)
	}
	return requestTyped(c, ctx, p, requestSpec{localtransport.MethodPost, "/api/v1/ci/publications/drafts", "api.v1.ci.publications.drafts.create", maxOperationResponseBodyBytes, operationTimeout, true}, in, func(d generated.DeclarationRevision, r generated.RunResult) bool {
		if !validGateData(d, generated.SchemaIDDeclarationRevision) || d.DeclarationType != "ci.artifact.publish" || d.CIJob != nil || d.CIEnrollment != nil || len(d.Operations) != 1 || len(d.Extensions) != 2 || d.Status != "draft" || d.Revision != 1 || d.StateRevision != in.ExpectedStateRevision+1 || r.StateRevision != d.StateRevision+1 || d.RecoveryEpoch != in.RecoveryEpoch || r.RecoveryEpoch != in.RecoveryEpoch {
			return false
		}
		op := d.Operations[0]
		if op.OperationID != "ci-publication" || op.OperationType != "ci.artifact.publish" || op.AdapterID != "oci-registry" || op.TargetID != in.BindingID || op.Idempotent || op.Sequence != 1 || op.OffsiteRunSpec != nil {
			return false
		}
		seen := map[string]bool{}
		for _, x := range d.Extensions {
			if seen[x.Name] {
				return false
			}
			seen[x.Name] = true
			if x.Name == "x-ci-publication" {
				if x.ValueDigest != op.ArtifactDigest {
					return false
				}
			} else if x.Name == "x-credential-bindings" {
				if x.ValueDigest != op.InputDigest {
					return false
				}
			} else {
				return false
			}
		}
		return true
	})
}
func ciPublicationRemoteArguments(s requestSpec) []string {
	if s.command == "api.v1.ci.publications.drafts.create" && s.path == "/api/v1/ci/publications/drafts" {
		return []string{"ci", "publication", "draft"}
	}
	return nil
}
