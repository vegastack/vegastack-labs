package plan

import (
	"context"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"github.com/vegastack/vegastack-labs/internal/hostreplacement"
	"github.com/vegastack/vegastack-labs/internal/store"
	"strings"
)

type HostReplacementDraftReader interface {
	GetDraft(context.Context, string) (store.HostReplacementDraft, error)
	ValidateDraftBinding(context.Context, store.HostReplacementDraft) error
}

func (s *Service) replacementPlan(ctx context.Context, d generated.DeclarationRevision, ops []generated.PlanOperation) (*generated.HostReplacementRequest, *generated.HostAliasClaimRequest, error) {
	candidate := d.HostAliasClaim != nil || d.DeclarationType == "host.replacement" || d.DeclarationType == "host.alias-claim"
	for _, op := range ops {
		candidate = candidate || op.AdapterID == hostreplacement.AdapterID || strings.HasPrefix(op.OperationType, "host.replacement.") || op.OperationType == hostreplacement.AliasClaimOperation
	}
	for _, ext := range d.Extensions {
		candidate = candidate || ext.Name == hostreplacement.ReplacementExtension || ext.Name == hostreplacement.AliasClaimExtension
	}
	if !candidate {
		return nil, nil, nil
	}
	deny := func() (*generated.HostReplacementRequest, *generated.HostAliasClaimRequest, error) {
		return nil, nil, planError(generated.ErrorCodeAuthorizationDenied)
	}
	if len(ops) != 1 || len(d.Extensions) != 1 || s.config.AuthorizationBranch != "human" || s.config.ExecutorMode != "central" {
		return deny()
	}
	op := ops[0]
	if op.AdapterID != hostreplacement.AdapterID || op.InputDigest != op.ArtifactDigest || !op.Idempotent || d.Extensions[0].ValueDigest != op.InputDigest {
		return deny()
	}
	if op.OperationType == hostreplacement.AliasClaimOperation {
		if d.DeclarationType != "host.alias-claim" || d.HostAliasClaim == nil || op.TargetID != d.DeclarationID || d.Extensions[0].Name != hostreplacement.AliasClaimExtension || hostreplacement.ValidateAliasClaim(*d.HostAliasClaim) != nil || hostaction.Digest(*d.HostAliasClaim) != op.InputDigest || d.HostAliasClaim.RecoveryEpoch != d.RecoveryEpoch {
			return deny()
		}
		claim := *d.HostAliasClaim
		return nil, &claim, nil
	}
	if d.DeclarationType != "host.replacement" || d.HostAliasClaim != nil || s.config.HostReplacements == nil || d.Extensions[0].Name != hostreplacement.ReplacementExtension || (op.OperationType != hostreplacement.FreezeOperation && op.OperationType != hostreplacement.CommitOperation) {
		return deny()
	}
	draft, err := s.config.HostReplacements.GetDraft(ctx, op.TargetID)
	if err != nil {
		return nil, nil, err
	}
	if draft.ID != op.TargetID || draft.Digest != op.InputDigest || draft.Digest != hostaction.Digest(draft.Request) || hostreplacement.ValidateInput(draft.Request) != nil || op.OperationType != "host.replacement."+draft.Request.Operation || draft.Request.RecoveryEpoch != d.RecoveryEpoch {
		return deny()
	}
	if err := s.config.HostReplacements.ValidateDraftBinding(ctx, draft); err != nil {
		return nil, nil, err
	}
	return &draft.Request, nil, nil
}
