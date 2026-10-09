package recovery

import (
	"context"

	"github.com/vegastack/vegastack-labs/internal/failure"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"github.com/vegastack/vegastack-labs/internal/store"
)

// ReplacementContinuityGuard derives bounded current ownership history from
// the live authority and the actual verified snapshot, before plan approval.
type ReplacementContinuityGuard interface {
	PrepareReplacementContinuity(context.Context, generated.RestoreRequest, VerifiedSource) (*generated.HostReplacementContinuityReference, error)
}
type StoreReplacementContinuityGuard struct {
	Authority    *store.Store
	Replacements *store.HostReplacementRepository
}

func (g StoreReplacementContinuityGuard) PrepareReplacementContinuity(ctx context.Context, request generated.RestoreRequest, source VerifiedSource) (*generated.HostReplacementContinuityReference, error) {
	deny := func() (*generated.HostReplacementContinuityReference, error) {
		return nil, failure.New(generated.ErrorCodePrerequisiteBlocked, "replacement-continuity", false)
	}
	if g.Authority == nil || g.Replacements == nil {
		return deny()
	}
	current, err := g.Authority.HostAliasHighWatermark(ctx)
	if err != nil {
		return nil, err
	}
	if current == 0 {
		if request.ReplacementContinuity != nil {
			return deny()
		}
		return nil, nil
	}
	draft, err := g.Authority.FindFrozenControlReplacement(ctx, request.FormerHostID, request.ReplacementHostID, request.PointID)
	if err != nil {
		return nil, err
	}
	if draft.Request.Source == nil || draft.Request.Source.SourceBindingDigest != hostaction.Digest(source.Binding) || draft.Request.Source.CustodyReferenceID != request.RecoveryDraftID || draft.Request.Source.CustodyBindingDigest != request.SourceAdmissionDigest {
		return deny()
	}
	watermark, err := InspectVerifiedSourceAliasWatermark(ctx, source)
	if err != nil {
		return nil, err
	}
	ref := generated.HostReplacementContinuityReference{Schema: generated.SchemaIDHostReplacementContinuityReference, SchemaVersion: "1.0.0", ReplacementID: draft.Request.ReplacementID, SourcePointID: source.Binding.PointID, SourceBindingDigest: hostaction.Digest(source.Binding), SourceAliasHighWatermark: watermark}
	continuity, err := g.Authority.LoadHostReplacementContinuity(ctx, draft.Request.ReplacementID, ref)
	if err != nil {
		return nil, err
	}
	if request.ReplacementContinuity != nil && !sameJSONValue(request.ReplacementContinuity, &continuity.Reference) {
		return deny()
	}
	return &continuity.Reference, nil
}
