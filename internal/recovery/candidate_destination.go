package recovery

import (
	"context"
	"github.com/vegastack/vegastack-labs/internal/failure"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostreplacement"
	"github.com/vegastack/vegastack-labs/internal/store"
)

// SnapshotSizeReader measures verified restored bytes, not manifest assertions.
// Unsupported source adapters cannot stage a replacement candidate.
type SnapshotSizeReader interface {
	InspectSnapshotBytes(context.Context) (int64, error)
}
type replacementDestinationResolver interface {
	ResolveReplacementDestination(context.Context, generated.RestoreBinding) (generated.HostReplacementRequest, error)
}
type replacementDestinationInspector interface {
	InspectReplacementDestination(context.Context, string, CandidatePaths, int64) (hostreplacement.ReplacementDestination, error)
}

func (s StoreRecoveryBundleStore) ResolveReplacementDestination(ctx context.Context, b generated.RestoreBinding) (generated.HostReplacementRequest, error) {
	if s.Authority == nil {
		return generated.HostReplacementRequest{}, failure.New(generated.ErrorCodePrerequisiteBlocked, "replacement-destination", false)
	}
	return store.NewHostReplacementRepository(s.Authority).ResolveReplacementDestination(ctx, b)
}

func (m CandidateManager) preflightReplacementDestination(ctx context.Context, b generated.RestoreBinding, source VerifiedSource, paths CandidatePaths) error {
	if b.ReplacementContinuity == nil {
		return nil
	}
	deny := func() error {
		return failure.New(generated.ErrorCodePrerequisiteBlocked, "replacement-destination", false)
	}
	resolver, ok := m.Bundles.(replacementDestinationResolver)
	if !ok {
		return deny()
	}
	in, err := resolver.ResolveReplacementDestination(ctx, b)
	if err != nil {
		return err
	}
	if hostreplacement.BindRestore(in, b) != nil {
		return deny()
	}
	reader, ok := source.Snapshot.(SnapshotSizeReader)
	if !ok {
		return deny()
	}
	size, err := reader.InspectSnapshotBytes(ctx)
	if err != nil || size <= 0 {
		return deny()
	}
	inspector, ok := m.Storage.(replacementDestinationInspector)
	if !ok {
		return deny()
	}
	observed, err := inspector.InspectReplacementDestination(ctx, m.DatabasePath, paths, size)
	if err != nil {
		return err
	}
	// These bindings were resolved from the current server-owned registration and
	// role declarations above; none come from the requesting browser's preview.
	observed.HostID = in.NewHostID
	observed.IdentityDigest = in.NewIdentityDigest
	observed.TargetDigest = in.NewTargetDigest
	observed.ProfileLockDigest = in.ProfileLockDigest
	observed.PreservedPreimageDigest = in.PreservedPreimageDigest
	if hostreplacement.ValidateDestination(in, observed) != nil {
		return deny()
	}
	return nil
}
