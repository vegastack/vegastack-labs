package server

import (
	"context"
	"github.com/vegastack/vegastack-labs/internal/adapter"
	collector "github.com/vegastack/vegastack-labs/internal/adapter/hostdiscovery"
	"github.com/vegastack/vegastack-labs/internal/failure"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"github.com/vegastack/vegastack-labs/internal/qualification"
	"github.com/vegastack/vegastack-labs/internal/store"
)

// nativeQualificationService is composed solely from existing server-owned
// repositories and the same scoped credential borrower as host discovery.
type nativeQualificationService struct {
	adapters  *adapter.Registry
	authority *store.Store
	gates     *store.GateRepository
	targets   *store.HostDiscoveryRepository
	borrower  collector.CredentialBorrower
}

func (s *nativeQualificationService) Inspect(ctx context.Context, in generated.QualificationInspectRequest) (generated.QualificationInspectData, error) {
	var zero generated.QualificationInspectData
	protected, err := qualification.LoadServerScope(ctx)
	if err != nil || s == nil || s.targets == nil || s.borrower == nil || hostaction.Digest(protected) != hostaction.Digest(in.Scope) {
		return zero, failure.New(generated.ErrorCodePrerequisiteBlocked, "native-protected-scope", false)
	}
	target, observed, err := s.targets.ResolveQualificationTarget(ctx, in)
	if err != nil {
		return zero, err
	}
	authorized, err := qualification.NewAuthorizedTarget(target, protected, observed, s.borrower)
	if err != nil {
		return zero, failure.New(generated.ErrorCodePrerequisiteBlocked, "native-target", false)
	}
	facts, err := qualification.CollectSuitability(ctx, authorized)
	if err != nil {
		return zero, err
	}
	// Grants, target binding and state must remain current after the read I/O.
	if err = s.targets.CheckCollection(ctx, target); err != nil {
		return zero, err
	}
	return generated.QualificationInspectData{Schema: generated.SchemaIDQualificationInspectData, SchemaVersion: "1.0.0", Facts: facts, RequestDigest: hostaction.Digest(in), StateRevision: in.ExpectedStateRevision, RecoveryEpoch: in.RecoveryEpoch}, nil
}
