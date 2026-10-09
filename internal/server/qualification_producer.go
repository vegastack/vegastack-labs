package server

import (
	"context"
	"github.com/vegastack/vegastack-labs/internal/failure"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"github.com/vegastack/vegastack-labs/internal/qualification"
)

// Lookup returns an existing terminal execution reference. It performs no
// native observation, evidence creation or qualification transition.
func (s *nativeQualificationService) LookupNativeProducerReference(ctx context.Context, in generated.NativeProducerLookupRequest) (generated.NativeProducerReference, error) {
	var zero generated.NativeProducerReference
	deny := func() (generated.NativeProducerReference, error) {
		return zero, failure.New(generated.ErrorCodePrerequisiteBlocked, "native-producer", false)
	}
	if s == nil || s.gates == nil || s.authority == nil {
		return deny()
	}
	scope, err := qualification.LoadServerScope(ctx)
	if err != nil || hostaction.Digest(scope) != in.ScopeDigest {
		return deny()
	}
	found := false
	for _, g := range scope.Guests {
		if g.HostID == in.HostID {
			found = true
		}
	}
	if !found {
		return deny()
	}
	gates := s.gates
	if in.ScenarioID == "native-credential-lifecycle" {
		authority, err := s.authority.CurrentAuthority(ctx)
		if err != nil {
			return deny()
		}
		measured, err := qualification.MeasureControllerIdentity(ctx, scope, authority.InstanceID)
		if err != nil {
			return deny()
		}
		gates = gates.WithNativeControllerIdentity(measured)
	}
	return gates.LookupNativeProducerReference(ctx, in, scope)
}
