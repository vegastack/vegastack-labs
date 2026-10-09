package hostdiscovery

import (
	"context"
	"github.com/vegastack/vegastack-labs/internal/failure"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/identity"
	"time"
)

type Service struct {
	Repository Repository
	Collector  Collector
}

func (s *Service) Discover(ctx context.Context, request generated.HostDiscoveryRequest) (generated.HostDiscoverySubmission, error) {
	var empty generated.HostDiscoverySubmission
	if s == nil || s.Repository == nil || s.Collector == nil {
		return empty, Error(generated.ErrorCodePrerequisiteBlocked)
	}
	_, ok := identity.PrincipalFromContext(ctx)
	if !ok {
		return empty, Error(generated.ErrorCodeAuthenticationRequired)
	}
	a, err := Attribution(ctx, "discovery-"+Digest(request)[7:39])
	if err != nil {
		return empty, Error(generated.ErrorCodeAuthenticationRequired)
	}
	attempt, err := s.Repository.Begin(ctx, BeginRequest{Request: request, Attribution: a})
	if err != nil {
		return empty, sanitize(err)
	}
	if attempt.Observation != nil {
		observation, err := s.Repository.Get(ctx, attempt.Observation.ObservationID)
		if err != nil {
			return empty, sanitize(err)
		}
		return submission(observation, false, Digest(request)), nil
	}
	collectionCtx, cancel := context.WithDeadline(ctx, attempt.Deadline)
	defer cancel()
	collection, err := s.Collector.Collect(collectionCtx, attempt.Target)
	if err != nil {
		stable := sanitize(err)
		code, _ := failure.As(stable)
		// Preserve attribution through cancellation, with a bounded local-only audit.
		auditCtx, stop := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
		defer stop()
		if auditErr := s.Repository.Fail(auditCtx, attempt, code.Code, a); auditErr != nil {
			return empty, sanitize(auditErr)
		}
		return empty, stable
	}
	observation, err := s.Repository.Complete(ctx, CompleteRequest{Attempt: attempt, Collection: collection, Attribution: a})
	if err != nil {
		return empty, sanitize(err)
	}
	return submission(observation, true, Digest(request)), nil
}
func (s *Service) Get(ctx context.Context, id string) (generated.HostObservation, error) {
	if s == nil || s.Repository == nil {
		return generated.HostObservation{}, Error(generated.ErrorCodePrerequisiteBlocked)
	}
	result, err := s.Repository.Get(ctx, id)
	if err != nil {
		return generated.HostObservation{}, sanitize(err)
	}
	return result, nil
}
func submission(o generated.HostObservation, created bool, originalRequestDigest string) generated.HostDiscoverySubmission {
	return generated.HostDiscoverySubmission{Schema: generated.SchemaIDHostDiscoverySubmission, SchemaVersion: "1.0.0", Observation: o, Created: created, OriginalRequestDigest: originalRequestDigest}
}
func sanitize(err error) error {
	if stable, ok := failure.As(err); ok {
		return Error(stable.Code)
	}
	if coded, ok := err.(interface{ Code() string }); ok {
		if _, known := generated.ErrorExitCodes[coded.Code()]; known {
			return Error(coded.Code())
		}
	}
	return Error(generated.ErrorCodeDependencyUnavailable)
}
