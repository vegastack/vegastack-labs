package hostdiscovery

import (
	"context"
	"errors"
	"github.com/vegastack/vegastack-labs/internal/audit"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/identity"
	"strings"
	"testing"
	"time"
)

type serviceRepository struct {
	deny     bool
	replay   bool
	complete int
}

func (r *serviceRepository) Begin(context.Context, BeginRequest) (Attempt, error) {
	if r.deny {
		return Attempt{}, Error(generated.ErrorCodeAuthorizationDenied)
	}
	a := Attempt{Deadline: time.Now().Add(time.Second)}
	if r.replay {
		a.Observation = &generated.HostObservation{ObservationID: "observation-a"}
	}
	return a, nil
}
func (r *serviceRepository) Complete(context.Context, CompleteRequest) (generated.HostObservation, error) {
	r.complete++
	return generated.HostObservation{ObservationID: "observation-a"}, nil
}
func (r *serviceRepository) Get(context.Context, string) (generated.HostObservation, error) {
	return generated.HostObservation{ObservationID: "observation-a"}, nil
}

type serviceCollector struct {
	calls int
	fail  bool
}

func (c *serviceCollector) Collect(context.Context, Target) (Collection, error) {
	c.calls++
	if c.fail {
		return Collection{}, errors.New("SYNTHETIC-CANARY-SECRET")
	}
	return Collection{}, nil
}
func TestServiceDenialReplayAndDiagnosticBoundary(t *testing.T) {
	for _, mode := range []string{"denied", "replay", "failure", "success"} {
		t.Run(mode, func(t *testing.T) {
			repo := &serviceRepository{deny: mode == "denied", replay: mode == "replay"}
			collector := &serviceCollector{fail: mode == "failure"}
			service := &Service{Repository: repo, Collector: collector}
			ctx := identity.WithVerifiedPrincipal(context.Background(), identity.Principal{ID: "human-a", Method: "local-os-peer"})
			_, err := service.Discover(ctx, generated.HostDiscoveryRequest{})
			if mode == "denied" || mode == "replay" {
				if collector.calls != 0 {
					t.Fatal("collection ran on denial or replay")
				}
			}
			if mode == "failure" {
				if err == nil || strings.Contains(err.Error(), "CANARY") || repo.complete != 0 {
					t.Fatal("collector failure leaked or persisted")
				}
			}
			if mode == "success" && (err != nil || repo.complete != 1) {
				t.Fatal("success not persisted")
			}
		})
	}
}

func (r *serviceRepository) Fail(context.Context, Attempt, string, audit.Attribution) error {
	return nil
}
