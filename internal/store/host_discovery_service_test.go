package store

import (
	"context"
	"errors"
	"github.com/vegastack/vegastack-labs/internal/failure"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostdiscovery"
	"strings"
	"testing"
)

type discoveryExternalFailure func(context.Context, hostdiscovery.Target) (hostdiscovery.Collection, error)

func (f discoveryExternalFailure) Collect(ctx context.Context, target hostdiscovery.Target) (hostdiscovery.Collection, error) {
	return f(ctx, target)
}
func TestDiscoveryServiceFailureIsDurablePrivateAndTerminal(t *testing.T) {
	for _, cancelled := range []bool{false, true} {
		t.Run(map[bool]string{false: "diagnostic", true: "cancelled"}[cancelled], func(t *testing.T) {
			s := portableDiscoveryStore(t)
			repo, request := seedAppliedDiscoveryFixture(t, s)
			ctx, cancel := context.WithCancel(discoveryPrincipalContext())
			defer cancel()
			service := &hostdiscovery.Service{Repository: repo, Collector: discoveryExternalFailure(func(context.Context, hostdiscovery.Target) (hostdiscovery.Collection, error) {
				if cancelled {
					cancel()
				}
				return hostdiscovery.Collection{}, errors.New("SYNTHETIC-CANARY-SECRET")
			})}
			if _, err := service.Discover(ctx, request.Request); err == nil || strings.Contains(err.Error(), "CANARY") {
				t.Fatalf("unsafe error: %v", err)
			}
			var observations, failures, audits int
			for _, item := range []struct {
				q   string
				out *int
			}{{`SELECT COUNT(*) FROM host_observations`, &observations}, {`SELECT COUNT(*) FROM host_discovery_failures`, &failures}, {`SELECT COUNT(*) FROM audit_events WHERE event_type='host.discovery.failed'`, &audits}} {
				if err := s.conn.QueryRowContext(context.Background(), item.q).Scan(item.out); err != nil {
					t.Fatal(err)
				}
			}
			if observations != 0 || failures != 1 || audits != 1 {
				t.Fatalf("failed collection persisted incorrectly: observations=%d failures=%d audits=%d", observations, failures, audits)
			}
			service.Collector = discoveryExternalFailure(func(context.Context, hostdiscovery.Target) (hostdiscovery.Collection, error) {
				t.Fatal("terminal retry reached external collector")
				return hostdiscovery.Collection{}, nil
			})
			_, err := service.Discover(discoveryPrincipalContext(), request.Request)
			stable, ok := failure.As(err)
			if !ok || stable.Code != generated.ErrorCodeDependencyUnavailable {
				t.Fatalf("terminal retry changed outcome: %v", err)
			}
			var leaked int
			if err := s.conn.QueryRowContext(context.Background(), `SELECT COUNT(*) FROM audit_events WHERE CAST(canonical_payload AS TEXT) LIKE '%CANARY%'`).Scan(&leaked); err != nil {
				t.Fatal(err)
			}
			if leaked != 0 {
				t.Fatal("diagnostic leaked into audit")
			}
		})
	}
}

func TestDiscoveryDraftRoleDenialIsAudited(t *testing.T) {
	s := portableDiscoveryStore(t)
	discoveryFixtureGrant(t, s)
	if _, err := s.conn.ExecContext(context.Background(), `UPDATE effective_authorization_grants SET status='revoked', grant_revision=2 WHERE capability='host.discovery.target.prepare'`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.conn.ExecContext(context.Background(), `INSERT INTO effective_authorization_grants VALUES('author-grant','operator-a','author','author','host.discovery.target.prepare','host-discovery-target','candidate-a',NULL,3,'active','now','now')`); err != nil {
		t.Fatal(err)
	}
	repo := NewHostDiscoveryRepository(s)
	attribution, err := hostdiscovery.Attribution(discoveryPrincipalContext(), "denial-test")
	if err != nil {
		t.Fatal(err)
	}
	target := discoveryFixtureTarget(t)
	target.TargetID = "candidate-a"
	target.Revision = 1
	_, err = repo.StageDraft(discoveryPrincipalContext(), generated.HostDiscoveryTargetDraftRequest{Schema: generated.SchemaIDHostDiscoveryTargetDraftRequest, SchemaVersion: "1.0.0", Target: target, Action: "activate", ExpectedTargetRevision: 0, ExpectedStateRevision: 0, IdempotencyKey: "denied-draft"}, attribution)
	if Code(err) != generated.ErrorCodeAuthorizationDenied {
		t.Fatalf("role denial: %v", err)
	}
	var drafts, denied int
	if err := s.conn.QueryRowContext(context.Background(), `SELECT COUNT(*) FROM host_discovery_drafts`).Scan(&drafts); err != nil {
		t.Fatal(err)
	}
	if err := s.conn.QueryRowContext(context.Background(), `SELECT COUNT(*) FROM audit_events WHERE event_type='host.discovery.failed'`).Scan(&denied); err != nil {
		t.Fatal(err)
	}
	if drafts != 0 || denied != 1 {
		t.Fatalf("drafts=%d denial audits=%d", drafts, denied)
	}
}
