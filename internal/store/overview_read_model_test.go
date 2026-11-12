package store

import (
	"context"
	"testing"
	"time"

	"github.com/vegastack/vegastack-labs/internal/authorization"
	"github.com/vegastack/vegastack-labs/internal/identity"
	"github.com/vegastack/vegastack-labs/internal/readmodel"
)

func overviewReadScope(t *testing.T, s *Store, capability, kind string, ids ...string) authorization.ReadScope {
	t.Helper()
	for _, id := range ids {
		seedReadGrant(t, s, "overview-reader", capability, kind, id, 1, "active")
	}
	scope, err := NewReadAuthorizer(s).AuthorizeRead(context.Background(), identity.Principal{ID: "overview-reader", Method: identity.LocalOSPeerMethod}, authorization.ReadTarget{Capability: capability, ResourceKind: kind})
	if err != nil {
		t.Fatal(err)
	}
	return scope
}
func overviewSources(t *testing.T, s *Store, scope authorization.ReadScope, snapshot RevisionToken) map[readmodel.SourceID]readmodel.SourceStatus {
	t.Helper()
	page, err := NewSourceRepository(s).ListSources(context.Background(), scope, readmodel.SourceListQuery{Limit: 7, Sort: "id-asc", EvaluationAt: s.config.Clock().UTC()}, snapshot)
	if err != nil {
		t.Fatal(err)
	}
	result := map[readmodel.SourceID]readmodel.SourceStatus{}
	for _, status := range page.Items {
		result[status.ID] = status
	}
	return result
}
func TestOverviewMutationAvailabilityTracksEngineHealth(t *testing.T) {
	for _, mode := range []string{"ready", "safe-mode", "recovery-pending", "disabled"} {
		t.Run(mode, func(t *testing.T) {
			s := portableDiscoveryStore(t)
			scope := overviewReadScope(t, s, "platform.summary.read", "platform-summary", "summary")
			switch mode {
			case "safe-mode":
				s.health.Mode = DatabaseSafeMode
			case "recovery-pending":
				s.health.RecoveryPending = true
			case "disabled":
				s.health.MutationEnabled = false
			}
			got, err := NewReadRepository(s).Summary(context.Background(), scope)
			if err != nil {
				t.Fatal(err)
			}
			if got.MutationAvailable != (mode == "ready") {
				t.Fatalf("engine availability for %s = %v", mode, got.MutationAvailable)
			}
			if _, err := NewReadAuthorizer(s).AuthorizeRead(context.Background(), identity.Principal{ID: "overview-reader", Method: identity.LocalOSPeerMethod}, authorization.ReadTarget{Capability: "inventory.draft.read", ResourceKind: "inventory-draft"}); err == nil {
				t.Fatal("summary availability granted unrelated access")
			}
		})
	}
}
func TestOverviewSourcesExposeImplementedDomainsAsUnknown(t *testing.T) {
	s := portableDiscoveryStore(t)
	scope := overviewReadScope(t, s, "platform.source.read", "platform-source", "gates", "people", "services", "backups", "providers")
	got := overviewSources(t, s, scope, s.health.Revision)
	if len(got) != 5 {
		t.Fatalf("source scope leaked or omitted a domain: %v", got)
	}
	for id, status := range got {
		if status.State != readmodel.SourceUnknown || status.CollectedAt != nil {
			t.Fatalf("empty implemented %s = %+v", id, status)
		}
	}
}
func TestOverviewDatabaseReadPreservesHistoricalIntegrityTime(t *testing.T) {
	s := portableDiscoveryStore(t)
	now := time.Date(2026, 11, 12, 9, 0, 0, 0, time.UTC)
	checked := now.Add(-25 * time.Hour)
	s.config.Clock = func() time.Time { return now }
	s.health.LastIntegrityCheckAt = &checked
	s.health.IntegrityStatus = IntegrityVerified
	scope := overviewReadScope(t, s, "platform.source.read", "platform-source", "database")
	got := overviewSources(t, s, scope, s.health.Revision)[readmodel.SourceDatabase]
	if got.State != readmodel.SourceHealthy || got.CollectedAt == nil || !got.CollectedAt.Equal(now) {
		t.Fatalf("successful current DB read = %+v", got)
	}
	if s.health.LastIntegrityCheckAt == nil || !s.health.LastIntegrityCheckAt.Equal(checked) {
		t.Fatal("read fabricated a new integrity check")
	}
	s.health.Mode = DatabaseSafeMode
	got = overviewSources(t, s, scope, s.health.Revision)[readmodel.SourceDatabase]
	if got.State != readmodel.SourceFailed {
		t.Fatalf("safe-mode source = %+v", got)
	}
}
func TestOverviewNodesUseAcceptedDiscoveryObservation(t *testing.T) {
	f := newRegistrationStoreFixture(t)
	draft := f.Stage(t)
	if _, err := f.repo.Apply(f.ctx, f.bind(t, draft)); err != nil {
		t.Fatal(err)
	}
	scope := overviewReadScope(t, f.s, "platform.source.read", "platform-source", "nodes")
	current, err := NewReadRepository(f.s).CurrentRevision(f.ctx, scope)
	if err != nil {
		t.Fatal(err)
	}
	got := overviewSources(t, f.s, scope, current)[readmodel.SourceNodes]
	if got.CollectedAt == nil || got.State != readmodel.SourceHealthy {
		t.Fatalf("registered discovery omitted: %+v", got)
	}
	before := overviewSources(t, f.s, scope, RevisionToken{StateRevision: 0, RecoveryEpoch: 0})[readmodel.SourceNodes]
	if before.CollectedAt != nil || before.State != readmodel.SourceUnknown {
		t.Fatalf("future registration leaked into snapshot: %+v", before)
	}
	if _, err := f.s.conn.ExecContext(f.ctx, `INSERT INTO host_discovery_targets VALUES('candidate-a',2,'fixture-target','revoked','fixture-plan',0)`); err != nil {
		t.Fatal(err)
	}
	got = overviewSources(t, f.s, scope, current)[readmodel.SourceNodes]
	if got.CollectedAt != nil || got.State != readmodel.SourceUnknown {
		t.Fatalf("revoked target freshened node source: %+v", got)
	}
}
