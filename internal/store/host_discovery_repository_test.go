package store

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"github.com/vegastack/vegastack-labs/internal/audit"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostdiscovery"
	"github.com/vegastack/vegastack-labs/internal/identity"
	"golang.org/x/crypto/ssh"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestHostDiscoveryMigration(t *testing.T) {
	catalog, err := Catalog()
	if err != nil {
		t.Fatal(err)
	}
	db := openCredentialMigrationFixture(t)
	for _, migration := range catalog {
		if _, err := db.Exec(migration.SQL); err != nil {
			t.Fatalf("%s: %v", migration.Name, err)
		}
	}
	for _, table := range []string{"host_discovery_drafts", "host_discovery_targets", "host_discovery_attempts", "host_observations", "host_observation_identities"} {
		var count int
		if err := db.QueryRow("SELECT COUNT(*) FROM " + table).Scan(&count); err != nil {
			t.Errorf("missing discovery table %s", table)
		}
	}
}

// portableDiscoveryStore exercises real SQLite/repository/audit transactions.
// It deliberately substitutes file-identity inspection; it is not evidence for
// Linux ownership, service startup, file locking or native credential behavior.
func portableDiscoveryStore(t *testing.T) *Store {
	t.Helper()
	db := openCredentialMigrationFixture(t)
	conn, err := db.Conn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	config, err := normalizeConfig(testConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	s := &Store{db: db, conn: conn, config: config, filesystem: discoveryFixtureFilesystem{}, events: newEventNotifier(), health: Health{Mode: DatabaseReady, MutationEnabled: true}}
	if err := s.configure(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := s.applyFoundation(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := s.backfillPreAnchor(context.Background()); err != nil {
		t.Fatal(err)
	}
	return s
}

type discoveryFixtureFilesystem struct{ FilesystemInspector }

func (discoveryFixtureFilesystem) InspectDatabase(context.Context, string, uint32) (FileIdentity, error) {
	return FileIdentity{}, nil
}
func (discoveryFixtureFilesystem) SameFile(FileIdentity, FileIdentity) bool { return true }
func discoveryPrincipalContext() context.Context {
	return identity.WithVerifiedPrincipal(context.Background(), identity.Principal{ID: "operator-a", Method: "local-os-peer", Kind: identity.PrincipalHuman})
}
func discoveryFixtureGrant(t *testing.T, s *Store) {
	t.Helper()
	if _, err := s.conn.ExecContext(context.Background(), `INSERT INTO effective_authorization_principals VALUES('operator-a','human','active',1,'now','now')`); err != nil {
		t.Fatal(err)
	}
	for i, capability := range []string{"host.discovery.target.prepare", "host.discovery.collect", "host.discovery.read"} {
		action := "read"
		if i == 0 {
			action = "author"
		}
		if _, err := s.conn.ExecContext(context.Background(), `INSERT INTO effective_authorization_grants VALUES(?, 'operator-a','infrastructure-admin',?,?,'host-discovery-target','candidate-a',NULL,1,'active','now','now')`, fmt.Sprintf("grant-%d", i), action, capability); err != nil {
			t.Fatal(err)
		}
	}
}
func discoveryFixtureTarget(t *testing.T) generated.HostDiscoveryTarget {
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ssh.NewSignerFromKey(private)
	if err != nil {
		t.Fatal(err)
	}
	return generated.HostDiscoveryTarget{Schema: generated.SchemaIDHostDiscoveryTarget, SchemaVersion: "1.0.0", TargetID: "candidate-a", Revision: 1, Address: "127.0.0.1", Port: 2222, User: "inspect", HostKey: strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key.PublicKey()))), ProfileID: "profile-a", CredentialReferenceID: "credential-a", MaterialVersion: "version-a", ExpectedOS: "debian", ExpectedVersion: "13", ExpectedArchitecture: "amd64"}
}
func TestDiscoveryDraftDoesNotGrantConnectionAuthority(t *testing.T) {
	s := portableDiscoveryStore(t)
	discoveryFixtureGrant(t, s)
	ctx := discoveryPrincipalContext()
	repo := NewHostDiscoveryRepository(s)
	p, _ := identity.PrincipalFromContext(ctx)
	a, err := audit.NewAttribution(p, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	target := discoveryFixtureTarget(t)
	request := generated.HostDiscoveryTargetDraftRequest{Schema: generated.SchemaIDHostDiscoveryTargetDraftRequest, SchemaVersion: "1.0.0", Target: target, Action: "activate", IdempotencyKey: "draft-a"}
	draft, err := repo.StageDraft(ctx, request, a)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repo.Begin(ctx, hostdiscovery.BeginRequest{Request: generated.HostDiscoveryRequest{Schema: generated.SchemaIDHostDiscoveryRequest, SchemaVersion: "1.0.0", TargetID: target.TargetID, TargetRevision: 1, IdempotencyKey: "collect-a"}, Attribution: a}); Code(err) != generated.ErrorCodePrerequisiteBlocked {
		t.Fatalf("unapplied draft allowed collection: %v", err)
	}
	if _, err := repo.ApplyTarget(ctx, DiscoveryActivation{DraftID: draft.ID, PlanID: "fake-plan", Attribution: a}); Code(err) != generated.ErrorCodeAuthorizationDenied {
		t.Fatalf("unauthorized activation: %v", err)
	}
	var count int
	if err := s.conn.QueryRowContext(ctx, `SELECT COUNT(*) FROM host_discovery_targets`).Scan(&count); err != nil || count != 0 {
		t.Fatal("draft or forged activation changed active targets")
	}
}

func seedAppliedDiscoveryFixture(t *testing.T, s *Store) (*HostDiscoveryRepository, hostdiscovery.BeginRequest) {
	t.Helper()
	discoveryFixtureGrant(t, s)
	ctx := discoveryPrincipalContext()
	p, _ := identity.PrincipalFromContext(ctx)
	a, err := audit.NewAttribution(p, &p, nil)
	if err != nil {
		t.Fatal(err)
	}
	repo := NewHostDiscoveryRepository(s)
	target := discoveryFixtureTarget(t)
	draft, err := repo.StageDraft(ctx, generated.HostDiscoveryTargetDraftRequest{Schema: generated.SchemaIDHostDiscoveryTargetDraftRequest, SchemaVersion: "1.0.0", Target: target, Action: "activate", IdempotencyKey: "draft-a"}, a)
	if err != nil {
		t.Fatal(err)
	}
	// Seed a previously applied binding for collection tests only. The distinct
	// activation tests exercise the real approval/lease validation path.
	digest := hostdiscovery.Digest("fixture")
	if _, err := s.conn.ExecContext(ctx, `INSERT INTO declaration_revisions VALUES('fixture-declaration',1,'host.discovery-target',0,0,?,?,'draft',?,'now','operator-a','session-a')`, digest, digest, []byte(`{}`)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.conn.ExecContext(ctx, `INSERT INTO immutable_plans VALUES('fixture-plan',?,'fixture-declaration',1,1,0,?,?,?,?,?,?,'2026-10-07T00:00:00Z','2026-10-08T00:00:00Z')`, digest, digest, digest, digest, []byte(`{}`), "fixture", digest); err != nil {
		t.Fatal(err)
	}
	if _, err := s.conn.ExecContext(ctx, `INSERT INTO host_discovery_targets VALUES('candidate-a',1,?,'active','fixture-plan',0)`, draft.ID); err != nil {
		t.Fatal(err)
	}
	return repo, hostdiscovery.BeginRequest{Request: generated.HostDiscoveryRequest{Schema: generated.SchemaIDHostDiscoveryRequest, SchemaVersion: "1.0.0", TargetID: "candidate-a", TargetRevision: 1, IdempotencyKey: "collect-a"}, Attribution: a}
}
func TestDiscoveryReservationCompletionAndReplay(t *testing.T) {
	s := portableDiscoveryStore(t)
	repo, request := seedAppliedDiscoveryFixture(t, s)
	ctx := discoveryPrincipalContext()
	attempt, err := repo.Begin(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repo.Begin(ctx, request); Code(err) != generated.ErrorCodeStateConflict {
		t.Fatalf("concurrent reservation allowed: %v", err)
	}
	collection := hostdiscovery.Collection{Facts: hostdiscovery.Facts{discoveryTestFact("machine-id", "0123456789abcdef0123456789abcdef", "machine-id")}}
	observed, err := repo.Complete(ctx, hostdiscovery.CompleteRequest{Attempt: attempt, Collection: collection, Attribution: request.Attribution})
	if err != nil {
		t.Fatal(err)
	}
	if observed.Status != "incomplete" || !slices.Contains(observed.Blockers, "hardening-unverified") {
		t.Fatal("partial facts incorrectly trusted")
	}
	replay, err := repo.Begin(ctx, request)
	if err != nil || replay.Observation == nil || replay.Observation.ObservationID != observed.ObservationID {
		t.Fatalf("retry lost immutable result: %v", err)
	}
	if _, err := s.conn.ExecContext(ctx, `UPDATE effective_authorization_grants SET status='revoked' WHERE capability='host.discovery.read'`); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.Get(ctx, observed.ObservationID); Code(err) != generated.ErrorCodeAuthorizationDenied {
		t.Fatalf("revoked read disclosed observation: %v", err)
	}
}
func TestDiscoveryCollectionChangesFailClosed(t *testing.T) {
	for _, mode := range []string{"grant", "revision", "epoch", "audit-fault", "timeout"} {
		t.Run(mode, func(t *testing.T) {
			s := portableDiscoveryStore(t)
			repo, request := seedAppliedDiscoveryFixture(t, s)
			ctx := discoveryPrincipalContext()
			attempt, err := repo.Begin(ctx, request)
			if err != nil {
				t.Fatal(err)
			}
			switch mode {
			case "grant":
				_, err = s.conn.ExecContext(ctx, `UPDATE effective_authorization_grants SET status='revoked' WHERE capability='host.discovery.collect'`)
			case "revision":
				_, err = s.conn.ExecContext(ctx, `UPDATE system_meta SET state_revision=state_revision+1`)
			case "epoch":
				_, err = s.conn.ExecContext(ctx, `UPDATE system_meta SET recovery_epoch=recovery_epoch+1`)
			case "audit-fault":
				s.auditFault = func(stage auditIntentStage) error {
					if stage == auditAfterBusiness {
						return errors.New("injected")
					}
					return nil
				}
			case "timeout":
				s.config.Clock = func() time.Time { return attempt.Deadline.Add(time.Second) }
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, err := repo.Complete(ctx, hostdiscovery.CompleteRequest{Attempt: attempt, Attribution: request.Attribution}); err == nil {
				t.Fatal("invalidated collection persisted")
			}
			var count int
			if err := s.conn.QueryRowContext(ctx, `SELECT COUNT(*) FROM host_observations`).Scan(&count); err != nil || count != 0 {
				t.Fatal("partial observation survived failure")
			}
		})
	}
}

func TestDiscoveryFailedAttemptNeverRecollects(t *testing.T) {
	s := portableDiscoveryStore(t)
	repo, request := seedAppliedDiscoveryFixture(t, s)
	ctx := discoveryPrincipalContext()
	attempt, err := repo.Begin(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	if err := repo.Fail(ctx, attempt, generated.ErrorCodeDependencyUnavailable, request.Attribution); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.Begin(ctx, request); Code(err) != generated.ErrorCodeDependencyUnavailable {
		t.Fatalf("failed retry lost terminal outcome: %v", err)
	}
	if _, err := repo.Complete(ctx, hostdiscovery.CompleteRequest{Attempt: attempt, Attribution: request.Attribution}); err == nil {
		t.Fatal("failed attempt completed")
	}
	var count int
	if err := s.conn.QueryRowContext(ctx, `SELECT COUNT(*) FROM host_observations`).Scan(&count); err != nil || count != 0 {
		t.Fatal("failed attempt saved observation")
	}
}

func TestDiscoveryDraftReplayRechecksAuthorization(t *testing.T) {
	s := portableDiscoveryStore(t)
	discoveryFixtureGrant(t, s)
	repo := NewHostDiscoveryRepository(s)
	ctx := discoveryPrincipalContext()
	a, _ := hostdiscovery.Attribution(ctx, "session")
	req := generated.HostDiscoveryTargetDraftRequest{Schema: generated.SchemaIDHostDiscoveryTargetDraftRequest, SchemaVersion: "1.0.0", Target: discoveryFixtureTarget(t), Action: "activate", IdempotencyKey: "draft-a"}
	if _, err := repo.StageDraft(ctx, req, a); err != nil {
		t.Fatal(err)
	}
	if _, err := s.conn.ExecContext(ctx, `UPDATE effective_authorization_grants SET status='revoked' WHERE capability='host.discovery.target.prepare'`); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.StageDraft(ctx, req, a); Code(err) != generated.ErrorCodeAuthorizationDenied {
		t.Fatalf("revoked draft replay accepted: %v", err)
	}
}

func TestDiscoveryDuplicateOutsideReadScopeAndStaleness(t *testing.T) {
	s := portableDiscoveryStore(t)
	repo, req := seedAppliedDiscoveryFixture(t, s)
	ctx := discoveryPrincipalContext()
	a, err := repo.Begin(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	collection := hostdiscovery.Collection{Facts: hostdiscovery.Facts{discoveryTestFact("machine-id", "0123456789abcdef0123456789abcdef", "machine-id")}}
	first, err := repo.Complete(ctx, hostdiscovery.CompleteRequest{Attempt: a, Collection: collection, Attribution: req.Attribution})
	if err != nil {
		t.Fatal(err)
	}
	for i, capability := range []string{"host.discovery.target.prepare", "host.discovery.collect", "host.discovery.read"} {
		action := "read"
		if i == 0 {
			action = "author"
		}
		if _, err := s.conn.ExecContext(ctx, `INSERT INTO effective_authorization_grants VALUES(?,'operator-a','infrastructure-admin',?,?,'host-discovery-target','candidate-b',NULL,1,'active','now','now')`, fmt.Sprintf("other-%d", i), action, capability); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.conn.ExecContext(ctx, `UPDATE effective_authorization_grants SET status='revoked' WHERE resource_id='candidate-a'`); err != nil {
		t.Fatal(err)
	}
	target := discoveryFixtureTarget(t)
	target.TargetID = "candidate-b"
	draft, err := repo.StageDraft(ctx, generated.HostDiscoveryTargetDraftRequest{Schema: generated.SchemaIDHostDiscoveryTargetDraftRequest, SchemaVersion: "1.0.0", Target: target, Action: "activate", ExpectedStateRevision: 2, IdempotencyKey: "draft-b"}, req.Attribution)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.conn.ExecContext(ctx, `INSERT INTO host_discovery_targets VALUES('candidate-b',1,?,'active','fixture-plan',0)`, draft.ID); err != nil {
		t.Fatal(err)
	}
	req.Request.TargetID = "candidate-b"
	req.Request.ExpectedStateRevision = 2
	req.Request.IdempotencyKey = "collect-b"
	secondAttempt, err := repo.Begin(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	second, err := repo.Complete(ctx, hostdiscovery.CompleteRequest{Attempt: secondAttempt, Collection: collection, Attribution: req.Attribution})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(second.Blockers, "identity-conflict") {
		t.Fatal("duplicate identity not blocked")
	}
	for _, code := range second.Blockers {
		if strings.Contains(code, "candidate-a") || strings.Contains(code, first.ObservationID) {
			t.Fatal("foreign identity leaked")
		}
	}
	originalDigest := second.ContentDigest
	s.config.Clock = func() time.Time { return time.Now().Add(time.Hour) }
	stale, err := repo.Get(ctx, second.ObservationID)
	if err != nil || !slices.Contains(stale.Blockers, "stale-observation") || stale.ContentDigest != originalDigest {
		t.Fatalf("stale observation behavior: %+v %v", stale, err)
	}
	req.Request.TargetRevision = 2
	if _, err := repo.Begin(ctx, req); Code(err) != generated.ErrorCodeStateConflict {
		t.Fatal("changed retry accepted")
	}
}

func discoveryTestFact(name, value, op string) generated.HostDiscoveryFact {
	f := hostdiscovery.Fact(name, value, op)
	f.CapturedAt = time.Now().UTC().Truncate(time.Second).Format(time.RFC3339)
	return f
}
