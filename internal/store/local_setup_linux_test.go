//go:build linux

package store

import (
	"context"
	"database/sql"
	"errors"
	"github.com/vegastack/vegastack-labs/internal/authorization"
	"github.com/vegastack/vegastack-labs/internal/identity"
	"testing"
	"time"
)

func TestLocalSetupFoundationAuthority(t *testing.T) {
	ctx := context.Background()
	cfg := testConfig(t)
	now := time.Now().UTC().Truncate(time.Second)
	cfg.Clock = func() time.Time { return now }
	setup := setupFixture(t, cfg.DatabasePath, cfg.ExpectedUID, now)
	cfg.InitialSetup = &setup
	s, err := Open(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if digest, err := s.ReadInitialSetupDigest(ctx); err != nil || digest != setup.ReviewDigest {
		t.Fatalf("completion digest %q %v", digest, err)
	}
	for table, want := range map[string]int{"read_principals": 1, "read_grants": 1, "effective_authorization_principals": 1, "effective_authorization_grants": 1, "audit_events": 1, "audit_chain_links": 1, "intent_keys": 1} {
		var count int
		if err := s.conn.QueryRowContext(ctx, "SELECT count(*) FROM "+table).Scan(&count); err != nil || count != want {
			t.Fatalf("%s count %d: %v", table, count, err)
		}
	}
	principal := identity.Principal{ID: setup.HumanID, Kind: identity.PrincipalHuman, Method: identity.LocalOSPeerMethod}
	target := authorization.ReadTarget{Capability: "control.health.read", ResourceKind: "control", ResourceID: "control"}
	if _, err := NewReadAuthorizer(s).AuthorizeRead(ctx, principal, target); err != nil {
		t.Fatal(err)
	}
	other := principal
	other.ID = "other-human"
	if _, err := NewReadAuthorizer(s).AuthorizeRead(ctx, other, target); err == nil {
		t.Fatal("other human gained read")
	}
	target.ResourceID = "other-control"
	if _, err := NewReadAuthorizer(s).AuthorizeRead(ctx, principal, target); err == nil {
		t.Fatal("widened read")
	}
	request := authorization.Request{Action: authorization.ActionAuthor, Target: authorization.Target{Capability: "gate.profile.author", ResourceKind: "profile", ResourceID: "profile-drafts"}}
	evaluator := authorization.NewEvaluator(NewEffectiveAuthorizationRepository(s))
	if d, err := evaluator.Authorize(ctx, principal, request); err != nil || !d.Allowed {
		t.Fatalf("author grant failed %v %v", d, err)
	}
	if d, _ := evaluator.Authorize(ctx, other, request); d.Allowed {
		t.Fatal("other human gained author")
	}
	request.Target.ResourceID = "other-profile"
	if d, _ := evaluator.Authorize(ctx, principal, request); d.Allowed {
		t.Fatal("widened author")
	}
	var authority, decidedAt, requestDigest string
	if err := s.conn.QueryRowContext(ctx, "SELECT target_id,occurred_at FROM audit_events").Scan(&authority, &decidedAt); err != nil || authority != setup.Approval.AuthorityID || decidedAt != setup.Approval.DecidedAt.UTC().Format(time.RFC3339Nano) {
		t.Fatalf("approval not durable: %q %q %v", authority, decidedAt, err)
	}
	if err := s.conn.QueryRowContext(ctx, "SELECT request_digest FROM intent_keys WHERE scope=?", initialSetupScope).Scan(&requestDigest); err != nil || requestDigest != setup.RequestDigest {
		t.Fatalf("request binding not durable %q %v", requestDigest, err)
	}
	var method string
	if err := s.conn.QueryRowContext(ctx, "SELECT principal_method FROM audit_events").Scan(&method); err != nil || method != identity.SlackSocketModeMethod {
		t.Fatalf("audit method %q %v", method, err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	cfg.Mode = OpenExisting
	cfg.InitialSetup = nil
	now = now.Add(2 * time.Hour)
	reopened, err := Open(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if digest, err := reopened.ReadInitialSetupDigest(ctx); err != nil || digest != setup.ReviewDigest {
		t.Fatalf("lost completion %q %v", digest, err)
	}
	cfg.Mode = InitializeNew
	cfg.InitialSetup = &setup
	if _, err := Open(ctx, cfg); err == nil {
		t.Fatal("overwrote existing database")
	}
}

// Exercise the same foundation transaction with the package's existing audit
// failpoint. No fixture grants are seeded: all rows come from InitialSetup.
func TestLocalSetupFoundationAtomicity(t *testing.T) {
	for _, stage := range []auditIntentStage{auditAfterBusiness, auditAfterEvent, auditAfterIntent, auditBeforeCommit, auditAfterCommit} {
		t.Run(string(stage), func(t *testing.T) {
			ctx := context.Background()
			cfg := testConfig(t)
			now := time.Now().UTC().Truncate(time.Second)
			cfg.Clock = func() time.Time { return now }
			setup := setupFixture(t, cfg.DatabasePath, cfg.ExpectedUID, now)
			cfg.InitialSetup = &setup
			fs := newFilesystemInspector()
			if _, err := fs.CreateDatabase(ctx, cfg.DatabasePath, cfg.ExpectedUID); err != nil {
				t.Fatal(err)
			}
			db, err := sql.Open(sqliteDriverName, sqliteURI(cfg.DatabasePath))
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			conn, err := db.Conn(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			fired := false
			s := &Store{conn: conn, config: cfg, auditFault: func(got auditIntentStage) error {
				if got == stage {
					fired = true
					return errors.New("synthetic crash")
				}
				return nil
			}}
			if err := s.configure(ctx); err != nil {
				t.Fatal(err)
			}
			if err := s.applyFoundation(ctx); err == nil {
				t.Fatal("failpoint did not fire")
			}
			if !fired {
				t.Fatal("foundation failed before intended crash seam")
			}
			var count int
			if stage == auditAfterCommit {
				for _, table := range []string{"read_grants", "effective_authorization_grants", "audit_events", "audit_chain_links", "intent_keys"} {
					if err := conn.QueryRowContext(ctx, "SELECT count(*) FROM "+table).Scan(&count); err != nil || count != 1 {
						t.Fatalf("durable %s: %d %v", table, count, err)
					}
				}
			} else {
				if err := conn.QueryRowContext(ctx, "SELECT count(*) FROM sqlite_master WHERE type='table'").Scan(&count); err != nil || count != 0 {
					t.Fatalf("partial foundation persisted %d %v", count, err)
				}
			}
		})
	}
}

func TestLocalSetupExpiredFoundationRollsBack(t *testing.T) {
	ctx := context.Background()
	cfg := testConfig(t)
	now := time.Now().UTC().Truncate(time.Second)
	setup := setupFixture(t, cfg.DatabasePath, cfg.ExpectedUID, now)
	cfg.InitialSetup = &setup
	cfg.Clock = func() time.Time { return now.Add(time.Hour) }
	if _, err := Open(ctx, cfg); err == nil {
		t.Fatal("expired setup initialized")
	}
	db, err := sql.Open(sqliteDriverName, sqliteURI(cfg.DatabasePath))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var count int
	if err := db.QueryRowContext(ctx, "SELECT count(*) FROM sqlite_master WHERE type='table'").Scan(&count); err != nil || count != 0 {
		t.Fatalf("expired authority persisted: %d %v", count, err)
	}
	cfg.InitialSetup = nil
	if _, err := Open(ctx, cfg); err == nil {
		t.Fatal("partial file overwritten")
	}
}
