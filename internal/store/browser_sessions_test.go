package store

import (
	"context"
	"errors"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/identity"
)

func TestBrowserSessionLifecycleStoresOnlyDigestsAndAuditsAtomically(t *testing.T) {
	s, now := newSessionStore(t)
	principal, binding := seedRemoteBinding(t, s, "principal-reader")
	session, raw, err := s.CreateBrowserSession(context.Background(), BrowserSessionCreate{Principal: principal, BindingDigest: binding, ExternalExpiresAt: now.Now().Add(2 * time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if raw == "" || session.Status != BrowserSessionActive || session.PrincipalID != principal.ID {
		t.Fatalf("session = %#v raw=%q", session, raw)
	}
	var rawCount int
	if err := s.conn.QueryRowContext(context.Background(), `SELECT count(*) FROM browser_sessions WHERE session_digest=? OR binding_digest=?`, raw, raw).Scan(&rawCount); err != nil || rawCount != 0 {
		t.Fatalf("raw session persisted: count=%d err=%v", rawCount, err)
	}
	var auditCount int
	if err := s.conn.QueryRowContext(context.Background(), `SELECT count(*) FROM audit_events WHERE event_type='identity.session-created' AND target_id=?`, session.Digest).Scan(&auditCount); err != nil || auditCount != 1 {
		t.Fatalf("create audit count=%d err=%v", auditCount, err)
	}

	nowValue := now.Now().Add(14 * time.Minute)
	now.Set(nowValue)
	validated, err := s.ValidateAndTouchBrowserSession(context.Background(), raw, binding, now.Now().Add(time.Hour))
	if err != nil || !validated.IdleExpiresAt.Equal(now.Now().Add(15*time.Minute)) {
		t.Fatalf("validated = %#v, %v", validated, err)
	}
	now.Set(now.Now().Add(16 * time.Minute))
	if _, err := s.ValidateAndTouchBrowserSession(context.Background(), raw, binding, now.Now().Add(time.Hour)); Code(err) != generated.ErrorCodeAuthenticationRequired {
		t.Fatalf("idle-expired error = %v", err)
	}
}

func TestBrowserSessionRenewalIsExactlyOnceAndOldValueCannotReplay(t *testing.T) {
	s, now := newSessionStore(t)
	principal, binding := seedRemoteBinding(t, s, "principal-reader")
	_, raw, err := s.CreateBrowserSession(context.Background(), BrowserSessionCreate{Principal: principal, BindingDigest: binding, ExternalExpiresAt: now.Now().Add(9 * time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	var successes atomic.Int32
	var replacement string
	var lock sync.Mutex
	var group sync.WaitGroup
	for range 8 {
		group.Add(1)
		go func() {
			defer group.Done()
			_, next, renewErr := s.RenewBrowserSession(context.Background(), raw, binding, now.Now().Add(9*time.Hour))
			if renewErr == nil {
				successes.Add(1)
				lock.Lock()
				replacement = next
				lock.Unlock()
			}
		}()
	}
	group.Wait()
	if successes.Load() != 1 || replacement == "" {
		t.Fatalf("renewal successes=%d replacement=%q", successes.Load(), replacement)
	}
	if _, err := s.ValidateAndTouchBrowserSession(context.Background(), raw, binding, now.Now().Add(time.Hour)); Code(err) != generated.ErrorCodeAuthenticationRequired {
		t.Fatalf("rotated session replay error=%v", err)
	}
	if _, err := s.ValidateAndTouchBrowserSession(context.Background(), replacement, binding, now.Now().Add(time.Hour)); err != nil {
		t.Fatalf("replacement invalid: %v", err)
	}
}

func TestBrowserSessionLogoutRevocationGrantAndRecoveryEpochFailClosed(t *testing.T) {
	tests := []struct {
		name string
		end  func(*testing.T, *Store, identity.Principal, string, string)
	}{
		{name: "logout", end: func(t *testing.T, s *Store, _ identity.Principal, binding, raw string) {
			if err := s.LogoutBrowserSession(context.Background(), raw, binding); err != nil {
				t.Fatal(err)
			}
			if err := s.LogoutBrowserSession(context.Background(), raw, binding); err != nil {
				t.Fatalf("idempotent logout: %v", err)
			}
		}},
		{name: "principal revocation", end: func(t *testing.T, s *Store, principal identity.Principal, _, _ string) {
			if err := s.RevokeBrowserSessions(context.Background(), principal, "principal-revoked"); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "grant revision", end: func(t *testing.T, s *Store, principal identity.Principal, _, _ string) {
			if _, err := s.conn.ExecContext(context.Background(), `UPDATE read_principals SET grant_revision=grant_revision+1,updated_at=? WHERE principal_id=?`, time.Now().UTC().Format(time.RFC3339Nano), principal.ID); err != nil {
				t.Fatal(err)
			}
		}},
		{name: "recovery epoch", end: func(t *testing.T, s *Store, _ identity.Principal, _, _ string) {
			if _, err := s.conn.ExecContext(context.Background(), `UPDATE system_meta SET recovery_epoch=recovery_epoch+1 WHERE id=1`); err != nil {
				t.Fatal(err)
			}
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			s, now := newSessionStore(t)
			principal, binding := seedRemoteBinding(t, s, "principal-reader")
			_, raw, err := s.CreateBrowserSession(context.Background(), BrowserSessionCreate{Principal: principal, BindingDigest: binding, ExternalExpiresAt: now.Now().Add(time.Hour)})
			if err != nil {
				t.Fatal(err)
			}
			test.end(t, s, principal, binding, raw)
			if _, err := s.ValidateAndTouchBrowserSession(context.Background(), raw, binding, now.Now().Add(time.Hour)); Code(err) != generated.ErrorCodeAuthenticationRequired {
				t.Fatalf("ended session error=%v", err)
			}
		})
	}
}

func TestBrowserSessionCreateRollsBackWhenAuditFails(t *testing.T) {
	s, now := newSessionStore(t)
	principal, binding := seedRemoteBinding(t, s, "principal-reader")
	s.auditFault = func(stage auditIntentStage) error {
		if stage == auditAfterEvent {
			return errors.New("injected audit failure")
		}
		return nil
	}
	if _, raw, err := s.CreateBrowserSession(context.Background(), BrowserSessionCreate{Principal: principal, BindingDigest: binding, ExternalExpiresAt: now.Now().Add(time.Hour)}); err == nil || raw != "" {
		t.Fatalf("CreateBrowserSession = raw %q err %v", raw, err)
	}
	var count int
	if err := s.conn.QueryRowContext(context.Background(), `SELECT count(*) FROM browser_sessions`).Scan(&count); err != nil || count != 0 {
		t.Fatalf("sessions=%d err=%v", count, err)
	}
}

type mutableClock struct {
	mu sync.Mutex
	at time.Time
}

func (clock *mutableClock) Now() time.Time                       { clock.mu.Lock(); defer clock.mu.Unlock(); return clock.at }
func (clock *mutableClock) Add(duration time.Duration) time.Time { return clock.Now().Add(duration) }
func (clock *mutableClock) Set(value time.Time)                  { clock.mu.Lock(); clock.at = value; clock.mu.Unlock() }

func newSessionStore(t *testing.T) (*Store, *mutableClock) {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("SQLite authority is supported on Linux")
	}
	clock := &mutableClock{at: time.Date(2026, 9, 10, 9, 0, 0, 0, time.UTC)}
	config := testConfig(t)
	config.Clock = clock.Now
	s, err := Open(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s, clock
}

func seedRemoteBinding(t *testing.T, s *Store, principalID string) (identity.Principal, string) {
	t.Helper()
	now := s.config.Clock().UTC().Format(time.RFC3339Nano)
	if _, err := s.conn.ExecContext(context.Background(), `INSERT INTO read_principals(principal_id,status,grant_revision,created_at,updated_at) VALUES(?,?,?,?,?)`, principalID, "active", 1, now, now); err != nil {
		t.Fatal(err)
	}
	verified := identity.VerifiedIdentity{Issuer: "https://team.cloudflareaccess.com", Subject: "subject-" + principalID, Audiences: []string{"aud-console"}, IssuedAt: s.config.Clock(), ExpiresAt: s.config.Clock().Add(time.Hour), Method: identity.CloudflareAccessMethod}
	binding, err := identity.BindingDigest(verified)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.conn.ExecContext(context.Background(), `INSERT INTO remote_identity_bindings(binding_digest,principal_id,status,created_at,updated_at) VALUES(?,?,?,?,?)`, binding, principalID, "active", now, now); err != nil {
		t.Fatal(err)
	}
	return identity.Principal{ID: principalID, Method: identity.CloudflareAccessMethod}, binding
}

func TestBrowserSessionDigestNeverContainsRawValue(t *testing.T) {
	digest, err := BrowserSessionDigest("this-is-a-raw-session-value-with-enough-entropy")
	if err != nil || strings.Contains(digest, "raw-session") {
		t.Fatalf("digest=%q err=%v", digest, err)
	}
}
