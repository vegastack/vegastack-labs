package store

import (
	"context"
	"database/sql"
	"strings"
	"testing"
	"time"

	"github.com/vegastack/vegastack-labs/internal/audit"
	"github.com/vegastack/vegastack-labs/internal/identity"
)

func cancellationStore(t *testing.T) *Store {
	t.Helper()
	s := portableDiscoveryStore(t)
	if _, e := s.conn.ExecContext(context.Background(), "CREATE TABLE cancellation_fixture(id TEXT PRIMARY KEY)"); e != nil {
		t.Fatal(e)
	}
	return s
}
func cancellationAuditRequest(t *testing.T) intentRequest {
	t.Helper()
	actor, e := audit.NewAttribution(identity.Principal{ID: "principal-test-1", Method: identity.LocalOSPeerMethod}, nil, nil)
	if e != nil {
		t.Fatal(e)
	}
	digest := audit.Fingerprint("sha256:" + strings.Repeat("a", 64))
	return intentRequest{Idempotency: audit.IntentKey{Scope: "cancellation-test", KeyDigest: digest, RequestDigest: digest}, Event: audit.EventDraft{Type: "test.cancellation", CorrelationID: "request-cancellation", Attribution: actor, Target: audit.Target{Kind: "test-target", ID: "target-cancellation"}}}
}
func assertCancellationStoreHealthy(t *testing.T, s *Store) {
	t.Helper()
	if e := s.Read(context.Background(), func(tx ReadTx) error {
		return tx.queryRow(context.Background(), "SELECT COUNT(*) FROM cancellation_fixture").Scan(new(int))
	}); e != nil {
		t.Fatalf("future read poisoned: %v", e)
	}
	if s.health.Mode != DatabaseReady || !s.health.MutationEnabled {
		t.Fatalf("cancellation entered safe mode: %+v", s.health)
	}
	_, e := s.WriteIntent(context.Background(), nil, func(tx IntentTx) error {
		_, e := tx.execChange(context.Background(), "INSERT INTO cancellation_fixture(id) VALUES('healthy')")
		return e
	})
	if e != nil {
		t.Fatalf("future healthy commit failed: %v", e)
	}
	var n int
	if e = s.conn.QueryRowContext(context.Background(), "SELECT COUNT(*) FROM cancellation_fixture WHERE id='healthy'").Scan(&n); e != nil || n != 1 {
		t.Fatalf("healthy write not committed n=%d err=%v", n, e)
	}
}
func TestCancellationDoesNotPoisonStore(t *testing.T) {
	for _, kind := range []string{"read", "read-return-nil", "write", "audit"} {
		t.Run(kind, func(t *testing.T) {
			s := cancellationStore(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			interrupt := func() { cancel(); time.Sleep(25 * time.Millisecond) } // Let database/sql observe transaction-context cancellation.
			var e error
			switch kind {
			case "read":
				e = s.Read(ctx, func(tx ReadTx) error { interrupt(); return ctx.Err() })
			case "read-return-nil":
				e = s.Read(ctx, func(ReadTx) error { interrupt(); return nil })
			case "write":
				_, e = s.WriteIntent(ctx, nil, func(tx IntentTx) error {
					_, e := tx.execChange(ctx, "INSERT INTO cancellation_fixture(id) VALUES('cancelled')")
					if e != nil {
						return e
					}
					interrupt()
					return nil
				})
			case "audit":
				_, e = s.writeIntent(ctx, cancellationAuditRequest(t), func(ctx context.Context, tx *sql.Tx) error {
					if _, e := tx.ExecContext(ctx, "INSERT INTO cancellation_fixture(id) VALUES('cancelled')"); e != nil {
						return e
					}
					interrupt()
					return nil
				})
			}
			if Code(e) != "INTERRUPTED" {
				t.Fatalf("cancellation error=%v", e)
			}
			assertCancellationStoreHealthy(t, s)
			var n int
			if e = s.conn.QueryRowContext(context.Background(), "SELECT COUNT(*) FROM cancellation_fixture WHERE id='cancelled'").Scan(&n); e != nil || n != 0 {
				t.Fatalf("cancelled write committed n=%d err=%v", n, e)
			}
		})
	}
}
func TestCancellationAtCommitDoesNotCommitOrPoisonStore(t *testing.T) {
	for _, kind := range []string{"write", "audit"} {
		t.Run(kind, func(t *testing.T) {
			s := cancellationStore(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			s.beforeCommit = func() error { cancel(); time.Sleep(25 * time.Millisecond); return nil }
			var e error
			if kind == "write" {
				_, e = s.WriteIntent(ctx, nil, func(tx IntentTx) error {
					_, e := tx.execChange(ctx, "INSERT INTO cancellation_fixture(id) VALUES('cancelled')")
					return e
				})
			} else {
				_, e = s.writeIntent(ctx, cancellationAuditRequest(t), func(ctx context.Context, tx *sql.Tx) error {
					_, e := tx.ExecContext(ctx, "INSERT INTO cancellation_fixture(id) VALUES('cancelled')")
					return e
				})
			}
			s.beforeCommit = nil
			if Code(e) != "INTERRUPTED" {
				t.Fatalf("cancelled commit error=%v", e)
			}
			assertCancellationStoreHealthy(t, s)
			var n int
			if e = s.conn.QueryRowContext(context.Background(), "SELECT COUNT(*) FROM cancellation_fixture WHERE id='cancelled'").Scan(&n); e != nil || n != 0 {
				t.Fatalf("cancelled commit persisted n=%d err=%v", n, e)
			}
		})
	}
}

func TestTransactionCommitFailureRetainsSafeMode(t *testing.T) {
	s := cancellationStore(t)
	for _, query := range []string{"CREATE TABLE cancellation_parent(id INTEGER PRIMARY KEY)", "CREATE TABLE cancellation_child(id INTEGER REFERENCES cancellation_parent(id) DEFERRABLE INITIALLY DEFERRED)"} {
		if _, e := s.conn.ExecContext(context.Background(), query); e != nil {
			t.Fatal(e)
		}
	}
	_, e := s.WriteIntent(context.Background(), nil, func(tx IntentTx) error {
		_, e := tx.execChange(context.Background(), "INSERT INTO cancellation_child(id) VALUES(1)")
		return e
	})
	if e == nil || s.health.Mode != DatabaseSafeMode || s.health.MutationEnabled || s.health.SafeModeReason != "commit-failure" {
		t.Fatalf("real commit failure lost existing safe mode: %v %+v", e, s.health)
	}
	if _, e = s.WriteIntent(context.Background(), nil, func(IntentTx) error { return nil }); Code(e) != "PREREQUISITE_BLOCKED" {
		t.Fatalf("writes not blocked after actual commit failure: %v", e)
	}
}
