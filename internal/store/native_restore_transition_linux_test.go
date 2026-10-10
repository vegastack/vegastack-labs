//go:build linux

package store

import (
	"context"
	"database/sql"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"testing"
)

func TestNativeAuthorityBridgeRequiresActualVerifiedRestore(t *testing.T) {
	seen := 0
	testRestorePlanAuthorityBundle(t, true, func(s *Store, want generated.RestoreBinding, verified bool) {
		seen++
		ctx := context.Background()
		err := s.Read(ctx, func(tx ReadTx) error {
			q := nativeQuery{tx, func(query string, a ...any) *sql.Row { return tx.queryRow(ctx, query, a...) }, func(query string, a ...any) (*sql.Rows, error) { return tx.query(ctx, query, a...) }}
			got, err := nativeVerifiedRestoreBinding(ctx, q)
			if err != nil {
				return err
			}
			if !verified && got != nil {
				t.Fatal("promoted but unverified authority bridged")
			}
			if verified && (got == nil || hostaction.Digest(*got) != hostaction.Digest(want)) {
				t.Fatal("verified original transition not resolved")
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	})
	if seen != 2 {
		t.Fatalf("missing intermediate/final checks: %d", seen)
	}
}
