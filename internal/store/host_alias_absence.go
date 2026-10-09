package store

import (
	"context"

	"github.com/vegastack/vegastack-labs/internal/generated"
)

// VerifyEmptyHostAliasHistory proves the finite ownership tables are empty.
// A zero MAX ordinal alone cannot establish this after partial recovery.
func (s *Store) VerifyEmptyHostAliasHistory(ctx context.Context) error {
	return s.Read(ctx, func(tx ReadTx) error { return verifyEmptyHostAliasHistory(ctx, tx) })
}
func verifyEmptyHostAliasHistory(ctx context.Context, tx ReadTx) error {
	var n int64
	if err := tx.queryRow(ctx, `SELECT
  (SELECT COUNT(*) FROM host_alias_history) +
  (SELECT COUNT(*) FROM host_alias_owners) +
  (SELECT COUNT(*) FROM host_replacement_events) +
  (SELECT COUNT(*) FROM host_replacement_drafts)`).Scan(&n); err != nil {
		return err
	}
	if n != 0 {
		return replacementError(generated.ErrorCodePrerequisiteBlocked)
	}
	return nil
}

// VerifyOriginalEmptyHostAuthority only permits the legacy absence branch on
// the original ready authority. A recovered or recovery-required database may
// have lost newer history; absence there needs authenticated continuity rather
// than an inference from its empty tables.
func (s *Store) VerifyOriginalEmptyHostAuthority(ctx context.Context) error {
	return s.Read(ctx, func(tx ReadTx) error {
		if err := verifyEmptyHostAliasHistory(ctx, tx); err != nil {
			return err
		}
		var epoch, transitions int64
		var mode string
		if err := tx.queryRow(ctx, `SELECT recovery_epoch,authority_mode,
   (SELECT COUNT(*) FROM recovery_authority_journal) +
   (SELECT COUNT(*) FROM recovery_authority_bundles)
   FROM system_meta WHERE id=1`).Scan(&epoch, &mode, &transitions); err != nil {
			return err
		}
		if epoch != 0 || mode != "ready" || transitions != 0 {
			return replacementError(generated.ErrorCodePrerequisiteBlocked)
		}
		return nil
	})
}
