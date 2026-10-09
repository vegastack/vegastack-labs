package store

import (
	"context"
	"database/sql"

	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostreplacement"
)

// ResolveReplacementDestination returns only the current persisted frozen
// replacement whose role, preimages and source match this restore binding.
func (r *HostReplacementRepository) ResolveReplacementDestination(ctx context.Context, b generated.RestoreBinding) (generated.HostReplacementRequest, error) {
	d, err := r.store.FindFrozenControlReplacement(ctx, b.FormerHostID, b.ReplacementHostID, b.Source.PointID)
	if err != nil {
		return generated.HostReplacementRequest{}, err
	}
	err = r.store.Read(ctx, func(tx ReadTx) error {
		row := func(query string, args ...any) *sql.Row { return tx.queryRow(ctx, query, args...) }
		event, _, err := readReplacementEvent(row, d.Request.ReplacementID)
		if err != nil || event.State.Status != "frozen" || event.State.BindingDigest != d.BindingDigest {
			return replacementError(generated.ErrorCodePlanStale)
		}
		if err := hostreplacement.BindRestore(d.Request, b); err != nil {
			return err
		}
		return validateReplacementHosts(row, d.Request)
	})
	return d.Request, err
}
