package store

import (
	"context"
	"database/sql"
	"github.com/vegastack/vegastack-labs/internal/debianaccess"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"github.com/vegastack/vegastack-labs/internal/maintenance"
	"slices"
)

// maintenanceTargetAllowed follows existing alias ownership and history before
// reading any host evidence. It performs no host/provider connection.
func maintenanceTargetAllowed(row discoveryRow, excluded []string, hostID string) error {
	if debianaccess.ProtectedName(hostID) {
		return actionError(generated.ErrorCodeAuthorizationDenied)
	}
	var target, digest string
	if row(`SELECT target_id,identity_digest FROM managed_hosts WHERE host_id=?`, hostID).Scan(&target, &digest) != nil {
		return actionError(generated.ErrorCodeAuthorizationDenied)
	}
	if e := requireHostUnfrozen(row, hostID); e != nil {
		return e
	}
	exclusions := append([]string{"vsk-node-04", "vsk-node-05"}, excluded...)
	for _, id := range exclusions {
		const hosts = `SELECT h.host_id FROM managed_hosts h WHERE h.host_id=?1 OR h.target_id=?1 OR h.host_id IN (SELECT owner_host_id FROM host_alias_owners WHERE alias_id=?1) OR h.identity_digest IN (SELECT owner_identity_digest FROM host_alias_owners WHERE alias_id=?1) OR h.host_id IN (SELECT owner_host_id FROM host_alias_history WHERE alias_id=?1) OR h.identity_digest IN (SELECT owner_identity_digest FROM host_alias_history WHERE alias_id=?1)`
		var n int
		if row(`SELECT COUNT(*) FROM managed_hosts h WHERE h.host_id IN (`+hosts+`) AND (h.host_id=?2 OR h.identity_digest=?3 OR h.target_id=?4)`, id, hostID, digest, target).Scan(&n) != nil || n != 0 || target == id {
			return actionError(generated.ErrorCodeAuthorizationDenied)
		}
	}
	return nil
}
func (r *GateRepository) ResolveMaintenanceHost(ctx context.Context, hostID string) (out HostAdmissionSnapshot, err error) {
	if r == nil || r.store == nil {
		return out, actionError(generated.ErrorCodeInputInvalid)
	}
	err = r.store.Read(ctx, func(tx ReadTx) error {
		row := func(q string, a ...any) *sql.Row { return tx.queryRow(ctx, q, a...) }
		if _, e := adoptionGrant(ctx, row, hostID, "host", "read", "host.read", false); e != nil {
			return e
		}
		if e := maintenanceTargetAllowed(row, r.store.config.NetworkConnectExcludedHostIDs, hostID); e != nil {
			return e
		}
		var e error
		out, e = r.resolveHostAdmission(ctx, tx, hostID)
		return e
	})
	return
}
func (r *DeclarationRepository) validateMaintenance(ctx context.Context, tx *sql.Tx, d generated.DeclarationRevision) error {
	if !maintenance.ValidateDeclaration(d) {
		return actionError(generated.ErrorCodeInputInvalid)
	}
	if d.Maintenance == nil {
		return nil
	}
	actor, e := serviceActor(ctx)
	if e != nil {
		return e
	}
	rowDevice := func(q string, a ...any) *sql.Row { return tx.QueryRowContext(ctx, q, a...) }
	if e := authorizeDeviceRow(rowDevice, actor); e != nil {
		return e
	}
	row := func(q string, a ...any) *sql.Row { return tx.QueryRowContext(ctx, q, a...) }
	if _, e := adoptionGrant(ctx, row, d.DeclarationID, "declaration", "author", "declaration.author", false); e != nil {
		return e
	}
	for _, target := range d.Maintenance.Targets {
		if _, e := adoptionGrant(ctx, row, target.HostID, "host", "author", "maintenance.prepare", true); e != nil {
			return e
		}
		if e := maintenanceTargetAllowed(row, r.store.config.NetworkConnectExcludedHostIDs, target.HostID); e != nil {
			return e
		}
		snapshot, e := NewGateRepository(r.store).resolveHostAdmission(ctx, ReadTx{handle: tx}, target.HostID)
		if e != nil {
			return e
		}
		if maintenance.ObservationDigest(snapshot.Results, slices.Contains(snapshot.Blockers, "host-binding-changed")) != target.ObservationDigest || snapshot.BindingDigest != target.BindingDigest || snapshot.Revision.RecoveryEpoch != d.RecoveryEpoch || snapshot.Revision.StateRevision != d.Maintenance.StateRevision {
			return actionError(generated.ErrorCodePlanStale)
		}
	}
	if d.Maintenance.PreparedByDigest != hostaction.Digest(d.CreatedBy) || d.Maintenance.AgentSessionDigest != hostaction.Digest(d.AgentSessionID) {
		return actionError(generated.ErrorCodeAuthorizationDenied)
	}
	return nil
}
