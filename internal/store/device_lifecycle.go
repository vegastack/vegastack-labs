package store

import (
	"context"
	"database/sql"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/identity"
)

func validateDeviceLifecycle(row discoveryRow, in generated.AuthorizationGrantBatchRequest) error {
	var owner, status string
	var revision int64
	err := row(`SELECT principal_id,status,device_revision FROM operator_devices WHERE device_id=?`, in.DeviceID).Scan(&owner, &status, &revision)
	if in.DeviceAction == "request" {
		if err != sql.ErrNoRows {
			return actionError(generated.ErrorCodeStateConflict)
		}
		return nil
	}
	if err != nil || owner != in.PrincipalID || revision != in.ExpectedDeviceRevision || status == "revoked" || in.DeviceAction == "approve" && status != "pending" {
		return actionError(generated.ErrorCodePlanStale)
	}
	return nil
}
func applyDeviceLifecycle(ctx context.Context, tx *sql.Tx, in generated.AuthorizationGrantBatchRequest, now string) error {
	row := func(q string, a ...any) *sql.Row { return tx.QueryRowContext(ctx, q, a...) }
	if err := validateDeviceLifecycle(row, in); err != nil {
		return err
	}
	if in.DeviceAction == "request" {
		_, err := tx.ExecContext(ctx, `INSERT INTO operator_devices VALUES(?,?,'pending',1,?,?)`, in.DeviceID, in.PrincipalID, now, now)
		return err
	}
	status := "approved"
	if in.DeviceAction == "revoke" {
		status = "revoked"
	}
	result, err := tx.ExecContext(ctx, `UPDATE operator_devices SET status=?,device_revision=device_revision+1,updated_at=? WHERE device_id=? AND principal_id=? AND device_revision=? AND status!='revoked'`, status, now, in.DeviceID, in.PrincipalID, in.ExpectedDeviceRevision)
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil || n != 1 {
		return actionError(generated.ErrorCodePlanStale)
	}
	return nil
}
func verifyDeviceLifecycle(row discoveryRow, in generated.AuthorizationGrantBatchRequest) error {
	var owner, status string
	var revision int64
	expected := "pending"
	if in.DeviceAction == "approve" {
		expected = "approved"
	}
	if in.DeviceAction == "revoke" {
		expected = "revoked"
	}
	if row(`SELECT principal_id,status,device_revision FROM operator_devices WHERE device_id=?`, in.DeviceID).Scan(&owner, &status, &revision) != nil || owner != in.PrincipalID || status != expected || revision != in.ExpectedDeviceRevision+1 {
		return actionError(generated.ErrorCodeStateConflict)
	}
	return nil
}

// AuthorizeDevice checks current server-owned state for every attributed request.
// It grants no scopes: ordinary authorization remains responsible for each action.
func (r *EffectiveAuthorizationRepository) AuthorizeDevice(ctx context.Context, p identity.Principal) error {
	if p.DeviceID == "" {
		return nil
	}
	if r == nil || r.store == nil {
		return actionError(generated.ErrorCodeAuthorizationDenied)
	}
	return r.store.Read(ctx, func(tx ReadTx) error {
		return authorizeDeviceRow(func(q string, a ...any) *sql.Row { return tx.queryRow(ctx, q, a...) }, p)
	})
}
func authorizeDeviceRow(row discoveryRow, p identity.Principal) error {
	if p.DeviceID == "" {
		return nil
	}
	var n int
	if row(`SELECT COUNT(*) FROM operator_devices d JOIN effective_authorization_principals p ON p.principal_id=d.principal_id JOIN read_principals r ON r.principal_id=p.principal_id WHERE d.device_id=? AND d.principal_id=? AND d.status='approved' AND p.status='active' AND p.principal_kind='human' AND r.status='active'`, p.DeviceID, p.ID).Scan(&n) != nil || n != 1 {
		return actionError(generated.ErrorCodeAuthorizationDenied)
	}
	return nil
}
