package store

import (
	"context"
	"database/sql"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/identity"
)

// Lifecycle operations affect local control-plane authority only. Onboarding
// neither provisions an external account nor grants any permissions.
func validateGrantBatchPrincipal(row discoveryRow, in generated.AuthorizationGrantBatchRequest) error {
	var status, kind, readStatus string
	var revision int64
	err := row(`SELECT p.status,p.principal_kind,p.grant_revision,r.status FROM effective_authorization_principals p JOIN read_principals r ON r.principal_id=p.principal_id WHERE p.principal_id=?`, in.PrincipalID).Scan(&status, &kind, &revision, &readStatus)
	if in.LifecycleAction == "onboard" {
		var n int
		if err != sql.ErrNoRows || row(`SELECT (SELECT COUNT(*) FROM read_principals WHERE principal_id=?)+(SELECT COUNT(*) FROM effective_authorization_principals WHERE principal_id=?)`, in.PrincipalID, in.PrincipalID).Scan(&n) != nil || n != 0 {
			return actionError(generated.ErrorCodeStateConflict)
		}
		return nil
	}
	want := "active"
	if in.LifecycleAction == "resume" {
		want = "suspended"
	}
	if err != nil || (status != want && !(in.LifecycleAction == "offboard" && status == "suspended")) || readStatus != status || revision != in.ExpectedGrantRevision || ((in.LifecycleAction != "" || in.DeviceAction != "" || in.IdentityBinding != nil) && kind != "human") {
		return actionError(generated.ErrorCodePlanStale)
	}
	if in.LifecycleAction == "suspend" || in.LifecycleAction == "offboard" {
		var targetAdmin, otherAdmin int
		q := `SELECT COUNT(*) FROM effective_authorization_principals p JOIN effective_authorization_grants g ON g.principal_id=p.principal_id AND g.grant_revision=p.grant_revision WHERE p.status='active' AND p.principal_kind='human' AND g.status='active' AND g.role_id IN ('infrastructure-admin','control-plane-admin') AND p.principal_id`
		if row(q+`=?`, in.PrincipalID).Scan(&targetAdmin) != nil || row(q+`!=?`, in.PrincipalID).Scan(&otherAdmin) != nil || targetAdmin > 0 && otherAdmin == 0 {
			return actionError(generated.ErrorCodeAuthorizationDenied)
		}
	}
	if in.DeviceAction != "" {
		return validateDeviceLifecycle(row, in)
	}
	return nil
}
func validateLifecycleActor(ctx context.Context, in generated.AuthorizationGrantBatchRequest) error {
	if in.LifecycleAction == "" && (in.DeviceAction == "" || in.DeviceAction == "request") {
		return nil
	}
	actor, ok := identity.PrincipalFromContext(ctx)
	if !ok || actor.ID == in.PrincipalID {
		return actionError(generated.ErrorCodeAuthorizationDenied)
	}
	return nil
}
func applyUserLifecycle(ctx context.Context, tx *sql.Tx, in generated.AuthorizationGrantBatchRequest, now string) error {
	if in.LifecycleAction == "onboard" {
		if _, err := tx.ExecContext(ctx, `INSERT INTO read_principals VALUES(?,'active',1,?,?)`, in.PrincipalID, now, now); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, `INSERT INTO effective_authorization_principals VALUES(?,'human','active',1,?,?)`, in.PrincipalID, now, now)
		return err
	}
	status := "active"
	if in.LifecycleAction == "suspend" {
		status = "suspended"
	}
	if in.LifecycleAction == "offboard" {
		status = "revoked"
	}
	for _, table := range []string{"read_principals", "effective_authorization_principals", "read_grants", "effective_authorization_grants"} {
		query := `UPDATE ` + table + ` SET grant_revision=grant_revision+1,updated_at=?`
		args := []any{now}
		if table == "read_principals" || table == "effective_authorization_principals" || status == "revoked" {
			query += `,status=?`
			args = append(args, status)
		}
		query += ` WHERE principal_id=?`
		args = append(args, in.PrincipalID)
		if _, err := tx.ExecContext(ctx, query, args...); err != nil {
			return err
		}
	}
	if in.LifecycleAction == "suspend" || in.LifecycleAction == "offboard" {
		if _, err := tx.ExecContext(ctx, `UPDATE browser_sessions SET status='revoked',ended_at=?,end_reason='user-lifecycle' WHERE principal_id=? AND status='active'`, now, in.PrincipalID); err != nil {
			return err
		}
	}
	if in.LifecycleAction == "offboard" {
		_, err := tx.ExecContext(ctx, `UPDATE remote_identity_bindings SET status='revoked',updated_at=? WHERE principal_id=? AND status!='revoked'`, now, in.PrincipalID)
		return err
	}
	return nil
}
