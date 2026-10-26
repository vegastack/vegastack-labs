package store

import (
	"context"
	"database/sql"
	"github.com/vegastack/vegastack-labs/internal/authorization"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/identity"
	"regexp"
)

type OperatorAccessRepository struct{ store *Store }

func NewOperatorAccessRepository(s *Store) *OperatorAccessRepository {
	return &OperatorAccessRepository{s}
}

var operatorReadID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)

// Every returned collection and its exact policy authority share one current read snapshot.
func (r *OperatorAccessRepository) snapshot(ctx context.Context, owner, after string, limit int, fn func(ReadTx, identity.Principal) error) error {
	p, ok := identity.PrincipalFromContext(ctx)
	if !ok || !identity.ValidPrincipal(p) {
		return actionError(generated.ErrorCodeAuthenticationRequired)
	}
	if r == nil || r.store == nil {
		return actionError(generated.ErrorCodeAuthorizationDenied)
	}
	if limit < 1 || limit > 100 || after != "" && !operatorReadID.MatchString(after) || owner != "" && !operatorReadID.MatchString(owner) {
		return actionError(generated.ErrorCodeInputInvalid)
	}
	return r.store.Read(ctx, func(tx ReadTx) error {
		row := func(q string, a ...any) *sql.Row { return tx.queryRow(ctx, q, a...) }
		if err := authorizeDeviceRow(row, p); err != nil {
			return err
		}
		var n int
		if err := row(`SELECT COUNT(*) FROM effective_authorization_principals p JOIN read_principals r ON r.principal_id=p.principal_id WHERE p.principal_id=? AND p.principal_kind=? AND p.status='active' AND r.status='active'`, p.ID, string(identity.EffectivePrincipalKind(p))).Scan(&n); err != nil {
			return err
		}
		if n != 1 {
			return actionError(generated.ErrorCodeAuthorizationDenied)
		}
		q := `SELECT COUNT(*) FROM effective_authorization_principals p JOIN effective_authorization_grants g ON g.principal_id=p.principal_id AND g.grant_revision=p.grant_revision WHERE p.principal_id=? AND p.status='active' AND g.status='active' AND g.action='read' AND g.capability='authorization.policy.read' AND g.resource_kind='authorization-policy'`
		args := []any{p.ID}
		if owner != "" {
			q += ` AND g.resource_id=?`
			args = append(args, owner)
		}
		if err := row(q, args...).Scan(&n); err != nil {
			return err
		}
		if n == 0 {
			return actionError(generated.ErrorCodeAuthorizationDenied)
		}
		return fn(tx, p)
	})
}
func (r *OperatorAccessRepository) ListPeople(ctx context.Context, after string, limit int) (generated.OperatorPeoplePage, error) {
	v := generated.OperatorPeoplePage{Schema: generated.SchemaIDOperatorPeoplePage, SchemaVersion: "1.0.0", People: []generated.OperatorPerson{}}
	err := r.snapshot(ctx, "", after, limit, func(tx ReadTx, p identity.Principal) error {
		if err := tx.queryRow(ctx, `SELECT state_revision,recovery_epoch FROM system_meta WHERE id=1`).Scan(&v.StateRevision, &v.RecoveryEpoch); err != nil {
			return err
		}
		rows, err := tx.query(ctx, `SELECT h.principal_id,h.status,h.grant_revision FROM effective_authorization_principals h WHERE h.principal_kind='human' AND h.principal_id>? AND EXISTS(SELECT 1 FROM effective_authorization_principals p JOIN effective_authorization_grants g ON g.principal_id=p.principal_id AND g.grant_revision=p.grant_revision WHERE p.principal_id=? AND p.status='active' AND g.status='active' AND g.action='read' AND g.capability='authorization.policy.read' AND g.resource_kind='authorization-policy' AND g.resource_id=h.principal_id) ORDER BY h.principal_id LIMIT ?`, after, p.ID, limit+1)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var x generated.OperatorPerson
			x.Schema = generated.SchemaIDOperatorPerson
			x.SchemaVersion = "1.0.0"
			if err := rows.Scan(&x.PrincipalID, &x.Status, &x.GrantRevision); err != nil {
				return err
			}
			if len(v.People) == limit {
				v.NextAfter = v.People[len(v.People)-1].PrincipalID
				break
			}
			v.People = append(v.People, x)
		}
		return rows.Err()
	})
	return v, err
}
func (r *OperatorAccessRepository) ListDevices(ctx context.Context, owner, after string, limit int) (generated.OperatorDeviceList, error) {
	v := generated.OperatorDeviceList{Schema: generated.SchemaIDOperatorDeviceList, SchemaVersion: "1.0.0", Devices: []generated.OperatorDevice{}}
	if owner == "" {
		return v, actionError(generated.ErrorCodeInputInvalid)
	}
	err := r.snapshot(ctx, owner, after, limit, func(tx ReadTx, _ identity.Principal) error {
		if err := tx.queryRow(ctx, `SELECT state_revision,recovery_epoch FROM system_meta WHERE id=1`).Scan(&v.StateRevision, &v.RecoveryEpoch); err != nil {
			return err
		}
		rows, err := tx.query(ctx, `SELECT device_id,principal_id,status,device_revision FROM operator_devices WHERE principal_id=? AND device_id>? ORDER BY device_id LIMIT ?`, owner, after, limit+1)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			x := generated.OperatorDevice{Schema: generated.SchemaIDOperatorDevice, SchemaVersion: "1.0.0"}
			if err := rows.Scan(&x.DeviceID, &x.PrincipalID, &x.Status, &x.DeviceRevision); err != nil {
				return err
			}
			if len(v.Devices) == limit {
				v.NextAfter = v.Devices[len(v.Devices)-1].DeviceID
				break
			}
			v.Devices = append(v.Devices, x)
		}
		return rows.Err()
	})
	return v, err
}
func (r *OperatorAccessRepository) ListGrants(ctx context.Context, owner, after string, limit int) (generated.OperatorGrantList, error) {
	v := generated.OperatorGrantList{Schema: generated.SchemaIDOperatorGrantList, SchemaVersion: "1.0.0", Grants: []generated.OperatorGrant{}}
	if owner == "" {
		return v, actionError(generated.ErrorCodeInputInvalid)
	}
	err := r.snapshot(ctx, owner, after, limit, func(tx ReadTx, _ identity.Principal) error {
		if err := tx.queryRow(ctx, `SELECT state_revision,recovery_epoch FROM system_meta WHERE id=1`).Scan(&v.StateRevision, &v.RecoveryEpoch); err != nil {
			return err
		}
		rows, err := tx.query(ctx, `SELECT grant_id,principal_id,role_id,action,capability,resource_kind,resource_id,ifnull(branch,''),status,grant_revision FROM effective_authorization_grants WHERE principal_id=? AND grant_id>? ORDER BY grant_id LIMIT ?`, owner, after, limit+1)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			x := generated.OperatorGrant{Schema: generated.SchemaIDOperatorGrant, SchemaVersion: "1.0.0"}
			if err := rows.Scan(&x.GrantID, &x.PrincipalID, &x.Role, &x.Action, &x.Capability, &x.ResourceKind, &x.ResourceID, &x.Branch, &x.Status, &x.GrantRevision); err != nil {
				return err
			}
			if len(v.Grants) == limit {
				v.NextAfter = v.Grants[len(v.Grants)-1].GrantID
				break
			}
			v.Grants = append(v.Grants, x)
		}
		return rows.Err()
	})
	return v, err
}

// Provider configuration is supplied by the server composition, never private
// profile fields. No connectivity observation is inferred from configuration.
func (r *OperatorAccessRepository) ProviderRevision(ctx context.Context, scope authorization.ReadScope) (RevisionToken, error) {
	var v RevisionToken
	if r == nil || r.store == nil {
		return v, actionError(generated.ErrorCodeAuthorizationDenied)
	}
	err := r.store.Read(ctx, func(tx ReadTx) error {
		p, ok := identity.PrincipalFromContext(ctx)
		if !ok {
			return actionError(generated.ErrorCodeAuthenticationRequired)
		}
		if err := authorizeDeviceRow(func(q string, a ...any) *sql.Row { return tx.queryRow(ctx, q, a...) }, p); err != nil {
			return err
		}
		if scope.PrincipalID != p.ID || scope.Capability != "platform.source.read" || scope.ResourceKind != "platform-source" {
			return actionError(generated.ErrorCodeAuthorizationDenied)
		}
		var active int
		if err := tx.queryRow(ctx, `SELECT COUNT(*) FROM effective_authorization_principals WHERE principal_id=? AND principal_kind=? AND status='active'`, p.ID, string(identity.EffectivePrincipalKind(p))).Scan(&active); err != nil {
			return err
		}
		if active != 1 {
			return actionError(generated.ErrorCodeAuthorizationDenied)
		}
		if err := verifyReadScope(ctx, tx, scope, "providers"); err != nil {
			return err
		}
		return tx.queryRow(ctx, `SELECT state_revision,recovery_epoch FROM system_meta WHERE id=1`).Scan(&v.StateRevision, &v.RecoveryEpoch)
	})
	return v, err
}
