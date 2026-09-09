package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"sort"
	"strconv"
	"strings"

	"github.com/vegastack/vegastack-labs/internal/authorization"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/identity"
)

type ReadAuthorizer struct{ store *Store }

func NewReadAuthorizer(store *Store) *ReadAuthorizer { return &ReadAuthorizer{store: store} }

func (authorizer *ReadAuthorizer) AuthorizeRead(ctx context.Context, principal identity.Principal, target authorization.ReadTarget) (authorization.ReadScope, error) {
	if principal.ID == "" || principal.Method != identity.LocalOSPeerMethod {
		return authorization.ReadScope{}, newStoreError(generated.ErrorCodeAuthenticationRequired, "read", false, nil)
	}
	if authorizer == nil || authorizer.store == nil || !authorization.ValidTarget(target) {
		return authorization.ReadScope{}, newStoreError(generated.ErrorCodeAuthorizationDenied, "read", false, nil)
	}
	var scope authorization.ReadScope
	err := authorizer.store.Read(ctx, func(tx ReadTx) error {
		var status string
		if err := tx.queryRow(ctx, `SELECT status,grant_revision FROM read_principals WHERE principal_id=?`, principal.ID).Scan(&status, &scope.GrantRevision); err != nil {
			return err
		}
		if status != "active" || scope.GrantRevision <= 0 {
			return sql.ErrNoRows
		}
		rows, err := tx.query(ctx, `SELECT resource_id,grant_revision FROM read_grants WHERE principal_id=? AND capability=? AND resource_kind=? AND status='active' AND (?='' OR resource_id=?) ORDER BY resource_id`, principal.ID, target.Capability, target.ResourceKind, target.ResourceID, target.ResourceID)
		if err != nil {
			return err
		}
		defer rows.Close()
		var resources []string
		for rows.Next() {
			var resource string
			var revision int64
			if err := rows.Scan(&resource, &revision); err != nil {
				return err
			}
			if revision != scope.GrantRevision {
				return sql.ErrNoRows
			}
			resources = append(resources, resource)
		}
		if err := rows.Err(); err != nil {
			return err
		}
		if len(resources) == 0 {
			return sql.ErrNoRows
		}
		scope.PrincipalID = principal.ID
		scope.Capability = target.Capability
		scope.ResourceKind = target.ResourceKind
		scope.ScopeDigest = scopeDigest(principal.ID, target.Capability, target.ResourceKind, scope.GrantRevision, resources)
		return nil
	})
	if err != nil {
		return authorization.ReadScope{}, newStoreError(generated.ErrorCodeAuthorizationDenied, "read", false, err)
	}
	return scope, nil
}

func scopeDigest(principal, capability, kind string, revision int64, resources []string) string {
	ordered := append([]string(nil), resources...)
	sort.Strings(ordered)
	parts := []string{"read-scope-v1", principal, capability, kind, strconv.FormatInt(revision, 10)}
	parts = append(parts, ordered...)
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return "sha256:" + hex.EncodeToString(sum[:])
}
