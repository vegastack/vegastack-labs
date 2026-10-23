package store

import (
	"context"
	"database/sql"
	"sort"
	"time"

	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/identity"
)

// BrowserIdentityBindingDigest validates only enrollment metadata. It does not
// authenticate an assertion. Fixed validity times let BindingDigest enforce its
// existing exact metadata bounds without accepting assertion/token material.
func BrowserIdentityBindingDigest(in generated.BrowserIdentityBindingChange) (string, error) {
	if !sort.StringsAreSorted(in.Audiences) {
		return "", actionError(generated.ErrorCodeInputInvalid)
	}
	start := time.Unix(1, 0)
	digest, err := identity.BindingDigest(identity.VerifiedIdentity{Method: in.Method, Issuer: in.Issuer, Subject: in.Subject, Audiences: in.Audiences, IssuedAt: start, ExpiresAt: start.Add(time.Second)})
	if err != nil {
		return "", actionError(generated.ErrorCodeInputInvalid)
	}
	return digest, nil
}
func validateBrowserIdentityBinding(row discoveryRow, in generated.AuthorizationGrantBatchRequest) error {
	b := in.IdentityBinding
	if b == nil {
		return nil
	}
	digest, err := BrowserIdentityBindingDigest(*b)
	if err != nil {
		return err
	}
	var owner, status string
	err = row(`SELECT principal_id,status FROM remote_identity_bindings WHERE binding_digest=?`, digest).Scan(&owner, &status)
	if b.Action == "bind" {
		if err != sql.ErrNoRows {
			return actionError(generated.ErrorCodeStateConflict)
		}
		return nil
	}
	if err != nil || owner != in.PrincipalID || (status != "active" && status != "suspended") {
		return actionError(generated.ErrorCodeStateConflict)
	}
	return nil
}
func applyBrowserIdentityBinding(ctx context.Context, tx *sql.Tx, in generated.AuthorizationGrantBatchRequest, now string) error {
	b := in.IdentityBinding
	digest, err := BrowserIdentityBindingDigest(*b)
	if err != nil {
		return err
	}
	if b.Action == "bind" {
		_, err = tx.ExecContext(ctx, `INSERT INTO remote_identity_bindings(binding_digest,principal_id,status,created_at,updated_at) VALUES(?,?,'active',?,?)`, digest, in.PrincipalID, now, now)
		return err
	}
	result, err := tx.ExecContext(ctx, `UPDATE remote_identity_bindings SET status='revoked',updated_at=? WHERE binding_digest=? AND principal_id=? AND status IN ('active','suspended')`, now, digest, in.PrincipalID)
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil || n != 1 {
		return actionError(generated.ErrorCodeStateConflict)
	}
	_, err = tx.ExecContext(ctx, `UPDATE browser_sessions SET status='revoked',ended_at=?,end_reason='identity-binding-revoked' WHERE binding_digest=? AND principal_id=? AND status='active'`, now, digest, in.PrincipalID)
	return err
}
func verifyBrowserIdentityBinding(row discoveryRow, in generated.AuthorizationGrantBatchRequest) error {
	digest, err := BrowserIdentityBindingDigest(*in.IdentityBinding)
	if err != nil {
		return err
	}
	expected := "active"
	if in.IdentityBinding.Action == "revoke" {
		expected = "revoked"
	}
	var owner, status string
	if row(`SELECT principal_id,status FROM remote_identity_bindings WHERE binding_digest=?`, digest).Scan(&owner, &status) != nil || owner != in.PrincipalID || status != expected {
		return actionError(generated.ErrorCodeIntegrityFailure)
	}
	if expected == "revoked" {
		var n int
		if row(`SELECT COUNT(*) FROM browser_sessions WHERE binding_digest=? AND status='active'`, digest).Scan(&n) != nil || n != 0 {
			return actionError(generated.ErrorCodeIntegrityFailure)
		}
	}
	return nil
}
