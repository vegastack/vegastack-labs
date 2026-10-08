package store

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/vegastack/vegastack-labs/internal/audit"
	"github.com/vegastack/vegastack-labs/internal/authorization"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/identity"
)

func validSetupExternalID(value string) bool {
	if value == "" || len(value) > 128 || !utf8.ValidString(value) || strings.TrimSpace(value) != value {
		return false
	}
	for _, r := range value {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

const initialSetupScope = "control-plane.initial-setup"

func initialSetupDigest(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// validateInitialSetup independently checks the exact sanitized review supplied
// by the server. Canonical re-encoding also rejects duplicate and unknown fields.
func validateInitialSetup(setup InitialSetup, now time.Time) error {
	invalid := func() error { return newStoreError("INPUT_INVALID", "initial-setup", false, nil) }
	if len(setup.ReviewJSON) == 0 || len(setup.ReviewJSON) > 32768 || initialSetupDigest(setup.ReviewJSON) != setup.ReviewDigest {
		return invalid()
	}
	var review InitialSetupReview
	decoder := json.NewDecoder(bytes.NewReader(setup.ReviewJSON))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&review) != nil {
		return invalid()
	}
	canonical, err := json.Marshal(review)
	if err != nil || !bytes.Equal(canonical, setup.ReviewJSON) {
		return invalid()
	}
	requestJSON, err := json.Marshal(review.Request)
	if err != nil || generated.ValidateContractJSON(generated.SchemaIDLocalSetupReviewRequest, requestJSON, generated.ContractExact) != nil {
		return invalid()
	}
	r := review.Request
	a := setup.Approval
	binding := review.Acknowledgement
	if a.Method != binding.Method || !identity.ValidPrincipal(identity.Principal{ID: a.HumanID, Kind: identity.PrincipalHuman, Method: a.Method}) {
		return invalid()
	}
	expiry, err := time.Parse(time.RFC3339Nano, r.ExpiresAt)
	if err != nil || !expiry.Equal(setup.ExpiresAt) || !now.Before(expiry) || a.DecidedAt.IsZero() || a.DecidedAt.After(now) || !a.DecidedAt.Before(expiry) {
		return invalid()
	}
	if setup.SetupID != r.SetupID || setup.HumanID != r.InitialHumanID || setup.HumanID != binding.HumanID || a.HumanID != setup.HumanID || a.AuthorityID != binding.AuthorityID || a.ReviewDigest != setup.ReviewDigest || a.RequestDigest != setup.RequestDigest || review.RequestDigest != setup.RequestDigest {
		return invalid()
	}
	for _, v := range []string{setup.SetupID, setup.HumanID, binding.AuthorityID} {
		if !authorization.ValidIdentifier(v) {
			return invalid()
		}
	}
	for _, v := range []string{binding.ExternalScopeID, binding.ExternalSubjectID, binding.DeliveryTargetID} {
		if !validSetupExternalID(v) {
			return invalid()
		}
	}
	for _, v := range []string{setup.RequestDigest, binding.ProfileDigest} {
		if !audit.ValidFingerprint(audit.Fingerprint(v)) {
			return invalid()
		}
	}
	if r.ServiceUID <= 0 || r.ServiceUID != r.InitialAdministratorUID || len(setup.ReadGrants) != len(r.InitialReadGrants) || len(setup.EffectiveGrants) != len(r.InitialEffectiveGrants) {
		return invalid()
	}
	seen := map[InitialReadGrant]bool{}
	for i, g := range setup.ReadGrants {
		expected := r.InitialReadGrants[i]
		if g != (InitialReadGrant{expected.Capability, expected.ResourceKind, expected.ResourceID}) || !authorization.ValidTarget(authorization.ReadTarget{Capability: g.Capability, ResourceKind: g.ResourceKind, ResourceID: g.ResourceID}) || !authorization.ValidIdentifier(g.ResourceID) || seen[g] {
			return invalid()
		}
		seen[g] = true
	}
	ids := map[string]bool{}
	scopes := map[InitialEffectiveGrant]bool{}
	for i, g := range setup.EffectiveGrants {
		expected := r.InitialEffectiveGrants[i]
		if expected.Branch == "none" {
			expected.Branch = ""
		}
		if g != (InitialEffectiveGrant{expected.GrantID, expected.RoleID, expected.Action, expected.Capability, expected.ResourceKind, expected.ResourceID, expected.Branch}) || !authorization.ValidIdentifier(g.GrantID) || ids[g.GrantID] || !authorization.ValidRole(authorization.Role(g.RoleID)) || g.RoleID == string(authorization.RolePreauthorizedExecutor) || !authorization.ValidAction(authorization.Action(g.Action)) || !authorization.ValidAuthorizationTarget(authorization.Target{Capability: g.Capability, ResourceKind: g.ResourceKind, ResourceID: g.ResourceID}) {
			return invalid()
		}
		if (g.Action == "read" || g.Action == "author") && g.Branch != "" || (g.Action == "acknowledge" || g.Action == "execute") && g.Branch != "human" {
			return invalid()
		}
		ids[g.GrantID] = true
		g.GrantID = ""
		if scopes[g] {
			return invalid()
		}
		scopes[g] = true
	}
	return nil
}

func (store *Store) applyInitialSetup(ctx context.Context, tx *sql.Tx, setup InitialSetup) error {
	if err := validateInitialSetup(setup, store.config.Clock().UTC()); err != nil {
		return err
	}
	var review InitialSetupReview
	if err := json.Unmarshal(setup.ReviewJSON, &review); err != nil {
		return newStoreError("INPUT_INVALID", "initial-setup", false, nil)
	}
	if review.Request.DatabasePath != store.config.DatabasePath || review.Request.ServiceUID != int64(store.config.ExpectedUID) {
		return newStoreError("INPUT_INVALID", "initial-setup", false, nil)
	}
	after := audit.Fingerprint(setup.ReviewDigest)
	event := audit.EventDraft{Type: "control.initialized", CorrelationID: setup.SetupID, Attribution: audit.Attribution{AuthenticatedPrincipalID: setup.HumanID, AuthenticatedPrincipalMethod: setup.Approval.Method, ResponsibleHumanPrincipalID: &setup.HumanID}, Target: audit.Target{Kind: "acknowledgement-authority", ID: setup.Approval.AuthorityID}, After: &after}
	key := audit.IntentKey{Scope: initialSetupScope, KeyDigest: audit.Fingerprint(setup.ReviewDigest), RequestDigest: audit.Fingerprint(setup.RequestDigest)}
	if audit.ValidateEventDraft(event) != nil || audit.ValidateIntentKey(key) != nil {
		return newStoreError("INPUT_INVALID", "initial-setup", false, nil)
	}
	_, err := store.appendAuditInTx(ctx, tx, intentRequest{Event: event, Idempotency: key, eventTime: &setup.Approval.DecidedAt}, true, func(ctx context.Context, tx *sql.Tx) error {
		now := store.config.Clock().UTC().Format(time.RFC3339Nano)
		if _, err := tx.ExecContext(ctx, `INSERT INTO read_principals VALUES(?,'active',1,?,?)`, setup.HumanID, now, now); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO effective_authorization_principals VALUES(?,'human','active',1,?,?)`, setup.HumanID, now, now); err != nil {
			return err
		}
		for _, g := range setup.ReadGrants {
			if _, err := tx.ExecContext(ctx, `INSERT INTO read_grants VALUES(?,?,?,?,1,'active',?,?)`, setup.HumanID, g.Capability, g.ResourceKind, g.ResourceID, now, now); err != nil {
				return err
			}
		}
		for _, g := range setup.EffectiveGrants {
			var branch any
			if g.Branch != "" {
				branch = g.Branch
			}
			if _, err := tx.ExecContext(ctx, `INSERT INTO effective_authorization_grants VALUES(?,?,?,?,?,?,?,?,1,'active',?,?)`, g.GrantID, setup.HumanID, g.RoleID, g.Action, g.Capability, g.ResourceKind, g.ResourceID, branch, now, now); err != nil {
				return err
			}
		}
		return nil
	})
	return err
}

func (store *Store) ReadInitialSetupDigest(ctx context.Context) (string, error) {
	var digest string
	err := store.Read(ctx, func(tx ReadTx) error {
		return tx.queryRow(ctx, `SELECT key_digest FROM intent_keys WHERE scope=?`, initialSetupScope).Scan(&digest)
	})
	return digest, err
}
