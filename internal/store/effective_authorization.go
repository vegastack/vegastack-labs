package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/vegastack/vegastack-labs/internal/audit"
	"github.com/vegastack/vegastack-labs/internal/authorization"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/identity"
)

type EffectiveAuthorizationRepository struct{ store *Store }

type DesiredAuthorizationGrant struct {
	ID              string
	PrincipalID     string
	Role            authorization.Role
	Action          authorization.Action
	Target          authorization.Target
	Branch          authorization.Branch
	DesiredRevision int64
	CreatedAt       time.Time
}

type PolicyChangeRequest struct {
	Expected      RevisionToken
	AuthorScope   authorization.EffectiveScope
	Grant         DesiredAuthorizationGrant
	CorrelationID string
	Attribution   audit.Attribution
	Idempotency   audit.IntentKey
	Destinations  []audit.OutboxRequirement
}

func NewEffectiveAuthorizationRepository(store *Store) *EffectiveAuthorizationRepository {
	return &EffectiveAuthorizationRepository{store: store}
}

func (repository *EffectiveAuthorizationRepository) Snapshot(ctx context.Context, principalID string, target authorization.Target) (authorization.EffectivePolicySnapshot, error) {
	snapshot := authorization.EffectivePolicySnapshot{PrincipalID: principalID, Status: authorization.EffectiveRevoked}
	if repository == nil || repository.store == nil || !authorization.ValidAuthorizationTarget(target) {
		return snapshot, newStoreError(generated.ErrorCodeAuthorizationDenied, "effective-authorization", false, nil)
	}
	err := repository.store.Read(ctx, func(tx ReadTx) error {
		if err := tx.queryRow(ctx, `SELECT state_revision,recovery_epoch FROM system_meta WHERE id=1`).Scan(&snapshot.StateRevision, &snapshot.RecoveryEpoch); err != nil {
			return err
		}
		var principalKind string
		err := tx.queryRow(ctx, `SELECT principal_kind,status,grant_revision FROM effective_authorization_principals WHERE principal_id=?`, principalID).Scan(&principalKind, &snapshot.Status, &snapshot.GrantRevision)
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		snapshot.PrincipalKind = identity.PrincipalKind(principalKind)
		if !identity.ValidPrincipalKind(snapshot.PrincipalKind) || snapshot.Status != authorization.EffectiveActive || snapshot.GrantRevision <= 0 {
			return nil
		}
		rows, err := tx.query(ctx, `SELECT role_id,action,capability,resource_kind,resource_id,branch FROM effective_authorization_grants WHERE principal_id=? AND capability=? AND resource_kind=? AND resource_id=? AND status='active' AND grant_revision=? ORDER BY role_id,action,grant_id`, principalID, target.Capability, target.ResourceKind, target.ResourceID, snapshot.GrantRevision)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var grant authorization.EffectiveGrant
			var branch sql.NullString
			if err := rows.Scan(&grant.Role, &grant.AllowedAction, &grant.Capability, &grant.ResourceKind, &grant.ResourceID, &branch); err != nil {
				return err
			}
			if branch.Valid {
				grant.Branch = authorization.Branch(branch.String)
			}
			snapshot.Grants = append(snapshot.Grants, grant)
		}
		return rows.Err()
	})
	if err != nil {
		return authorization.EffectivePolicySnapshot{}, err
	}
	return snapshot, nil
}

func (repository *EffectiveAuthorizationRepository) RecordDecision(ctx context.Context, record authorization.DecisionRecord) error {
	if repository == nil || repository.store == nil || !authorization.ValidDecisionRecord(record) {
		return newStoreError("INPUT_INVALID", "authorization-decision", false, nil)
	}
	decision := record.Decision
	eventType := audit.EventType("authorization.denied")
	if decision.Allowed {
		eventType = "authorization.allowed"
	}
	fingerprint := decisionFingerprint(record)
	event := audit.EventDraft{
		Type: eventType, CorrelationID: record.CorrelationID, Attribution: record.Attribution,
		Target: audit.Target{Kind: audit.TargetKind(decision.Target.ResourceKind), ID: decision.Target.ResourceID},
		After:  &fingerprint,
	}
	expected := RevisionToken{StateRevision: decision.StateRevision, RecoveryEpoch: decision.RecoveryEpoch}
	_, err := repository.store.executeAuditIntent(ctx, intentRequest{Expected: &expected, Idempotency: record.Idempotency, Event: event, Destinations: record.Destinations}, false, func(ctx context.Context, transaction *sql.Tx) error {
		var branch any
		if decision.Branch != nil {
			branch = string(*decision.Branch)
		}
		var planDigest any
		if decision.PlanDigest != "" {
			planDigest = decision.PlanDigest
		}
		var scopeDigest any
		if decision.Scope.ScopeDigest != "" {
			scopeDigest = decision.Scope.ScopeDigest
		}
		_, insertErr := transaction.ExecContext(ctx, `INSERT INTO authorization_decisions(decision_id,principal_id,action,capability,resource_kind,resource_id,allowed,branch,reason_code,grant_revision,state_revision,recovery_epoch,plan_digest,scope_digest,decided_at,audit_correlation_id) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
			record.DecisionID, decision.PrincipalID, decision.Action, decision.Target.Capability, decision.Target.ResourceKind, decision.Target.ResourceID, decision.Allowed, branch, decision.ReasonCode, decision.GrantRevision, decision.StateRevision, decision.RecoveryEpoch, planDigest, scopeDigest, record.DecidedAt.Format("2006-01-02T15:04:05Z"), record.CorrelationID)
		return insertErr
	})
	return err
}

func (repository *EffectiveAuthorizationRepository) StageDesiredGrant(ctx context.Context, request PolicyChangeRequest) (Commit, error) {
	if repository == nil || repository.store == nil || !validPolicyChangeRequest(request) {
		return Commit{}, newStoreError("INPUT_INVALID", "authorization-policy", false, nil)
	}
	fingerprint := desiredGrantFingerprint(request.Grant)
	event := audit.EventDraft{
		Type: "authorization.policy-staged", CorrelationID: request.CorrelationID, Attribution: request.Attribution,
		Target: audit.Target{Kind: "authorization-policy", ID: request.Grant.PrincipalID}, After: &fingerprint,
	}
	result, err := repository.store.executeAuditIntent(ctx, intentRequest{Expected: &request.Expected, Idempotency: request.Idempotency, Event: event, Destinations: request.Destinations}, true, func(ctx context.Context, transaction *sql.Tx) error {
		if !effectiveAuthorScopeMatches(ctx, transaction, request.AuthorScope) {
			return newStoreError(generated.ErrorCodeAuthorizationDenied, "authorization-policy", false, nil)
		}
		var branch any
		if request.Grant.Branch != "" {
			branch = string(request.Grant.Branch)
		}
		_, insertErr := transaction.ExecContext(ctx, `INSERT INTO desired_authorization_grants(desired_grant_id,principal_id,proposed_by_principal_id,role_id,action,capability,resource_kind,resource_id,branch,desired_revision,status,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,'draft',?)`,
			request.Grant.ID, request.Grant.PrincipalID, request.AuthorScope.PrincipalID, request.Grant.Role, request.Grant.Action, request.Grant.Target.Capability, request.Grant.Target.ResourceKind, request.Grant.Target.ResourceID, branch, request.Grant.DesiredRevision, request.Grant.CreatedAt.Format("2006-01-02T15:04:05Z"))
		return insertErr
	})
	if err != nil {
		return Commit{}, err
	}
	return result.Commit, nil
}

func validPolicyChangeRequest(request PolicyChangeRequest) bool {
	grant := request.Grant
	scope := request.AuthorScope
	if scope.Action != authorization.ActionAuthor || scope.Capability != "authorization.policy.write" || scope.ResourceKind != "authorization-policy" || scope.ResourceID != grant.PrincipalID ||
		scope.StateRevision != request.Expected.StateRevision || scope.RecoveryEpoch != request.Expected.RecoveryEpoch || scope.GrantRevision <= 0 || scope.ScopeDigest == "" ||
		!authorization.ValidIdentifier(grant.ID) || !authorization.ValidIdentifier(grant.PrincipalID) || !authorization.ValidRole(grant.Role) || !authorization.ValidAction(grant.Action) || !authorization.ValidAuthorizationTarget(grant.Target) ||
		grant.DesiredRevision <= 0 || grant.CreatedAt.IsZero() || grant.CreatedAt.Location() != time.UTC || !authorization.ValidIdentifier(request.CorrelationID) ||
		request.Attribution.AuthenticatedPrincipalID != scope.PrincipalID || audit.ValidateIntentKey(request.Idempotency) != nil || audit.ValidateOutboxRequirements(request.Destinations) != nil {
		return false
	}
	if grant.Action == authorization.ActionRead || grant.Action == authorization.ActionAuthor {
		return grant.Branch == "" && grant.Role != authorization.RolePreauthorizedExecutor
	}
	if !authorization.ValidBranch(grant.Branch) {
		return false
	}
	if grant.Branch == authorization.BranchPreauthorized {
		return grant.Action == authorization.ActionExecute && grant.Role == authorization.RolePreauthorizedExecutor
	}
	return grant.Role != authorization.RolePreauthorizedExecutor
}

func effectiveAuthorScopeMatches(ctx context.Context, transaction *sql.Tx, scope authorization.EffectiveScope) bool {
	var snapshot authorization.EffectivePolicySnapshot
	var principalKind string
	if err := transaction.QueryRowContext(ctx, `SELECT principal_kind,status,grant_revision FROM effective_authorization_principals WHERE principal_id=?`, scope.PrincipalID).Scan(&principalKind, &snapshot.Status, &snapshot.GrantRevision); err != nil {
		return false
	}
	snapshot.PrincipalID = scope.PrincipalID
	snapshot.PrincipalKind = identity.PrincipalKind(principalKind)
	snapshot.StateRevision = scope.StateRevision
	snapshot.RecoveryEpoch = scope.RecoveryEpoch
	var grant authorization.EffectiveGrant
	var branch sql.NullString
	err := transaction.QueryRowContext(ctx, `SELECT role_id,action,capability,resource_kind,resource_id,branch FROM effective_authorization_grants WHERE principal_id=? AND role_id=? AND action=? AND capability=? AND resource_kind=? AND resource_id=? AND status='active' AND grant_revision=?`,
		scope.PrincipalID, scope.Role, scope.Action, scope.Capability, scope.ResourceKind, scope.ResourceID, scope.GrantRevision).Scan(&grant.Role, &grant.AllowedAction, &grant.Capability, &grant.ResourceKind, &grant.ResourceID, &branch)
	if err != nil {
		return false
	}
	if branch.Valid {
		grant.Branch = authorization.Branch(branch.String)
	}
	expected, ok := authorization.BindEffectiveScope(snapshot, grant, authorization.Target{Capability: scope.Capability, ResourceKind: scope.ResourceKind, ResourceID: scope.ResourceID})
	return ok && expected == scope
}

func decisionFingerprint(record authorization.DecisionRecord) audit.Fingerprint {
	decision := record.Decision
	branch := ""
	if decision.Branch != nil {
		branch = string(*decision.Branch)
	}
	parts := []string{
		"authorization-decision-v1", record.DecisionID, decision.PrincipalID, string(decision.Action),
		decision.Target.Capability, decision.Target.ResourceKind, decision.Target.ResourceID,
		strconv.FormatBool(decision.Allowed), branch, decision.ReasonCode,
		strconv.FormatInt(decision.GrantRevision, 10), strconv.FormatInt(decision.StateRevision, 10),
		strconv.FormatInt(decision.RecoveryEpoch, 10), decision.PlanDigest, decision.Scope.ScopeDigest,
		record.DecidedAt.Format("2006-01-02T15:04:05Z"), record.CorrelationID,
	}
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return audit.Fingerprint("sha256:" + hex.EncodeToString(sum[:]))
}

func desiredGrantFingerprint(grant DesiredAuthorizationGrant) audit.Fingerprint {
	parts := []string{"desired-authorization-grant-v1", grant.ID, grant.PrincipalID, string(grant.Role), string(grant.Action), grant.Target.Capability, grant.Target.ResourceKind, grant.Target.ResourceID, string(grant.Branch), strconv.FormatInt(grant.DesiredRevision, 10), grant.CreatedAt.Format("2006-01-02T15:04:05Z")}
	sum := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	return audit.Fingerprint("sha256:" + hex.EncodeToString(sum[:]))
}
