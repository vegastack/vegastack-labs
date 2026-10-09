package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"strings"

	"github.com/vegastack/vegastack-labs/internal/authorization"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"github.com/vegastack/vegastack-labs/internal/identity"
)

const GrantBatchAdapter = "core.authorization"
const GrantBatchOperation = "identity.change"

func ValidateAuthorizationGrantBatch(in generated.AuthorizationGrantBatchRequest) error {
	raw, err := json.Marshal(in)
	if err != nil || generated.ValidateContractJSON("vegastack-labs.dev/authorization-grant-batch-request", raw, generated.ContractExact) != nil {
		return actionError(generated.ErrorCodeInputInvalid)
	}
	ids, scopes := map[string]bool{}, map[string]bool{}
	for _, g := range in.Changes {
		target := authorization.Target{Capability: g.Capability, ResourceKind: g.ResourceKind, ResourceID: g.ResourceID}
		role, action, branch := authorization.Role(g.RoleID), authorization.Action(g.Action), authorization.Branch(g.Branch)
		if !authorization.ValidAuthorizationTarget(target) || !authorization.ValidRole(role) || !authorization.ValidAction(action) || role == authorization.RolePreauthorizedExecutor || ((action == authorization.ActionRead || action == authorization.ActionAuthor) && (branch != "")) || ((action == authorization.ActionExecute || action == authorization.ActionAcknowledge) && branch != authorization.BranchHuman) {
			return actionError(generated.ErrorCodeInputInvalid)
		}
		if strings.HasPrefix(g.Capability, "authorization.policy.") || g.Capability == GrantBatchOperation || (g.ResourceID == in.PrincipalID && g.ResourceKind == "plan-target" && g.Capability == "plan.acknowledge") {
			return actionError(generated.ErrorCodeAuthorizationDenied)
		}
		scope := strings.Join([]string{g.RoleID, g.Action, g.Capability, g.ResourceKind, g.ResourceID, g.Branch}, "\x00")
		if ids[g.GrantID] || scopes[scope] {
			return actionError(generated.ErrorCodeInputInvalid)
		}
		ids[g.GrantID], scopes[scope] = true, true
	}
	return nil
}

func GrantBatchDeclarationID(principal string) string {
	sum := sha256.Sum256([]byte(principal))
	return "authorization-policy-" + hex.EncodeToString(sum[:16])
}

func ValidateGrantBatchDeclaration(d generated.DeclarationRevision) bool {
	present := d.AuthorizationGrantBatch != nil || d.DeclarationType == "authorization.policy"
	for _, op := range d.Operations {
		present = present || op.AdapterID == GrantBatchAdapter
	}
	if !present {
		return true
	}
	in := d.AuthorizationGrantBatch
	if in == nil || ValidateAuthorizationGrantBatch(*in) != nil || d.DeclarationType != "authorization.policy" || d.DeclarationID != GrantBatchDeclarationID(in.PrincipalID) || len(d.Operations) != 1 || len(d.Extensions) != 0 || d.RecoveryEpoch != in.RecoveryEpoch {
		return false
	}
	if d.Status == "draft" && (d.StateRevision != in.ExpectedStateRevision+1 || d.Revision != in.ExpectedDeclarationRevision+1) {
		return false
	}
	op := d.Operations[0]
	return op.Sequence == 1 && op.OperationID == "grant-batch" && op.OperationType == GrantBatchOperation && op.AdapterID == GrantBatchAdapter && op.TargetID == in.PrincipalID && op.InputDigest == hostaction.Digest(in) && op.ArtifactDigest == hostaction.Digest("core.authorization@1") && !op.Idempotent && op.OffsiteRunSpec == nil
}

type GrantBatchRepository struct{ store *Store }

func NewGrantBatchRepository(s *Store) *GrantBatchRepository { return &GrantBatchRepository{store: s} }

// Stage prepares an inert declaration; its owning declaration writer inserts
// desired rows atomically with that declaration and never changes effective grants.
func (r *GrantBatchRepository) Stage(ctx context.Context, in generated.AuthorizationGrantBatchRequest) (generated.DeclarationRevisionRequest, error) {
	var out generated.DeclarationRevisionRequest
	if r == nil || r.store == nil {
		return out, actionError(generated.ErrorCodePrerequisiteBlocked)
	}
	if err := ValidateAuthorizationGrantBatch(in); err != nil {
		return out, err
	}
	err := r.store.Read(ctx, func(tx ReadTx) error {
		row := func(q string, a ...any) *sql.Row { return tx.queryRow(ctx, q, a...) }
		if _, err := adoptionGrant(ctx, row, in.PrincipalID, "authorization-policy", "author", "authorization.policy.write", true); err != nil {
			return err
		}
		var status string
		var revision, epoch, state int64
		if row(`SELECT p.status,p.grant_revision,s.state_revision,s.recovery_epoch FROM effective_authorization_principals p CROSS JOIN system_meta s WHERE p.principal_id=? AND s.id=1`, in.PrincipalID).Scan(&status, &revision, &state, &epoch) != nil || status != "active" || revision != in.ExpectedGrantRevision || state != in.ExpectedStateRevision || epoch != in.RecoveryEpoch {
			return actionError(generated.ErrorCodePlanStale)
		}
		return validateGrantBatchChanges(row, in)
	})
	if err != nil {
		return out, err
	}
	copy := in
	copy.Changes = append([]generated.AuthorizationGrantChange(nil), in.Changes...)
	out = generated.DeclarationRevisionRequest{Schema: generated.SchemaIDDeclarationRevisionRequest, SchemaVersion: "1.0.0", DeclarationID: GrantBatchDeclarationID(in.PrincipalID), DeclarationType: "authorization.policy", ExpectedRevision: in.ExpectedDeclarationRevision + 1, ExpectedStateRevision: in.ExpectedStateRevision, RecoveryEpoch: in.RecoveryEpoch, ReasonDigest: in.ReasonDigest, Extensions: []generated.ContractExtension{}, AuthorizationGrantBatch: &copy, Operations: []generated.DeclarationOperation{{Sequence: 1, OperationID: "grant-batch", OperationType: GrantBatchOperation, AdapterID: GrantBatchAdapter, TargetID: in.PrincipalID, InputDigest: hostaction.Digest(in), ArtifactDigest: hostaction.Digest("core.authorization@1"), Idempotent: false}}}
	return out, nil
}

func validateGrantBatchChanges(row discoveryRow, in generated.AuthorizationGrantBatchRequest) error {
	for _, g := range in.Changes {
		var principal, role, action, capability, kind, resource, status string
		var branch sql.NullString
		err := row(`SELECT principal_id,role_id,action,capability,resource_kind,resource_id,branch,status FROM effective_authorization_grants WHERE grant_id=?`, g.GrantID).Scan(&principal, &role, &action, &capability, &kind, &resource, &branch, &status)
		if g.Change == "add" {
			if err != sql.ErrNoRows {
				return actionError(generated.ErrorCodeStateConflict)
			}
			var count int
			if row(`SELECT COUNT(*) FROM effective_authorization_grants WHERE principal_id=? AND role_id=? AND action=? AND capability=? AND resource_kind=? AND resource_id=? AND ifnull(branch,'')=?`, in.PrincipalID, g.RoleID, g.Action, g.Capability, g.ResourceKind, g.ResourceID, g.Branch).Scan(&count) != nil || count != 0 {
				return actionError(generated.ErrorCodeStateConflict)
			}
		} else if err != nil || principal != in.PrincipalID || role != g.RoleID || action != g.Action || capability != g.Capability || kind != g.ResourceKind || resource != g.ResourceID || branch.String != g.Branch || status != "active" {
			return actionError(generated.ErrorCodeStateConflict)
		}
	}
	return nil
}

func stageGrantBatchRows(ctx context.Context, tx *sql.Tx, in generated.AuthorizationGrantBatchRequest, actor, created string) error {
	row := func(q string, a ...any) *sql.Row { return tx.QueryRowContext(ctx, q, a...) }
	principal, ok := identity.PrincipalFromContext(ctx)
	if !ok || principal.ID != actor {
		return actionError(generated.ErrorCodeAuthorizationDenied)
	}
	if _, err := adoptionGrant(ctx, row, in.PrincipalID, "authorization-policy", "author", "authorization.policy.write", true); err != nil {
		return err
	}
	var status string
	var revision int64
	if row(`SELECT status,grant_revision FROM effective_authorization_principals WHERE principal_id=?`, in.PrincipalID).Scan(&status, &revision) != nil || status != "active" || revision != in.ExpectedGrantRevision {
		return actionError(generated.ErrorCodePlanStale)
	}
	if err := validateGrantBatchChanges(row, in); err != nil {
		return err
	}
	for _, g := range in.Changes {
		sum := sha256.Sum256([]byte(hostaction.Digest(in) + ":" + g.GrantID))
		id := "desired-" + hex.EncodeToString(sum[:16])
		var branch any
		if g.Branch != "" {
			branch = g.Branch
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO desired_authorization_grants(desired_grant_id,principal_id,proposed_by_principal_id,role_id,action,capability,resource_kind,resource_id,branch,desired_revision,status,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,'draft',?)`, id, in.PrincipalID, actor, g.RoleID, g.Action, g.Capability, g.ResourceKind, g.ResourceID, branch, in.ExpectedGrantRevision+1, created); err != nil {
			return err
		}
	}
	return nil
}
