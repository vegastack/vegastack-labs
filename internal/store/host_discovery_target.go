package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"strconv"
	"time"

	"github.com/vegastack/vegastack-labs/internal/audit"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostdiscovery"
)

type DiscoveryDraft struct {
	ID, Digest string
	Request    generated.HostDiscoveryTargetDraftRequest
}
type DiscoveryActivation struct {
	DraftID, PlanID, PlanDigest, RunID, StepID, LeaseID string
	Attribution                                         audit.Attribution
}

func (r *HostDiscoveryRepository) StageDraft(ctx context.Context, request generated.HostDiscoveryTargetDraftRequest, a audit.Attribution) (_ DiscoveryDraft, outcome error) {
	defer r.discoveryFailureAudit(ctx, "draft", request.Target.TargetID, &outcome)
	raw, _ := json.Marshal(request)
	if generated.ValidateContractJSON(generated.SchemaIDHostDiscoveryTargetDraftRequest, raw, generated.ContractExact) != nil || hostdiscovery.ValidateConsoleConfirmation(request) != nil || request.Target.Revision != request.ExpectedTargetRevision+1 {
		return DiscoveryDraft{}, discoveryError(generated.ErrorCodeInputInvalid)
	}
	// Audit replay skips its business callback, so authorize before either path.
	if err := r.store.Read(ctx, func(tx ReadTx) error {
		row := func(q string, args ...any) *sql.Row { return tx.queryRow(ctx, q, args...) }
		principal, _, err := discoveryGrant(ctx, row, request.Target.TargetID, "host.discovery.target.prepare", true)
		if err != nil {
			return err
		}
		if principal != a.AuthenticatedPrincipalID {
			return discoveryError(generated.ErrorCodeAuthorizationDenied)
		}
		return discoveryInventoryRead(row, principal, request.Target)
	}); err != nil {
		return DiscoveryDraft{}, err
	}
	digest := hostdiscovery.Digest(request)
	id := "discovery-draft-" + digest[7:39]
	intent := discoveryIntent(a, "host.discovery.target-drafted", id, hostdiscovery.Digest([]string{a.AuthenticatedPrincipalID, request.IdempotencyKey}), digest)
	intent.Expected = &RevisionToken{StateRevision: request.ExpectedStateRevision, RecoveryEpoch: request.Target.RecoveryEpoch}
	_, err := r.store.executeAuditIntent(ctx, intent, false, func(ctx context.Context, tx *sql.Tx) error {
		row := func(q string, args ...any) *sql.Row { return tx.QueryRowContext(ctx, q, args...) }
		principal, _, err := discoveryGrant(ctx, row, request.Target.TargetID, "host.discovery.target.prepare", true)
		if err != nil {
			return err
		}
		if principal != a.AuthenticatedPrincipalID {
			return discoveryError(generated.ErrorCodeAuthorizationDenied)
		}
		var latest int64
		if err := row(`SELECT COALESCE(MAX(revision),0) FROM host_discovery_targets WHERE target_id=?`, request.Target.TargetID).Scan(&latest); err != nil {
			return err
		}
		if latest != request.ExpectedTargetRevision || (request.Action == "revoke" && latest == 0) {
			return discoveryError(generated.ErrorCodeStateConflict)
		}
		if err := discoveryInventoryRead(row, principal, request.Target); err != nil {
			return err
		}
		if request.Target.InventoryDraftID != nil {
			var count int
			if err := row(`SELECT COUNT(*) FROM inventory_draft_assets WHERE draft_id=? AND draft_revision=? AND local_id=?`, *request.Target.InventoryDraftID, request.Target.InventoryDraftRevision, *request.Target.AssetID).Scan(&count); err != nil || count != 1 {
				return discoveryError(generated.ErrorCodePrerequisiteBlocked)
			}
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO host_discovery_drafts VALUES(?,?,?,?,?,?,?,?,?,?)`, id, request.Target.TargetID, request.Target.Revision, latest, request.Action, digest, raw, principal, request.ExpectedStateRevision, request.Target.RecoveryEpoch)
		return err
	})
	if err != nil {
		return DiscoveryDraft{}, err
	}
	return DiscoveryDraft{ID: id, Digest: digest, Request: request}, nil
}
func (r *HostDiscoveryRepository) GetDraft(ctx context.Context, id string) (DiscoveryDraft, error) {
	result := DiscoveryDraft{ID: id}
	err := r.store.Read(ctx, func(tx ReadTx) error {
		var raw []byte
		if err := tx.queryRow(ctx, `SELECT canonical_bytes,digest FROM host_discovery_drafts WHERE draft_id=?`, id).Scan(&raw, &result.Digest); err != nil {
			return err
		}
		if json.Unmarshal(raw, &result.Request) != nil || hostdiscovery.Digest(result.Request) != result.Digest {
			return discoveryError(generated.ErrorCodeIntegrityFailure)
		}
		return nil
	})
	return result, err
}

// ApplyTarget requires the current persisted human-authorized execution lease.
// This function never opens a host connection or resolves credentials.
func (r *HostDiscoveryRepository) ApplyTarget(ctx context.Context, request DiscoveryActivation) (string, error) {
	draft, err := r.GetDraft(ctx, request.DraftID)
	if err != nil {
		return "", err
	}
	intent := discoveryIntent(request.Attribution, "host.discovery.target-applied", request.DraftID, hostdiscovery.Digest([]string{request.PlanID, request.StepID}), draft.Digest)
	intent.Context = audit.ContextIDs{PlanID: request.PlanID, RunID: request.RunID}
	_, err = r.store.executeAuditIntent(ctx, intent, false, func(ctx context.Context, tx *sql.Tx) error {
		var planRaw []byte
		var revision, epoch int64
		if err := tx.QueryRowContext(ctx, `SELECT canonical_bytes,state_revision,recovery_epoch FROM immutable_plans WHERE plan_id=? AND plan_digest=?`, request.PlanID, request.PlanDigest).Scan(&planRaw, &revision, &epoch); err != nil {
			return discoveryError(generated.ErrorCodeAuthorizationDenied)
		}
		var plan generated.Plan
		if json.Unmarshal(planRaw, &plan) != nil || plan.AuthorizationBranch != "human" || plan.ExecutorMode != "central" || plan.Risk != "control-plane" || len(plan.Operations) != 1 {
			return discoveryError(generated.ErrorCodeAuthorizationDenied)
		}
		op := plan.Operations[0]
		if op.AdapterID != "core.host-discovery-target" || op.OperationType != "host.discovery-target."+draft.Request.Action || op.TargetID != draft.ID || op.InputDigest != draft.Digest || op.ArtifactDigest != draft.Digest {
			return discoveryError(generated.ErrorCodePlanStale)
		}
		var current RevisionToken
		if err := tx.QueryRowContext(ctx, `SELECT state_revision,recovery_epoch FROM system_meta WHERE id=1`).Scan(&current.StateRevision, &current.RecoveryEpoch); err != nil {
			return err
		}
		if current.StateRevision != revision || current.RecoveryEpoch != epoch || epoch != draft.Request.Target.RecoveryEpoch {
			return discoveryError(generated.ErrorCodePlanStale)
		}
		var count int
		err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM plan_runs r JOIN acknowledgement_requests a ON a.acknowledgement_id=r.acknowledgement_id JOIN plan_run_steps s ON s.run_id=r.run_id JOIN target_execution_leases l ON l.lease_id=s.active_lease_id WHERE r.run_id=? AND r.plan_id=? AND r.plan_digest=? AND r.status='running' AND a.status='approved' AND a.consumed_at IS NOT NULL AND a.plan_digest=? AND s.step_id=? AND s.target_id=? AND s.input_digest=? AND s.artifact_digest=? AND s.effect_state='intent-recorded' AND s.status='running' AND l.lease_id=? AND l.status='active' AND l.run_id=r.run_id AND l.step_id=s.step_id AND l.target_id=s.target_id AND r.executor_mode='central' AND r.recovery_epoch=a.recovery_epoch AND a.recovery_epoch=l.recovery_epoch AND a.plan_id=r.plan_id AND s.adapter_id='core.host-discovery-target' AND l.expires_at>? AND l.recovery_epoch=?`, request.RunID, request.PlanID, request.PlanDigest, request.PlanDigest, request.StepID, draft.ID, draft.Digest, draft.Digest, request.LeaseID, r.store.config.Clock().UTC().Format(time.RFC3339), epoch).Scan(&count)
		if err != nil || count != 1 {
			return discoveryError(generated.ErrorCodeApprovalRequired)
		}
		var latest int64
		if err := tx.QueryRowContext(ctx, `SELECT COALESCE(MAX(revision),0) FROM host_discovery_targets WHERE target_id=?`, draft.Request.Target.TargetID).Scan(&latest); err != nil {
			return err
		}
		if latest != draft.Request.ExpectedTargetRevision {
			return discoveryError(generated.ErrorCodeStateConflict)
		}
		status := "active"
		if draft.Request.Action == "revoke" {
			status = "revoked"
		}
		_, err = tx.ExecContext(ctx, `INSERT INTO host_discovery_targets VALUES(?,?,?,?,?,?)`, draft.Request.Target.TargetID, draft.Request.Target.Revision, draft.ID, status, request.PlanID, epoch)
		return err
	})
	return draft.Digest, err
}
func (r *HostDiscoveryRepository) VerifyTarget(ctx context.Context, draftID, planID, digest string) error {
	return r.store.Read(ctx, func(tx ReadTx) error {
		var count int
		if err := tx.queryRow(ctx, `SELECT COUNT(*) FROM host_discovery_targets t JOIN host_discovery_drafts d ON d.draft_id=t.draft_id WHERE t.draft_id=? AND t.plan_id=? AND d.digest=? AND t.revision=(SELECT MAX(t2.revision) FROM host_discovery_targets t2 WHERE t2.target_id=t.target_id)`, draftID, planID, digest).Scan(&count); err != nil || count != 1 {
			return discoveryError(generated.ErrorCodeStateConflict)
		}
		return nil
	})
}

func discoveryInventoryRead(row discoveryRow, principal string, target generated.HostDiscoveryTarget) error {
	if target.InventoryDraftID == nil {
		return nil
	}
	var count int
	resource := *target.InventoryDraftID + ":" + strconv.FormatInt(target.InventoryDraftRevision, 10)
	if err := row(`SELECT COUNT(*) FROM read_principals p JOIN read_grants g ON g.principal_id=p.principal_id AND g.grant_revision=p.grant_revision WHERE p.principal_id=? AND p.status='active' AND g.status='active' AND g.capability='inventory.draft.read' AND g.resource_kind='inventory-draft' AND g.resource_id=?`, principal, resource).Scan(&count); err != nil || count == 0 {
		return discoveryError(generated.ErrorCodeAuthorizationDenied)
	}
	return nil
}
