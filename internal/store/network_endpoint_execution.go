package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"github.com/vegastack/vegastack-labs/internal/audit"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"github.com/vegastack/vegastack-labs/internal/identity"
	"github.com/vegastack/vegastack-labs/internal/networkconnect"
	"time"
)

type NetworkEndpointApply = GrantBatchApply

func (r *NetworkEndpointRepository) Apply(ctx context.Context, in NetworkEndpointApply) (string, error) {
	if r == nil || r.store == nil {
		return "", actionError(generated.ErrorCodePrerequisiteBlocked)
	}
	p, err := NewPlanRepository(r.store).GetPlan(ctx, in.PlanID)
	if err != nil {
		return "", err
	}
	b := p.Plan.NetworkEndpoint
	if b == nil || networkconnect.ValidateRequest(*b) != nil {
		return "", actionError(generated.ErrorCodeInputInvalid)
	}
	if err = r.store.Read(ctx, func(tx ReadTx) error {
		return validateNetworkEndpointExecution(ctx, func(q string, a ...any) *sql.Row { return tx.queryRow(ctx, q, a...) }, p.Plan, *b, in, r.store.config.Clock().UTC(), r.store.config.NetworkConnectExcludedHostIDs...)
	}); err != nil {
		return "", err
	}
	preimage, before, err := r.store.prepareMutationSnapshot(ctx, p.Plan, in)
	if err != nil {
		return "", err
	}
	digest := hostaction.Digest(b)
	event := audit.EventDraft{Type: "network.endpoint-applied", CorrelationID: in.RunID, Attribution: in.Attribution, Target: audit.Target{Kind: "host", ID: b.Endpoint.HostID}, Before: (*audit.Fingerprint)(&before), After: (*audit.Fingerprint)(&digest)}
	expected := RevisionToken{StateRevision: p.Plan.Binding.StateRevision, RecoveryEpoch: p.Plan.Binding.RecoveryEpoch}
	_, err = r.store.writeIntent(ctx, intentRequest{Expected: &expected, Idempotency: audit.IntentKey{Scope: "network-endpoint", KeyDigest: digestParts("network-endpoint", in.RunID, in.StepID, in.LeaseID), RequestDigest: audit.Fingerprint(hostaction.Digest(in))}, Event: event}, func(ctx context.Context, tx *sql.Tx) error {
		row := func(q string, a ...any) *sql.Row { return tx.QueryRowContext(ctx, q, a...) }
		if err := validateNetworkEndpointExecution(ctx, row, p.Plan, *b, in, r.store.config.Clock().UTC(), r.store.config.NetworkConnectExcludedHostIDs...); err != nil {
			return err
		}
		if err := r.store.verifyMutationPreimage(ctx, preimage, before); err != nil {
			return err
		}
		raw, _ := json.Marshal(b)
		_, err := tx.ExecContext(ctx, `INSERT INTO network_endpoint_revisions VALUES(?,?,?,?,?,?)`, b.Endpoint.HostID, b.Endpoint.Revision, raw, digest, in.PlanID, in.RunID)
		return err
	})
	return digest, err
}
func (r *NetworkEndpointRepository) Verify(ctx context.Context, planID, runID, digest string) error {
	return r.store.Read(ctx, func(tx ReadTx) error {
		var n int
		if tx.queryRow(ctx, `SELECT COUNT(*) FROM network_endpoint_revisions e JOIN audit_events a ON a.correlation_id=e.run_id AND a.event_type='network.endpoint-applied' WHERE e.plan_id=? AND e.run_id=? AND e.digest=? AND a.after_fingerprint=e.digest`, planID, runID, digest).Scan(&n) != nil || n != 1 {
			return actionError(generated.ErrorCodeIntegrityFailure)
		}
		return nil
	})
}
func validateNetworkEndpointExecution(ctx context.Context, row discoveryRow, p generated.Plan, b generated.NetworkEndpointRequest, in NetworkEndpointApply, now time.Time, excluded ...string) error {
	deny := func() error { return actionError(generated.ErrorCodeAuthorizationDenied) }
	if p.AuthorizationBranch != "human" || p.ExecutorMode != "central" || p.Risk != "control-plane" || len(p.Operations) != 1 || p.PlanID != in.PlanID || p.PlanDigest != in.PlanDigest || hostaction.Digest(p.NetworkEndpoint) != hostaction.Digest(b) {
		return deny()
	}
	expires, err := time.Parse(time.RFC3339, p.ExpiresAt)
	if err != nil || !now.Before(expires) {
		return actionError(generated.ErrorCodePlanStale)
	}
	op := p.Operations[0]
	if op.OperationID != "network-endpoint" || op.OperationType != networkconnect.Operation || op.AdapterID != networkconnect.AdapterID || op.TargetID != b.Endpoint.HostID || op.InputDigest != hostaction.Digest(b) || op.ArtifactDigest != hostaction.Digest(b) {
		return deny()
	}
	var raw []byte
	var reason string
	var d generated.DeclarationRevision
	if row(`SELECT canonical_bytes,reason_digest FROM declaration_revisions WHERE declaration_id=? AND declaration_revision=?`, p.DeclarationID, p.Binding.DeclarationRevision).Scan(&raw, &reason) != nil || !decodeStoredDeclaration(raw, reason, &d) || !ValidateNetworkEndpointDeclaration(d) || hostaction.Digest(d.NetworkEndpoint) != hostaction.Digest(b) {
		return deny()
	}
	var original generated.DeclarationRevision
	if row(`SELECT canonical_bytes,reason_digest FROM declaration_revisions WHERE declaration_id=? AND declaration_revision=?`, p.DeclarationID, b.ExpectedDeclarationRevision+1).Scan(&raw, &reason) != nil || !decodeStoredDeclaration(raw, reason, &original) || original.Status != "draft" || !ValidateNetworkEndpointDeclaration(original) || hostaction.Digest(original.NetworkEndpoint) != hostaction.Digest(b) {
		return deny()
	}
	var human, kind string

	if row(`SELECT a.human_id FROM plan_runs r JOIN acknowledgement_requests a ON a.acknowledgement_id=r.acknowledgement_id JOIN plan_run_steps s ON s.run_id=r.run_id JOIN target_execution_leases l ON l.lease_id=s.active_lease_id WHERE r.run_id=? AND r.plan_id=? AND r.plan_digest=? AND r.status='running' AND r.cancellation_requested=0 AND r.executor_mode='central' AND a.plan_id=r.plan_id AND a.plan_digest=r.plan_digest AND a.status='approved' AND a.consumed_at IS NOT NULL AND a.recovery_epoch=r.recovery_epoch AND s.step_id=? AND s.operation_id=? AND s.operation_type=? AND s.adapter_id=? AND s.target_id=? AND s.input_digest=? AND s.artifact_digest=? AND s.status='running' AND s.effect_state='intent-recorded' AND l.lease_id=? AND l.status='active' AND l.run_id=r.run_id AND l.step_id=s.step_id AND l.target_id=s.target_id AND l.recovery_epoch=r.recovery_epoch AND l.recovery_epoch=? AND l.expires_at>?`, in.RunID, in.PlanID, in.PlanDigest, in.StepID, op.OperationID, op.OperationType, op.AdapterID, op.TargetID, op.InputDigest, op.ArtifactDigest, in.LeaseID, p.Binding.RecoveryEpoch, now.Format(time.RFC3339)).Scan(&human) != nil {
		return actionError(generated.ErrorCodeApprovalRequired)
	}
	if in.Attribution.ResponsibleHumanPrincipalID == nil || *in.Attribution.ResponsibleHumanPrincipalID != human {
		return deny()
	}
	if row(`SELECT p.principal_kind FROM effective_authorization_principals p JOIN audit_events a ON a.principal_id=p.principal_id WHERE p.principal_id=? AND p.status='active' AND a.event_type='run.created' AND a.correlation_id=? AND a.principal_method=?`, in.Attribution.AuthenticatedPrincipalID, in.RunID, in.Attribution.AuthenticatedPrincipalMethod).Scan(&kind) != nil {
		return deny()
	}
	actor := identity.Principal{ID: in.Attribution.AuthenticatedPrincipalID, Method: in.Attribution.AuthenticatedPrincipalMethod, Kind: identity.PrincipalKind(kind)}
	if !identity.ValidPrincipal(actor) || (actor.Kind == identity.PrincipalAgent && in.Attribution.Agent == nil) {
		return deny()
	}
	if _, err := adoptionPrincipalGrant(actor, row, b.Endpoint.HostID, "host", "author", "network.endpoint.write", true); err != nil {
		return err
	}
	if _, err := adoptionPrincipalGrant(actor, row, b.Endpoint.HostID, "execution-target", "execute", networkconnect.Operation, true); err != nil {
		return err
	}
	var count int
	if row(`SELECT COUNT(*) FROM effective_authorization_principals p JOIN effective_authorization_grants g ON g.principal_id=p.principal_id AND g.grant_revision=p.grant_revision WHERE p.principal_id=? AND p.principal_kind='human' AND p.status='active' AND g.status='active' AND g.role_id IN ('control-plane-admin','infrastructure-admin') AND g.action='acknowledge' AND g.branch='human' AND g.capability='plan.acknowledge' AND g.resource_kind='plan-target' AND g.resource_id=?`, human, b.Endpoint.HostID).Scan(&count) != nil || count == 0 {
		return deny()
	}
	return validateNetworkEndpointState(identity.WithVerifiedPrincipal(ctx, actor), row, b, excluded...)
}
