package store

import (
	"context"
	"encoding/json"
	"github.com/vegastack/vegastack-labs/internal/generated"
)

// Operator projection of existing intent/receipt history. This is deliberately
// not qualification: native and provider readiness remain common gate blockers.
func readRoleFoundation(ctx context.Context, tx ReadTx, hostID string, epoch int64) (*generated.HostRoleFoundation, error) {
	rows, err := tx.query(ctx, `SELECT p.canonical_bytes,p.readable_plan,s.status,s.effect_state,COALESCE(e.status,'') FROM immutable_plans p JOIN plan_runs r ON r.plan_id=p.plan_id AND r.plan_digest=p.plan_digest JOIN plan_run_steps s ON s.run_id=r.run_id LEFT JOIN execution_receipts e ON e.run_id=s.run_id AND e.step_id=s.step_id AND e.result_digest=s.result_digest WHERE r.recovery_epoch=? AND s.target_id=? AND json_type(p.canonical_bytes,'$.hostRoleScope')='object' AND json_extract(p.canonical_bytes,'$.hostAction.actionId')!='debian.role.collect' ORDER BY p.state_revision DESC,p.plan_id DESC LIMIT 1`, epoch, hostID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	if !rows.Next() {
		return nil, rows.Err()
	}
	var raw []byte
	var readable, status, effect, receipt string
	var p generated.Plan
	if rows.Scan(&raw, &readable, &status, &effect, &receipt) != nil || json.Unmarshal(raw, &p) != nil || !validPlanDigests(p, readable) || p.HostRoleScope == nil || p.HostAction == nil {
		return nil, actionError(generated.ErrorCodeIntegrityFailure)
	}
	rows.Close()
	s := p.HostRoleScope
	out := &generated.HostRoleFoundation{Schema: generated.SchemaIDHostRoleFoundation, SchemaVersion: "1.0.0", RoleID: s.RoleID, RoleBindingDigest: s.RoleBindingDigest, Status: "pending", ServiceState: "not-applicable", Blockers: []string{"native-qualification-pending", "provider-qualification-pending"}}
	if s.RoleID == "control" {
		out.ServiceState = "pending-handoff"
		out.Blockers = append(out.Blockers, "service-handoff-pending")
	}
	if status == "succeeded" && effect == "verified" && receipt == "succeeded" {
		out.Status = "installed"
		if p.HostAction.ActionID == "debian.control.handoff.verify" {
			var n int
			err := tx.queryRow(ctx, `SELECT COUNT(*) FROM host_control_results c JOIN execution_receipts e ON e.receipt_id=c.receipt_id AND e.result_digest=c.result_digest AND e.status='succeeded' WHERE c.plan_id=? AND c.plan_digest=? AND c.host_id=? AND c.recovery_epoch=? AND c.control_id='linux.control-service' AND c.status='passed' AND json_extract(c.measurement_bytes,'$.role.roleBindingDigest')=?`, p.PlanID, p.PlanDigest, hostID, epoch, s.RoleBindingDigest).Scan(&n)
			if err != nil {
				return nil, err
			}
			if n > 0 {
				out.ServiceState = "active"
				out.Blockers = out.Blockers[:2]
			}
		}
	} else if status == "failed" || status == "partial" || effect == "effect-unknown" {
		out.Status = "partial"
		out.Blockers = append(out.Blockers, "role-apply-partial")
		if p.HostAction.ActionID == "debian.control.handoff" || p.HostAction.ActionID == "debian.control.handoff.verify" {
			out.Status = "recovery-required"
			out.ServiceState = "unverified"
		}
	} else {
		out.Blockers = append(out.Blockers, "role-apply-pending")
	}
	return out, nil
}
