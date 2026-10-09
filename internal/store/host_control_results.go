package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"github.com/vegastack/vegastack-labs/internal/adapter"
	transport "github.com/vegastack/vegastack-labs/internal/adapter/hostaction"
	"github.com/vegastack/vegastack-labs/internal/audit"
	"github.com/vegastack/vegastack-labs/internal/debianaccess"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"time"
)

type HostControlResultsRequest struct {
	Operation   adapter.Operation
	Binding     adapter.ExactExecutionBinding
	Effect      adapter.Effect
	Result      generated.HostActionResult
	Attribution audit.Attribution
}

func (s *Store) HostAccessRunAttribution(ctx context.Context, runID string) (audit.Attribution, error) {
	var a audit.Attribution
	e := s.Read(ctx, func(tx ReadTx) error {
		var human, name, session sql.NullString
		e := tx.queryRow(ctx, `SELECT principal_id,principal_method,responsible_human_principal_id,agent_name,agent_session_id FROM audit_events WHERE event_type='run.created' AND correlation_id=? ORDER BY event_id LIMIT 1`, runID).Scan(&a.AuthenticatedPrincipalID, &a.AuthenticatedPrincipalMethod, &human, &name, &session)
		if e != nil {
			return e
		}
		if human.Valid {
			a.ResponsibleHumanPrincipalID = &human.String
		}
		if name.Valid && session.Valid {
			a.Agent = &audit.AgentMetadata{Name: name.String, SessionID: session.String}
		}
		return nil
	})
	return a, e
}
func (s *Store) RecordHostControlResults(ctx context.Context, q HostControlResultsRequest) error {
	if s == nil || hostaction.ValidateResult(q.Result) != nil || len(q.Result.ControlMeasurements) == 0 || q.Result.ResultDigest != hostaction.ResultDigest(q.Result) || q.Effect.ResultDigest != q.Result.ResultDigest || q.Effect.Status != q.Result.Status || q.Effect.Changed != q.Result.Changed || q.Effect.EffectObserved != q.Result.EffectObserved {
		return actionError(generated.ErrorCodeIntegrityFailure)
	}
	a, e := s.HostAccessRunAttribution(ctx, q.Binding.RunID)
	if e != nil || hostaction.Digest(a) != hostaction.Digest(q.Attribution) {
		return actionError(generated.ErrorCodeAuthorizationDenied)
	}
	intent := discoveryIntent(a, "host.control.measured", q.Binding.StepID, hostaction.Digest([]string{q.Binding.RunID, q.Binding.StepID, q.Result.ResultDigest}), hostaction.Digest(q.Result))
	intent.Expected = &RevisionToken{StateRevision: q.Binding.StateRevision, RecoveryEpoch: q.Binding.RecoveryEpoch}
	_, e = s.executeAuditIntent(ctx, intent, false, func(ctx context.Context, tx *sql.Tx) error {
		row := func(query string, args ...any) *sql.Row { return tx.QueryRowContext(ctx, query, args...) }
		var raw, receiptRaw, leaseRaw []byte
		if row(`SELECT p.canonical_bytes FROM immutable_plans p JOIN plan_runs r ON r.plan_id=p.plan_id AND r.plan_digest=p.plan_digest JOIN acknowledgement_requests a ON a.acknowledgement_id=r.acknowledgement_id WHERE r.run_id=? AND r.status='running' AND r.cancellation_requested=0 AND a.status='approved' AND a.consumed_at IS NOT NULL AND a.recovery_epoch=r.recovery_epoch`, q.Binding.RunID).Scan(&raw) != nil {
			return actionError(generated.ErrorCodeApprovalRequired)
		}
		var p generated.Plan
		if json.Unmarshal(raw, &p) != nil || p.PlanID != q.Binding.PlanID || p.PlanDigest != q.Binding.PlanDigest || (p.HostBaselineScope == nil && p.HostAccessSequence == nil && (p.HostAction == nil || p.HostAction.ActionID != "debian.access.collect")) || p.Binding.StateRevision != q.Binding.StateRevision || p.Binding.RecoveryEpoch != q.Binding.RecoveryEpoch {
			return actionError(generated.ErrorCodePlanStale)
		}
		d, op, e := actionDraftForPlan(row, p, q.Operation.OperationID)
		if e != nil {
			return e
		}
		o := q.Operation
		if op.OperationID != o.OperationID || op.OperationType != o.OperationType || op.AdapterID != o.AdapterID || op.ExecutorID != o.ExecutorID || op.TargetID != o.TargetID || op.InputDigest != o.InputDigest || op.ArtifactDigest != o.ArtifactDigest || op.Idempotent != o.Idempotent {
			return actionError(generated.ErrorCodeIntegrityFailure)
		}
		if row(`SELECT e.canonical_bytes,l.canonical_bytes FROM execution_receipts e JOIN target_execution_leases l ON l.lease_id=e.lease_id JOIN plan_run_steps s ON s.run_id=e.run_id AND s.step_id=e.step_id WHERE e.run_id=? AND e.step_id=? AND e.lease_id=? AND s.active_lease_id=l.lease_id AND s.status='running' AND s.effect_state='receipt-recorded' AND s.result_digest=e.result_digest AND l.status='active'`, q.Binding.RunID, q.Binding.StepID, q.Binding.LeaseID).Scan(&receiptRaw, &leaseRaw) != nil {
			return actionError(generated.ErrorCodePrerequisiteBlocked)
		}
		var receipt generated.ExecutionReceipt
		var lease generated.ExecutorLease
		if json.Unmarshal(receiptRaw, &receipt) != nil || json.Unmarshal(leaseRaw, &lease) != nil || generated.ValidateExecutionReceiptBinding(lease, receipt) != nil || receipt.ResultDigest != q.Result.ResultDigest || receipt.Status != q.Result.Status || receipt.OperationID != o.OperationID || receipt.TargetID != o.TargetID || receipt.ArtifactDigest != o.ArtifactDigest || receipt.PlanDigest != p.PlanDigest || receipt.RecoveryEpoch != q.Binding.RecoveryEpoch || lease.MaximumExpiresAt != q.Binding.MaximumExpiresAt {
			return actionError(generated.ErrorCodeIntegrityFailure)
		}
		deadline, e := time.Parse(time.RFC3339, lease.LeaseExpiresAt)
		if e != nil || !s.config.Clock().Before(deadline) {
			return actionError(generated.ErrorCodePlanStale)
		}
		if e = validateAccessCurrentTargets(row, p, s.config.Clock()); e != nil {
			return e
		}
		apply := d
		sequenceDigest := hostaction.Digest(d.Request)
		if p.HostAccessSequence != nil {
			apply, e = readHostActionDraft(row, accessDraftID(p.HostAccessSequence.ApplyDraftDigest))
			if e != nil {
				return e
			}
			sequenceDigest = hostaction.Digest(*p.HostAccessSequence)
		}
		input, e := debianaccess.DecodeInput([]byte(apply.Request.ActionInput))
		if p.HostBaselineScope != nil {
			input, e = baselineProjection(p)
			if len(q.Result.ControlMeasurements) != len(p.HostBaselineScope.ControlIDs) {
				return actionError(generated.ErrorCodeIntegrityFailure)
			}
		}
		if e != nil {
			return actionError(generated.ErrorCodeIntegrityFailure)
		}
		var probe *generated.AccessProbeInput
		if d.Request.ActionID == "debian.access.probe.local" || d.Request.ActionID == "debian.access.probe-source" {
			var value generated.AccessProbeInput
			if json.Unmarshal([]byte(d.Request.ActionInput), &value) != nil {
				return actionError(generated.ErrorCodeIntegrityFailure)
			}
			probe = &value
			if len(value.Cases) != len(q.Result.ControlMeasurements) {
				return actionError(generated.ErrorCodeIntegrityFailure)
			}
			if o.OperationType == debianaccess.LocalProbeOperation && q.Result.BundleDigest != transport.LocalProbeResultBinding(o, q.Binding, value) {
				return actionError(generated.ErrorCodeIntegrityFailure)
			}
		}
		identityClass := ""
		if row(`SELECT identity_class FROM managed_hosts WHERE host_id=?`, input.HostID).Scan(&identityClass) != nil {
			return actionError(generated.ErrorCodePlanStale)
		}
		resultBytes, _ := json.Marshal(q.Result)
		for ordinal, m := range q.Result.ControlMeasurements {
			observed, e := time.Parse(time.RFC3339Nano, m.ObservedAt)
			if e != nil || observed.After(s.config.Clock().Add(time.Second)) || s.config.Clock().Sub(observed) > 10*time.Minute || m.SubjectHostID != input.HostID || m.SubjectIdentityDigest != input.HostIdentityDigest || m.ProfileLockDigest != input.ProfileLockDigest {
				return actionError(generated.ErrorCodePlanStale)
			}
			if p.HostBaselineScope != nil {
				if e = validateBaselineMeasurement(p, m, ordinal); e != nil {
					return e
				}
			}
			if probe != nil {
				if e = validateAccessProbeMeasurement(*probe, m, ordinal); e != nil {
					return e
				}
			}
			control := generated.HostControlResult{Schema: generated.SchemaIDHostControlResult, SchemaVersion: "1.0.0", HostID: input.HostID, IdentityDigest: input.HostIdentityDigest, IdentityClass: identityClass, ProfileID: input.ProfileID, OSFamily: input.ProfileLock.OSFamily, OSVersion: input.ProfileLock.OSVersion, Architecture: input.ProfileLock.Architecture, RoleID: "host", BaselineVersion: input.ActionVersion, ControlID: m.ControlID, ProducerID: m.ProducerID, ProducerVersion: m.ProducerVersion, ActionReceiptDigest: hostaction.BytesDigest(receiptRaw), DeclarationID: p.DeclarationID, DeclarationRevision: p.Binding.DeclarationRevision, RecoveryEpoch: p.Binding.RecoveryEpoch, ObservedAt: m.ObservedAt, Status: m.Status, MeasurementDigest: m.MeasurementDigest, PositiveProbeDigest: m.PositiveProbeDigest, NegativeProbeDigest: m.NegativeProbeDigest}
			if p.HostBaselineScope != nil {
				control.RoleID = p.HostBaselineScope.RoleID
			}
			controlBytes, _ := json.Marshal(control)
			measurementBytes, _ := json.Marshal(m)
			if len(controlBytes) > 16384 || generated.ValidateContractJSON(generated.SchemaIDHostControlResult, controlBytes, generated.ContractExact) != nil {
				return actionError(generated.ErrorCodeIntegrityFailure)
			}
			_, e = tx.ExecContext(ctx, `INSERT INTO host_control_results VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(run_id,step_id,result_digest,ordinal) DO NOTHING`, q.Binding.RunID, q.Binding.StepID, q.Result.ResultDigest, ordinal, p.PlanID, p.PlanDigest, sequenceDigest, o.OperationID, o.TargetID, input.HostID, input.HostIdentityDigest, p.Binding.RecoveryEpoch, receipt.ReceiptID, hostaction.BytesDigest(receiptRaw), m.ControlID, m.Status, m.ObservedAt, m.MeasurementDigest, measurementBytes, controlBytes, resultBytes)
			if e != nil {
				return e
			}
		}
		return nil
	})
	return e
}
func validateAccessCurrentTargets(row discoveryRow, p generated.Plan, now time.Time) error {
	if p.HostBaselineScope != nil {
		return validateBaselineCurrent(row, p, now)
	}
	if p.HostAccessSequence == nil {
		if p.HostAction == nil || p.HostAction.ActionID != "debian.access.collect" {
			return actionError(generated.ErrorCodeIntegrityFailure)
		}
		_, e := actionTarget(row, *p.HostAction)
		return e
	}
	for _, request := range p.HostAccessSequence.Actions {
		if request.ActionID == "debian.access.probe.local" || request.ActionID == "debian.access.probe-source" {
			var probe generated.AccessProbeInput
			if json.Unmarshal([]byte(request.ActionInput), &probe) != nil {
				return actionError(generated.ErrorCodeIntegrityFailure)
			}
			subject, e := readManagedHost(row, probe.SubjectHostID)
			if e != nil {
				return e
			}
			current, e := discoveryTarget(row, subject.TargetID)
			if e != nil || current.Binding.HostKey != probe.SubjectHostKey {
				return actionError(generated.ErrorCodePlanStale)
			}
			for _, c := range probe.Cases {
				for _, tuple := range []generated.AccessProbeTuple{c.Destination, c.Witness} {
					if e := validateAccessTuple(row, tuple, p.Binding.RecoveryEpoch, now); e != nil {
						return e
					}
				}
			}
		}

		if _, e := actionTarget(row, request); e != nil {
			return e
		}
	}
	for _, target := range p.HostAccessSequence.AuxiliaryTargets {
		var digest string
		var epoch int64
		if debianaccess.ProtectedName(target.HostID) || row(`SELECT identity_digest,recovery_epoch FROM managed_hosts WHERE host_id=?`, target.HostID).Scan(&digest, &epoch) != nil || digest != target.IdentityDigest || epoch != p.Binding.RecoveryEpoch {
			return actionError(generated.ErrorCodePlanStale)
		}
	}
	return nil
}
func validateAccessProbeMeasurement(p generated.AccessProbeInput, m generated.AccessMeasurement, ordinal int) error {
	if ordinal >= len(p.Cases) || m.Probe == nil {
		return actionError(generated.ErrorCodeIntegrityFailure)
	}
	c := p.Cases[ordinal]
	v := m.Probe
	if v.ProbeID != c.ProbeID || v.SourceHostID != p.Source.HostID || v.SourceIdentityDigest != p.Source.IdentityDigest || v.SourceContextDigest != p.Source.ContextDigest || v.Expected != c.Expected || v.DestinationDigest != hostaction.Digest(c.Destination) || v.ActualSourceAddress != p.Source.Address || m.Status == "passed" && v.Actual != v.Expected {
		return actionError(generated.ErrorCodeIntegrityFailure)
	}
	return nil
}
func (r *GateRepository) ReadHostControlResults(ctx context.Context, hostID string) ([]generated.HostControlResult, error) {
	out := []generated.HostControlResult{}
	if r == nil || r.store == nil {
		return out, actionError(generated.ErrorCodeInputInvalid)
	}
	e := r.store.Read(ctx, func(tx ReadTx) error {
		rows, e := tx.query(ctx, `SELECT c.control_bytes,p.canonical_bytes FROM host_control_results c JOIN immutable_plans p ON p.plan_id=c.plan_id AND p.plan_digest=c.plan_digest JOIN execution_receipts e ON e.receipt_id=c.receipt_id AND e.result_digest=c.result_digest AND e.status='succeeded' JOIN plan_run_steps s ON s.run_id=c.run_id AND s.step_id=c.step_id AND s.status='succeeded' AND s.effect_state='verified' JOIN system_meta m ON m.id=1 AND m.recovery_epoch=c.recovery_epoch JOIN managed_hosts h ON h.host_id=c.host_id AND h.identity_digest=c.host_identity_digest WHERE c.host_id=? ORDER BY c.control_id,c.observed_at DESC,c.rowid DESC`, hostID)
		if e != nil {
			return e
		}
		defer rows.Close()
		seen := map[string]bool{}
		for rows.Next() {
			var raw, planRaw []byte
			var p generated.Plan
			var value generated.HostControlResult
			if rows.Scan(&raw, &planRaw) != nil || json.Unmarshal(planRaw, &p) != nil || json.Unmarshal(raw, &value) != nil || generated.ValidateContractJSON(generated.SchemaIDHostControlResult, raw, generated.ContractExact) != nil {
				return actionError(generated.ErrorCodeIntegrityFailure)
			}
			if seen[value.ControlID] {
				continue
			}
			seen[value.ControlID] = true
			if p.HostBaselineScope != nil && validateBaselineCurrent(func(q string, a ...any) *sql.Row { return tx.queryRow(ctx, q, a...) }, p, r.store.config.Clock()) != nil {
				continue
			}
			out = append(out, value)
		}
		return rows.Err()
	})
	return out, e
}
