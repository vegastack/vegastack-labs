package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"github.com/vegastack/vegastack-labs/internal/debianaccess"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"time"
)

// AccessVerificationEvidence is reconstructed from current immutable plan and
// actual completed receipt-backed rows; no caller supplies probe success.
func (r *HostActionRepository) AccessVerificationEvidence(ctx context.Context, x HostActionExecution) (*generated.AccessVerificationEvidence, error) {
	if x.Plan.HostAccessSequence == nil || x.Draft.Request.ActionID != "debian.access.confirm" {
		return nil, actionError(generated.ErrorCodeAuthorizationDenied)
	}
	var result *generated.AccessVerificationEvidence
	e := r.store.Read(ctx, func(tx ReadTx) error {
		row := func(q string, args ...any) *sql.Row { return tx.queryRow(ctx, q, args...) }
		if e := validateAccessCurrentTargets(row, x.Plan, r.store.config.Clock()); e != nil {
			return e
		}
		seq := *x.Plan.HostAccessSequence
		var receiptRaw []byte
		var started string
		if row(`SELECT e.canonical_bytes,s.started_at FROM execution_receipts e JOIN plan_run_steps s ON s.run_id=e.run_id AND s.step_id=e.step_id WHERE e.run_id=? AND s.operation_id=? AND e.status='succeeded' AND s.status='succeeded' AND s.effect_state='verified'`, x.Run.RunID, seq.ApplyOperationID).Scan(&receiptRaw, &started) != nil {
			return actionError(generated.ErrorCodePrerequisiteBlocked)
		}
		at, e := time.Parse(time.RFC3339, started)
		if e != nil {
			return actionError(generated.ErrorCodeIntegrityFailure)
		}
		deadline := at.Add(600 * time.Second)
		if !r.store.config.Clock().Add(2 * time.Second).Before(deadline) {
			return actionError(generated.ErrorCodePlanStale)
		}
		apply, e := readHostActionDraft(row, accessDraftID(seq.ApplyDraftDigest))
		if e != nil {
			return e
		}
		desired, e := debianaccess.DecodeInput([]byte(apply.Request.ActionInput))
		if e != nil {
			return e
		}
		containerAbsentAllowed := len(desired.ContainerFlows) == 0
		for _, request := range seq.Actions {
			if request.ActionID == "debian.access.probe.local" || request.ActionID == "debian.access.probe-source" {
				var probe generated.AccessProbeInput
				if json.Unmarshal([]byte(request.ActionInput), &probe) != nil {
					return actionError(generated.ErrorCodeIntegrityFailure)
				}
				for _, c := range probe.Cases {
					if c.Kind == "container-published" || c.Kind == "container-unpublished" || c.Kind == "container-east-west" {
						containerAbsentAllowed = false
					}
				}
			}
		}
		recordDigest := ""
		digests := []string{}
		operationIDs := []string{seq.ApplyOperationID}
		for _, p := range seq.ProbeSteps {
			operationIDs = append(operationIDs, p.OperationID)
		}
		for i, id := range operationIDs {
			rows, e := tx.query(ctx, `SELECT c.measurement_bytes,c.receipt_digest,c.result_digest FROM host_control_results c JOIN plan_run_steps s ON s.run_id=c.run_id AND s.step_id=c.step_id JOIN execution_receipts e ON e.receipt_id=c.receipt_id WHERE c.run_id=? AND c.operation_id=? AND c.plan_digest=? AND c.sequence_digest=? AND c.recovery_epoch=? AND s.status='succeeded' AND s.effect_state='verified' AND e.status='succeeded' AND e.result_digest=c.result_digest ORDER BY c.ordinal`, x.Run.RunID, id, x.Plan.PlanDigest, hostaction.Digest(seq), x.Plan.Binding.RecoveryEpoch)
			if e != nil {
				return e
			}
			count := 0
			for rows.Next() {
				var raw []byte
				var receiptDigest, resultDigest string
				var m generated.AccessMeasurement
				if rows.Scan(&raw, &receiptDigest, &resultDigest) != nil || json.Unmarshal(raw, &m) != nil || m.MeasurementDigest != hostaction.MeasurementDigest(m) {
					rows.Close()
					return actionError(generated.ErrorCodeIntegrityFailure)
				}
				count++
				if i == 0 {
					if receiptDigest != hostaction.BytesDigest(receiptRaw) {
						rows.Close()
						return actionError(generated.ErrorCodeIntegrityFailure)
					}
					if m.RollbackRecordDigest != "" {
						if recordDigest != "" && recordDigest != m.RollbackRecordDigest {
							rows.Close()
							return actionError(generated.ErrorCodeIntegrityFailure)
						}
						recordDigest = m.RollbackRecordDigest
					}
				} else {
					observed, e := time.Parse(time.RFC3339Nano, m.ObservedAt)
					if e != nil || observed.Before(at) || (m.Status != "passed" && !(containerAbsentAllowed && m.ControlID == "debian.container-firewall" && m.Status == "partial" && m.Reason == "container-not-installed")) {
						rows.Close()
						return actionError(generated.ErrorCodePrerequisiteBlocked)
					}
				}
				digests = append(digests, hostaction.Digest([]string{id, m.MeasurementDigest, receiptDigest, resultDigest}))
			}
			e = rows.Err()
			rows.Close()
			if e != nil {
				return e
			}
			if count == 0 {
				return actionError(generated.ErrorCodePrerequisiteBlocked)
			}
		}
		if recordDigest == "" {
			return actionError(generated.ErrorCodePrerequisiteBlocked)
		}
		result = &generated.AccessVerificationEvidence{Schema: generated.SchemaIDAccessVerificationEvidence, SchemaVersion: "1.0.0", ApplyReceiptDigest: hostaction.BytesDigest(receiptRaw), RollbackRecordDigest: recordDigest, ProbeResultsDigest: hostaction.Digest(digests), SequenceDigest: seq.SpecificationDigest, ExpiresAt: deadline.UTC().Format(time.RFC3339)}
		return nil
	})
	return result, e
}
