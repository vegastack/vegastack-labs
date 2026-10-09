package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"time"
)

type HostStoragePrerequisites struct {
	VolumeEvidenceDigests, RecoveryEvidenceDigests []string
	RecoveryEpoch                                  int64
}

func (r *GateRepository) ResolveHostStoragePrerequisites(ctx context.Context, hostID string, volumeIDs []string, at time.Time) (HostStoragePrerequisites, error) {
	out := HostStoragePrerequisites{}
	if r == nil || r.store == nil || hostID == "" || len(volumeIDs) == 0 || len(volumeIDs) > 16 || at.IsZero() {
		return out, actionError(generated.ErrorCodeInputInvalid)
	}
	e := r.store.Read(ctx, func(tx ReadTx) error {
		return resolveHostStoragePrerequisites(ctx, tx, hostID, volumeIDs, at, &out)
	})
	return out, e
}

func resolveHostStoragePrerequisites(ctx context.Context, tx ReadTx, hostID string, volumeIDs []string, at time.Time, out *HostStoragePrerequisites) error {

	row := func(q string, a ...any) *sql.Row { return tx.queryRow(ctx, q, a...) }
	var identity string
	if row(`SELECT identity_digest,recovery_epoch FROM managed_hosts WHERE host_id=?`, hostID).Scan(&identity, &out.RecoveryEpoch) != nil {
		return actionError(generated.ErrorCodePlanStale)
	}
	var current int64
	if row(`SELECT recovery_epoch FROM system_meta WHERE id=1`).Scan(&current) != nil || current != out.RecoveryEpoch {
		return actionError(generated.ErrorCodePlanStale)
	}
	seen := map[string]bool{}
	for _, volume := range volumeIDs {
		if seen[volume] {
			return actionError(generated.ErrorCodeInputInvalid)
		}
		seen[volume] = true
		var bindingDigest, observationReceipt string
		for _, kind := range []string{"encryption", "recovery"} {
			var raw, resultRaw, planRaw, receiptRaw []byte
			var m generated.AccessMeasurement
			var result generated.HostActionResult
			var plan generated.Plan
			var receipt generated.ExecutionReceipt
			if row(`SELECT c.measurement_bytes,c.result_bytes,p.canonical_bytes,e.canonical_bytes FROM host_control_results c JOIN execution_receipts e ON e.receipt_id=c.receipt_id AND e.result_digest=c.result_digest AND e.status='succeeded' JOIN plan_run_steps s ON s.run_id=c.run_id AND s.step_id=c.step_id AND s.status='succeeded' AND s.effect_state='verified' JOIN immutable_plans p ON p.plan_id=c.plan_id AND p.plan_digest=c.plan_digest WHERE c.host_id=? AND c.host_identity_digest=? AND c.recovery_epoch=? AND c.control_id=? ORDER BY c.observed_at DESC,c.rowid DESC LIMIT 1`, hostID, identity, current, "linux.volume-"+kind+":"+volume).Scan(&raw, &resultRaw, &planRaw, &receiptRaw) != nil || json.Unmarshal(raw, &m) != nil || json.Unmarshal(resultRaw, &result) != nil || json.Unmarshal(planRaw, &plan) != nil || json.Unmarshal(receiptRaw, &receipt) != nil {
				return actionError(generated.ErrorCodePrerequisiteBlocked)
			}
			observed, err := time.Parse(time.RFC3339, m.ObservedAt)
			if err != nil || observed.After(at.Add(time.Second)) || at.Sub(observed) > 10*time.Minute || m.Status != "passed" || m.Volume == nil || m.Volume.Binding.VolumeID != volume || m.MeasurementDigest != hostaction.MeasurementDigest(m) || hostaction.ValidateResult(result) != nil || result.ResultDigest != receipt.ResultDigest || validateBaselineCurrent(row, plan, at) != nil {
				return actionError(generated.ErrorCodePrerequisiteBlocked)
			}
			found := false
			for _, v := range result.ControlMeasurements {
				found = found || hostaction.Digest(v) == hostaction.Digest(m)
			}
			if !found {
				return actionError(generated.ErrorCodeIntegrityFailure)
			}
			digest := hostaction.BytesDigest(receiptRaw)
			if kind == "encryption" {
				if m.Volume.Kind != "mapping" {
					return actionError(generated.ErrorCodeIntegrityFailure)
				}
				bindingDigest = hostaction.Digest(m.Volume.Binding)
				observationReceipt = digest
				out.VolumeEvidenceDigests = append(out.VolumeEvidenceDigests, m.MeasurementDigest)
			} else {
				if m.Volume.Kind != "recovery" || hostaction.Digest(m.Volume.Binding) != bindingDigest || m.Volume.PriorVolumeReceiptDigest != observationReceipt {
					return actionError(generated.ErrorCodePrerequisiteBlocked)
				}
				out.RecoveryEvidenceDigests = append(out.RecoveryEvidenceDigests, m.MeasurementDigest)
			}
		}
	}
	return nil

}
