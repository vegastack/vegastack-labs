package store

import (
	"context"
	"encoding/json"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/servicerecovery"
)

// GetVerifiedRecovery returns applied isolated-restore evidence for the current
// exact service, policy/configuration and epoch. A profile intent flag cannot
// create this evidence. Any newer uncertain attempt/result invalidates it.
func (r *ServiceRecoveryRepository) GetVerifiedRecovery(ctx context.Context, serviceID, policyID string, epoch int64) (out generated.ServiceRecoveryRecord, err error) {
	current, e := NewServiceRepository(r.store).Get(ctx, serviceID)
	if e != nil {
		return out, e
	}
	policy, e := r.policy(policyID)
	if e != nil {
		return out, e
	}
	if policy.Binding.ServiceID != serviceID {
		return out, actionError(generated.ErrorCodeAuthorizationDenied)
	}
	err = r.store.Read(ctx, func(tx ReadTx) error {
		var stateEpoch int64
		if tx.queryRow(ctx, `SELECT recovery_epoch FROM system_meta WHERE id=1`).Scan(&stateEpoch) != nil || stateEpoch != epoch {
			return actionError(generated.ErrorCodePlanStale)
		}
		var pending int
		if tx.queryRow(ctx, `SELECT COUNT(*) FROM service_recovery_attempts WHERE service_id=? AND status='attempted'`, serviceID).Scan(&pending) != nil || pending != 0 {
			return actionError(generated.ErrorCodeRecoveryRequired)
		}
		var raw []byte
		var digest string
		if tx.queryRow(ctx, `SELECT canonical_bytes,digest FROM service_recoveries WHERE service_id=? ORDER BY revision DESC LIMIT 1`, serviceID).Scan(&raw, &digest) != nil || json.Unmarshal(raw, &out) != nil || servicerecovery.Digest(out) != digest {
			return actionError(generated.ErrorCodePrerequisiteBlocked)
		}
		if out.Status != "succeeded" || out.Request.Action != "isolated-restore" || !out.IsolatedRestoreVerified || out.Request.Binding != policy.Binding || out.Request.Definition != current.Definition || out.Request.RecoveryEpoch != epoch || out.BackupPointID == "" || out.SnapshotID == "" || out.TargetWritersEnabled || out.SourceFenced || !out.SourceResumed {
			return actionError(generated.ErrorCodePrerequisiteBlocked)
		}
		return nil
	})
	return
}

// BackupPoint resolves only the immutable successful point record named by an
// approved request; it does not accept a browser/operator success assertion.
func (r *ServiceRecoveryRepository) BackupPoint(ctx context.Context, q generated.ServiceRecoveryRequest) (out generated.ServiceRecoveryRecord, err error) {
	if q.BackupPointID == "" {
		return out, nil
	}
	err = r.store.Read(ctx, func(tx ReadTx) error {
		var raw []byte
		var digest string
		query := `SELECT canonical_bytes,digest FROM service_recoveries WHERE service_id=? AND policy_id=? AND recovery_epoch=? AND status='succeeded' AND json_extract(canonical_bytes,'$.backupPointId')=? ORDER BY revision DESC LIMIT 1`
		if tx.queryRow(ctx, query, q.Definition.ServiceID, q.Binding.PolicyID, q.RecoveryEpoch, q.BackupPointID).Scan(&raw, &digest) != nil || json.Unmarshal(raw, &out) != nil || servicerecovery.Digest(out) != digest || out.Request.Binding != q.Binding {
			return actionError(generated.ErrorCodePrerequisiteBlocked)
		}
		return nil
	})
	return
}
