package store

import (
	"encoding/json"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
)

// A recovery point gets its owner only from the stored creation receipt and
// exact canonical policy, never from a restore request's asserted identifier.
func recoveryPointPolicy(row discoveryRow, pointID string) (string, error) {
	var id, digest string
	var raw []byte
	if row(`SELECT p.policy_id,p.policy_digest,d.canonical_json FROM recovery_points p JOIN backup_jobs j ON j.job_id=p.job_id AND j.policy_id=p.policy_id AND j.policy_digest=p.policy_digest JOIN backup_policy_drafts d ON d.policy_id=p.policy_id AND d.policy_digest=p.policy_digest AND d.recovery_epoch=p.recovery_epoch WHERE p.point_id=?`, pointID).Scan(&id, &digest, &raw) != nil || hostaction.BytesDigest(raw) != digest || generated.ValidateContractJSON(generated.SchemaIDBackupPolicy, raw, generated.ContractExact) != nil {
		return "", actionError(generated.ErrorCodeAuthorizationDenied)
	}
	var p generated.BackupPolicy
	if json.Unmarshal(raw, &p) != nil || p.PolicyID != id {
		return "", actionError(generated.ErrorCodeIntegrityFailure)
	}
	return id, nil
}
