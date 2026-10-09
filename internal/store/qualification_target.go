package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"github.com/vegastack/vegastack-labs/internal/debianaccess"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostadoption"
	"github.com/vegastack/vegastack-labs/internal/hostdiscovery"
	"time"
)

// ResolveQualificationTarget reads only current authorized records. It neither
// opens a network connection nor creates a discovery attempt.
func (r *HostDiscoveryRepository) ResolveQualificationTarget(ctx context.Context, in generated.QualificationInspectRequest) (target hostdiscovery.Target, observedIdentityDigest string, err error) {
	raw, _ := json.Marshal(in)
	if generated.ValidateContractJSON(generated.SchemaIDQualificationInspectRequest, raw, generated.ContractExact) != nil || debianaccess.ProtectedName(in.Scope.PhysicalHostID) {
		return target, "", discoveryError(generated.ErrorCodeInputInvalid)
	}
	err = r.store.Read(ctx, func(tx ReadTx) error {
		row := func(q string, a ...any) *sql.Row { return tx.queryRow(ctx, q, a...) }
		principal, grant, e := discoveryGrant(ctx, row, in.TargetID, "host.discovery.collect", true)
		if e != nil {
			return e
		}
		if _, _, e = discoveryGrant(ctx, row, in.TargetID, "host.discovery.read", false); e != nil {
			return e
		}
		target, e = discoveryTarget(row, in.TargetID)
		if e != nil {
			return e
		}
		if e = discoveryInventoryRead(row, principal, target.Binding); e != nil {
			return e
		}
		var current RevisionToken
		if e = row(`SELECT state_revision,recovery_epoch FROM system_meta WHERE id=1`).Scan(&current.StateRevision, &current.RecoveryEpoch); e != nil {
			return e
		}
		if target.Binding.Revision != in.TargetRevision || target.Digest != in.TargetDigest || current.StateRevision != in.ExpectedStateRevision || current.RecoveryEpoch != in.RecoveryEpoch || target.Binding.RecoveryEpoch != in.RecoveryEpoch {
			return discoveryError(generated.ErrorCodePlanStale)
		}
		// A target is active only through the acknowledged activation; additionally
		// require its exact succeeded receipt and verified step before external I/O.
		var count int
		if e = row(`SELECT COUNT(*) FROM host_discovery_targets t JOIN host_discovery_drafts d ON d.draft_id=t.draft_id JOIN immutable_plans p ON p.plan_id=t.plan_id JOIN plan_runs r ON r.plan_id=p.plan_id AND r.plan_digest=p.plan_digest JOIN execution_receipts x ON x.run_id=r.run_id AND x.status='succeeded' JOIN plan_run_steps s ON s.run_id=r.run_id AND s.step_id=x.step_id AND s.status='succeeded' AND s.effect_state='verified' JOIN acknowledgement_requests a ON a.acknowledgement_id=r.acknowledgement_id AND a.plan_id=p.plan_id AND a.plan_digest=p.plan_digest AND a.status='approved' AND a.consumed_at IS NOT NULL WHERE t.target_id=? AND t.revision=? AND d.digest=? AND s.adapter_id='core.host-discovery-target' AND s.target_id=d.draft_id AND s.input_digest=d.digest AND s.artifact_digest=d.digest AND r.recovery_epoch=?`, in.TargetID, in.TargetRevision, in.TargetDigest, in.RecoveryEpoch).Scan(&count); e != nil {
			return e
		}
		if count != 1 {
			return discoveryError(generated.ErrorCodePrerequisiteBlocked)
		}
		var observationID string
		if e = row(`SELECT observation_id FROM host_observations WHERE target_id=? ORDER BY state_revision DESC LIMIT 1`, in.TargetID).Scan(&observationID); e != nil {
			return discoveryError(generated.ErrorCodePrerequisiteBlocked)
		}
		observation, e := readDiscoveryObservation(row, observationID)
		if e != nil {
			return e
		}
		expires, e := time.Parse(time.RFC3339, observation.ExpiresAt)
		if e != nil || !r.store.config.Clock().Before(expires) || observation.TargetRevision != in.TargetRevision || observation.TargetDigest != in.TargetDigest || observation.RecoveryEpoch != in.RecoveryEpoch {
			return discoveryError(generated.ErrorCodePrerequisiteBlocked)
		}
		for _, b := range observation.Blockers {
			if b == "identity-conflict" || b == "inventory-identity-mismatch" || b == "stale-observation" {
				return discoveryError(generated.ErrorCodePrerequisiteBlocked)
			}
		}
		var serial string
		for _, f := range observation.Facts {
			if f.Name == "product-serial" {
				if serial != "" {
					return discoveryError(generated.ErrorCodeIntegrityFailure)
				}
				serial = f.Value
			}
		}
		if serial == "" {
			return discoveryError(generated.ErrorCodePrerequisiteBlocked)
		}
		observedIdentityDigest = hostadoption.IdentityDigest("product-serial", serial)
		if observedIdentityDigest != in.Scope.PhysicalHostIdentityDigest {
			return discoveryError(generated.ErrorCodePrerequisiteBlocked)
		}
		target.GrantRevision = grant
		target.StateRevision = current.StateRevision
		return nil
	})
	if err != nil {
		return hostdiscovery.Target{}, "", err
	}
	return
}
