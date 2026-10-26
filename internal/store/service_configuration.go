package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"github.com/vegastack/vegastack-labs/internal/audit"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/servicecatalog"
	"net/url"
	"strconv"
	"time"
)

// RecordCapacity accepts only in-process, identity-checked SSH observations.
// There is deliberately no API accepting this evidence from an operator.
func (r *DeploymentRepository) RecordCapacity(ctx context.Context, serviceID string, c generated.ServiceCapacity) error {
	actor, e := serviceActor(ctx)
	if e != nil {
		return e
	}
	record, e := NewServiceRepository(r.store).Get(ctx, serviceID)
	if e != nil {
		return e
	}
	if e = servicecatalog.ValidateCapacity(c, record.Definition.HostID, record.Definition.HostIdentityDigest, c.TargetDigest, c.RecoveryEpoch, r.store.config.Clock().UTC()); e != nil {
		return e
	}
	attribution, e := audit.NewAttribution(actor, nil, nil)
	if e != nil {
		return e
	}
	raw, e := json.Marshal(c)
	if e != nil {
		return e
	}
	digest := servicecatalog.Digest(c)
	_, e = r.store.executeAuditIntent(ctx, intentRequest{Idempotency: audit.IntentKey{Scope: "service-capacity-observation", KeyDigest: audit.Fingerprint(digest), RequestDigest: audit.Fingerprint(digest)}, Event: audit.EventDraft{Type: "service.capacity-observed", CorrelationID: serviceID, Attribution: attribution, Target: audit.Target{Kind: "service", ID: serviceID}, After: (*audit.Fingerprint)(&digest)}}, false, func(ctx context.Context, tx *sql.Tx) error {
		row := func(q string, a ...any) *sql.Row { return tx.QueryRowContext(ctx, q, a...) }
		if e := NewServiceRepository(r.store).authorize(actor, row, record.Definition, "read", "service.read"); e != nil {
			return e
		}
		var epoch int64
		if row(`SELECT recovery_epoch FROM system_meta WHERE id=1`).Scan(&epoch) != nil || epoch != c.RecoveryEpoch {
			return actionError(generated.ErrorCodePlanStale)
		}
		_, e := tx.ExecContext(ctx, `INSERT INTO service_capacity_observations(digest,service_id,host_id,canonical_bytes,recovery_epoch) VALUES(?,?,?,?,?)`, digest, serviceID, c.HostID, raw, c.RecoveryEpoch)
		return e
	})
	return e
}

func (r *DeploymentRepository) validateConfiguration(row discoveryRow, in generated.ServiceDeploymentRequest, at time.Time) error {
	if in.Configuration == nil {
		if in.Capacity != nil {
			return actionError(generated.ErrorCodeInputInvalid)
		}
		return nil
	}
	if servicecatalog.ValidateConfiguration(*in.Configuration) != nil || in.Capacity == nil {
		return actionError(generated.ErrorCodePrerequisiteBlocked)
	}
	if (in.Configuration.DataClass == "stateless" && in.Binding.DataPolicy != "" && in.Binding.DataPolicy != "stateless") || (in.Configuration.DataClass == "stateful" && in.Binding.DataPolicy != "" && ((in.Configuration.Migration == "backward-compatible" && in.Binding.DataPolicy != "compatible") || (in.Configuration.Migration == "irreversible" && in.Binding.DataPolicy != "irreversible"))) {
		return actionError(generated.ErrorCodeInputInvalid)
	}
	c := *in.Capacity
	if servicecatalog.ValidateCapacity(c, in.Definition.HostID, in.Definition.HostIdentityDigest, c.TargetDigest, in.RecoveryEpoch, at) != nil {
		return actionError(generated.ErrorCodePlanStale)
	}
	var raw []byte
	if row(`SELECT canonical_bytes FROM service_capacity_observations WHERE digest=? AND service_id=? AND host_id=? AND recovery_epoch=?`, servicecatalog.Digest(c), in.Definition.ServiceID, c.HostID, c.RecoveryEpoch).Scan(&raw) != nil || string(raw) != string(mustConfigurationJSON(c)) {
		return actionError(generated.ErrorCodeEvidenceInvalid)
	}
	var targetID string
	if row(`SELECT target_id FROM managed_hosts WHERE host_id=? AND identity_digest=? AND recovery_epoch=?`, c.HostID, c.HostIdentityDigest, c.RecoveryEpoch).Scan(&targetID) != nil {
		return actionError(generated.ErrorCodePlanStale)
	}
	target, e := discoveryTarget(row, targetID)
	if e != nil || target.Digest != c.TargetDigest {
		return actionError(generated.ErrorCodePlanStale)
	}
	if in.Configuration.Exposure == "public" {
		if e := validateServiceExposure(row, in, target.Binding.Address, at); e != nil {
			return e
		}
	}

	if in.Action == "rollback" && in.Configuration.Rollback != "previous-artifact" {
		return actionError(generated.ErrorCodePrerequisiteBlocked)
	}
	return checkServiceCapacity(row, in)
}
func mustConfigurationJSON(v any) []byte { b, _ := json.Marshal(v); return b }
func checkServiceCapacity(row discoveryRow, in generated.ServiceDeploymentRequest) error {
	if in.Configuration == nil {
		return nil
	}
	if in.Capacity == nil {
		return actionError(generated.ErrorCodePrerequisiteBlocked)
	}
	var cpu, memory, storage int64
	if row(`SELECT COALESCE(SUM(cpu_percent),0),COALESCE(SUM(memory_bytes),0),COALESCE(SUM(storage_bytes),0) FROM service_capacity_reservations WHERE host_id=? AND service_id!=?`, in.Definition.HostID, in.Definition.ServiceID).Scan(&cpu, &memory, &storage) != nil {
		return actionError(generated.ErrorCodeDependencyUnavailable)
	}
	c, r := in.Capacity, in.Configuration
	if cpu > c.CPUQuotaPercent || memory > c.MemoryBytes || storage > c.StorageBytes || r.CPUQuotaPercent > c.CPUQuotaPercent-cpu || r.MemoryBytes > c.MemoryBytes-memory || r.StorageBytes > c.StorageBytes-storage {
		return actionError(generated.ErrorCodePrerequisiteBlocked)
	}
	return nil
}
func reserveServiceCapacity(ctx context.Context, tx *sql.Tx, in generated.ServiceDeploymentRequest, planID string) error {
	if in.Configuration == nil {
		return nil
	}
	row := func(q string, a ...any) *sql.Row { return tx.QueryRowContext(ctx, q, a...) }
	if e := checkServiceCapacity(row, in); e != nil {
		return e
	}
	c := in.Configuration
	_, e := tx.ExecContext(ctx, `INSERT INTO service_capacity_reservations(service_id,host_id,plan_id,configuration_digest,cpu_percent,memory_bytes,storage_bytes,recovery_epoch) VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(service_id) DO UPDATE SET host_id=excluded.host_id,plan_id=excluded.plan_id,configuration_digest=excluded.configuration_digest,cpu_percent=MAX(service_capacity_reservations.cpu_percent,excluded.cpu_percent),memory_bytes=MAX(service_capacity_reservations.memory_bytes,excluded.memory_bytes),storage_bytes=MAX(service_capacity_reservations.storage_bytes,excluded.storage_bytes),recovery_epoch=excluded.recovery_epoch`, in.Definition.ServiceID, in.Definition.HostID, planID, in.Binding.ConfigurationDigest, c.CPUQuotaPercent, c.MemoryBytes, c.StorageBytes, in.RecoveryEpoch)
	return e
}

func (r *DeploymentRepository) CheckPlacement(ctx context.Context, d generated.ServiceDefinition, configuration generated.ServiceConfiguration, capacity generated.ServiceCapacity) error {
	p, e := serviceActor(ctx)
	if e != nil {
		return e
	}
	return r.store.Read(ctx, func(tx ReadTx) error {
		row := func(q string, a ...any) *sql.Row { return tx.queryRow(ctx, q, a...) }
		if e := NewServiceRepository(r.store).authorize(p, row, d, "read", "service.read"); e != nil {
			return e
		}
		return r.validateConfiguration(row, generated.ServiceDeploymentRequest{Definition: d, Configuration: &configuration, Capacity: &capacity, RecoveryEpoch: capacity.RecoveryEpoch}, r.store.config.Clock().UTC())
	})
}

func validateServiceExposure(row discoveryRow, in generated.ServiceDeploymentRequest, address string, at time.Time) error {
	var raw []byte
	var status, observed string
	c := in.Configuration
	if row(`SELECT d.request_bytes,o.status,o.observed_at FROM ingress_ownership w JOIN ingress_drafts d ON d.draft_id=w.draft_id JOIN ingress_observations o ON o.profile_id=w.profile_id AND o.draft_id=w.draft_id AND o.run_id=w.run_id AND o.recovery_epoch=w.recovery_epoch WHERE w.profile_id=? AND w.recovery_epoch=? AND o.rowid=(SELECT MAX(latest.rowid) FROM ingress_observations latest WHERE latest.profile_id=w.profile_id AND latest.recovery_epoch=w.recovery_epoch) ORDER BY w.revision DESC,o.rowid DESC LIMIT 1`, c.ExposurePolicyID, in.RecoveryEpoch).Scan(&raw, &status, &observed) != nil || status != "observed" {
		return actionError(generated.ErrorCodePrerequisiteBlocked)
	}
	var route generated.IngressDraftRequest
	when, e := time.Parse(time.RFC3339, observed)
	if e != nil || when.After(at.Add(time.Second)) || at.Sub(when) > 5*time.Minute || json.Unmarshal(raw, &route) != nil || route.Change.OriginIdentityDigest != c.OriginIdentityDigest {
		return actionError(generated.ErrorCodePrerequisiteBlocked)
	}
	origin, e := url.Parse(route.Change.OriginService)
	if e != nil || origin.Hostname() != address || origin.Port() != strconv.FormatInt(c.OriginPort, 10) || route.Change.Hostname != c.ExposureHostname || route.RecoveryEpoch != in.RecoveryEpoch {
		return actionError(generated.ErrorCodePrerequisiteBlocked)
	}
	return nil
}
