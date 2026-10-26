package server

import (
	"context"
	"github.com/vegastack/vegastack-labs/internal/adapter/serviceruntime"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/store"
	"slices"
	"time"
)

func runtimeCapacityTarget(t store.ServiceRuntimeTarget) serviceruntime.Target {
	return serviceruntime.Target{HostID: t.HostID, HostIdentityDigest: t.HostIdentityDigest, Address: t.Address, User: t.User, HostKey: t.HostKey, Port: t.Port, ExpectedMachineIDDigest: t.ExpectedMachineIDDigest}
}
func (c *serviceDeploymentComposition) observeCapacity(ctx context.Context, d generated.ServiceDefinition, b generated.ServiceDeploymentProviderBinding) (generated.ServiceCapacity, error) {
	var out generated.ServiceCapacity
	target, e := c.base.repo.RuntimeTarget(ctx, d.ServiceID)
	if e != nil {
		return out, e
	}
	value, credential, e := c.base.borrow(ctx, d, false, target.RecoveryEpoch, b.RuntimeReferenceID, "service.runtime", "runtime-observe", "credential.service-runtime.read")
	if e != nil {
		return out, e
	}
	defer value.Close()
	check := func(ctx context.Context) error {
		if _, e := c.base.check(ctx, d, false, target.RecoveryEpoch); e != nil {
			return e
		}
		actual, e := c.base.repo.RuntimeTarget(ctx, d.ServiceID)
		if e != nil {
			return e
		}
		actual.StateRevision = 0
		before := target
		before.StateRevision = 0
		if actual != before {
			return serviceFailure(generated.ErrorCodePlanStale)
		}
		admission, e := (hostReplacementComposition{gates: c.base.gates, clock: time.Now}).roleAdmission(ctx, d.HostID)
		if e != nil || admission.IdentityDigest != d.HostIdentityDigest || admission.Profile.RoleID != "application" {
			return serviceFailure(generated.ErrorCodePrerequisiteBlocked)
		}
		return c.base.recheckCredential(ctx, d, false, target.RecoveryEpoch, b.RuntimeReferenceID, "service.runtime", "runtime-observe", "credential.service-runtime.read", credential)
	}
	observer, ok := c.runtime.(serviceruntime.CapacityObserver)
	if !ok {
		return out, serviceFailure(generated.ErrorCodePrerequisiteBlocked)
	}
	binding, e := c.base.binding(d)
	if e != nil || binding.Coolify == nil {
		return out, serviceFailure(generated.ErrorCodePrerequisiteBlocked)
	}
	runtimeTarget := runtimeCapacityTarget(target)
	runtimeTarget.ApplicationUUID = binding.Coolify.ApplicationUUID
	observed, e := observer.ObserveCapacity(ctx, runtimeTarget, value, check)
	if e != nil {
		return out, e
	}
	if e = check(ctx); e != nil {
		return out, e
	}
	at, e := time.Parse(time.RFC3339, observed.ObservedAt)
	if e != nil || at.After(time.Now().UTC().Add(time.Second)) || time.Since(at) > 5*time.Second {
		return out, serviceFailure(generated.ErrorCodeEvidenceInvalid)
	}
	out = generated.ServiceCapacity{Schema: generated.SchemaIDServiceCapacity, SchemaVersion: "1.0.0", HostID: d.HostID, HostIdentityDigest: d.HostIdentityDigest, TargetDigest: target.TargetDigest, CPUQuotaPercent: observed.CPUQuotaPercent, MemoryBytes: observed.MemoryBytes, StorageBytes: observed.StorageBytes, ObservedAt: observed.ObservedAt, ExpiresAt: at.Add(30 * time.Minute).Format(time.RFC3339), RecoveryEpoch: target.RecoveryEpoch}
	if e = c.repo.RecordCapacity(ctx, d.ServiceID, out); e != nil {
		return generated.ServiceCapacity{}, e
	}
	return out, nil
}

// Configuration distinguishes desired protected settings from a verified
// deployment's accepted settings, which remain in the deployment record.
func (c *serviceDeploymentComposition) Configuration(ctx context.Context, serviceID string) (generated.ServiceConfigurationStatus, error) {
	record, e := c.base.repo.Get(ctx, serviceID)
	if e != nil {
		return generated.ServiceConfigurationStatus{}, e
	}
	out := generated.ServiceConfigurationStatus{Schema: generated.SchemaIDServiceConfigurationStatus, SchemaVersion: "1.0.0", ServiceID: serviceID, PlacementState: "unknown", PlacementReason: "configuration-not-declared", ObservedAt: time.Now().UTC().Truncate(time.Second).Format(time.RFC3339), StateRevision: record.StateRevision, RecoveryEpoch: record.RecoveryEpoch}
	b, ok := c.bindings[serviceID]
	if !ok || b.Configuration == nil {
		return out, nil
	}
	copy := *b.Configuration
	copy.SecretReferenceIDs = append([]string{}, b.Configuration.SecretReferenceIDs...)
	out.Configuration = &copy
	out.ConfigurationDigest = b.Binding.ConfigurationDigest
	capacity, e := c.observeCapacity(ctx, record.Definition, b)
	if e != nil {
		if _, currentErr := c.base.repo.Get(ctx, serviceID); currentErr != nil {
			return generated.ServiceConfigurationStatus{}, currentErr
		}
		out.PlacementState = "blocked"
		out.PlacementReason = "admission-or-capacity-unavailable"
		return out, nil
	}
	if e = c.repo.CheckPlacement(ctx, record.Definition, copy, capacity); e != nil {
		if _, currentErr := c.base.repo.Get(ctx, serviceID); currentErr != nil {
			return generated.ServiceConfigurationStatus{}, currentErr
		}
		out.PlacementState = "blocked"
		out.PlacementReason = "configuration-or-capacity-blocked"
		return out, nil
	}
	if _, currentErr := c.base.repo.Get(ctx, serviceID); currentErr != nil {
		return generated.ServiceConfigurationStatus{}, currentErr
	}
	out.PlacementState = "eligible"
	out.PlacementReason = "current-qualified-capacity"
	return out, nil
}
func (c *serviceDeploymentComposition) checkDataContract(ctx context.Context, q generated.ServiceDeploymentRequest) error {
	if q.Configuration == nil || q.Configuration.DataClass == "stateless" {
		return nil
	}
	proof, e := store.NewServiceRecoveryRepository(c.base.store).GetVerifiedRecovery(ctx, q.Definition.ServiceID, q.Configuration.BackupPolicyID, q.RecoveryEpoch)
	if e != nil {
		return e
	}
	if proof.Request.Definition != q.Definition || proof.Request.Binding.SourceHostID != q.Definition.HostID || proof.Request.Binding.ConsistencyProcedureID != q.Configuration.ConsistencyProcedureID || proof.PlanID != q.Configuration.RecoveryRecordID || (proof.Request.Binding.DataClass != "workload" && proof.Request.Binding.DataClass != "registry") {
		return serviceFailure(generated.ErrorCodePrerequisiteBlocked)
	}
	if proof.ElapsedSeconds < 1 || proof.ElapsedSeconds > q.Configuration.RecoveryObjectiveSeconds {
		return serviceFailure(generated.ErrorCodePrerequisiteBlocked)
	}
	if q.Action == "rollback" && (q.Configuration.Rollback != "previous-artifact" || q.Configuration.Migration != "backward-compatible" || !slices.Contains(proof.SourceImageDigests, q.Artifact.Digest)) {
		return serviceFailure(generated.ErrorCodeRecoveryRequired)
	}
	return nil
}
