package store

import (
	"context"
	"database/sql"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostdiscovery"
)

// PlatformDefinition is a protected logical platform subject, never a fabricated
// Coolify application registration. Host identity still comes from the current
// managed/discovered host records and requires its existing host.read grant.
func (r *ServiceRecoveryRepository) PlatformDefinition(ctx context.Context, policyID string, target bool) (out generated.ServiceDefinition, err error) {
	p, e := r.policy(policyID)
	if e != nil || p.Binding.DataClass != "platform" || p.PlatformOwnerID == "" {
		return out, actionError(generated.ErrorCodePrerequisiteBlocked)
	}
	hostID, serviceID := p.Binding.SourceHostID, p.Binding.ServiceID
	if target {
		hostID = p.Binding.TargetHostID
		serviceID = p.TargetServiceID
	}
	err = r.store.Read(ctx, func(tx ReadTx) error {
		row := func(q string, a ...any) *sql.Row { return tx.queryRow(ctx, q, a...) }
		if _, e := adoptionGrant(ctx, row, hostID, "host", "read", "host.read", false); e != nil {
			return e
		}
		host, e := readManagedHost(row, hostID)
		if e != nil {
			return e
		}
		out = generated.ServiceDefinition{Schema: generated.SchemaIDServiceDefinition, SchemaVersion: "1.0.0", ServiceID: serviceID, EnvironmentID: "platform", OwnerID: p.PlatformOwnerID, HostID: hostID, HostIdentityDigest: managedRecoveryIdentity(row, host.HostID), BindingID: p.Binding.PolicyID, BindingDigest: p.Binding.ConfigurationDigest}
		return nil
	})
	return
}
func (r *ServiceRecoveryRepository) platformAuthorize(ctx context.Context, row discoveryRow, d generated.ServiceDefinition, policyID string) error {
	p, e := serviceActor(ctx)
	if e != nil {
		return e
	}
	policy, e := r.policy(policyID)
	if e != nil {
		return e
	}
	if policy.Binding.DataClass != "platform" || d.EnvironmentID != "platform" || d.ServiceID != policy.Binding.ServiceID || d.OwnerID != policy.PlatformOwnerID || d.HostID != policy.Binding.SourceHostID || d.BindingID != policy.Binding.PolicyID || d.BindingDigest != policy.Binding.ConfigurationDigest {
		return actionError(generated.ErrorCodePlanStale)
	}
	if _, e = adoptionPrincipalGrant(p, row, d.ServiceID, "service", "author", "service.recovery.prepare", false); e != nil {
		return e
	}
	if e = authorizeDeviceRow(row, p); e != nil {
		return e
	}
	var n int
	if row(`SELECT COUNT(*) FROM effective_authorization_principals WHERE principal_id=? AND status='active'`, d.OwnerID).Scan(&n) != nil || n != 1 {
		return actionError(generated.ErrorCodeAuthorizationDenied)
	}
	host, e := readManagedHost(row, d.HostID)
	if e != nil || managedRecoveryIdentity(row, host.HostID) != d.HostIdentityDigest {
		return actionError(generated.ErrorCodePlanStale)
	}
	return nil
}

// HostRuntimeTarget reuses current managed/discovery identity and protected
// physical exclusions for platform components which are not Coolify apps.
func (r *ServiceRecoveryRepository) HostRuntimeTarget(ctx context.Context, hostID, identity string) (out ServiceRuntimeTarget, err error) {
	err = r.store.Read(ctx, func(tx ReadTx) error {
		row := func(q string, a ...any) *sql.Row { return tx.queryRow(ctx, q, a...) }
		if _, e := adoptionGrant(ctx, row, hostID, "host", "read", "host.read", false); e != nil {
			return e
		}
		if e := requireHostUnfrozen(row, hostID); e != nil {
			return e
		}
		host, e := readManagedHost(row, hostID)
		if e != nil {
			return e
		}
		if managedRecoveryIdentity(row, host.HostID) != identity {
			return actionError(generated.ErrorCodePlanStale)
		}
		target, e := discoveryTarget(row, host.TargetID)
		if e != nil {
			return e
		}
		var n int
		for _, id := range r.store.config.NetworkConnectExcludedHostIDs {
			const hosts = `SELECT h.host_id FROM managed_hosts h WHERE h.host_id=?1 OR h.target_id=?1 OR h.host_id IN (SELECT owner_host_id FROM host_alias_owners WHERE alias_id=?1) OR h.identity_digest IN (SELECT owner_identity_digest FROM host_alias_owners WHERE alias_id=?1) OR h.host_id IN (SELECT owner_host_id FROM host_alias_history WHERE alias_id=?1) OR h.identity_digest IN (SELECT owner_identity_digest FROM host_alias_history WHERE alias_id=?1)`
			if row(`SELECT COUNT(*) FROM managed_hosts h WHERE h.host_id IN (`+hosts+`) AND (h.host_id=?2 OR h.identity_digest=?3 OR h.target_id=?4)`, id, hostID, identity, host.TargetID).Scan(&n) != nil || n != 0 {
				return actionError(generated.ErrorCodeAuthorizationDenied)
			}
		}
		observation, e := readDiscoveryObservation(row, host.ObservationID)
		if e != nil {
			return e
		}
		copy := observation
		copy.ContentDigest = ""
		if observation.ContentDigest != hostdiscovery.Digest(copy) || observation.RecoveryEpoch != host.RecoveryEpoch || observation.TargetID != host.TargetID || observation.TargetRevision != target.Binding.Revision || observation.TargetDigest != target.Digest || target.Binding.RecoveryEpoch != host.RecoveryEpoch {
			return actionError(generated.ErrorCodePlanStale)
		}
		machine := ""
		for _, fact := range observation.Facts {
			if fact.Name == "machine-id" && fact.Operation == "machine-id" {
				if machine != "" {
					return actionError(generated.ErrorCodeIntegrityFailure)
				}
				machine = hostdiscovery.Digest(fact.Value)
			}
		}
		var epoch int64
		if machine == "" || target.Binding.Port < 1 || target.Binding.Port > 65535 || row(`SELECT recovery_epoch FROM system_meta WHERE id=1`).Scan(&epoch) != nil || epoch != host.RecoveryEpoch {
			return actionError(generated.ErrorCodePlanStale)
		}
		out = ServiceRuntimeTarget{HostID: hostID, HostIdentityDigest: identity, Address: target.Binding.Address, User: target.Binding.User, HostKey: target.Binding.HostKey, Port: uint16(target.Binding.Port), ExpectedMachineIDDigest: machine, TargetDigest: target.Digest, TargetRevision: target.Binding.Revision, RecoveryEpoch: epoch}
		return nil
	})
	return
}

func managedRecoveryIdentity(row discoveryRow, hostID string) string {
	var identity string
	if row(`SELECT identity_digest FROM managed_hosts WHERE host_id=?`, hostID).Scan(&identity) != nil {
		return ""
	}
	return identity
}
