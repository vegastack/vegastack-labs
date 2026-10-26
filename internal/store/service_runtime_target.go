package store

import (
	"context"
	"database/sql"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostdiscovery"
	"github.com/vegastack/vegastack-labs/internal/principal"
)

// ServiceRuntimeTarget is a current, authorized connection binding. It contains
// no credential and confers neither host admission nor permission to mutate.
// StateRevision is informational: callers compare the remaining binding fields
// across observations, since their own run journal can advance the state.
type ServiceRuntimeTarget struct {
	HostID, HostIdentityDigest, Address, User, HostKey, ExpectedMachineIDDigest string
	Port                                                                        uint16
	TargetDigest                                                                string
	TargetRevision, StateRevision, RecoveryEpoch                                int64
}

// RuntimeTarget resolves the service, protected exclusions, current target and
// accepted adoption observation in one server-owned read transaction. Callers
// must separately enforce role admission and borrow a runtime-scoped credential.
func (r *ServiceRepository) RuntimeTarget(ctx context.Context, serviceID string) (out ServiceRuntimeTarget, err error) {
	if !principal.ValidID(serviceID) {
		return out, actionError(generated.ErrorCodeInputInvalid)
	}
	p, err := serviceActor(ctx)
	if err != nil {
		return out, err
	}
	if r == nil || r.store == nil {
		return out, actionError(generated.ErrorCodePrerequisiteBlocked)
	}
	err = r.store.Read(ctx, func(tx ReadTx) error {
		row := func(q string, args ...any) *sql.Row { return tx.queryRow(ctx, q, args...) }
		// Deny before reading a private service's registration or target.
		if _, e := adoptionPrincipalGrant(p, row, serviceID, "service", "read", "service.read", false); e != nil {
			return e
		}
		record, e := readService(row, serviceID)
		if e != nil {
			return e
		}
		if e = r.authorize(p, row, record.Definition, "read", "service.read"); e != nil {
			return e
		}
		host, e := readManagedHost(row, record.Definition.HostID)
		if e != nil {
			return e
		}
		target, e := discoveryTarget(row, host.TargetID)
		if e != nil {
			return e
		}
		observation, e := readDiscoveryObservation(row, host.ObservationID)
		if e != nil {
			return actionError(generated.ErrorCodePrerequisiteBlocked)
		}
		copy := observation
		copy.ContentDigest = ""
		if observation.ContentDigest != hostdiscovery.Digest(copy) {
			return actionError(generated.ErrorCodeIntegrityFailure)
		}
		if target.Binding.RecoveryEpoch != host.RecoveryEpoch || observation.RecoveryEpoch != host.RecoveryEpoch || observation.TargetID != host.TargetID || observation.TargetRevision != target.Binding.Revision || observation.TargetDigest != target.Digest || observation.ObservationID != host.ObservationID || host.ProfileID != target.Binding.ProfileID {
			return actionError(generated.ErrorCodePlanStale)
		}
		machineDigest := ""
		for _, fact := range observation.Facts {
			if fact.Name == "machine-id" {
				if machineDigest != "" || fact.Value == "" || fact.Operation != "machine-id" {
					return actionError(generated.ErrorCodeIntegrityFailure)
				}
				machineDigest = hostdiscovery.Digest(fact.Value)
			}
		}
		if machineDigest == "" {
			return actionError(generated.ErrorCodePrerequisiteBlocked)
		}
		if target.Binding.Port < 1 || target.Binding.Port > 65535 {
			return actionError(generated.ErrorCodeIntegrityFailure)
		}
		out = ServiceRuntimeTarget{HostID: host.HostID, HostIdentityDigest: record.Definition.HostIdentityDigest, Address: target.Binding.Address, User: target.Binding.User, HostKey: target.Binding.HostKey, ExpectedMachineIDDigest: machineDigest, Port: uint16(target.Binding.Port), TargetDigest: target.Digest, TargetRevision: target.Binding.Revision, RecoveryEpoch: host.RecoveryEpoch}
		return row(`SELECT state_revision FROM system_meta WHERE id=1`).Scan(&out.StateRevision)
	})
	if err != nil {
		out = ServiceRuntimeTarget{}
	}
	return
}
