//go:build linux || darwin

package debianaccess

import (
	"context"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"time"
)

func (n *nativeRuntime) collectDestinations(ctx context.Context, in generated.DebianAccessInput) ([]generated.AccessMeasurement, error) {
	read := n.readContexts
	if read == nil {
		read = ReadPreparedProbeContexts
	}
	records, e := read()
	if e != nil {
		return nil, e
	}
	observe := n.observeContainer
	if observe == nil {
		observe = ObservePreparedContainer
	}
	var destinations []generated.AccessDestinationObservation
	for _, record := range records {
		if record.Kind != "container" || record.HostID != in.HostID || record.IdentityDigest != in.HostIdentityDigest {
			continue
		}
		facts, e := observe(ctx, record)
		if e != nil {
			return nil, e
		}
		for _, fact := range facts {
			if fact.HostID != in.HostID || fact.IdentityDigest != in.HostIdentityDigest || fact.ContextID != record.ContextID || fact.ContextDigest != hostaction.Digest(record) || fact.ContainerID != record.ContainerID {
				return nil, errAccess
			}
		}
		destinations = append(destinations, facts...)
		if len(destinations) > 8 {
			return nil, errAccess
		}
	}
	if len(destinations) == 0 {
		return nil, nil
	}
	return []generated.AccessMeasurement{{Schema: generated.SchemaIDAccessMeasurement, SchemaVersion: "1.0.0", ControlID: "debian.destination-ownership", Kind: "identity", Status: "passed", SubjectHostID: in.HostID, SubjectIdentityDigest: in.HostIdentityDigest, ProfileLockDigest: in.ProfileLockDigest, ProducerID: "debian-access-native", ProducerVersion: "1.0.0", ObservedAt: n.now().Format(time.RFC3339), ConfigurationDigest: hostaction.Digest(destinations), PositiveProbeDigest: digestBytes(nil), NegativeProbeDigest: digestBytes(nil), Reason: "prepared-container-address-observed", DestinationOwnership: destinations}}, nil
}
func (n *nativeRuntime) Collect(ctx context.Context, b generated.HostActionBundle, in generated.DebianAccessInput) (RoleResult, error) {
	if e := n.inspectProfile(ctx, in); e != nil {
		return RoleResult{}, e
	}
	ownership, ownershipErr := n.collectDestinations(ctx, in)
	local, e := n.collectConfiguration(ctx, b, in)
	if e != nil {
		if ownershipErr != nil || len(ownership) == 0 {
			return RoleResult{}, e
		}
		local = n.measure(in, "partial", "configuration-unqualified", false)
	}
	if ownershipErr != nil {
		if len(in.ContainerFlows) > 0 {
			return RoleResult{}, ownershipErr
		}
	} else {
		local.Measurements = append(local.Measurements, ownership...)
	}
	return local, nil
}
