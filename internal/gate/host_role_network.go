package gate

import (
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"github.com/vegastack/vegastack-labs/internal/store"
	"slices"
	"time"
)

// RoleNetworkProofDigest composes actual owned configuration with the same
// approved positive/negative probe and destination receipts used by baseline
// admission. It never promotes a template or fixture to a native qualification.
func RoleNetworkProofDigest(s store.HostAdmissionSnapshot, in generated.LinuxRoleInput, at time.Time) (string, error) {
	if in.NetworkAccess == nil || !in.NetworkingRequired || s.RoleBindingDigest != in.RoleBindingDigest || s.RoleIntentRevision == 0 {
		return "", errHostAdmission
	}
	v := hostProofVerifier{snapshot: s, at: at}
	expected := hostaction.Digest(*in.NetworkAccess)
	ids := []string{"debian.host-firewall"}
	if len(in.NetworkAccess.ContainerFlows) > 0 {
		ids = append(ids, "debian.container-firewall")
	}
	var digests []string
	for _, id := range ids {
		x, reason := v.measurement(id)
		if reason != "" || x.Plan.Binding.StateRevision <= s.RoleIntentRevision {
			return "", errHostAdmission
		}
		var requested string
		if x.Plan.HostAction != nil {
			requested = x.Plan.HostAction.ActionInputDigest
		} else if x.Plan.HostAccessSequence != nil && len(x.Plan.HostAccessSequence.Actions) > 0 {
			requested = x.Plan.HostAccessSequence.Actions[0].ActionInputDigest
		}
		if requested != expected {
			return "", errHostAdmission
		}
		proofs, reason := v.accessProof(x)
		if reason != "" {
			return "", errHostAdmission
		}
		digests = append(digests, x.Measurement.MeasurementDigest)
		digests = append(digests, proofs...)
		for _, digest := range proofs {
			found := false
			for _, m := range s.Measurements {
				if m.Measurement.MeasurementDigest == digest && m.Plan.Binding.StateRevision > s.RoleIntentRevision {
					found = true
				}
			}
			if !found {
				return "", errHostAdmission
			}
		}
	}
	slices.Sort(digests)
	digests = slices.Compact(digests)
	return hostaction.Digest(digests), nil
}
