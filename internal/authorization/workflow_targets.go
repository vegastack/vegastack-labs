package authorization

import (
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"github.com/vegastack/vegastack-labs/internal/hostadoption"
	"github.com/vegastack/vegastack-labs/internal/hostdiscovery"
	"github.com/vegastack/vegastack-labs/internal/hostreplacement"
)

// ExecutionResourceIDs projects only exact typed single-operation workflows.
// Unsupported and legacy operations retain their original exact target.
func ExecutionResourceIDs(p generated.Plan, op generated.PlanOperation) []string {
	fallback := []string{op.TargetID}
	if p.AuthorizationBranch != "human" || p.ExecutorMode != "central" || len(p.Operations) != 1 || p.Operations[0] != op {
		return fallback
	}
	exact := func(id, digest, adapter, kind string) bool {
		return p.DeclarationID == id && op.TargetID == id && op.InputDigest == digest && op.ArtifactDigest == digest && op.AdapterID == adapter && op.OperationType == kind
	}
	if in := p.HostDiscoveryTarget; in != nil {
		digest := hostdiscovery.Digest(*in)
		id := "discovery-draft-" + digest[7:39]
		if exact(id, digest, "core.host-discovery-target", "host.discovery-target."+in.Action) && in.Target.RecoveryEpoch == p.Binding.RecoveryEpoch && ValidIdentifier(in.Target.TargetID) {
			return []string{in.Target.TargetID}
		}
	}
	if in := p.HostAdoption; in != nil {
		digest := hostadoption.Digest(*in)
		id := "host-adoption-" + digest[7:39]
		if exact(id, digest, "core.host-adoption", "host.adopt") && in.RecoveryEpoch == p.Binding.RecoveryEpoch && ValidIdentifier(in.HostID) {
			return []string{in.HostID}
		}
	}
	if in := p.HostReplacement; in != nil {
		digest := hostaction.Digest(*in)
		id := "host-replacement-" + digest[7:39]
		kind := hostreplacement.FreezeOperation
		if in.Operation == "commit" {
			kind = hostreplacement.CommitOperation
		}
		if exact(id, digest, hostreplacement.AdapterID, kind) && hostreplacement.ValidateInput(*in) == nil && in.RecoveryEpoch == p.Binding.RecoveryEpoch {
			return []string{in.OldHostID, in.NewHostID}
		}
	}
	if in := p.HostAliasClaim; in != nil {
		digest := hostaction.Digest(*in)
		if exact(p.DeclarationID, digest, hostreplacement.AdapterID, hostreplacement.AliasClaimOperation) && hostreplacement.ValidateAliasClaim(*in) == nil && in.RecoveryEpoch == p.Binding.RecoveryEpoch {
			return append([]string(nil), in.AliasIDs...)
		}
	}
	return fallback
}
func FirstExecutionTarget(p generated.Plan, id string) bool {
	if len(p.Operations) == 0 {
		return false
	}
	for _, target := range ExecutionResourceIDs(p, p.Operations[0]) {
		if target == id {
			return true
		}
	}
	return false
}
