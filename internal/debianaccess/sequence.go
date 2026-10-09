package debianaccess

import (
	"encoding/json"
	"fmt"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"sort"
	"time"
)

const LocalProbeOperation = "host.access.probe.local"

// Sequence binds only predeclared drafts. It never allocates runtime steps.
func Sequence(ops []generated.PlanOperation, requests []generated.HostActionRequest) (generated.HostAccessSequence, error) {
	var out generated.HostAccessSequence
	if len(ops) < 3 || len(ops) > 18 || len(ops) != len(requests) {
		return out, errInput
	}
	apply := requests[0]
	input, e := DecodeInput([]byte(apply.ActionInput))
	if e != nil || apply.ActionID != "debian.access.apply" || apply.HostID != input.HostID || apply.ConsoleConfirmation.HostIdentityDigest != input.HostIdentityDigest {
		return out, errInput
	}
	out = generated.HostAccessSequence{Schema: generated.SchemaIDHostAccessSequence, SchemaVersion: "1.0.0", Actions: requests, SubjectHostID: apply.HostID, SubjectIdentityDigest: input.HostIdentityDigest, ProfileLockDigest: input.ProfileLockDigest, ApplyOperationID: ops[0].OperationID, ApplyDraftDigest: hostaction.Digest(apply), ProbeSteps: []generated.HostAccessProbeStep{}, ConfirmOperationID: ops[len(ops)-1].OperationID, ConfirmDraftDigest: hostaction.Digest(requests[len(requests)-1])}
	ids := map[string]bool{}
	executions := map[string]bool{}
	probeIDs := map[string]bool{}
	coverage := map[string]bool{}
	policyProbes := []generated.AccessProbeInput{}
	collected := false
	budget := int64(120) // apply and confirm each fit one existing 60s lease.
	for i, op := range ops {
		r := requests[i]
		execution := hostaction.Digest([]string{r.HostID, r.ActionID, r.ActionInputDigest})
		if executions[execution] {
			return out, errInput
		}
		executions[execution] = true
		if ids[op.OperationID] || hostaction.ValidateRequest(r) != nil || r.ActionVersion != ActionVersion || r.RecoveryEpoch != apply.RecoveryEpoch || r.ExpectedStateRevision != apply.ExpectedStateRevision || op.AdapterID != hostaction.AdapterID || op.TargetID != r.HostID || op.ArtifactDigest != hostaction.Digest(r) || op.Idempotent || op.Sequence != int64(i+1) {
			return out, errInput
		}
		ids[op.OperationID] = true
		if i == 0 || i == len(ops)-1 {
			if op.OperationType != hostaction.OperationType || r.HostID != apply.HostID {
				return out, errInput
			}
			continue
		}
		p := generated.HostAccessProbeStep{Schema: generated.SchemaIDHostAccessProbeStep, SchemaVersion: "1.0.0", OperationID: op.OperationID, SourceHostID: r.HostID, SourceIdentityDigest: r.ConsoleConfirmation.HostIdentityDigest, DraftDigest: op.ArtifactDigest, SpecificationDigest: r.ActionInputDigest}
		switch r.ActionID {
		case "debian.access.collect":
			v, err := DecodeInput([]byte(r.ActionInput))
			if err != nil || r.HostID != apply.HostID || hostaction.Digest(v) != hostaction.Digest(input) || op.OperationType != hostaction.OperationType {
				return out, errInput
			}
			p.Kind = "collect"
			collected = true
			p.SourceContextDigest = input.HostIdentityDigest
			budget += 60
		case "debian.access.probe.local", "debian.access.probe-source":
			var probe generated.AccessProbeInput
			if generated.ValidateContractJSON(generated.SchemaIDAccessProbeInput, []byte(r.ActionInput), generated.ContractExact) != nil || json.Unmarshal([]byte(r.ActionInput), &probe) != nil || probe.SubjectHostID != apply.HostID || probe.SubjectIdentityDigest != input.HostIdentityDigest || probe.ProfileLockDigest != input.ProfileLockDigest || probe.ApplyInputDigest != apply.ActionInputDigest || probe.RollbackDigest != input.RollbackDigest || len(probe.Cases) == 0 {
				return out, errInput
			}
			for _, c := range probe.Cases {
				if probeIDs[c.ProbeID] {
					return out, errInput
				}
				probeIDs[c.ProbeID] = true
				coverage[c.Kind+":"+c.Expected] = true
				if c.Kind == "ssh-source" && (r.ActionID == "debian.access.probe.local" || probe.Source.Kind == "host-network") {
					return out, errInput
				}
			}
			policyProbes = append(policyProbes, probe)
			p.SourceContextDigest = probe.Source.ContextDigest
			duration, budgetErr := RequiredProbeDuration(probe)
			if budgetErr != nil || duration >= 60*time.Second {
				return out, errInput
			}
			budget += int64((duration + time.Second - 1) / time.Second)
			if r.ActionID == "debian.access.probe.local" {
				if op.OperationType != LocalProbeOperation || r.HostID != apply.HostID {
					return out, errInput
				}
				p.Kind = "local-probe"
			} else {
				if op.OperationType != hostaction.OperationType || r.HostID != probe.Source.HostID || r.ConsoleConfirmation.HostIdentityDigest != probe.Source.IdentityDigest {
					return out, errInput
				}
				p.Kind = "source-probe"
				for _, c := range probe.Cases {
					if c.Kind == "ssh-admin" {
						return out, errInput
					}
				}
			}
		default:
			return out, errInput
		}
		out.ProbeSteps = append(out.ProbeSteps, p)
	}
	if validateProbePolicy(input, policyProbes) != nil {
		return out, fmt.Errorf("%w: policy probe coverage", errInput)
	}
	if !collected {
		return out, errInput
	}
	for _, required := range []string{"ssh-admin:allowed", "ssh-wrong-user:denied", "ssh-password:denied", "ssh-root:denied", "ssh-source:denied", "host-flow:allowed", "host-flow:denied"} {
		if !coverage[required] {
			return out, fmt.Errorf("%w: incomplete probe matrix", errInput)
		}
	}
	if len(input.ContainerFlows) > 0 {
		for _, required := range []string{"container-published:allowed", "container-unpublished:denied", "container-east-west:allowed", "container-east-west:denied"} {
			if !coverage[required] {
				return out, errInput
			}
		}
	}
	if budget >= 570 {
		return out, fmt.Errorf("%w: sequence exceeds rollback budget", errInput)
	}
	out.AuxiliaryTargets, e = SequenceAuxiliaryTargets(requests)
	if e != nil {
		return out, e
	}
	out.SpecificationDigest = SequenceSpecificationDigest(out)
	last := requests[len(requests)-1]
	var confirm generated.AccessConfirmInput
	if last.ActionID != "debian.access.confirm" || generated.ValidateContractJSON(generated.SchemaIDAccessConfirmInput, []byte(last.ActionInput), generated.ContractExact) != nil || json.Unmarshal([]byte(last.ActionInput), &confirm) != nil || confirm.HostID != apply.HostID || confirm.HostIdentityDigest != input.HostIdentityDigest || confirm.ProfileLockDigest != input.ProfileLockDigest || confirm.RollbackDigest != input.RollbackDigest || confirm.ApplyOperationID != ops[0].OperationID || confirm.ApplyDraftDigest != out.ApplyDraftDigest || confirm.ApplyInputDigest != apply.ActionInputDigest || confirm.ProbeSpecificationDigest != out.SpecificationDigest {
		return out, errInput
	}
	return out, nil
}

func SequenceSpecificationDigest(s generated.HostAccessSequence) string {
	return hostaction.Digest(struct {
		Subject  string
		Identity string
		Profile  string
		Apply    string
		Probes   []generated.HostAccessProbeStep
	}{s.SubjectHostID, s.SubjectIdentityDigest, s.ProfileLockDigest, s.ApplyDraftDigest, s.ProbeSteps})
}

func SequenceAuxiliaryTargets(requests []generated.HostActionRequest) ([]generated.AccessTargetIdentity, error) {
	identities := map[string]string{}
	add := func(id, digest string) bool {
		if ProtectedName(id) || id == "" || digest == "" {
			return false
		}
		if old, ok := identities[id]; ok && old != digest {
			return false
		}
		identities[id] = digest
		return true
	}
	for _, r := range requests {
		if !add(r.HostID, r.ConsoleConfirmation.HostIdentityDigest) {
			return nil, errInput
		}
		if r.ActionID != "debian.access.probe.local" && r.ActionID != "debian.access.probe-source" {
			continue
		}
		var p generated.AccessProbeInput
		if json.Unmarshal([]byte(r.ActionInput), &p) != nil || !add(p.SubjectHostID, p.SubjectIdentityDigest) || !add(p.Source.HostID, p.Source.IdentityDigest) {
			return nil, errInput
		}
		for _, c := range p.Cases {
			if !add(c.Destination.HostID, c.Destination.IdentityDigest) || !add(c.Witness.HostID, c.Witness.IdentityDigest) {
				return nil, errInput
			}
		}
	}
	if len(identities) > 64 {
		return nil, errInput
	}
	ids := make([]string, 0, len(identities))
	for id := range identities {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	out := make([]generated.AccessTargetIdentity, 0, len(ids))
	for _, id := range ids {
		out = append(out, generated.AccessTargetIdentity{Schema: generated.SchemaIDAccessTargetIdentity, SchemaVersion: "1.0.0", HostID: id, IdentityDigest: identities[id]})
	}
	return out, nil
}
