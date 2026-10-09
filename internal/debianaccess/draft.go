package debianaccess

import (
	"encoding/json"
	"fmt"
	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
)

type AccessDraft struct {
	Requests   []generated.HostActionRequest
	Operations []generated.PlanOperation
	Bindings   []credentialref.StepBinding
	Sequence   generated.HostAccessSequence
}

// BuildDraft is the deterministic finite request compiler shared by staging and
// callers preparing exact author scope. It performs no rendering or I/O.
func BuildDraft(input generated.HostAccessDraftRequest) (AccessDraft, error) {
	raw, e := json.Marshal(input.Input)
	if e != nil {
		return AccessDraft{}, errInput
	}
	if _, e = DecodeInput(raw); e != nil {
		return AccessDraft{}, e
	}
	apply := input.Subject
	apply.ActionID = "debian.access.apply"
	apply.ActionVersion = ActionVersion
	apply.ActionInput = string(raw)
	apply.ActionInputDigest = hostaction.BytesDigest(raw)
	requests := []generated.HostActionRequest{apply}
	ops := []generated.PlanOperation{}
	seq := generated.HostAccessSequence{Schema: generated.SchemaIDHostAccessSequence, SchemaVersion: "1.0.0", SubjectHostID: apply.HostID, SubjectIdentityDigest: input.Input.HostIdentityDigest, ProfileLockDigest: input.Input.ProfileLockDigest, ApplyOperationID: "access-apply", ApplyDraftDigest: hostaction.Digest(apply), ProbeSteps: []generated.HostAccessProbeStep{}, ConfirmOperationID: "access-confirm"}
	for i, p := range input.Probes {
		request := p.Request
		opID := fmt.Sprintf("access-probe-%02d", i+1)
		kind := p.Kind
		contextDigest := input.Input.HostIdentityDigest
		if kind == "collect" {
			request.ActionID = "debian.access.collect"
			request.ActionInput = apply.ActionInput
		} else {
			var probe generated.AccessProbeInput
			if json.Unmarshal([]byte(request.ActionInput), &probe) != nil {
				return AccessDraft{}, errInput
			}
			probe.ApplyInputDigest = apply.ActionInputDigest
			probe.RollbackDigest = input.Input.RollbackDigest
			probe.SubjectHostID = apply.HostID
			probe.SubjectIdentityDigest = input.Input.HostIdentityDigest
			probe.ProfileLockDigest = input.Input.ProfileLockDigest
			contextDigest = probe.Source.ContextDigest
			bytes, _ := json.Marshal(probe)
			request.ActionInput = string(bytes)
			if kind == "local-probe" {
				request.ActionID = "debian.access.probe.local"
			} else {
				request.ActionID = "debian.access.probe-source"
			}
		}
		request.ActionVersion = ActionVersion
		request.ActionInputDigest = hostaction.BytesDigest([]byte(request.ActionInput))
		requests = append(requests, request)
		seq.ProbeSteps = append(seq.ProbeSteps, generated.HostAccessProbeStep{Schema: generated.SchemaIDHostAccessProbeStep, SchemaVersion: "1.0.0", OperationID: opID, Kind: kind, SourceHostID: request.HostID, SourceIdentityDigest: request.ConsoleConfirmation.HostIdentityDigest, SourceContextDigest: contextDigest, DraftDigest: hostaction.Digest(request), SpecificationDigest: request.ActionInputDigest})
	}
	seq.AuxiliaryTargets, e = SequenceAuxiliaryTargets(requests)
	if e != nil {
		return AccessDraft{}, errInput
	}
	seq.SpecificationDigest = SequenceSpecificationDigest(seq)
	confirm := apply
	confirm.ActionID = "debian.access.confirm"
	confirm.IdempotencyKey = apply.IdempotencyKey + ":confirm"
	confirmation := generated.AccessConfirmInput{Schema: generated.SchemaIDAccessConfirmInput, SchemaVersion: "1.0.0", HostID: apply.HostID, HostIdentityDigest: input.Input.HostIdentityDigest, ProfileLockDigest: input.Input.ProfileLockDigest, RollbackDigest: input.Input.RollbackDigest, ApplyOperationID: seq.ApplyOperationID, ApplyDraftDigest: seq.ApplyDraftDigest, ApplyInputDigest: apply.ActionInputDigest, ProbeSpecificationDigest: seq.SpecificationDigest}
	raw, _ = json.Marshal(confirmation)
	confirm.ActionInput = string(raw)
	confirm.ActionInputDigest = hostaction.BytesDigest(raw)
	requests = append(requests, confirm)
	seq.ConfirmDraftDigest = hostaction.Digest(confirm)
	seq.Actions = requests
	bindings := []credentialref.StepBinding{}
	for i, request := range requests {
		opID := seq.ApplyOperationID
		typ := hostaction.OperationType
		if i == len(requests)-1 {
			opID = seq.ConfirmOperationID
		} else if i > 0 {
			opID = seq.ProbeSteps[i-1].OperationID
			if seq.ProbeSteps[i-1].Kind == "local-probe" {
				typ = LocalProbeOperation
			}
		}
		bindings = append(bindings, credentialref.StepBinding{OperationID: opID, AdapterID: hostaction.AdapterID, TargetID: request.HostID, ReferenceID: request.CredentialReferenceID, ConsumerID: hostaction.AdapterID, PurposeID: hostaction.PurposeID, MaterialVersion: request.CredentialMaterialVersion, ResolverID: "native-systemd", StateRevision: apply.ExpectedStateRevision + 3, RecoveryEpoch: apply.RecoveryEpoch})
		ops = append(ops, generated.PlanOperation{Sequence: int64(i + 1), OperationID: opID, OperationType: typ, AdapterID: hostaction.AdapterID, ExecutorID: "executor-central", TargetID: request.HostID, ArtifactDigest: hostaction.Digest(request)})
	}
	for i := range ops {
		ops[i].InputDigest = credentialref.OperationManifestDigest(bindings, ops[i].OperationID)
	}
	checked, e := Sequence(ops, requests)
	if e != nil || hostaction.Digest(checked) != hostaction.Digest(seq) {
		return AccessDraft{}, errInput
	}
	return AccessDraft{Requests: requests, Operations: ops, Bindings: bindings, Sequence: seq}, nil
}
