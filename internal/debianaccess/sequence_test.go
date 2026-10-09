package debianaccess

import (
	"encoding/json"
	"fmt"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"testing"
)

func accessSequenceFixture(t *testing.T) ([]generated.PlanOperation, []generated.HostActionRequest) {
	in := validInput(t)
	raw, _ := json.Marshal(in)
	d := hostaction.Digest("test-target")
	apply := generated.HostActionRequest{Schema: generated.SchemaIDHostActionRequest, SchemaVersion: "1.0.0", ActionID: "debian.access.apply", ActionVersion: "1.0.0", ActionInput: string(raw), ActionInputDigest: hostaction.BytesDigest(raw), HostID: in.HostID, TargetRevision: 1, TargetDigest: d, AutomationPrincipalID: "automation", CallerUID: 1001, CredentialReferenceID: "action-key", CredentialMaterialVersion: "version-a", ConsoleConfirmation: generated.HostActionConsoleConfirmation{Schema: generated.SchemaIDHostActionConsoleConfirmation, SchemaVersion: "1.0.0", Method: "administrator-verified-console", TargetDigest: d, HostIdentityDigest: in.HostIdentityDigest}, ExpectedStateRevision: 1, RecoveryEpoch: 0, IdempotencyKey: "apply-a"}
	collect := apply
	collect.ActionID = "debian.access.collect"
	collect.IdempotencyKey = "collect-a"
	source := generated.AccessProbeSource{Schema: generated.SchemaIDAccessProbeSource, SchemaVersion: "1.0.0", HostID: in.HostID, IdentityDigest: in.HostIdentityDigest, Kind: "host-network", ContextID: "test-context", ContextDigest: d, Interface: "eth0", InterfaceIndex: 2, Address: "192.0.2.1", Family: "ipv4", RouteDigest: d}
	tuple := generated.AccessProbeTuple{Schema: generated.SchemaIDAccessProbeTuple, SchemaVersion: "1.0.0", HostID: in.HostID, IdentityDigest: in.HostIdentityDigest, Address: "192.0.2.2", Port: 22, Protocol: "tcp"}
	probe := generated.AccessProbeInput{Schema: generated.SchemaIDAccessProbeInput, SchemaVersion: "1.0.0", SubjectHostID: in.HostID, SubjectIdentityDigest: in.HostIdentityDigest, SubjectHostKey: in.Accounts[0].PublicKeys[0], ProfileLockDigest: in.ProfileLockDigest, ApplyInputDigest: apply.ActionInputDigest, RollbackDigest: in.RollbackDigest, AdministratorUser: "automation", Source: source, Cases: []generated.AccessProbeCase{}, TimeoutMillis: 10, Attempts: 1}
	for i, kind := range []string{"ssh-admin", "ssh-wrong-user", "ssh-password", "ssh-root", "host-flow", "host-flow"} {
		expected := "denied"
		if i == 0 || i == 4 {
			expected = "allowed"
		}
		probe.Cases = append(probe.Cases, generated.AccessProbeCase{Schema: generated.SchemaIDAccessProbeCase, SchemaVersion: "1.0.0", ProbeID: fmt.Sprintf("probe-%d", i), Kind: kind, Expected: expected, Destination: tuple, Witness: tuple})
	}
	local := apply
	local.ActionID = "debian.access.probe.local"
	raw, _ = json.Marshal(probe)
	local.ActionInput = string(raw)
	local.ActionInputDigest = hostaction.BytesDigest(raw)
	local.IdempotencyKey = "local-a"
	probe.Source.HostID = "source-host"
	probe.Source.IdentityDigest = hostaction.Digest("source-host")
	probe.Source.Kind = "network-namespace"
	probe.Source.Address = "198.51.100.2"
	probe.Cases = []generated.AccessProbeCase{{Schema: generated.SchemaIDAccessProbeCase, SchemaVersion: "1.0.0", ProbeID: "probe-source", Kind: "ssh-source", Expected: "denied", Destination: tuple, Witness: tuple}}
	remote := apply
	remote.HostID = probe.Source.HostID
	remote.ConsoleConfirmation.HostIdentityDigest = probe.Source.IdentityDigest
	remote.ActionID = "debian.access.probe-source"
	remote.IdempotencyKey = "source-a"
	raw, _ = json.Marshal(probe)
	remote.ActionInput = string(raw)
	remote.ActionInputDigest = hostaction.BytesDigest(raw)
	requests := []generated.HostActionRequest{apply, collect, local, remote}
	ops := []generated.PlanOperation{}
	seq := generated.HostAccessSequence{SubjectHostID: apply.HostID, SubjectIdentityDigest: in.HostIdentityDigest, ProfileLockDigest: in.ProfileLockDigest, ApplyOperationID: "apply", ApplyDraftDigest: hostaction.Digest(apply), ProbeSteps: []generated.HostAccessProbeStep{}}
	for i, r := range requests {
		opID := fmt.Sprintf("step-%d", i)
		if i == 0 {
			opID = "apply"
		}
		kind := "collect"
		if i == 2 {
			kind = "local-probe"
		}
		if i == 3 {
			kind = "source-probe"
		}
		typ := hostaction.OperationType
		if i == 2 {
			typ = LocalProbeOperation
		}
		ops = append(ops, generated.PlanOperation{Sequence: int64(i + 1), OperationID: opID, OperationType: typ, AdapterID: hostaction.AdapterID, ExecutorID: "executor-central", TargetID: r.HostID, InputDigest: d, ArtifactDigest: hostaction.Digest(r)})
		if i > 0 {
			context := in.HostIdentityDigest
			if i > 1 {
				context = source.ContextDigest
			}
			seq.ProbeSteps = append(seq.ProbeSteps, generated.HostAccessProbeStep{Schema: generated.SchemaIDHostAccessProbeStep, SchemaVersion: "1.0.0", OperationID: opID, Kind: kind, SourceHostID: r.HostID, SourceIdentityDigest: r.ConsoleConfirmation.HostIdentityDigest, SourceContextDigest: context, DraftDigest: hostaction.Digest(r), SpecificationDigest: r.ActionInputDigest})
		}
	}
	confirm := apply
	confirm.ActionID = "debian.access.confirm"
	confirm.IdempotencyKey = "confirm-a"
	raw, _ = json.Marshal(generated.AccessConfirmInput{Schema: generated.SchemaIDAccessConfirmInput, SchemaVersion: "1.0.0", HostID: in.HostID, HostIdentityDigest: in.HostIdentityDigest, ProfileLockDigest: in.ProfileLockDigest, RollbackDigest: in.RollbackDigest, ApplyOperationID: "apply", ApplyDraftDigest: seq.ApplyDraftDigest, ApplyInputDigest: apply.ActionInputDigest, ProbeSpecificationDigest: SequenceSpecificationDigest(seq)})
	confirm.ActionInput = string(raw)
	confirm.ActionInputDigest = hostaction.BytesDigest(raw)
	requests = append(requests, confirm)
	ops = append(ops, generated.PlanOperation{Sequence: 5, OperationID: "confirm", OperationType: hostaction.OperationType, AdapterID: hostaction.AdapterID, ExecutorID: "executor-central", TargetID: confirm.HostID, InputDigest: d, ArtifactDigest: hostaction.Digest(confirm)})
	return ops, requests
}
func TestAccessSequenceRequiresExactCompleteWorkflow(t *testing.T) {
	ops, requests := accessSequenceFixture(t)
	seq, e := Sequence(ops, requests)
	if e != nil {
		t.Fatalf("complete sequence: %v", e)
	}
	if len(seq.Actions) != 5 || len(seq.AuxiliaryTargets) != 2 {
		t.Fatal("approval omits actions or source")
	}
	for _, name := range []string{"reorder", "missing-probe", "changed-apply", "changed-source", "wrong-local-type", "repeated-operation"} {
		t.Run(name, func(t *testing.T) {
			o := append([]generated.PlanOperation(nil), ops...)
			r := append([]generated.HostActionRequest(nil), requests...)
			switch name {
			case "reorder":
				o[1], o[2] = o[2], o[1]
			case "missing-probe":
				o = append(o[:3], o[4:]...)
				r = append(r[:3], r[4:]...)
			case "changed-apply":
				r[0].ActionInput = "{}"
			case "changed-source":
				r[3].HostID = "other-host"
			case "wrong-local-type":
				o[2].OperationType = hostaction.OperationType
			case "repeated-operation":
				o[3].OperationID = o[2].OperationID
			}
			if _, e := Sequence(o, r); e == nil {
				t.Fatal("changed sequence accepted")
			}
		})
	}
}
