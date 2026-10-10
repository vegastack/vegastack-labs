package qualification

// Synthetic inputs mirror the owning debianaccess sequence fixture. The owning
// validator builds the sequence; no infrastructure or native qualification is claimed.
import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"github.com/vegastack/vegastack-labs/internal/debianaccess"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"golang.org/x/crypto/ssh"
	"strings"
	"testing"
)

func nativeSequenceInput(t *testing.T) generated.DebianAccessInput {
	t.Helper()
	public, _, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	key, e := ssh.NewPublicKey(public)
	if e != nil {
		t.Fatal(e)
	}
	k := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key)))
	d := hostaction.BytesDigest([]byte("synthetic-qualified-lock"))
	a := generated.AccessAccount{Schema: generated.SchemaIDAccessAccount, SchemaVersion: "1.0.0", Name: "automation", UID: 1001, GID: 1001, Home: "/home/automation", Role: "automation", PublicKeys: []string{k}, PublicKeyDigests: []string{hostaction.BytesDigest([]byte(k))}}
	lock := generated.DebianProfileLock{Schema: generated.SchemaIDDebianProfileLock, SchemaVersion: "1.0.0", ImageDigest: d, OSFamily: "debian", OSVersion: "13.6", Architecture: "amd64", PackageSourceDigest: d, Packages: []generated.AccessPackage{{Schema: generated.SchemaIDAccessPackage, SchemaVersion: "1.0.0", Name: "openssh-server", Version: "synthetic-test"}}, ExecutableVersion: "1.0.0", AnsibleVersion: "synthetic-test", AnsibleExecutableDigest: d, CollectionDigest: d, RoleDigest: d, Backend: "iptables-nft"}
	in := generated.DebianAccessInput{Schema: generated.SchemaIDDebianAccessInput, SchemaVersion: "1.0.0", HostID: "test-host", HostIdentityDigest: d, ProfileID: "test-profile", ProfileLock: lock, ProfileLockDigest: hostaction.Digest(lock), ActionVersion: "1.0.0", AutomationUID: 1001, Accounts: []generated.AccessAccount{a}, SSHUsers: []string{"automation"}, SSHSourcePrefixes: []string{"192.0.2.0/24"}, RecoverySourcePrefixes: []string{"192.0.2.1/32"}, PrivilegedServiceKeys: []generated.AccessServiceKey{}, Interfaces: []generated.AccessInterface{{Schema: generated.SchemaIDAccessInterface, SchemaVersion: "1.0.0", Name: "eth0", Index: 2, Addresses: []string{"192.0.2.2"}}}, HostFlows: []generated.AccessFlow{}, ContainerFlows: []generated.AccessFlow{}}
	in.RollbackSpecification = generated.AccessRollbackSpecification{Schema: generated.SchemaIDAccessRollbackSpecification, SchemaVersion: "1.0.0", HostID: in.HostID, HostIdentityDigest: d, ProfileLockDigest: in.ProfileLockDigest, DeadlineSeconds: 600, RecoverySourcePrefixes: in.RecoverySourcePrefixes, OwnedState: []generated.AccessOwnedState{{Schema: generated.SchemaIDAccessOwnedState, SchemaVersion: "1.0.0", ResourceID: "ssh-config", BeforeDigest: d, AfterDigest: d}}}
	in.RollbackDigest = hostaction.Digest(in.RollbackSpecification)
	in.RenderedAccess = generated.RenderedAccess{Schema: generated.SchemaIDRenderedAccess, SchemaVersion: "1.0.0", ProfileLockDigest: in.ProfileLockDigest, RendererDigest: d, Accounts: in.Accounts, SSHUsers: in.SSHUsers, SSHSourcePrefixes: in.SSHSourcePrefixes, RecoverySourcePrefixes: in.RecoverySourcePrefixes, PrivilegedServiceKeys: in.PrivilegedServiceKeys, Interfaces: in.Interfaces, HostFlows: in.HostFlows, ContainerFlows: in.ContainerFlows, RollbackUnitsDigest: d}
	in.RenderedAccessDigest = hostaction.Digest(in.RenderedAccess)
	return in
}
func nativeSequenceRequests(t *testing.T) ([]generated.PlanOperation, []generated.HostActionRequest) {
	in := nativeSequenceInput(t)
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
		destination := tuple
		if i == 5 {
			destination.Port = 1
		}
		probe.Cases = append(probe.Cases, generated.AccessProbeCase{Schema: generated.SchemaIDAccessProbeCase, SchemaVersion: "1.0.0", ProbeID: fmt.Sprintf("probe-%d", i), Kind: kind, Expected: expected, Destination: destination, Witness: tuple})
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
			typ = debianaccess.LocalProbeOperation
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
	raw, _ = json.Marshal(generated.AccessConfirmInput{Schema: generated.SchemaIDAccessConfirmInput, SchemaVersion: "1.0.0", HostID: in.HostID, HostIdentityDigest: in.HostIdentityDigest, ProfileLockDigest: in.ProfileLockDigest, RollbackDigest: in.RollbackDigest, ApplyOperationID: "apply", ApplyDraftDigest: seq.ApplyDraftDigest, ApplyInputDigest: apply.ActionInputDigest, ProbeSpecificationDigest: debianaccess.SequenceSpecificationDigest(seq)})
	confirm.ActionInput = string(raw)
	confirm.ActionInputDigest = hostaction.BytesDigest(raw)
	requests = append(requests, confirm)
	ops = append(ops, generated.PlanOperation{Sequence: 5, OperationID: "confirm", OperationType: hostaction.OperationType, AdapterID: hostaction.AdapterID, ExecutorID: "executor-central", TargetID: confirm.HostID, InputDigest: d, ArtifactDigest: hostaction.Digest(confirm)})
	return ops, requests
}
func nativeSequenceExecutions(t *testing.T) []ProducerExecution {
	t.Helper()
	ops, requests := nativeSequenceRequests(t)
	seq, err := debianaccess.Sequence(ops, requests)
	if err != nil {
		t.Fatal(err)
	}
	in, err := debianaccess.DecodeInput([]byte(requests[0].ActionInput))
	if err != nil {
		t.Fatal(err)
	}
	d := hostaction.Digest("fixture")
	record := hostaction.Digest("rollback-record")
	plan := generated.Plan{PlanID: "plan-a", PlanDigest: d, Operations: ops, HostAccessSequence: &seq}
	var out []ProducerExecution
	var aggregate []string
	for i, r := range requests {
		var ms []generated.AccessMeasurement
		switch r.ActionID {
		case "debian.access.apply", "debian.access.collect":
			for _, control := range []struct{ id, kind string }{{"debian.accounts", "account"}, {"debian.ssh", "ssh"}, {"debian.host-firewall", "host-flow"}, {"debian.container-firewall", "container-flow"}} {
				m := generated.AccessMeasurement{ControlID: control.id, Kind: control.kind, Status: "passed", ProducerID: "debian-access-native", ConfigurationDigest: in.RenderedAccessDigest, Reason: "measured"}
				if control.id == "debian.container-firewall" {
					m.Status = "partial"
					m.Reason = "container-not-installed"
				}
				if i == 0 {
					m.RollbackRecordDigest = record
				}
				ms = append(ms, m)
			}
		case "debian.access.probe.local", "debian.access.probe-source":
			var p generated.AccessProbeInput
			if json.Unmarshal([]byte(r.ActionInput), &p) != nil {
				t.Fatal("probe")
			}
			for _, c := range p.Cases {
				probe := generated.AccessProbeObservation{Schema: generated.SchemaIDAccessProbeObservation, SchemaVersion: "1.0.0", ProbeID: c.ProbeID, SourceHostID: p.Source.HostID, SourceIdentityDigest: p.Source.IdentityDigest, SourceContextDigest: p.Source.ContextDigest, ActualSourceAddress: p.Source.Address, SourceNamespaceDigest: d, DestinationDigest: hostaction.Digest(c.Destination), WitnessDigest: d, Expected: c.Expected, Actual: c.Expected}
				kind := "host-flow"
				if strings.HasPrefix(c.Kind, "ssh-") {
					kind = "ssh"
				}
				m := generated.AccessMeasurement{ControlID: c.ProbeID, Kind: kind, Status: "passed", ProducerID: "debian-access-probe", ConfigurationDigest: p.ApplyInputDigest, Reason: "measured", Probe: &probe, PositiveProbeDigest: d, NegativeProbeDigest: d}
				if c.Expected == "allowed" {
					m.PositiveProbeDigest = hostaction.Digest(probe)
				} else {
					m.NegativeProbeDigest = hostaction.Digest(probe)
				}
				ms = append(ms, m)
			}
		case "debian.access.confirm":
			ms = []generated.AccessMeasurement{{ControlID: "debian-access-confirm", Kind: "identity", Status: "passed", ProducerID: "debian-access-native", ConfigurationDigest: requests[0].ActionInputDigest, Reason: "independent-probes-confirmed", PositiveProbeDigest: hostaction.Digest(aggregate), NegativeProbeDigest: hostaction.Digest(aggregate), RollbackRecordDigest: record}}
		}
		for j := range ms {
			m := &ms[j]
			m.Schema = generated.SchemaIDAccessMeasurement
			m.SchemaVersion = "1.0.0"
			m.SubjectHostID = in.HostID
			m.SubjectIdentityDigest = in.HostIdentityDigest
			m.ProfileLockDigest = in.ProfileLockDigest
			m.ProducerVersion = "1.0.0"
			m.BundleDigest = d
			m.ObservedAt = "2026-10-09T00:00:00Z"
			if m.PositiveProbeDigest == "" {
				m.PositiveProbeDigest = d
			}
			if m.NegativeProbeDigest == "" {
				m.NegativeProbeDigest = d
			}
			m.MeasurementDigest = hostaction.MeasurementDigest(*m)
		}
		result := generated.HostActionResult{Schema: generated.SchemaIDHostActionResult, SchemaVersion: "1.0.0", BundleDigest: d, Status: "succeeded", Changed: i == 0, EffectObserved: true, Reason: "access-observed", ControlMeasurements: ms}
		result.ResultDigest = hostaction.ResultDigest(result)
		receipt := generated.ExecutionReceipt{Schema: generated.SchemaIDExecutionReceipt, SchemaVersion: "1.0.0", OperationID: ops[i].OperationID, ArtifactDigest: ops[i].ArtifactDigest, TargetID: r.HostID, ResultDigest: result.ResultDigest, Status: "succeeded"}
		out = append(out, ProducerExecution{Reference: generated.NativeProducerReference{HostID: r.HostID, RunID: "run-a"}, Plan: plan, Receipt: receipt, Result: &result})
		if i < len(requests)-1 {
			for _, m := range ms {
				aggregate = append(aggregate, hostaction.Digest([]string{ops[i].OperationID, m.MeasurementDigest, hostaction.Digest(receipt), result.ResultDigest}))
			}
		}
	}
	return out
}
func TestNativeCompleteAccessSequenceRequiresEveryActualReceipt(t *testing.T) {
	es := nativeSequenceExecutions(t)
	if _, _, err := validateNativeAccessSequence(es, false); err != nil {
		t.Fatal("complete owning sequence", err)
	}
	for _, variant := range []string{"missing-source", "other-run", "forged-confirm", "missing-probe"} {
		t.Run(variant, func(t *testing.T) {
			v := nativeSequenceExecutions(t)
			switch variant {
			case "missing-source":
				v = append(v[:3], v[4:]...)
			case "other-run":
				v[2].Reference.RunID = "other"
			case "forged-confirm":
				v[4].Result.ControlMeasurements[0].PositiveProbeDigest = hostaction.Digest("other")
				v[4].Result.ControlMeasurements[0].MeasurementDigest = hostaction.MeasurementDigest(v[4].Result.ControlMeasurements[0])
				v[4].Result.ResultDigest = hostaction.ResultDigest(*v[4].Result)
				v[4].Receipt.ResultDigest = v[4].Result.ResultDigest
			case "missing-probe":
				v[2].Result.ControlMeasurements = v[2].Result.ControlMeasurements[:1]
				v[2].Result.ResultDigest = hostaction.ResultDigest(*v[2].Result)
				v[2].Receipt.ResultDigest = v[2].Result.ResultDigest
			}
			if _, _, err := validateNativeAccessSequence(v, false); err == nil {
				t.Fatal("incomplete/substituted sequence accepted")
			}
		})
	}
}
