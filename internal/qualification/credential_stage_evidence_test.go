package qualification

import (
	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/hostaction"
	"strings"
	"testing"
)

func TestCredentialSSHRequiresExactAuthenticatedSourceAndOutcome(t *testing.T) {
	d := hostaction.Digest("identity")
	in := generated.DebianAccessInput{HostID: "subject", HostIdentityDigest: d, SSHUsers: []string{"administrator"}, SSHSourcePrefixes: []string{"192.0.2.0/24"}}
	o := generated.NativeSshObservation{HostKeyVerified: true, Outcomes: []string{"allowed"}, PublicKeyDigest: d, DestinationHostID: "subject", DestinationIdentityDigest: d, User: "administrator", SourceAddress: "192.0.2.10"}
	if err := validateCredentialSSH(o, "allowed", in); err != nil {
		t.Fatal(err)
	}
	denied := o
	denied.Outcomes = []string{"denied"}
	if err := validateCredentialSSH(denied, "denied", in); err != nil {
		t.Fatal(err)
	}
	for _, variant := range []string{"wrong-user", "wrong-host", "source-excluded", "unverified-host", "transport-error"} {
		t.Run(variant, func(t *testing.T) {
			bad := o
			switch variant {
			case "wrong-user":
				bad.User = "root"
			case "wrong-host":
				bad.DestinationIdentityDigest = hostaction.Digest("other")
			case "source-excluded":
				bad.SourceAddress = "198.51.100.1"
			case "unverified-host":
				bad.HostKeyVerified = false
			case "transport-error":
				bad.Outcomes = []string{"error"}
			}
			if validateCredentialSSH(bad, "allowed", in) == nil {
				t.Fatal("invalid SSH proof accepted")
			}
		})
	}
}
func TestNativeCredentialLifecycleDoesNotInferTransitionsFromReceiptPresence(t *testing.T) {
	if validateNativeCredentialChain(nil) == nil {
		t.Fatal("missing lifecycle qualified")
	}
	if validateNativeCredentialChain([]*NativeCredentialEvidence{{}, {}, {}, {}, {}}) == nil {
		t.Fatal("five empty projections qualified")
	}
	if validateCredentialScenarioEvidence([]ProducerExecution{{Receipt: generated.ExecutionReceipt{Status: "succeeded"}}}, []generated.NativeObservation{{}}) == nil {
		t.Fatal("receipt presence qualified credentials")
	}
}

func credentialChainFixture(t *testing.T) []*NativeCredentialEvidence {
	t.Helper()
	text := func(s string) *string { return &s }
	number := func(n int64) *int64 { return &n }
	var out []*NativeCredentialEvidence
	for i, action := range []credentialref.LifecycleAction{credentialref.ActionStage, credentialref.ActionActivate, credentialref.ActionStage, credentialref.ActionRotate, credentialref.ActionRevoke} {
		version := "version-old"
		if i == 2 || i == 3 {
			version = "version-current"
		}
		b := credentialref.LifecycleBinding{OperationID: "operation-a", Action: action, ReferenceID: "reference-a", ConsumerIDs: []string{"consumer-a"}, MaterialVersion: version, ResolverID: "native-systemd", TargetID: "target-a", CiphertextFingerprint: hostaction.Digest(version), StateRevision: int64(i + 2)}
		status := "active"
		switch action {
		case credentialref.ActionStage:
			status = "staged"
			b.DraftID = text("draft-a")
			b.ImportDraftStateRevision = number(1)
			b.ImportDraftConsumerID = text("consumer-a")
			b.ImportDraftPurposeID = text("purpose-a")
		case credentialref.ActionRevoke:
			status = "revoked"
			b.ConsumerIDs = nil
		case credentialref.ActionRotate:
			b.DraftID = text("draft-a")
			b.ImportDraftStateRevision = number(1)
			b.ImportDraftConsumerID = text("consumer-a")
			b.ImportDraftPurposeID = text("purpose-a")
			b.PriorMaterialVersion = text("version-old")
			b.OverlapSeconds = 900
		}
		if action == credentialref.ActionActivate || action == credentialref.ActionRotate {
			b.RequiredDeniedConsumerIDs = []string{"denied-a"}
			b.NativeArtifactConsumerID = "consumer-a"
			b.NativeConsumers = []credentialref.NativeConsumerBinding{{ConsumerID: "consumer-a", TargetID: b.TargetID, HostMachineID: strings.Repeat("a", 32), UnitName: "a.service", ServiceUID: 1001, ServiceGID: 1001, ProfileID: "profile-a", RoleID: "role-a", LoadedName: credentialref.LoadedNameForVersion("consumer-a", b.ReferenceID, version)}}
			b.NativeDeniedReaders = []credentialref.NativeDeniedReaderBinding{{ConsumerID: "denied-a", TargetID: b.TargetID, HostMachineID: strings.Repeat("a", 32), ReaderUID: 2001, ReaderGID: 2001, ProfileID: "profile-a", RoleID: "denied"}}
		}
		if !credentialref.ValidLifecycleBinding(b) {
			t.Fatalf("invalid fixture action %s", action)
		}
		v := &NativeCredentialEvidence{Binding: b, Status: status}
		if status == "active" {
			r := credentialref.NativeLoadedReceipt{Version: 1, Binding: b, ConsumerID: "consumer-a", PlanDigest: hostaction.Digest("plan"), RunID: "run-a", StepID: "step-a", Proof: credentialref.NativeInvocationMetadata{BootID: "00000000-0000-0000-0000-000000000001", InvocationID: strings.Repeat(string(rune('a'+i)), 32), MainPID: uint32(42 + i), ProcessStartTicks: uint64(i + 1), NamespaceDevice: 1, NamespaceInode: 2, CredentialDevice: 3, CredentialInode: 4, CredentialUID: 1001, CredentialGID: 1001, CredentialMode: 0100400, SourceDevice: 5, SourceInode: 6, SourceFingerprint: b.CiphertextFingerprint}}
			if !credentialref.ValidNativeLoadedReceipt(r) {
				t.Fatal("invalid receipt fixture")
			}
			v.Verifications = []credentialref.ConsumerVerification{{ConsumerID: "consumer-a", Result: "verified", NativeReceipt: &r}}
		}
		out = append(out, v)
	}
	return out
}
func TestNativeCredentialChainRequiresRealVersionAndInvocationTransitions(t *testing.T) {
	values := credentialChainFixture(t)
	if err := validateNativeCredentialChain(values); err != nil {
		t.Fatal(err)
	}
	for _, variant := range []string{"same-invocation", "wrong-prior", "unrevoked", "wrong-controller"} {
		t.Run(variant, func(t *testing.T) {
			v := credentialChainFixture(t)
			switch variant {
			case "same-invocation":
				v[3].Verifications[0].NativeReceipt.Proof.InvocationID = v[1].Verifications[0].NativeReceipt.Proof.InvocationID
			case "wrong-prior":
				s := "other-version"
				v[3].Binding.PriorMaterialVersion = &s
			case "unrevoked":
				v[4].Status = "active"
			case "wrong-controller":
				v[3].Controller.HostID = "other"
			}
			if validateNativeCredentialChain(v) == nil {
				t.Fatal("invalid lifecycle qualified")
			}
		})
	}
}
