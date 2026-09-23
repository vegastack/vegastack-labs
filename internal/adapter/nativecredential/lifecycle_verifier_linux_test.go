//go:build linux

package nativecredential

import (
	"context"
	"strings"
	"testing"

	"github.com/vegastack/vegastack-labs/internal/credentialref"
)

type deniedAuthority struct{ openedUID uint32 }

func (*deniedAuthority) Restart(context.Context, string) (RestartReceipt, error) {
	return RestartReceipt{}, errProbeBlocked
}
func (a *deniedAuthority) Probe(_ context.Context, request AccessProbeRequest) (AccessProbeResult, error) {
	if request.UID == a.openedUID {
		return AccessProbeResult{Status: AccessProbeOpened, Device: 2, Inode: 3, OwnerUID: request.UID, OwnerGID: request.GID, Mode: 0o100400}, nil
	}
	return AccessProbeResult{Status: AccessProbeDenied}, nil
}

func TestExactDeniedReaders(t *testing.T) {
	name := credentialref.LoadedNameForVersion("consumer-a", "reference-a", "version-a")
	binding := credentialref.LifecycleBinding{
		OperationID: "operation-a", Action: credentialref.ActionActivate, ReferenceID: "reference-a", ConsumerIDs: []string{"consumer-a", "consumer-b"},
		RequiredDeniedConsumerIDs: []string{"denied-a", "denied-b"}, NativeArtifactConsumerID: "consumer-a",
		NativeConsumers: []credentialref.NativeConsumerBinding{
			{ConsumerID: "consumer-a", TargetID: "target-a", HostMachineID: strings.Repeat("a", 32), UnitName: "alpha.service", ServiceUID: 1001, ServiceGID: 1001, ProfileID: "profile-a", RoleID: "role-a", LoadedName: name},
			{ConsumerID: "consumer-b", TargetID: "target-a", HostMachineID: strings.Repeat("a", 32), UnitName: "beta.service", ServiceUID: 1002, ServiceGID: 1002, ProfileID: "profile-a", RoleID: "role-b", LoadedName: name},
		},
		NativeDeniedReaders: []credentialref.NativeDeniedReaderBinding{
			{ConsumerID: "denied-a", TargetID: "target-a", HostMachineID: strings.Repeat("a", 32), ReaderUID: 2001, ReaderGID: 2001, ProfileID: "profile-a", RoleID: "role-denied-a"},
			{ConsumerID: "denied-b", TargetID: "target-a", HostMachineID: strings.Repeat("a", 32), ReaderUID: 2002, ReaderGID: 2002, ProfileID: "profile-a", RoleID: "role-denied-b"},
		},
		MaterialVersion: "version-a", ResolverID: "native-systemd", TargetID: "target-a", CiphertextFingerprint: "sha256:" + strings.Repeat("a", 64), StateRevision: 12, RecoveryEpoch: 3,
	}
	step := NativeVerificationStep{OperationID: binding.OperationID, OperationType: string(binding.Action), TargetID: binding.TargetID, ArtifactDigest: binding.CiphertextFingerprint}
	authority := &deniedAuthority{openedUID: 2002}
	verifier := &NativeLifecycleVerifier{Authority: authority, policy: func(credentialref.LifecycleBinding) error { return nil },
		observe: func(_ context.Context, _ credentialref.LifecycleBinding, reader credentialref.NativeConsumerBinding) (NativeInvocationProof, error) {
			pid := uint32(42)
			if reader.UnitName == "beta.service" {
				pid = 43
			}
			return NativeInvocationProof{BootID: "00000000-0000-0000-0000-000000000001", InvocationID: strings.Repeat("1", 32), MainPID: pid, ProcessStartTicks: 7,
				NamespaceDevice: 6, NamespaceInode: 7, CredentialDevice: 2, CredentialInode: 3, CredentialUID: reader.ServiceUID, CredentialGID: reader.ServiceGID,
				CredentialMode: 0o100400, SourceDevice: 4, SourceInode: 5, SourceFingerprint: binding.CiphertextFingerprint}, nil
		},
		recheck: func(context.Context, credentialref.LifecycleBinding, credentialref.NativeConsumerBinding, NativeInvocationProof) error {
			return nil
		},
	}
	if results, err := verifier.VerifyNative(context.Background(), step, binding); err == nil || len(results) != 0 {
		t.Fatalf("unexpectedly opened denied reader was accepted: %v %+v", err, results)
	}
	authority.openedUID = 0
	if results, err := verifier.VerifyNative(context.Background(), step, binding); err != nil || len(results) != 4 {
		t.Fatalf("exact positive/denied set rejected: %v %+v", err, results)
	}
}

func TestNativePolicyMatchesSealedReaders(t *testing.T) {
	name := credentialref.LoadedNameForVersion("consumer-a", "reference-a", "version-a")
	machine := strings.Repeat("a", 32)
	binding := credentialref.LifecycleBinding{Action: credentialref.ActionActivate, ResolverID: "native-systemd", ReferenceID: "reference-a", MaterialVersion: "version-a",
		TargetID: "target-a", NativeArtifactConsumerID: "consumer-a", ConsumerIDs: []string{"consumer-a"}, RequiredDeniedConsumerIDs: []string{"denied-a"},
		NativeConsumers:     []credentialref.NativeConsumerBinding{{ConsumerID: "consumer-a", TargetID: "target-a", HostMachineID: machine, UnitName: "alpha.service", ServiceUID: 1001, ServiceGID: 1001, ProfileID: "profile-a", RoleID: "role-a", LoadedName: name}},
		NativeDeniedReaders: []credentialref.NativeDeniedReaderBinding{{ConsumerID: "denied-a", TargetID: "target-a", HostMachineID: machine, ReaderUID: 2001, ReaderGID: 2001, ProfileID: "profile-a", RoleID: "role-denied"}},
	}
	policy := probePolicy{Version: 1, MachineID: machine, Units: []string{"alpha.service"}, Probes: []probeEnrollment{
		{UnitName: "alpha.service", CredentialName: name, UID: 1001, GID: 1001},
		{UnitName: "alpha.service", CredentialName: name, UID: 2001, GID: 2001},
	}}
	if err := matchNativePolicy(policy, binding); err != nil {
		t.Fatalf("exact policy rejected: %v", err)
	}
	policy.Probes = append(policy.Probes, probeEnrollment{UnitName: "alpha.service", CredentialName: name, UID: 3001, GID: 3001})
	if err := matchNativePolicy(policy, binding); err == nil {
		t.Fatal("extra OS probe authority accepted")
	}
	policy.Probes = policy.Probes[:1]
	if err := matchNativePolicy(policy, binding); err == nil {
		t.Fatal("missing denied-reader authority accepted")
	}
}
