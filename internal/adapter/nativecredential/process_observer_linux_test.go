//go:build linux

package nativecredential

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/vegastack/vegastack-labs/internal/credentialref"
)

type sequenceUnits struct {
	items []AppliedUnitSnapshot
	next  int
}

func (s *sequenceUnits) ObserveAppliedUnit(_ context.Context, _ string) (AppliedUnitSnapshot, error) {
	if s.next >= len(s.items) {
		return AppliedUnitSnapshot{}, errAppliedUnit
	}
	item := s.items[s.next]
	s.next++
	return item, nil
}

type fixedAuthority struct{ probes int }

func (*fixedAuthority) Restart(context.Context, string) (RestartReceipt, error) {
	return RestartReceipt{UnitName: "alpha.service", BootID: "00000000-0000-0000-0000-000000000001", RequestMonotonicNanos: 1000, FinishMonotonicNanos: 1500, Status: "completed"}, nil
}
func (a *fixedAuthority) Probe(context.Context, AccessProbeRequest) (AccessProbeResult, error) {
	a.probes++
	return AccessProbeResult{Status: AccessProbeOpened, Device: 2, Inode: 3, OwnerUID: 1001, OwnerGID: 1001, Mode: 0o100400}, nil
}

func nativeInvocationFixture() (invocationObserver, credentialref.LifecycleBinding, credentialref.NativeConsumerBinding, *sequenceUnits, *fixedAuthority) {
	root := "/sealed"
	name := credentialref.LoadedNameForVersion("consumer-a", "reference-a", "version-a")
	binding := credentialref.LifecycleBinding{ReferenceID: "reference-a", MaterialVersion: "version-a", NativeArtifactConsumerID: "consumer-a", CiphertextFingerprint: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
	reader := credentialref.NativeConsumerBinding{ConsumerID: "consumer-a", UnitName: "alpha.service", HostMachineID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", ServiceUID: 1001, ServiceGID: 1001, LoadedName: name}
	base := AppliedUnitSnapshot{UnitName: reader.UnitName, MachineID: reader.HostMachineID, BootID: "00000000-0000-0000-0000-000000000001", InvocationID: "11111111111111111111111111111111", ActiveState: "active", MainPID: 41, ExecMainStartMonotonicUSec: 2, User: "1001", Group: "1001", EncryptedSources: []CredentialSource{{ID: name, AbsolutePath: filepath.Join(root, name)}}}
	after := base
	after.InvocationID = "22222222222222222222222222222222"
	after.MainPID = 42
	units := &sequenceUnits{items: []AppliedUnitSnapshot{base, after, after}}
	authority := &fixedAuthority{}
	observer := invocationObserver{units: units, authority: authority, root: root, ownerUID: 0,
		inspect: func(context.Context, InspectRequest) (CiphertextInspection, error) {
			return CiphertextInspection{State: "present", Fingerprint: binding.CiphertextFingerprint, Device: 4, Inode: 5}, nil
		},
		process: func(context.Context, AppliedUnitSnapshot, credentialref.NativeConsumerBinding) (ProcessIdentity, error) {
			return ProcessIdentity{MainPID: 42, StartTicks: 7, UID: 1001, GID: 1001, NamespaceDevice: 6, NamespaceInode: 8}, nil
		},
	}
	return observer, binding, reader, units, authority
}

func TestInvocationReplacement(t *testing.T) {
	observer, binding, reader, units, authority := nativeInvocationFixture()
	units.items[2].MainPID = 43
	if _, err := observer.observe(context.Background(), binding, reader); err == nil {
		t.Fatal("PID replacement during proof accepted")
	}
	if authority.probes == 0 {
		t.Fatal("test never reached the observation boundary")
	}
}

func TestInvocationExactProof(t *testing.T) {
	observer, binding, reader, _, authority := nativeInvocationFixture()
	proof, err := observer.observe(context.Background(), binding, reader)
	if err != nil || proof.MainPID != 42 || proof.CredentialInode != 3 || proof.SourceInode != 5 || authority.probes != 2 {
		t.Fatalf("exact invocation proof unavailable: %+v %v", proof, err)
	}
}

func TestProcessStatusIdentity(t *testing.T) {
	if !procStatusIdentityMatches("Name:\ttest\nUid:\t1001\t1001\t1001\t1001\nGid:\t1002\t1002\t1002\t1002\n", 1001, 1002) {
		t.Fatal("exact process identity rejected")
	}
	if procStatusIdentityMatches("Uid:\t1001\t0\t1001\t1001\nGid:\t1002\t1002\t1002\t1002\n", 1001, 1002) {
		t.Fatal("effective root identity accepted")
	}
}
