package nativecredential

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/vegastack/vegastack-labs/internal/credentialref"
)

type receiptSequence struct {
	receipt credentialref.NativeLoadedReceipt
	calls   int
	revoke  bool
}

func (r *receiptSequence) ReadNativeLoadedReceipt(context.Context, credentialref.StepBinding) (credentialref.NativeLoadedReceipt, error) {
	r.calls++
	if r.revoke && r.calls > 1 {
		return credentialref.NativeLoadedReceipt{}, errors.New("revoked")
	}
	return r.receipt, nil
}
func loadedReceiptFixture() (credentialref.NativeLoadedReceipt, credentialref.StepBinding) {
	fingerprint := "sha256:" + strings.Repeat("a", 64)
	b := credentialref.LifecycleBinding{OperationID: "activate-a", Action: credentialref.ActionActivate, ReferenceID: "reference-a", ConsumerIDs: []string{"consumer-a"}, RequiredDeniedConsumerIDs: []string{"denied-a"}, NativeArtifactConsumerID: "consumer-a", MaterialVersion: "version-a", ResolverID: "native-systemd", TargetID: "target-a", CiphertextFingerprint: fingerprint, StateRevision: 3, RecoveryEpoch: 1}
	b.NativeConsumers = []credentialref.NativeConsumerBinding{{ConsumerID: "consumer-a", TargetID: b.TargetID, HostMachineID: strings.Repeat("a", 32), UnitName: "a.service", ServiceUID: 1001, ServiceGID: 1001, ProfileID: "profile-a", RoleID: "role-a", LoadedName: credentialref.LoadedNameForVersion("consumer-a", b.ReferenceID, b.MaterialVersion)}}
	b.NativeDeniedReaders = []credentialref.NativeDeniedReaderBinding{{ConsumerID: "denied-a", TargetID: b.TargetID, HostMachineID: strings.Repeat("a", 32), ReaderUID: 2001, ReaderGID: 2001, ProfileID: "profile-a", RoleID: "denied-a"}}
	r := credentialref.NativeLoadedReceipt{Version: 1, Binding: b, ConsumerID: "consumer-a", PlanDigest: fingerprint, RunID: "run-a", StepID: "step-a", Proof: credentialref.NativeInvocationMetadata{BootID: "00000000-0000-0000-0000-000000000001", InvocationID: strings.Repeat("b", 32), MainPID: 42, ProcessStartTicks: 7, NamespaceDevice: 1, NamespaceInode: 2, CredentialDevice: 3, CredentialInode: 4, CredentialUID: 1001, CredentialGID: 1001, CredentialMode: 0100400, SourceDevice: 5, SourceInode: 6, SourceFingerprint: fingerprint}}
	return r, credentialref.StepBinding{OperationID: "execute-a", AdapterID: "adapter-a", ReferenceID: b.ReferenceID, ConsumerID: r.ConsumerID, PurposeID: "purpose-a", TargetID: b.TargetID, MaterialVersion: b.MaterialVersion, ResolverID: b.ResolverID, StateRevision: 5, RecoveryEpoch: 1}
}
func TestLoadedObserverRequiresPersistedCurrentInvocation(t *testing.T) {
	good, b := loadedReceiptFixture()
	for _, name := range []string{"current", "legacy", "other-process", "changed-source", "revoked-during-check", "wrong-epoch"} {
		t.Run(name, func(t *testing.T) {
			seq := &receiptSequence{receipt: good}
			pid := 42
			step := b
			checks := 0
			switch name {
			case "legacy":
				seq.receipt = credentialref.NativeLoadedReceipt{}
			case "other-process":
				pid = 43
			case "changed-source":
				seq.receipt.Proof.SourceInode++
			case "revoked-during-check":
				seq.revoke = true
			case "wrong-epoch":
				step.RecoveryEpoch++
			}
			observer := installedLoadedObserver{receipts: seq, currentPID: func() int { return pid }, recheck: func(_ context.Context, r credentialref.NativeLoadedReceipt, _ credentialref.NativeConsumerBinding) error {
				checks++
				if r.Proof != good.Proof {
					return errors.New("invocation changed")
				}
				return nil
			}}
			loaded, err := observer.ObserveLoaded(context.Background(), step)
			if name == "current" {
				if err != nil || loaded.Inode != good.Proof.CredentialInode || seq.calls != 2 || checks != 1 {
					t.Fatal("current proof not rechecked", loaded, err)
				}
			} else if err == nil {
				t.Fatal("unqualified receipt accepted")
			}
		})
	}
}
