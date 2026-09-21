//go:build linux

package nativecredential

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/generated"
	"github.com/vegastack/vegastack-labs/internal/run"
)

// This test only runs in the separately created, disposable Debian VM. It is
// not a fixture-only substitute for the systemd credential acceptance lane.
func TestDisposableNativeLifecycle(t *testing.T) {
	if os.Getenv("VSK141_DISPOSABLE") != "1" {
		t.Skip("requires approved disposable systemd VM")
	}
	if os.Geteuid() != 21141 {
		t.Fatal("disposable verifier must run as the unprivileged service account")
	}
	root := os.Getenv("VSK141_CIPHERTEXT_ROOT")
	fingerprint := os.Getenv("VSK141_FINGERPRINT")
	machine := os.Getenv("VSK141_MACHINE_ID")
	name := credentialref.LoadedNameForVersion("consumer-a", "reference-a", "version-a")
	binding := credentialref.LifecycleBinding{OperationID: "operation-a", Action: credentialref.ActionActivate, ReferenceID: "reference-a",
		ConsumerIDs: []string{"consumer-a", "consumer-b"}, RequiredDeniedConsumerIDs: []string{"denied-a", "denied-b"}, NativeArtifactConsumerID: "consumer-a",
		NativeConsumers: []credentialref.NativeConsumerBinding{
			{ConsumerID: "consumer-a", TargetID: "target-a", HostMachineID: machine, UnitName: "vsk141-alpha.service", ServiceUID: 21142, ServiceGID: 21142, ProfileID: "profile-a", RoleID: "role-a", LoadedName: name},
			{ConsumerID: "consumer-b", TargetID: "target-a", HostMachineID: machine, UnitName: "vsk141-beta.service", ServiceUID: 21143, ServiceGID: 21143, ProfileID: "profile-a", RoleID: "role-b", LoadedName: name},
		},
		NativeDeniedReaders: []credentialref.NativeDeniedReaderBinding{
			{ConsumerID: "denied-a", TargetID: "target-a", HostMachineID: machine, ReaderUID: 21144, ReaderGID: 21144, ProfileID: "profile-a", RoleID: "role-denied-a"},
			{ConsumerID: "denied-b", TargetID: "target-a", HostMachineID: machine, ReaderUID: 21145, ReaderGID: 21145, ProfileID: "profile-a", RoleID: "role-denied-b"},
		}, MaterialVersion: "version-a", ResolverID: "native-systemd", TargetID: "target-a", CiphertextFingerprint: fingerprint, StateRevision: 12, RecoveryEpoch: 3,
	}
	step := run.ExactStepBinding{Step: generated.RunStep{OperationID: binding.OperationID, OperationType: string(binding.Action), TargetID: binding.TargetID, ArtifactDigest: binding.CiphertextFingerprint}}
	verifier, err := NewInstalledNativeLifecycleVerifier(context.Background(), root, 21141)
	if err == nil {
		var result []credentialref.ConsumerVerification
		result, err = verifier.Verify(context.Background(), step, binding)
		if err == nil && os.Getenv("VSK141_EXPECT_DENIAL") != "1" {
			if len(result) != 4 || result[0].Result != "verified" || result[1].Result != "verified" || result[2].Result != "denied" || result[3].Result != "denied" {
				t.Fatalf("native result set is incomplete: %d", len(result))
			}
		}
	}
	if os.Getenv("VSK141_EXPECT_DENIAL") == "1" {
		if err == nil {
			t.Fatal("tampered native source or authority was accepted")
		}
		return
	}
	if err != nil || !credentialref.ValidLifecycleBinding(binding) || !strings.HasPrefix(fingerprint, "sha256:") {
		t.Fatalf("real native lifecycle proof unavailable: %v", err)
	}
}
