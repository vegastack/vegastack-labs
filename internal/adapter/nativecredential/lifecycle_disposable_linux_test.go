//go:build linux

package nativecredential

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/vegastack/vegastack-labs/internal/credentialref"
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
	step := NativeVerificationStep{OperationID: binding.OperationID, OperationType: string(binding.Action), TargetID: binding.TargetID, ArtifactDigest: binding.CiphertextFingerprint}
	if err := qualifyNativePolicy(binding); err != nil && os.Getenv("VSK141_EXPECT_DENIAL") != "1" {
		t.Fatal("installed policy does not match sealed readers")
	}
	verifier, err := NewInstalledNativeLifecycleVerifier(context.Background(), root, 21141)
	if err != nil && os.Getenv("VSK141_EXPECT_DENIAL") != "1" {
		if info, statErr := os.Lstat(root); statErr == nil {
			t.Logf("ciphertext root mode=%04o directory=%t", info.Mode().Perm(), info.IsDir())
		} else {
			t.Log("ciphertext root absent")
		}
		if policy, policyErr := readProbePolicy(probePolicyPath); policyErr == nil {
			if authority, authorityErr := NewNativeAuthority(policy.Units); authorityErr == nil {
				for _, unit := range policy.Units {
					t.Logf("authority qualification %s=%t", unit, authority.qualified(context.Background(), unit))
				}
			}
		} else {
			t.Log("installed root policy unreadable")
		}
		t.Fatal("installed native authority unavailable")
	}
	if err == nil {
		var result []credentialref.ConsumerVerification
		result, err = verifier.VerifyNative(context.Background(), step, binding)
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
		if !credentialref.ValidLifecycleBinding(binding) {
			t.Log("sealed binding invalid")
		}
		for _, reader := range binding.NativeConsumers {
			snapshot, observeErr := ObserveAppliedUnit(context.Background(), reader.UnitName)
			if observeErr != nil {
				t.Logf("applied unit unavailable: %s", reader.UnitName)
				continue
			}
			if validateAppliedSource(snapshot, binding, reader, root+"/"+reader.LoadedName) != nil {
				t.Logf("applied source mismatch: %s", reader.UnitName)
				if len(snapshot.EncryptedSources) == 1 {
					t.Logf("applied state=%s reload=%t pid=%d id-match=%t path-match=%t", snapshot.ActiveState, snapshot.NeedDaemonReload, snapshot.MainPID,
						snapshot.EncryptedSources[0].ID == reader.LoadedName, snapshot.EncryptedSources[0].AbsolutePath == root+"/"+reader.LoadedName)
				}
			}
			if _, processErr := observeProcessIdentity(context.Background(), snapshot, reader); processErr != nil {
				t.Logf("process observer blocked: %s: %v", reader.UnitName, processErr)
			}
			if _, proofErr := verifier.observe(context.Background(), binding, reader); proofErr != nil {
				t.Logf("invocation observer blocked: %s: %v", reader.UnitName, proofErr)
			} else {
				t.Logf("invocation observer passed: %s", reader.UnitName)
			}
		}
		t.Fatalf("real native lifecycle proof unavailable: %v", err)
	}
}
