package credentialref

import (
	"testing"

	"github.com/vegastack/vegastack-labs/internal/generated"
)

func TestLifecycleTargetDigestSealsMetadataAndNormalizesSets(t *testing.T) {
	draft := "draft-a"
	input := generated.CredentialLifecycleRequest{Schema: generated.SchemaIDCredentialLifecycleRequest, SchemaVersion: "1.3.0", Action: "credential.stage", DraftID: &draft, ReferenceID: "reference-a", ConsumerIDs: []string{"consumer-b", "consumer-a"}, RequiredDeniedConsumerIDs: []string{}, MaterialVersion: "version-a", ResolverID: "native-systemd", TargetID: "target-a", ExpectedStateRevision: 3, RecoveryEpoch: 1, IdempotencyKey: "key-a"}
	digest := LifecycleTargetDigest(input)
	if digest == "" {
		t.Fatal("a digest must be calculable before targetDigest is populated")
	}
	input.TargetDigest = digest
	input.ConsumerIDs = []string{"consumer-a", "consumer-b"}
	if LifecycleTargetDigest(input) != digest {
		t.Fatal("set ordering changed target identity")
	}
	input.MaterialVersion = "version-b"
	if LifecycleTargetDigest(input) == digest {
		t.Fatal("material substitution retained target identity")
	}
	input.ConsumerIDs = []string{"consumer-a", "consumer-a"}
	if LifecycleTargetDigest(input) != "" {
		t.Fatal("invalid metadata had a target digest")
	}
}

func TestNativeLifecycleTargetDigestSealsPhysicalReader(t *testing.T) {
	input := generated.CredentialLifecycleRequest{
		Schema: generated.SchemaIDCredentialLifecycleRequest, SchemaVersion: "1.3.0", Action: "credential.activate",
		ReferenceID: "reference-a", ConsumerIDs: []string{"consumer-a"}, RequiredDeniedConsumerIDs: []string{"consumer-denied"},
		MaterialVersion: "version-a", ResolverID: "native-systemd", TargetID: "target-a", IdempotencyKey: "key-a",
		NativeConsumers:     &[]generated.CredentialNativeConsumer{{Schema: generated.SchemaIDCredentialNativeConsumer, SchemaVersion: "1.0.0", ConsumerID: "consumer-a", TargetID: "target-a", HostMachineID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", UnitName: "alpha.service", ServiceUID: 1001, ServiceGID: 1001, ProfileID: "profile-a", RoleID: "role-a"}},
		NativeDeniedReaders: &[]generated.CredentialNativeDeniedReader{{Schema: generated.SchemaIDCredentialNativeDeniedReader, SchemaVersion: "1.0.0", ConsumerID: "consumer-denied", TargetID: "target-a", HostMachineID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", ReaderUID: 2001, ReaderGID: 2001, ProfileID: "profile-a", RoleID: "role-denied"}},
	}
	before := LifecycleTargetDigest(input)
	if before == "" {
		t.Fatal("valid native target lacked digest")
	}
	changed := input
	readers := append([]generated.CredentialNativeDeniedReader(nil), (*input.NativeDeniedReaders)...)
	readers[0].ReaderUID++
	changed.NativeDeniedReaders = &readers
	if LifecycleTargetDigest(changed) == before {
		t.Fatal("changed denied UID retained target digest")
	}
	changed = input
	positive := append([]generated.CredentialNativeConsumer(nil), (*input.NativeConsumers)...)
	positive[0].UnitName = "beta.service"
	changed.NativeConsumers = &positive
	if LifecycleTargetDigest(changed) == before {
		t.Fatal("changed unit retained target digest")
	}
}

func TestNativeLifecycleTargetDigestRejectsPhysicalAliases(t *testing.T) {
	input := generated.CredentialLifecycleRequest{
		Schema: generated.SchemaIDCredentialLifecycleRequest, SchemaVersion: "1.3.0", Action: "credential.activate",
		ReferenceID: "reference-a", ConsumerIDs: []string{"consumer-a", "consumer-b"},
		RequiredDeniedConsumerIDs: []string{"consumer-denied", "consumer-denied-b"},
		MaterialVersion:           "version-a", ResolverID: "native-systemd", TargetID: "target-a", IdempotencyKey: "key-a",
		NativeConsumers: &[]generated.CredentialNativeConsumer{
			{Schema: generated.SchemaIDCredentialNativeConsumer, SchemaVersion: "1.0.0", ConsumerID: "consumer-a", TargetID: "target-a", HostMachineID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", UnitName: "alpha.service", ServiceUID: 1001, ServiceGID: 1001, ProfileID: "profile-a", RoleID: "role-a"},
			{Schema: generated.SchemaIDCredentialNativeConsumer, SchemaVersion: "1.0.0", ConsumerID: "consumer-b", TargetID: "target-a", HostMachineID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", UnitName: "beta.service", ServiceUID: 1002, ServiceGID: 1002, ProfileID: "profile-a", RoleID: "role-b"},
		},
		NativeDeniedReaders: &[]generated.CredentialNativeDeniedReader{
			{Schema: generated.SchemaIDCredentialNativeDeniedReader, SchemaVersion: "1.0.0", ConsumerID: "consumer-denied", TargetID: "target-a", HostMachineID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", ReaderUID: 2001, ReaderGID: 2001, ProfileID: "profile-a", RoleID: "role-denied"},
			{Schema: generated.SchemaIDCredentialNativeDeniedReader, SchemaVersion: "1.0.0", ConsumerID: "consumer-denied-b", TargetID: "target-a", HostMachineID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", ReaderUID: 2002, ReaderGID: 2002, ProfileID: "profile-a", RoleID: "role-denied-b"},
		},
	}
	if LifecycleTargetDigest(input) == "" {
		t.Fatal("distinct physical readers must have a target digest")
	}
	positiveAlias := input
	positives := append([]generated.CredentialNativeConsumer(nil), (*input.NativeConsumers)...)
	positives[1].UnitName = positives[0].UnitName
	positiveAlias.NativeConsumers = &positives
	if LifecycleTargetDigest(positiveAlias) != "" {
		t.Fatal("two positive IDs aliased one unit")
	}
	deniedAlias := input
	denied := append([]generated.CredentialNativeDeniedReader(nil), (*input.NativeDeniedReaders)...)
	denied[1].ReaderUID, denied[1].ReaderGID = denied[0].ReaderUID, denied[0].ReaderGID
	deniedAlias.NativeDeniedReaders = &denied
	if LifecycleTargetDigest(deniedAlias) != "" {
		t.Fatal("two denied IDs aliased one physical reader")
	}
}
