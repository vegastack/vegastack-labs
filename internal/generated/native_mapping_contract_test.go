package generated

import "testing"

func TestNativeLifecycleRequestRequiresExactReaderMap(t *testing.T) {
	request := CredentialLifecycleRequest{
		Schema: SchemaIDCredentialLifecycleRequest, SchemaVersion: "1.3.0", Action: "credential.activate",
		ReferenceID: "reference-a", ConsumerIDs: []string{"consumer-a"}, RequiredDeniedConsumerIDs: []string{"consumer-denied"},
		MaterialVersion: "version-a", ResolverID: "native-systemd", TargetID: "target-a", IdempotencyKey: "key-a",
		TargetDigest:        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		NativeConsumers:     &[]CredentialNativeConsumer{{Schema: SchemaIDCredentialNativeConsumer, SchemaVersion: "1.0.0", ConsumerID: "consumer-a", TargetID: "target-a", HostMachineID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", UnitName: "alpha.service", ServiceUID: 1001, ServiceGID: 1001, ProfileID: "profile-a", RoleID: "role-a"}},
		NativeDeniedReaders: &[]CredentialNativeDeniedReader{{Schema: SchemaIDCredentialNativeDeniedReader, SchemaVersion: "1.0.0", ConsumerID: "consumer-denied", TargetID: "target-a", HostMachineID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", ReaderUID: 2001, ReaderGID: 2001, ProfileID: "profile-a", RoleID: "role-denied"}},
	}
	if err := ValidateLifecycleRequestSemantics(request); err != nil {
		t.Fatalf("exact native map rejected: %v", err)
	}
	request.NativeDeniedReaders = nil
	if ValidateLifecycleRequestSemantics(request) == nil {
		t.Fatal("missing denied physical identity accepted")
	}
}
