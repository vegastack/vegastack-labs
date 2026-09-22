package api

import (
	"testing"

	"github.com/vegastack/vegastack-labs/internal/credentialref"
	"github.com/vegastack/vegastack-labs/internal/generated"
)

func TestBindNativeLifecycleReadersRequiresLocalHostAndExactMap(t *testing.T) {
	const host = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	request := generated.CredentialLifecycleRequest{
		Schema: generated.SchemaIDCredentialLifecycleRequest, SchemaVersion: "1.3.0", Action: "credential.activate",
		ReferenceID: "reference-a", ConsumerIDs: []string{"consumer-a", "consumer-b"}, RequiredDeniedConsumerIDs: []string{"consumer-denied"},
		MaterialVersion: "version-a", ResolverID: "native-systemd", TargetID: "target-a", IdempotencyKey: "key-a",
		TargetDigest: "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		NativeConsumers: &[]generated.CredentialNativeConsumer{
			{Schema: generated.SchemaIDCredentialNativeConsumer, SchemaVersion: "1.0.0", ConsumerID: "consumer-a", TargetID: "target-a", HostMachineID: host, UnitName: "alpha.service", ServiceUID: 1001, ServiceGID: 1001, ProfileID: "profile-a", RoleID: "role-a"},
			{Schema: generated.SchemaIDCredentialNativeConsumer, SchemaVersion: "1.0.0", ConsumerID: "consumer-b", TargetID: "target-a", HostMachineID: host, UnitName: "beta.service", ServiceUID: 1002, ServiceGID: 1002, ProfileID: "profile-a", RoleID: "role-b"},
		},
		NativeDeniedReaders: &[]generated.CredentialNativeDeniedReader{{Schema: generated.SchemaIDCredentialNativeDeniedReader, SchemaVersion: "1.0.0", ConsumerID: "consumer-denied", TargetID: "target-a", HostMachineID: host, ReaderUID: 2001, ReaderGID: 2001, ProfileID: "profile-a", RoleID: "role-denied"}},
	}
	binding := credentialref.LifecycleBinding{Action: credentialref.ActionActivate, ReferenceID: request.ReferenceID, ConsumerIDs: request.ConsumerIDs, RequiredDeniedConsumerIDs: request.RequiredDeniedConsumerIDs, NativeArtifactConsumerID: "consumer-a", MaterialVersion: request.MaterialVersion, ResolverID: request.ResolverID, TargetID: request.TargetID}
	if err := bindNativeLifecycleReaders(request, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", &binding); err == nil {
		t.Fatal("foreign host map accepted")
	}
	binding.NativeConsumers = nil
	binding.NativeDeniedReaders = nil
	if err := bindNativeLifecycleReaders(request, host, &binding); err != nil {
		t.Fatal(err)
	}
	want := credentialref.LoadedNameForVersion("consumer-a", "reference-a", "version-a")
	if !credentialref.ValidNativeBindings(binding) || binding.NativeConsumers[0].LoadedName != want || binding.NativeConsumers[1].LoadedName != want {
		t.Fatal("exact local map was not sealed")
	}
	request.NativeDeniedReaders = nil
	if err := bindNativeLifecycleReaders(request, host, &binding); err == nil {
		t.Fatal("missing denied identity accepted")
	}
}
