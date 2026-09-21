package credentialref

import "testing"

func TestNativeMappingSeal(t *testing.T) {
	binding := validActivateBinding()
	binding.NativeArtifactConsumerID = "consumer-a"
	binding.NativeConsumers = []NativeConsumerBinding{
		{ConsumerID: "consumer-a", TargetID: "target-a", HostMachineID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", UnitName: "alpha.service", ServiceUID: 1001, ServiceGID: 1001, ProfileID: "profile-a", RoleID: "role-a", LoadedName: LoadedNameForVersion("consumer-a", "reference-a", "version-a")},
		{ConsumerID: "consumer-b", TargetID: "target-a", HostMachineID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", UnitName: "beta.service", ServiceUID: 1002, ServiceGID: 1002, ProfileID: "profile-a", RoleID: "role-b", LoadedName: LoadedNameForVersion("consumer-a", "reference-a", "version-a")},
	}
	binding.NativeDeniedReaders = []NativeDeniedReaderBinding{{ConsumerID: "consumer-denied", TargetID: "target-a", HostMachineID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", ReaderUID: 2001, ReaderGID: 2001, ProfileID: "profile-a", RoleID: "role-denied"}}
	before := binding.Digest()
	if before == "" {
		t.Fatal("valid native map rejected")
	}
	changed := binding
	changed.NativeConsumers = append([]NativeConsumerBinding(nil), binding.NativeConsumers...)
	changed.NativeConsumers[0].ServiceUID++
	if changed.Digest() == before {
		t.Fatal("UID must be sealed")
	}
	changed = binding
	changed.NativeDeniedReaders = nil
	if ValidLifecycleBinding(changed) {
		t.Fatal("missing denied identity accepted")
	}
	changed = binding
	changed.NativeConsumers = append([]NativeConsumerBinding(nil), binding.NativeConsumers...)
	changed.NativeConsumers[0].LoadedName = "wrong"
	if ValidLifecycleBinding(changed) {
		t.Fatal("wrong loaded name accepted")
	}
	changed = binding
	changed.NativeArtifactConsumerID = ""
	if ValidLifecycleBinding(changed) {
		t.Fatal("missing artifact origin accepted")
	}
	changed = binding
	changed.NativeArtifactConsumerID = "consumer-b"
	if ValidLifecycleBinding(changed) {
		t.Fatal("substituted artifact origin accepted")
	}
	changed.NativeConsumers = append([]NativeConsumerBinding(nil), binding.NativeConsumers...)
	for index := range changed.NativeConsumers {
		changed.NativeConsumers[index].LoadedName = LoadedNameForVersion("consumer-b", binding.ReferenceID, binding.MaterialVersion)
	}
	if !ValidLifecycleBinding(changed) || changed.Digest() == before {
		t.Fatal("valid different artifact origin must require a different plan")
	}
}
