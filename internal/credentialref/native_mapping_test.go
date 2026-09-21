package credentialref

import "testing"

func TestNativeMappingSeal(t *testing.T) {
	binding := validActivateBinding()
	binding.NativeConsumers = []NativeConsumerBinding{
		{ConsumerID: "consumer-a", TargetID: "target-a", HostMachineID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", UnitName: "alpha.service", ServiceUID: 1001, ServiceGID: 1001, ProfileID: "profile-a", RoleID: "role-a", LoadedName: LoadedNameForVersion("consumer-a", "reference-a", "version-a")},
		{ConsumerID: "consumer-b", TargetID: "target-a", HostMachineID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", UnitName: "beta.service", ServiceUID: 1002, ServiceGID: 1002, ProfileID: "profile-a", RoleID: "role-b", LoadedName: LoadedNameForVersion("consumer-b", "reference-a", "version-a")},
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
}
