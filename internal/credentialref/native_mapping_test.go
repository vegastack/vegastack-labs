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

func TestNativeMappingRejectsPhysicalReaderAliases(t *testing.T) {
	base := validActivateBinding()
	base.RequiredDeniedConsumerIDs = []string{"consumer-denied", "consumer-denied-b"}
	base.NativeDeniedReaders = append(base.NativeDeniedReaders, NativeDeniedReaderBinding{
		ConsumerID: "consumer-denied-b", TargetID: "target-a", HostMachineID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		ReaderUID: 2002, ReaderGID: 2002, ProfileID: "profile-a", RoleID: "role-denied-b",
	})
	if !ValidLifecycleBinding(base) {
		t.Fatal("distinct physical readers must be valid")
	}
	positiveAlias := base
	positiveAlias.NativeConsumers = append([]NativeConsumerBinding(nil), base.NativeConsumers...)
	positiveAlias.NativeConsumers[1].UnitName = positiveAlias.NativeConsumers[0].UnitName
	if ValidLifecycleBinding(positiveAlias) || positiveAlias.Digest() != "" {
		t.Fatal("two positive IDs aliased one physical unit")
	}
	deniedAlias := base
	deniedAlias.NativeDeniedReaders = append([]NativeDeniedReaderBinding(nil), base.NativeDeniedReaders...)
	deniedAlias.NativeDeniedReaders[1].ReaderUID = deniedAlias.NativeDeniedReaders[0].ReaderUID
	deniedAlias.NativeDeniedReaders[1].ReaderGID = deniedAlias.NativeDeniedReaders[0].ReaderGID
	if ValidLifecycleBinding(deniedAlias) || deniedAlias.Digest() != "" {
		t.Fatal("two denied IDs aliased one physical reader")
	}
}
