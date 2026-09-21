package credentialref

import "testing"

const (
	testFingerprint = "sha256:" + "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	testCustody     = "sha256:" + "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	testFence       = "sha256:" + "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
)

func stagePointer(value string) *string { return &value }
func epochPointer(value int64) *int64   { return &value }

func validActivateBinding() LifecycleBinding {
	return LifecycleBinding{
		OperationID:               "operation-a",
		Action:                    ActionActivate,
		ReferenceID:               "reference-a",
		ConsumerIDs:               []string{"consumer-a", "consumer-b"},
		RequiredDeniedConsumerIDs: []string{"consumer-denied"},
		NativeConsumers: []NativeConsumerBinding{
			{ConsumerID: "consumer-a", TargetID: "target-a", HostMachineID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", UnitName: "alpha.service", ServiceUID: 1001, ServiceGID: 1001, ProfileID: "profile-a", RoleID: "role-a", LoadedName: LoadedNameForVersion("consumer-a", "reference-a", "version-a")},
			{ConsumerID: "consumer-b", TargetID: "target-a", HostMachineID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", UnitName: "beta.service", ServiceUID: 1002, ServiceGID: 1002, ProfileID: "profile-a", RoleID: "role-b", LoadedName: LoadedNameForVersion("consumer-b", "reference-a", "version-a")},
		},
		NativeDeniedReaders:   []NativeDeniedReaderBinding{{ConsumerID: "consumer-denied", TargetID: "target-a", HostMachineID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", ReaderUID: 2001, ReaderGID: 2001, ProfileID: "profile-a", RoleID: "role-denied"}},
		MaterialVersion:       "version-a",
		ResolverID:            "native-systemd",
		TargetID:              "target-a",
		CiphertextFingerprint: testFingerprint,
		StateRevision:         12,
		RecoveryEpoch:         3,
	}
}

func TestValidLifecycleBindingAcceptsEachAction(t *testing.T) {
	cases := map[LifecycleAction]LifecycleBinding{}

	activate := validActivateBinding()
	cases[ActionActivate] = activate

	stage := validActivateBinding()
	stage.Action = ActionStage
	stage.DraftID = stagePointer("draft-a")
	sealOrigin(&stage)
	stage.RequiredDeniedConsumerIDs = nil
	stage.NativeConsumers, stage.NativeDeniedReaders = nil, nil
	cases[ActionStage] = stage

	rotate := validActivateBinding()
	rotate.Action = ActionRotate
	rotate.DraftID = stagePointer("draft-a")
	sealOrigin(&rotate)
	rotate.PriorMaterialVersion = stagePointer("version-old")
	rotate.OverlapSeconds = 900
	cases[ActionRotate] = rotate

	revoke := validActivateBinding()
	revoke.Action = ActionRevoke
	revoke.ConsumerIDs = nil
	revoke.RequiredDeniedConsumerIDs = nil
	revoke.NativeConsumers, revoke.NativeDeniedReaders = nil, nil
	cases[ActionRevoke] = revoke

	recover := validActivateBinding()
	recover.Action = ActionRecover
	recover.RequiredDeniedConsumerIDs = nil
	recover.NativeConsumers, recover.NativeDeniedReaders = nil, nil
	recover.DraftID = stagePointer("draft-a")
	sealOrigin(&recover)
	recover.PriorRecoveryEpoch = epochPointer(2)
	recover.RecoveryEpoch = 3
	recover.CustodyProofDigest = stagePointer(testCustody)
	recover.FormerControllerFenceDigest = stagePointer(testFence)
	cases[ActionRecover] = recover

	for action, binding := range cases {
		if !ValidLifecycleBinding(binding) {
			t.Errorf("action %s rejected a valid binding", action)
		}
		if binding.Digest() == "" {
			t.Errorf("action %s produced an empty digest", action)
		}
	}
}

func TestValidLifecycleBindingRejectsUnsafeSets(t *testing.T) {
	empty := validActivateBinding()
	empty.ConsumerIDs = nil
	if ValidLifecycleBinding(empty) {
		t.Fatal("activate accepted an empty consumer set")
	}

	duplicate := validActivateBinding()
	duplicate.ConsumerIDs = []string{"consumer-a", "consumer-a"}
	if ValidLifecycleBinding(duplicate) {
		t.Fatal("accepted a duplicate consumer")
	}

	overlapping := validActivateBinding()
	overlapping.RequiredDeniedConsumerIDs = []string{"consumer-a"}
	if ValidLifecycleBinding(overlapping) {
		t.Fatal("accepted a consumer that is both positive and denied")
	}

	tooMany := validActivateBinding()
	tooMany.ConsumerIDs = make([]string, 0, MaxLifecycleConsumers+1)
	for index := 0; index <= MaxLifecycleConsumers; index++ {
		tooMany.ConsumerIDs = append(tooMany.ConsumerIDs, "consumer-"+string(rune('a'+index%26))+string(rune('a'+index/26)))
	}
	if ValidLifecycleBinding(tooMany) {
		t.Fatal("accepted more than the consumer cap")
	}
}

func TestValidLifecycleBindingRejectsWrongActionNullables(t *testing.T) {
	// activate must not carry recovery custody fields
	activateWithCustody := validActivateBinding()
	activateWithCustody.CustodyProofDigest = stagePointer(testCustody)
	if ValidLifecycleBinding(activateWithCustody) {
		t.Fatal("activate accepted recovery custody proof")
	}

	// recover must strictly increase the epoch
	staleRecover := validActivateBinding()
	staleRecover.Action = ActionRecover
	staleRecover.DraftID = stagePointer("draft-a")
	staleRecover.PriorRecoveryEpoch = epochPointer(3)
	staleRecover.RecoveryEpoch = 3
	staleRecover.CustodyProofDigest = stagePointer(testCustody)
	staleRecover.FormerControllerFenceDigest = stagePointer(testFence)
	if ValidLifecycleBinding(staleRecover) {
		t.Fatal("recover accepted a non-increasing epoch")
	}

	// rotate overlap must stay within the bound
	longRotate := validActivateBinding()
	longRotate.Action = ActionRotate
	longRotate.DraftID = stagePointer("draft-a")
	longRotate.PriorMaterialVersion = stagePointer("version-old")
	longRotate.OverlapSeconds = MaxLifecycleOverlapSeconds + 1
	if ValidLifecycleBinding(longRotate) {
		t.Fatal("rotate accepted an overlap beyond the bound")
	}

	// provider-specific fingerprint form must be a sha256 digest
	badFingerprint := validActivateBinding()
	badFingerprint.CiphertextFingerprint = "op://vault/item"
	if ValidLifecycleBinding(badFingerprint) {
		t.Fatal("accepted a non-digest ciphertext fingerprint")
	}
}

func TestLifecycleDigestIsDeterministicAndSensitive(t *testing.T) {
	base := validActivateBinding()
	if base.Digest() != base.Digest() {
		t.Fatal("digest is not deterministic")
	}
	reordered := validActivateBinding()
	reordered.ConsumerIDs = []string{"consumer-b", "consumer-a"}
	if base.Digest() != reordered.Digest() {
		t.Fatal("digest depends on consumer order")
	}
	changed := validActivateBinding()
	changed.MaterialVersion = "version-b"
	changed.NativeConsumers = append([]NativeConsumerBinding(nil), changed.NativeConsumers...)
	for index := range changed.NativeConsumers {
		changed.NativeConsumers[index].LoadedName = LoadedNameForVersion(changed.NativeConsumers[index].ConsumerID, changed.ReferenceID, changed.MaterialVersion)
	}
	if base.Digest() == changed.Digest() {
		t.Fatal("digest ignored the material version")
	}
	if LifecycleManifestDigest([]LifecycleBinding{base}) == "" {
		t.Fatal("manifest digest empty for a valid binding")
	}
	if LifecycleManifestDigest([]LifecycleBinding{base, {}}) != "" {
		t.Fatal("manifest digest accepted an invalid member")
	}
}

func TestLifecycleDraftOriginMustBeSealed(t *testing.T) {
	binding := validActivateBinding()
	binding.Action = ActionStage
	binding.DraftID = stagePointer("draft-a")
	binding.RequiredDeniedConsumerIDs = nil
	binding.NativeConsumers, binding.NativeDeniedReaders = nil, nil
	if ValidLifecycleBinding(binding) || binding.Digest() != "" {
		t.Fatal("incomplete historical draft binding must fail closed")
	}
}

func sealOrigin(binding *LifecycleBinding) {
	binding.ImportDraftStateRevision = epochPointer(1)
	binding.ImportDraftConsumerID = stagePointer("consumer-a")
	binding.ImportDraftPurposeID = stagePointer("purpose-a")
}
