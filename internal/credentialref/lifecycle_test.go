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
		MaterialVersion:           "version-a",
		ResolverID:                "native-systemd",
		TargetID:                  "target-a",
		CiphertextFingerprint:     testFingerprint,
		StateRevision:             12,
		RecoveryEpoch:             3,
	}
}

func TestValidLifecycleBindingAcceptsEachAction(t *testing.T) {
	cases := map[LifecycleAction]LifecycleBinding{}

	activate := validActivateBinding()
	cases[ActionActivate] = activate

	stage := validActivateBinding()
	stage.Action = ActionStage
	stage.DraftID = stagePointer("draft-a")
	stage.RequiredDeniedConsumerIDs = nil
	cases[ActionStage] = stage

	rotate := validActivateBinding()
	rotate.Action = ActionRotate
	rotate.DraftID = stagePointer("draft-a")
	rotate.PriorMaterialVersion = stagePointer("version-old")
	rotate.OverlapSeconds = 900
	cases[ActionRotate] = rotate

	revoke := validActivateBinding()
	revoke.Action = ActionRevoke
	revoke.ConsumerIDs = nil
	revoke.RequiredDeniedConsumerIDs = nil
	cases[ActionRevoke] = revoke

	recover := validActivateBinding()
	recover.Action = ActionRecover
	recover.DraftID = stagePointer("draft-a")
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
